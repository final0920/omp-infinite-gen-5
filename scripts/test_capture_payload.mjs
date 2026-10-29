import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { CaptureService } from '../source/capture_service.js';
import { createAnalysisService } from '../analysis_tools.js';
import { hashBytes } from '../source/analysis_artifacts.js';
import { inspectCapturePayload, materializeCapturePayload } from '../source/capture_payload.js';

async function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-capture-payload-'));
  const cfg = { artifactDir: root };
  const mgr = { checkCancelled() {}, rpc() { throw new Error('Payload helpers must not invoke an engine'); } };
  mgr.analysis = createAnalysisService(mgr, cfg);
  const service = new CaptureService(mgr, cfg);
  const session = { id: randomUUID(), scope: ['https://payload.example.test'] };
  async function save(bytes = Buffer.from([0, 255, 128, 1, 2]), changes = {}) {
    const base = { id: randomUUID(), method: 'GET', url: 'https://payload.example.test/download?token=private-query', startedAt: new Date().toISOString(), endedAt: new Date().toISOString(),
      protocol: 'https', encrypted: false, complete: true, tlsDecrypted: true,
      request: { headers: { authorization: 'Bearer private-token' }, body: Buffer.alloc(0), bodyBytes: 0, truncated: false },
      response: { statusCode: 200, headers: { 'content-type': 'application/octet-stream', 'content-disposition': 'attachment; filename="../../malicious-target.exe"', 'set-cookie': 'sid=private-cookie' }, body: bytes, bodyBytes: bytes.length, truncated: false } };
    const value = { ...base, ...changes, request: { ...base.request, ...changes.request }, response: { ...base.response, ...changes.response } };
    const id = await service.enqueue(value, session); await service.queue;
    assert(id, 'Capture fixture must be persisted successfully'); return id;
  }
  return { root, cfg, mgr, service, session, save, async close() { await service.dispose(); await mgr.analysis.dispose(); fs.rmSync(root, { recursive: true, force: true }); } };
}

test('inspection remains read-only, secret-free and bound to exact capture metadata', async () => {
  const f = await fixture();
  try {
    const bytes = Buffer.from([0, 255, 128, 1, 2]), id = await f.save(bytes);
    const value = inspectCapturePayload(f.service, { id, session_id: f.session.id });
    assert.equal(value.sha256, hashBytes(bytes)); assert.equal(value.byteCount, bytes.length); assert.equal(value.complete, true);
    assert.equal(value.executed, false); assert.equal(value.canMaterialize, true);
    assert.equal(value.provenance.sourceMetadataSha256, f.service.artifacts.metadata(id).digest);
    assert.equal(value.provenance.sourceReportSha256, f.service.artifacts.metadata(id).result.recordSha256);
    assert.equal(value.provenance.captureId, id); assert.equal(value.provenance.sessionId, f.session.id);
    assert.equal(fs.existsSync(path.join(f.root, 'capture-payloads')), false);
    const serialized = JSON.stringify(value);
    for (const secret of ['private-query', 'private-token', 'private-cookie', 'malicious-target.exe']) assert(!serialized.includes(secret));
  } finally { await f.close(); }
});

test('materialization writes exact bytes to immutable hash path and creates a reusable producer report', async () => {
  const f = await fixture();
  try {
    const bytes = Buffer.from([0, 255, 128, 1, 2]), id = await f.save(bytes);
    const first = materializeCapturePayload(f.service, { id });
    assert.equal(first.path, path.join(f.root, 'capture-payloads', hashBytes(bytes) + '.bin'));
    assert.deepEqual(fs.readFileSync(first.path), bytes); assert.equal(first.executed, false); assert.equal(first.reused, false);
    const report = f.service.artifacts.get(first.result_id);
    assert.equal(report.kind, 'delivered-payload'); assert.equal(report.action, 'materialize');
    assert.equal(first.reportSha256, hashBytes(Buffer.from(JSON.stringify(report))));
    assert.equal(report.result.provenance.captureId, id);
    const inspected = await f.mgr.analysis.execute('crypto', { action: 'inspect', input: first.input });
    assert.equal(inspected.input.origin.derivedFrom.kind, 'delivered-payload'); assert.equal(inspected.input.origin.derivedFrom.resultId, first.result_id);
    const second = materializeCapturePayload(f.service, { id });
    assert.equal(second.path, first.path); assert.equal(second.sha256, first.sha256); assert.equal(second.reused, true);
    assert.notEqual(second.result_id, first.result_id);
    assert.deepEqual(fs.readdirSync(path.dirname(first.path)), [hashBytes(bytes) + '.bin']);
  } finally { await f.close(); }
});

test('existing hash path tamper is rejected and never overwritten', async () => {
  const f = await fixture();
  try {
    const id = await f.save(), first = materializeCapturePayload(f.service, { id });
    fs.writeFileSync(first.path, 'do not replace me');
    assert.throws(() => materializeCapturePayload(f.service, { id }), /immutable SHA-256/);
    assert.equal(fs.readFileSync(first.path, 'utf8'), 'do not replace me');
  } finally { await f.close(); }
});

test('interrupted exclusive write cleans up only its owned partial file and permits a later retry', async () => {
  const f = await fixture();
  try {
    const bytes = Buffer.from([0, 255, 128, 1, 2]), id = await f.save(bytes);
    const original = fs.writeSync; let writes = 0, failure;
    fs.writeSync = (fd, data, offset, length, ...rest) => {
      if (++writes === 1) return original(fd, data, offset, Math.min(2, length), ...rest);
      throw Object.assign(new Error('fixture disk full'), { code: 'ENOSPC' });
    };
    try { materializeCapturePayload(f.service, { id }); } catch (error) { failure = error; }
    finally { fs.writeSync = original; }
    assert.equal(failure.code, 'ENOSPC'); assert.equal(failure.partialFileRetained, false);
    assert.equal(fs.existsSync(path.join(f.root, 'capture-payloads', hashBytes(bytes) + '.bin')), false);
    const completed = materializeCapturePayload(f.service, { id });
    assert.equal(completed.reused, false); assert.deepEqual(fs.readFileSync(completed.path), bytes);
  } finally { await f.close(); }
});

test('existing destination hardlinks are rejected even when their bytes match', async () => {
  const f = await fixture();
  try {
    const bytes = Buffer.from([0, 255, 128, 1, 2]), id = await f.save(bytes);
    const directory = path.join(f.root, 'capture-payloads'); fs.mkdirSync(directory);
    const external = path.join(f.root, 'external.bin'); fs.writeFileSync(external, bytes);
    const destination = path.join(directory, hashBytes(bytes) + '.bin'); fs.linkSync(external, destination);
    assert.throws(() => materializeCapturePayload(f.service, { id }), /exactly one link/);
    assert.deepEqual(fs.readFileSync(external), bytes);
  } finally { await f.close(); }
});

test('destination symlinks are rejected without touching linked bytes', async t => {
  const f = await fixture();
  try {
    const bytes = Buffer.from([0, 255, 128, 1, 2]), id = await f.save(bytes);
    const directory = path.join(f.root, 'capture-payloads'); fs.mkdirSync(directory);
    const external = path.join(f.root, 'outside.bin'); fs.writeFileSync(external, 'untouched');
    try { fs.symlinkSync(external, path.join(directory, hashBytes(bytes) + '.bin'), 'file'); }
    catch (error) { if (['EPERM', 'EACCES'].includes(error.code)) { t.skip('Host does not permit file symlink fixture'); return; } throw error; }
    assert.throws(() => materializeCapturePayload(f.service, { id }), /exactly one link/);
    assert.equal(fs.readFileSync(external, 'utf8'), 'untouched');
  } finally { await f.close(); }
});

test('output directory symlinks and replacement are rejected', async t => {
  const f = await fixture();
  try {
    const id = await f.save(), linked = path.join(f.root, 'linked-directory'); fs.mkdirSync(linked);
    const directory = path.join(f.root, 'capture-payloads');
    try { fs.symlinkSync(linked, directory, process.platform === 'win32' ? 'junction' : 'dir'); }
    catch (error) { if (['EPERM', 'EACCES'].includes(error.code)) { t.skip('Host does not permit directory symlink fixture'); return; } throw error; }
    assert.throws(() => materializeCapturePayload(f.service, { id }), /non-linked directory/);
    assert.deepEqual(fs.readdirSync(linked), []); fs.unlinkSync(directory);
    materializeCapturePayload(f.service, { id });
    fs.renameSync(directory, path.join(f.root, 'old-payloads')); fs.mkdirSync(directory);
    assert.throws(() => materializeCapturePayload(f.service, { id }), /directory was replaced/);
    assert.deepEqual(fs.readdirSync(directory), []);
  } finally { await f.close(); }
});

test('stale sessions, supplied paths and tampered capture reports are rejected', async () => {
  const f = await fixture();
  try {
    const id = await f.save();
    assert.throws(() => materializeCapturePayload(f.service, { id, session_id: randomUUID() }), /another session/);
    assert.throws(() => materializeCapturePayload(f.service, { id, path: 'elsewhere.exe' }), /derived only/);
    fs.appendFileSync(path.join(f.service.artifacts.root, 'records', `${id}.json`), ' ');
    assert.throws(() => inspectCapturePayload(f.service, { id }), /hash does not match/);
    assert.equal(fs.existsSync(path.join(f.root, 'capture-payloads')), false);
  } finally { await f.close(); }
});

test('incomplete, truncated, encoded and partial-resource responses cannot materialize', async () => {
  const f = await fixture();
  try {
    const cases = [
      [{ complete: false }, 'INCOMPLETE_CAPTURE'],
      [{ response: { bodyBytes: 99, truncated: true } }, 'INCOMPLETE_CAPTURE'],
      [{ response: { headers: { 'content-encoding': 'gzip' } } }, 'HTTP_CONTENT_ENCODING_REQUIRES_EXPLICIT_DECODE'],
      [{ response: { statusCode: 206 } }, 'PARTIAL_HTTP_RESOURCE'],
      [{ response: { statusCode: 200, headers: { 'Content-Range': 'bytes 0-4/100' } } }, 'PARTIAL_HTTP_RESOURCE'],
    ];
    for (const [change, code] of cases) {
      const id = await f.save(undefined, change), inspected = inspectCapturePayload(f.service, { id });
      assert.equal(inspected.canMaterialize, false); assert(inspected.blockedReasons.includes(code));
      assert.throws(() => materializeCapturePayload(f.service, { id }), new RegExp(code));
    }
    const encrypted = await f.save(undefined, { encrypted: true, tunnel: true });
    assert.throws(() => materializeCapturePayload(f.service, { id: encrypted }), /encrypted CONNECT/);
    assert.equal(fs.existsSync(path.join(f.root, 'capture-payloads')), false);
  } finally { await f.close(); }
});

test('complete unknown bytes materialize regardless of misleading MIME, empty bytes do not', async () => {
  const f = await fixture();
  try {
    const id = await f.save(undefined, { response: { headers: { 'content-type': 'image/png', 'content-encoding': 'identity' } } });
    const result = materializeCapturePayload(f.service, { id });
    assert.equal(result.executed, false); assert.equal(path.extname(result.path), '.bin');
    const empty = await f.save(Buffer.alloc(0));
    assert.throws(() => materializeCapturePayload(f.service, { id: empty }), /EMPTY_PAYLOAD/);
  } finally { await f.close(); }
});

test('only one complete uncompressed WebSocket data frame is materializable', async () => {
  const f = await fixture();
  try {
    const websocket = { direction: 'server_to_client', fin: true, opcode: 2, compressed: false, payloadEncoding: 'bytes', partial: false, reassembled: false };
    const complete = await f.save(undefined, { protocol: 'websocket', method: 'WEBSOCKET', websocket });
    assert.equal(materializeCapturePayload(f.service, { id: complete }).executed, false);
    for (const change of [{ fin: false }, { opcode: 0 }, { opcode: 9 }, { compressed: true }, { partial: true }]) {
      const id = await f.save(undefined, { protocol: 'websocket', websocket: { ...websocket, ...change } });
      assert.equal(inspectCapturePayload(f.service, { id }).canMaterialize, false);
      assert.throws(() => materializeCapturePayload(f.service, { id }), /WEBSOCKET|INCOMPLETE/);
    }
    assert.throws(() => materializeCapturePayload(f.service, { id: complete, body: 'request' }), /WEBSOCKET_DIRECTION_MISMATCH/);
  } finally { await f.close(); }
});

test('report failure explicitly preserves evidence that payload bytes were saved', async () => {
  const f = await fixture();
  try {
    const id = await f.save(), original = f.service.artifacts.save;
    f.service.artifacts.save = () => { throw new Error('fixture report failure'); };
    let failure;
    try { materializeCapturePayload(f.service, { id }); } catch (error) { failure = error; }
    finally { f.service.artifacts.save = original; }
    assert.equal(failure.code, 'PAYLOAD_REPORT_FAILED'); assert.equal(failure.stage, 'report'); assert.equal(failure.fileSaved, true);
    assert.equal(hashBytes(fs.readFileSync(failure.path)), failure.sha256);
  } finally { await f.close(); }
});
