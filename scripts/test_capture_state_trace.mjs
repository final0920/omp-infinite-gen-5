import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { CaptureService } from '../source/capture_service.js';
import { createAnalysisService } from '../analysis_tools.js';
import { buildCaptureStateTrace } from '../source/capture_state_trace.js';

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-state-trace-'));
  const mgr = { checkCancelled() {}, rpc() { throw new Error('No engine RPC allowed'); } }, cfg = { artifactDir: root };
  mgr.analysis = createAnalysisService(mgr, cfg);
  const service = new CaptureService(mgr, cfg), session = { id: randomUUID(), scope: ['http://protocol.test'] };
  let counter = 0;
  async function save(request = '01', response = '11', changes = {}) {
    const tick = Date.UTC(2026, 0, 1) + counter++ * 10;
    const base = { id: randomUUID(), url: 'http://protocol.test/message?secret=hidden-query', method: 'POST',
      protocol: 'http', startedAt: new Date(tick).toISOString(), endedAt: new Date(tick + 5).toISOString(), complete: true,
      request: { headers: { authorization: 'hidden-authorization' }, body: Buffer.from(request, 'hex') },
      response: { statusCode: 200, headers: { 'set-cookie': 'hidden-cookie' }, body: Buffer.from(response, 'hex') } };
    return service.enqueue({ ...base, ...changes, request: { ...base.request, ...changes.request }, response: { ...base.response, ...changes.response } }, session);
  }
  const trace = (ids, id = 'conversation1', extra = {}) => ({ id, session_id: session.id, start: 'session-start', complete: true, ids, ...extra });
  return { root, mgr, service, session, save, trace, async close() { await service.dispose(); await mgr.analysis.dispose(); fs.rmSync(root, { recursive: true, force: true }); } };
}
const fields = { request: { source: 'body-field', offset: 0, size: 1 }, response: { source: 'body-field', offset: 0, size: 1 } };

test('explicit conversations produce reusable directional trace refs and source digests without secret URLs', async () => {
  const f = fixture();
  try {
    const ids = [await f.save('01', '11'), await f.save('02', '12')];
    const hold = await f.save('03', '13');
    const result = buildCaptureStateTrace(f.service, { action: 'state_trace', traces: [f.trace(ids)], holdout: [f.trace([hold], 'heldout')], symbols: fields });
    assert.equal(result.counts.events, 6); assert.equal(result.networkSent, false); assert.equal(result.targetExecuted, false);
    const saved = f.service.artifacts.get(result.result_id), manifest = JSON.parse(f.service.artifacts.read(result.input.ref).data);
    assert.equal(manifest.schemaVersion, 'ig5.protocol-traces.v1'); assert.equal(saved.kind, 'capture-traces');
    assert.deepEqual(manifest.traces[0].events.map(event => event.symbol), ['field:01', 'field:11', 'field:02', 'field:12']);
    assert.deepEqual(manifest.traces[0].events.map(event => event.direction), ['client_to_server', 'server_to_client', 'client_to_server', 'server_to_client']);
    assert.equal(manifest.traces[0].events[0].evidence.sha256, f.service.artifacts.metadata(ids[0]).result.recordSha256);
    assert.equal(manifest.traces[0].events[0].evidence.bodySha256, f.service.record(ids[0]).result.request.body.sha256);
    assert.equal(saved.result.provenance.length, 3);
    for (const secret of ['hidden-query', 'hidden-authorization', 'hidden-cookie']) assert(!JSON.stringify([saved, manifest]).includes(secret));
    const inspected = await f.mgr.analysis.execute('protocol', { action: 'inspect', input: result.input });
    assert.equal(inspected.input.origin.derivedFrom.kind, 'capture-traces');
  } finally { await f.close(); }
});

test('default symbol abstraction uses route hash/status and retains explicitly unknown starts and partial ends', async () => {
  const f = fixture();
  try {
    const result = buildCaptureStateTrace(f.service, { traces: [f.trace([await f.save()], 'partial', { start: 'unknown', complete: false })] });
    const manifest = JSON.parse(f.service.artifacts.read(result.input.ref).data), trace = manifest.traces[0];
    assert.equal(trace.start, 'unknown'); assert.equal(trace.complete, false);
    assert.match(trace.events[0].symbol, /^POST:route:[a-f0-9]{32}$/); assert.equal(trace.events[1].symbol, 'status:200');
    assert(!JSON.stringify(manifest).includes('/message'));
  } finally { await f.close(); }
});

test('reused captures, stale sessions, missing boundaries, backward and overlapping exchanges reject', async () => {
  const f = fixture();
  try {
    const first = await f.save(), second = await f.save();
    assert.throws(() => buildCaptureStateTrace(f.service, { traces: [f.trace([first, first])] }), /twice/);
    assert.throws(() => buildCaptureStateTrace(f.service, { traces: [f.trace([first])], holdout: [f.trace([first], 'hold')] }), /shared/);
    assert.throws(() => buildCaptureStateTrace(f.service, { traces: [f.trace([second, first])] }), /non-overlapping/);
    assert.throws(() => buildCaptureStateTrace(f.service, { traces: [f.trace([first], 'stale', { session_id: randomUUID() })] }), /another session/);
    assert.throws(() => buildCaptureStateTrace(f.service, { traces: [f.trace([first], 'no-start', { start: undefined })] }), /declare/);
    const overlap = await f.save('01', '11', { startedAt: '2026-01-01T00:00:00.002Z', endedAt: '2026-01-01T00:00:00.003Z' });
    assert.throws(() => buildCaptureStateTrace(f.service, { traces: [f.trace([first, overlap])] }), /non-overlapping/);
  } finally { await f.close(); }
});

test('incomplete, encoded body fields, out-of-range selectors, tunnels and partial resources fail explicitly', async () => {
  const f = fixture();
  try {
    const bad = [await f.save('01', '11', { complete: false }), await f.save('01', '11', { tunnel: true }),
      await f.save('01', '11', { response: { bodyBytes: 5 } }), await f.save('01', '11', { response: { headers: { 'content-encoding': 'gzip' } } }),
      await f.save('01', '11', { response: { statusCode: 206 } })];
    for (const id of bad) assert.throws(() => buildCaptureStateTrace(f.service, { traces: [f.trace([id])], symbols: fields }));
    const id = await f.save();
    assert.throws(() => buildCaptureStateTrace(f.service, { traces: [f.trace([id])], symbols: { request: { source: 'body-field', offset: -1, size: 1 } } }));
    assert.throws(() => buildCaptureStateTrace(f.service, { traces: [f.trace([id])], symbols: { request: { source: 'body-field', offset: -0, size: 1 } } }));
    let getterCalls = 0;
    assert.throws(() => buildCaptureStateTrace(f.service, { get traces() { getterCalls++; return []; } }), /accessors/);
    assert.equal(getterCalls, 0);
    assert.throws(() => buildCaptureStateTrace(f.service, { traces: [f.trace([id])], symbols: { response: { source: 'body-field', offset: 0, size: 2 } } }), /outside/);
    assert.throws(() => buildCaptureStateTrace(f.service, { traces: [f.trace([id])], output_path: 'user-path' }), /unsupported/);
  } finally { await f.close(); }
});

test('authenticated capture report and body tampering cannot become state evidence', async () => {
  const f = fixture();
  try {
    const id = await f.save(), record = f.service.record(id);
    fs.writeFileSync(path.join(f.service.artifacts.root, 'blobs', record.result.response.body.sha256 + '.bin'), Buffer.from('ff', 'hex'));
    assert.throws(() => buildCaptureStateTrace(f.service, { traces: [f.trace([id])] }), /hash/);
    const changed = await f.save('02', '12');
    const reportPath = path.join(f.service.artifacts.root, 'records', changed + '.json');
    const changedReport = JSON.parse(fs.readFileSync(reportPath)); changedReport.result.method = 'DELETE';
    fs.writeFileSync(reportPath, JSON.stringify(changedReport));
    assert.throws(() => buildCaptureStateTrace(f.service, { traces: [f.trace([changed])] }), /hash|digest/i);
  } finally { await f.close(); }
});

test('capture producer manifests feed real state inference and subsequent saved-model validation unchanged', async () => {
  const f = fixture();
  try {
    const train = buildCaptureStateTrace(f.service, { traces: [f.trace([await f.save('01', '11'), await f.save('02', '12')])], symbols: fields });
    const inferred = await f.mgr.analysis.execute('protocol', { action: 'state_infer', input: train.input });
    const fresh = buildCaptureStateTrace(f.service, { traces: [f.trace([await f.save('01', '11'), await f.save('02', '12')], 'fresh')], symbols: fields });
    const replay = await f.mgr.analysis.execute('protocol', { action: 'state_validate', input: fresh.input, state_model: { result_id: inferred.result_id } });
    const stored = f.service.artifacts.get(replay.result_id);
    assert.equal(stored.result.state.holdout.accepted, 1);
    assert.equal(stored.result.state.sourceResultId, inferred.result_id);
  } finally { await f.close(); }
});

test('aggregate body verification budget rejects large conversation selections before writing a trace manifest', async () => {
  const f = fixture();
  try {
    const ids = [];
    for (let i = 0; i < 9; i++) ids.push(await f.save('', '', { response: { body: Buffer.alloc(1048576, i) } }));
    assert.throws(() => buildCaptureStateTrace(f.service, { traces: [f.trace(ids)] }), /8 MiB/);
    const reports = await f.service.artifacts.list({ limit: 100 });
    assert(reports.items.every(report => report.kind !== 'capture-traces'));
  } finally { await f.close(); }
});
