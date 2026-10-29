import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { CaptureService } from '../source/capture_service.js';
import { createAnalysisService } from '../analysis_tools.js';
import { defineCaptureTools } from '../capture_tools.js';
import { NETWORK_API, correlateCaptureTraffic } from '../source/traffic_correlate.js';

class FakeProxy {
  constructor(options) { this.options = options; this.running = false; }
  async start(options) { this.running = true; this.current = options; return this.status(); }
  status() { return { running: this.running, port: this.current?.port || 23456, tlsInterceptEnabled: this.current?.tls === true }; }
  async stop() { this.running = false; }
  emit(exchange) { return this.options.onExchange(exchange); }
}
const wide = text => Buffer.from(Array.from(text, letter => [letter.charCodeAt(0), 0]).flat());
const sampleBytes = Buffer.concat([
  Buffer.from('MZ fixture header\n'),
  Buffer.from('http://api.example.test/v1/ping\0'),
  Buffer.from('User-Agent: IG5-Fixture/1.0\r\n'),
  Buffer.from('WinHttpOpen\0InternetOpenW\0WinHttpOpenW\0'),
  wide('api.example.test'), Buffer.from([0, 0]),
  Buffer.from('unrelated tail'),
]);
async function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-correlate-'));
  const cfg = { artifactDir: root }, mgr = { checkCancelled() {} };
  mgr.analysis = createAnalysisService(mgr, cfg);
  const service = new CaptureService(mgr, cfg, { CaptureProxy: FakeProxy });
  return { root, cfg, mgr, service, async dispose() { await service.dispose(); await mgr.analysis.dispose(); fs.rmSync(root, { recursive: true, force: true }); } };
}
async function seed(f, { url = 'http://api.example.test/v1/ping?token=secret-query', responseBody = sampleBytes, requestBody = Buffer.from([0, 255]) } = {}) {
  if (!f.service.status().running) await f.service.control({ action: 'start', scope: [new URL(url).origin] });
  const id = await f.service.proxy.emit({ method: 'POST', url, startedAt: new Date().toISOString(), endedAt: new Date().toISOString(), protocol: 'http', encrypted: false, complete: true,
    request: { headers: { authorization: 'Bearer secret-credential', cookie: 'sid=secret-cookie', 'user-agent': 'IG5-Fixture/1.0', accept: 'application/x-fixture', 'content-type': 'application/octet-stream' }, body: requestBody, bodyBytes: requestBody.length, truncated: false },
    response: { statusCode: 200, headers: { 'content-type': 'application/octet-stream' }, body: responseBody, bodyBytes: responseBody.length, truncated: false } });
  await f.service.queue; return id;
}
const writeSample = (root, bytes) => { const file = path.join(root, 'sample.bin'); fs.writeFileSync(file, bytes); return file; };
const linkOf = (result, kind, label) => result.links.find(row => row.kind === kind && (label === undefined || row.label === label));

test('captured body identity is reported as E1 without executing or leaking capture secrets', async () => {
  const f = await fixture();
  try {
    const id = await seed(f), sample = writeSample(f.root, sampleBytes);
    const result = correlateCaptureTraffic(f.service, { id, sample: { path: sample } });
    assert.equal(result.schema, 'ig5.trafficCorrespondence.v1'); assert.equal(result.executed, false); assert.equal(result.networkRequests, 0);
    assert.equal(result.mode, 'read-only'); assert.equal(result.sample.sha256.length, 64); assert.equal(result.sample.bytes, sampleBytes.length);
    const identity = linkOf(result, 'body-bytes-identity');
    assert.equal(identity.direction, 'response'); assert.equal(identity.evidenceLevel, 'E1'); assert.equal(identity.bytes, sampleBytes.length);
    assert.equal(identity.captureComplete, true);
    assert.equal(result.capture.path, '/v1/ping'); assert.equal(result.capture.queryValuesExcluded, true);
    const text = JSON.stringify(result);
    for (const secret of ['secret-query', 'secret-credential', 'secret-cookie', 'token=']) assert(!text.includes(secret), `leaked ${secret}`);
    assert(!text.includes('api.example.test?'));
    const flipped = Buffer.from(sampleBytes); flipped[flipped.length - 1] ^= 0xff;
    const different = correlateCaptureTraffic(f.service, { id, sample: { path: writeSample(f.root, flipped) } });
    assert.equal(linkOf(different, 'body-bytes-identity'), undefined, 'same length with different bytes must not match');
  } finally { await f.dispose(); }
});

test('endpoint, header and network-API literals carry exact offsets and encodings; unmatched stays explicit', async () => {
  const f = await fixture();
  try {
    const id = await seed(f), sample = writeSample(f.root, sampleBytes);
    const result = correlateCaptureTraffic(f.service, { id, sample: { path: sample } });
    const origin = linkOf(result, 'endpoint-origin', 'origin');
    assert.equal(origin.matches[0].offset, sampleBytes.indexOf('http://api.example.test')); assert.equal(origin.evidenceLevel, 'E0');
    const host = linkOf(result, 'endpoint-host', 'host');
    assert.deepEqual(host.matches[0], { offset: sampleBytes.indexOf('api.example.test'), encoding: 'ascii', caseInsensitive: false });
    const wideOffset = sampleBytes.indexOf(wide('api.example.test'));
    assert(host.matches.some(row => row.encoding === 'utf16le' && row.offset === wideOffset), 'UTF-16LE host occurrence was not reported');
    assert.equal(linkOf(result, 'endpoint-path', 'path').matches[0].offset, sampleBytes.indexOf('/v1/ping'));
    assert.equal(linkOf(result, 'request-header-value', 'user-agent').matches[0].offset, sampleBytes.indexOf('IG5-Fixture/1.0'));
    const apis = result.links.filter(row => row.kind === 'communication-api-literal');
    const winhttp = apis.find(row => row.needle === 'winhttpopen');
    assert(winhttp, 'WinHttpOpen literal was not reported');
    assert.deepEqual(winhttp.matches.map(row => row.offset), [sampleBytes.indexOf('WinHttpOpen\0')], 'word boundaries must exclude WinHttpOpenW');
    assert(sampleBytes.indexOf('WinHttpOpenW') > 0);
    assert(apis.some(row => row.needle === 'internetopenw'), 'InternetOpenW literal was not reported');
    assert(!apis.some(row => row.needle === 'socket'), 'an absent literal was reported');
    assert(apis.every(row => row.evidenceLevel === 'E0'));
    const missing = result.unmatched.map(row => row.needle);
    assert(missing.includes('application/x-fixture')); assert(missing.includes('application/octet-stream'));
    assert(result.unmatched.every(row => /absence is not proof/.test(row.detail)));
    assert.equal(result.coverage.endpointNeedles, 6); assert.equal(result.coverage.matchesTruncated, false);
  } finally { await f.dispose(); }
});

test('correlate validates sample identity, shape and size before scanning', async () => {
  const f = await fixture();
  try {
    const id = await seed(f), sample = writeSample(f.root, sampleBytes);
    await assert.rejects(async () => correlateCaptureTraffic(f.service, { id, sample: { path: sample, sha256: '0'.repeat(64) } }), /does not match/);
    await assert.rejects(async () => correlateCaptureTraffic(f.service, { id, sample: { path: sample, extra: 1 } }), /only path and sha256/);
    await assert.rejects(async () => correlateCaptureTraffic(f.service, { id, sample: 'x' }), /sample must be an object/);
    await assert.rejects(async () => correlateCaptureTraffic(f.service, { id, sample: { path: f.root } }), /regular/);
    await assert.rejects(async () => correlateCaptureTraffic(f.service, { id, sample: { path: 'x'.repeat(4097) } }), /4096/);
    const big = path.join(f.root, 'big.bin'); fs.writeFileSync(big, Buffer.alloc(32 * 1024 * 1024 + 1));
    await assert.rejects(async () => correlateCaptureTraffic(f.service, { id, sample: { path: big } }), /correlation budget/);
  } finally { await f.dispose(); }
});

test('empty captured and sample bodies never fabricate a byte-identity link', async () => {
  const f = await fixture();
  try {
    const id = await seed(f, { responseBody: Buffer.alloc(0), requestBody: Buffer.alloc(0) }), sample = writeSample(f.root, Buffer.alloc(0));
    const result = correlateCaptureTraffic(f.service, { id, sample: { path: sample } });
    assert.equal(linkOf(result, 'body-bytes-identity'), undefined);
    assert.equal(result.sample.bytes, 0);
  } finally { await f.dispose(); }
});

test('encrypted CONNECT tunnel bytes are never presented as application-body identity', async () => {
  const f = await fixture();
  try {
    const url = 'http://api.example.test:8080/', sample = writeSample(f.root, sampleBytes);
    if (!f.service.status().running) await f.service.control({ action: 'start', scope: [new URL(url).origin] });
    const id = await f.service.proxy.emit({ method: 'CONNECT', url, startedAt: new Date().toISOString(), endedAt: new Date().toISOString(),
      protocol: 'connect', encrypted: true, tunnel: true, complete: true,
      request: { headers: {}, body: sampleBytes, bodyBytes: sampleBytes.length, truncated: false },
      response: { headers: {}, body: Buffer.alloc(0), bodyBytes: 0, truncated: false } });
    await f.service.queue;
    const result = correlateCaptureTraffic(f.service, { id, sample: { path: sample } });
    assert.equal(linkOf(result, 'body-bytes-identity'), undefined);
    assert.equal(result.capture.tunnel, true); assert.equal(result.capture.path, null);
  } finally { await f.dispose(); }
});

test('tool surface exposes correlate and keeps unrelated actions rejected', async () => {
  const f = await fixture();
  try {
    f.mgr.capture = f.service;
    const tools = defineCaptureTools({}, f.mgr, f.cfg);
    const read = tools.find(tool => tool.name === 'ig5_capture');
    assert(read.parameters.properties.action.enum.includes('correlate'));
    assert.deepEqual(read.parameters.properties.sample.required, ['path']);
    const id = await seed(f), sample = writeSample(f.root, sampleBytes);
    const result = read.execute({ action: 'correlate', id, sample: { path: sample } });
    assert.equal(result.schema, 'ig5.trafficCorrespondence.v1');
    assert.throws(() => read.execute({ action: 'invent' }), /status, list/);
  } finally { await f.dispose(); }
});

test('per-needle match caps report truncation without increasing returned evidence', async () => {
  const f = await fixture();
  try {
    const id = await seed(f);
    // Numeric path avoids case-fold variants, testing the exact cap boundary.
    for (const [count, truncated] of [[4, false], [5, true], [6, true]]) {
      const sample = writeSample(f.root, Buffer.from('/123456 '.repeat(count)));
      const record = f.service.record(id);
      const service = { record() { return { ...record, result: { ...record.result, url: 'http://api.example.test/123456' } }; } };
      const report = correlateCaptureTraffic(service, { id, sample: { path: sample } });
      assert.equal(linkOf(report, 'endpoint-path').matches.length, Math.min(count, 4));
      assert.equal(report.coverage.matchesTruncated, truncated);
    }
  } finally { await f.dispose(); }
});

test('curated network API literals stay inside the behaviour taxonomy network block', () => {
  const source = fs.readFileSync(new URL('../worker/behavior_rules.py', import.meta.url), 'utf8');
  const start = source.indexOf("'network': ("), end = source.indexOf("'memory-execution': (");
  assert(start > 0 && end > start, 'network taxonomy block was not found');
  const names = new Set([...source.slice(start, end).matchAll(/'([a-z0-9_]+)'/g)].map(match => match[1]));
  for (const [name] of NETWORK_API) assert(names.has(name), `${name} is not in the network taxonomy`);
});
