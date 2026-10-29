// Actual loopback delivery and bundled static engine; the fixture is never executed.
// The public approval service is controlled. This does not exercise desktop GUI consent.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { createHash, randomUUID } from 'node:crypto';
import { apply } from '../index.js';
import { buildPE64Fixture } from './fixtures/pe64.mjs';

const scratch = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-capture-runtime-'));
const sourceRoot = fs.realpathSync(new URL('..', import.meta.url));
const reportPath = path.join(os.homedir(), '.dsh', 'ig5', 'artifacts', 'capture-v110', `payload-runtime-${randomUUID()}.json`);
const fixture = buildPE64Fixture(1);
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const sourceFiles = ['index.js', 'capture_tools.js', 'source/capture_service.js', 'source/capture_payload.js', 'source/delivered_payload.js', 'scripts/test_capture_payload_runtime.mjs'];
const sourceHashes = Object.fromEntries(sourceFiles.map(file => [file, hash(fs.readFileSync(path.join(sourceRoot, file)))]));
const expectedSha = hash(fixture.image), definitions = new Map(), events = new Map(), effects = [], approvals = [];
const checks = [], agent = { id: 'capture-payload-runtime-test' };
let sequence = 0, requests = 0, failure, cleaned = false, actualNetwork = false, nativeStaticEngine = false;
let stageReached = 'setup';
const ctx = {
  tools: { register(def) { definitions.set(def.name, def); return () => definitions.delete(def.name); } },
  on(name, fn) { events.set(name, fn); return () => events.delete(name); },
  get(name) { if (name === 'approval') return { request: async request => { approvals.push(request.toolName); return 'allowed-once'; } }; },
  inject(names, fn) { if (names.includes('webServer')) fn({ webServer: { register() { return () => {}; } } }); return { dispose() {} }; },
  effect(fn) { const dispose = fn(); if (typeof dispose === 'function') effects.push(dispose); },
};
const call = async (name, args) => {
  const execution = { agent, callId: 'payload-runtime-' + (++sequence), signal: new AbortController().signal };
  const gate = await events.get('tools/pre-execute')({ name, arguments: args, ...execution }, async () => ({ kind: 'allow' }));
  assert.equal(gate.kind, 'allow');
  return definitions.get(name).execute(args, execution);
};
const pass = (label, evidence) => { checks.push({ label, evidence }); console.log('PASS', label); };
const origin = http.createServer((req, res) => {
  requests++;
  res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': String(fixture.image.length),
    'content-disposition': 'attachment; filename="../../should-never-be-used.exe"' });
  res.end(fixture.image);
});
try {
  await new Promise(resolve => origin.listen(0, '127.0.0.1', resolve));
  apply(ctx, { artifactDir: path.join(scratch, 'artifacts'), projectRoot: path.join(scratch, 'projects'),
    toolset: 'full', reverseProvider: 'bundled', defaultEngine: 'reverse', backgroundOpen: false,
    requestTimeoutMs: 120000, openTimeoutMs: 180000 });
  assert.equal(definitions.size, 43);
  const scope = ['http://127.0.0.1:' + origin.address().port];
  const session = await call('ig5_capture_control', { action: 'start', scope, port: 0 });
  const delivered = await new Promise((resolve, reject) => {
    http.get({ hostname: '127.0.0.1', port: session.port, path: scope[0] + '/delivered-module?token=fixture-secret',
      headers: { host: '127.0.0.1:' + origin.address().port } }, res => {
      const chunks = []; res.on('data', chunk => chunks.push(chunk)); res.on('error', reject);
      res.on('end', () => resolve(Buffer.concat(chunks)));
    }).on('error', reject);
  });
  assert.deepEqual(delivered, fixture.image);
  actualNetwork = true; stageReached = 'http-delivery';
  await call('ig5_capture_control', { action: 'stop', session_id: session.session_id });
  const history = await call('ig5_capture', { action: 'list', session_id: session.session_id });
  assert.equal(history.items.length, 1);
  const identity = { id: history.items[0].id, session_id: session.session_id, body: 'response' };
  const inspected = await call('ig5_capture', { action: 'inspect_payload', ...identity });
  assert.equal(inspected.sha256, expectedSha); assert.equal(inspected.canMaterialize, true);
  assert(inspected.classification.candidates.some(row => row.format === 'pe'));
  assert.equal(inspected.executed, false);
  const sample = await call('ig5_capture', { action: 'materialize', ...identity });
  assert.equal(sample.sha256, expectedSha); assert.equal(sample.executed, false);
  assert.equal(path.basename(sample.path), expectedSha + '.bin');
  assert.deepEqual(fs.readFileSync(sample.path), fixture.image);
  assert(!JSON.stringify(sample.provenance).includes('fixture-secret'));
  assert.equal((await call('ig5_status', {})).sessions.length, 0, 'Saving a payload must not open an engine');
  pass('HTTP delivery, PE header triage and immutable sample retain identical SHA-256', {
    captureId: identity.id, sessionId: identity.session_id, sha256: expectedSha, bytes: fixture.image.length,
    payloadReportId: sample.result_id, payloadReportSha256: sample.reportSha256, provenance: sample.provenance,
  });
  stageReached = 'materialized';

  const opened = await call('ig5_open', { path: sample.path, background: false, analysis_timeout: 60 });
  assert.equal(opened.provider, 'ghidra'); assert.equal(opened.bits, 64); assert.equal(opened.sha256, expectedSha);
  assert(opened.n_funcs >= 16); assert.equal(opened.partial, false);
  nativeStaticEngine = true; stageReached = 'native-static-open';
  const target = sample.path;
  const created = (await call('ig5_workspace', { target, workspace: { action: 'create',
    goal: '解释捕获的模块分支函数', hypothesis: '测试模块根据参数返回不同值', next_step: '获取函数证据包' } })).workspace;
  const dossier = await call('ig5_decompile', { target, ea: fixture.addresses.branch, style: 'dossier',
    task_id: created.taskId, dossier_max_bytes: 16000, dossier_max_rows: 32 });
  assert.equal(dossier.kind, 'function-dossier'); assert.equal(dossier.provenance.sha256, expectedSha);
  assert.equal(dossier.function.ea, fixture.addresses.branch); assert.equal(dossier.investigation.ok, true);
  for (const section of Object.values(dossier.sections)) assert(['ok', 'truncated'].includes(section.status));
  const decompiled = JSON.stringify(dossier.sections.decompile);
  assert.match(decompiled, /return/); assert.match(decompiled, /ig5_fixture_branch/);
  const savedTask = (await call('ig5_workspace', { target, workspace: { action: 'get', id: created.taskId } })).workspace;
  assert.equal(savedTask.systemEvidence.length, 1);
  assert.equal(savedTask.systemEvidence[0].stale, false);
  assert.equal((await call('ig5_status', {})).sessions.find(row => row.target === target).dbRevision, opened.dbRevision);
  assert.equal(requests, 1, 'Offline triage, extraction and native analysis cannot contact the server again');
  assert.deepEqual(approvals, ['ig5_capture_control', 'ig5_capture_control']);
  assert.deepEqual(fs.readFileSync(sample.path), fixture.image, 'Static analysis must preserve the delivered bytes');
  pass('Saved network payload opens in actual bundled Ghidra and produces five native dossier sections', {
    provider: opened.provider, functions: opened.n_funcs, targetSha256: opened.sha256,
    dossierSha256: dossier.provenance.sha256, sections: Object.fromEntries(Object.entries(dossier.sections).map(([key, value]) => [key, value.status])),
    taskId: created.taskId, reportId: dossier.investigation.reportId, targetExecuted: false, databaseRevision: opened.dbRevision,
  });
  stageReached = 'native-dossier';
  await call('ig5_close', { target });
  for (const file of sourceFiles) assert.equal(hash(fs.readFileSync(path.join(sourceRoot, file))), sourceHashes[file], 'Source changed during acceptance: ' + file);
} catch (error) {
  failure = { name: error.name, code: error.code || null, message: error.message }; console.error(error);
} finally {
  try {
    for (const dispose of effects.reverse()) await dispose();
    await new Promise(resolve => origin.close(resolve));
    const relative = path.relative(fs.realpathSync(os.tmpdir()), fs.realpathSync(scratch));
    assert(relative.startsWith('ig5-capture-runtime-') && !relative.includes(path.sep));
    fs.rmSync(scratch, { recursive: true, force: true }); cleaned = true;
  } catch (error) { failure ||= { message: error.message }; console.error(error); }
  fs.mkdirSync(path.dirname(reportPath), { recursive: true });
  fs.writeFileSync(reportPath, JSON.stringify({ at: new Date().toISOString(), ok: !failure, sourceRoot, checks, failure,
    requests, approvals, cleaned, actualNetwork, nativeStaticEngine, stageReached, targetExecuted: false, desktopGui: false, sourceHashes,
  }, null, 2));
  console.log('Evidence:', reportPath);
  if (failure) process.exitCode = 1;
}
