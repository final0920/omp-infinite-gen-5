// Real HTTP application-state fixture -> IG5 proxy -> authenticated trace artifact -> real data worker.
// Approval service is controlled here; actual desktop command acceptance is recorded separately.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { apply } from '../index.js';
import { AnalysisArtifacts } from '../source/analysis_artifacts.js';

const root = path.join(os.homedir(), '.dsh', 'ig5', 'artifacts', 'state-v110', 'network-' + randomUUID());
fs.mkdirSync(root, { recursive: true });
const definitions = new Map(), events = new Map(), effects = [], serverStates = new Map();
let requests = 0, sequence = 0, failure, evidence;
const context = {
  tools: { register(def) { definitions.set(def.name, def); return () => definitions.delete(def.name); } },
  on(name, fn) { events.set(name, fn); return () => events.delete(name); },
  get(name) { if (name === 'approval') return { request: async () => 'allowed-once' }; },
  inject(names, fn) { if (names.includes('webServer')) fn({ webServer: { register() { return () => {}; } } }); return { dispose() {} }; },
  effect(fn) { const dispose = fn(); if (typeof dispose === 'function') effects.push(dispose); },
};
async function call(name, args) {
  const execution = { agent: { id: 'protocol-state-network-test' }, callId: 'state-' + ++sequence, signal: new AbortController().signal };
  const gate = await events.get('tools/pre-execute')({ name, arguments: args, ...execution }, async () => ({ kind: 'allow' }));
  assert.equal(gate.kind, 'allow'); return definitions.get(name).execute(args, execution);
}
const origin = http.createServer((req, res) => {
  requests++; const chunks = [];
  req.on('data', bytes => chunks.push(bytes));
  req.on('end', () => {
    const key = req.url.split('/')[2], opcode = Buffer.concat(chunks)[0], before = serverStates.get(key) || 0;
    let reply = 0xff, after = before;
    if (before === 0 && opcode === 1) { reply = 0x11; after = 1; }
    else if (before === 1 && opcode === 2) { reply = 0x12; after = 2; }
    else if (before === 2 && opcode === 3) { reply = 0x13; }
    else if (before === 2 && opcode === 4) { reply = 0x14; after = 3; }
    serverStates.set(key, after); res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end(Buffer.from([reply]));
  });
});
try {
  await new Promise(resolve => origin.listen(0, '127.0.0.1', resolve));
  apply(context, { artifactDir: path.join(root, 'artifacts'), projectRoot: path.join(root, 'projects'), toolset: 'full' });
  const originUrl = 'http://127.0.0.1:' + origin.address().port;
  const session = await call('ig5_capture_control', { action: 'start', scope: [originUrl], port: 0 });
  const cases = { train1: [1, 2, 3, 4], train2: [1, 2, 3, 3, 4], repeated: [1, 2, 3, 4], badorder: [1, 3, 4], longer: [1, 2, 3, 3, 3, 4] };
  for (const [name, opcodes] of Object.entries(cases)) for (const [index, opcode] of opcodes.entries()) {
    const response = await new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port: session.port, method: 'POST', path: originUrl + '/case/' + name + '/' + index,
        headers: { host: new URL(originUrl).host, 'content-length': '1' } }, res => {
        const chunks = []; res.on('data', bytes => chunks.push(bytes)); res.on('error', reject); res.on('end', () => resolve(Buffer.concat(chunks)));
      }); req.on('error', reject); req.end(Buffer.from([opcode]));
    });
    assert.equal(response[0], name === 'badorder' && index > 0 ? 0xff : opcode + 0x10);
  }
  await call('ig5_capture_control', { action: 'stop', session_id: session.session_id });
  const list = await call('ig5_capture', { action: 'list', session_id: session.session_id, limit: 100 });
  assert.equal(list.items.length, 22);
  const trace = name => ({ id: name, start: 'session-start', complete: true, session_id: session.session_id,
    ids: list.items.filter(row => row.url.includes('/case/' + name + '/')).sort((a, b) => Number(a.url.split('/').at(-1)) - Number(b.url.split('/').at(-1))).map(row => row.id) });
  const symbols = { request: { source: 'body-field', offset: 0, size: 1 }, response: { source: 'body-field', offset: 0, size: 1 } };
  const produced = await call('ig5_capture', { action: 'state_trace', traces: [trace('train1'), trace('train2')], holdout: [trace('repeated'), trace('badorder')], symbols });
  const inferred = await call('ig5_protocol', { action: 'state_infer', input: produced.input, state_model: { merge: 'future-equivalent', merge_depth: 1 } });
  const artifacts = new AnalysisArtifacts(path.join(root, 'artifacts', 'analysis-data'));
  const state = artifacts.get(inferred.result_id).result.state;
  assert.equal(state.holdout.accepted, 1); assert.equal(state.holdout.rejected, 1);
  assert.equal(state.holdout.traces.find(row => row.traceId === 'repeated').independence.status, 'no-overlap-observed');
  const fresh = await call('ig5_capture', { action: 'state_trace', traces: [trace('longer')], symbols });
  const validated = await call('ig5_protocol', { action: 'state_validate', input: fresh.input, state_model: { result_id: inferred.result_id, model: 'merged-hypothesis' } });
  const replay = artifacts.get(validated.result_id).result.state;
  assert.equal(replay.holdout.total, 1);
  assert.equal(replay.holdout.traces[0].status, 'accepted');
  assert.equal(replay.holdout.traces[0].nondeterministic, true);
  assert.equal(replay.holdout.traces[0].independence.duplicateBehavior, false);
  assert.equal(state.observedModel.states.length, 13); assert.equal(state.mergedHypothesis.states.length, 10);
  assert.equal(requests, 22, 'State extraction and model work must not send network requests');
  const manifestPath = path.join(root, 'desktop-traces.json'), validationPath = path.join(root, 'desktop-validation.json');
  fs.writeFileSync(manifestPath, artifacts.read(produced.input.ref).data);
  fs.writeFileSync(validationPath, artifacts.read(fresh.input.ref).data);
  evidence = { actualNetwork: true, dataWorker: true, requests, captureSessionId: session.session_id, captureReportId: produced.result_id,
    inferenceReportId: inferred.result_id, validationReportId: validated.result_id, observedStates: state.observedModel.states.length,
    mergedStates: state.mergedHypothesis.states.length, holdout: state.holdout, longerTrace: replay.holdout, manifestPath, validationPath,
    hiddenServerStatesRecovered: false, desktopGui: false };
  console.log('PASS 22 real HTTP exchanges; capture source chain; trained state model; held-out replay; saved-model validation without extra requests');
} catch (error) { failure = { code: error.code || null, message: error.message }; console.error(error); }
finally {
  for (const dispose of effects.reverse()) await dispose();
  await new Promise(resolve => origin.close(resolve));
  const report = path.join(root, 'acceptance.json'); fs.writeFileSync(report, JSON.stringify({ at: new Date().toISOString(), ok: !failure, failure, evidence }, null, 2));
  console.log('Evidence:', report); if (failure) process.exitCode = 1;
}
