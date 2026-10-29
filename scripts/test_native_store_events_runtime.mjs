// Explicit native test: executes only this generated three-instruction PE leaf.
// A fixture-bound test approval service exercises the original public once gate.
// Does not change DSH settings, accept external targets or weaken product policy.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID, createHash } from 'node:crypto';
import { apply } from '../index.js';
import { buildPE64Fixture } from './fixtures/pe64.mjs';
assert(process.argv.includes('--run-owned-native-fixture'), 'Explicit native fixture opt-in required');
const option = name => process.argv[process.argv.indexOf(name) + 1];
const requested = option('--evidence'); assert(process.argv.includes('--evidence') && path.isAbsolute(requested));
const evidence = path.resolve(requested), root = path.resolve(import.meta.dirname, '..');
const relative = path.relative(root, evidence); assert(relative === '..' || relative.startsWith('..' + path.sep) || path.isAbsolute(relative), 'Evidence must be outside plugin');
assert(!fs.existsSync(evidence), 'Use a new evidence directory'); fs.mkdirSync(evidence, { recursive: true });
const artifactDir = process.argv.includes('--record-root') ? path.resolve(option('--record-root')) : path.join(evidence, 'artifacts');
const image = buildPE64Fixture().image;
Buffer.from('48894c24f8488b4424f8c3', 'hex').copy(image, 0x400);
const target = path.join(evidence, 'owned-store-load64.exe'); fs.writeFileSync(target, image, { flag: 'wx' });
const hash = bytes => createHash('sha256').update(bytes).digest('hex'), targetSha256 = hash(image);
const tools = new Map(), hooks = new Map(), effects = [], rows = [], approvals = [], agent = { id: 'owned-store-events-public-fixture' };
let active, mode = 'allowed-once', sequence = 0, opened = false, stopped = false, nativeStartDispatched = false;
const approval = { async request(value) {
  assert.equal(value.agent, agent); assert.equal(value.callId, active.callId); assert.equal(value.toolName, 'ig5_dbg');
  assert.equal(active.args.target, target); assert.equal(active.args.backend, 'x64dbg'); assert.equal(hash(fs.readFileSync(target)), targetSha256);
  assert(['load', 'start', 'bpt', 'unbpt', 'regs', 'setreg', 'trace', 'cont', 'stop'].includes(active.args.op));
  approvals.push({ callId: value.callId, op: active.args.op, outcome: mode }); return mode;
} };
const ctx = { tools: { register(definition) { tools.set(definition.name, definition); return () => tools.delete(definition.name); } },
  get(name) { return name === 'approval' ? approval : undefined; },
  on(name, callback) { hooks.set(name, callback); return () => hooks.delete(name); },
  inject() { return { dispose() {} }; }, effect(body) { const dispose = body(); if (typeof dispose === 'function') effects.push(dispose); } };
apply(ctx, { reverse: false, reverseProvider: 'bundled', toolset: 'full', artifactDir, projectRoot: path.join(evidence, 'projects'), stateRoot: path.join(evidence, 'state'), requestTimeoutMs: 120000 });
async function call(name, args) {
  assert(['ig5_dbg', 'ig5_open', 'ig5_close', 'ig5_profile', 'ig5_status', 'ig5_doctor'].includes(name));
  const execution = { agent, callId: 'owned-store-' + (++sequence) + '-' + randomUUID(), signal: new AbortController().signal };
  if (name === 'ig5_dbg') {
    active = { callId: execution.callId, args };
    let dispatched = false;
    const decision = await hooks.get('tools/pre-execute')({ name, arguments: args, ...execution }, async () => { dispatched = true; return { kind: 'allow' }; });
    if (decision.kind !== 'allow') { assert.equal(dispatched, false); return { denied: true }; }
    assert(dispatched);
  }
  if (name === 'ig5_dbg' && args.op === 'start') nativeStartDispatched = true;
  const result = await tools.get(name).execute(args, execution); rows.push({ name, args, result });
  if (name === 'ig5_dbg') await hooks.get('tools/post-execute')({ name, arguments: args, ...execution }, { isError: false, value: result }, async () => ({ kind: 'accept' }));
  return result;
}
const dbg = (op, args = {}) => call('ig5_dbg', { target, engine: 'ghidra', backend: 'x64dbg', op, timeout: 30, ...args });
const report = { schema: 'ig5-native-store-events-runtime-v1', target, targetSha256, generatedFixtureOnly: true, externalTargetsExecuted: false, businessAccepted: false };
try {
  mode = 'rejected'; assert.equal((await dbg('trace', { record_trace: true, record_events: true, max_steps: 4 })).denied, true); mode = 'allowed-once';
  const readiness = await call('ig5_doctor', { engine: 'x64dbg' }); report.readonlyPreflight = readiness;
  assert.equal(readiness.ok, true, 'Known/unknown policy block: no native fixture execution permitted');
  await call('ig5_open', { path: target, engine: 'ghidra', background: false }); opened = true;
  await dbg('load'); const started = await dbg('start'); assert.equal(started.state, 'suspended'); report.debuggeePid = started.context.pid;
  const entry = '0x' + (BigInt(started.context.mainModuleBase) + 0x1000n).toString(16);
  await dbg('bpt', { rva: '0x1000' }); let state = await dbg('regs');
  for (let n = 0; state.regs.rip !== entry && n < 4; n++) { await dbg('cont'); state = await dbg('regs'); }
  assert.equal(state.regs.rip, entry); await dbg('unbpt', { rva: '0x1000' });
  const value = '0x123456789abcdef0'; await dbg('setreg', { reg: 'rcx', expected: state.regs.rcx, value });
  const trace = await dbg('trace', { record_trace: true, record_events: true, max_steps: 4 });
  assert.equal(trace.traceSaved, true, trace.traceArtifactError); assert.equal(trace.traceSummary.instructionCount, 3); assert.equal(trace.traceSummary.stopReason, 'returned');
  assert.equal(trace.storeEvents.groups, 3); assert.equal(trace.storeEvents.completeDecodedStoreGroups, 3);
  const observed = await call('ig5_recovery', { recovery: { observations: { recordings: [{ id: trace.traceReportId, sha256: trace.traceReportSha256 }], target_sha256: targetSha256, limit: 3 } } });
  const full = JSON.parse(fs.readFileSync(observed.observations.reportPath)).result;
  const write = full.stopGroups[0].memoryWrites;
  assert.equal(write.stores.length, 1); assert.equal(write.stores[0].afterHex, 'f0debc9a78563412');
  assert.equal(write.completeDecodedStoreSet, true); assert.equal(write.actualWriteCausalityProved, false);
  assert.equal(full.stopGroups[2].after.gprs.rax, value); assert.equal(full.businessAccepted, false);
  report.trace = { reportId: trace.traceReportId, reportPath: trace.traceReportPath, reportSha256: trace.traceReportSha256, storeEvents: trace.storeEvents };
  report.observation = observed.observations;
  report.replays = [];
  for (const recordEvents of [true, false]) {
    const current = await dbg('regs');
    await dbg('setreg', { reg: 'rsp', expected: current.regs.rsp, value: state.regs.rsp });
    await dbg('setreg', { reg: 'rip', expected: current.regs.rip, value: entry });
    const replay = await dbg('trace', { record_trace: true, record_events: recordEvents, max_steps: 4 });
    assert.equal(replay.traceSaved, true, replay.traceArtifactError); assert.equal(replay.traceSummary.instructionCount, 3);
    assert.equal(replay.traceSummary.stopReason, 'returned'); assert.equal((await dbg('regs')).regs.rax, value);
    if (recordEvents) {
      const view = await call('ig5_recovery', { recovery: { observations: { recordings: [{ id: replay.traceReportId, sha256: replay.traceReportSha256 }], target_sha256: targetSha256, limit: 3 } } });
      const raw = JSON.parse(fs.readFileSync(view.observations.reportPath)).result;
      assert.equal(raw.stopGroups[0].memoryWrites.stores[0].changed, false);
      assert.equal(raw.stopGroups[0].memoryWrites.stores[0].status, 'observed');
      assert.equal(raw.stopGroups[0].memoryWrites.actualWriteCausalityProved, false);
    } else assert.equal(replay.storeEvents, undefined);
    report.replays.push({ recordEvents, reportId: replay.traceReportId, reportPath: replay.traceReportPath, reportSha256: replay.traceReportSha256, elapsedMs: replay.traceSummary.elapsedMs });
  }
  report.workersBeforeClose = (await call('ig5_status', {})).sessions.filter(s => path.resolve(s.target) === path.resolve(target)).map(s => ({ engine: s.engine, pid: s.pid, alive: s.alive }));
  assert.equal((await dbg('stop')).state, 'no-task'); stopped = true;
  await call('ig5_close', { target, engine: 'ghidra' }); opened = false;
  assert.equal(hash(fs.readFileSync(target)), targetSha256); report.ok = true;
} catch (error) { report.error = { message: error.message, code: error.code, stack: error.stack }; report.ok = false; process.exitCode = 1; }
finally {
  if (opened && !stopped) { try { await dbg('stop'); } catch (error) { report.stopError = error.message; } }
  for (const dispose of effects.reverse()) { try { await dispose(); } catch (error) { report.disposeError = error.message; report.ok = false; process.exitCode = 1; } }
  report.rows = rows; report.approvals = approvals; report.cleanupAuthorityChanged = false;
  report.nativeExecutionAttempted = nativeStartDispatched;
  report.nativeTargetExecuted = rows.some(row => row.result.nativeTargetExecuted === true
    || row.name === 'ig5_dbg' && row.args.op === 'start' && row.result.context?.pid > 0) ? true : nativeStartDispatched ? null : false;
  fs.writeFileSync(path.join(evidence, 'acceptance.json'), JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
  console.log(JSON.stringify({ ok: report.ok, report: path.join(evidence, 'acceptance.json'), nativeTargetExecuted: report.nativeTargetExecuted, approvals: approvals.length, error: report.error?.message }));
}
