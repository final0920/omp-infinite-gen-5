// Explicit native acceptance on the pinned IG5-owned LEA/RET fixture only.
// Public tool wrappers and the real one-time gate are used for every debug RPC.
// A spawn observer retains the exact bridge ChildProcess for crash injection;
// it never sends private debugger requests or terminates a PID guessed from UI.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { createHash, randomUUID } from 'node:crypto';
import { apply } from '../index.js';

const target = path.resolve(process.env.IG5_GUEST_TARGET || '');
const profileFile = path.resolve(process.env.IG5_GUEST_PROFILE || '');
const evidence = path.resolve(process.env.IG5_GUEST_EVIDENCE || '');
assert(process.env.IG5_GUEST_TARGET && process.env.IG5_GUEST_PROFILE && process.env.IG5_GUEST_EVIDENCE, 'Provide explicit private guest target/profile/evidence paths');
const hash = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
assert.equal(hash(target), 'f9a145e4bc3abd32590199df5d5cb1ef42355307827d99d804fd6c81b10e8b38');
const profile = JSON.parse(fs.readFileSync(profileFile)), pin = hash(profileFile);
assert(profile.targets.some(row => row.id === 'owned-add64' && row.sha256 === hash(target)));
fs.mkdirSync(evidence, { recursive: true });
const definitions = new Map(), hooks = new Map(), effects = [], bridges = [], approvals = [], calls = [];
const agent = { id: 'ig5-owned-guest-native-acceptance' };
const spawnOriginal = childProcess.spawn;
childProcess.spawn = (...args) => {
  const proc = spawnOriginal(...args);
  if (Array.isArray(args[1]) && args[1].some(value => /[\\/]adapters[\\/]vmci[\\/]adapter\.py$/.test(value))) bridges.push(proc);
  return proc;
};
syncBuiltinESMExports();
let allowed = true;
const ctx = { tools: { register(def) { definitions.set(def.name, def); return () => definitions.delete(def.name); } },
  get(name) { if (name === 'approval') return { async request(request) {
    assert.equal(request.agent, agent); assert.equal(request.toolName, 'ig5_dbg'); assert(request.callId);
    assert(request.reason.includes('guest=lab')); assert(request.reason.includes(pin));
    approvals.push({ callId: request.callId, outcome: allowed ? 'allowed-once' : 'rejected' }); return allowed ? 'allowed-once' : 'rejected';
  } }; },
  on(name, callback) { hooks.set(name, callback); return () => hooks.delete(name); },
  inject(names, callback) { if (names.includes('webServer')) callback({ webServer: { register() { return () => {}; } } }); return { dispose() {} }; },
  effect(callback) { const remove = callback(); if (typeof remove === 'function') effects.push(remove); },
};
apply(ctx, { reverse: false, reverseProvider: 'bundled', toolset: 'full', backgroundOpen: false, artifactDir: evidence,
  projectRoot: path.join(evidence, 'projects'), remoteExecutionRoot: path.join(evidence, 'remote-executions'),
  guestDebugProfiles: { lab: profileFile }, requestTimeoutMs: 120000, openTimeoutMs: 180000 });
const execution = signal => ({ agent, signal: signal || new AbortController().signal, callId: randomUUID() });
async function call(name, args = {}, signal) {
  const selected = { ...(name === 'ig5_open' ? { path: target } : {}), ...(!['ig5_profile','ig5_status'].includes(name) ? { target, engine: 'ghidra' } : {}), ...args };
  const exec = execution(signal), dispatched = async () => definitions.get(name).execute(selected, exec);
  try {
    const result = name === 'ig5_dbg' ? await hooks.get('tools/pre-execute')({ name, arguments: selected, ...exec }, dispatched) : await dispatched();
    calls.push({ name, args: selected, result }); return result;
  } catch (error) { calls.push({ name, args: selected, error: { message: error.message, code: error.code } }); throw error; }
}
const dbg = (op, args = {}, signal) => call('ig5_dbg', { op, backend: 'x64dbg', guest_profile: 'lab', guest_binding_sha256: pin, ...args }, signal);
const wait = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
const expectedLocation = value => {
  assert.equal(value.executionLocation.kind, 'vmci-guest'); assert.equal(value.executionLocation.profileSha256, pin);
  assert.equal(value.executionLocation.guestCID, profile.guestCID); assert.equal(value.executionLocation.bundleSha256, profile.bundleSha256);
};
const report = { schema: 'ig5-public-guest-native-acceptance-v1', ok: false, configuredModelUsed: false,
  sourceRoot: path.resolve(import.meta.dirname, '..'), target, targetSha256: hash(target), guestCID: profile.guestCID, profileSha256: pin,
  bundleSha256: profile.bundleSha256, calls, approvals, ownedFixtureOnly: true, protectionBusinessRecoveryPassed: false };
try {
  assert.equal(definitions.size, 43);
  const inspected = await call('ig5_profile', { guest_debug: 'lab' }); assert.equal(inspected.guestDebug.bindingSha256, pin);
  const before = await call('ig5_status');
  if (before.remoteExecutions.length) await dbg('recover', { control: 'takeover' });
  if (process.env.IG5_GUEST_RECOVER_ONLY === '1') {
    assert.equal((await call('ig5_status')).remoteExecutions.length, 0);
    report.recoveryOnly = true; report.ok = true;
  } else {
  await call('ig5_open', { background: false });
  const beforeDenied = bridges.length;
  allowed = false; const denied = await dbg('load'); assert.equal(denied.kind, 'deny'); assert.equal(bridges.length, beforeDenied); allowed = true;
  await dbg('load'); const started = await dbg('start'); expectedLocation(started); assert.equal(started.state, 'suspended');
  await dbg('bpt', { rva: '0x1000' });
  let initial = await dbg('regs');
  const entry = '0x' + (BigInt(started.context.mainModuleBase) + 0x1000n).toString(16);
  for (let i = 0; initial.regs.rip !== entry && i < 4; i++) { await dbg('cont'); initial = await dbg('regs'); }
  assert.equal(initial.regs.rip, entry); await dbg('unbpt', { rva: '0x1000' });
  const captures = [];
  for (const [x,y] of [[0n,0n],[1n,2n],[0xffffffffffffffffn,3n],[0x123456789abcdef0n,0xfedcba9876543210n]]) {
    const current = await dbg('regs');
    for (const [reg,value] of [['rip',entry],['rsp',initial.regs.rsp],['rcx','0x'+x.toString(16)],['rdx','0x'+y.toString(16)]])
      await dbg('setreg', { reg, value, expected: current.regs[reg] });
    const recorded = await dbg('trace', { record_trace: true, record_image: true, max_steps: 2, trace_inputs: ['rcx','rdx'], trace_output: 'rax' });
    expectedLocation(recorded); assert.equal(recorded.traceSaved, true); assert.equal(recorded.nativeStepsPerformed, 2);
    assert.equal(recorded.traceSummary.stopReason, 'returned'); assert.equal(hash(recorded.tracePath), recorded.traceSha256);
    const saved = JSON.parse(fs.readFileSync(recorded.traceReportPath)); expectedLocation(saved.result);
    const recovered = await call('ig5_ir', recorded.recoveryArgs);
    assert.equal(recovered.paths[0].outputProof.status, 'unsat'); assert.equal(recovered.paths[0].finalSnapshotVerified, true);
    assert.equal(recovered.paths[0].observedOutput, '0x'+BigInt.asUintN(64,x+y).toString(16));
    assert.equal(recovered.wholeBinaryVerified, false); assert.equal(recovered.nativeTargetExecuted, false);
    captures.push({ x:'0x'+x.toString(16),y:'0x'+y.toString(16),traceReportPath:recorded.traceReportPath,traceReportSha256:recorded.traceReportSha256,output:recovered.paths[0].observedOutput,proof:recovered.paths[0].outputProof.status });
  }
  report.captures = captures;
  await assert.rejects(dbg('step', { expected_stop_seq: 0 }), /pause changed/);
  await dbg('stop'); assert.equal((await call('ig5_status')).remoteExecutions[0].state, 'active');
  await call('ig5_close'); assert.equal((await call('ig5_status')).remoteExecutions.length, 0);
  await call('ig5_open', { background: false });
  await dbg('load'); const second = await dbg('start'); expectedLocation(second);
  const current = await dbg('regs'); await dbg('setreg', { reg:'rip',value:'0x'+(BigInt(second.context.mainModuleBase)+0x1080n).toString(16),expected:current.regs.rip });
  const continued = dbg('cont', { timeout: 30 }).then(result => ({ result }), error => ({ error: { message: error.message, code:error.code } }));
  await wait(300);
  const bridge = bridges.at(-1); assert(bridge && bridge.exitCode === null && !bridge.killed);
  const exited = new Promise(resolve => bridge.once('exit', resolve)); bridge.kill(); await exited;
  const interrupted = await continued; assert(interrupted.error, 'bridge crash must not return native success');
  const lost = await call('ig5_status'); assert.equal(lost.remoteExecutions[0].state, 'unknown');
  const bridgeCount = bridges.length; await assert.rejects(dbg('start'), /retained/); assert.equal(bridges.length, bridgeCount);
  const repaired = await dbg('recover'); assert.equal(repaired.guestExecutionCleaned, true);
  assert.equal((await call('ig5_status')).remoteExecutions.length, 0);
  report.disconnectRecovery = { originalSessionId: second.executionLocation.sessionId, interrupted, recovered: repaired, rootBridgeExitObserved: true };
  await dbg('load'); await dbg('start'); await dbg('stop'); await call('ig5_close');
  assert.equal((await call('ig5_status')).remoteExecutions.length, 0);
  assert.equal(hash(target), report.targetSha256); assert.equal(hash(profileFile), pin);
  report.ok = true;
  }
} catch (error) { report.error = { message: error.message, code: error.code, stack: error.stack }; process.exitCode = 1; }
finally {
  for (const dispose of effects.reverse()) { try { await dispose(); } catch (error) { report.disposeError = error.message; report.ok = false; process.exitCode = 1; } }
  childProcess.spawn = spawnOriginal; syncBuiltinESMExports();
  const file = path.join(evidence, 'public-guest-native-' + randomUUID() + '.json'); fs.writeFileSync(file, JSON.stringify(report, null, 2));
  console.log(JSON.stringify({ ok: report.ok, report: file, calls: calls.length, approvals: approvals.length, captures: report.captures?.length || 0, error: report.error?.message }));
}
