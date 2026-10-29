// Native execution is limited to an IG5-generated PE leaf in a private directory.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { apply } from '../index.js';
import { buildPE64Fixture } from './fixtures/pe64.mjs';

const evidence = process.env.IG5_DYNAMIC_EVIDENCE || 'C:/Users/IG5User/.dsh/ig5/artifacts/dynamic-trace-20261014';
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-dynamic-trace-'));
fs.mkdirSync(evidence, { recursive: true });
const target = path.join(scratch, '五代自产加法.exe'), fixture = buildPE64Fixture();
// Real Win64 loader relocation/ASLR, with a harmless relocated data pointer.
fixture.image.writeUInt16LE(0x160, 0x98 + 70);
fixture.image.writeUInt32LE(0x3d00, 0x98 + 112 + 5 * 8);
fixture.image.writeUInt32LE(24, 0x98 + 116 + 5 * 8);
fixture.image.writeBigUInt64LE(0x140001000n, 0x1a00);
fixture.image.writeUInt32LE(0x3000, 0x1b00);
fixture.image.writeUInt32LE(12, 0x1b04);
fixture.image.writeUInt16LE(0xac00, 0x1b08);
fixture.image.writeUInt16LE(0, 0x1b0a);
fixture.image.writeUInt32LE(0x1000, 0x1b0c);
fixture.image.writeUInt32LE(12, 0x1b10);
fixture.image.writeUInt16LE(0xa3f2, 0x1b14);
fixture.image.writeUInt16LE(0, 0x1b16);
// A second leaf uses input-dependent stack stores/reads and restores RBX.
Buffer.from('5389cb31d3538b04245b5bc3', 'hex').copy(fixture.image, 0x760);
// Actual high-byte result parity, rather than the preserved CL byte.
Buffer.from('89d022ec0f9ac0c3', 'hex').copy(fixture.image, 0x7d0);
Buffer.from('48b80010004001000000c3', 'hex').copy(fixture.image, 0x7f0);
// Real timestamp instructions retain x in R8; no clock value is fabricated.
Buffer.from('4989c80f314c89c0c3', 'hex').copy(fixture.image, 0x780);
Buffer.from('4989c80f01f94c89c0c3', 'hex').copy(fixture.image, 0x790);
// CPUID extended feature query, with a safe adjacent NOP for coalesced stops.
Buffer.from('b8010000800fa290c3', 'hex').copy(fixture.image, 0x7a0);
fs.writeFileSync(target, fixture.image);
const definitions = new Map(), effects = [], hooks = new Map();
const ctx = { tools: { register(d) { definitions.set(d.name, d); return () => definitions.delete(d.name); } },
  get() {}, on(name, callback) { hooks.set(name, callback); return () => hooks.delete(name); },
  inject(names, callback) { if (names.includes('webServer')) callback({ webServer: { register() { return () => {}; } } }); return { dispose() {} }; },
  effect(callback) { const dispose = callback(); if (typeof dispose === 'function') effects.push(dispose); },
};
apply(ctx, { reverse: false, reverseProvider: 'bundled', toolset: 'full', artifactDir: evidence, projectRoot: path.join(scratch, 'projects'), requestTimeoutMs: 120000 });
const rows = [];
const call = async (name, args) => {
  const result = await definitions.get(name).execute({ target, engine: 'ghidra', ...args }, { agent: { id: 'owned-native-trace-fixture-test' }, signal: new AbortController().signal });
  rows.push({ name, args, result }); return result;
};
const dbg = (op, args = {}) => call('ig5_dbg', { backend: 'x64dbg', op, timeout: 30, ...args });
try {
  assert.equal(definitions.size, 43);
  await call('ig5_open', { path: target, background: false });
  let dispatched = false;
  const gate = await hooks.get('tools/pre-execute')({ name: 'ig5_dbg', arguments: { target, op: 'trace', record_trace: true } }, () => { dispatched = true; });
  assert.equal(gate.kind, 'deny'); assert.equal(dispatched, false);
  await dbg('load');
  const started = await dbg('start'); assert.equal(started.state, 'suspended');
  const entry = '0x' + (BigInt(started.context.mainModuleBase) + 0x1000n).toString(16);
  await dbg('bpt', { rva: '0x1000' });
  let regs = await dbg('regs');
  for (let i = 0; regs.regs.rip !== entry && i < 4; i++) { await dbg('cont'); regs = await dbg('regs'); }
  assert.equal(regs.regs.rip, entry);
  await dbg('unbpt', { rva: '0x1000' });
  await dbg('setreg', { reg: 'rcx', value: '0xffffffffffffffff', expected: regs.regs.rcx });
  await dbg('setreg', { reg: 'rdx', value: '0x3', expected: regs.regs.rdx });
  await assert.rejects(dbg('trace', { record_trace: true, max_steps: 513 }), /1\.\.512/);
  const trace = await dbg('trace', { record_trace: true, record_image: true, max_steps: 2, trace_inputs: ['rcx', 'rdx'], trace_output: 'rax' });
  assert(trace.traceSaved && trace.recoveryReady);
  assert.equal(trace.traceSummary.instructionCount, 2);
  assert.equal(trace.traceSummary.stopReason, 'returned');
  assert.equal(trace.nativeStepsPerformed, 2);
  assert.equal(createHash('sha256').update(fs.readFileSync(trace.tracePath)).digest('hex'), trace.traceSha256);
  assert.equal(trace.traceSummary.wholeFunctionCoverageProved, false);
  assert.equal(trace.loadedImage.schema, 'ig5.native-main-image.v1');
  assert.equal(trace.loadedImage.stopSeq, trace.traceSummary.startStopSeq);
  assert(trace.recoveryArgs.trace_image.report_sha256);
  const result = await call('ig5_ir', trace.recoveryArgs);
  assert.equal(result.nativeTargetExecuted, false); assert.equal(result.databaseModified, false); assert.equal(result.wholeBinaryVerified, false);
  assert(result.paths[0].binaryBinding.allInstructionBytesMatch);
  assert.equal(result.paths[0].binaryBinding.capturedImageMatchedInstructions, 2);
  assert.equal(result.paths[0].finalSnapshotVerified, true);
  assert.equal(result.paths[0].observedOutput, '0x2');
  assert.equal(result.paths[0].outputProof.status, 'unsat');
  assert.equal(result.recoveredExpression.op, 'add');
  assert.equal((await dbg('regs')).regs.rax, '0x2');
  let current = await dbg('regs');
  await dbg('setreg', { reg: 'rsp', value: regs.regs.rsp, expected: current.regs.rsp });
  await dbg('setreg', { reg: 'rip', value: '0x' + (BigInt(started.context.mainModuleBase) + 0x1360n).toString(16), expected: current.regs.rip });
  await dbg('setreg', { reg: 'rcx', value: '0xffffffff', expected: current.regs.rcx });
  await dbg('setreg', { reg: 'rdx', value: '0x5', expected: current.regs.rdx });
  const memoryTrace = await dbg('trace', { record_trace: true, max_steps: 8, trace_inputs: ['ecx', 'edx'], trace_output: 'eax' });
  assert.equal(memoryTrace.traceSummary.instructionCount, 8);
  assert.equal(memoryTrace.traceSummary.stopReason, 'returned');
  assert.equal(fs.readFileSync(memoryTrace.tracePath, 'utf8').split('\n').filter(line => line.startsWith('mr:')).length, 4);
  const memoryResult = await call('ig5_ir', memoryTrace.recoveryArgs);
  assert.equal(memoryResult.recoveredExpression.op, 'xor');
  assert.equal(memoryResult.paths[0].observedOutput, '0xfffffffa');
  assert.equal(memoryResult.paths[0].outputProof.status, 'unsat');
  assert(memoryResult.paths[0].binaryBinding.allInstructionBytesMatch && memoryResult.paths[0].finalSnapshotVerified);
  assert.equal((await dbg('regs')).regs.rbx, current.regs.rbx);
  const beforeParity = await dbg('regs');
  await dbg('setreg', { reg: 'rsp', value: regs.regs.rsp, expected: beforeParity.regs.rsp });
  await dbg('setreg', { reg: 'rip', value: '0x' + (BigInt(started.context.mainModuleBase) + 0x13d0n).toString(16), expected: beforeParity.regs.rip });
  await dbg('setreg', { reg: 'rcx', value: '0x1', expected: beforeParity.regs.rcx });
  await dbg('setreg', { reg: 'rdx', value: '0xf900', expected: beforeParity.regs.rdx });
  const parityTrace = await dbg('trace', { record_trace: true, max_steps: 4, trace_inputs: ['ecx', 'edx'], trace_output: 'al' });
  const parityResult = await call('ig5_ir', parityTrace.recoveryArgs);
  assert.equal(parityResult.paths[0].observedOutput, '0x1');
  assert.equal(parityResult.paths[0].outputProof.status, 'unsat');
  const parityReport = fs.readFileSync(parityResult.reportPath);
  assert.equal(createHash('sha256').update(parityReport).digest('hex'), parityResult.reportSha256);
  assert(JSON.parse(parityReport).result.paths[0].semanticCorrections.some(row => row.flag === 'PF'));
  const beforeRelocation = await dbg('regs');
  await dbg('setreg', { reg: 'rsp', value: regs.regs.rsp, expected: beforeRelocation.regs.rsp });
  await dbg('setreg', { reg: 'rip', value: '0x' + (BigInt(started.context.mainModuleBase) + 0x13f0n).toString(16), expected: beforeRelocation.regs.rip });
  const relocationTrace = await dbg('trace', { record_trace: true, max_steps: 2, trace_inputs: ['rcx', 'rdx'], trace_output: 'rax' });
  const relocationResult = await call('ig5_ir', relocationTrace.recoveryArgs);
  assert.equal(relocationResult.paths[0].observedOutput, '0x' + (BigInt(started.context.mainModuleBase) + 0x1000n).toString(16));
  assert(relocationResult.paths[0].binaryBinding.allInstructionBytesMatch);
  if (started.context.mainModuleBase !== '0x140000000') {
    assert.equal(relocationResult.paths[0].binaryBinding.loaderRelocationMatchedInstructions, 1);
    assert.equal(relocationResult.paths[0].binaryBinding.allOriginalFileInstructionBytesMatch, false);
  }
  const beforeFeature = await dbg('regs');
  await dbg('setreg', { reg: 'rsp', value: regs.regs.rsp, expected: beforeFeature.regs.rsp });
  await dbg('setreg', { reg: 'rip', value: '0x' + (BigInt(started.context.mainModuleBase) + 0x13a0n).toString(16), expected: beforeFeature.regs.rip });
  const featureTrace = await dbg('trace', { record_trace: true, max_steps: 4, trace_inputs: ['rdi', 'rsi'], trace_output: 'rax' });
  assert.equal(featureTrace.traceSummary.stopReason, 'returned');
  const rdtscpSupported = (BigInt((await dbg('regs')).regs.rdx) & (1n << 27n)) !== 0n;
  const timestampCases = [[0x1380n, 'rdtsc'], ...(rdtscpSupported ? [[0x1390n, 'rdtscp']] : [])];
  console.log(JSON.stringify({ rdtscpHardwareSupported: rdtscpSupported, source: 'owned-native-CPUID-80000001-EDX-bit27' }));
  for (const [rva, operation] of timestampCases) {
    const beforeClock = await dbg('regs');
    await dbg('setreg', { reg: 'rsp', value: regs.regs.rsp, expected: beforeClock.regs.rsp });
    await dbg('setreg', { reg: 'rip', value: '0x' + (BigInt(started.context.mainModuleBase) + rva).toString(16), expected: beforeClock.regs.rip });
    await dbg('setreg', { reg: 'rcx', value: '0xfeed123456789abc', expected: beforeClock.regs.rcx });
    const clockTrace = await dbg('trace', { record_trace: true, max_steps: 4, trace_inputs: ['rcx', 'rdx'], trace_output: 'rax' });
    assert.equal(clockTrace.traceSummary.stopReason, 'returned');
    const clockResult = await call('ig5_ir', clockTrace.recoveryArgs);
    assert.equal(clockResult.paths[0].observedOutput, '0xfeed123456789abc');
    assert.equal(clockResult.recoveredExpression.name, 'x');
    assert.equal(clockResult.paths[0].outputDependsOnEnvironmentUnknowns, false);
    assert(clockResult.paths[0].environmentReads.some(row => row.operation === operation));
    assert(clockResult.paths[0].binaryBinding.allInstructionBytesMatch && clockResult.paths[0].finalSnapshotVerified);
  }
  const paused = await dbg('regs');
  await dbg('setreg', { reg: 'rip', value: '0x' + (BigInt(started.context.mainModuleBase) + 0x1080n).toString(16), expected: paused.regs.rip });
  const loopTrace = await dbg('trace', { record_trace: true, max_steps: 128, trace_inputs: ['rcx', 'rdx'], trace_output: 'rax' });
  assert.equal(loopTrace.traceSummary.instructionCount, 128);
  assert.equal(loopTrace.traceSummary.stopReason, 'instruction-budget');
  assert.equal(loopTrace.traceSummary.endStopSeq - loopTrace.traceSummary.startStopSeq, 128);
  assert(loopTrace.traceSummary.finalSnapshotIncluded && loopTrace.traceSummary.wholeFunctionCoverageProved === false);
  console.log(JSON.stringify({ recordedWindow: 128, elapsedMs: loopTrace.traceSummary.elapsedMs, nativeFinalSnapshot: true, fullFunctionClaimed: false }));
  const continued = dbg('cont').then(result => ({ result }), error => ({ error }));
  await new Promise(resolve => setTimeout(resolve, 300));
  const interrupted = await dbg('suspend', { interrupt_method: 'break-process' });
  assert.equal(interrupted.state, 'suspended'); assert.equal(interrupted.interruptMethod, 'break-process');
  assert.equal(interrupted.eventName, 'exception'); assert.equal(interrupted.context.exception.code, '0x80000003');
  const continuation = await continued; if (continuation.error) throw continuation.error;
  assert.equal(continuation.result.interruptedBy, 'suspend');
  const selected = await dbg('regs', { thread_id: started.context.tid });
  assert.equal(selected.selectedThreadRegs.rip, '0x' + (BigInt(started.context.mainModuleBase) + 0x1080n).toString(16));
  assert.equal(selected.activeDebuggerThreadChanged, false); assert.equal(selected.regs, undefined);
  assert.equal((await dbg('stop')).state, 'no-task');
  assert.deepEqual(fs.readFileSync(target), fixture.image);
  fs.writeFileSync(path.join(evidence, 'acceptance.json'), JSON.stringify({ ok: true, target, pluginRoot: path.resolve(import.meta.dirname, '..'),
    externalTargetsExecuted: false, generatedTargetExecuted: true, databaseModified: false, rows }, null, 2));
  console.log(JSON.stringify({ ok: true, runtimeBase: trace.traceSummary.runtimeBase, aslrMoved: trace.traceSummary.runtimeBase !== '0x140000000', tracePath: trace.tracePath, recordedInstructions: trace.traceSummary.instructionCount, expression: result.recoveredExpression, observed: result.paths[0].observedOutput }));
} catch (error) {
  fs.writeFileSync(path.join(evidence, 'failed.json'), JSON.stringify({ error: error.message, rows }, null, 2)); throw error;
} finally { for (const dispose of effects.reverse()) await dispose(); }
