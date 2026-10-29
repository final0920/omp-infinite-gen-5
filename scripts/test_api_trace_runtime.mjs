// Explicit native acceptance for op=apitrace. Executes only a generated tmp PE
// fixture with a real KERNEL32 import table; it makes no network or DB writes.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { apply } from '../index.js';
import { buildPE64ImportFixture } from './fixtures/pe64-imports.mjs';

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-api-trace-'));
const target = path.join(scratch, 'api-trace-sample.exe');
const fixture = buildPE64ImportFixture();
fs.writeFileSync(target, fixture.image);
const targetSha256 = createHash('sha256').update(fixture.image).digest('hex');
const tools = new Map(), effects = [];
const ctx = {
  tools: { register(def) { tools.set(def.name, def); return () => tools.delete(def.name); } },
  get: () => undefined, on() {}, inject() { return { dispose() {} }; },
  effect(body) { const remove = body(); if (typeof remove === 'function') effects.push(remove); },
};
const call = (name, args = {}, agent = 'owner-one') => tools.get(name).execute({ target, engine: 'ghidra', ...args }, { agent: { id: agent } });
const dbg = (op, args = {}) => call('ig5_dbg', { backend: 'x64dbg', op, timeout: 10, ...args });
try {
  apply(ctx, { reverse: false, toolset: 'full', artifactDir: path.join(scratch, 'artifacts'), requestTimeoutMs: 120000 });
  await call('ig5_open', { path: target, background: false });
  assert.equal((await dbg('load')).targetExecuted, false);
  const started = await dbg('start');
  assert.equal(started.ok, true);
  assert.equal(started.state, 'suspended');

  // x64dbg's first pause is the loader breakpoint, before the IAT is resolved.
  // Reach the image entry point first, then remove that planning breakpoint.
  await dbg('bpt', { rva: '0x1000' });
  const entry = '0x' + (BigInt(started.context.mainModuleBase) + 0x1000n).toString(16);
  let regs = await dbg('regs');
  for (let attempt = 0; regs.regs.rip !== entry && attempt < 6; attempt++) {
    await dbg('cont');
    regs = await dbg('regs');
  }
  assert.equal(regs.regs.rip, entry);
  await dbg('unbpt', { rva: '0x1000' });
  // Independent check that the loader bound the import table in this debuggee.
  const iat = await dbg('readmem', { rva: '0x2400', size: 32 });
  const slots = Buffer.from(iat.hex, 'hex');
  assert.equal(slots.length, 32);
  for (let offset = 0; offset < 32; offset += 8) {
    assert.notEqual(slots.readBigUInt64LE(offset), 0n, 'IAT slot ' + offset + ' is unresolved');
  }

  const traced = await dbg('apitrace', {
    api_names: ['IsDebuggerPresent', 'GetTickCount64', 'Sleep'],
    max_api_calls: 3, timeout: 30,
  });
  assert.equal(traced.ok, true, traced.error);
  assert.equal(traced.schema, 'ig5.apiTrace.v1');
  assert.equal(traced.evidenceLevel, 'E1');
  assert.equal(traced.behaviorEvidenceLevel, 'E0');
  assert.equal(traced.nativeTargetExecuted, true);
  assert.equal(traced.state, 'suspended');
  assert.equal(traced.apiSet.selection.mode, 'requested');
  assert.equal(traced.apiSet.selectedCount, 3);
  assert.equal(traced.apiSet.breakpointsSet, 3);
  assert.deepEqual(traced.calls.map((row) => row.api), ['IsDebuggerPresent', 'GetTickCount64', 'Sleep']);
  assert.deepEqual(traced.calls.map((row) => row.callerRva), ['0x100a', '0x1010', '0x101b']);
  for (const row of traced.calls) {
    assert.equal(row.threadId, started.context.tid);
    assert.equal(row.argumentsUnavailable, null);
    assert.equal(row.pauseMatchesHit, true);
    assert.equal(row.callerInMainModule, true);
  }
  assert.deepEqual(traced.calls[2].arguments.values.find((item) => item.name === 'rcx'), { name: 'rcx', value: '0x1' });
  assert.equal(traced.coverage.stopReason, 'call-budget');
  assert.equal(traced.coverage.callsRecorded, 3);
  assert.equal(traced.coverage.callsTruncated, true);
  assert.equal(traced.coverage.breakpointCleanup.attempted, true);
  assert.equal(traced.coverage.breakpointCleanup.cleared, true);
  assert.ok(traced.behavior.categories.some((row) => row.category === 'debug-detection'));
  assert.equal(traced.behavior.evidenceLevel, 'E0');

  assert.equal(traced.apiTraceSaved, true, traced.apiTraceArtifactError);
  assert.ok(fs.existsSync(traced.apiTraceReportPath));
  const report = JSON.parse(fs.readFileSync(traced.apiTraceReportPath, 'utf8'));
  assert.equal(report.kind, 'api-trace');
  assert.equal(report.action, 'trace');
  assert.equal(report.result.calls.length, 3);
  assert.equal(report.result.targetSha256, targetSha256);
  assert.equal(report.result.databaseModified, false);
  assert.deepEqual(report.result.request, { api_names: ['IsDebuggerPresent', 'GetTickCount64', 'Sleep'], max_api_calls: 3, max_apis: null });
  assert.match(traced.apiTraceReportSha256, /^[a-f0-9]{64}$/);

  const exited = await dbg('cont', { timeout: 10 });
  assert.equal(exited.state, 'no-task');
  assert.deepEqual(fs.readFileSync(target), fixture.image);
  console.log(JSON.stringify({
    schema: 'ig5.api-trace-runtime.v1',
    calls: traced.calls.map((row) => ({ api: row.api, callerRva: row.callerRva, threadId: row.threadId })),
    stopReason: traced.coverage.stopReason,
    cleanupCleared: traced.coverage.breakpointCleanup.cleared,
    artifactSaved: traced.apiTraceSaved,
    targetUnchanged: true,
    nativeTargetExecuted: traced.nativeTargetExecuted,
  }));
} finally {
  try { const state = await dbg('state'); if (state.state !== 'no-task') await dbg('stop'); } catch {}
  for (const remove of effects.reverse()) await remove();
  assert.equal(path.dirname(path.resolve(scratch)), path.resolve(os.tmpdir()));
  assert.ok(path.basename(scratch).startsWith('ig5-api-trace-'));
  await fs.promises.rm(scratch, { recursive: true, force: true, maxRetries: 30, retryDelay: 100 });
}
