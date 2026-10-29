// Opt-in native acceptance of our compiler-bound thread-visibility fixture.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { apply } from '../index.js';
const [generationRoot, evidenceRoot] = process.argv.slice(2).map(p => path.resolve(p));
assert(generationRoot && evidenceRoot && !fs.existsSync(evidenceRoot), 'Supply own compiler proof and a fresh evidence directory');
const sha = data => createHash('sha256').update(data).digest('hex');
const proofBytes = fs.readFileSync(path.join(generationRoot, 'compiler-proof.json')), proof = JSON.parse(proofBytes);
assert.equal(proof.schema, 'ig5.owned-thread-visibility.v1');
assert.equal(proof.sourceSHA256, sha(fs.readFileSync(new URL('./fixtures/debug_hidden_thread.c', import.meta.url))));
assert.equal(proof.targetSHA256, sha(fs.readFileSync(proof.target)));
fs.mkdirSync(evidenceRoot);
const tools = new Map(), effects = [], receipt = { sourceProofSHA256: sha(proofBytes), target: proof.target, targetSHA256: proof.targetSHA256,
  nativeExecutedOwnedFixture: false, thirdPartySamplesExecuted: false, calls: [], status: 'starting' };
const save = () => fs.writeFileSync(path.join(evidenceRoot, 'receipt.json'), JSON.stringify(receipt, null, 2));
const ctx = { tools: { register(d) { tools.set(d.name, d); return () => tools.delete(d.name); } }, get() {}, on() {},
  inject() { return { dispose() {} }; }, effect(callback) { const d = callback(); if (typeof d === 'function') effects.push(d); } };
apply(ctx, { reverse: false, toolset: 'full', artifactDir: evidenceRoot, projectRoot: path.join(evidenceRoot, 'projects'), requestTimeoutMs: 120000 });
const call = async (name, args) => { const result = await tools.get(name).execute(args, { agent: { id: 'owned-thread-visibility-native-test' } }); receipt.calls.push({ name, args, result }); save(); return result; };
const dbg = (op, args = {}) => call('ig5_dbg', { target: proof.target, engine: 'ghidra', backend: 'x64dbg', op, timeout: 45, ...args });
try {
  await call('ig5_open', { path: proof.target, engine: 'ghidra', background: false, analysis_timeout: 20 });
  const antiDebug = process.env.IG5_SCYLLAHIDE_TEST === '1';
  await dbg('load'); const started = await dbg('start', antiDebug ? { anti_debug_profile: 'scyllahide-thread-context' } : {}); receipt.nativeExecutedOwnedFixture = true;
  if (antiDebug) { receipt.antiDebugEnvironment = started.antiDebugEnvironment; assert.equal(receipt.antiDebugEnvironment.installationConfirmedBySidecar, true); }
  receipt.mainThreadId = started.context.tid;
  receipt.before = await dbg('regs', { thread_id: receipt.mainThreadId });
  assert.equal(receipt.before.selectedThreadDebuggerVisibility.hiddenFromDebugger, false);
  for (let n = 0; n < 8; n++) {
    const stop = await dbg('cont'); assert.equal(stop.state, 'suspended');
    if (stop.context.tid !== receipt.mainThreadId) { receipt.observerThreadId = stop.context.tid; break; }
  }
  assert(receipt.observerThreadId, 'Visible helper trap was not reached');
  const active = await dbg('regs');
  receipt.hiddenMain = await dbg('regs', { thread_id: receipt.mainThreadId });
  receipt.visibleObserver = await dbg('regs', { thread_id: receipt.observerThreadId });
  const after = await dbg('regs');
  assert.equal(receipt.hiddenMain.selectedThreadDebuggerVisibility.hiddenFromDebugger, !antiDebug);
  assert.equal(receipt.visibleObserver.selectedThreadDebuggerVisibility.hiddenFromDebugger, false);
  assert.equal(receipt.hiddenMain.activeDebuggerThreadChanged, false);
  assert.deepEqual(after.regs, active.regs);
  assert.equal(after.context.tid, active.context.tid); assert.equal(after.context.stopSeq, active.context.stopSeq);
  receipt.status = antiDebug ? 'owned-scyllahide-thread-hide-prevention-verified' : 'owned-hidden-and-visible-thread-observations-verified';
} catch (error) { receipt.status = 'failed'; receipt.error = error.message; throw error; }
finally {
  try { await dbg('stop'); } catch (error) { receipt.stopError = error.message; }
  for (const dispose of effects.reverse()) await dispose();
  receipt.targetUnchanged = sha(fs.readFileSync(proof.target)) === proof.targetSHA256; save();
  console.log(JSON.stringify({ status: receipt.status, targetUnchanged: receipt.targetUnchanged, main: receipt.mainThreadId, observer: receipt.observerThreadId }));
}
