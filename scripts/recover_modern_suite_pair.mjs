// Join each OWN run independently, then use the public readonly trace tool.
// No reference expression or branch predicate is supplied to recovery.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { apply } from '../index.js';
import { joinRecordedTrace } from '../source/debug_trace_chunks.js';
import { AnalysisArtifacts } from '../source/analysis_artifacts.js';
const [left, right, destination] = process.argv.slice(2).map(value => path.resolve(value));
assert(left && right && destination && left !== right && !fs.existsSync(destination), 'Supply two distinct completed owned recordings and a fresh evidence folder');
const hash = data => createHash('sha256').update(data).digest('hex');
const originals = [left, right].map(folder => {
  const receiptPath = path.join(folder, 'receipt.json'), bytes = fs.readFileSync(receiptPath), receipt = JSON.parse(bytes);
  assert(['owned-compiled-suite-c-v1', 'owned-packed-suite-c-v1', 'owned-enigma-suite-c-v1', 'owned-enigma-suite-c-v2'].includes(receipt.generatedCase.recipe));
  assert.equal(receipt.parts.at(-1).summary.stopReason, 'until-address'); assert.equal(receipt.targetUnchanged, true);
  assert.equal(hash(fs.readFileSync(receipt.target)), receipt.generatedCase.targetSha256);
  return { folder, receiptPath, bytes, receipt };
});
assert.equal(originals[0].receipt.generatedCase.id, originals[1].receipt.generatedCase.id);
assert.equal(originals[0].receipt.generatedCase.targetSha256, originals[1].receipt.generatedCase.targetSha256);
fs.mkdirSync(destination, { recursive: true });
fs.writeFileSync(path.join(destination, 'receipt.json'), originals[0].bytes);
const store = new AnalysisArtifacts(path.join(destination, 'trace-recovery')), traces = [];
for (const { folder, receipt } of originals) {
  const joined = await joinRecordedTrace({ artifactDir: folder }, receipt.parts.map(row => row.reportId), receipt.generatedCase.targetSha256, receipt.maxInstructions ?? 50000);
  const blob = store.put(joined.data);
  traces.push({ path: path.join(store.root, 'blobs', blob.sha256 + '.bin'), sha256: blob.sha256,
    ...(joined.imageReference ? { trace_image: joined.imageReference } : {}),
    recording: { entry: receipt.parts[0].summary.entry, exit: receipt.parts.at(-1).summary.exit,
      runtimeBase: joined.runtimeBase, initialFlags: receipt.parts[0].summary.initialFlags } });
}
const definitions = new Map(), effects = [];
const ctx = { tools: { register(d) { definitions.set(d.name, d); return () => definitions.delete(d.name); } }, get() {}, on() {},
  inject() { return { dispose() {} }; }, effect(callback) { const dispose = callback(); if (typeof dispose === 'function') effects.push(dispose); } };
apply(ctx, { reverse: false, toolset: 'full', artifactDir: destination, projectRoot: path.join(destination, 'projects') });
try {
  const receipt = originals[0].receipt;
  const args = { target: receipt.target, level: 'trace', traces, trace_entry: traces[0].recording.entry, trace_exit: traces[0].recording.exit,
    trace_runtime_base: traces[0].recording.runtimeBase, trace_inputs: receipt.generatedCase.inputs, trace_output: receipt.generatedCase.output,
    initial_flags: traces[0].recording.initialFlags, max_instructions: Math.max(...originals.map(row => row.receipt.maxInstructions ?? 50000)) };
  const result = await definitions.get('ig5_ir').execute(args, { agent: { id: 'owned-modern-suite-two-path-validation' } });
  fs.writeFileSync(path.join(destination, 'revalidation.json'), JSON.stringify({ sourceReceiptSha256: hash(originals[0].bytes),
    additionalSourceReceipts: originals.map(row => ({ path: row.receiptPath, sha256: hash(row.bytes) })), args, result }, null, 2));
  console.log(JSON.stringify({ ok: result.ok, coverage: result.coverage, expression: result.recoveredExpression,
    instructions: result.paths.map(row => row.instructionCount), reportId: result.reportId, reportSha256: result.reportSha256 }));
} catch (error) {
  fs.writeFileSync(path.join(destination, 'failure.json'), JSON.stringify({ status: 'readonly-pair-recovery-failed',
    message: error.message, code: error.code || null, sourceReceipts: originals.map(row => ({ path: row.receiptPath, sha256: hash(row.bytes) })),
    wholeBinaryVerified: false, accepted: false }, null, 2));
  throw error;
} finally { for (const dispose of effects.reverse()) await dispose(); await store.dispose(); }
