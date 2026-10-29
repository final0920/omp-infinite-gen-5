// Public readonly tool validation of a COMPLETE owned native function recording.
// No target launch, upstream source execution, or reference formula sent to tool.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { apply } from '../index.js';
const folder = path.resolve(process.argv[2] || '');
if (!process.argv[2]) throw new Error('Supply completed owned native receipt folder');
const receipt = JSON.parse(fs.readFileSync(path.join(folder, 'receipt.json'), 'utf8'));
assert.equal(receipt.generatedCase.recipe, 'owned-compiled-c-v1');
assert.equal(receipt.parts.at(-1).summary.stopReason, 'until-address');
const hash = data => createHash('sha256').update(data).digest('hex');
assert.equal(hash(fs.readFileSync(receipt.target)), receipt.generatedCase.targetSha256);
const definitions = new Map(), effects = [];
const ctx = { tools: { register(d) { definitions.set(d.name, d); return () => definitions.delete(d.name); } }, get() {}, on() {},
  inject() { return { dispose() {} }; }, effect(callback) { const dispose = callback(); if (typeof dispose === 'function') effects.push(dispose); } };
apply(ctx, { reverse: false, toolset: 'full', artifactDir: folder, projectRoot: path.join(folder, 'projects') });
try {
  const args = { target: receipt.target, level: 'trace', trace_chunk_reports: receipt.parts.map(row => row.reportId),
    trace_entry: receipt.parts[0].summary.entry, trace_exit: receipt.parts.at(-1).summary.exit,
    trace_inputs: receipt.generatedCase.inputs, trace_output: receipt.generatedCase.output, initial_flags: receipt.parts[0].summary.initialFlags };
  const result = await definitions.get('ig5_ir').execute(args, { agent: { id: 'owned-modern-readonly-validation' } });
  assert.equal(result.paths[0].outputProof.status, 'unsat');
  assert(result.paths[0].finalSnapshotVerified && result.paths[0].binaryBinding.allInstructionBytesMatch);
  assert.equal(result.paths[0].observedOutput, '0x3'); assert.equal(result.coverage, 'trace-model-input-domain');
  assert.equal(result.wholeBinaryVerified, false); assert.equal(result.nativeTargetExecuted, false);
  const evaluate = (node, x, y) => {
    if (node.op === 'input') return node.name === 'x' ? x : y;
    if (node.op === 'constant') return BigInt(node.value);
    assert.equal(node.op, 'add'); return BigInt.asUintN(node.bits, node.args.reduce((sum, child) => sum + evaluate(child, x, y), 0n));
  };
  const values = [0n, 1n, 2n, (1n << 31n) - 1n, 1n << 31n, (1n << 32n) - 1n, 1n << 32n, (1n << 63n) - 1n, 1n << 63n, (1n << 64n) - 1n];
  let checked = 0, seed = 0xc0ffee12345678n;
  for (const x of values) for (const y of values) { assert.equal(evaluate(result.recoveredExpression, x, y), BigInt.asUintN(64, x + y)); checked++; }
  for (let n = 0; n < 1024; n++) {
    seed = BigInt.asUintN(64, seed * 6364136223846793005n + 1442695040888963407n); const x = seed;
    seed = BigInt.asUintN(64, seed * 6364136223846793005n + 1442695040888963407n); const y = seed;
    assert.equal(evaluate(result.recoveredExpression, x, y), BigInt.asUintN(64, x + y)); checked++;
  }
  const acceptance = { status: 'recorded-function-model-verified', producerVersion: '3.11.0 build 2835 Demo', targetSha256: receipt.generatedCase.targetSha256,
    nativeRecordingExecutedOwnedTarget: true, recoveryExecutedTarget: false, downloadedChallengesExecuted: false, wholeBinaryVerified: false,
    sourceReceiptSha256: hash(fs.readFileSync(path.join(folder, 'receipt.json'))), independentReferencePairs: checked,
    referenceWasNotSuppliedToRecovery: true, args, result };
  fs.writeFileSync(path.join(folder, 'acceptance.json'), JSON.stringify(acceptance, null, 2));
  console.log(JSON.stringify({ status: acceptance.status, expression: result.recoveredExpression, instructions: result.paths[0].instructionCount,
    unobservedContinuations: result.paths[0].unobservedContinuationInstructions, referencePairs: checked,
    reportPath: result.reportPath, reportSha256: result.reportSha256, wholeBinaryVerified: false }));
} finally { for (const dispose of effects.reverse()) await dispose(); }
