// Verify an actual DSH-created readonly report against the owned native receipt.
// This verifier neither launches a target nor invokes the model/tools itself.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
const [base, id] = process.argv.slice(2);
assert(base && /^[0-9a-f-]{36}$/.test(id || ''), 'Supply modern evidence root and observed DSH report UUID');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const artifactRoot = path.dirname(path.resolve(base));
const recordPath = path.join(artifactRoot, 'trace-recovery/records', id + '.json');
const metadataPath = path.join(artifactRoot, 'trace-recovery/metadata', id + '.json');
const bytes = fs.readFileSync(recordPath), metadata = JSON.parse(fs.readFileSync(metadataPath));
assert.equal(sha(bytes), metadata.recordSha256);
const record = JSON.parse(bytes), result = record.result;
assert.equal(record.id, id); assert.equal(record.kind, 'trace'); assert.equal(record.action, 'recover');
const acceptancePath = path.join(base, 'native-compiled-add64-virtualization/acceptance.json');
const acceptance = JSON.parse(fs.readFileSync(acceptancePath));
assert.equal(result.targetSha256, acceptance.targetSha256);
assert.equal(result.ok, true); assert.equal(result.nativeTargetExecuted, false);
assert.equal(result.traceReplayed, true); assert.equal(result.databaseModified, false);
assert.equal(result.wholeBinaryVerified, false); assert.equal(result.coverage, 'trace-model-input-domain');
assert.equal(result.paths.length, 1);
const p = result.paths[0];
assert.equal(p.instructionCount, 25241); assert.equal(p.finalSnapshotVerified, true);
assert.equal(p.outputProof.status, 'unsat'); assert.equal(p.binaryBinding.allInstructionBytesMatch, true);
assert.equal(p.binaryBinding.loaderRelocationMatchedInstructions, 1);
assert.equal(p.binaryBinding.allOriginalFileInstructionBytesMatch, false);
assert.equal(p.traceSha256, acceptance.result.paths[0].traceSha256);
assert.deepEqual(result.recoveredExpression, acceptance.result.recoveredExpression);
assert.equal(p.unobservedContinuationInstructions, 1);
const evaluate = (node, x, y) => {
  if (node.op === 'input') { assert(['x', 'y'].includes(node.name)); return node.name === 'x' ? x : y; }
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
const startupLog = fs.readFileSync(path.join(artifactRoot, 'ig5-diag.log'), 'utf8').trimEnd().split('\n').slice(-5).join('\n');
assert(startupLog.includes('version 1.1.0'));
const output = { status: 'actual-DSH-recorded-function-model-verified', createdAt: new Date().toISOString(),
  observedDshReportId: id, recordPath, recordSha256: metadata.recordSha256, metadataPath,
  nativeAcceptancePath: acceptancePath, nativeAcceptanceSha256: sha(fs.readFileSync(acceptancePath)),
  producerVersion: acceptance.producerVersion, targetSha256: result.targetSha256, traceSha256: p.traceSha256,
  expression: result.recoveredExpression, instructions: p.instructionCount, independentReferencePairs: checked,
  finalSnapshotVerified: p.finalSnapshotVerified, outputProof: p.outputProof, binaryBinding: p.binaryBinding,
  unobservedContinuationInstructions: p.unobservedContinuationInstructions, coverage: result.coverage,
  wholeBinaryVerified: false, replayExecutedTarget: false, startupLog,
  limitations: ['The model replayed an existing owned native recording; no new native launch in DSH',
    'Function model under recorded environment assumptions, not whole-binary recovery',
    'One CPUID/flag continuation has no intermediate GPR snapshot and remains explicit'] };
fs.writeFileSync(path.join(base, 'dsh-verified.json'), JSON.stringify(output, null, 2) + '\n');
console.log(JSON.stringify({ status: output.status, reportId: id, instructions: p.instructionCount, checked, recordSha256: metadata.recordSha256 }));
