// Bind a freshly observed DSH readonly report to the independently checked
// owned native suite recording. No target/model execution occurs here.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
const [base, id, folderName, outputLabel] = process.argv.slice(2);
assert(!outputLabel || /^[a-z0-9-]{1,70}$/.test(outputLabel), 'Use a bounded evidence output label');
assert(base && /^[0-9a-f-]{36}$/.test(id || '') && /^native-[a-z0-9-]{1,100}$/.test(folderName || ''), 'Supply evidence root, observed report UUID and owned receipt folder name');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const artifactRoot = path.dirname(path.resolve(base));
const recordPath = path.join(artifactRoot, 'trace-recovery/records', id + '.json');
const metadataPath = path.join(artifactRoot, 'trace-recovery/metadata', id + '.json');
const bytes = fs.readFileSync(recordPath), metadata = JSON.parse(fs.readFileSync(metadataPath));
assert.equal(sha(bytes), metadata.recordSha256);
const record = JSON.parse(bytes), result = record.result;
assert.equal(record.id, id); assert.equal(record.kind, 'trace'); assert.equal(record.action, 'recover');
const acceptancePath = path.join(base, folderName, 'acceptance.json'), acceptanceBytes = fs.readFileSync(acceptancePath), acceptance = JSON.parse(acceptanceBytes);
assert.equal(acceptance.status, 'owned-compiled-suite-function-model-verified');
assert.equal(acceptance.independentReferencePairs, 2409);
const sourceProofPath = path.join(base, folderName, 'source-reference-proof.json'), sourceProofBytes = fs.readFileSync(sourceProofPath), sourceProof = JSON.parse(sourceProofBytes);
assert.equal(sourceProof.nativeAcceptanceSha256, sha(acceptanceBytes));
assert.equal(sourceProof.result, 'all-unsat');
assert.equal(sourceProof.wholeBinaryVerified, false); assert.equal(sourceProof.referenceWasNotSuppliedToRecovery, true);
assert(sourceProof.classes.length > 0 && sourceProof.classes.every(row => row.proof.status === 'unsat'));
assert.equal(result.targetSha256, acceptance.targetSha256);
assert.equal(result.ok, true); assert.equal(result.nativeTargetExecuted, false);
assert.equal(result.traceReplayed, true); assert.equal(result.databaseModified, false);
assert.equal(result.wholeBinaryVerified, false); assert.equal(result.coverage, 'trace-model-input-domain');
assert.equal(result.paths.length, acceptance.result.paths.length);
assert.deepEqual(result.inputs, acceptance.result.inputs);
assert.deepEqual(result.output, acceptance.result.output);
if (acceptance.result.proofScope) assert.deepEqual(result.proofScope, acceptance.result.proofScope);
for (let index = 0; index < result.paths.length; index++) {
const p = result.paths[index], reference = acceptance.result.paths[index];
assert.equal(p.instructionCount, reference.instructionCount); assert.equal(p.finalSnapshotVerified, true);
assert.equal(p.outputProof.status, 'unsat'); assert.equal(p.binaryBinding.allInstructionBytesMatch, true);
assert.equal(p.traceSha256, reference.traceSha256);
assert.deepEqual(result.recoveredExpression, acceptance.result.recoveredExpression);
assert.equal(p.outputDependsOnEnvironmentUnknowns, false);
assert.equal(p.unobservedContinuationInstructions, reference.unobservedContinuationInstructions);
assert.deepEqual(p.recording, reference.recording);
if (reference.binaryBinding.capturedImageEvidence) {
  assert.deepEqual(p.binaryBinding.capturedImageEvidence, reference.binaryBinding.capturedImageEvidence);
  assert.equal(p.binaryBinding.allOriginalFileInstructionBytesMatch, reference.binaryBinding.allOriginalFileInstructionBytesMatch);
}
if (result.paths.length === 2) assert.equal(p.guard.proof.status, 'unsat');
}
if (result.paths.length === 2) {
  assert.equal(result.coverageProof.disjoint.status, 'unsat'); assert.equal(result.coverageProof.exhaustive.status, 'unsat');
}
const p = result.paths[0];
const output = { status: 'actual-DSH-owned-suite-function-model-verified', createdAt: new Date().toISOString(),
  case: acceptance.id, observedDshReportId: id, recordPath, recordSha256: metadata.recordSha256, metadataPath,
  nativeAcceptancePath: acceptancePath, nativeAcceptanceSha256: sha(acceptanceBytes),
  sourceProofPath, sourceProofSha256: sha(sourceProofBytes), sourceReferenceInputDomain: sourceProof.inputDomain,
  producerVersion: acceptance.producerVersion, producer: acceptance.producer, targetSha256: result.targetSha256, traceSha256: p.traceSha256,
  expression: result.recoveredExpression, instructions: result.paths.reduce((sum, row) => sum + row.instructionCount, 0),
  paths: result.paths.map(row => ({ traceSha256: row.traceSha256, instructionCount: row.instructionCount,
    recording: row.recording, guard: row.guard?.conditionExpression, finalSnapshotVerified: row.finalSnapshotVerified,
    outputProof: row.outputProof, binaryBinding: row.binaryBinding, unobservedContinuationInstructions: row.unobservedContinuationInstructions })),
  independentReferencePairs: acceptance.independentReferencePairs,
  finalSnapshotVerified: p.finalSnapshotVerified, outputProof: p.outputProof, binaryBinding: p.binaryBinding,
  unobservedContinuationInstructions: p.unobservedContinuationInstructions, coverage: result.coverage,
  proofScope: result.proofScope,
  wholeBinaryVerified: false, replayExecutedTarget: false,
  startupLog: fs.readFileSync(path.join(artifactRoot, 'ig5-diag.log'), 'utf8').trimEnd().split('\n').slice(-5).join('\n'),
  limitations: ['DSH replayed an existing owned native recording; no new native launch in DSH',
    'Function model under recorded environment assumptions, not whole-binary recovery',
    'Explicit CPUID continuations retain their missing intermediate snapshot; other instructions retain actual recorded observations'] };
const outputName = outputLabel ? outputLabel + '.json' : acceptance.id === 'compiled-rotate-mix64' ? 'dsh-suite-verified.json' : `dsh-${acceptance.id}-verified.json`;
fs.writeFileSync(path.join(base, outputName), JSON.stringify(output, null, 2) + '\n');
console.log(JSON.stringify({ status: output.status, reportId: id, instructions: output.instructions, checked: acceptance.independentReferencePairs }));
