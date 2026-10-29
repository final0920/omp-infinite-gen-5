// Independent bit-vector evaluation of a completed owned compiled-suite report.
// Reference formulas are local checks and are never supplied to recovery.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
const folder = path.resolve(process.argv[2] || '');
assert(process.argv[2], 'Supply a completed owned native receipt folder');
const receiptPath = path.join(folder, 'receipt.json'), receiptBytes = fs.readFileSync(receiptPath), receipt = JSON.parse(receiptBytes);
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
assert(['owned-compiled-suite-c-v1', 'owned-packed-suite-c-v1', 'owned-enigma-suite-c-v1', 'owned-enigma-suite-c-v2'].includes(receipt.generatedCase.recipe));
assert.equal(receipt.parts.at(-1).summary.stopReason, 'until-address');
assert.equal(receipt.targetUnchanged, true);
assert.equal(hash(fs.readFileSync(receipt.target)), receipt.generatedCase.targetSha256);
const proofBytes = fs.readFileSync(receipt.generatedCase.compilerProofPath), proof = JSON.parse(proofBytes);
assert.equal(hash(proofBytes), receipt.generatedCase.compilerProofSha256);
assert.equal(proof.sourceSHA256, hash(fs.readFileSync(new URL(receipt.generatedCase.recipe === 'owned-packed-suite-c-v1' ? './fixtures/packed_compiled_suite.c' : receipt.generatedCase.recipe === 'owned-enigma-suite-c-v1' ? './fixtures/enigma_compiled_suite.c' : receipt.generatedCase.recipe === 'owned-enigma-suite-c-v2' ? './fixtures/enigma_compiled_suite_v2.c' : './fixtures/modern_compiled_suite.c', import.meta.url))));
assert.equal(proof.id, receipt.generatedCase.id);
const revalidationPath = path.join(folder, 'revalidation.json');
const revalidation = fs.existsSync(revalidationPath) ? JSON.parse(fs.readFileSync(revalidationPath)) : null;
if (revalidation) assert.equal(revalidation.sourceReceiptSha256, hash(receiptBytes));
if (revalidation?.additionalSourceReceipts) {
  assert.equal(revalidation.additionalSourceReceipts.length, 2);
  for (const original of revalidation.additionalSourceReceipts) {
    const bytes = fs.readFileSync(original.path); assert.equal(hash(bytes), original.sha256);
    const saved = JSON.parse(bytes); assert.equal(saved.generatedCase.targetSha256, receipt.generatedCase.targetSha256);
    assert.equal(saved.parts.at(-1).summary.stopReason, 'until-address'); assert.equal(saved.targetUnchanged, true);
  }
}
const result = revalidation?.result || receipt.recovery;
let producer = receipt.producer;
if (process.argv[3]) {
  const generationPath = path.resolve(process.argv[3]), generationBytes = fs.readFileSync(generationPath), generation = JSON.parse(generationBytes);
  assert(generation.rows.some(row => row.id === receipt.generatedCase.id && row.mode === receipt.generatedCase.mode && row.targetSha256 === receipt.generatedCase.targetSha256));
  producer = { producerVersion: generation.producerVersion, producerSha256: generation.producerSha256, archiveSha256: generation.archiveSha256,
    generationPath, generationSha256: hash(generationBytes) };
}
assert.equal(result.ok, true); assert.equal(result.coverage, 'trace-model-input-domain');
assert.equal(result.nativeTargetExecuted, false); assert.equal(result.wholeBinaryVerified, false);
assert(result.recoveredExpression);
for (const p of result.paths) {
  assert.equal(p.outputProof.status, 'unsat'); assert.equal(p.finalSnapshotVerified, true);
  assert.equal(p.binaryBinding.allInstructionBytesMatch, true);
}
if (result.paths.length === 2) {
  assert.equal(result.coverageProof.disjoint.status, 'unsat'); assert.equal(result.coverageProof.exhaustive.status, 'unsat');
  for (const p of result.paths) assert.equal(p.guard.proof.status, 'unsat');
}
const mask = (value, bits) => { assert(Number.isInteger(bits) && bits > 0 && bits <= 256); return BigInt.asUintN(bits, value); };
const evaluate = (node, x, y, budget) => {
  assert(--budget.remaining >= 0, 'Independent expression evaluation budget exhausted');
  const predicate = condition => {
    assert(condition, 'A structured condition is required; string conditions are not executed');
    if (['land', 'lor', 'lxor', 'lnot'].includes(condition.op)) {
      const a = condition.args.map(predicate);
      return condition.op === 'land' ? a.every(Boolean) : condition.op === 'lor' ? a.some(Boolean) : condition.op === 'lnot' ? !a[0] : a.reduce((p, q) => p !== q, false);
    }
    const a = condition.args.map(n => evaluate(n, x, y, budget));
    const signed = condition.op.startsWith('s'), left = signed ? BigInt.asIntN(condition.args[0].bits, a[0]) : a[0], right = signed ? BigInt.asIntN(condition.args[1].bits, a[1]) : a[1];
    if (condition.op === 'eq') return left === right; if (condition.op === 'ne') return left !== right;
    if (['ult', 'slt'].includes(condition.op)) return left < right; if (['ule', 'sle'].includes(condition.op)) return left <= right;
    if (['ugt', 'sgt'].includes(condition.op)) return left > right; if (['uge', 'sge'].includes(condition.op)) return left >= right;
    throw new Error('Unsupported independent predicate: ' + condition.op);
  };
  if (node.op === 'input') { assert(['x', 'y'].includes(node.name)); return mask(node.name === 'x' ? x : y, node.bits); }
  if (node.op === 'constant') return mask(BigInt(node.value), node.bits);
  if (node.op === 'select') return mask(evaluate(predicate(node.conditionExpression) ? node.then : node.else, x, y, budget), node.bits);
  if (node.op === 'bool-bv') return predicate(node.conditionExpression) ? 1n : 0n;
  const a = node.args.map(n => evaluate(n, x, y, budget));
  if (node.op === 'extract') return mask(a[0] >> BigInt(node.low), node.bits);
  if (node.op === 'zx') return mask(a[0], node.bits);
  if (node.op === 'sx') return mask(BigInt.asIntN(node.args[0].bits, a[0]), node.bits);
  if (node.op === 'concat') return mask(a.reduce((v, child, i) => (v << BigInt(node.args[i].bits)) | child, 0n), node.bits);
  if (node.op === 'not') return mask(~a[0], node.bits);
  if (['shl', 'lshr', 'ashr'].includes(node.op)) {
    if (a[1] >= BigInt(node.bits)) return node.op === 'ashr' && BigInt.asIntN(node.bits, a[0]) < 0n ? mask(-1n, node.bits) : 0n;
    return mask(node.op === 'shl' ? a[0] << a[1] : node.op === 'lshr' ? a[0] >> a[1] : BigInt.asIntN(node.bits, a[0]) >> a[1], node.bits);
  }
  if (['rol', 'ror'].includes(node.op)) {
    const count = a[1] % BigInt(node.bits), inverse = BigInt(node.bits) - count;
    return mask(node.op === 'rol' ? (a[0] << count) | (a[0] >> inverse) : (a[0] >> count) | (a[0] << inverse), node.bits);
  }
  if (node.op === 'urem') return a[1] === 0n ? a[0] : a[0] % a[1];
  const functions = { add: (p, q) => p + q, sub: (p, q) => p - q, mul: (p, q) => p * q, xor: (p, q) => p ^ q, and: (p, q) => p & q, or: (p, q) => p | q };
  assert(functions[node.op], 'Unsupported independent expression: ' + node.op);
  return mask(a.reduce(functions[node.op]), node.bits);
};
const reference = (x, y) => {
  if (receipt.generatedCase.id === 'packed-branch-mix64') return (x ^ y) & 1n ? mask(x + y, 64) ^ 0xd6e8feb86659fd93n : mask((x ^ y) + 0x9e3779b97f4a7c15n, 64);
  if (receipt.generatedCase.id === 'packed-round-mix64') {
    let state = x;
    for (let i = 0n; i < 8n; i++) { const sum = mask(state + y + i, 64); state = mask((sum << 7n) | (sum >> 57n), 64) ^ mask(y * 0x9e3779b97f4a7c15n, 64); }
    return state;
  }
  if (receipt.generatedCase.id === 'compiled-rotate-mix64') {
    const n = y & 63n; return mask(((x << n) | (x >> (64n - n))) ^ mask(x + y, 64), 64);
  }
  if (receipt.generatedCase.id === 'compiled-signed-select64') return BigInt.asIntN(64, x) > BigInt.asIntN(64, y) ? x : y;
  assert.equal(receipt.generatedCase.id, 'compiled-mul-mix32'); return mask((mask(x, 32) ^ mask(y, 32)) + 99n, 32) * 143n & 0xffffffffn;
};
const values = [0n, 1n, 2n, 31n, 32n, 33n, 63n, 64n, 65n, 127n, 128n, 256n, (1n << 31n) - 1n, 1n << 31n, (1n << 32n) - 1n, 1n << 32n, (1n << 63n) - 1n, 1n << 63n, (1n << 64n) - 1n];
let checked = 0, seed = 0x7e57c0ffeeabcdefn;
const check = (x, y) => { assert.equal(evaluate(result.recoveredExpression, x, y, { remaining: 2048 }), reference(x, y)); checked++; };
for (const x of values) for (const y of values) check(x, y);
for (let n = 0; n < 2048; n++) {
  seed = mask(seed * 6364136223846793005n + 1442695040888963407n, 64); const x = seed;
  seed = mask(seed * 6364136223846793005n + 1442695040888963407n, 64); check(x, seed);
}
const acceptance = { status: 'owned-compiled-suite-function-model-verified', id: receipt.generatedCase.id,
  ...(producer ? { producer } : {}), targetSha256: receipt.generatedCase.targetSha256,
  sourceReceiptSha256: hash(receiptBytes), independentReferencePairs: checked, referenceWasNotSuppliedToRecovery: true,
  nativeRecordingExecutedOwnedTarget: true, recoveryExecutedTarget: false, downloadedChallengesExecuted: false,
  wholeBinaryVerified: false, result };
fs.writeFileSync(path.join(folder, 'acceptance.json'), JSON.stringify(acceptance, null, 2) + '\n');
console.log(JSON.stringify({ status: acceptance.status, id: acceptance.id, checked, expression: result.recoveredExpression }));
