// Reproducible OWN control packing. No target or downloaded challenge executes.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
const [inputArg, outputArg, producerArg] = process.argv.slice(2);
assert(inputArg && outputArg && producerArg, 'Supply own controls, fresh private output and pinned UPX executable');
const root = path.resolve(import.meta.dirname, '..'), inputRoot = path.resolve(inputArg), outputRoot = path.resolve(outputArg), producer = path.resolve(producerArg);
assert(!outputRoot.toLowerCase().startsWith(root.toLowerCase() + path.sep) && outputRoot.toLowerCase() !== root.toLowerCase(), 'Generated targets must stay outside plugin');
assert(!fs.existsSync(outputRoot), 'Use a fresh output directory');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const producerSha256 = hash(fs.readFileSync(producer));
assert.equal(producerSha256, 'd20ebe0b7b22b6be968c8c34be61f94ddea12cb11462e2cec27f548ef9574df8');
const version = spawnSync(producer, ['--version'], { windowsHide: true, encoding: 'utf8', timeout: 10000 });
assert.equal(version.status, 0); assert.match(version.stdout, /^upx 5\.2\.1\b/m);
const cases = ['packed-branch-mix64', 'packed-round-mix64'];
const sourceSHA256 = hash(fs.readFileSync(new URL('./fixtures/packed_compiled_suite.c', import.meta.url)));
const inputs = cases.map((id, caseDefine) => {
  const input = path.join(inputRoot, id + '.exe'), proofPath = path.join(inputRoot, id + '-proof.json');
  const proofBytes = fs.readFileSync(proofPath), proof = JSON.parse(proofBytes.toString().replace(/^\uFEFF/, ''));
  assert.equal(proof.schema, 'ig5.owned-packed-suite.v1'); assert.equal(proof.id, id); assert.equal(proof.caseDefine, caseDefine);
  assert.equal(proof.sourceSHA256, sourceSHA256); assert.equal(proof.inputSHA256, hash(fs.readFileSync(input)));
  assert.equal(proof.mapSHA256, hash(fs.readFileSync(path.join(inputRoot, id + '.map'))));
  assert.equal(proof.compressionDataBytes, 65536); assert.match(proof.entryRVA, /^0x[0-9a-f]{1,8}$/);
  return { id, input, inputSha256: proof.inputSHA256, compilerProofPath: proofPath, compilerProofSha256: hash(proofBytes), entryRVA: proof.entryRVA };
});
fs.mkdirSync(outputRoot, { recursive: true });
const generation = { producerSource: 'https://github.com/upx/upx/releases/tag/v5.2.1', producerVersion: '5.2.1', producerSha256,
  archiveSha256: 'eabc6792a347d45e945be7748423e7868fd01b0d2bcaa2f4b1031fd71ff69bda', nativeTargetsExecuted: false, rows: [] };
for (const item of inputs) for (const [mode, flags] of [['nrv-best', ['--best']], ['lzma-best', ['--best', '--lzma']]]) {
  const target = path.join(outputRoot, item.id + '-' + mode + '.exe'), args = [...flags, '-o', target, item.input];
  const packed = spawnSync(producer, args, { windowsHide: true, encoding: 'utf8', timeout: 60000, maxBuffer: 1024 * 1024 });
  const log = Buffer.from((packed.stdout || '') + (packed.stderr || ''));
  fs.writeFileSync(path.join(outputRoot, item.id + '-' + mode + '.log'), log);
  const generated = packed.status === 0 && fs.existsSync(target);
  const row = { ...item, recipe: 'owned-packed-suite-c-v1', mode, inputs: ['rcx', 'rdx'], output: 'rax', target, args,
    exitCode: packed.status, error: packed.error?.message || null, generated, logSha256: hash(log),
    ...(generated ? { bytes: fs.statSync(target).size, targetSha256: hash(fs.readFileSync(target)) } : {}) };
  generation.rows.push(row);
  fs.writeFileSync(path.join(outputRoot, 'generation.json'), JSON.stringify(generation, null, 2) + '\n');
  console.log(JSON.stringify({ id: row.id, mode, generated, bytes: row.bytes, exitCode: row.exitCode }));
}
