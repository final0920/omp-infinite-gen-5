// Read compressed headers/checksums with the pinned producer; never run targets.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
const [generationArg, producerArg, outputArg] = process.argv.slice(2);
assert(generationArg && producerArg && outputArg, 'Supply pinned own generation receipt, UPX executable and fresh private evidence directory');
const root = path.resolve(import.meta.dirname, '..'), output = path.resolve(outputArg), producer = path.resolve(producerArg);
assert(!fs.existsSync(output) && output.toLowerCase() !== root.toLowerCase() && !output.toLowerCase().startsWith(root.toLowerCase() + path.sep));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const generationBytes = fs.readFileSync(generationArg), generation = JSON.parse(generationBytes);
assert.equal(generation.producerSha256, 'd20ebe0b7b22b6be968c8c34be61f94ddea12cb11462e2cec27f548ef9574df8');
assert.equal(hash(fs.readFileSync(producer)), generation.producerSha256);
assert.equal(generation.producerVersion, '5.2.1');
const rows = generation.rows.filter(row => row.generated);
for (const item of rows) {
  assert(['owned-compiled-suite-c-v1', 'owned-packed-suite-c-v1'].includes(item.recipe));
  const proofBytes = fs.readFileSync(item.compilerProofPath), proof = JSON.parse(proofBytes);
  assert.equal(hash(proofBytes), item.compilerProofSha256);
  const packed = item.recipe === 'owned-packed-suite-c-v1';
  assert.equal(proof.sourceSHA256, hash(fs.readFileSync(new URL(packed ? './fixtures/packed_compiled_suite.c' : './fixtures/modern_compiled_suite.c', import.meta.url))));
  assert.equal(proof.id, item.id); assert.equal(proof.inputSHA256, hash(fs.readFileSync(item.input)));
  assert.equal(hash(fs.readFileSync(item.target)), item.targetSha256);
}
fs.mkdirSync(output, { recursive: true });
const receipt = { status: 'checking', generationPath: path.resolve(generationArg), generationSha256: hash(generationBytes),
  producerSha256: generation.producerSha256, producerVersion: generation.producerVersion,
  methodDefinitionsSource: 'https://github.com/upx/upx/blob/v5.2.1/src/conf.h', nativeTargetsExecuted: false, rows: [] };
for (const item of rows) {
  const info = spawnSync(producer, ['--fileinfo', item.target], { windowsHide: true, encoding: 'utf8', timeout: 10000, maxBuffer: 1024 * 1024 });
  const checked = spawnSync(producer, ['-t', item.target], { windowsHide: true, encoding: 'utf8', timeout: 10000, maxBuffer: 1024 * 1024 });
  const infoLog = Buffer.from((info.stdout || '') + (info.stderr || '')), testLog = Buffer.from((checked.stdout || '') + (checked.stderr || ''));
  const stem = item.id + '-' + item.mode;
  fs.writeFileSync(path.join(output, stem + '-fileinfo.log'), infoLog); fs.writeFileSync(path.join(output, stem + '-checksum.log'), testLog);
  assert.equal(info.status, 0); assert.equal(checked.status, 0);
  const methodMatch = infoLog.toString().match(/compressed by UPX \d+, method (\d+), level (\d+), filter (0x[0-9a-f]+\/0x[0-9a-f]+)/i);
  assert(methodMatch, 'Producer did not report an explicit compression method');
  const method = Number(methodMatch[1]);
  assert(item.mode === 'lzma-best' ? method === 14 : item.mode === 'nrv-best' && method >= 2 && method <= 10);
  assert.equal(hash(fs.readFileSync(item.target)), item.targetSha256);
  receipt.rows.push({ id: item.id, mode: item.mode, targetSha256: item.targetSha256, method,
    algorithm: method === 14 ? 'LZMA' : 'NRV', level: Number(methodMatch[2]), filter: methodMatch[3],
    fileinfoSha256: hash(infoLog), checksumLogSha256: hash(testLog), checksumPassed: true, targetUnchanged: true });
  fs.writeFileSync(path.join(output, 'receipt.json'), JSON.stringify(receipt, null, 2) + '\n');
}
receipt.status = 'compressed-headers-and-checksums-verified';
fs.writeFileSync(path.join(output, 'receipt.json'), JSON.stringify(receipt, null, 2) + '\n');
console.log(JSON.stringify({ status: receipt.status, nativeTargetsExecuted: false, rows: receipt.rows.map(row => ({ id: row.id, mode: row.mode, method: row.method })) }));
