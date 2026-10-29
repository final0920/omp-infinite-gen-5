// Snapshot metadata for already pinned public data and OWN official-producer
// outputs. This script never downloads, protects, or launches a target.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { modernOwnedImage, modernOwnedHarnessImage } from './fixtures/modern_owned_cases.mjs';
const base = path.resolve(process.argv[2] || '');
if (!process.argv[2]) throw new Error('Supply modern evidence root');
const sha = data => createHash('sha256').update(data).digest('hex');
const external = JSON.parse(fs.readFileSync(path.join(base, 'corpus/download-manifest.json'), 'utf8'));
const files = external.files.map(row => ({ ...row, file: 'corpus/' + row.file }));
const add = (filename, role, expected, extra = {}) => {
  const relative = path.relative(base, filename).split(path.sep).join('/');
  if (relative.startsWith('../') || path.isAbsolute(relative)) throw new Error('Input outside modern corpus');
  if (files.some(row => row.file === relative)) return;
  const data = fs.readFileSync(filename), actual = sha(data);
  if (expected && actual !== expected) throw new Error('Modern corpus pin differs: ' + relative);
  files.push({ file: relative, bytes: data.length, sha256: actual, role, ...extra });
};
let modernOutputs = 0;
const generationDirectories = ['generated-vmp311', 'generated-vmp311-harness', 'compiled-vmp311'];
if (fs.existsSync(path.join(base, 'compiled-suite-vmp311/generation.json'))) generationDirectories.push('compiled-suite-vmp311');
if (fs.existsSync(path.join(base, 'packed-suite-vmp311/generation.json'))) generationDirectories.push('packed-suite-vmp311');
for (const directory of generationDirectories) {
 const generationPath = path.join(base, directory, 'generation.json');
 const generation = JSON.parse(fs.readFileSync(generationPath, 'utf8'));
 if (generation.producerSha256 !== '52e23d2f9c959a21bdc2067d03d29e20cd85995a202cb7f2116d89b19c88c527') throw new Error('Official producer pin differs');
 for (const item of generation.rows) {
  if (['owned-compiled-c-v1', 'owned-compiled-suite-c-v1', 'owned-packed-suite-c-v1'].includes(item.recipe)) {
    const proof = JSON.parse(fs.readFileSync(item.compilerProofPath));
    const fixture = item.recipe === 'owned-compiled-c-v1' ? './fixtures/modern_compiled.c' : item.recipe === 'owned-packed-suite-c-v1' ? './fixtures/packed_compiled_suite.c' : './fixtures/modern_compiled_suite.c';
    if (sha(fs.readFileSync(new URL(fixture, import.meta.url))) !== proof.sourceSHA256 || proof.inputSHA256 !== item.inputSha256) throw new Error('Compiler source/input pin differs');
    if (item.recipe === 'owned-compiled-suite-c-v1' && (proof.schema !== 'ig5.owned-compiled-suite.v1' || proof.id !== item.id || proof.caseDefine !== ['compiled-rotate-mix64', 'compiled-signed-select64', 'compiled-mul-mix32'].indexOf(item.id))) throw new Error('Compiler case define differs');
    if (item.recipe === 'owned-packed-suite-c-v1' && (proof.schema !== 'ig5.owned-packed-suite.v1' || proof.id !== item.id || proof.caseDefine !== ['packed-branch-mix64', 'packed-round-mix64'].indexOf(item.id))) throw new Error('Packed compiler case define differs');
    add(item.compilerProofPath, 'compiler-proof', item.compilerProofSha256);
  } else if (sha((item.harness ? modernOwnedHarnessImage : modernOwnedImage)(item.id)) !== item.inputSha256) throw new Error('Owned recipe differs');
  const version = { protection: 'VMProtect', version: '3.11.0 build 2835 Demo', versionEvidence: item.versionEvidence,
    producerSha256: generation.producerSha256, generationReceiptSha256: sha(fs.readFileSync(generationPath)), sourcePage: generation.producerSource, ownedRecipe: item.id };
  add(item.input, 'control', item.inputSha256, { ownedGenerated: true });
  if (fs.existsSync(item.target)) add(item.target, 'protected-self-generated', item.targetSha256, { ...version, mode: item.mode, inputSha256: item.inputSha256,
    ownedGenerated: true, nativeExecutionEligibility: 'Only explicit approved debug fixture tests; no downloaded challenges' });
  else files.push({ file: path.relative(base, item.target).split(path.sep).join('/'), bytes: item.bytes, sha256: item.targetSha256,
    role: 'protected-self-generated', ...version, mode: item.mode, ownedGenerated: true, storageState: 'unavailable-no-restoration', inputSha256: item.inputSha256 });
  modernOutputs++;
  add(item.project, 'recipe', item.projectSha256, version);
  add(item.log, 'producer-log', item.logSha256, version);
 }
 add(generationPath, 'generation-receipt');
}
add(path.join(base, 'official-demo-provenance.json'), 'version-provenance');
let upxOutputs = 0;
for (const directory of ['upx-generated', 'upx-packed-generated']) {
  const generationPath = path.join(base, directory, 'generation.json');
  if (!fs.existsSync(generationPath)) continue;
  const generationBytes = fs.readFileSync(generationPath), generation = JSON.parse(generationBytes);
  if (generation.producerSha256 !== 'd20ebe0b7b22b6be968c8c34be61f94ddea12cb11462e2cec27f548ef9574df8' || generation.producerVersion !== '5.2.1' || generation.archiveSha256 !== 'eabc6792a347d45e945be7748423e7868fd01b0d2bcaa2f4b1031fd71ff69bda') throw new Error('UPX producer/version/archive pin differs');
  for (const item of generation.rows) {
    const proofBytes = fs.readFileSync(item.compilerProofPath), proof = JSON.parse(proofBytes);
    const packed = item.recipe === 'owned-packed-suite-c-v1';
    if (!packed && item.recipe !== 'owned-compiled-suite-c-v1') throw new Error('Unsupported UPX owned recipe');
    const fixture = packed ? './fixtures/packed_compiled_suite.c' : './fixtures/modern_compiled_suite.c';
    const cases = packed ? ['packed-branch-mix64', 'packed-round-mix64'] : ['compiled-rotate-mix64', 'compiled-signed-select64', 'compiled-mul-mix32'];
    if (sha(proofBytes) !== item.compilerProofSha256 || proof.sourceSHA256 !== sha(fs.readFileSync(new URL(fixture, import.meta.url))) || proof.inputSHA256 !== item.inputSha256 || proof.id !== item.id || proof.caseDefine !== cases.indexOf(item.id)) throw new Error('UPX owned compiler/source pin differs');
    const version = { protection: 'UPX', version: '5.2.1', producerSha256: generation.producerSha256,
      generationReceiptSha256: sha(generationBytes), sourcePage: generation.producerSource, ownedRecipe: item.id,
      versionEvidence: 'Pinned official producer/version/archive; target header method is verified separately' };
    add(item.input, 'control', item.inputSha256, { ownedGenerated: true });
    add(item.compilerProofPath, 'compiler-proof', item.compilerProofSha256);
    const logs = [item.target + '.log', path.join(base, directory, item.id + '-' + item.mode + '.log')]
      .filter(filename => fs.existsSync(filename) && sha(fs.readFileSync(filename)) === item.logSha256);
    if (logs.length !== 1) throw new Error('UPX producer log pin/path is missing or ambiguous');
    add(logs[0], 'producer-log', item.logSha256, version);
    if (!item.generated) continue;
    add(item.target, 'protected-self-generated', item.targetSha256, { ...version, mode: item.mode, inputSha256: item.inputSha256,
      ownedGenerated: true, nativeExecutionEligibility: 'Only explicit approved debug fixture tests; no downloaded challenges' });
    upxOutputs++;
  }
  add(generationPath, 'generation-receipt', sha(generationBytes));
}
for (const row of files) {
  if (row.storageState) continue;
  const data = fs.readFileSync(path.join(base, row.file));
  if (data.length !== row.bytes || sha(data) !== row.sha256) throw new Error('Preflight differs: ' + row.file);
}
const manifest = { schema: 'ig5.modern-protection-corpus.v1', distribution: 'Metadata only; protected targets and producer stay in private artifacts',
  limitations: ['Demo/basic options only, maximum protection is not validated', 'Public VMP3/Themida exact versions unspecified',
    'Intake is not business logic recovery; native execution of downloaded challenges is excluded'], files };
const output = path.join(import.meta.dirname, 'fixtures/modern_corpus.json');
fs.writeFileSync(output, JSON.stringify(manifest, null, 2) + '\n');
console.log(JSON.stringify({ records: files.length, pinnedOfficialModernOutputs: modernOutputs, upxOutputs, manifest: output }));
