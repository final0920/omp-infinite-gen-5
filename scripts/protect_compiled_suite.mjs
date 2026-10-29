// Protect our three independently compiled fixtures with the pinned producer.
// The generated target is data here and is never executed by this script.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
const base = path.resolve(process.argv[2] || '');
if (!process.argv[2]) throw new Error('Supply modern evidence root');
if (process.argv[3] && process.argv[3] !== 'packed') throw new Error('Only the explicit owned packed suite option is supported');
const packed = process.argv[3] === 'packed';
const hash = data => createHash('sha256').update(data).digest('hex');
const producer = path.join(base, 'official-producer/VMProtect_Con.exe'), expected = '52e23d2f9c959a21bdc2067d03d29e20cd85995a202cb7f2116d89b19c88c527';
if (hash(fs.readFileSync(producer)) !== expected) throw new Error('Official producer pin differs');
const output = path.join(base, packed ? 'packed-suite-vmp311' : 'compiled-suite-vmp311'); fs.mkdirSync(output, { recursive: true });
const sourceSha = hash(fs.readFileSync(new URL(packed ? './fixtures/packed_compiled_suite.c' : './fixtures/modern_compiled_suite.c', import.meta.url)));
const cases = packed ? ['packed-branch-mix64', 'packed-round-mix64'] : ['compiled-rotate-mix64', 'compiled-signed-select64', 'compiled-mul-mix32'];
const leaf = packed ? 'ig5_packed_leaf' : 'ig5_modern_leaf';
const exportRVA = data => {
  const pe = data.readUInt32LE(0x3c), optional = pe + 24, sections = optional + data.readUInt16LE(pe + 20);
  if (data.toString('ascii', pe, pe + 4) !== 'PE\0\0' || data.readUInt16LE(optional) !== 0x20b) throw new Error('Expected owned PE64');
  const raw = rva => {
    for (let n = 0; n < data.readUInt16LE(pe + 6); n++) {
      const s = sections + n * 40, start = data.readUInt32LE(s + 12), length = data.readUInt32LE(s + 16);
      if (rva >= start && rva < start + length) return data.readUInt32LE(s + 20) + rva - start;
    }
    throw new Error('Owned export RVA is not file-backed');
  };
  const directory = raw(data.readUInt32LE(optional + 112)), names = raw(data.readUInt32LE(directory + 32)), ordinals = raw(data.readUInt32LE(directory + 36)), functions = raw(data.readUInt32LE(directory + 28));
  for (let i = 0; i < data.readUInt32LE(directory + 24); i++) {
    const offset = raw(data.readUInt32LE(names + i * 4));
    if (data.toString('ascii', offset, data.indexOf(0, offset)) === leaf) return '0x' + data.readUInt32LE(functions + 4 * data.readUInt16LE(ordinals + i * 2)).toString(16);
  }
  throw new Error('Owned export was lost');
};
const receipt = { producerSha256: expected, producerVersion: '3.11.0 build 2835 Demo', producerSource: 'https://www.vmpsoft.com/files', nativeTargetsExecuted: false, rows: [] };
for (let index = 0; index < cases.length; index++) {
  const id = cases[index], proofPath = path.join(base, packed ? 'packed-suite-control' : 'compiled-suite-control', id + '-proof.json'), proofBytes = fs.readFileSync(proofPath), proof = JSON.parse(proofBytes);
  if (proof.schema !== (packed ? 'ig5.owned-packed-suite.v1' : 'ig5.owned-compiled-suite.v1') || proof.id !== id || proof.caseDefine !== index || proof.sourceSHA256 !== sourceSha || hash(fs.readFileSync(proof.target)) !== proof.inputSHA256) throw new Error('Owned compiler proof differs');
  const input = path.join(output, id + '.exe'); fs.copyFileSync(proof.target, input, fs.constants.COPYFILE_EXCL);
  for (const [mode, type] of [['virtualization', 0], ['mutation', 1], ['ultra', 2]]) {
    const target = path.join(output, id + '-' + mode + '.exe'), project = target + '.vmp', log = target + '.log';
    const xml = '<?xml version="1.0" encoding="UTF-8"?><Document><Protection InputFileName="' + id + '.exe" Options="0" VMCodeSectionName=".ig5vm" VMExecutorCount="1"><Procedures><Procedure MapAddress="' + leaf + '" IncludedInCompilation="true" CompilationType="' + type + '" Options="0"/></Procedures></Protection></Document>';
    fs.writeFileSync(project, xml, { flag: 'wx' });
    const result = spawnSync(producer, [input, target, '-pf', project, '-we'], { windowsHide: true, cwd: output, timeout: 60000, maxBuffer: 1024 * 1024 });
    fs.writeFileSync(log, Buffer.concat([result.stdout || Buffer.alloc(0), result.stderr || Buffer.alloc(0)]));
    if (result.status !== 0) throw new Error('Official protection failed: ' + id + '/' + mode);
    const data = fs.readFileSync(target);
    receipt.rows.push({ id, recipe: packed ? 'owned-packed-suite-c-v1' : 'owned-compiled-suite-c-v1', compilerProofPath: proofPath, compilerProofSha256: hash(proofBytes),
      inputs: ['rcx', 'rdx'], output: 'rax', input, inputSha256: proof.inputSHA256, mode, target, targetSha256: hash(data), bytes: data.length,
      entryRVA: exportRVA(data), project, projectSha256: hash(Buffer.from(xml)), log, logSha256: hash(fs.readFileSync(log)), versionEvidence: 'Pinned official producer, owned MSVC suite source and case define' });
    fs.writeFileSync(path.join(output, 'generation.json'), JSON.stringify(receipt, null, 2));
    console.log(JSON.stringify({ id, mode, entryRVA: receipt.rows.at(-1).entryRVA, sha256: receipt.rows.at(-1).targetSha256 }));
  }
}
