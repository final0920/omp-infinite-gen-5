// Invoke the pinned official producer on our compiled C control only.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
const base = path.resolve(process.argv[2] || '');
if (!process.argv[2]) throw new Error('Supply modern evidence root');
const hash = data => createHash('sha256').update(data).digest('hex');
const producer = path.join(base, 'official-producer/VMProtect_Con.exe'), expected = '52e23d2f9c959a21bdc2067d03d29e20cd85995a202cb7f2116d89b19c88c527';
if (hash(fs.readFileSync(producer)) !== expected) throw new Error('Official producer pin differs');
const proofPath = path.join(base, 'compiled-control/compiler-proof.json'), proof = JSON.parse(fs.readFileSync(proofPath, 'utf8'));
if (hash(fs.readFileSync(new URL('./fixtures/modern_compiled.c', import.meta.url))) !== proof.sourceSHA256 || hash(fs.readFileSync(proof.target)) !== proof.inputSHA256) throw new Error('Owned compiler proof differs');
const output = path.join(base, 'compiled-vmp311'); fs.mkdirSync(output, { recursive: true });
const input = path.join(output, 'compiled-add64.exe'); fs.copyFileSync(proof.target, input, fs.constants.COPYFILE_EXCL);
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
    if (data.toString('ascii', offset, data.indexOf(0, offset)) === 'ig5_modern_add64') return '0x' + data.readUInt32LE(functions + 4 * data.readUInt16LE(ordinals + i * 2)).toString(16);
  }
  throw new Error('Owned export was lost');
};
const receipt = { producerSha256: expected, producerVersion: '3.11.0 build 2835 Demo', producerSource: 'https://www.vmpsoft.com/files', nativeTargetsExecuted: false, rows: [] };
for (const [mode, type] of [['virtualization', 0], ['mutation', 1], ['ultra', 2]]) {
  const target = path.join(output, 'compiled-add64-' + mode + '.exe'), project = target + '.vmp', log = target + '.log';
  const xml = '<?xml version="1.0" encoding="UTF-8"?><Document><Protection InputFileName="compiled-add64.exe" Options="0" VMCodeSectionName=".ig5vm" VMExecutorCount="1"><Procedures><Procedure MapAddress="ig5_modern_add64" IncludedInCompilation="true" CompilationType="' + type + '" Options="0"/></Procedures></Protection></Document>';
  fs.writeFileSync(project, xml, { flag: 'wx' });
  const result = spawnSync(producer, [input, target, '-pf', project, '-we'], { windowsHide: true, cwd: output, timeout: 60000, maxBuffer: 1024 * 1024 });
  fs.writeFileSync(log, Buffer.concat([result.stdout || Buffer.alloc(0), result.stderr || Buffer.alloc(0)]));
  if (result.status !== 0) throw new Error('Official protection failed: ' + mode);
  const data = fs.readFileSync(target);
  receipt.rows.push({ id: 'compiled-add64', recipe: 'owned-compiled-c-v1', compilerProofPath: proofPath, compilerProofSha256: hash(fs.readFileSync(proofPath)),
    inputs: ['rcx', 'rdx'], output: 'rax', input, inputSha256: proof.inputSHA256, mode, target, targetSha256: hash(data), bytes: data.length,
    entryRVA: exportRVA(data), project, projectSha256: hash(Buffer.from(xml)), log, logSha256: hash(fs.readFileSync(log)), versionEvidence: 'Pinned official producer and owned MSVC control proof' });
  fs.writeFileSync(path.join(output, 'generation.json'), JSON.stringify(receipt, null, 2));
  console.log(JSON.stringify({ mode, entryRVA: receipt.rows.at(-1).entryRVA, sha256: receipt.rows.at(-1).targetSha256 }));
}
