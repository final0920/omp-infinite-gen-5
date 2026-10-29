// Uses only an explicitly supplied official signed evaluation producer.
// It protects owned generated data; protected targets are NOT executed here.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { modernOwnedCases, modernOwnedImage, modernOwnedHarnessImage } from './fixtures/modern_owned_cases.mjs';

const producer = path.resolve(process.argv[2] || ''), output = path.resolve(process.argv[3] || '');
if (!process.argv[2] || !process.argv[3]) throw new Error('Usage: generate_modern_owned_corpus.mjs OFFICIAL_PRODUCER OUTPUT');
const expected = '52e23d2f9c959a21bdc2067d03d29e20cd85995a202cb7f2116d89b19c88c527';
const hash = data => createHash('sha256').update(data).digest('hex');
if (hash(fs.readFileSync(producer)) !== expected) throw new Error('Official 3.11 build 2835 producer pin differs');
const source = path.resolve(import.meta.dirname, '..');
const harness = process.argv[4] === '--harness';
if (output === source || output.startsWith(source + path.sep)) throw new Error('Generated corpus must stay outside plugin');
fs.mkdirSync(output, { recursive: true });
const rows = [], receipt = { producerSha256: expected, producerVersion: '3.11.0 build 2835 Demo',
  producerSource: 'https://www.vmpsoft.com/files', blueprintSha256: hash(fs.readFileSync(new URL('./fixtures/modern_owned_cases.mjs', import.meta.url))),
  nativeTargetsExecuted: false, rows };
for (const item of modernOwnedCases) {
  const input = path.join(output, item.id + '.exe'), image = (harness ? modernOwnedHarnessImage : modernOwnedImage)(item.id);
  fs.writeFileSync(input, image, { flag: 'wx' });
  for (const [mode, type] of [['virtualization', 0], ['mutation', 1], ['ultra', 2]]) {
    const project = path.join(output, item.id + '-' + mode + '.vmp');
    const target = path.join(output, item.id + '-' + mode + '.exe');
    const xml = '<?xml version="1.0" encoding="UTF-8"?><Document><Protection InputFileName="' + path.basename(input) + '" Options="0" VMCodeSectionName=".ig5vm" VMExecutorCount="1"><Procedures><Procedure MapAddress="ig5_fixture_add" IncludedInCompilation="true" CompilationType="' + type + '" Options="0"/></Procedures></Protection></Document>';
    fs.writeFileSync(project, xml, { flag: 'wx' });
    const result = spawnSync(producer, [input, target, '-pf', project, '-we'], { windowsHide: true, cwd: output, timeout: 60000, maxBuffer: 1024 * 1024 });
    const log = path.join(output, item.id + '-' + mode + '.log');
    fs.writeFileSync(log, Buffer.concat([result.stdout || Buffer.alloc(0), result.stderr || Buffer.alloc(0)]));
    if (result.status !== 0 || !fs.existsSync(target)) throw new Error('Official producer failed: ' + item.id + '/' + mode + '; see ' + log);
    const data = fs.readFileSync(target);
    if (data.length > 64 * 1024 * 1024 || hash(data) === hash(image)) throw new Error('Protection output is oversized or unchanged');
    rows.push({ ...item, harness, recipe: harness ? 'owned-caller-v2' : 'owned-direct-entry-v1', mode, input, inputSha256: hash(image), target, targetSha256: hash(data), bytes: data.length,
      project, projectSha256: hash(Buffer.from(xml)), log, logSha256: hash(fs.readFileSync(log)), versionEvidence: 'Pinned official producer banner and Authenticode provenance, project mode and successful CLI log' });
    fs.writeFileSync(path.join(output, 'generation.json'), JSON.stringify(receipt, null, 2));
    console.log(JSON.stringify({ case: item.id, mode, bytes: data.length, sha256: hash(data) }));
  }
}
