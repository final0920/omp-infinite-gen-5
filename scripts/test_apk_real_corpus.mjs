// The APK front end against REAL packages: the 52pojie challenge APKs the protection corpus collected (not generated,
// protections unconfirmed). Checks that nothing is rejected or flagged as damaged, and compares every DEX instruction
// stream and every manifest with the independent readers (dexlib2, AXMLPrinter2). The corpus lives outside the source
// tree (see docs/PROTECTION_CORPUS.md); without it the whole file is skipped loudly. Override with IG5_PROTECTION_CORPUS.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { analyzeApk } from '../source/apk_analysis.js';
import { parseAxml } from '../source/apk_axml.js';
import { DexFile } from '../source/apk_dex.js';
import { ZipArchive } from '../source/apk_zip.js';
import { axmlToText, dexDump, dexLines, parsePrinted, tools } from './fixtures/oracle.mjs';

const root = process.env.IG5_PROTECTION_CORPUS || path.join(os.homedir(), '.dsh', 'ig5', 'artifacts', 'corpus-expansion-20261014', 'corpus');
const directory = path.join(root, 'derived');
const apks = fs.existsSync(directory) ? fs.readdirSync(directory).filter(name => name.endsWith('.apk')).sort().map(name => path.join(directory, name)) : [];
const skip = !apks.length ? `real APK corpus not found at ${directory}` : false;
if (skip) console.log('SKIPPED:', skip);

test('every real APK is analysed without errors, anomalies or budget hits', { skip }, () => {
  assert.ok(apks.length >= 10, `expected the corpus APKs, found ${apks.length}`);
  for (const file of apks) {
    const started = Date.now(), report = analyzeApk({ path: file }), name = path.basename(file).slice(0, 8);
    assert.ok(report.overview.package, `${name}: package name`); assert.ok(report.overview.dexFiles >= 1, `${name}: dex`); assert.ok(report.overview.methods > 100, `${name}: methods`);
    assert.deepEqual(report.dex.filter(d => d.error), [], `${name}: DEX errors`); assert.equal(report.manifest.error, undefined, `${name}: manifest`);
    assert.deepEqual(report.anomalies, [], `${name}: container anomalies`); assert.deepEqual(report.limitsHit, [], `${name}: budgets`);
    for (const dex of report.dex) { assert.equal(dex.checksumOk, true, `${name}/${dex.name} checksum`); assert.equal(dex.signatureOk, true, `${name}/${dex.name} signature`); assert.equal(dex.scanned.truncatedBodies, 0, `${name}/${dex.name} truncated bodies`); }
    assert.ok(report.signatures.certificates.length >= 1, `${name}: signing certificate`); assert.ok(Date.now() - started < 20000, `${name}: took ${Date.now() - started} ms`);
    assert.ok(Buffer.byteLength(JSON.stringify(report)) < 2 * 1024 * 1024, `${name}: report size`);
  }
});

test('every DEX in the corpus decodes to exactly the instruction stream and references dexlib2 reports', { skip: skip || (tools ? false : 'bundled JDK / dexlib2 not found'), timeout: 600000 }, () => {
  let files = 0, lines = 0;
  for (const file of apks) {
    const zip = ZipArchive.open(file);
    try {
      for (const entry of zip.entries.filter(e => /^classes\d*\.dex$/.test(e.name))) {
        const bytes = zip.read(entry), ours = dexLines(new DexFile(bytes)), theirs = dexDump(bytes);
        assert.equal(ours.length, theirs.length, `${path.basename(file).slice(0, 8)}/${entry.name}: line count`);
        const at = ours.findIndex((line, i) => line !== theirs[i]);
        assert.equal(at, -1, `${path.basename(file).slice(0, 8)}/${entry.name}: first difference at line ${at}: ${ours[at]} | ${theirs[at]}`);
        files++; lines += ours.length;
      }
    } finally { zip.close(); }
  }
  console.log(`dexlib2 agreement: ${files} DEX files, ${lines} lines`);
  assert.ok(files >= 10);
});

test('every real manifest decodes to the elements, attributes and values AXMLPrinter2 prints', { skip: skip || (tools ? false : 'bundled JDK / AXMLPrinter2 not found') }, () => {
  const flatten = (element, depth = 0) => [[depth, element.name, element.attributes], ...element.children.flatMap(child => flatten(child, depth + 1))];
  const number = text => (/^0x[0-9a-f]+$/i.test(text) ? String(parseInt(text, 16)) : text);       // the reference zero-pads and upper-cases hex values
  let compared = 0;
  for (const file of apks) {
    const zip = ZipArchive.open(file); const bytes = zip.read('AndroidManifest.xml'); zip.close();
    const parsed = parseAxml(bytes); if (parsed.utf8Pool) continue;                // the reference cannot read UTF-8 string pools
    const ours = flatten(parsed.root), theirs = parsePrinted(axmlToText(bytes));
    assert.equal(ours.length, theirs.length, `${path.basename(file).slice(0, 8)}: element count`);
    ours.forEach(([depth, tag, attrs], i) => {
      assert.deepEqual([depth, tag, attrs.length], [theirs[i][0], theirs[i][1], theirs[i][2].length], `${path.basename(file).slice(0, 8)} <${tag}>`);
      attrs.forEach((attr, j) => {
        const [theirName, theirValue] = theirs[i][2][j], value = attr.type === 'reference' ? attr.value.toString(16).toUpperCase() : attr.text;
        assert.equal(theirName.split(':').pop(), attr.name); assert.equal(number(attr.type === 'reference' ? theirValue.replace('@', '') : theirValue), number(value), `<${tag}> ${attr.name}`);
      });
    });
    compared++;
  }
  assert.ok(compared >= 10, `compared ${compared} manifests`);
});
