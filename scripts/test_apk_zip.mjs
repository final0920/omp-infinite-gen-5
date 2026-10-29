// ZIP reader for APK analysis: correct reads, and every structural defect it must report or refuse.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { ZipArchive, crc32 } from '../source/apk_zip.js';
import { buildSigningBlock, buildZip, u32 } from './fixtures/apk_builder.mjs';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-apk-zip-'));
test.after(() => fs.rmSync(root, { recursive: true, force: true }));
let counter = 0;
const write = bytes => { const file = path.join(root, `case-${++counter}.zip`); fs.writeFileSync(file, bytes); return file; };
const open = (bytes, options) => ZipArchive.open(write(bytes), options);
const codeOf = fn => { try { fn(); } catch (error) { return error.code; } return 'NO-ERROR'; };
const text = 'hello apk '.repeat(40);

test('stored and deflated entries read back exactly, with CRC and size verified', () => {
  const zip = open(buildZip([{ name: 'a.txt', data: text, method: 'store' }, { name: 'dir/b.bin', data: Buffer.from([0, 1, 2, 3, 255]), method: 'deflate' }, { name: 'empty', data: '' }]));
  try {
    assert.deepEqual(zip.entries.map(e => e.name), ['a.txt', 'dir/b.bin', 'empty']);
    assert.equal(zip.read('a.txt').toString(), text);
    assert.deepEqual([...zip.read('dir/b.bin')], [0, 1, 2, 3, 255]);
    assert.equal(zip.read('empty').length, 0);
    assert.deepEqual(zip.anomalies, [], 'a clean archive reports nothing');
  } finally { zip.close(); }
});

test('whole-file SHA-256 matches an independent digest and the file identity is stable', () => {
  const bytes = buildZip([{ name: 'a', data: text }]);
  const file = write(bytes), zip = ZipArchive.open(file);
  try {
    assert.equal(zip.sha256(), createHash('sha256').update(bytes).digest('hex'));
    zip.assertUnchanged();
    fs.appendFileSync(file, 'x');
    assert.equal(codeOf(() => zip.assertUnchanged()), 'ZIP_CHANGED');
  } finally { zip.close(); }
});

test('non-ZIP, truncated and out-of-range inputs are refused with a code', () => {
  assert.equal(codeOf(() => open(Buffer.alloc(100, 7))), 'ZIP_FORMAT');
  assert.equal(codeOf(() => open(Buffer.from('tiny'))), 'ZIP_INPUT');
  const good = buildZip([{ name: 'a', data: text }]);
  assert.equal(codeOf(() => open(good.subarray(0, good.length - 10))), 'ZIP_FORMAT', 'a cut-off end record');
  const lying = Buffer.from(good); lying.writeUInt32LE(0x7fffffff, lying.length - 6);       // central directory offset beyond the file
  assert.equal(codeOf(() => open(lying)), 'ZIP_FORMAT');
  const many = Buffer.from(good); many.writeUInt16LE(60000, many.length - 12); many.writeUInt16LE(60000, many.length - 14);
  assert.equal(codeOf(() => open(many, { entries: 1000 })), 'ZIP_LIMIT');
  assert.equal(codeOf(() => ZipArchive.open(root)), 'ZIP_INPUT', 'a directory');
});

test('symbolic links are refused', { skip: process.platform === 'win32' ? 'creating symlinks needs elevation on Windows' : false }, () => {
  const file = write(buildZip([{ name: 'a', data: 'x' }])), link = path.join(root, 'link.zip');
  fs.symlinkSync(file, link);
  assert.equal(codeOf(() => ZipArchive.open(link)), 'ZIP_INPUT');
});

test('integrity failures are detected on read: CRC, size, corrupt deflate, truncated data', () => {
  const crcBad = open(buildZip([{ name: 'a', data: text, crc: 12345 }]));
  assert.equal(codeOf(() => crcBad.read('a')), 'ZIP_CRC'); crcBad.close();
  const sizeBad = open(buildZip([{ name: 'a', data: text, method: 'store', size: text.length - 1 }]));
  assert.equal(codeOf(() => sizeBad.read('a')), 'ZIP_SIZE', 'stored bytes longer than the directory says'); sizeBad.close();
  const corrupt = open(buildZip([{ name: 'a', data: text, rawData: Buffer.from('this is not a deflate stream at all'), size: text.length, crc: crc32(Buffer.from(text)) }]));
  assert.equal(codeOf(() => corrupt.read('a')), 'ZIP_INFLATE'); corrupt.close();
  const short = open(buildZip([{ name: 'a', data: text, method: 'store', size: text.length + 50 }]));
  assert.equal(codeOf(() => short.read('a')), 'ZIP_SIZE', 'declared size larger than the stored bytes'); short.close();
});

test('structural tricks are reported as anomalies rather than silently accepted', () => {
  const zip = open(buildZip([
    { name: 'classes.dex', data: 'one' }, { name: 'classes.dex', data: 'two' },            // duplicate entry
    { name: '../../evil', data: 'x' }, { name: '/abs/path', data: 'x' }, { name: 'back\\slash', data: 'x' },
    { name: 'enc.bin', data: 'x', flags: 1 }, { name: 'odd.bin', data: 'x', method: 99, rawData: Buffer.from('x') },
    { name: 'lies.txt', data: 'x', localName: 'other.txt' },
  ], { trailing: 'garbage after the end record' }));
  try {
    const codes = zip.anomalies.map(a => a.code);
    for (const code of ['duplicate-entry', 'suspicious-name', 'encrypted-entry', 'unsupported-method', 'data-after-archive']) assert(codes.includes(code), code + ' in ' + codes);
    assert.equal(zip.anomalies.filter(a => a.code === 'suspicious-name').length, 3);
    assert.equal(zip.read('classes.dex').toString(), 'one', 'the first entry with a name is the one lookups return');
    assert.equal(codeOf(() => zip.read('enc.bin')), 'ZIP_ENCRYPTED');
    assert.equal(codeOf(() => zip.read('odd.bin')), 'ZIP_METHOD');
    zip.read('lies.txt');
    assert(zip.anomalies.some(a => a.code === 'local-name-mismatch'), 'the local header names a different file than the central directory');
  } finally { zip.close(); }
});

test('a decompression bomb is flagged and cannot be read past the byte budget', () => {
  const zip = open(buildZip([{ name: 'bomb', data: Buffer.alloc(8 * 1024 * 1024, 0) }]), { entryBytes: 1024 * 1024 });
  try {
    assert(zip.anomalies.some(a => a.code === 'extreme-compression-ratio'));
    assert.equal(codeOf(() => zip.read('bomb')), 'ZIP_LIMIT');
    assert.equal(codeOf(() => zip.read('bomb', 100)), 'ZIP_LIMIT');
  } finally { zip.close(); }
});

test('an inflated stream longer than the directory claims is cut off while inflating, not expanded first', () => {
  const real = Buffer.alloc(64 * 1024 * 1024, 7);                  // inflates to 64 MiB, the directory claims 100 bytes
  const zip = open(buildZip([{ name: 'liar', data: real, size: 100, crc: crc32(real) }]));
  try {
    const started = Date.now();
    assert.equal(codeOf(() => zip.read('liar')), 'ZIP_INFLATE', 'the output cap must stop the inflate itself');
    assert(Date.now() - started < 3000, 'and it must stop early');
  } finally { zip.close(); }
});

test('a local-header offset pointing outside the file is a range error, not a short read', () => {
  const bytes = buildZip([{ name: 'a', data: text }]);
  const central = bytes.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
  bytes.writeUInt32LE(0x7fffff00, central + 42);
  const zip = open(bytes);
  try { assert.equal(codeOf(() => zip.read('a')), 'ZIP_RANGE'); } finally { zip.close(); }
});

test('an inconsistent decoy end record at the very end does not displace the real one', () => {
  // The decoy claims a 5-byte comment but none follows, so only the real end record is self-consistent.
  const decoy = Buffer.concat([u32(0x06054b50), Buffer.alloc(16), Buffer.from([5, 0])]);
  const zip = open(buildZip([{ name: 'a', data: text }], { comment: Buffer.concat([Buffer.from('c'), decoy]).toString('latin1') }));
  try {
    assert.equal(zip.read('a').toString(), text);
    assert(zip.anomalies.some(a => a.code === 'multiple-eocd'));
  } finally { zip.close(); }
});

test('the APK Signing Block is located and split into id/value pairs', () => {
  const block = buildSigningBlock([{ id: 0x7109871a, value: Buffer.from('v2-signers') }, { id: 0xf05368c0, value: Buffer.from('v3-signers') }]);
  const zip = open(buildZip([{ name: 'a', data: text }], { signingBlock: block }));
  try {
    const found = zip.signingBlock();
    assert.deepEqual(found.pairs.map(p => [p.id.toString(16), p.value.toString()]), [['7109871a', 'v2-signers'], ['f05368c0', 'v3-signers']]);
    assert.equal(found.size, block.length);
    assert.equal(zip.read('a').toString(), text, 'entries are unaffected');
  } finally { zip.close(); }
  const plain = open(buildZip([{ name: 'a', data: text }]));
  assert.equal(plain.signingBlock(), null); plain.close();
  const broken = Buffer.from(block); broken.writeBigUInt64LE(999999n, 0);
  const bad = open(buildZip([{ name: 'a', data: text }], { signingBlock: broken }));
  assert.equal(codeOf(() => bad.signingBlock()), 'ZIP_FORMAT', 'header and footer sizes must agree'); bad.close();
});

test('ZIP64 end records are followed', () => {
  const zip = open(buildZip([{ name: 'a', data: text }, { name: 'b', data: 'second' }], { zip64: true }));
  try { assert.equal(zip.zip64, true); assert.equal(zip.read('b').toString(), 'second'); } finally { zip.close(); }
});

test('an ordinary archive comment does not hide the end record', () => {
  const zip = open(buildZip([{ name: 'a', data: text }], { comment: 'built by a test, comment text' }));
  try { assert.equal(zip.read('a').toString(), text); assert.deepEqual(zip.anomalies, []); } finally { zip.close(); }
});

test('a decoy end record hidden in the comment wins like it does in Android and Python, and the ambiguity is reported', () => {
  // The last self-consistent end record is the one used by libziparchive and zipfile; a parser that prefers the first one reads a different archive.
  const decoy = Buffer.concat([u32(0x06054b50), Buffer.alloc(18)]);
  const zip = open(buildZip([{ name: 'a', data: text }], { comment: Buffer.concat([Buffer.from('c'), decoy]).toString('latin1') }));
  try {
    assert(zip.anomalies.some(a => a.code === 'multiple-eocd' && a.count === 2), JSON.stringify(zip.anomalies));
    assert.equal(zip.entries.length, 0, 'the decoy describes an empty archive');
  } finally { zip.close(); }
});

test('CRC-32 matches the published check value', () => {
  assert.equal(crc32(Buffer.from('123456789')), 0xcbf43926);
});
