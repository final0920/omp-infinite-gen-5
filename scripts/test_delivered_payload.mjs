import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectDeliveredPayload, DELIVERED_PAYLOAD_LIMITS } from '../source/delivered_payload.js';
import { jsonToolOutput } from '../source/json_output.js';

const inspect = (value, options = {}) => inspectDeliveredPayload(Buffer.isBuffer(value) ? value : Buffer.from(value), options);
const has = (result, format) => result.candidates.some(candidate => candidate.format === format);
function pe() {
  const bytes = Buffer.alloc(512); bytes.write('MZ'); bytes.writeUInt32LE(128, 60); bytes.write('PE\0\0', 128);
  bytes.writeUInt16LE(0x8664, 132); bytes.writeUInt16LE(1, 134); bytes.writeUInt16LE(112, 148); bytes.writeUInt16LE(0x20b, 152);
  return bytes;
}
function elf(bits, endian) {
  const bytes = Buffer.alloc(bits === 32 ? 52 : 64); bytes.set([0x7f, 0x45, 0x4c, 0x46, bits === 32 ? 1 : 2, endian === 'little' ? 1 : 2, 1]);
  const write = (value, offset) => endian === 'little' ? bytes.writeUInt16LE(value, offset) : bytes.writeUInt16BE(value, offset);
  write(bits === 32 ? 3 : 62, 18); write(bytes.length, bits === 32 ? 40 : 52); return bytes;
}

test('PE bytes override dishonest MIME without claiming file validity', () => {
  const result = inspect(pe(), { contentType: 'text/javascript; password=SECRET', complete: true });
  assert.ok(has(result, 'pe')); assert.equal(has(result, 'javascript'), false);
  assert.equal(result.candidates[0].validation, 'header-only');
  assert.equal(result.evidence.find(item => item.code === 'PE_COFF_HEADER').boundedHeaderShapeConsistent, true);
  assert.equal(result.source.complete, true); assert.equal(result.preview.hex, '4d5a');
  assert.equal(JSON.stringify(result).includes('SECRET'), false);
});

test('PE pointer cannot escape byte or inspection bounds; MZ alone does not validate PE', () => {
  assert.equal(inspect('MZ').candidates[0].validation, 'incomplete-header');
  const huge = pe(); huge.writeUInt32LE(0xffffffff, 60);
  assert.ok(inspect(huge).evidence.some(item => item.code === 'PE_HEADER_POINTER_OUTSIDE_CAPTURE'));
  const earlier = pe(); earlier.writeUInt32LE(1, 60);
  assert.ok(has(inspect(earlier), 'dos-or-malformed-pe'));
  const mismatch = pe(); mismatch.write('NOPE', 128);
  assert.ok(inspect(mismatch).evidence.some(item => item.code === 'PE_SIGNATURE_MISMATCH'));
  const budget = Buffer.alloc(300000); budget.write('MZ'); budget.writeUInt32LE(270000, 60);
  assert.ok(inspect(budget).evidence.some(item => item.code === 'PE_HEADER_POINTER_OUTSIDE_BUDGET'));
});

test('ELF identifies class and endian using both encodings without validating tables', () => {
  for (const bits of [32, 64]) for (const endian of ['little', 'big']) {
    const result = inspect(elf(bits, endian));
    assert.ok(has(result, 'elf'));
    const ident = result.evidence.find(item => item.code === 'ELF_IDENT');
    assert.equal(ident.bits, bits); assert.equal(ident.endian, endian);
    assert.equal(result.evidence.find(item => item.code === 'ELF_HEADER_FIELDS').boundedHeaderShapeConsistent, true);
  }
  assert.ok(inspect(Buffer.from([0x7f, 0x45, 0x4c, 0x46])).evidence.some(item => item.code === 'ELF_IDENT_INCOMPLETE'));
  const invalid = elf(64, 'little'); invalid[4] = 3; invalid[5] = 9;
  assert.equal(inspect(invalid).evidence.find(item => item.code === 'ELF_IDENT').bits, null);
});

test('WASM checks version prefix, retains truncation, and never instantiates modules', () => {
  const raw = Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]);
  assert.equal(inspect(raw).evidence.find(item => item.code === 'WASM_HEADER').supportedVersionPrefix, true);
  raw[4] = 2; assert.equal(inspect(raw).evidence.find(item => item.code === 'WASM_HEADER').supportedVersionPrefix, false);
  const short = inspect(raw.subarray(0, 6), { complete: true, truncated: true });
  assert.equal(short.source.complete, false); assert.equal(short.source.completeness, 'partial');
  assert.equal(short.evidence.find(item => item.code === 'WASM_HEADER').version, null);
});

test('gzip, zlib and ZIP hints require explicit bounded decode and ignore script MIME', () => {
  const fixtures = [['gzip', Buffer.from([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3])],
    ['zlib', Buffer.from([0x78, 0x9c, 1, 0])], ['zip', Buffer.from([0x50, 0x4b, 3, 4])]];
  for (const [format, bytes] of fixtures) {
    const result = inspect(bytes, { contentType: 'text/javascript' });
    assert.ok(has(result, format)); assert.equal(result.encoding.requiresExplicitDecode, true);
    assert.equal(result.text.inspected, false); assert.equal(has(result, 'javascript'), false);
  }
  const bogus = inspect(Buffer.from([0x1f, 0x8b, 9, 0xe0]));
  assert.equal(bogus.evidence[0].reservedFlagsClear, false); assert.equal(bogus.evidence[0].deflateMethod, false);
  const archive = Buffer.alloc(30); archive.set([0x50, 0x4b, 3, 4]); archive.writeUInt16LE(65535, 26);
  assert.equal(inspect(archive).evidence.find(item => item.code === 'ZIP_LOCAL_HEADER_FIELDS').variableHeaderPresent, false);
});

test('unverified Content-Encoding defers text interpretation without overriding binary evidence', () => {
  const result = inspect('const secret = "DO_NOT_REVEAL";', { contentType: 'text/javascript', contentEncoding: 'gzip' });
  assert.equal(result.text.inspected, false); assert.equal(result.encoding.reason, 'unverified-content-encoding-hint');
  assert.equal(has(result, 'javascript'), false); assert.equal(JSON.stringify(result).includes('DO_NOT_REVEAL'), false);
  assert.ok(has(inspect(pe(), { contentEncoding: 'br' }), 'pe'));
});

test('JSON returns only structure counts with unsafe-number caveats, never secrets or key names', () => {
  const result = inspect('{"password":"SENTINEL_SECRET","__proto__":{"x":1},"function":"function injected() {}","big":9007199254740993,"over":1e999}', { complete: true });
  assert.ok(has(result, 'json')); assert.equal(has(result, 'javascript'), false);
  assert.equal(result.text.json.topLevel, 'object'); assert.equal(result.text.json.topLevelMembers, 5);
  assert.equal(result.text.json.valuesIncluded, false); assert.equal(result.text.json.keyNamesIncluded, false);
  assert.equal(result.text.json.unsafeNumberRepresentations, 2);
  const output = JSON.stringify(result);
  for (const value of ['password', 'SENTINEL_SECRET', '__proto__', 'injected']) assert.equal(output.includes(value), false);
  assert.deepEqual(jsonToolOutput(result), result);
});

test('strict JSON handles scalars, invalid syntax and invalid UTF-8 without echoing parser input', () => {
  for (const value of ['"TOKEN_SECRET"', 'true', 'false', 'null', '-0', '12.25', '[]']) assert.ok(has(inspect(value), 'json'));
  for (const value of ['{"password":"DONT_PRINT",}', '{bad}', '\ufeff{"a":1}']) {
    const result = inspect(value); assert.equal(has(result, 'json'), false); assert.equal(JSON.stringify(result).includes('DONT_PRINT'), false);
  }
  const invalid = inspect(Buffer.from([0xc3, 0x28, 0x7b, 0x7d]), { contentType: 'application/json' });
  assert.equal(invalid.text.utf8, false); assert.equal(has(invalid, 'json'), false);
});

test('JSON depth, tokens and byte limits stop parsing with explicit budget evidence', () => {
  const deep = inspect('['.repeat(33) + '0' + ']'.repeat(33));
  assert.equal(deep.text.json.reason, 'json-depth-budget'); assert.equal(deep.budget.jsonBudgetExceeded, true);
  assert.equal(has(deep, 'json'), false);
  const many = inspect('[' + Array(5000).fill('0').join(',') + ']');
  assert.equal(many.text.json.reason, 'json-token-budget');
  const large = inspect(Buffer.alloc(DELIVERED_PAYLOAD_LIMITS.textBytes + 1, 0x20));
  assert.equal(large.text.inspected, false); assert.equal(large.budget.textBudgetExceeded, true);
  assert.throws(() => inspect(Buffer.alloc(DELIVERED_PAYLOAD_LIMITS.inputBytes + 1)), { code: 'DELIVERED_PAYLOAD_INPUT' });
});

test('braces inside JSON strings do not consume nesting budget or appear in output', () => {
  const result = inspect(JSON.stringify({ secret: '['.repeat(10000), other: '\\\\"{}}' }));
  assert.ok(has(result, 'json')); assert.equal(result.budget.jsonBudgetExceeded, false);
  assert.ok(JSON.stringify(result).length < 7000);
});

test('JS, HTML and shebang are unexecuted lexical hints; MIME alone is insufficient', () => {
  globalThis.__ig5DeliveredProbe = 0;
  const result = inspect('const stolen = (globalThis.__ig5DeliveredProbe = 99); function run(){ throw new Error("SECRET_SCRIPT"); }', { contentType: 'application/json' });
  assert.ok(has(result, 'javascript')); assert.equal(globalThis.__ig5DeliveredProbe, 0);
  assert.equal(JSON.stringify(result).includes('SECRET_SCRIPT'), false);
  assert.equal(result.candidates[0].validation, 'heuristic');
  assert.ok(has(inspect('<!DOCTYPE html><html><script>globalThis.__ig5DeliveredProbe=777</script></html>'), 'html'));
  assert.equal(inspect('#!/usr/bin/env python3\nprint("secret")').candidates[0].language, 'python');
  assert.ok(has(inspect('plain text', { contentType: 'application/javascript' }), 'text'));
  assert.equal(globalThis.__ig5DeliveredProbe, 0); delete globalThis.__ig5DeliveredProbe;
});

test('opaque/control bytes do not cause encryption claims or payload previews', () => {
  const result = inspect(Buffer.from([0, 1, 2, 3, 4, 200, 202, 210]));
  assert.ok(has(result, 'unknown')); assert.equal(result.preview.kind, 'omitted');
  assert.equal(result.candidates.some(item => /encrypt|aes|xor/i.test(item.format)), false);
  const controls = inspect(Buffer.from([0x61, 0, 0x62])); assert.equal(controls.text.disallowedControlCharacters, 1);
  assert.ok(has(inspect(''), 'empty'));
});

test('WS compression and continuation block whole-message text or JSON claims', () => {
  for (const websocket of [{ opcode: 1, fin: false, compressed: false }, { opcode: 0, fin: true, compressed: false }, { opcode: 1, fin: true, compressed: true }]) {
    const result = inspect('{"code":"secret"}', { websocket, complete: true });
    assert.equal(has(result, 'json'), false); assert.equal(result.text.inspected, false);
    assert.equal(JSON.stringify(result).includes('secret'), false);
  }
  assert.ok(has(inspect('{"x":1}', { websocket: { opcode: 1, fin: true, compressed: false }, complete: true }), 'json'));
  const control = inspect('const a = 1', { websocket: { opcode: 9, fin: true, compressed: false }, complete: true });
  assert.ok(has(control, 'websocket-control')); assert.equal(has(control, 'javascript'), false);
  const compressed = inspect(pe(), { websocket: { opcode: 2, fin: true, compressed: true }, complete: true });
  assert.equal(has(compressed, 'pe'), false); assert.equal(compressed.encoding.requiresExplicitDecode, true);
});

test('results stay strict JSON, bounded and immutable; metadata getters are never evaluated', () => {
  const original = pe(), copy = Buffer.from(original), result = inspect(original, { contentType: 'secret-type/'.repeat(1000), contentEncoding: 'CUSTOM_SECRET_ENCODING' });
  assert.deepEqual(original, copy); assert.equal(result.media.metadataTruncated, true);
  assert.deepEqual(result.media.contentEncodingHint, ['unknown']);
  assert.equal(JSON.stringify(result).includes('CUSTOM_SECRET_ENCODING'), false);
  assert.deepEqual(jsonToolOutput(result), result);
  for (const raw of ['hello', '{"a":1}', '\n'.repeat(65536) + 'unclassified', pe(), elf(64, 'big')]) assert.doesNotThrow(() => jsonToolOutput(inspect(raw)));
  assert.throws(() => inspectDeliveredPayload('string'), { code: 'DELIVERED_PAYLOAD_INPUT' });
  assert.throws(() => inspect('x', { complete: 'true' }), { code: 'DELIVERED_PAYLOAD_INPUT' });
  let invoked = false; const options = {}; Object.defineProperty(options, 'contentType', { get() { invoked = true; return 'text/plain'; } });
  assert.throws(() => inspect('x', options), { code: 'DELIVERED_PAYLOAD_INPUT' }); assert.equal(invoked, false);
});
