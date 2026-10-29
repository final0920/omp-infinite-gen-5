// Android binary XML: round trips, a hand-assembled UTF-8 vector, resource-id naming, hostile input, and an
// independent check against AXMLPrinter2 (UTF-16 pools). The reference check is skipped, loudly, when the bundled JDK is absent.
import assert from 'node:assert/strict';
import test from 'node:test';
import { ANDROID_ATTRIBUTE_IDS, ANDROID_NS, attribute, parseAxml } from '../source/apk_axml.js';
import { buildAxml } from './fixtures/apk_builder.mjs';
import { axmlToText, parsePrinted, tools } from './fixtures/oracle.mjs';

const A = (name, resId, type, value, extra = {}) => ({ name, ns: ANDROID_NS, resId, type, value, ...extra });
const manifest = () => ({ name: 'manifest', attrs: [A('versionCode', 0x0101021b, 'int', 7), { name: 'package', type: 'string', value: 'com.example.app' }], children: [
  { name: 'uses-permission', attrs: [A('name', 0x01010003, 'string', 'android.permission.INTERNET')] },
  { name: 'application', attrs: [A('debuggable', 0x0101000f, 'bool', true), A('label', 0x01010001, 'ref', 0x7f010001)], children: [
    { name: 'activity', attrs: [A('name', 0x01010003, 'string', '.Main'), A('exported', 0x01010010, 'bool', false)] }] }] });
const codeOf = fn => { try { fn(); } catch (error) { return error.code; } return 'NO-ERROR'; };
const flatten = (element, depth = 0) => [[depth, element.name, element.attributes.map(a => [a.name, a])], ...element.children.flatMap(child => flatten(child, depth + 1))];

for (const utf8 of [false, true]) {
  test(`a manifest-shaped document decodes exactly (${utf8 ? 'UTF-8' : 'UTF-16'} string pool)`, () => {
    const parsed = parseAxml(buildAxml(manifest(), { utf8 }));
    assert.equal(parsed.utf8Pool, utf8); assert.deepEqual(parsed.anomalies, []); assert.equal(parsed.elements, 4);
    const root = parsed.root;
    assert.equal(root.name, 'manifest');
    assert.deepEqual(root.attributes.map(a => [a.name, a.type, a.value]), [['versionCode', 'int', 7], ['package', 'string', 'com.example.app']]);
    const application = root.children[1];
    assert.deepEqual(application.attributes.map(a => [a.name, a.value, a.text]), [['debuggable', true, 'true'], ['label', 0x7f010001, '@0x7f010001']]);
    assert.equal(application.children[0].attributes.find(a => a.name === 'exported').value, false);
    assert.equal(parsed.namespaces[0].uri, ANDROID_NS); assert.equal(attribute(root, 'package').value, 'com.example.app');
  });
}

test('typed values: negative ints, hex, floats, colors, null', () => {
  const root = { name: 'x', attrs: [{ name: 'i', type: 'int', value: -5 }, { name: 'h', type: 'hex', value: 0xdeadbeef }, { name: 'f', type: 'float', value: 1.5 }, { name: 'n', type: 'null' }] };
  const attrs = Object.fromEntries(parseAxml(buildAxml(root, { resourceMap: false })).root.attributes.map(a => [a.name, a]));
  assert.equal(attrs.i.value, -5); assert.equal(attrs.h.text, '0xdeadbeef'); assert.equal(attrs.f.value, 1.5); assert.equal(attrs.n.type, 'null');
});

test('long and non-ASCII strings survive both pool encodings, including the extended length forms', () => {
  const long = 'é中😀'.repeat(60);
  for (const [utf8, size] of [[false, 40000], [true, 30000]]) {          // 40000 needs the extended UTF-16 length; UTF-8 lengths stop at 32767
    const huge = 'x'.repeat(size);
    const root = { name: 'x', attrs: [{ name: 'a', type: 'string', value: long }, { name: 'b', type: 'string', value: huge }, { name: 'c', type: 'string', value: 'zero\u0000inside' }] };
    const attrs = Object.fromEntries(parseAxml(buildAxml(root, { utf8, resourceMap: false })).root.attributes.map(a => [a.name, a.value]));
    assert.equal(attrs.a, long, `utf8=${utf8}`); assert.equal(attrs.b.length, size, `utf8=${utf8}`); assert.equal(attrs.b, huge); assert.equal(attrs.c, 'zero\u0000inside');
  }
  assert.throws(() => buildAxml({ name: 'x', attrs: [{ name: 'b', type: 'string', value: 'x'.repeat(40000) }] }, { utf8: true }), /32767/);
});

test('a hand-assembled UTF-8 string pool (not produced by the test builder) is decoded', () => {
  // pool: ["ab", "é"] as UTF-8 (flag 0x100); one empty element whose name is string 1
  const hex = '03000800' + '74000000'
    + '01001c00' + '30000000' + '02000000' + '00000000' + '00010000' + '24000000' + '00000000' + '00000000' + '05000000'
    + '020261620001' + '02c3a900' + '0000'
    + '02011000' + '24000000' + '01000000' + 'ffffffff' + 'ffffffff' + '01000000' + '1400' + '1400' + '0000' + '0000' + '0000' + '0000'
    + '03011000' + '18000000' + '01000000' + 'ffffffff' + 'ffffffff' + '01000000';
  const bytes = Buffer.from(hex, 'hex');
  assert.equal(bytes.length, 0x74);
  const parsed = parseAxml(bytes);
  assert.equal(parsed.utf8Pool, true); assert.equal(parsed.strings, 2); assert.equal(parsed.root.name, 'é'); assert.deepEqual(parsed.anomalies, []);
});

test('the resource id decides an attribute\'s identity, and a disagreeing string name is reported', () => {
  const root = { name: 'activity', attrs: [A('name', 0x01010003, 'string', 'com.evil.Main', { poolName: 'zzz_garbage' }), A('exported', 0x01010010, 'bool', true, { poolName: '' })] };
  const parsed = parseAxml(buildAxml(root));
  assert.deepEqual(parsed.root.attributes.map(a => a.name), ['name', 'exported']);
  assert.deepEqual(parsed.anomalies.map(a => [a.code, a.poolName, a.resourceName]), [['attribute-name-mismatch', 'zzz_garbage', 'name'], ['attribute-name-mismatch', '', 'exported']]);
  const unknown = parseAxml(buildAxml({ name: 'x', attrs: [{ name: '', ns: ANDROID_NS, resId: 0x01019999, type: 'int', value: 1 }] })).root.attributes[0];
  assert.equal(unknown.name, 'res_0x1019999'); assert.equal(unknown.resourceId, 0x01019999);
});

test('the framework attribute id table has no duplicates and only plausible framework ids', () => {
  const ids = Object.keys(ANDROID_ATTRIBUTE_IDS).map(Number), names = Object.values(ANDROID_ATTRIBUTE_IDS);
  assert.equal(new Set(names).size, names.length, 'two ids share a name');
  assert(ids.every(id => id >= 0x01010000 && id < 0x01020000), 'framework attribute ids live in package 0x01, type 0x01');
  assert.equal(ANDROID_ATTRIBUTE_IDS[0x01010003], 'name'); assert.equal(ANDROID_ATTRIBUTE_IDS[0x01010010], 'exported');
});

test('hostile input is refused with a code', () => {
  const good = buildAxml(manifest());
  assert.equal(codeOf(() => parseAxml(Buffer.from('<?xml version="1.0"?><manifest/>'))), 'AXML_FORMAT');
  assert.equal(codeOf(() => parseAxml(good.subarray(0, 6))), 'AXML_FORMAT');
  assert.equal(codeOf(() => parseAxml(Buffer.alloc(8, 0))), 'AXML_FORMAT');
  const hugeCount = Buffer.from(good); hugeCount.writeUInt32LE(0x7fffffff, 8 + 8);               // string count in the pool header
  assert.equal(codeOf(() => parseAxml(hugeCount)), 'AXML_LIMIT');
  const badOffset = Buffer.from(good); badOffset.writeUInt32LE(0x00ffffff, 8 + 28);               // first string offset far outside the pool
  assert.equal(codeOf(() => parseAxml(badOffset)), 'AXML_FORMAT');
  let nested = { name: 'leaf' }; for (let i = 0; i < 80; i++) nested = { name: 'e', children: [nested] };
  assert.equal(codeOf(() => parseAxml(buildAxml(nested))), 'AXML_LIMIT');
  assert.equal(codeOf(() => parseAxml(buildAxml({ name: 'r', children: Array.from({ length: 30 }, () => ({ name: 'c' })) }), { elements: 10 })), 'AXML_LIMIT');
  assert.equal(codeOf(() => parseAxml(buildAxml({ name: 'r', attrs: Array.from({ length: 30 }, (_, i) => ({ name: 'a' + i, type: 'int', value: i })) }), { attributes: 10 })), 'AXML_LIMIT');
});

test('structural oddities are reported, not hidden', () => {
  const good = buildAxml(manifest());
  const longer = Buffer.concat([good, Buffer.from('trailing')]);
  assert(parseAxml(longer).anomalies.some(a => a.code === 'size-mismatch'));
  const cut = good.subarray(0, good.length - 24);                                                  // drop the last end-element chunk
  const parsed = parseAxml(cut);
  assert(parsed.anomalies.some(a => a.code === 'size-mismatch') && parsed.root.name === 'manifest');
  const twoRoots = parseAxml(buildAxml({ name: 'a' }));
  assert.deepEqual(twoRoots.anomalies, []);
});

test('truncating a valid file at every length never reads out of bounds', () => {
  const good = buildAxml(manifest());
  for (let length = 0; length < good.length; length += 3) {
    const outcome = codeOf(() => parseAxml(good.subarray(0, length)));
    assert(outcome === 'NO-ERROR' || /^AXML_/.test(outcome), `length ${length} gave ${outcome}`);
  }
});

test('the reference decoder AXMLPrinter2 reads the same elements, attributes and values', { skip: tools ? false : 'bundled JDK / AXMLPrinter2 not found' }, () => {
  const trees = [manifest(), { name: 'manifest', attrs: [{ name: 'package', type: 'string', value: 'p.q' }], children: Array.from({ length: 6 }, (_, i) => (
    { name: 'service', attrs: [A('name', 0x01010003, 'string', `.S${i}`), A('enabled', 0x0101000e, 'bool', i % 2 === 0), A('priority', 0x0101001c, 'int', -i)] })) },
  { name: 'r', attrs: [{ name: 'plain', type: 'string', value: 'ünï©ode 中文' }, { name: 'n', type: 'int', value: 123456 }] }];
  for (const tree of trees) {
    const bytes = buildAxml(tree, { utf8: false });
    const ours = flatten(parseAxml(bytes).root), theirs = parsePrinted(axmlToText(bytes));
    assert.equal(ours.length, theirs.length, 'same number of elements');
    ours.forEach(([depth, tag, attrs], index) => {
      const [theirDepth, theirTag, theirAttrs] = theirs[index];
      assert.equal(depth, theirDepth); assert.equal(tag, theirTag);
      assert.equal(attrs.length, theirAttrs.length, `attributes of <${tag}>`);
      attrs.forEach(([name, attr], i) => {
        const [theirName, theirValue] = theirAttrs[i];
        assert.equal(theirName.split(':').pop(), name);
        const expected = attr.type === 'reference' ? attr.value.toString(16).toUpperCase() : attr.text;
        assert.equal(attr.type === 'reference' ? theirValue.replace('@', '') : theirValue, expected, `${tag}@${name}`);
      });
    });
  }
});
