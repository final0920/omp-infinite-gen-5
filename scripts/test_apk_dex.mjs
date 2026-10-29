// DEX reader: generated files with known content, hostile headers and bodies, and an independent comparison with dexlib2
// (the smali project's reader). The dexlib2 checks are skipped, loudly, when the bundled JDK is absent.
import assert from 'node:assert/strict';
import test from 'node:test';
import { DEX_LIMITS, DexFile, dexWidthOf } from '../source/apk_dex.js';
import { I, buildDex } from './fixtures/dex_builder.mjs';
import { dexDump, dexLines, opcodeTable, tools } from './fixtures/oracle.mjs';

const OBJECT = 'Ljava/lang/Object;', STRING = 'Ljava/lang/String;';
const codeOf = fn => { try { fn(); } catch (error) { return error.code; } return 'NO-ERROR'; };
const codes = dex => dex.anomalies.map(a => a.code);
const MODEL = { class: 'Landroid/os/Build;', name: 'MODEL', type: STRING };
const OPEN = { class: 'Ljava/net/URL;', name: 'openConnection', params: [], ret: 'Ljava/net/URLConnection;' };
const SUPER_INIT = { class: OBJECT, name: '<init>' };

const sample = () => ({ classes: [
  { name: 'Lcom/example/Main;', access: 1, superclass: OBJECT, source: 'Main.java', interfaces: ['Ljava/lang/Runnable;'], methods: [
    { name: '<init>', direct: true, access: 0x10001, code: { registers: 2, ins: 1, outs: 1, insns: [I.invoke('direct', SUPER_INIT, [0]), I.returnVoid()] } },
    { name: 'run', direct: false, access: 1, code: { registers: 3, ins: 1, outs: 2, insns: [I.constString(0, 'http://c2.example/gate'), I.newInstance(1, 'Ljava/net/URL;'), I.sget(0, MODEL),
      I.invoke('virtual', OPEN, [1]), I.moveResultObject(0), I.returnVoid()] } },
    { name: 'abstractThing', direct: false, access: 0x401 }] },
  { name: 'Lcom/example/Empty;', access: 1, superclass: OBJECT }] });

function describe(dex) {
  return [...dex.classDefs()].map(c => ({ type: c.type, superclass: c.superclass, source: c.source, interfaces: dex.interfaces(c), methods: dex.methodsOf(c).map(m => {
    const scan = dex.scanCode(m.codeOffset);
    return { name: m.ref.text, access: m.access, direct: m.direct, code: scan && { invokes: scan.invokes.map(i => dex.methodRef(i).text), strings: scan.strings.map(i => dex.string(i)),
      fields: scan.fields.map(i => dex.fieldRef(i).text), types: scan.types.map(i => dex.type(i)), registers: scan.registers, ins: scan.ins, outs: scan.outs } };
  }) }));
}

test('a generated file is read back exactly: classes, methods, and who calls what', () => {
  const dex = new DexFile(buildDex(sample()));
  assert.equal(dex.version, '035'); assert.equal(dex.checksumOk, true); assert.equal(dex.signatureOk, true); assert.deepEqual(dex.anomalies, []);
  const [main, empty] = describe(dex);
  assert.equal(main.type, 'Lcom/example/Main;'); assert.equal(main.superclass, OBJECT); assert.equal(main.source, 'Main.java'); assert.deepEqual(main.interfaces, ['Ljava/lang/Runnable;']);
  assert.deepEqual(main.methods.map(m => [m.name, m.direct, m.access, m.code !== null]), [
    ['Lcom/example/Main;-><init>()V', true, 0x10001, true], ['Lcom/example/Main;->abstractThing()V', false, 0x401, false], ['Lcom/example/Main;->run()V', false, 1, true]]);   // methods follow method-id (sorted) order within direct/virtual
  assert.deepEqual(main.methods[0].code.invokes, ['Ljava/lang/Object;-><init>()V']);
  assert.deepEqual(main.methods[2].code, { invokes: ['Ljava/net/URL;->openConnection()Ljava/net/URLConnection;'], strings: ['http://c2.example/gate'], fields: ['Landroid/os/Build;->MODEL:Ljava/lang/String;'],
    types: ['Ljava/net/URL;'], registers: 3, ins: 1, outs: 2 });
  assert.equal(empty.type, 'Lcom/example/Empty;'); assert.deepEqual(empty.methods, []); assert.equal(empty.source, null);
});

test('method attribution is per method, not per file', () => {
  const dex = new DexFile(buildDex({ classes: [{ name: 'LA;', superclass: OBJECT, methods: [
    { name: 'one', direct: false, code: { insns: [I.constString(0, 'only-in-one'), I.returnVoid()] } },
    { name: 'two', direct: false, code: { insns: [I.constString(0, 'only-in-two'), I.returnVoid()] } }] }] }));
  const byName = Object.fromEntries(describe(dex)[0].methods.map(m => [m.name, m.code.strings]));
  assert.deepEqual(byName, { 'LA;->one()V': ['only-in-one'], 'LA;->two()V': ['only-in-two'] });
});

test('every reference-carrying instruction family is attributed, including jumbo strings, ranges and wide type forms', () => {
  const dex = new DexFile(buildDex({ classes: [{ name: 'LA;', superclass: OBJECT, methods: [{ name: 'm', direct: false, code: { insns: [
    I.constStringJumbo(0, 'jumbo'), I.constClass(1, 'LCls;'), I.invokeRange('static', { class: 'LB;', name: 's', params: ['I', 'I'], ret: 'I' }, 0, 2), I.iget(0, 1, { class: 'LA;', name: 'f', type: 'I' }),
    I.raw([0x0023, 0]), I.raw([0x0024, 0, 0]), I.raw([0x0025, 0, 0]), I.returnVoid()] } }] }] }));
  const scan = dex.scanCode(dex.methodsOf([...dex.classDefs()][0])[0].codeOffset);
  assert.deepEqual(scan.strings.map(i => dex.string(i)), ['jumbo']);
  assert.deepEqual(scan.invokes.map(i => dex.methodRef(i).text), ['LB;->s(II)I']);
  assert.deepEqual(scan.fields.map(i => dex.fieldRef(i).text), ['LA;->f:I']);
  assert.equal(scan.types.length, 4, 'const-class plus new-array, filled-new-array and filled-new-array/range'); assert.equal(dex.type(scan.types[0]), 'LCls;');
});

test('a jumbo string index uses all 32 bits', () => {
  const dex = new DexFile(buildDex({ classes: [{ name: 'LA;', superclass: OBJECT, methods: [{ name: 'm', direct: false, code: { insns: [I.raw([0x001b, 0x0001, 0x0001]), I.returnVoid()] } }] }] }));
  assert.deepEqual(dex.scanCode(dex.methodsOf([...dex.classDefs()][0])[0].codeOffset).strings, [0x10001]);
});

test('modified UTF-8: NUL, two-byte, three-byte and supplementary characters decode to the original string', () => {
  const texts = ['a\u0000b', 'é', '中文', '😀 emoji', '\u0000', 'x'.repeat(300)];
  const dex = new DexFile(buildDex({ classes: [{ name: 'LA;', superclass: OBJECT, methods: [{ name: 'm', direct: false, code: { insns: [...texts.map((t, i) => I.constString(i, t)), I.returnVoid()] } }] }] }));
  assert.deepEqual(dex.anomalies, []);
  const scan = dex.scanCode(dex.methodsOf([...dex.classDefs()][0])[0].codeOffset);
  assert.deepEqual(scan.strings.map(i => dex.string(i)), texts);
});

test('string() and the table lookups refuse bad indices instead of throwing', () => {
  const dex = new DexFile(buildDex(sample()));
  for (const bad of [-1, 1e9, 1.5, NaN, undefined, '1']) {
    assert.equal(dex.string(bad), null); assert.equal(dex.type(bad), null); assert.equal(dex.methodRef(bad), null); assert.equal(dex.fieldRef(bad), null);
  }
  assert.equal(dex.string(dex.strings.size), null); assert.equal(dex.type(dex.types.size), null); assert.equal(dex.methodRef(dex.methods.size), null); assert.equal(dex.fieldRef(dex.fields.size), null);
});

test('header trouble is reported as anomalies while the content is still read', () => {
  const sampleCodes = options => codes(new DexFile(buildDex(sample(), options)));
  assert.deepEqual(sampleCodes({ badChecksum: true }), ['checksum-mismatch']);
  assert.deepEqual(sampleCodes({ badSignature: true }), ['signature-mismatch']);
  assert.deepEqual(sampleCodes({ fileSizeLie: 12345 }).includes('file-size-mismatch'), true);
  const lie = new DexFile(buildDex(sample(), { stringLengthLie: 'Main.java' }));
  assert.equal(codes(lie).includes('string-length-mismatch'), false, 'the lie is only seen once the string is read');
  [...lie.classDefs()];
  assert.equal(codes(lie).includes('string-length-mismatch'), true);
  const file = buildDex(sample()); file.writeUInt32LE(0x70 + 4, 36);
  assert.equal(codes(new DexFile(file)).includes('header-size'), true);
});

test('invalid modified UTF-8 and a missing terminator are flagged, not fatal', () => {
  const file = buildDex({ classes: [{ name: 'LA;', superclass: OBJECT, source: 'marker-source' }] });
  const at = file.indexOf('marker-source');
  file[at + 3] = 0xff;                                    // a byte that can never start or continue a sequence
  const dex = new DexFile(file); [...dex.classDefs()];
  assert.equal(codes(dex).includes('invalid-mutf8'), true);
});

test('hostile input is rejected with a code, never an uncaught exception', () => {
  const good = buildDex(sample());
  assert.equal(codeOf(() => new DexFile(Buffer.alloc(10))), 'DEX_FORMAT');
  assert.equal(codeOf(() => new DexFile(Buffer.from('cdex\n001\0'.padEnd(0x70, '\0'), 'latin1'))), 'DEX_FORMAT');
  assert.equal(codeOf(() => new DexFile(Buffer.alloc(0x70))), 'DEX_FORMAT');
  const bigEndian = Buffer.from(good); bigEndian.writeUInt32LE(0x78563412, 40);
  assert.equal(codeOf(() => new DexFile(bigEndian)), 'DEX_FORMAT');
  for (const [at, name] of [[56, 'strings'], [64, 'types'], [72, 'protos'], [80, 'fields'], [88, 'methods'], [96, 'classes']]) {
    const far = Buffer.from(good); far.writeUInt32LE(far.length + 1000, at + 4);
    assert.equal(codeOf(() => new DexFile(far)), 'DEX_FORMAT', `${name} table pointing past the end`);
    const many = Buffer.from(good); many.writeUInt32LE(0x7fffffff, at);
    assert.ok(['DEX_LIMIT', 'DEX_FORMAT'].includes(codeOf(() => new DexFile(many))), `${name} table with an absurd count`);
  }
  const budget = codeOf(() => new DexFile(good, { strings: 2 })); assert.equal(budget, 'DEX_LIMIT');
  assert.equal(codeOf(() => new DexFile(good, { bytes: 100 })), 'DEX_FORMAT');
});

test('a truncated file keeps failing safely at every cut point', () => {
  const good = buildDex(sample());
  for (let cut = 0; cut < good.length; cut += 7) {
    const piece = good.subarray(0, cut);
    try { const dex = new DexFile(piece); for (const c of dex.classDefs()) for (const m of dex.methodsOf(c)) dex.scanCode(m.codeOffset); }
    catch (error) { assert.ok(/^DEX_/.test(error.code), `cut ${cut}: ${error.stack}`); }
  }
});

test('bad class_data and code offsets are anomalies, a bad LEB128 or method count is a coded error', () => {
  const main = () => { const file = buildDex(sample()), dex = new DexFile(file); return { file, dex, c: [...dex.classDefs()][0] }; };
  const cd = main(); cd.file.writeUInt32LE(cd.file.length + 50, cd.dex.classes.offset + 24);
  const afterCd = new DexFile(cd.file); assert.deepEqual(afterCd.methodsOf([...afterCd.classDefs()][0]), []); assert.equal(codes(afterCd).includes('bad-class-data'), true);
  const dex = new DexFile(buildDex(sample()));
  assert.equal(dex.scanCode(0x7ffffff0), null); assert.equal(codes(dex).includes('bad-code-offset'), true);
  const sizeFile = buildDex(sample()), sizeDex = new DexFile(sizeFile), method = sizeDex.methodsOf([...sizeDex.classDefs()][0])[0];
  sizeFile.writeUInt32LE(0x7fffffff, method.codeOffset + 12);
  assert.equal(sizeDex.scanCode(method.codeOffset), null); assert.equal(codes(sizeDex).includes('bad-code-size'), true);
  const past = buildDex(sample()), pastDex = new DexFile(past);      // within the instruction budget but beyond the end of the file
  past.writeUInt32LE(past.length, pastDex.methodsOf([...pastDex.classDefs()][0])[0].codeOffset + 12);
  assert.equal(pastDex.scanCode(pastDex.methodsOf([...pastDex.classDefs()][0])[0].codeOffset), null);
  const lebFile = buildDex(sample()), lebDex = new DexFile(lebFile), c = [...lebDex.classDefs()][0];
  lebFile.fill(0xff, c.dataOffset, c.dataOffset + 6); lebFile[c.dataOffset + 6] = 0x01;      // six bytes: a ULEB128 is at most five
  assert.equal(codeOf(() => lebDex.uleb(c.dataOffset)), 'DEX_FORMAT');
  lebFile.fill(0xff, c.dataOffset + 7, c.dataOffset + 9); lebFile.fill(0, c.dataOffset, c.dataOffset + 5); assert.equal(lebDex.uleb(c.dataOffset).value, 0);
  lebFile.fill(0xff, c.dataOffset, c.dataOffset + 40);       // a continuation bit that never ends
  assert.equal(codeOf(() => lebDex.methodsOf(c)), 'DEX_FORMAT');
  const many = buildDex(sample()), manyDex = new DexFile(many, { methodsPerClass: 1 });
  assert.equal(codeOf(() => manyDex.methodsOf([...manyDex.classDefs()][0])), 'DEX_LIMIT');
});

test('switch and array payloads are skipped as data, so the instruction after them is still found', () => {
  const dex = new DexFile(buildDex({ classes: [{ name: 'LA;', superclass: OBJECT, methods: [{ name: 'm', direct: false, code: { insns: [
    I.returnVoid(), I.packedSwitchPayload(1, [4, 5, 6]), I.sparseSwitchPayload([1, 100], [4, 5]), I.fillArrayDataPayload(1, [1, 2, 3, 4, 5]), I.fillArrayDataPayload(8, [1, 2, 3, 4, 5, 6, 7, 8]),
    I.constString(0, 'after-payloads'), I.returnVoid()] } }] }] }));
  const scan = dex.scanCode(dex.methodsOf([...dex.classDefs()][0])[0].codeOffset, { trace: true });
  assert.equal(scan.truncated, false); assert.deepEqual(scan.strings.map(i => dex.string(i)), ['after-payloads']);
  assert.deepEqual(scan.sequence.map(s => [s.op, s.units]), [[0x0e, 1], [0x100, 10], [0x200, 10], [0x300, 7], [0x300, 8], [0x1a, 2], [0x0e, 1]]);
});

test('a payload that claims more data than the method has is truncated, not followed past the end', () => {
  const dex = new DexFile(buildDex({ classes: [{ name: 'LA;', superclass: OBJECT, methods: [{ name: 'm', direct: false, code: { insns: [I.raw([0x0100, 0xffff, 0, 0]), I.returnVoid()] } }] }] }));
  const scan = dex.scanCode(dex.methodsOf([...dex.classDefs()][0])[0].codeOffset);
  assert.equal(scan.truncated, true); assert.equal(codes(dex).includes('truncated-instruction'), true);
  const cut = new DexFile(buildDex({ classes: [{ name: 'LA;', superclass: OBJECT, methods: [{ name: 'm', direct: false, code: { insns: [I.raw([0x0300, 4, 0xffff])] } }] }] }));
  assert.equal(cut.scanCode(cut.methodsOf([...cut.classDefs()][0])[0].codeOffset).truncated, true);
});

test('an instruction whose width runs past the end of the method is flagged', () => {
  const dex = new DexFile(buildDex({ classes: [{ name: 'LA;', superclass: OBJECT, methods: [{ name: 'm', direct: false, code: { insns: [I.raw([0x001a])] } }] }] }));
  assert.equal(dex.scanCode(dex.methodsOf([...dex.classDefs()][0])[0].codeOffset).truncated, true);
});

test('the width table is complete and consistent', () => {
  assert.equal(dexWidthOf(0x00), 1); assert.equal(dexWidthOf(0x18), 5); assert.equal(dexWidthOf(0x6e), 3); assert.equal(dexWidthOf(0x1a), 2); assert.equal(dexWidthOf(0x1b), 3);
  for (let op = 0; op < 256; op++) assert.ok(dexWidthOf(op) >= 1 && dexWidthOf(op) <= 5, `opcode ${op}`);
  assert.ok(DEX_LIMITS.insns > 0 && Object.isFrozen(DEX_LIMITS));
});

// ---- independent comparison with dexlib2 -----------------------------------------------------------------------------

const skipOracle = { skip: tools ? false : 'bundled JDK / dexlib2 not found' };

test('dexlib2 sees the same classes, methods, instruction stream and references', skipOracle, () => {
  const bytes = buildDex(sample());
  assert.deepEqual(dexLines(new DexFile(bytes)), dexDump(bytes));
});

test('dexlib2 agrees on strings with NUL, non-ASCII and supplementary characters, and on jumbo/range/array forms', skipOracle, () => {
  const bytes = buildDex({ classes: [{ name: 'LA;', superclass: OBJECT, methods: [{ name: 'm', direct: false, code: { insns: [
    I.constString(0, 'a\u0000b'), I.constString(1, 'é中'), I.constString(2, '😀'), I.constStringJumbo(3, 'jumbo'), I.constClass(4, 'LCls;'), I.invokeRange('static', { class: 'LB;', name: 's', params: ['I', 'I'], ret: 'I' }, 0, 2),
    I.raw([0x0023, 0]), I.raw([0x0024, 0, 0]), I.raw([0x0025, 0, 0]), I.raw([0x001f, 0]), I.raw([0x0020, 0]), I.returnVoid(),
    I.packedSwitchPayload(0, [3, 4]), I.sparseSwitchPayload([5], [6]), I.fillArrayDataPayload(2, [1, 2, 3, 4, 5, 6]), I.returnVoid()] } }] }] });
  assert.deepEqual(dexLines(new DexFile(bytes)), dexDump(bytes));
});

test('dexlib2 and the width table agree on every opcode it defines', skipOracle, () => {
  const table = opcodeTable();
  assert.ok(table.size >= 240, `reference defines ${table.size} opcodes`);
  const disagree = [...table].filter(([value, { units }]) => value < 0x100 && dexWidthOf(value) !== units).map(([value, { name, units }]) => `${name}(0x${value.toString(16)}): ours ${dexWidthOf(value)} vs ${units}`);
  assert.deepEqual(disagree, []);
});

test('a method holding one instruction of every opcode dexlib2 defines decodes to the same stream', skipOracle, () => {
  const table = opcodeTable(), insns = [];
  const field = I.sget(0, { class: 'LA;', name: 'f', type: 'I' });
  for (const [value, { units }] of [...table].sort((a, b) => a[0] - b[0])) {
    if (value >= 0xfa) continue;                          // invoke-polymorphic/custom and method handle forms need extra tables the generator does not build
    if (value >= 0x100) continue;                         // payload pseudo-instructions are covered above
    insns.push(I.raw([value, ...Array(units - 1).fill(0)]));
  }
  const bytes = buildDex({ classes: [{ name: 'LA;', superclass: OBJECT, methods: [{ name: 'm', params: [], direct: false, code: { insns: [field, I.constString(0, 's'), I.newInstance(0, 'LA;'), I.invoke('static', { class: 'LA;', name: 'x' }, []), ...insns, I.returnVoid()] } }] }] });
  const ours = dexLines(new DexFile(bytes)), theirs = dexDump(bytes);
  assert.deepEqual(ours, theirs);
  assert.ok(ours.filter(line => line.startsWith('OP ')).length > 200, 'the stream really contains hundreds of instructions');
});
