// Test-side DEX writer, built from the published format description. Output is an inert byte buffer used to check the
// parser; it is never run. Pools are sorted as the format requires, the checksum and SHA-1 signature are real, and
// instructions are written through a small DSL that resolves pool indices in a second pass.
import { createHash } from 'node:crypto';

const u16 = value => { const b = Buffer.alloc(2); b.writeUInt16LE(value & 0xffff); return b; };
const u32 = value => { const b = Buffer.alloc(4); b.writeUInt32LE(value >>> 0); return b; };
export function uleb(value) { const out = []; do { let byte = value & 0x7f; value = Math.floor(value / 128); if (value) byte |= 0x80; out.push(byte); } while (value); return Buffer.from(out); }
export function mutf8(text) {
  const bytes = [];
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit === 0) bytes.push(0xc0, 0x80);
    else if (unit < 0x80) bytes.push(unit);
    else if (unit < 0x800) bytes.push(0xc0 | (unit >> 6), 0x80 | (unit & 0x3f));
    else bytes.push(0xe0 | (unit >> 12), 0x80 | ((unit >> 6) & 0x3f), 0x80 | (unit & 0x3f));
  }
  return Buffer.from(bytes);
}
export function adler32(buffer) { let a = 1, b = 0; for (const byte of buffer) { a = (a + byte) % 65521; b = (b + a) % 65521; } return ((b << 16) | a) >>> 0; }
const align = (parts, size, to) => { while (size.value % to) { parts.push(Buffer.alloc(1)); size.value += 1; } };
const shorty = d => (d.startsWith('L') || d.startsWith('[') ? 'L' : d[0]);

/** Instruction constructors: each returns (ctx) => array of 16-bit code units. */
const invokeOps = { virtual: 0x6e, super: 0x6f, direct: 0x70, static: 0x71, interface: 0x72 };
export const I = {
  nop: () => () => [0x0000],
  returnVoid: () => () => [0x000e],
  moveResult: reg => () => [(reg << 8) | 0x0a],
  moveResultObject: reg => () => [(reg << 8) | 0x0c],
  const4: (reg, value) => () => [((value & 0xf) << 12) | (reg << 8) | 0x12],
  constString: (reg, text) => ctx => [(reg << 8) | 0x1a, ctx.str(text)],
  constStringJumbo: (reg, text) => ctx => { const i = ctx.str(text); return [(reg << 8) | 0x1b, i & 0xffff, i >>> 16]; },
  constClass: (reg, type) => ctx => [(reg << 8) | 0x1c, ctx.type(type)],
  newInstance: (reg, type) => ctx => [(reg << 8) | 0x22, ctx.type(type)],
  invoke: (kind, method, regs = []) => ctx => {
    const [c = 0, d = 0, e = 0, f = 0, g = 0] = regs;
    return [(regs.length << 12) | (g << 8) | invokeOps[kind], ctx.method(method), c | (d << 4) | (e << 8) | (f << 12)];
  },
  invokeRange: (kind, method, first, count) => ctx => [(count << 8) | (invokeOps[kind] + 0x06), ctx.method(method), first],
  sget: (reg, field) => ctx => [(reg << 8) | 0x60, ctx.field(field)],
  iget: (reg, object, field) => ctx => [(object << 12) | (reg << 8) | 0x52, ctx.field(field)],
  ifEqz: (reg, offset) => () => [(reg << 8) | 0x38, offset & 0xffff],
  goto: offset => () => [((offset & 0xff) << 8) | 0x28],
  packedSwitchPayload: (firstKey, targets) => () => [0x0100, targets.length, firstKey & 0xffff, (firstKey >>> 16) & 0xffff, ...targets.flatMap(t => [t & 0xffff, (t >>> 16) & 0xffff])],
  sparseSwitchPayload: (keys, targets) => () => [0x0200, keys.length, ...keys.flatMap(k => [k & 0xffff, (k >>> 16) & 0xffff]), ...targets.flatMap(t => [t & 0xffff, (t >>> 16) & 0xffff])],
  fillArrayDataPayload: (width, bytes) => () => { const padded = Buffer.concat([Buffer.from(bytes), Buffer.alloc(bytes.length % 2)]), count = bytes.length / width; const units = []; for (let i = 0; i < padded.length; i += 2) units.push(padded.readUInt16LE(i)); return [0x0300, width, count & 0xffff, count >>> 16, ...units]; },
  raw: units => () => units,
};

/**
 * spec: { classes: [{ name, access, superclass, source, interfaces, methods: [{ name, params, ret, access, direct, code: { registers, ins, outs, insns: [instruction...] } }] }] }
 * options: { version, badChecksum, badSignature, fileSizeLie }
 */
export function buildDex(spec, options = {}) {
  const { version = '035' } = options;
  const strings = new Set(), types = new Set(), protos = new Map(), fields = new Map(), methods = new Map();
  const addType = d => { strings.add(d); types.add(d); return d; };
  const protoKey = (params, ret) => `${ret}(${params.join('')})`;
  const addProto = (params, ret) => { addType(ret); params.forEach(addType); const key = protoKey(params, ret); strings.add(shorty(ret) + params.map(shorty).join('')); protos.set(key, { params, ret }); return key; };
  const methodKey = m => `${m.class}->${m.name}${protoKey(m.params ?? [], m.ret ?? 'V')}`;
  const addMethod = m => { addType(m.class); strings.add(m.name); addProto(m.params ?? [], m.ret ?? 'V'); methods.set(methodKey(m), { class: m.class, name: m.name, params: m.params ?? [], ret: m.ret ?? 'V' }); return methodKey(m); };
  const fieldKey = f => `${f.class}->${f.name}:${f.type}`;
  const addField = f => { addType(f.class); addType(f.type); strings.add(f.name); fields.set(fieldKey(f), f); return fieldKey(f); };
  const collect = { str: s => { strings.add(s); return 0; }, type: t => { addType(t); return 0; }, field: f => { addField(f); return 0; }, method: m => { addMethod(m); return 0; } };
  for (const cls of spec.classes) {
    addType(cls.name); if (cls.superclass) addType(cls.superclass); (cls.interfaces ?? []).forEach(addType); if (cls.source) strings.add(cls.source);
    for (const m of cls.methods ?? []) { addMethod({ class: cls.name, name: m.name, params: m.params, ret: m.ret }); for (const ins of m.code?.insns ?? []) ins(collect); }
  }
  const stringList = [...strings].sort(), stringIndex = new Map(stringList.map((s, i) => [s, i]));
  const typeList = [...types].sort((a, b) => stringIndex.get(a) - stringIndex.get(b)), typeIndex = new Map(typeList.map((t, i) => [t, i]));
  const protoList = [...protos.entries()].sort(([, a], [, b]) => typeIndex.get(a.ret) - typeIndex.get(b.ret) || a.params.map(p => typeIndex.get(p)).join(',').localeCompare(b.params.map(p => typeIndex.get(p)).join(','))), protoIndex = new Map(protoList.map(([k], i) => [k, i]));
  const fieldList = [...fields.values()].sort((a, b) => typeIndex.get(a.class) - typeIndex.get(b.class) || stringIndex.get(a.name) - stringIndex.get(b.name) || typeIndex.get(a.type) - typeIndex.get(b.type));
  const fieldIndex = new Map(fieldList.map((f, i) => [fieldKey(f), i]));
  const methodList = [...methods.values()].sort((a, b) => typeIndex.get(a.class) - typeIndex.get(b.class) || stringIndex.get(a.name) - stringIndex.get(b.name) || protoIndex.get(protoKey(a.params, a.ret)) - protoIndex.get(protoKey(b.params, b.ret)));
  const methodIndex = new Map(methodList.map((m, i) => [methodKey(m), i]));
  const final = { str: s => stringIndex.get(s), type: t => typeIndex.get(t), field: f => fieldIndex.get(fieldKey(f)), method: m => methodIndex.get(methodKey(m)) };

  const stringsAt = 0x70, typesAt = stringsAt + stringList.length * 4, protosAt = typesAt + typeList.length * 4, fieldsAt = protosAt + protoList.length * 12;
  const methodsAt = fieldsAt + fieldList.length * 8, classesAt = methodsAt + methodList.length * 8, dataAt = classesAt + spec.classes.length * 32;
  const data = [], position = { value: dataAt }, map = [];
  const emit = (buffer, kind) => { const at = position.value; data.push(buffer); position.value += buffer.length; return at; };
  const section = (type, size, offset) => { if (size) map.push({ type, size, offset }); };

  const stringOffsets = []; let firstString = position.value;
  for (const text of stringList) { const body = mutf8(text); const declared = options.stringLengthLie === text ? text.length + 1 : text.length; stringOffsets.push(emit(Buffer.concat([uleb(declared), body, Buffer.from([0])]))); }
  section(0x2002, stringList.length, firstString);
  const listOffsets = new Map(); let firstList = null;
  const typeListAt = list => { if (!list.length) return 0; const key = list.join(','); if (listOffsets.has(key)) return listOffsets.get(key); align(data, position, 4); const at = emit(Buffer.concat([u32(list.length), ...list.map(t => u16(typeIndex.get(t))), Buffer.alloc(list.length % 2 ? 2 : 0)])); firstList ??= at; listOffsets.set(key, at); return at; };
  const protoParams = protoList.map(([, p]) => typeListAt(p.params));
  const interfaceAt = spec.classes.map(c => typeListAt(c.interfaces ?? []));
  if (listOffsets.size) section(0x1001, listOffsets.size, firstList);

  const codeAt = new Map(); let firstCode = null;
  for (const cls of spec.classes) for (const m of cls.methods ?? []) {
    if (!m.code) continue;
    const units = m.code.insns.flatMap(ins => ins(final)), body = Buffer.concat([u16(m.code.registers ?? 4), u16(m.code.ins ?? 0), u16(m.code.outs ?? 0), u16(0), u32(0), u32(units.length), ...units.map(u16)]);
    align(data, position, 4); const at = emit(body); firstCode ??= at; codeAt.set(`${cls.name}.${m.name}${(m.params ?? []).join('')}`, at);
  }
  if (codeAt.size) section(0x2001, codeAt.size, firstCode);

  const classData = []; let firstData = null;
  for (const cls of spec.classes) {
    const own = (cls.methods ?? []).map(m => ({ m, idx: methodIndex.get(methodKey({ class: cls.name, name: m.name, params: m.params, ret: m.ret })), code: codeAt.get(`${cls.name}.${m.name}${(m.params ?? []).join('')}`) ?? 0 }));
    const direct = own.filter(x => x.m.direct).sort((a, b) => a.idx - b.idx), virtual = own.filter(x => !x.m.direct).sort((a, b) => a.idx - b.idx);
    if (!own.length) { classData.push(0); continue; }
    const encode = group => { let previous = 0; return Buffer.concat(group.map(x => { const out = Buffer.concat([uleb(x.idx - previous), uleb(x.m.access ?? 1), uleb(x.code)]); previous = x.idx; return out; })); };
    const at = emit(Buffer.concat([uleb(0), uleb(0), uleb(direct.length), uleb(virtual.length), encode(direct), encode(virtual)]));
    firstData ??= at; classData.push(at);
  }
  if (firstData !== null) section(0x2000, classData.filter(Boolean).length, firstData);
  align(data, position, 4);
  const mapAt = position.value;
  const mapItems = [{ type: 0x0000, size: 1, offset: 0 }, { type: 0x0001, size: stringList.length, offset: stringsAt }, { type: 0x0002, size: typeList.length, offset: typesAt },
    { type: 0x0003, size: protoList.length, offset: protosAt }, { type: 0x0004, size: fieldList.length, offset: fieldsAt }, { type: 0x0005, size: methodList.length, offset: methodsAt },
    { type: 0x0006, size: spec.classes.length, offset: classesAt }, ...map, { type: 0x1000, size: 1, offset: mapAt }].filter(item => item.size);
  emit(Buffer.concat([u32(mapItems.length), ...mapItems.map(item => Buffer.concat([u16(item.type), u16(0), u32(item.size), u32(item.offset)]))]));
  const total = position.value;

  const header = Buffer.alloc(0x70);
  header.write(`dex\n${version}\0`, 0, 'latin1');
  header.writeUInt32LE(options.fileSizeLie ?? total, 32); header.writeUInt32LE(0x70, 36); header.writeUInt32LE(0x12345678, 40);
  header.writeUInt32LE(mapAt, 52);
  [[56, stringList.length, stringsAt], [64, typeList.length, typesAt], [72, protoList.length, protosAt], [80, fieldList.length, fieldsAt], [88, methodList.length, methodsAt], [96, spec.classes.length, classesAt]]
    .forEach(([at, size, offset]) => { header.writeUInt32LE(size, at); header.writeUInt32LE(size ? offset : 0, at + 4); });
  header.writeUInt32LE(total - dataAt, 104); header.writeUInt32LE(dataAt, 108);
  const body = Buffer.concat([
    ...stringOffsets.map(u32), ...typeList.map(t => u32(stringIndex.get(t))),
    ...protoList.flatMap(([, p], i) => [u32(stringIndex.get(shorty(p.ret) + p.params.map(shorty).join(''))), u32(typeIndex.get(p.ret)), u32(protoParams[i])]),
    ...fieldList.map(f => Buffer.concat([u16(typeIndex.get(f.class)), u16(typeIndex.get(f.type)), u32(stringIndex.get(f.name))])),
    ...methodList.map(m => Buffer.concat([u16(typeIndex.get(m.class)), u16(protoIndex.get(protoKey(m.params, m.ret))), u32(stringIndex.get(m.name))])),
    ...spec.classes.map((c, i) => Buffer.concat([u32(typeIndex.get(c.name)), u32(c.access ?? 1), u32(c.superclass ? typeIndex.get(c.superclass) : 0xffffffff), u32(interfaceAt[i]),
      u32(c.source ? stringIndex.get(c.source) : 0xffffffff), u32(0), u32(classData[i]), u32(0)])),
    ...data]);
  const file = Buffer.concat([header, body]);
  file.write(`dex\n${version}\0`, 0, 'latin1');
  createHash('sha1').update(file.subarray(32)).digest().copy(file, 12);
  if (options.badSignature) file[12] ^= 0xff;
  file.writeUInt32LE(adler32(file.subarray(12)), 8);
  if (options.badChecksum) file.writeUInt32LE((file.readUInt32LE(8) + 1) >>> 0, 8);
  return file;
}
