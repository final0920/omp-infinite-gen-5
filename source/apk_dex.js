import { createHash } from 'node:crypto';

// DEX reader with a Dalvik instruction sweep. It resolves string/type/field/method tables lazily, validates every
// index and offset, and, for each method body, lists the methods it invokes, the fields it touches, the types it
// instantiates and the strings it loads. That attribution (who calls what) is the point: a method-id table alone only
// says what a file mentions. Nothing is executed. Obfuscators corrupt headers on purpose, so problems the Android
// runtime tolerates are reported as anomalies instead of aborting.
const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
export const DEX_LIMITS = Object.freeze({ bytes: 128 * 1024 * 1024, strings: 3000000, types: 1000000, methods: 1000000, fields: 1000000, classes: 500000, insns: 2000000, methodsPerClass: 20000 });
const HEADER = 0x70;

// Width of every Dalvik instruction in 16-bit code units, indexed by opcode (dex format reference). Payload pseudo-instructions
// (packed-switch, sparse-switch, fill-array-data) are recognised separately because their length is data-dependent.
const WIDTH = (() => {
  const w = new Uint8Array(256).fill(1);
  for (const [from, to, units] of [[0x02, 0x02, 2], [0x03, 0x03, 3], [0x05, 0x05, 2], [0x06, 0x06, 3], [0x08, 0x08, 2], [0x09, 0x09, 3], [0x13, 0x13, 2], [0x14, 0x14, 3],
    [0x15, 0x16, 2], [0x17, 0x17, 3], [0x18, 0x18, 5], [0x19, 0x19, 2], [0x1a, 0x1a, 2], [0x1b, 0x1b, 3], [0x1c, 0x1c, 2], [0x1f, 0x20, 2], [0x22, 0x23, 2], [0x24, 0x26, 3],
    [0x29, 0x29, 2], [0x2a, 0x2c, 3], [0x2d, 0x3d, 2], [0x44, 0x6d, 2], [0x6e, 0x72, 3], [0x74, 0x78, 3], [0x90, 0xaf, 2], [0xd0, 0xe2, 2],
    // ART "quickened" opcodes only occur in optimized files, never in a shipped classes.dex, but their widths are known:
    [0xe3, 0xe8, 2], [0xe9, 0xea, 3], [0xeb, 0xf2, 2], [0xfa, 0xfb, 4], [0xfc, 0xfd, 3], [0xfe, 0xff, 2]])
    for (let op = from; op <= to; op++) w[op] = units;
  return w;
})();
const OPS = { constString: 0x1a, constStringJumbo: 0x1b };
// const-class, check-cast, instance-of, new-instance, new-array, filled-new-array, filled-new-array/range
const isTypeRef = op => op === 0x1c || op === 0x1f || op === 0x20 || (op >= 0x22 && op <= 0x25);
const isInvoke = op => (op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78) || op === 0xfa || op === 0xfb;
const isField = op => op >= 0x52 && op <= 0x6d;

function adler32(buffer, from) { let a = 1, b = 0; for (let i = from; i < buffer.length;) { const end = Math.min(buffer.length, i + 5552); for (; i < end; i++) { a += buffer[i]; b += a; } a %= 65521; b %= 65521; } return ((b << 16) | a) >>> 0; }

export class DexFile {
  constructor(buffer, options = {}) {
    const limits = { ...DEX_LIMITS, ...options };
    this.limits = limits; this.b = buffer; this.anomalies = []; this.stringCache = new Map();
    if (buffer.length < HEADER || buffer.length > limits.bytes) fail('DEX_FORMAT', 'Not a DEX file (size)');
    const magic = buffer.toString('latin1', 0, 8);
    if (!/^dex\n0\d\d\0$/.test(magic)) fail('DEX_FORMAT', magic.startsWith('cdex') ? 'Compact DEX is not supported' : 'Not a DEX file (magic)');
    this.version = magic.slice(4, 7);
    if (buffer.readUInt32LE(40) !== 0x12345678) fail('DEX_FORMAT', 'Only little-endian DEX files are supported');
    this.header = { checksum: buffer.readUInt32LE(8), signature: buffer.subarray(12, 32).toString('hex'), fileSize: buffer.readUInt32LE(32), headerSize: buffer.readUInt32LE(36),
      mapOffset: buffer.readUInt32LE(52) };
    if (this.header.headerSize !== HEADER) this.#note('header-size', { value: this.header.headerSize });
    if (this.header.fileSize !== buffer.length) this.#note('file-size-mismatch', { declared: this.header.fileSize, actual: buffer.length });
    this.checksumOk = adler32(buffer, 12) === this.header.checksum;
    this.signatureOk = createHash('sha1').update(buffer.subarray(32)).digest('hex') === this.header.signature;
    if (!this.checksumOk) this.#note('checksum-mismatch');
    if (!this.signatureOk) this.#note('signature-mismatch');
    const section = (name, at, itemSize, max) => {
      const size = buffer.readUInt32LE(at), offset = buffer.readUInt32LE(at + 4);
      if (size > max) fail('DEX_LIMIT', `${name} count ${size} exceeds the budget ${max}`);
      if (size && (offset < HEADER || offset + size * itemSize > buffer.length)) fail('DEX_FORMAT', `${name} table lies outside the file`);
      return { size, offset };
    };
    this.strings = section('string_ids', 56, 4, limits.strings); this.types = section('type_ids', 64, 4, limits.types); this.protos = section('proto_ids', 72, 12, limits.types);
    this.fields = section('field_ids', 80, 8, limits.fields); this.methods = section('method_ids', 88, 8, limits.methods); this.classes = section('class_defs', 96, 32, limits.classes);
  }

  #note(code, detail = {}) { if (this.anomalies.length < 64) this.anomalies.push({ code, ...detail }); }

  uleb(at) {
    let result = 0, shift = 0;
    for (let i = 0; i < 5; i++) {
      if (at + i >= this.b.length) fail('DEX_FORMAT', 'LEB128 runs past the file');
      const byte = this.b[at + i];
      result += (byte & 0x7f) * 2 ** shift; shift += 7;
      if (!(byte & 0x80)) return { value: result, next: at + i + 1 };
    }
    return fail('DEX_FORMAT', 'LEB128 value is longer than 5 bytes');
  }

  /** Modified UTF-8 string ``index`` (null if the index is invalid). */
  string(index) {
    if (!Number.isInteger(index) || index < 0 || index >= this.strings.size) return null;
    if (this.stringCache.has(index)) return this.stringCache.get(index);
    const dataAt = this.b.readUInt32LE(this.strings.offset + index * 4);
    if (dataAt < HEADER || dataAt >= this.b.length) { this.#note('bad-string-offset', { index }); return null; }
    const { value: declared, next } = this.uleb(dataAt);
    const units = [];
    let at = next, bad = false;
    for (; at < this.b.length && this.b[at] !== 0; at++) {
      const byte = this.b[at];
      if (byte < 0x80) units.push(byte);
      else if ((byte & 0xe0) === 0xc0 && at + 1 < this.b.length && (this.b[at + 1] & 0xc0) === 0x80) { units.push(((byte & 0x1f) << 6) | (this.b[at + 1] & 0x3f)); at += 1; }
      else if ((byte & 0xf0) === 0xe0 && at + 2 < this.b.length && (this.b[at + 1] & 0xc0) === 0x80 && (this.b[at + 2] & 0xc0) === 0x80) { units.push(((byte & 0x0f) << 12) | ((this.b[at + 1] & 0x3f) << 6) | (this.b[at + 2] & 0x3f)); at += 2; }
      else { units.push(0xfffd); bad = true; }
      if (units.length > 1 << 20) { this.#note('string-too-long', { index }); break; }
    }
    if (at >= this.b.length) this.#note('unterminated-string', { index });
    if (bad) this.#note('invalid-mutf8', { index });
    if (declared !== units.length) this.#note('string-length-mismatch', { index, declared, actual: units.length });
    let text = '';
    for (let i = 0; i < units.length; i += 8192) text += String.fromCharCode(...units.slice(i, i + 8192));
    if (this.stringCache.size < 200000) this.stringCache.set(index, text);
    return text;
  }

  type(index) { if (!Number.isInteger(index) || index < 0 || index >= this.types.size) return null; return this.string(this.b.readUInt32LE(this.types.offset + index * 4)); }

  #proto(index) {
    if (index < 0 || index >= this.protos.size) return '()?';
    const at = this.protos.offset + index * 12, ret = this.type(this.b.readUInt32LE(at + 4)) ?? '?', paramsAt = this.b.readUInt32LE(at + 8);
    let params = '';
    if (paramsAt) {
      if (paramsAt + 4 > this.b.length) return `(?)${ret}`;
      const count = Math.min(this.b.readUInt32LE(paramsAt), 255);
      for (let i = 0; i < count && paramsAt + 4 + i * 2 + 2 <= this.b.length; i++) params += this.type(this.b.readUInt16LE(paramsAt + 4 + i * 2)) ?? '?';
    }
    return `(${params})${ret}`;
  }

  methodRef(index) {
    if (!Number.isInteger(index) || index < 0 || index >= this.methods.size) return null;
    const at = this.methods.offset + index * 8, cls = this.type(this.b.readUInt16LE(at)) ?? '?', name = this.string(this.b.readUInt32LE(at + 4)) ?? '?', proto = this.#proto(this.b.readUInt16LE(at + 2));
    return { index, class: cls, name, proto, text: `${cls}->${name}${proto}` };
  }

  fieldRef(index) {
    if (!Number.isInteger(index) || index < 0 || index >= this.fields.size) return null;
    const at = this.fields.offset + index * 8, cls = this.type(this.b.readUInt16LE(at)) ?? '?', type = this.type(this.b.readUInt16LE(at + 2)) ?? '?', name = this.string(this.b.readUInt32LE(at + 4)) ?? '?';
    return { index, class: cls, name, type, text: `${cls}->${name}:${type}` };
  }

  /** Class definitions in file order. */
  * classDefs() {
    for (let i = 0; i < this.classes.size; i++) {
      const at = this.classes.offset + i * 32, superIndex = this.b.readUInt32LE(at + 8), sourceIndex = this.b.readUInt32LE(at + 16);
      yield { index: i, type: this.type(this.b.readUInt32LE(at)), access: this.b.readUInt32LE(at + 4), superclass: superIndex === 0xffffffff ? null : this.type(superIndex),
        source: sourceIndex === 0xffffffff ? null : this.string(sourceIndex), dataOffset: this.b.readUInt32LE(at + 24), interfacesOffset: this.b.readUInt32LE(at + 12) };
    }
  }

  interfaces(classDef) {
    const at = classDef.interfacesOffset;
    if (!at || at + 4 > this.b.length) return [];
    const count = Math.min(this.b.readUInt32LE(at), 256), out = [];
    for (let i = 0; i < count && at + 4 + i * 2 + 2 <= this.b.length; i++) out.push(this.type(this.b.readUInt16LE(at + 4 + i * 2)));
    return out;
  }

  /** Methods declared by a class: { ref, access, direct, codeOffset }. */
  methodsOf(classDef) {
    if (!classDef.dataOffset) return [];
    if (classDef.dataOffset < HEADER || classDef.dataOffset >= this.b.length) { this.#note('bad-class-data', { class: classDef.type }); return []; }
    let { value: staticFields, next } = this.uleb(classDef.dataOffset), r;
    ({ value: r, next } = this.uleb(next)); const instanceFields = r;
    ({ value: r, next } = this.uleb(next)); const direct = r;
    ({ value: r, next } = this.uleb(next)); const virtual = r;
    if (direct + virtual > this.limits.methodsPerClass) fail('DEX_LIMIT', `Class ${classDef.type} declares ${direct + virtual} methods`);
    for (let i = 0; i < staticFields + instanceFields; i++) { ({ next } = this.uleb(next)); ({ next } = this.uleb(next)); }
    const methods = [];
    for (const [count, isDirect] of [[direct, true], [virtual, false]]) {
      let index = 0;
      for (let i = 0; i < count; i++) {
        let diff, access, code;
        ({ value: diff, next } = this.uleb(next)); ({ value: access, next } = this.uleb(next)); ({ value: code, next } = this.uleb(next));
        index += diff;
        const ref = this.methodRef(index);
        if (!ref) { this.#note('bad-method-index', { class: classDef.type, index }); continue; }
        methods.push({ ref, access, direct: isDirect, codeOffset: code });
      }
    }
    return methods;
  }

  /**
   * Linear sweep of one code_item. Returns the invoked method indices, touched field indices, instantiated or
   * referenced type indices and loaded string indices. ``trace`` additionally records every (opcode, width).
   */
  scanCode(codeOffset, { trace = false } = {}) {
    if (!codeOffset) return null;
    if (codeOffset < HEADER || codeOffset + 16 > this.b.length) { this.#note('bad-code-offset', { codeOffset }); return null; }
    const b = this.b, size = b.readUInt32LE(codeOffset + 12), start = codeOffset + 16;
    if (size > this.limits.insns || start + size * 2 > b.length) { this.#note('bad-code-size', { codeOffset, size }); return null; }
    const result = { registers: b.readUInt16LE(codeOffset), ins: b.readUInt16LE(codeOffset + 2), outs: b.readUInt16LE(codeOffset + 4), tries: b.readUInt16LE(codeOffset + 6), insnsSize: size,
      invokes: [], fields: [], types: [], strings: [], truncated: false, ...(trace ? { instructions: [], sequence: [] } : {}) };
    for (let pc = 0; pc < size;) {
      const unit = b.readUInt16LE(start + pc * 2), op = unit & 0xff;
      let width, code = op;
      if (unit === 0x0100 || unit === 0x0200 || unit === 0x0300) {                 // data-carrying pseudo-instructions
        code = unit;
        if (pc + 2 > size) { result.truncated = true; break; }
        const n = b.readUInt16LE(start + (pc + 1) * 2);
        if (unit === 0x0100) width = 4 + 2 * n;
        else if (unit === 0x0200) width = 2 + 4 * n;
        else { if (pc + 4 > size) { result.truncated = true; break; } width = 4 + Math.ceil((b.readUInt32LE(start + (pc + 2) * 2) * n) / 2); }
      } else width = WIDTH[op];
      if (pc + width > size) { result.truncated = true; if (trace) result.instructions.push([code, width]); break; }
      const arg = pc + 1 < size ? b.readUInt16LE(start + (pc + 1) * 2) : 0;
      let reference = null;
      if (code < 0x100) {
        if (isInvoke(op)) { result.invokes.push(arg); reference = ['invoke', arg]; }
        else if (isField(op)) { result.fields.push(arg); reference = ['field', arg]; }
        else if (op === OPS.constString) { result.strings.push(arg); reference = ['string', arg]; }
        else if (op === OPS.constStringJumbo) { const index = pc + 2 < size ? b.readUInt32LE(start + (pc + 1) * 2) : 0; result.strings.push(index); reference = ['string', index]; }
        else if (isTypeRef(op)) { result.types.push(arg); reference = ['type', arg]; }
      }
      if (trace) { result.instructions.push([code, width]); result.sequence.push({ op: code, units: width, reference }); }
      pc += width;
    }
    if (result.truncated) this.#note('truncated-instruction', { codeOffset });
    return result;
  }
}

export const dexWidthOf = op => WIDTH[op];
