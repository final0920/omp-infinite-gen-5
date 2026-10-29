// Test-side builders for APK analysis: ZIP archives (with deliberate defects), Android binary XML and DEX files.
// They follow the published formats from scratch so the parsers are checked against a second reading of the spec,
// not against themselves. Nothing here is executed; the outputs are inert byte buffers.
import zlib from 'node:zlib';
import { crc32 } from '../../source/apk_zip.js';

const u16 = value => { const b = Buffer.alloc(2); b.writeUInt16LE(value); return b; };
const u32 = value => { const b = Buffer.alloc(4); b.writeUInt32LE(value >>> 0); return b; };
const u64 = value => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(value)); return b; };

/**
 * entries: [{ name, data, method: 'store'|'deflate'|<number>, flags, crc, size, localName, rawData, extra }]
 * options: { comment, trailing, signingBlock: Buffer (inserted before the central directory), zip64 }
 */
export function buildZip(entries, options = {}) {
  const parts = [], central = [];
  let offset = 0;
  const push = buffer => { parts.push(buffer); offset += buffer.length; };
  for (const entry of entries) {
    const data = Buffer.from(entry.data ?? '');
    const method = entry.method === 'deflate' || entry.method === undefined ? 8 : entry.method === 'store' ? 0 : entry.method;
    const payload = entry.rawData ?? (method === 8 ? zlib.deflateRawSync(data, { level: 9 }) : data);
    const crc = entry.crc ?? crc32(data), size = entry.size ?? data.length, flags = entry.flags ?? 0;
    const name = Buffer.from(entry.name), localName = Buffer.from(entry.localName ?? entry.name), extra = entry.extra ?? Buffer.alloc(0);
    const localOffset = offset;
    push(Buffer.concat([u32(0x04034b50), u16(20), u16(flags), u16(method), u16(0), u16(0x21), u32(crc), u32(payload.length), u32(size), u16(localName.length), u16(0), localName, payload]));
    central.push(Buffer.concat([u32(0x02014b50), u16(20), u16(20), u16(flags), u16(method), u16(0), u16(0x21), u32(crc), u32(payload.length), u32(size),
      u16(name.length), u16(extra.length), u16(0), u16(0), u16(0), u32(0), u32(localOffset), name, extra]));
  }
  if (options.signingBlock) push(options.signingBlock);
  const directory = Buffer.concat(central), comment = Buffer.from(options.comment ?? '');
  const centralOffset = offset;
  push(directory);
  if (options.zip64) {
    const recordOffset = offset;
    push(Buffer.concat([u32(0x06064b50), u64(44), u16(45), u16(45), u32(0), u32(0), u64(entries.length), u64(entries.length), u64(directory.length), u64(centralOffset)]));
    push(Buffer.concat([u32(0x07064b50), u32(0), u64(recordOffset), u32(1)]));
    push(Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(0xffff), u16(0xffff), u32(0xffffffff), u32(0xffffffff), u16(comment.length), comment]));
  } else {
    push(Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(entries.length), u16(entries.length), u32(directory.length), u32(centralOffset), u16(comment.length), comment]));
  }
  if (options.trailing) push(Buffer.from(options.trailing));
  return Buffer.concat(parts);
}

/** An APK Signing Block holding the given id/value pairs (id: number, value: Buffer). */
export function buildSigningBlock(pairs) {
  const body = Buffer.concat(pairs.map(({ id, value }) => Buffer.concat([u64(value.length + 4), u32(id), value])));
  const size = body.length + 24;
  return Buffer.concat([u64(size), body, u64(size), Buffer.from('APK Sig Block 42')]);
}

/**
 * Android binary XML. element: { name, ns?, attrs: [{ name, ns?, resId?, poolName?, type, value }], children: [] }
 * type: 'string' | 'int' | 'hex' | 'bool' | 'ref' | 'float' | 'null'. resId puts the attribute name first in the pool and in the resource map,
 * as aapt does; poolName overrides the pool string while resId keeps the real identity (an obfuscated manifest).
 * options: { utf8, resourceMap, namespaces: [{ prefix, uri }] }
 */
export function buildAxml(root, options = {}) {
  const { utf8 = false, resourceMap = true, namespaces = [{ prefix: 'android', uri: 'http://schemas.android.com/apk/res/android' }] } = options;
  const pool = [], index = new Map(), ids = [];
  const add = (text, key = text) => { if (!index.has(key)) { index.set(key, pool.length); pool.push(text); } return index.get(key); };
  const withIds = [];
  const walk = element => { for (const a of element.attrs ?? []) if (a.resId !== undefined) withIds.push(a); (element.children ?? []).forEach(walk); };
  walk(root);
  const nameKey = a => `\0id:${a.resId}:${a.poolName ?? a.name}`;
  for (const a of [...withIds].sort((x, y) => x.resId - y.resId)) if (!index.has(nameKey(a))) { add(a.poolName ?? a.name, nameKey(a)); ids.push(a.resId); }
  const NS = namespaces.map(n => ({ prefix: add(n.prefix), uri: add(n.uri) }));
  const uriIndex = uri => (uri === undefined || uri === null ? 0xffffffff : add(uri));
  const encodePool = () => {
    const parts = [], offsets = [];
    let cursor = 0;
    for (const text of pool) {
      let body;
      if (utf8) {
        const bytes = Buffer.from(text, 'utf8'), chars = Buffer.from(text, 'utf16le').length / 2;
        // A UTF-8 pool stores lengths in 7 or 15 bits; aapt cannot produce a longer string, so refuse to build one.
        if (chars > 0x7fff || bytes.length > 0x7fff) throw new Error('a UTF-8 string pool cannot hold a string longer than 32767');
        const len = n => (n < 0x80 ? Buffer.from([n]) : Buffer.from([0x80 | (n >> 8), n & 255]));
        body = Buffer.concat([len(chars), len(bytes.length), bytes, Buffer.from([0])]);
      } else {
        const units = Buffer.from(text, 'utf16le'), n = units.length / 2;
        body = Buffer.concat([n < 0x8000 ? u16(n) : Buffer.concat([u16(0x8000 | (n >> 16)), u16(n & 0xffff)]), units, u16(0)]);
      }
      offsets.push(cursor); parts.push(body); cursor += body.length;
    }
    let data = Buffer.concat(parts);
    if (data.length % 4) data = Buffer.concat([data, Buffer.alloc(4 - (data.length % 4))]);
    const headerSize = 28, stringsStart = headerSize + pool.length * 4;
    return Buffer.concat([u16(0x0001), u16(headerSize), u32(stringsStart + data.length), u32(pool.length), u32(0), u32(utf8 ? 0x100 : 0), u32(stringsStart), u32(0),
      ...offsets.map(u32), data]);
  };
  const node = (type, line, ...ext) => { const body = Buffer.concat(ext); return Buffer.concat([u16(type), u16(16), u32(16 + body.length), u32(line), u32(0xffffffff), body]); };
  const encodeValue = a => {
    const t = a.type ?? 'string';
    if (t === 'string') { const i = add(String(a.value)); return [i, 0x03, i]; }
    if (t === 'int') return [0xffffffff, 0x10, a.value >>> 0];
    if (t === 'hex') return [0xffffffff, 0x11, a.value >>> 0];
    if (t === 'bool') return [0xffffffff, 0x12, a.value ? 0xffffffff : 0];
    if (t === 'ref') return [0xffffffff, 0x01, a.value >>> 0];
    if (t === 'float') { const b = Buffer.alloc(4); b.writeFloatLE(a.value); return [0xffffffff, 0x04, b.readUInt32LE(0)]; }
    return [0xffffffff, 0x00, 0];
  };
  // strings referenced by elements are interned before the pool is serialized
  const elementChunks = [];
  const encodeElement = (element, depth) => {
    const nameIndex = add(element.name), nsIndex = uriIndex(element.ns);
    const attrs = (element.attrs ?? []).map(a => {
      const attrNs = uriIndex(a.ns), attrName = a.resId !== undefined ? index.get(nameKey(a)) : add(a.poolName ?? a.name), [raw, dataType, data] = encodeValue(a);
      return Buffer.concat([u32(attrNs), u32(attrName), u32(raw), u16(8), Buffer.from([0, dataType]), u32(data)]);
    });
    elementChunks.push(node(0x0102, depth + 2, u32(nsIndex), u32(nameIndex), u16(20), u16(20), u16(attrs.length), u16(0), u16(0), u16(0), ...attrs));
    (element.children ?? []).forEach(child => encodeElement(child, depth + 1));
    elementChunks.push(node(0x0103, depth + 2, u32(nsIndex), u32(nameIndex)));
  };
  encodeElement(root, 0);
  const startNs = NS.map((n, i) => node(0x0100, 1, u32(n.prefix), u32(n.uri))), endNs = [...NS].reverse().map(n => node(0x0101, 1, u32(n.prefix), u32(n.uri)));
  const map = resourceMap && ids.length ? Buffer.concat([u16(0x0180), u16(8), u32(8 + ids.length * 4), ...ids.map(u32)]) : Buffer.alloc(0);
  const body = Buffer.concat([encodePool(), map, ...startNs, ...elementChunks, ...endNs]);
  return Buffer.concat([u16(0x0003), u16(8), u32(8 + body.length), body]);
}

export { u16, u32, u64 };
