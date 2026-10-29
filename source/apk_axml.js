// Android binary XML (AXML) decoder, as used for AndroidManifest.xml. Iterative (no recursion), fully bounds-checked,
// and tolerant in the way Android is: attribute names are resolved from the RESOURCE ID when one is present, because
// the platform ignores the string name then. A disagreement between the two is reported as an anomaly, since
// obfuscators rewrite names to confuse tools that trust the string.
const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
export const AXML_LIMITS = Object.freeze({ bytes: 16 * 1024 * 1024, strings: 200000, elements: 50000, attributes: 2000, depth: 64 });
const TYPE = { xml: 0x0003, pool: 0x0001, map: 0x0180, startNs: 0x0100, endNs: 0x0101, start: 0x0102, end: 0x0103, cdata: 0x0104 };
const NONE = 0xffffffff;
export const ANDROID_NS = 'http://schemas.android.com/apk/res/android';

// Framework attribute resource ids that matter for a manifest. Only ids that are certain are listed; an id not
// listed here falls back to the name in the string pool.
export const ANDROID_ATTRIBUTE_IDS = Object.freeze({
  0x01010000: 'theme', 0x01010001: 'label', 0x01010002: 'icon', 0x01010003: 'name', 0x01010006: 'permission', 0x01010007: 'readPermission',
  0x01010008: 'writePermission', 0x01010009: 'protectionLevel', 0x0101000a: 'permissionGroup', 0x0101000b: 'sharedUserId', 0x0101000c: 'hasCode',
  0x0101000d: 'persistent', 0x0101000e: 'enabled', 0x0101000f: 'debuggable', 0x01010010: 'exported', 0x01010011: 'process', 0x01010012: 'taskAffinity',
  0x01010018: 'authorities', 0x0101001b: 'grantUriPermissions', 0x0101001c: 'priority', 0x0101001d: 'launchMode', 0x01010024: 'value',
  0x01010025: 'resource', 0x01010026: 'mimeType', 0x01010027: 'scheme', 0x01010028: 'host', 0x01010029: 'port', 0x0101002a: 'path',
  0x0101002b: 'pathPrefix', 0x0101002c: 'pathPattern', 0x0101020c: 'minSdkVersion', 0x0101021b: 'versionCode', 0x0101021c: 'versionName',
  0x01010270: 'targetSdkVersion', 0x01010271: 'maxSdkVersion', 0x01010272: 'testOnly', 0x01010280: 'allowBackup', 0x0101028e: 'required',
  0x010104ec: 'usesCleartextTraffic', 0x01010527: 'networkSecurityConfig',
});

class View {
  constructor(buffer, start, end) { this.b = buffer; this.start = start; this.end = end; }
  u8(at) { this.#check(at, 1); return this.b[at]; }
  u16(at) { this.#check(at, 2); return this.b.readUInt16LE(at); }
  u32(at) { this.#check(at, 4); return this.b.readUInt32LE(at); }
  #check(at, size) { if (at < this.start || at + size > this.end) fail('AXML_FORMAT', 'A read falls outside its chunk'); }
}

function readPool(buffer, start, size, limits) {
  const view = new View(buffer, start, start + size);
  if (view.u16(start + 2) < 28) fail('AXML_FORMAT', 'String pool header is too small');
  const count = view.u32(start + 8), styles = view.u32(start + 12), flags = view.u32(start + 16), stringsStart = view.u32(start + 20);
  if (count > limits.strings) fail('AXML_LIMIT', `String pool declares ${count} strings (budget ${limits.strings})`);
  const utf8 = (flags & 0x100) !== 0, headerSize = view.u16(start + 2), offsetsAt = start + headerSize, dataAt = start + stringsStart;
  if (offsetsAt + (count + styles) * 4 > start + size || dataAt > start + size) fail('AXML_FORMAT', 'String pool offsets lie outside the chunk');
  const strings = new Array(count);
  for (let i = 0; i < count; i++) {
    let at = dataAt + view.u32(offsetsAt + i * 4);
    if (utf8) {
      let chars = view.u8(at++); if (chars & 0x80) chars = ((chars & 0x7f) << 8) | view.u8(at++);
      let bytes = view.u8(at++); if (bytes & 0x80) bytes = ((bytes & 0x7f) << 8) | view.u8(at++);
      if (at + bytes > start + size) fail('AXML_FORMAT', 'A string runs past the pool');
      strings[i] = buffer.toString('utf8', at, at + bytes);
    } else {
      let chars = view.u16(at); at += 2; if (chars & 0x8000) { chars = ((chars & 0x7fff) << 16) | view.u16(at); at += 2; }
      if (at + chars * 2 > start + size) fail('AXML_FORMAT', 'A string runs past the pool');
      strings[i] = buffer.toString('utf16le', at, at + chars * 2);
    }
  }
  return { strings, utf8, styles };
}

function typedValue(pool, dataType, data, raw) {
  switch (dataType) {
    case 0x03: return { value: pool[data] ?? null, text: pool[data] ?? '', type: 'string' };
    case 0x12: return { value: data !== 0, text: data !== 0 ? 'true' : 'false', type: 'boolean' };
    case 0x10: { const value = data | 0; return { value, text: String(value), type: 'int' }; }
    case 0x11: return { value: data, text: '0x' + data.toString(16), type: 'hex' };
    case 0x01: return { value: data, text: '@0x' + data.toString(16).padStart(8, '0'), type: 'reference' };
    case 0x02: return { value: data, text: '?0x' + data.toString(16).padStart(8, '0'), type: 'attribute' };
    case 0x04: { const b = Buffer.alloc(4); b.writeUInt32LE(data); const value = b.readFloatLE(0); return { value, text: String(value), type: 'float' }; }
    case 0x1c: case 0x1d: case 0x1e: case 0x1f: return { value: data, text: '#' + data.toString(16).padStart(8, '0'), type: 'color' };
    case 0x00: return { value: raw !== null ? raw : null, text: raw ?? '', type: 'null' };
    default: return { value: data, text: `type:0x${dataType.toString(16)}/0x${data.toString(16)}`, type: 'other' };
  }
}

export function parseAxml(buffer, options = {}) {
  const limits = { ...AXML_LIMITS, ...options };
  if (buffer.length < 8 || buffer.length > limits.bytes) fail('AXML_FORMAT', 'Not an Android binary XML file (size)');
  if (buffer.readUInt16LE(0) !== TYPE.xml) fail('AXML_FORMAT', 'Not an Android binary XML file (magic)');
  const total = buffer.readUInt32LE(4), anomalies = [];
  const note = (code, detail) => { if (anomalies.length < 64) anomalies.push({ code, ...detail }); };
  if (total !== buffer.length) note('size-mismatch', { declared: total, actual: buffer.length });
  const end = Math.min(total, buffer.length);
  let pool = null, resourceIds = [], root = null, count = 0, offset = buffer.readUInt16LE(2);
  const stack = [], namespaces = [], uriOf = new Map();
  const str = index => (index === NONE || !pool ? null : pool.strings[index] ?? null);
  while (offset + 8 <= end) {
    const type = buffer.readUInt16LE(offset), headerSize = buffer.readUInt16LE(offset + 2), size = buffer.readUInt32LE(offset + 4);
    if (size < 8 || headerSize > size || offset + size > end) { note('bad-chunk', { offset, type, size }); break; }
    const view = new View(buffer, offset, offset + size);
    if (type === TYPE.pool) pool = readPool(buffer, offset, size, limits);
    else if (type === TYPE.map) { resourceIds = []; for (let at = offset + headerSize; at + 4 <= offset + size && resourceIds.length < limits.strings; at += 4) resourceIds.push(buffer.readUInt32LE(at)); }
    else if (type === TYPE.startNs || type === TYPE.endNs) {
      if (type === TYPE.startNs) { const prefix = str(view.u32(offset + 16)), uri = str(view.u32(offset + 20)); namespaces.push({ prefix, uri }); uriOf.set(view.u32(offset + 20), uri); }
    } else if (type === TYPE.start) {
      if (!pool) fail('AXML_FORMAT', 'An element appears before the string pool');
      if (++count > limits.elements) fail('AXML_LIMIT', `More than ${limits.elements} elements`);
      const body = offset + headerSize, ns = view.u32(body), nameIndex = view.u32(body + 4), attributeStart = view.u16(body + 8), attributeSize = view.u16(body + 10), attributeCount = view.u16(body + 12);
      if (attributeCount > limits.attributes) fail('AXML_LIMIT', `An element has ${attributeCount} attributes (budget ${limits.attributes})`);
      if (attributeSize < 20) fail('AXML_FORMAT', 'Attribute records are too small');
      const element = { name: str(nameIndex) ?? '', namespace: str(ns), line: view.u32(offset + 8), attributes: [], children: [] };
      for (let i = 0; i < attributeCount; i++) {
        const at = body + attributeStart + i * attributeSize, attrNs = view.u32(at), attrName = view.u32(at + 4), rawIndex = view.u32(at + 8);
        const dataType = view.u8(at + 15), data = view.u32(at + 16), resourceId = attrName < resourceIds.length ? resourceIds[attrName] : null;
        const poolName = str(attrName) ?? '', known = resourceId !== null ? ANDROID_ATTRIBUTE_IDS[resourceId] : undefined;
        if (known && poolName !== known) note('attribute-name-mismatch', { element: element.name, poolName: poolName.slice(0, 64), resourceName: known });
        const value = typedValue(pool.strings, dataType, data, str(rawIndex));
        element.attributes.push({ name: known || poolName || (resourceId !== null ? 'res_0x' + resourceId.toString(16) : ''), namespace: str(attrNs),
          resourceId, ...value, raw: str(rawIndex) });
      }
      if (stack.length >= limits.depth) fail('AXML_LIMIT', `Elements nest deeper than ${limits.depth}`);
      if (stack.length) stack[stack.length - 1].children.push(element);
      else if (!root) root = element;
      else note('multiple-roots', { name: element.name });
      stack.push(element);
    } else if (type === TYPE.end) {
      if (!stack.length) note('unbalanced-end', { offset }); else stack.pop();
    } else if (type !== TYPE.cdata) note('unknown-chunk', { type: '0x' + type.toString(16), offset });
    offset += size;
  }
  if (offset < end) note('trailing-bytes', { bytes: end - offset });
  if (stack.length) note('unclosed-elements', { count: stack.length });
  if (!root) fail('AXML_FORMAT', 'The document has no root element');
  return { root, namespaces, strings: pool ? pool.strings.length : 0, utf8Pool: pool?.utf8 ?? null, elements: count, anomalies };
}

/** First attribute called ``name`` (any namespace); the manifest reader uses this. */
export const attribute = (element, name) => element.attributes.find(a => a.name === name);
