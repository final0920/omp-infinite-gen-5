// Read a bounded PE32+ export and its bytes for OWN debugger fixture setup.
// No image is loaded/executed and no forwarder is followed.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
export function peExport(data, name) {
  assert(Buffer.isBuffer(data) && data.length >= 0x100 && data.length <= 16 * 1024 * 1024);
  assert(/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(name));
  const range = (offset, size) => { assert(Number.isSafeInteger(offset) && offset >= 0 && size >= 0 && offset + size <= data.length, 'PE range is outside file'); return offset; };
  assert.equal(data.readUInt16LE(0), 0x5a4d);
  const nt = data.readUInt32LE(0x3c); range(nt, 24); assert.equal(data.readUInt32LE(nt), 0x4550);
  const optional = nt + 24, optionalSize = data.readUInt16LE(nt + 20); range(optional, optionalSize);
  assert(optionalSize >= 120); assert.equal(data.readUInt16LE(optional), 0x20b);
  const sectionCount = data.readUInt16LE(nt + 6); assert(sectionCount >= 1 && sectionCount <= 96);
  const sectionTable = optional + optionalSize; range(sectionTable, 40 * sectionCount);
  const map = (rva, size) => {
    const matches = [];
    for (let n = 0; n < sectionCount; n++) {
      const row = sectionTable + n * 40, va = data.readUInt32LE(row + 12), rawSize = data.readUInt32LE(row + 16), raw = data.readUInt32LE(row + 20);
      if (rva >= va && rva + size <= va + rawSize) matches.push(range(raw + rva - va, size));
    }
    assert.equal(matches.length, 1, 'Export must map to one file-backed section'); return matches[0];
  };
  const directoryRva = data.readUInt32LE(optional + 112), directorySize = data.readUInt32LE(optional + 116);
  assert(directoryRva && directorySize >= 40); const directory = map(directoryRva, 40);
  const functions = data.readUInt32LE(directory + 20), names = data.readUInt32LE(directory + 24);
  assert(functions > 0 && functions <= 8192 && names > 0 && names <= 8192);
  const addresses = map(data.readUInt32LE(directory + 28), functions * 4), strings = map(data.readUInt32LE(directory + 32), names * 4), ordinals = map(data.readUInt32LE(directory + 36), names * 2);
  let found;
  for (let n = 0; n < names; n++) {
    const textRva = data.readUInt32LE(strings + 4 * n); const start = map(textRva, 1);
    const end = data.indexOf(0, start); assert(end >= start && end - start <= 128); map(textRva, end - start + 1);
    if (data.toString('ascii', start, end) !== name) continue;
    assert.equal(found, undefined, 'Export name is ambiguous');
    const ordinal = data.readUInt16LE(ordinals + 2 * n); assert(ordinal < functions);
    const rva = data.readUInt32LE(addresses + ordinal * 4); assert(rva < directoryRva || rva >= directoryRva + directorySize, 'Forwarded exports are not used');
    found = { name, rva: '0x' + rva.toString(16), bytes: data.subarray(map(rva, 16), map(rva, 16) + 16).toString('hex'),
      imageSha256: createHash('sha256').update(data).digest('hex') };
  }
  assert(found, 'Named PE export is absent'); return found;
}
