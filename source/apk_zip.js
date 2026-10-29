import fs from 'node:fs';
import zlib from 'node:zlib';
import { createHash } from 'node:crypto';

// Bounded, read-only ZIP reader for APK analysis. It reads through a file descriptor (an APK can be hundreds of
// MiB), follows the central directory the way Android does, and reports structural oddities instead of hiding
// them. It never writes to disk and never trusts sizes it has not checked against the file.
export const ZIP_LIMITS = Object.freeze({ fileBytes: 2 ** 31, entries: 100000, nameBytes: 1024, entryBytes: 256 * 1024 * 1024, ratio: 1000 });
const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
const SIG = { local: 0x04034b50, central: 0x02014b50, eocd: 0x06054b50, zip64Eocd: 0x06064b50, zip64Locator: 0x07064b50 };
const SIGNING_MAGIC = Buffer.from('APK Sig Block 42');
const CRC_TABLE = (() => { const table = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; table[n] = c >>> 0; } return table; })();
export function crc32(buffer) { let c = 0xffffffff; for (let i = 0; i < buffer.length; i++) c = CRC_TABLE[(c ^ buffer[i]) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }
const u64 = (buffer, offset) => { const value = buffer.readBigUInt64LE(offset); if (value > BigInt(Number.MAX_SAFE_INTEGER)) fail('ZIP_RANGE', 'ZIP offset is not safely addressable'); return Number(value); };

export class ZipArchive {
  static open(file, options = {}) {
    const limits = { ...ZIP_LIMITS, ...options };
    const before = fs.lstatSync(file, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink()) fail('ZIP_INPUT', 'The input must be a regular, non-linked file');
    if (before.size < 22n || before.size > BigInt(limits.fileBytes)) fail('ZIP_INPUT', 'The file is too small to be a ZIP archive or exceeds the size budget');
    const fd = fs.openSync(file, 'r');
    try {
      const opened = fs.fstatSync(fd, { bigint: true });
      if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) fail('ZIP_CHANGED', 'The file was replaced while opening');
      return new ZipArchive(file, fd, opened, limits);
    } catch (error) { fs.closeSync(fd); throw error; }
  }

  constructor(file, fd, identity, limits) {
    this.file = file; this.fd = fd; this.identity = identity; this.limits = limits; this.size = Number(identity.size);
    this.anomalies = []; this.entries = []; this.byName = new Map();
    this.#readDirectory();
  }

  #read(offset, length) {
    if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0 || offset + length > this.size) fail('ZIP_RANGE', 'A ZIP structure points outside the file');
    const buffer = Buffer.alloc(length);
    for (let done = 0; done < length;) {
      const count = fs.readSync(this.fd, buffer, done, length - done, offset + done);
      if (!count) fail('ZIP_CHANGED', 'The file became shorter while reading');
      done += count;
    }
    return buffer;
  }

  #note(code, detail) { if (this.anomalies.length < 64) this.anomalies.push({ code, ...detail }); }

  #readDirectory() {
    const tailLength = Math.min(this.size, 22 + 65535 + 20 + 56);
    const tail = this.#read(this.size - tailLength, tailLength);
    const found = [];
    for (let at = tail.length - 22; at >= 0; at--) if (tail.readUInt32LE(at) === SIG.eocd) found.push(at);
    // Like libziparchive and Python's zipfile, the LAST self-consistent end record wins. More than one is reported:
    // a parser that prefers the first one would read a different archive from the same bytes.
    const at = found.find(position => position + 22 + tail.readUInt16LE(position + 20) === tail.length) ?? found[0];
    if (at === undefined) fail('ZIP_FORMAT', 'No end-of-central-directory record: this is not a ZIP archive');
    if (found.length > 1) this.#note('multiple-eocd', { count: found.length });
    if (at + 22 + tail.readUInt16LE(at + 20) !== tail.length) this.#note('data-after-archive', { bytes: tail.length - (at + 22 + tail.readUInt16LE(at + 20)) });
    let count = tail.readUInt16LE(at + 10), size = tail.readUInt32LE(at + 12), offset = tail.readUInt32LE(at + 16);
    if (count === 0xffff || size === 0xffffffff || offset === 0xffffffff) {
      const locator = at - 20;
      if (locator < 0 || tail.readUInt32LE(locator) !== SIG.zip64Locator) fail('ZIP_FORMAT', 'ZIP64 values without a ZIP64 locator');
      const record = this.#read(u64(tail, locator + 8), 56);
      if (record.readUInt32LE(0) !== SIG.zip64Eocd) fail('ZIP_FORMAT', 'Invalid ZIP64 end-of-central-directory record');
      count = u64(record, 32); size = u64(record, 40); offset = u64(record, 48);
      this.zip64 = true;
    }
    if (count > this.limits.entries) fail('ZIP_LIMIT', `The archive declares ${count} entries (budget ${this.limits.entries})`);
    if (offset + size > this.size) fail('ZIP_FORMAT', 'The central directory lies outside the file');
    this.centralOffset = offset; this.centralSize = size;
    const directory = this.#read(offset, size);
    let cursor = 0;
    for (let index = 0; index < count; index++) {
      if (cursor + 46 > directory.length || directory.readUInt32LE(cursor) !== SIG.central) fail('ZIP_FORMAT', `Central directory entry ${index} is malformed`);
      const nameLength = directory.readUInt16LE(cursor + 28), extraLength = directory.readUInt16LE(cursor + 30), commentLength = directory.readUInt16LE(cursor + 32);
      if (nameLength > this.limits.nameBytes || cursor + 46 + nameLength + extraLength + commentLength > directory.length) fail('ZIP_FORMAT', `Central directory entry ${index} has an invalid name or extra length`);
      const rawName = directory.subarray(cursor + 46, cursor + 46 + nameLength);
      const entry = { index, name: rawName.toString('utf8'), flags: directory.readUInt16LE(cursor + 8), method: directory.readUInt16LE(cursor + 10),
        crc: directory.readUInt32LE(cursor + 16), compressed: directory.readUInt32LE(cursor + 20), size: directory.readUInt32LE(cursor + 24),
        localOffset: directory.readUInt32LE(cursor + 42) };
      const extra = directory.subarray(cursor + 46 + nameLength, cursor + 46 + nameLength + extraLength);
      for (let e = 0; e + 4 <= extra.length;) {
        const id = extra.readUInt16LE(e), length = extra.readUInt16LE(e + 2);
        if (id === 1 && e + 4 + length <= extra.length) {
          let p = e + 4;
          if (entry.size === 0xffffffff && p + 8 <= e + 4 + length) { entry.size = u64(extra, p); p += 8; }
          if (entry.compressed === 0xffffffff && p + 8 <= e + 4 + length) { entry.compressed = u64(extra, p); p += 8; }
          if (entry.localOffset === 0xffffffff && p + 8 <= e + 4 + length) entry.localOffset = u64(extra, p);
        }
        e += 4 + length;
      }
      entry.encrypted = (entry.flags & 1) !== 0;
      entry.directory = entry.name.endsWith('/');
      if (!Buffer.from(entry.name, 'utf8').equals(rawName)) this.#note('non-utf8-name', { index });
      if (/(^|\/)\.\.(\/|$)|^\/|\\|\0/.test(entry.name)) this.#note('suspicious-name', { name: entry.name.slice(0, 120) });
      if (this.byName.has(entry.name)) this.#note('duplicate-entry', { name: entry.name.slice(0, 120) });
      else this.byName.set(entry.name, entry);
      if (!entry.directory && entry.compressed > 0 && entry.size / entry.compressed > this.limits.ratio) this.#note('extreme-compression-ratio', { name: entry.name.slice(0, 120), ratio: Math.round(entry.size / entry.compressed) });
      if (entry.method !== 0 && entry.method !== 8) this.#note('unsupported-method', { name: entry.name.slice(0, 120), method: entry.method });
      if (entry.encrypted) this.#note('encrypted-entry', { name: entry.name.slice(0, 120) });
      this.entries.push(entry);
      cursor += 46 + nameLength + extraLength + commentLength;
    }
    if (cursor !== directory.length) this.#note('central-directory-slack', { bytes: directory.length - cursor });
  }

  /** The APK Signing Block (v2/v3 signatures) that sits between the entries and the central directory, if any. */
  signingBlock() {
    const end = this.centralOffset;
    if (end < 32) return null;
    const footer = this.#read(end - 24, 24);
    if (!footer.subarray(8).equals(SIGNING_MAGIC)) return null;
    const blockSize = u64(footer, 0);
    if (blockSize < 24 || blockSize + 8 > end) fail('ZIP_FORMAT', 'Invalid APK Signing Block size');
    const start = end - blockSize - 8;
    const block = this.#read(start, blockSize + 8);
    if (u64(block, 0) !== blockSize) fail('ZIP_FORMAT', 'APK Signing Block header and footer sizes differ');
    const pairs = [];
    for (let at = 8; at < block.length - 24;) {
      const length = u64(block, at);
      if (length < 4 || at + 8 + length > block.length - 24) fail('ZIP_FORMAT', 'Invalid APK Signing Block pair');
      pairs.push({ id: block.readUInt32LE(at + 8), value: block.subarray(at + 12, at + 8 + length) });
      at += 8 + length;
    }
    return { offset: start, size: blockSize + 8, pairs };
  }

  /** Decompressed bytes of one entry, refusing anything over ``maxBytes`` and verifying size and CRC-32. */
  read(entryOrName, maxBytes = this.limits.entryBytes) {
    const entry = typeof entryOrName === 'string' ? this.byName.get(entryOrName) : entryOrName;
    if (!entry) fail('ZIP_ENTRY', 'No such entry');
    if (entry.encrypted) fail('ZIP_ENCRYPTED', 'The entry is encrypted');
    if (entry.size > Math.min(maxBytes, this.limits.entryBytes)) fail('ZIP_LIMIT', `Entry ${entry.name} is ${entry.size} bytes (budget ${Math.min(maxBytes, this.limits.entryBytes)})`);
    const local = this.#read(entry.localOffset, 30);
    if (local.readUInt32LE(0) !== SIG.local) fail('ZIP_FORMAT', `Local header of ${entry.name} is missing`);
    const nameLength = local.readUInt16LE(26), extraLength = local.readUInt16LE(28);
    const localName = this.#read(entry.localOffset + 30, nameLength).toString('utf8');
    if (localName !== entry.name) this.#note('local-name-mismatch', { name: entry.name.slice(0, 120), local: localName.slice(0, 120) });
    const raw = this.#read(entry.localOffset + 30 + nameLength + extraLength, entry.compressed);
    let data;
    if (entry.method === 0) data = raw;
    else if (entry.method === 8) {
      try { data = zlib.inflateRawSync(raw, { maxOutputLength: entry.size + 1 }); }
      catch (error) { fail('ZIP_INFLATE', `Entry ${entry.name} could not be decompressed: ${error.code || error.message}`); }
    } else fail('ZIP_METHOD', `Compression method ${entry.method} is not supported`);
    if (data.length !== entry.size) fail('ZIP_SIZE', `Entry ${entry.name} decompressed to ${data.length} bytes, the directory says ${entry.size}`);
    if (crc32(data) !== entry.crc) fail('ZIP_CRC', `Entry ${entry.name} fails its CRC-32 check`);
    return data;
  }

  /** SHA-256 of the whole file, streamed. */
  sha256() {
    const hash = createHash('sha256'), chunk = Buffer.alloc(1 << 20);
    for (let at = 0; at < this.size;) { const count = fs.readSync(this.fd, chunk, 0, Math.min(chunk.length, this.size - at), at); if (!count) fail('ZIP_CHANGED', 'The file became shorter while hashing'); hash.update(chunk.subarray(0, count)); at += count; }
    return hash.digest('hex');
  }

  /** Throws if the file was replaced or modified since it was opened. */
  assertUnchanged() {
    const now = fs.fstatSync(this.fd, { bigint: true }), path = fs.lstatSync(this.file, { bigint: true });
    if (now.size !== this.identity.size || now.mtimeNs !== this.identity.mtimeNs || path.ino !== this.identity.ino || path.dev !== this.identity.dev) fail('ZIP_CHANGED', 'The file changed during analysis');
  }

  close() { if (this.fd !== null) { fs.closeSync(this.fd); this.fd = null; } }
}
