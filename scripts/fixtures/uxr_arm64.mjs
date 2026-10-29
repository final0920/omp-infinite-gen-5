/** Owned ELF64/AArch64 static fixture. No target execution is needed. */
export function buildUXRArm64(count = 72) {
  if (!Number.isInteger(count) || count < 2 || count > 72) throw new Error('count must be 2..72');
  const image = Buffer.alloc(0x4000), base = 0x400000n, text = 0x1000;
  const strings = Buffer.from('\0' + Array.from({ length: count }, (_, i) => `uxr_${String(i).padStart(2, '0')}\0`).join(''));
  const names = Buffer.from('\0.text\0.symtab\0.strtab\0.shstrtab\0');
  Buffer.from('7f454c46020101000000000000000000', 'hex').copy(image);
  image.writeUInt16LE(2, 16); image.writeUInt16LE(183, 18); image.writeUInt32LE(1, 20);
  image.writeBigUInt64LE(base + BigInt(text), 24); image.writeBigUInt64LE(64n, 32); image.writeBigUInt64LE(0x3000n, 40);
  image.writeUInt16LE(64, 52); image.writeUInt16LE(56, 54); image.writeUInt16LE(1, 56);
  image.writeUInt16LE(64, 58); image.writeUInt16LE(5, 60); image.writeUInt16LE(4, 62);
  image.writeUInt32LE(1, 64); image.writeUInt32LE(5, 68);
  image.writeBigUInt64LE(base, 80); image.writeBigUInt64LE(base, 88);
  image.writeBigUInt64LE(0x2000n, 96); image.writeBigUInt64LE(0x2000n, 104); image.writeBigUInt64LE(0x1000n, 112);
  const functions = [];
  for (let i = 0; i < count; i++) {
    const offset = text + i * 16, symbol = 0x2000 + (i + 1) * 24;
    // BL to the following symbol / MOV W0,#42; RET. Static analysis only.
    image.writeUInt32LE(i + 1 < count ? 0x94000004 : 0x52800540, offset);
    image.writeUInt32LE(0xd65f03c0, offset + 4);
    image.writeUInt32LE(1 + i * 7, symbol); image[symbol + 4] = 0x12;
    image.writeUInt16LE(1, symbol + 6); image.writeBigUInt64LE(base + BigInt(offset), symbol + 8);
    image.writeBigUInt64LE(8n, symbol + 16); functions.push(`0x${(base + BigInt(offset)).toString(16)}`);
  }
  strings.copy(image, 0x2700); names.copy(image, 0x3160);
  const section = (i, name, type, flags, addr, offset, size, link, info, align, entrySize) => {
    const at = 0x3000 + i * 64;
    image.writeUInt32LE(name, at); image.writeUInt32LE(type, at + 4);
    for (const [delta, value] of [[8, flags], [16, addr], [24, offset], [32, size], [48, align], [56, entrySize]]) image.writeBigUInt64LE(BigInt(value), at + delta);
    image.writeUInt32LE(link, at + 40); image.writeUInt32LE(info, at + 44);
  };
  section(1, 1, 1, 6, base + BigInt(text), text, count * 16, 0, 0, 4, 0);
  section(2, 7, 2, 0, 0, 0x2000, (count + 1) * 24, 3, 1, 8, 24);
  section(3, 15, 3, 0, 0, 0x2700, strings.length, 0, 0, 1, 0);
  section(4, 23, 3, 0, 0, 0x3160, names.length, 0, 0, 1, 0);
  return { image, functions };
}
