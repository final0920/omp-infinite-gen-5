import { buildUXRArm64 } from './uxr_arm64.mjs';

/** 256 independent memory updates produce a long native decompilation. Never execute. */
export function buildUXRLargeArm64() {
  const { image, functions } = buildUXRArm64(2);
  for (let i = 0; i < 256; i++) {
    image.writeUInt32LE((0xb9400022 | i << 10) >>> 0, 0x1000 + i * 12);
    image.writeUInt32LE(0x4a020000, 0x1004 + i * 12);
    image.writeUInt32LE((0xb9000020 | i << 10) >>> 0, 0x1008 + i * 12);
  }
  image.writeUInt32LE(0xd65f03c0, 0x1c00);
  image.writeBigUInt64LE(0xc04n, 0x2028); // first symbol st_size
  image.writeBigUInt64LE(0xc04n, 0x3060); // .text sh_size
  image.writeBigUInt64LE(48n, 0x30a0); // .symtab: null + first symbol
  return { image, ea: functions[0] };
}
