// Deterministic PE64 fixture with a real KERNEL32 import table and a small
// benign entry point. Loading it executes IsDebuggerPresent, GetTickCount64 and
// Sleep(1), then ExitProcess(0). Tests must write only a temporary copy.
export function buildPE64ImportFixture() {
  const image = Buffer.alloc(0x1e00);
  const base = 0x140000000n;
  const optional = 0x98;
  const u16 = (offset, value) => image.writeUInt16LE(value, offset);
  const u32 = (offset, value) => image.writeUInt32LE(value >>> 0, offset);
  const u64 = (offset, value) => image.writeBigUInt64LE(BigInt(value), offset);
  const raw = (rva) => rva < 0x2000 ? 0x400 + rva - 0x1000
    : rva < 0x3000 ? 0x800 + rva - 0x2000 : 0xe00 + rva - 0x3000;
  const text = (offset, value) => image.write(value, offset, 'ascii');
  const bytes = (offset, hex) => Buffer.from(hex, 'hex').copy(image, offset);
  const address = (rva) => '0x' + (base + BigInt(rva)).toString(16);

  text(0, 'MZ'); u32(0x3c, 0x80); text(0x80, 'PE\0\0');
  u16(0x84, 0x8664); u16(0x86, 3); u16(0x94, 0xf0); u16(0x96, 0x22);
  u16(optional, 0x20b); image[optional + 2] = 14;
  u32(optional + 4, 0x400); u32(optional + 8, 0x1600);
  u32(optional + 16, 0x1000); u32(optional + 20, 0x1000); u64(optional + 24, base);
  u32(optional + 32, 0x1000); u32(optional + 36, 0x200);
  u16(optional + 40, 6); u16(optional + 48, 6);
  u32(optional + 56, 0x4000); u32(optional + 60, 0x400);
  u16(optional + 68, 3); u16(optional + 70, 0x100);
  u64(optional + 72, 0x100000); u64(optional + 80, 0x1000);
  u64(optional + 88, 0x100000); u64(optional + 96, 0x1000);
  u32(optional + 108, 16);
  // Data directory 1: import descriptors at RVA 0x2200 (one descriptor plus null).
  u32(optional + 120, 0x2200); u32(optional + 124, 0x28);
  for (const [index, name, rva, offset, size, flags] of [
    [0, '.text', 0x1000, 0x400, 0x400, 0x60000020],
    [1, '.rdata', 0x2000, 0x800, 0x600, 0x40000040],
    [2, '.data', 0x3000, 0xe00, 0x1000, 0xc0000040],
  ]) {
    const header = optional + 0xf0 + index * 40;
    text(header, name); u32(header + 8, size); u32(header + 12, rva);
    u32(header + 16, size); u32(header + 20, offset); u32(header + 36, flags);
  }

  const imports = [
    ['IsDebuggerPresent', 0x2340, 0x2400],
    ['GetTickCount64', 0x2360, 0x2408],
    ['Sleep', 0x2380, 0x2410],
    ['ExitProcess', 0x23a0, 0x2418],
  ];
  // Descriptor: OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk.
  u32(raw(0x2200), 0x2300); u32(raw(0x2200) + 12, 0x2280); u32(raw(0x2200) + 16, 0x2400);
  text(raw(0x2280), 'KERNEL32.dll\0');
  // The on-disk IAT is normally a mirror of the import lookup table; Windows only
  // binds the slots when FirstThunk holds the same thunk RVAs (a zeroed IAT loads
  // without error but leaves every slot unresolved).
  imports.forEach(([, nameRva], index) => {
    u64(raw(0x2300) + index * 8, nameRva);
    u64(raw(0x2400) + index * 8, nameRva);
  });
  for (const [, nameRva] of imports) {
    u16(raw(nameRva), 0);
    text(raw(nameRva) + 2, nameFor(nameRva) + '\0');
  }
  function nameFor(nameRva) {
    return { 0x2340: 'IsDebuggerPresent', 0x2360: 'GetTickCount64', 0x2380: 'Sleep', 0x23a0: 'ExitProcess' }[nameRva];
  }

  // sub rsp,0x28; call [rip+disp] x2; mov ecx,1; call Sleep; xor ecx,ecx; call ExitProcess.
  // Each disp32 targets one static IAT slot; the loader replaces the slots at run time.
  bytes(raw(0x1000), '4883ec28'
    + 'ff15' + disp32(0x1004, 0x2400)
    + 'ff15' + disp32(0x100a, 0x2408)
    + 'b901000000'
    + 'ff15' + disp32(0x1015, 0x2410)
    + '31c9'
    + 'ff15' + disp32(0x101d, 0x2418)
    + 'cc');
  function disp32(instructionRva, targetRva) {
    const value = targetRva - (instructionRva + 6);
    return Buffer.from([value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff]).toString('hex');
  }

  return {
    image,
    entryRva: 0x1000,
    entry: address(0x1000),
    imports: imports.map(([name, , iatRva]) => ({ name, iatRva, iat: address(iatRva) })),
    apis: Object.fromEntries(imports.map(([name, , iatRva]) => [name, address(iatRva)])),
  };
}
