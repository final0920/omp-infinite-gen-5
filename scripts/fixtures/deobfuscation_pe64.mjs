import { buildPE64Fixture } from './pe64.mjs';

// Statically analyzed synthetic functions; this module never launches the PE.
export function buildDeobfuscationPE64Fixture() {
  const fixture = buildPE64Fixture(1), image = Buffer.from(fixture.image);
  const code = [], labels = new Map(), jumps = [];
  const emit = (hex) => code.push(...Buffer.from(hex, 'hex'));
  const label = (name) => labels.set(name, code.length);
  const jump = (opcode, destination) => { emit(opcode); jumps.push({ offset: code.length, destination }); code.push(0); };
  // A two-state flattened dispatcher. The state phi receives 1 from entry and
  // 2 from case1; each incoming edge therefore has a distinct proven route.
  emit('b801000000'); jump('eb', 'dispatch');
  label('case1'); emit('89ca83c207b802000000'); jump('eb', 'dispatch');
  label('case2'); emit('89d0c3');
  label('dispatch'); emit('83f801'); jump('74', 'case1'); emit('83f802'); jump('74', 'case2'); emit('b8ffffffffc3');
  for (const item of jumps) {
    const relative = labels.get(item.destination) - item.offset - 1;
    if (relative < -128 || relative > 127) throw new Error('Fixture jump exceeds short displacement');
    code[item.offset] = relative & 255;
  }
  if (code.length > 0x80) throw new Error('Fixture dispatcher exceeds reserved region');
  Buffer.from(code).copy(image, 0x540);
  // x*(x-1) is even for every 32-bit input. Both outcomes still exist in the
  // native firstpass graph, so branch removal needs an algebraic proof.
  Buffer.from('89c88d51ff0fafc283e00185c07506b82a000000c3b800000000c3', 'hex').copy(image, 0x720);
  // (x | y) - (x & y) == x ^ y, and (x | y) & ~(x & y) == x ^ y.
  Buffer.from('89c809d021d129c8c3', 'hex').copy(image, 0x740);
  Buffer.from('89c809d021d1f7d121c8c3', 'hex').copy(image, 0x6c0);
  // An actual indirect target fed by unknown memory; never resolve it by guess.
  Buffer.from('488b01ffe0', 'hex').copy(image, 0x440);
  return { ...fixture, image, addresses: { ...fixture.addresses, dispatcher: fixture.addresses.branch, opaqueParity: fixture.addresses.xor_copy, unresolvedMemory: fixture.addresses.fault, linearMba: fixture.addresses.sub_copy, booleanMba: fixture.addresses.xor_self, indirectTarget: fixture.addresses.buffer } };
}
