// Owned deterministic leaf code. No downloaded sample bytes or upstream source.
import { buildPE64Fixture } from './pe64.mjs';

export const modernOwnedCases = [
  { id: 'add64', hex: '488d0411c3', inputs: ['rcx', 'rdx'], output: 'rax', semantics: 'uint64(x+y)' },
  { id: 'xor32', hex: '89c831d0c3', inputs: ['ecx', 'edx'], output: 'eax', semantics: 'uint32(x^y)' },
  { id: 'multiply32', hex: '89c80fafc2c3', inputs: ['ecx', 'edx'], output: 'eax', semantics: 'uint32(x*y)' },
  { id: 'bitmix32', hex: '89c831d083c06369c08f000000c3', inputs: ['ecx', 'edx'], output: 'eax', semantics: 'uint32(((x^y)+99)*143)' },
  { id: 'signedmax32', hex: '89c839d10f4cc2c3', inputs: ['ecx', 'edx'], output: 'eax', semantics: 'signed32(x)<signed32(y)?y:x' },
  { id: 'shifts32', hex: '89c8c1e003c1e80731d0c3', inputs: ['ecx', 'edx'], output: 'eax', semantics: '(uint32(x<<3)>>7)^y' },
  { id: 'fixedloop32', hex: '89c841b80400000031d083c00b41ffc875f6c3', inputs: ['ecx', 'edx'], output: 'eax', semantics: 'uint32(z=x; four times z=(z^y)+11)' },
  { id: 'inputloop32', hex: '89d083e103ffc183c005ffc975f9c3', inputs: ['ecx', 'edx'], output: 'eax', semantics: 'uint32(y+5*((x&3)+1))' },
  { id: 'stackxor32', hex: '5389cb31d3538b04245b5bc3', inputs: ['ecx', 'edx'], output: 'eax', semantics: 'uint32(x^y), input-dependent stack writes/reads' },
];

export function modernOwnedImage(id) {
  const item = modernOwnedCases.find(row => row.id === id);
  if (!item) throw new Error('Unknown owned case');
  const image = buildPE64Fixture().image;
  image.fill(0xcc, 0x400, 0x440);
  Buffer.from(item.hex, 'hex').copy(image, 0x400);
  return image;
}

// A separate, unprotected entry calls the selected exported leaf. This avoids
// conflating a protector's replacement EXE entry with the original function.
// The original recipe above remains byte-identical for historical pins.
export function modernOwnedHarnessImage(id) {
  const image = modernOwnedImage(id);
  image.writeUInt32LE(0x13a0, 0x98 + 16);
  Buffer.from('4883ec28b901000000ba02000000e84dfcffff4883c428c3', 'hex').copy(image, 0x7a0);
  return image;
}
