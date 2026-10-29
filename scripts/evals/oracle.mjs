/** Evaluator-owned reference for self-authored specifications; repo access exposes answers. */
export function reference(input) {
  if (input.kind === 'branch-function') return input.values.map(x => x < input.threshold ? x + 1 : x - 1);
  if (input.kind === 'memory-function') return input.values.map(x => ({ returned: (x + input.increment) & 255, written: x ^ 0x5a }));
  if (input.kind === 'length-prefix') {
    const bytes = Buffer.from(input.hex, 'hex'), frames = [];
    let offset = 0;
    while (offset < bytes.length && offset + 1 + bytes[offset] <= bytes.length) {
      const length = bytes[offset++]; frames.push(bytes.subarray(offset, offset + length).toString('hex')); offset += length;
    }
    return { frames, tail: bytes.subarray(offset).toString('hex'), semanticsVerified: false };
  }
  if (input.kind === 'toy-vm') return input.values.map(x => ({ returned: (x & 1 ? x + input.delta : x - input.delta) >>> 0, written: (x * 3) & 255 }));
  throw new Error('Unsupported reference kind');
}
