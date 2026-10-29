import { hashBytes } from './analysis_artifacts.js';

/** Lossless delta coding of native GPR snapshots; no VM semantics or execution.
 * Verify exact expansion back to the original bytes before using a derivative.
 */
export function compactNativeTrace(data) {
  const source = data.toString('ascii');
  if (!/^h:ig5-native-x64-v[12]\n/.test(source) || data.some(value => value > 127) || /^d:/m.test(source)) return { data };
  const rows = source.split('\n'), encoded = ['h:ig5-native-x64-v2'], expanded = [rows[0]];
  let previous;
  for (const row of rows.slice(1)) {
    if (!row.startsWith('r:')) { encoded.push(row); expanded.push(row); continue; }
    const values = row.split(':').slice(1);
    if (values.length !== 16 || !values.every(value => /^0x[0-9a-f]{1,16}$/i.test(value))) throw new Error('Invalid native GPR snapshot for delta coding');
    if (previous) {
      let mask = 0; const changes = [];
      for (let index = 0; index < 16; index++) if (values[index] !== previous[index]) { mask |= 1 << index; changes.push(values[index]); }
      const delta = 'd:0x' + mask.toString(16) + (changes.length ? ':' + changes.join(':') : '');
      encoded.push(delta);
      const restored = [...previous]; let cursor = 0;
      for (let index = 0; index < 16; index++) if (mask & (1 << index)) restored[index] = changes[cursor++];
      expanded.push('r:' + restored.join(':'));
    } else { encoded.push(row); expanded.push(row); }
    previous = values;
  }
  if (!Buffer.from(expanded.join('\n'), 'ascii').equals(data)) throw new Error('Native register delta roundtrip differs');
  const output = Buffer.from(encoded.join('\n'), 'ascii');
  return { data: output, normalization: { method: 'lossless-native-GPR-deltas-v2', originalSha256: hashBytes(data),
    normalizedSha256: hashBytes(output), originalBytes: data.length, normalizedBytes: output.length, exactExpansionVerified: true } };
}
