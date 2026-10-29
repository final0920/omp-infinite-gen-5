// Synthetic observation format fixtures. They do not execute any instruction.
import { createHash } from 'node:crypto';
export const observationTarget = 'a'.repeat(64);
export const observationHash = value => createHash('sha256').update(value).digest('hex');
const regs = value => ['0x' + BigInt(value).toString(16), ...Array(15).fill('0x0')];
export function observationWindow({ id = 1, count = 2, start = 1, pc = 0x1000, value = 1,
  version = 2, delta = true, cpuid = false, reads = true, changeCode = false, gs = true } = {}) {
  const rows = [`h:ig5-native-x64-v${version}`];
  if (gs) rows.push('s:gs:0x7000');
  let ea = pc;
  for (let n = 0; n < count; n++) {
    rows.push(n && delta && version === 2 ? 'd:0x1:0x' + (value + n).toString(16) : 'r:' + regs(value + n).join(':'));
    rows.push('e:0x202');
    if (reads) rows.push('mr:0x8000:4:0x12345678');
    rows.push(`i:0x${ea.toString(16)}:${cpuid ? 2 : 1}:${cpuid ? '0fa2' : changeCode && n % 2 ? 'cc' : '90'}`);
    if (cpuid) rows.push(`c:0x${(ea + 2).toString(16)}:1:90`);
    if (!changeCode) ea += cpuid ? 3 : 1;
  }
  rows.push('f:' + regs(value + count).join(':') + ':0x' + ea.toString(16) + ':0x202');
  const data = Buffer.from(rows.join('\n') + '\n');
  return { source: { reportId: '11111111-1111-1111-1111-' + id.toString(16).padStart(12, '0'),
    reportSha256: 'b'.repeat(64), locationFingerprint: 'c'.repeat(64), image: null },
  summary: { targetSha256: observationTarget, nativeTargetExecuted: true, format: `ig5.x86-recording.v${version}`,
    finalSnapshotIncluded: true, finalSnapshotCurrent: true, runId: 'synthetic-run', threadId: 7,
    startStopSeq: start, endStopSeq: start + count, instructionCount: count * (cpuid ? 2 : 1), confirmedStepStops: count,
    runtimeBase: '0x1000', entry: '0x' + pc.toString(16), exit: '0x' + (changeCode ? pc : ea - (cpuid ? 1 : 1)).toString(16),
    initialFlags: '0x202', stopReason: 'instruction-budget', bytes: data.length, sha256: observationHash(data) }, data };
}
export function replaceObservationRows(window, change) {
  const value = structuredClone(window); value.data = Buffer.from(change(Buffer.from(value.data).toString('ascii')));
  value.summary.bytes = value.data.length; value.summary.sha256 = observationHash(value.data); return value;
}
