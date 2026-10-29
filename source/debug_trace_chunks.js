import path from 'node:path';
import { AnalysisArtifacts, hashBytes } from './analysis_artifacts.js';
import { compactNativeTrace } from './native_trace_encoding.js';

const fail = message => { throw new Error('Recorded trace continuation refused: ' + message); };
const hex = value => /^0x[0-9a-f]{1,16}$/i.test(value);
const numbers = (row, count) => {
  const values = row.split(':').slice(1);
  if (values.length !== count || !values.every(hex)) fail('invalid register snapshot');
  return values.map(value => BigInt(value));
};

/** Join only immutable, consecutive recordings of one owned process/thread.
 * No instruction is executed here; all raw reports/blobs remain preserved.
 */
export async function joinRecordedTrace(cfg, ids, targetSha256, maxInstructions = 50000) {
  if (!Number.isSafeInteger(maxInstructions) || maxInstructions < 1 || maxInstructions > 100000) fail('instruction budget must be 1..100000');
  if (!Array.isArray(ids) || !ids.length || ids.length > 256 || new Set(ids).size !== ids.length) fail('choose 1..256 distinct recording report IDs');
  const store = new AnalysisArtifacts(path.join(cfg.artifactDir || cfg.projectRoot, 'debug-traces'));
  try {
    let previous, previousFinal, previousSegments, imageReference, bytes = 0, count = 0;
    const lines = ['h:ig5-native-x64-v1'], sources = [];
    for (const id of ids) {
      const record = store.get(id), summary = record.result;
      if (record.kind !== 'debug-trace' || record.action !== 'record' || summary.targetSha256 !== targetSha256 || !summary.finalSnapshotIncluded || summary.finalSnapshotCurrent === false || !summary.nativeTargetExecuted) fail('wrong recording identity or incomplete final snapshot');
      if (!Number.isSafeInteger(summary.startStopSeq) || !Number.isSafeInteger(summary.endStopSeq) || summary.endStopSeq - summary.startStopSeq !== (summary.confirmedStepStops ?? summary.instructionCount)) fail('recorded pause count differs from confirmed steps');
      const { data } = store.read(summary.input.ref, 1024 * 1024);
      bytes += data.length;
      if (bytes > 16 * 1024 * 1024 || hashBytes(data) !== summary.sha256 || data.length !== summary.bytes || !data.length || data.at(-1) !== 10 || data.some(byte => byte > 127)) fail('hash/size/ASCII budget mismatch');
      const rows = data.toString('ascii').trimEnd().split('\n');
      const header = rows.shift();
      if (!['h:ig5-native-x64-v1', 'h:ig5-native-x64-v2'].includes(header)) fail('native header is missing');
      if (header.endsWith('v2')) lines[0] = header;
      const segments = [];
      if (rows[0]?.startsWith('s:')) {
        const row = rows.shift().split(':');
        if (row.length !== 3 || row[1] !== 'gs' || !hex(row[2])) fail('invalid segment base declaration');
        segments.push('s:gs:0x' + BigInt(row[2]).toString(16));
      }
      if (!rows[0]?.startsWith('r:') || !rows[1]?.startsWith('e:') || !rows.at(-1)?.startsWith('f:')) fail('native format/final snapshot is missing');
      const final = numbers(rows.pop(), 18), initial = numbers(rows[0], 16);
      const instructions = rows.filter(row => /^[ic]:/.test(row));
      if (instructions.length !== summary.instructionCount || instructions[0]?.split(':')[1] !== summary.entry || instructions.at(-1)?.split(':')[1] !== summary.exit) fail('recorded instruction summary differs');
      count += instructions.length;
      if (count > maxInstructions) fail('combined instruction budget exceeded');
      if (previous) {
        if (segments.join('\n') !== previousSegments.join('\n')) fail('segment base continuation differs');
        if (['runId', 'threadId', 'runtimeBase'].some(key => summary[key] !== previous[key]) || summary.startStopSeq !== previous.endStopSeq || !['instruction-budget', 'recording-deadline', 'recording-evidence-budget'].includes(previous.stopReason)) fail('process/thread/pause history is not consecutive');
        if (initial.some((value, index) => value !== previousFinal[index]) || !hex(rows[1].slice(2)) || BigInt(rows[1].slice(2)) !== previousFinal[17] || BigInt(summary.entry) !== previousFinal[16]) fail('GPR/flags/RIP continuation differs');
      }
      else {
        lines.push(...segments);
        if (summary.loadedImage) imageReference = { report_path: path.join(store.root, 'records', id + '.json'), report_sha256: store.metadata(id).result.recordSha256 };
      }
      lines.push(...rows); previous = summary; previousFinal = final;
      previousSegments = segments;
      sources.push({ reportId: id, reportSha256: store.metadata(id).result.recordSha256, traceSha256: summary.sha256, instructionCount: summary.instructionCount });
    }
    lines.push('f:' + previousFinal.map(value => '0x' + value.toString(16)).join(':'));
    const compacted = compactNativeTrace(Buffer.from(lines.join('\n') + '\n', 'ascii'));
    if (compacted.data.length > 4 * 1024 * 1024) fail('normalized trace exceeds 4 MiB');
    return { ...compacted, sources, ...(imageReference ? { imageReference } : {}), runtimeBase: previous.runtimeBase, rawPartsPreserved: true,
      nativeTargetExecutedByJoin: false, wholeFunctionCoverageProved: false };
  } finally { await store.dispose(); }
}
