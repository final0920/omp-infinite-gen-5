import path from 'node:path';
import { AnalysisArtifacts, hashBytes, readStableFile } from './analysis_artifacts.js';
import { readNativeStoreEvents } from './native_store_events.js';

/** Keep approved native recordings outside databases and out of the UI cache. */
export async function saveDebugTrace(cfg, session, result, params) {
  if (!result?.recording || typeof result.traceData !== 'string') return result;
  const { traceData, imageData, imageSummary, storeEventData, storeEventSummary, ...response } = result;
  const data = Buffer.from(traceData, 'ascii'), summary = result.traceSummary;
  if (!summary || data.length > 1024 * 1024 || summary.bytes !== data.length || summary.sha256 !== hashBytes(data)) throw new Error('Native trace digest/size mismatch');
  if (!summary.instructionCount) return { ...response, traceSaved: false };
  if (!data.length || data[data.length - 1] !== 10 || /[^\x00-\x7f]/.test(traceData)) throw new Error('Native trace is incomplete or non-ASCII');
  let eventBytes, events;
  if (params.record_events) {
    if (typeof storeEventData !== 'string' || /[^\x00-\x7f]/.test(storeEventData)) throw new Error('Native store-event evidence is missing/non-ASCII');
    eventBytes = Buffer.from(storeEventData, 'ascii');
    if (storeEventSummary?.schema !== 'ig5.native-store-events.v1' || storeEventSummary.bytes !== eventBytes.length
      || storeEventSummary.sha256 !== hashBytes(eventBytes)) throw new Error('Native store-event digest/size mismatch');
    events = readNativeStoreEvents(eventBytes, summary, data);
  } else if (storeEventData !== undefined || storeEventSummary !== undefined) throw new Error('Unrequested native store-event evidence');
  const artifacts = new AnalysisArtifacts(path.join(cfg.artifactDir || cfg.projectRoot, 'debug-traces'));
  try {
    let loadedImage;
    if (params.record_image) {
      if (!imageSummary || typeof imageData !== 'string' || imageData.length > Math.ceil(8 * 1024 * 1024 / 3) * 4 || imageData.length % 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(imageData)) throw new Error('Native image snapshot is missing/oversized');
      const bytes = Buffer.from(imageData, 'base64');
      if (bytes.toString('base64') !== imageData || bytes.length < 1 || bytes.length > 8 * 1024 * 1024 || bytes.length !== imageSummary.bytes || hashBytes(bytes) !== imageSummary.sha256 ||
          imageSummary.runId !== summary.runId || imageSummary.threadId !== summary.threadId || imageSummary.stopSeq !== summary.startStopSeq ||
          imageSummary.runtimeBase !== summary.runtimeBase || !imageSummary.nativeTargetExecuted) throw new Error('Native image snapshot identity/hash differs');
      loadedImage = { ...imageSummary, input: artifacts.put(bytes), targetSha256: session.sha256 };
    }
    const input = artifacts.put(data);
    const storeEvents = eventBytes ? { ...storeEventSummary, input: artifacts.put(eventBytes), groups: events.events.length,
      completeDecodedStoreGroups: events.events.filter(event => event.completeDecodedStoreSet).length,
      actualWriteCausalityProved: false, cpuWriteFootprintProved: false } : undefined;
    const tracePath = path.join(artifacts.root, 'blobs', input.sha256 + '.bin');
    const record = artifacts.save({ kind: 'debug-trace', action: 'record', result: {
      ...summary, ...(loadedImage ? { loadedImage } : {}), ...(storeEvents ? { storeEvents } : {}), target: session.target, targetSha256: session.sha256, input,
      nativeTargetExecuted: result.nativeStepsPerformed > 0, databaseModified: false,
      ...(result.executionLocation ? { executionLocation: result.executionLocation, guestProvenance: result.guestProvenance } : {}),
    } });
    const recoveryArgs = { target: session.target, level: 'trace', traces: [{ path: tracePath, sha256: input.sha256 }],
      trace_entry: summary.entry, trace_exit: summary.exit, initial_flags: summary.initialFlags,
      trace_runtime_base: summary.runtimeBase, max_instructions: 50000 };
    if (params.trace_inputs) recoveryArgs.trace_inputs = params.trace_inputs;
    if (params.trace_output) recoveryArgs.trace_output = params.trace_output;
    if (loadedImage) recoveryArgs.trace_image = { report_path: path.join(artifacts.root, 'records', record.id + '.json'), report_sha256: artifacts.metadata(record.id).result.recordSha256 };
    return { ...response, traceSaved: true, tracePath, traceSha256: input.sha256,
      traceReportId: record.id, traceReportPath: path.join(artifacts.root, 'records', record.id + '.json'),
      traceReportSha256: artifacts.metadata(record.id).result.recordSha256,
      ...(loadedImage ? { loadedImage: { ...loadedImage, input: undefined } } : {}),
      ...(storeEvents ? { storeEvents: { ...storeEvents, input: undefined } } : {}),
      recoveryArgs, recoveryReady: !!params.trace_inputs && !!params.trace_output && summary.finalSnapshotIncluded,
      nativeTargetExecuted: result.nativeStepsPerformed > 0, databaseModified: false,
      traceScope: 'approved recorded instruction window; whole function/program coverage is not proved' };
  } finally { await artifacts.dispose(); }
}

/** Explicit hash-bound recording reference; sparse native holes are never filled. */
export function readDebugImage(reference, targetSha256, entry, flags, runtimeBase, recordedTargetPath) {
  if (!reference || typeof reference.report_path !== 'string' || !/^[a-f0-9]{64}$/.test(reference.report_sha256 || '')) throw new Error('Native image requires report_path and report_sha256');
  const { data } = readStableFile(reference.report_path, 8 * 1024 * 1024);
  if (hashBytes(data) !== reference.report_sha256) throw new Error('Native image recording report hash differs');
  const record = JSON.parse(data), summary = record.result, image = summary?.loadedImage;
  if (record.schemaVersion !== 1 || !/^[a-f0-9-]{36}$/.test(record.id || '') || path.basename(reference.report_path) !== record.id + '.json' ||
      record.kind !== 'debug-trace' || record.action !== 'record' || summary.targetSha256 !== targetSha256 || summary.nativeTargetExecuted !== true ||
      !image || image.schema !== 'ig5.native-main-image.v1' || image.targetSha256 !== targetSha256 ||
      image.nativeTargetExecuted !== true || typeof image.runId !== 'string' || !image.runId || !Number.isSafeInteger(image.threadId) || image.threadId < 1 || !Number.isSafeInteger(image.stopSeq) || image.stopSeq < 1 ||
      image.runId !== summary.runId || image.threadId !== summary.threadId || image.stopSeq !== summary.startStopSeq ||
      image.runtimeBase !== summary.runtimeBase || summary.entry !== entry || summary.initialFlags !== flags ||
      runtimeBase !== undefined && BigInt(runtimeBase) !== BigInt(image.runtimeBase)) throw new Error('Native image recording identity/boundaries differ');
  if (recordedTargetPath !== undefined) {
    const canonical = value => {
      if (typeof value !== 'string' || !path.isAbsolute(value) || value.includes('\0')) throw new Error('Recorded target path requires an absolute label');
      const normalized = path.normalize(value);
      return process.platform === 'win32' ? normalized.toLowerCase() : normalized;
    };
    if (canonical(summary.target) !== canonical(recordedTargetPath) ||
        !['ig5.x86-recording.v1', 'ig5.x86-recording.v2'].includes(summary.format) ||
        summary.finalSnapshotIncluded !== true || summary.finalSnapshotCurrent === false)
      throw new Error('Recorded target path/native snapshot identity differs');
  }
  if (!/^[a-f0-9]{64}$/.test(image.sha256 || '') || image.input?.ref !== 'sha256:' + image.sha256) throw new Error('Native image blob reference differs');
  const blobPath = path.join(path.dirname(path.dirname(reference.report_path)), 'blobs', image.sha256 + '.bin');
  const blob = readStableFile(blobPath, 8 * 1024 * 1024).data;
  if (blob.length !== image.bytes || hashBytes(blob) !== image.sha256) throw new Error('Native image blob hash/size differs');
  return { ...image, path: blobPath, sourceReportSha256: reference.report_sha256, sourceReportId: record.id,
    ...(typeof summary.target === 'string' ? { recordedTargetPath: summary.target } : {}) };
}
