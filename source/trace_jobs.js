import path from 'node:path';
import { KernelJobs } from './kernel_jobs.js';
import { AnalysisArtifacts, hashBytes, readStableFile } from './analysis_artifacts.js';
import { joinRecordedTrace } from './debug_trace_chunks.js';
import { compactNativeTrace } from './native_trace_encoding.js';
import { readDebugImage } from './debug_trace.js';

/** Immutable, hash-bound trace snapshots. Only our isolated semantics worker runs. */
export class TraceJobs {
  constructor(cfg, dependencies) {
    this.cfg = cfg;
    this.jobs = new KernelJobs(cfg, { ...dependencies, offlineTrace: true });
    this.artifacts = new AnalysisArtifacts(path.join(cfg.artifactDir || cfg.projectRoot, 'trace-recovery'));
  }
  async run(args, signal) {
    if (Object.hasOwn(args, 'loaded_image')) throw new Error('Native image bytes require a hash-bound trace_image recording reference');
    const maximum = args.max_instructions ?? 50000;
    if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 100000) throw new Error('Trace max_instructions must be 1..100000; default 50000');
    const recordedOnly = Object.hasOwn(args, 'trace_image_only') ? args.trace_image_only : false;
    if (typeof recordedOnly !== 'boolean') throw new Error('trace_image_only must be an explicit boolean');
    if (recordedOnly && (typeof args.target !== 'string' || !path.isAbsolute(args.target) || typeof args.trace_target_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(args.trace_target_sha256)))
      throw new Error('Recorded-image-only mode requires the absolute recorded target label and trace_target_sha256');
    if (!recordedOnly && Object.hasOwn(args, 'trace_target_sha256')) throw new Error('trace_target_sha256 requires trace_image_only=true');
    let targetSha256;
    if (recordedOnly) targetSha256 = args.trace_target_sha256;
    else targetSha256 = hashBytes(readStableFile(args.target, 64 * 1024 * 1024).data);
    let joinedInput;
    if (args.trace_chunk_reports !== undefined) {
      if (args.traces !== undefined) throw new Error('Choose traces or trace_chunk_reports, not both');
      const joined = await joinRecordedTrace(this.cfg, args.trace_chunk_reports, targetSha256, maximum);
      if (recordedOnly && !joined.imageReference) throw new Error('Recorded-image-only mode requires a captured image for every path');
      if (args.trace_runtime_base !== undefined && BigInt(args.trace_runtime_base) !== BigInt(joined.runtimeBase)) throw new Error('Recorded runtime base differs');
      const input = this.artifacts.put(joined.data);
      joinedInput = { ...input, path: path.join(this.artifacts.root, 'blobs', input.sha256 + '.bin'), sources: joined.sources,
        normalization: joined.normalization, rawPartsPreserved: true, nativeTargetExecutedByJoin: false, wholeFunctionCoverageProved: false };
      args = { ...args, traces: [{ path: joinedInput.path, sha256: input.sha256 }], trace_runtime_base: joined.runtimeBase, ...(joined.imageReference && !args.trace_image ? { trace_image: joined.imageReference } : {}) };
    }
    if (!Array.isArray(args.traces) || args.traces.length < 1 || args.traces.length > 2) throw new Error('level=trace requires one or two explicit traces');
    if (!args.trace_entry || !args.trace_exit || !args.trace_inputs || !args.trace_output || !args.initial_flags) throw new Error('level=trace requires trace_entry, trace_exit, trace_inputs, trace_output and initial_flags');
    if (['action', 'name', 'optimize', 'abi', 'offset', 'max_code_bytes', 'max_blocks', 'limit', 'max_slots', 'max_bases', 'max_scan_bytes'].some(key => Object.hasOwn(args, key))) throw new Error('Kernel/database parameters are not accepted by level=trace');
    if (signal?.aborted || this.jobs.closed) throw new Error('Trace recovery cancelled/disposed');
    let bytes = 0; const inputNormalization = [];
    const traces = args.traces.map(trace => {
      if (!trace || typeof trace.path !== 'string' || !/^[a-f0-9]{64}$/.test(trace.sha256 || '')) throw new Error('Each trace requires an explicit path and expected sha256');
      if (Object.hasOwn(trace, 'loaded_image')) throw new Error('Native image bytes require a hash-bound trace_image recording reference');
      if (trace.trace_image && args.trace_image) throw new Error('Choose shared trace_image or per-path trace_image references');
      if (recordedOnly && !trace.trace_image && !args.trace_image) throw new Error('Recorded-image-only mode requires a captured image for every path');
      const { data } = readStableFile(trace.path, 16 * 1024 * 1024);
      const actual = hashBytes(data);
      if (actual !== trace.sha256) throw new Error('Trace SHA-256 mismatch: ' + trace.path);
      let recording;
      if (trace.recording !== undefined) {
        const keys = ['entry', 'exit', 'runtimeBase', 'initialFlags'];
        if (!trace.recording || typeof trace.recording !== 'object' || Array.isArray(trace.recording) ||
            Object.keys(trace.recording).length !== keys.length ||
            keys.some(key => !/^0x[0-9a-fA-F]{1,16}$/.test(trace.recording[key] || '')) ||
            BigInt(trace.recording.initialFlags) >= 0x100000000n) throw new Error('Each recording requires explicit entry/exit/runtimeBase/initialFlags hexadecimal values');
        recording = Object.fromEntries(keys.map(key => [key, trace.recording[key]]));
      }
      const compacted = compactNativeTrace(data);
      if (compacted.data.length > 4 * 1024 * 1024) throw new Error('Trace exceeds 4 MiB after verified native normalization');
      if (compacted.normalization) {
        const input = this.artifacts.put(compacted.data);
        inputNormalization.push({ ...compacted.normalization, normalizedPath: path.join(this.artifacts.root, 'blobs', input.sha256 + '.bin') });
      }
      bytes += compacted.data.length;
      if (bytes > 8 * 1024 * 1024) throw new Error('Combined trace input exceeds 8 MiB');
      const loaded_image = trace.trace_image ? readDebugImage(trace.trace_image, targetSha256,
        recording?.entry ?? args.trace_entry, recording?.initialFlags ?? args.initial_flags, recording?.runtimeBase ?? args.trace_runtime_base,
        recordedOnly ? args.target : undefined) : undefined;
      return { sha256: hashBytes(compacted.data), data: compacted.data.toString('base64'), ...(recording ? { recording } : {}), ...(loaded_image ? { loaded_image } : {}) };
    });
    if (new Set(traces.map(trace => trace.sha256)).size !== traces.length) throw new Error('Duplicate traces do not establish path coverage');
    const request = { ...args, traces, target_sha256: targetSha256 };
    if (traces[0].loaded_image) request.trace_runtime_base ??= traces[0].loaded_image.runtimeBase;
    if (args.trace_image) {
      request.loaded_image = readDebugImage(args.trace_image, request.target_sha256, args.trace_entry, args.initial_flags, args.trace_runtime_base,
        recordedOnly ? args.target : undefined);
      request.trace_runtime_base ??= request.loaded_image.runtimeBase;
      if (traces.some(trace => trace.recording && BigInt(trace.recording.runtimeBase) !== BigInt(request.loaded_image.runtimeBase))) throw new Error('One native image cannot bind independent recordings with different runtime bases');
    }
    delete request.trace_image;
    delete request.trace_chunk_reports;
    const result = await this.jobs.run(request, signal);
    if (inputNormalization.length) result.inputNormalization = inputNormalization;
    if (joinedInput) result.joinedRecording = joinedInput;
    if (signal?.aborted || this.jobs.closed) throw new Error('Trace recovery cancelled/disposed before report commit');
    const record = this.artifacts.save({ kind: 'trace', action: 'recover', result });
    // Put the recovery claim and immutable evidence reference before detailed
    // observations. A host text limit must not hide the second path or claim.
    const priority = ['ok', 'engine', 'method', 'nativeTargetExecuted', 'traceReplayed', 'databaseModified',
      'targetSha256', 'targetVerification', 'coverage', 'proofScope', 'inputs', 'output', 'wholeBinaryVerified', 'recoveredExpression', 'coverageProof', 'solverQueries', 'solverCacheHits'];
    const report = { reportId: record.id, reportSha256: this.artifacts.metadata(record.id).result.recordSha256,
      reportPath: path.join(this.artifacts.root, 'records', record.id + '.json'), completeEvidenceSaved: true };
    const head = Object.fromEntries(priority.filter(key => Object.hasOwn(result, key)).map(key => [key, result[key]]));
    const tail = Object.fromEntries(Object.entries(result).filter(([key]) => !priority.includes(key) && !['paths', 'joinedRecording'].includes(key)));
    const build = (limit, summarizeProofs = false, compactJSON = false) => {
    let previewTruncated = false;
    const proofSummary = (proof, pointer) => {
      if (!proof || typeof proof !== 'object') return proof;
      return { ...Object.fromEntries(['status', 'method', 'scope', 'rewriteCount', 'solverMs', 'counterexample', 'reason']
        .filter(key => Object.hasOwn(proof, key)).map(key => [key, proof[key]])),
        previewSummary: true, fullProofRef: { reportId: record.id, reportSha256: report.reportSha256, jsonPointer: pointer } };
    };
    const paths = result.paths?.map((row, index) => {
      const preview = { ...row }, counts = {};
      for (const key of ['snapshotRepairs', 'environmentReads', 'fixedEnvironmentConstraintChecks', 'fixedEnvironmentAddressChecks', 'semanticCorrections']) {
        if (Array.isArray(row[key])) {
          counts[key] = row[key].length;
          if (row[key].length > limit) { preview[key] = row[key].slice(0, limit); previewTruncated = true; }
        }
      }
      for (const [section, key, countKey] of [['guard', 'sources', 'guardSources'], ['guard', 'environmentAssumptions', 'environmentAssumptions'],
        ['binaryBinding', 'loaderRelocationEvidence', 'loaderRelocationEvidence'], ['binaryBinding', 'mismatchAddresses', 'mismatchAddresses'],
        ['expressionNormalization', 'steps', 'expressionNormalizationSteps'], ['expressionNormalization', 'attempts', 'expressionNormalizationAttempts'],
        ['guardDomainDiagnostic', 'attempts', 'guardDomainAttempts'], ['guardDomainDiagnostic', 'provedRanges', 'guardDomainProvedRanges'],
        ['guardCandidateSearch', 'attempts', 'guardCandidateAttempts'], ['guardCandidateSearch', 'rejectedByWitness', 'guardCandidatesRejectedByWitness'],
        ['guardCandidateSearch', 'witnesses', 'guardCandidateWitnesses'],
        ['astNormalization', 'steps', 'astNormalizationSteps'], ['astNormalization', 'attempts', 'astNormalizationAttempts']]) {
        const values = row[section]?.[key];
        if (Array.isArray(values)) {
          counts[countKey] = values.length;
          if (values.length > limit) { preview[section] = { ...preview[section], [key]: values.slice(0, limit) }; previewTruncated = true; }
        }
      }
      if (summarizeProofs) {
        const pointer = '/result/paths/' + index;
        for (const key of ['outputProof', 'synthesisProof']) {
          if (row[key]) preview[key] = proofSummary(row[key], pointer + '/' + key);
        }
        if (row.guard?.proof) preview.guard = { ...preview.guard, proof: proofSummary(row.guard.proof, pointer + '/guard/proof') };
        if (Array.isArray(row.synthesisAttempts)) {
          counts.synthesisAttempts = row.synthesisAttempts.length;
          preview.synthesisAttempts = row.synthesisAttempts.map((attempt, attemptIndex) => ({ ...attempt,
            ...(attempt.proof ? { proof: proofSummary(attempt.proof, pointer + '/synthesisAttempts/' + attemptIndex + '/proof') } : {}) }));
        }
        previewTruncated = true;
      }
      return { ...preview, evidenceCounts: counts };
    });
    let joinedRecording;
    if (result.joinedRecording) {
      joinedRecording = { ...result.joinedRecording };
      const sources = joinedRecording.sources;
      if (sources?.length > limit) { joinedRecording.sources = sources.slice(0, limit); joinedRecording.sourceCount = sources.length; previewTruncated = true; }
    }
    return { ...head, ...report, ...(paths ? { paths } : {}), ...tail, ...(joinedRecording ? { joinedRecording } : {}),
      previewTruncated, previewEvidenceLimit: limit, previewBudgetBytes: 16384, previewBudgetExceeded: false,
      proofPreviewMode: summarizeProofs ? 'summaries-with-immutable-report-references' : 'full',
      ...(compactJSON ? { previewCompactJSON: true } : {}) };
    };
    let preview;
    for (const limit of [32, 16, 8, 4, 2, 1, 0]) {
      preview = build(limit);
      if (Buffer.byteLength(JSON.stringify(preview, null, 1), 'utf8') <= 16384) return preview;
    }
    // Full proofs remain unchanged in the hash-bound report. Explicit summaries
    // avoid repeating the same local-certificate chain in three preview fields.
    // Expressions stay intact; every summarized proof has its exact JSON pointer.
    preview = build(0, true);
    if (Buffer.byteLength(JSON.stringify(preview, null, 1), 'utf8') <= 16384) return preview;
    // Whitespace is not semantic data. The trace renderer applies the same
    // lossless JSON validator and emits this representation without indentation.
    preview = build(0, true, true);
    if (Buffer.byteLength(JSON.stringify(preview), 'utf8') <= 16384) return preview;
    // Unusually large core expressions remain explicit, with an honest overrun.
    preview.previewBudgetExceeded = true;
    return preview;
  }
  async dispose() {
    try { await this.jobs.dispose(); } finally { await this.artifacts.dispose(); }
  }
}
