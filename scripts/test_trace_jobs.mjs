import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { TraceJobs } from '../source/trace_jobs.js';
import { defineIntegrationTools } from '../integration_tools.js';
import { compactNativeTrace } from '../source/native_trace_encoding.js';
import { AnalysisArtifacts, hashBytes } from '../source/analysis_artifacts.js';
import { readDebugImage } from '../source/debug_trace.js';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-trace-'));
const target = path.join(dir, 'target'), trace = path.join(dir, 'trace');
fs.writeFileSync(target, 'target'); fs.writeFileSync(trace, 'trace\n');
const hash = createHash('sha256').update('trace\n').digest('hex');
const args = { target, level: 'trace', traces: [{ path: trace, sha256: hash }], trace_entry: '0x1', trace_exit: '0x2', trace_inputs: ['edi', 'esi'], trace_output: 'eax', initial_flags: '0x202' };

test('host snapshots, hash binding and report preservation', async () => {
  const jobs = new TraceJobs({ projectRoot: dir });
  jobs.jobs.run = async request => {
    assert.equal(Buffer.from(request.traces[0].data, 'base64').toString(), 'trace\n');
    assert.match(request.target_sha256, /^[a-f0-9]{64}$/);
    return { ok: true, nativeTargetExecuted: false, wholeBinaryVerified: false };
  };
  try {
    const result = await jobs.run(args);
    assert.equal(jobs.artifacts.get(result.reportId).result.wholeBinaryVerified, false);
    await assert.rejects(jobs.run({ ...args, traces: [{ path: trace, sha256: '0'.repeat(64) }] }), /SHA-256 mismatch/);
    await assert.rejects(jobs.run({ ...args, traces: [...args.traces, ...args.traces] }), /Duplicate traces/);
    await assert.rejects(jobs.run({ ...args, action: 'analyze' }), /not accepted/);
    await assert.rejects(jobs.run({ ...args, loaded_image: {} }), /hash-bound trace_image/);
    await assert.rejects(jobs.run(args, AbortSignal.abort()), /cancelled/);
    for (const maximum of [0, 100001, 50000.5, true]) await assert.rejects(jobs.run({ ...args, max_instructions: maximum }), /max_instructions/);
  } finally { await jobs.dispose(); }
});

test('trace-only routing preserves raw/high/kernel separation', async () => {
  const tool = defineIntegrationTools({ trace: { run: async value => ({ route: 'trace', level: value.level }) } }, { projectRoot: dir }, undefined).find(tool => tool.name === 'ig5_ir');
  assert(tool.parameters.properties.level.enum.includes('trace'));
  assert.deepEqual(await tool.execute(args), { route: 'trace', level: 'trace' });
  assert.throws(() => tool.execute({ ...args, level: 'raw' }), /Trace-only/);
  for (const level of ['raw', 'high', 'kernel']) {
    for (const extra of [{ trace_image_only: true }, { trace_target_sha256: 'a'.repeat(64) }])
      assert.throws(() => tool.execute({ target, level, ...extra }), /Trace-only/);
  }
});

test('recorded-image-only mode uses an absent target label and rejects incomplete identities before a worker', async () => {
  const store = new AnalysisArtifacts(path.join(dir, 'debug-recorded-only'));
  const input = store.put(Buffer.from([0x90, 0xc3]));
  const missingTarget = path.join(dir, 'missing-original.exe'), targetSha256 = 'a'.repeat(64);
  const image = { schema: 'ig5.native-main-image.v1', runtimeBase: '0x1000', moduleSize: 2, bytes: input.bytes,
    sha256: input.sha256, input, targetSha256, runId: 'captured', threadId: 1, stopSeq: 3, nativeTargetExecuted: true,
    regions: [{ rva: '0x0', bytes: 2, blobOffset: 0 }], partial: false };
  const record = store.save({ kind: 'debug-trace', action: 'record', result: { target: missingTarget, targetSha256,
    format: 'ig5.x86-recording.v2', finalSnapshotIncluded: true, finalSnapshotCurrent: true, nativeTargetExecuted: true,
    runId: 'captured', threadId: 1, startStopSeq: 3, runtimeBase: '0x1000', entry: '0x1000', initialFlags: '0x202', loadedImage: image } });
  const reference = { report_path: path.join(store.root, 'records', record.id + '.json'), report_sha256: store.metadata(record.id).result.recordSha256 };
  const request = { ...args, target: missingTarget, trace_entry: '0x1000', trace_image: reference,
    trace_image_only: true, trace_target_sha256: targetSha256 };
  let starts = 0;
  const jobs = new TraceJobs({ projectRoot: dir });
  jobs.jobs.run = async value => { starts++; assert.equal(value.target_sha256, targetSha256); assert.equal(value.trace_image_only, true);
    assert.equal(value.loaded_image.recordedTargetPath, missingTarget); return { ok: true, nativeTargetExecuted: false }; };
  try {
    assert.equal(fs.existsSync(missingTarget), false);
    await jobs.run(request); assert.equal(starts, 1); assert.equal(fs.existsSync(missingTarget), false);
    const variants = [
      [{ ...request, trace_image_only: false }, /requires trace_image_only/],
      [{ ...request, trace_image_only: null }, /explicit boolean/],
      [{ ...request, trace_image_only: 1 }, /explicit boolean/],
      [{ ...request, trace_target_sha256: undefined }, /trace_target_sha256/],
      [{ ...request, trace_target_sha256: 'b'.repeat(64) }, /identity/],
      [{ ...request, target: missingTarget + '.other' }, /identity/],
      [{ ...request, trace_image: undefined }, /captured image/],
      [{ ...request, traces: [{ ...args.traces[0], loaded_image: image }] }, /hash-bound trace_image/],
    ];
    for (const [value, expected] of variants) await assert.rejects(jobs.run(value), expected);
    const { trace_image_only, trace_target_sha256, ...originalMode } = request;
    await assert.rejects(jobs.run(originalMode), /ENOENT/);
    assert.equal(starts, 1);
    fs.writeFileSync(path.join(store.root, 'blobs', input.sha256 + '.bin'), Buffer.from([0x90, 0x90]));
    await assert.rejects(jobs.run(request), /blob hash/); assert.equal(starts, 1);
  } finally { await jobs.dispose(); await store.dispose(); }
});

test('native image references require matching target, pause, boundaries and blob hashes', async () => {
  const store = new AnalysisArtifacts(path.join(dir, 'debug-traces'));
  const input = store.put(Buffer.from([0x90, 0x90]));
  const targetSha = hashBytes(fs.readFileSync(target));
  const image = { schema: 'ig5.native-main-image.v1', runtimeBase: '0x1000', moduleSize: 2, bytes: input.bytes,
    sha256: input.sha256, input, targetSha256: targetSha, runId: 'owned', threadId: 1, stopSeq: 3, nativeTargetExecuted: true,
    regions: [{ rva: '0x0', bytes: 2, blobOffset: 0 }], unreadableRanges: [], partial: false };
  const record = store.save({ kind: 'debug-trace', action: 'record', result: { targetSha256: targetSha, nativeTargetExecuted: true,
    runId: 'owned', threadId: 1, startStopSeq: 3, runtimeBase: '0x1000', entry: '0x1000', initialFlags: '0x202', loadedImage: image } });
  const ref = { report_path: path.join(store.root, 'records', record.id + '.json'), report_sha256: store.metadata(record.id).result.recordSha256 };
  try {
    assert.equal(readDebugImage(ref, targetSha, '0x1000', '0x202', '0x1000').sha256, input.sha256);
    const jobs = new TraceJobs({ projectRoot: dir });
    jobs.jobs.run = async request => { assert.equal(request.trace_runtime_base, '0x1000'); assert.equal(request.loaded_image.sha256, input.sha256); return { ok: true }; };
    try {
      await jobs.run({ ...args, trace_entry: '0x1000', initial_flags: '0x202', trace_image: ref });
      await assert.rejects(jobs.run({ ...args, trace_entry: '0x1000', initial_flags: '0x202', trace_image: ref,
        traces: [{ ...args.traces[0], recording: { entry: '0x2000', exit: '0x2001', runtimeBase: '0x2000', initialFlags: '0x202' } }] }), /different runtime bases/);
      const secondImage = { ...image, runtimeBase: '0x2000', runId: 'other-owned', threadId: 2, stopSeq: 4 };
      const secondRecord = store.save({ kind: 'debug-trace', action: 'record', result: { targetSha256: targetSha, nativeTargetExecuted: true,
        runId: secondImage.runId, threadId: 2, startStopSeq: 4, runtimeBase: '0x2000', entry: '0x2000', initialFlags: '0x246', loadedImage: secondImage } });
      const secondRef = { report_path: path.join(store.root, 'records', secondRecord.id + '.json'), report_sha256: store.metadata(secondRecord.id).result.recordSha256 };
      const secondTrace = path.join(dir, 'second-trace'); fs.writeFileSync(secondTrace, 'another-trace\n');
      jobs.jobs.run = async request => { assert.equal(request.traces[0].loaded_image.runtimeBase, '0x1000'); assert.equal(request.traces[1].loaded_image.runtimeBase, '0x2000'); assert.equal(request.traces[1].loaded_image.runId, 'other-owned'); return { ok: true }; };
      await jobs.run({ ...args, trace_entry: '0x1000', initial_flags: '0x202', traces: [
        { ...args.traces[0], trace_image: ref }, { path: secondTrace, sha256: hashBytes(fs.readFileSync(secondTrace)), trace_image: secondRef,
          recording: { entry: '0x2000', exit: '0x2001', runtimeBase: '0x2000', initialFlags: '0x246' } }] });
      await assert.rejects(jobs.run({ ...args, traces: [{ ...args.traces[0], loaded_image: image }] }), /hash-bound trace_image/);
    } finally { await jobs.dispose(); }
    assert.throws(() => readDebugImage(ref, targetSha, '0x1001', '0x202', '0x1000'), /identity/);
    assert.throws(() => readDebugImage(ref, '0'.repeat(64), '0x1000', '0x202'), /identity/);
    assert.throws(() => readDebugImage({ ...ref, report_sha256: '0'.repeat(64) }, targetSha, '0x1000', '0x202'), /report hash/);
    fs.writeFileSync(path.join(store.root, 'blobs', input.sha256 + '.bin'), Buffer.from([0x90, 0xc3]));
    assert.throws(() => readDebugImage(ref, targetSha, '0x1000', '0x202'), /blob hash/);
  } finally { await store.dispose(); }
});

test('per-path ASLR recording metadata is preserved and bounded', async () => {
  const jobs = new TraceJobs({ projectRoot: dir });
  const recording = { entry: '0x7ff000001000', exit: '0x7ff000001010', runtimeBase: '0x7ff000000000', initialFlags: '0x246' };
  jobs.jobs.run = async request => { assert.deepEqual(request.traces[0].recording, recording); return { ok: true }; };
  try {
    await jobs.run({ ...args, traces: [{ ...args.traces[0], recording }] });
    for (const invalid of [{ ...recording, extra: '0x0' }, { ...recording, entry: 12 }, { ...recording, initialFlags: '0x100000000' }]) {
      await assert.rejects(jobs.run({ ...args, traces: [{ ...args.traces[0], recording: invalid }] }), /recording requires/);
    }
  } finally { await jobs.dispose(); }
});

test('bounded FC preview retains complete hash-bound evidence', async () => {
  const jobs = new TraceJobs({ projectRoot: dir });
  jobs.jobs.run = async () => ({ paths: [{ outputProof: { status: 'unsat' }, snapshotRepairs: Array.from({ length: 80 }, (_, n) => ({ instruction: n })) }], coverage: 'single-recorded-path' });
  try {
    const result = await jobs.run(args);
    assert.equal(result.paths[0].snapshotRepairs.length, 32);
    assert.equal(result.paths[0].evidenceCounts.snapshotRepairs, 80);
    assert(result.previewTruncated && result.completeEvidenceSaved);
    assert.equal(jobs.artifacts.get(result.reportId).result.paths[0].snapshotRepairs.length, 80);
    assert.equal(result.paths[0].outputProof.status, 'unsat');
  } finally { await jobs.dispose(); }
});

test('native compression roundtrip is exact and continuation metadata stays explicit', () => {
  const registers = 'r:' + Array(16).fill('0x0').join(':');
  const raw = Buffer.from('h:ig5-native-x64-v2\ns:gs:0x1000\n' + registers + '\ne:0x202\ni:0x1:2:0fa2\nc:0x3:1:f9\n' + registers + '\ne:0x203\ni:0x4:1:90\n');
  const result = compactNativeTrace(raw);
  assert.equal(result.normalization.originalSha256, createHash('sha256').update(raw).digest('hex'));
  assert(result.normalization.exactExpansionVerified);
  assert(result.data.toString().includes('\nd:0x0\n'));
  assert(result.data.toString().includes('\nc:0x3:1:f9\n'));
});

test('large duplicate proof chains use explicit immutable references without changing full evidence', async () => {
  const jobs = new TraceJobs({ projectRoot: dir });
  const proof = { status: 'unsat', method: 'local-equalities-and-congruence', scope: 'Full original output equality',
    localProofs: Array.from({ length: 8 }, () => ({ status: 'unsat', method: 'universal-template', evidence: 'independent full-width lemma '.repeat(300) })) };
  const expression = { op: 'input', name: 'x', bits: 64 };
  jobs.jobs.run = async () => ({ paths: [0,1].map(() => ({ outputExpression: expression, outputProof: proof,
    synthesisProof: proof, synthesisAttempts: [{ method: 'before-synthesis', proof }] })), wholeBinaryVerified: false });
  try {
    const result = await jobs.run(args), saved = jobs.artifacts.get(result.reportId);
    assert.equal(result.proofPreviewMode, 'summaries-with-immutable-report-references');
    assert.equal(result.previewBudgetExceeded, false); assert(Buffer.byteLength(JSON.stringify(result,null,1)) <= 16384);
    for (let index = 0; index < 2; index++) {
      const preview = result.paths[index]; assert.equal(preview.outputProof.status,'unsat'); assert.equal(preview.outputProof.previewSummary,true);
      assert.deepEqual(preview.outputExpression,expression);
      assert.deepEqual(saved.result.paths[index].outputProof,proof); assert.equal(saved.result.paths[index].outputProof.previewSummary,undefined);
      const reference = preview.outputProof.fullProofRef;
      assert.equal(reference.reportId,result.reportId); assert.equal(reference.reportSha256,result.reportSha256);
      assert.equal(reference.jsonPointer,'/result/paths/'+index+'/outputProof');
      assert.equal(preview.synthesisAttempts[0].proof.fullProofRef.jsonPointer,'/result/paths/'+index+'/synthesisAttempts/0/proof');
    }
  } finally { await jobs.dispose(); }
});

test('deep expressions remain whole in compact lossless JSON when indentation exceeds the preview budget', async () => {
  const jobs = new TraceJobs({ projectRoot: dir });
  let expression = { op: 'input', name: 'x', bits: 64 };
  for(let n=0;n<25;n++) expression={op:'add',bits:64,args:[expression,{op:'constant',bits:64,value:'0x1'}]};
  jobs.jobs.run = async () => ({ paths:[0,1].map(()=>({outputExpression:expression,outputProof:{status:'unsat'}})),wholeBinaryVerified:false });
  try {
    const preview=await jobs.run(args);assert.equal(preview.previewCompactJSON,true);assert.equal(preview.previewBudgetExceeded,false);
    const tool=defineIntegrationTools({}, {projectRoot:dir}).find(d=>d.name==='ig5_ir');
    const rendered=tool.output.render(args,preview)[0].text;
    assert(Buffer.byteLength(rendered)<=16384);assert.deepEqual(JSON.parse(rendered),preview);
    for(const row of JSON.parse(rendered).paths)assert.deepEqual(row.outputExpression,expression);
    assert.throws(()=>tool.output.render(args,{...preview,invalid:-0}),/non-lossless number/);
  } finally { await jobs.dispose(); }
});

test('two long paths keep proofs and both environments inside the FC evidence budget', async () => {
  const jobs = new TraceJobs({ projectRoot: dir });
  const rows = [0, 1].map(index => ({ traceSha256: String(index).repeat(64), instructionCount: 25000 + index,
    recording: { entry: '0x1000', exit: '0x2000', runtimeBase: '0x0', initialFlags: index ? '0x204' : '0x200' },
    outputProof: { status: 'unsat' }, finalSnapshotVerified: true,
    guard: { expression: index ? 'x > y' : 'x <= y', proof: { status: 'unsat' }, sources: Array(100).fill('0x1234') },
    semanticCorrections: Array.from({ length: 100 }, (_, n) => ({ instruction: n, detail: 'actual observed state '.repeat(60) })),
    snapshotRepairs: Array.from({ length: 100 }, (_, n) => ({ instruction: n, values: Array(8).fill('0x1') })),
    guardCandidateSearch: { attempts: Array.from({ length: 42 }, () => ({ candidate: 'unsigned(x) < unsigned(y)', proof: { status: 'sat', counterexample: { x: '0x1', y: '0x2' } } })),
      witnesses: Array.from({ length: 16 }, (_, n) => ({ sourceAttempt: n, inputs: { x: '0x1', y: '0x2' }, guardValue: true })),
      rejectedByWitness: Array.from({ length: 31 }, () => ({ witnessIndex: 0, candidateValue: false, guardValue: true, method: 'exact-SAT-counterexample-reuse' })) },
    astNormalization: { steps: Array.from({ length: 80 }, () => ({ rule: 'local-identity', proof: { status: 'unsat' } })), attempts: [] } }));
  const scope = { symbolicInputBits: { x: 64, y: 64 }, allInputPairsProved: true, originalBinaryWholeProgramProved: false };
  jobs.jobs.run = async () => ({ coverage: 'trace-model-input-domain', proofScope: scope, recoveredExpression: { op: 'select', bits: 64 },
    coverageProof: { disjoint: { status: 'unsat' }, exhaustive: { status: 'unsat' } }, paths: rows, wholeBinaryVerified: false });
  try {
    const result = await jobs.run(args), rendered = JSON.stringify(result, null, 1);
    assert(Buffer.byteLength(rendered, 'utf8') <= 16384); assert.equal(result.previewBudgetExceeded, false);
    assert.equal(result.paths.length, 2); assert.equal(result.paths[1].recording.initialFlags, '0x204');
    assert.equal(result.paths[1].guard.proof.status, 'unsat'); assert.equal(result.coverageProof.exhaustive.status, 'unsat');
    assert.deepEqual(result.proofScope, scope);
    assert(rendered.indexOf('proofScope') < rendered.indexOf('semanticCorrections'));
    assert(rendered.indexOf('reportId') < rendered.indexOf('semanticCorrections'));
    assert(result.previewTruncated && result.previewEvidenceLimit < 32);
    assert.equal(jobs.artifacts.get(result.reportId).result.paths[1].semanticCorrections.length, 100);
    assert.equal(result.paths[1].evidenceCounts.astNormalizationSteps, 80);
    assert.equal(jobs.artifacts.get(result.reportId).result.paths[1].astNormalization.steps.length, 80);
    assert.equal(result.paths[1].evidenceCounts.guardCandidateAttempts, 42);
    assert.equal(result.paths[1].evidenceCounts.guardCandidatesRejectedByWitness, 31);
    assert.equal(result.paths[1].evidenceCounts.guardCandidateWitnesses, 16);
    assert.equal(jobs.artifacts.get(result.reportId).result.paths[1].guardCandidateSearch.rejectedByWitness.length, 31);
  } finally { await jobs.dispose(); }
});
