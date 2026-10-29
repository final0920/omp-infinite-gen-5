import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { analyzeVmObservations } from '../source/vm_observations.js';
import { runRecoveryProfile } from '../source/vm_recovery_profile.js';
import { AnalysisJobs } from '../source/analysis_jobs.js';
import { AnalysisArtifacts } from '../source/analysis_artifacts.js';
import { createAnalysisService } from '../analysis_tools.js';
import { observationWindow as window, replaceObservationRows as replace, observationTarget as target, observationHash as hash } from './fixtures/vm_observation_cases.mjs';
const run = (windows = [window()], extra = {}) => analyzeVmObservations({ targetSha256: target, windows, ...extra });

test('v1 and lossless v2 delta frames preserve all GPR, flags, memory and source lines', () => {
  for (const version of [1, 2]) {
    const value = run([window({ version })]), [a, b] = value.stopGroups;
    assert.deepEqual(value.totals, { windows: 1, rawBytes: window({ version }).data.length, instructions: 2, stopGroups: 2, memoryReads: 2 });
    assert.equal(Object.keys(a.before.gprs).length, 16); assert.equal(a.before.gprs.rax, '0x1');
    assert.deepEqual(a.after.gprs, b.before.gprs); assert.equal(b.after.gprs.rax, '0x3');
    assert.equal(a.memoryReads[0].littleEndianHex, '78563412'); assert.equal(a.memoryReads[0].bytes, 4);
    assert.equal(a.pauseSequence.before, 1); assert.equal(b.pauseSequence.after, 3);
    assert.equal(a.memoryWrites.status, 'not-recorded-by-this-format'); assert.equal(a.phase, 'unclassified');
    assert.equal(value.identity.moduleLoadEpoch, null); assert.equal(value.windows[0].memoryEpoch, null);
    for (const key of ['nativeTargetExecutedByThisRequest', 'changesExecutionAuthority', 'liveExecutionInspected', 'businessAccepted', 'wholeFunctionCoverageProved', 'architectureProved']) assert.equal(value[key], false);
  }
});
test('coalesced CPUID observations never invent an intermediate snapshot or validate continuation semantics', () => {
  const value = run([window({ cpuid: true })]);
  assert.equal(value.totals.instructions, 4); assert.equal(value.totals.stopGroups, 2);
  const group = value.stopGroups[0]; assert.equal(group.instructions.length, 2);
  assert.equal(group.intermediateStateAvailable, false); assert.equal(group.instructions[1].beforeStateAvailable, false);
  assert.equal(group.instructions[1].continuationSemanticsValidated, false);
  assert.equal(group.after.rip, '0x1003'); assert.equal(group.after.gprs.rax, '0x2');
});
test('changed observed code bytes have no guessed cause or global code epoch', () => {
  const value = run([window({ count: 4, changeCode: true })]);
  assert.equal(value.codeObservations.observedChanges, 3); assert.equal(value.codeObservations.globalCodeEpochKnown, false);
  assert.equal(value.codeObservations.changes[0].cause, 'unknown-not-a-proved-SMC-write');
});
test('paging still validates the complete input and an out-of-range page is explicit', () => {
  const value = run([window({ count: 5 })], { offset: 3, limit: 1 });
  assert.equal(value.stopGroups[0].groupIndex, 3); assert.equal(value.pagination.nextOffset, 4);
  assert.equal(value.pagination.entireInputValidated, true); assert.equal(value.pagination.pageIsWholeRecording, false);
  assert.equal(run(undefined, { offset: 10 }).stopGroups.length, 0);
  const corrupt = replace(window({ count: 5 }), text => text.replace(/f:.*/, 'f:0x1'));
  assert.throws(() => run([corrupt], { limit: 1 }), /snapshot width/);
});
test('consecutive windows require the complete final-to-initial snapshot and run/thread/location', () => {
  const first = window(), second = window({ id: 2, start: 3, pc: 0x1002, value: 3 });
  assert.equal(run([first, second]).totals.stopGroups, 4);
  for (const field of ['runId', 'threadId', 'runtimeBase', 'startStopSeq']) {
    const bad = structuredClone(second); bad.summary[field] = typeof bad.summary[field] === 'number' ? bad.summary[field] + 1 : field === 'runtimeBase' ? '0x2000' : 'different';
    if (field === 'startStopSeq') bad.summary.endStopSeq++;
    assert.throws(() => run([first, bad]), /continuity/);
  }
  const badLocation = structuredClone(second); badLocation.source.locationFingerprint = 'd'.repeat(64);
  assert.throws(() => run([first, badLocation]), /continuity/);
  assert.throws(() => run([first, window({ id: 2, start: 3, pc: 0x1002, value: 4 })]), /continuity/);
  assert.throws(() => run([first, window({ id: 2, start: 3, pc: 0x1002, value: 3, gs: false })]), /continuity/);
  first.summary.stopReason = 'returned'; assert.throws(() => run([first, second]), /continuity/);
});
test('later window corruption cannot be hidden by an earlier page', () => {
  const bad = replace(window({ id: 2, start: 3, pc: 0x1002, value: 3 }), text => text + 'i:0x1004:1:90\n');
  assert.throws(() => run([window(), bad], { limit: 1 }), /after final snapshot/);
});
test('legacy finalSnapshotCurrent absence remains distinct from explicit false', () => {
  const value = window(); delete value.summary.finalSnapshotCurrent;
  assert.equal(run([value]).totals.windows, 1); value.summary.finalSnapshotCurrent = false;
  assert.throws(() => run([value]), /final snapshot/);
});
test('framing rejects non-ASCII, missing newline, mismatched version, delta width and order', () => {
  const cases = [text => text.trimEnd(), text => text + '\u00ff', text => text.replace('x64-v2', 'x64-v1'),
    text => text.replace('d:0x1:0x2', 'd:0x3:0x2'), text => text.replace('e:0x202\n', ''),
    text => text.replace('d:0x1', 'd:0x10000'), text => text.replace('e:0x202', 'e:0x100000000')];
  for (const change of cases) assert.throws(() => run([replace(window(), change)]), error => error.code === 'INVALID_VM_OBSERVATION');
});
test('record identity/hash/summary mismatch and duplicate windows are rejected', () => {
  for (const [field, value] of Object.entries({ bytes: 1, sha256: 'd'.repeat(64), entry: '0x1001', exit: '0x1003', initialFlags: '0x203', instructionCount: 3, confirmedStepStops: 1, nativeTargetExecuted: false, targetSha256: '0'.repeat(64) })) {
    const bad = window(); bad.summary[field] = value;
    assert.throws(() => run([bad]), error => error.code === 'INVALID_VM_OBSERVATION');
  }
  assert.throws(() => run([window(), window()]), /identity/);
});
test('memory observation widths and values are bounded without guessed bytecode roles', () => {
  const value = replace(window(), text => text.replaceAll('mr:0x8000:4:0x12345678', 'mr:0x8000:64:0x1'));
  const read = run([value]).stopGroups[0].memoryReads[0];
  assert.equal(read.littleEndianHex, '01' + '00'.repeat(63)); assert.match(read.meaning, /not-bytecode/);
  for (const replacement of ['mr:0x8000:3:0x1', 'mr:0x8000:1:0x100', Array(9).fill('mr:0x8000:1:0x0').join('\n')])
    assert.throws(() => run([replace(window(), text => text.replace('mr:0x8000:4:0x12345678', replacement))]), /memory observation|byte width/);
});
test('native continuation requires v2, preceding CPUID, adjacency and one continuation', () => {
  for (const change of [text => text.replace('0fa2', '9090'), text => text.replace('c:0x1002', 'c:0x1003'), text => text.replace('c:0x1002:1:90', 'c:0x1002:1:90\nc:0x1003:1:90')])
    assert.throws(() => run([replace(window({ cpuid: true }), change)]), /Invalid/);
});
test('instruction and page budgets apply even when output is small', () => {
  assert.throws(() => run(undefined, { maxInstructions: 1, limit: 1 }), /instruction budget/);
  for (const extra of [{ limit: 65 }, { offset: -0 }, { maxInstructions: 100001 }]) assert.throws(() => run(undefined, extra), /budget/);
  assert.throws(() => run(Array.from({ length: 257 }, (_, n) => window({ id: n + 1 }))), /1..256/);
});
test('bounded code address tracking reports a lower bound after 4096 addresses', () => {
  const windows = Array.from({ length: 9 }, (_, n) => window({ id: n + 1, start: 1 + 512 * n, count: 512, pc: 0x1000 + 512 * n, value: 1 + 512 * n, reads: false }));
  const value = run(windows, { limit: 1 }); assert.equal(value.codeObservations.trackedAddresses, 4096);
  assert.equal(value.codeObservations.trackingComplete, false); assert.equal(value.codeObservations.changeCountIsLowerBound, true);
});
test('actual bounded data worker matches the pure observer and honors cancellation', async t => {
  const jobs = new AnalysisJobs(); t.after(() => jobs.dispose());
  const request = { targetSha256: target, windows: [window({ cpuid: true })] };
  assert.deepEqual(await jobs.run('vm-observations', request), analyzeVmObservations(request));
  const controller = new AbortController(); controller.abort();
  await assert.rejects(jobs.run('vm-observations', request, controller.signal), error => error.code === 'ABORT_ERR');
  const active = new AbortController(), cancelled = jobs.run('vm-observations', request, active.signal);
  active.abort(); await assert.rejects(cancelled, error => error.code === 'ABORT_ERR');
  assert.deepEqual(await jobs.run('vm-observations', request), analyzeVmObservations(request));
  const bad = replace(window(), text => text + 'bad\n');
  await assert.rejects(jobs.run('vm-observations', { targetSha256: target, windows: [bad] }), error => error.code === 'INVALID_VM_OBSERVATION');
});

async function host(t, count = 3) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-native-observations-'));
  const inputStore = new AnalysisArtifacts(path.join(root, 'debug-traces'));
  const analysis = createAnalysisService({}, { artifactDir: root, projectRoot: root });
  const source = window({ count }), input = inputStore.put(source.data);
  const record = inputStore.save({ kind: 'debug-trace', action: 'record', result: { ...source.summary, input } });
  const request = { recordings: [{ id: record.id, sha256: inputStore.metadata(record.id).result.recordSha256 }], target_sha256: target };
  const mgr = { analysis, checkCancelled() {}, scope: { getStore: () => ({ signal: new AbortController().signal }) } };
  const invoke = (value = request, extra = {}) => runRecoveryProfile(mgr, { recovery: { observations: value }, ...extra }, { artifactDir: root, projectRoot: root });
  const reports = () => fs.readdirSync(path.join(analysis.artifacts.root, 'records')).length;
  t.after(async () => { await analysis.dispose(); await inputStore.dispose();
    assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir())); assert.match(path.basename(root), /^ig5-native-observations-/);
    assert.equal(fs.lstatSync(root).isSymbolicLink(), false); fs.rmSync(root, { recursive: true, force: true }); });
  return { root, inputStore, source, record, request, mgr, analysis, invoke, reports };
}
test('profile imports committed bytes, saves a hash-bound full page and truthfully truncates its preview', async t => {
  const f = await host(t), { observations: view } = await f.invoke();
  assert.equal(hash(fs.readFileSync(view.reportPath)), view.reportSha256); assert.equal(view.eventPreviewComplete, false);
  assert.equal(view.stopGroups.length, 2); assert.equal(f.analysis.artifacts.get(view.reportId).result.stopGroups.length, 3);
  assert.equal(view.wholeFunctionCoverageProved, false); assert.equal(view.liveExecutionInspected, false); assert.equal(view.architectureProved, false);
  assert.equal(f.reports(), 1);
});

test('opt-in phase profile binds versions, keeps old output unchanged, and rejects forged worker stages before save', async t => {
  const f = await host(t);
  assert.equal((await f.invoke()).observations.phaseModel, undefined);
  const view = (await f.invoke({ ...f.request, phase_model: true })).observations;
  assert.equal(view.phaseModel.groups.length, 2); assert.equal(view.phaseModel.responsePreviewComplete, false);
  const result = f.analysis.artifacts.get(view.reportId).result;
  assert.equal(result.phaseModel.groups.length, 3); assert.equal(result.phaseModel.phaseVerified, false);
  assert.equal(result.phaseModel.groups[0].versions[0].version.binding.reportId, f.record.id);
  await assert.rejects(f.invoke({ ...f.request, phase_model: 'true' }), /boolean/);
  const original = f.analysis.observeNative;
  const count = f.reports();
  f.analysis.observeNative = async (...args) => { const output = await original(...args); output.phaseModel.groups[0].versions[0].version.binding.reportSha256 = 'f'.repeat(64); return output; };
  await assert.rejects(f.invoke({ ...f.request, phase_model: true }), { code: 'CODE_VERSION_MISMATCH' });
  assert.equal(f.reports(), count);
});
test('profile does not access debugger, approval, task mutation or target execution services', async t => {
  const f = await host(t);
  for (const key of ['get', 'spawnWorker', 'performDebug', 'run', 'close', 'remoteStore']) f.mgr[key] = () => { throw Error('Unexpected native service ' + key); };
  assert.equal((await f.invoke()).observations.nativeTargetExecutedByThisRequest, false);
});
test('wrong report SHA, changed report bytes and changed blobs leave no output report', async t => {
  const f = await host(t), bad = structuredClone(f.request); bad.recordings[0].sha256 = '0'.repeat(64);
  await assert.rejects(f.invoke(bad), /report SHA/);
  const filename = path.join(f.inputStore.root, 'records', f.record.id + '.json'), original = fs.readFileSync(filename);
  fs.appendFileSync(filename, ' '); await assert.rejects(f.invoke(), /report bytes/); fs.writeFileSync(filename, original);
  fs.appendFileSync(path.join(f.inputStore.root, 'blobs', f.source.summary.sha256 + '.bin'), ' ');
  await assert.rejects(f.invoke(), /hash does not match/); assert.equal(f.reports(), 0);
});
test('strict parameter modes reject mixed controls, duplicates and unknown input fields', async t => {
  const f = await host(t);
  assert.throws(() => f.invoke(f.request, { target: 'x' }), /Use recovery separately/);
  assert.throws(() => runRecoveryProfile(f.mgr, { recovery: { observations: f.request, case_ref: {} } }, {}), /recovery requires exactly/);
  for (const change of [value => { value.execute = true; }, value => { value.limit = 65; }, value => { value.recordings.push(value.recordings[0]); }, value => { value.recordings[0].path = 'untrusted'; }]) {
    const bad = structuredClone(f.request); change(bad); await assert.rejects(f.invoke(bad), /fields|budget|duplicate/);
  }
  assert.equal(f.reports(), 0);
});
test('cancellation after the worker reply leaves no saved observation report', async t => {
  const f = await host(t), original = f.analysis.observeNative;
  f.analysis.observeNative = async (...args) => { const result = await original(...args); f.mgr.checkCancelled = () => { throw Object.assign(Error('cancelled'), { code: 'ABORT_ERR' }); }; return result; };
  await assert.rejects(f.invoke(), error => error.code === 'ABORT_ERR'); assert.equal(f.reports(), 0);
});
test('host rejects corrupted worker scope, source identity, pagination, instruction and memory observations before save', async t => {
  const f = await host(t), original = f.analysis.observeNative;
  const changes = [value => { value.businessAccepted = true; }, value => { value.windows[0].reportSha256 = '0'.repeat(64); },
    value => { value.pagination.returned = 1; }, value => { value.stopGroups[0].groupIndex = 99; },
    value => { value.stopGroups[0].instructions[0].bytes = 'cc'; }, value => { value.stopGroups[0].memoryReads[0].littleEndianHex = '00000000'; }];
  for (const change of changes) {
    f.analysis.observeNative = async (...args) => { const value = await original(...args); change(value); return value; };
    await assert.rejects(f.invoke(), /differs|shape/); assert.equal(f.reports(), 0);
  }
});
