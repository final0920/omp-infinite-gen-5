import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeVmPhases, validatePhaseModel } from '../source/vm_phase_model.js';
import { createCodeEpochMap, requireObservedCodeVersion } from '../source/code_epoch_map.js';
import { AnalysisJobs } from '../source/analysis_jobs.js';
import { observationWindow, replaceObservationRows, observationTarget as target, observationHash as hash } from './fixtures/vm_observation_cases.mjs';
import { storeEventCase } from './fixtures/vm_store_event_cases.mjs';

const run = (windows, extra = {}) => analyzeVmPhases({ targetSha256: target, windows, ...extra });
test('point versions preserve scope and never prove stable intervals or inherit epochs across a stop', () => {
  const window = observationWindow({ count: 3, changeCode: true }), result = run([window]);
  assert(validatePhaseModel(result, [window]));
  assert.equal(result.phaseModel.counts.codeChangeGroups, 2);
  assert.equal(result.phaseModel.codeEpochs.observationEpoch, 2);
  const versions = result.phaseModel.groups.map(g => g.versions[0]);
  assert.equal(versions[0].version.contentSha256, versions[2].version.contentSha256);
  assert.notEqual(versions[0].version.id, versions[2].version.id);
  assert(requireObservedCodeVersion(versions[0].version, versions[0].version));
  assert.throws(() => requireObservedCodeVersion(versions[2].version, versions[0].version), { code: 'CODE_VERSION_MISMATCH' });
  for (const point of versions) { assert.equal(point.relation.intervalStable, 'unknown'); assert.equal(point.version.globalMemoryEpoch, null); }
  assert(result.phaseModel.groups.every(g => g.phase === 'unknown' && g.verifiedPhase === null));
});

test('content changes detect overlapping byte ranges and width changes; tracker overflow retains unknown', () => {
  const map = createCodeEpochMap();
  const version = (pc, bytes, id) => ({ id, binding: { pc, bytes } });
  map.observe(version('0x1000', '90cc', 'a'));
  const overlap = map.observe(version('0x1001', '9090', 'b'));
  assert.equal(overlap.changedBytes[0].before, 'cc'); assert.equal(overlap.changedBytes[0].address, '0x1001');
  assert.equal(map.overlap('0x1001', 2).previouslyObservedCodeBytes, 2);
  for (let n = 0; n < 16385; n++) map.observe(version('0x' + (0x2000 + n).toString(16), '90', String(n)));
  assert.equal(map.status().trackingComplete, false); assert.equal(map.status().changeCountIsLowerBound, true);
  assert.throws(() => map.observe(version('0xffffffffffffffff', '9090', 'x')), { code: 'CODE_VERSION_MISMATCH' });
});

test('temporal setup prefix, repeated-control and code-write fixture remain distinct observations, never VM role proof', () => {
  const f = storeEventCase();
  const original = observationWindow({ count: 4 });
  const window = replaceObservationRows(original, text => text.replace('i:0x1002:1:90', 'i:0x1001:1:90').replace('i:0x1003:1:90', 'i:0x1001:1:cc'));
  window.summary.exit = '0x1001';
  f.event.runId = window.summary.runId;
  f.event.startStopSeq = 1; f.event.endStopSeq = 5; f.event.traceSha256 = window.summary.sha256;
  const template = f.event.events[0];
  f.event.events = Array.from({ length: 4 }, (_, n) => ({ ...structuredClone(template), groupIndex: n, pc: n ? '0x1001' : '0x1000', beforeStopSeq: n + 1, afterStopSeq: n + 2,
    stores: n === 2 ? [{ address: '0x1001', bytes: 1, beforeHex: '90', afterHex: 'cc', changed: true, status: 'observed' }] : [] }));
  window.storeEventData = Buffer.from(JSON.stringify(f.event)); window.source.storeEvents = { sha256: hash(window.storeEventData), bytes: window.storeEventData.length };
  const result = run([window]), rows = result.phaseModel.groups;
  assert.equal(rows[0].events.controlVisit, 'first-observed'); assert.equal(rows[2].events.controlVisit, 'revisited');
  assert.equal(rows[2].events.memoryChanges[0].codeOverlap.previouslyObservedCodeBytes, 1);
  assert.equal(rows[3].candidate, 'observed-code-change'); assert.equal(rows[3].versions[0].relation.observationEpoch, 1);
  const link = rows[3].versions[0].relation.storeObservations[0];
  assert.equal(link.source.groupIndex, 2); assert.equal(link.source.storeBlobSha256, window.source.storeEvents.sha256);
  assert.equal(link.priorCodeVersionId, rows[2].versions[0].version.id);
  assert.equal(link.nextCodeVersionId, rows[3].versions[0].version.id);
  assert.equal(link.beforeMatches, true); assert.equal(link.afterMatches, true);
  assert.equal(link.actualWriteCausalityProved, false); assert.equal(link.intervalStable, 'unknown');
  assert.deepEqual(run([window], { offset: 3, limit: 1 }).phaseModel.groups[0], rows[3]);
  assert(validatePhaseModel(result, [window]));
  for (const mutate of [r => { r.phaseModel.groups[3].versions[0].relation.storeObservations[0].source.groupIndex = 1; },
    r => { r.phaseModel.codeEpochs.storeTimeline.matchingBytes++; },
    r => { r.phaseModel.groups[0].events.exit = 'verified-function-return'; },
    r => { r.phaseModel.groups[3].versions[0].relation.changedBytes = []; }]) {
    const forged = structuredClone(result); mutate(forged);
    assert.throws(() => validatePhaseModel(forged, [window]), { code: 'INVALID_VM_PHASE_MODEL' });
  }
  assert(rows.every(row => row.dispatch === 'unknown' && row.initialization === 'unknown' && row.business === 'unknown'));
  assert.equal(result.phaseModel.smcCoverageComplete, false);
});

test('store timeline preserves conflicting bytes, overlapping snapshot ambiguity and bounded unknown coverage', () => {
  const map = createCodeEpochMap(), v = (bytes, id) => ({ id, binding: { pc: '0x1000', bytes } });
  map.observe(v('9090', 'old'));
  const group = { groupIndex: 1, pauseSequence: { before: 2, after: 3 }, memoryWrites: { sourceBlobSha256: 'a'.repeat(64),
    stores: [{ address: '0x1000', bytes: 2, beforeHex: '90aa', afterHex: 'ccdd', changed: true }] } };
  const source = { reportId: 'raw', reportSha256: 'b'.repeat(64) }, summary = { sha256: 'c'.repeat(64) };
  map.noteStores(group, source, summary); map.noteStores(group, source, summary);
  const links = map.observe(v('cc90', 'later')).storeObservations;
  assert.equal(links.length, 2); assert.equal(links[0].beforeMatches, true); assert.equal(links[0].afterMatches, true);
  assert.equal(links[1].beforeMatches, false); assert.equal(links[1].afterMatches, false);
  assert(links.every(l => l.ambiguous && l.observationCount === 2 && l.actualWriteCausalityProved === false));
  assert.equal(map.status().storeTimeline.matchingBytes, 1); assert.equal(map.status().storeTimeline.conflictingBytes, 1);
  assert.equal(map.status().storeTimeline.pendingBytes, 0);
  assert.equal(map.observe(v('9090', 'again')).storeObservations.length, 0, 'snapshot must only bind the next observed bytes');
  map.noteStores({ ...group, memoryWrites: { stores: [{ ...group.memoryWrites.stores[0], changed: null }] } }, source, summary);
  assert.equal(map.status().storeTimeline.pendingBytes, 0, 'unavailable snapshots do not become changed writes');
  map.noteStores({ ...group, memoryWrites: { ...group.memoryWrites, stores: [{ ...group.memoryWrites.stores[0], address: '0x2000' }] } }, source, summary);
  assert.equal(map.status().storeTimeline.pendingBytes, 0, 'unobserved code does not acquire a fabricated previous version');
});

test('same bytes and missing store snapshots never mean no write; CPUID continuation keeps no intermediate state', () => {
  const f = storeEventCase(); f.event.events[0].stores[0].afterHex = f.event.events[0].stores[0].beforeHex; f.event.events[0].stores[0].changed = false;
  f.window.storeEventData = Buffer.from(JSON.stringify(f.event)); Object.assign(f.window.source.storeEvents, { sha256: hash(f.window.storeEventData), bytes: f.window.storeEventData.length });
  const result = run([f.window]);
  assert.equal(result.phaseModel.groups[0].events.unchangedByteObservations, 1);
  assert.equal(result.phaseModel.groups[0].events.unchangedBytesProveNoWrite, false);
  const cpuid = run([observationWindow({ cpuid: true })]);
  assert.equal(cpuid.phaseModel.groups[0].intermediateStateAvailable, false);
  assert.equal(cpuid.phaseModel.groups[0].versions[1].version.binding.beforeStateAvailable, false);
});

test('whole-input validation precedes publishing a page and page identities are deterministic', () => {
  const window = observationWindow({ count: 5 }); const whole = run([window]), paged = run([window], { offset: 3, limit: 1 });
  assert.deepEqual(paged.phaseModel.groups[0], whole.phaseModel.groups[3]);
  const broken = replaceObservationRows(window, text => text + 'bad\n'); assert.throws(() => run([broken], { limit: 1 }), /after final/);
  const forged = structuredClone(whole); forged.phaseModel.groups[0].versions[0].version.binding.reportSha256 = 'f'.repeat(64);
  assert.throws(() => validatePhaseModel(forged, [window]), { code: 'CODE_VERSION_MISMATCH' });
  const promoted = structuredClone(whole); promoted.phaseModel.groups[0].dispatch = 'verified';
  assert.throws(() => validatePhaseModel(promoted, [window]), { code: 'INVALID_VM_PHASE_MODEL' });
});

test('bounded original data worker executes the optional model and preserves cancellation', async t => {
  const jobs = new AnalysisJobs(); t.after(() => jobs.dispose());
  const request = { targetSha256: target, windows: [observationWindow({ count: 5 })], phaseModel: true };
  assert.deepEqual(await jobs.run('vm-observations', request), analyzeVmPhases(request));
  const abort = new AbortController(); abort.abort();
  await assert.rejects(jobs.run('vm-observations', request, abort.signal), { code: 'ABORT_ERR' });
});

test('unrecorded control addresses are not counted as new visits after the bound; unavailable writes stay unknown', () => {
  const windows = Array.from({ length: 9 }, (_, n) => observationWindow({ id: n + 1, start: 1 + 512 * n, count: 512, pc: 0x1000 + 512 * n, value: 1 + 512 * n, reads: false }));
  const model = run(windows, { offset: 4096, limit: 1 }).phaseModel;
  assert.equal(model.counts.firstVisits, 4096); assert.equal(model.counts.unindexedVisits, 512);
  assert.equal(model.visitsComplete, false); assert.equal(model.groups[0].candidate, 'unindexed-control-location');
  const f = storeEventCase();
  Object.assign(f.event.events[0].stores[0], { changed: null, afterHex: null, status: 'unavailable' }); f.event.events[0].completeDecodedStoreSet = false;
  f.window.storeEventData = Buffer.from(JSON.stringify(f.event)); Object.assign(f.window.source.storeEvents, { sha256: hash(f.window.storeEventData), bytes: f.window.storeEventData.length });
  const row = run([f.window]).phaseModel.groups[0]; assert.equal(row.events.unknownStores, 1); assert.equal(row.events.memoryChanges.length, 0);
});

test('original bounded worker retains at most 16384 pending code-byte snapshots and marks coverage unknown', async t => {
  // Format-only stress fixture: no CPU instructions are executed or certified.
  const windows = Array.from({ length: 33 }, (_, n) => observationWindow({ id: n + 1, start: n * 512 + 1,
    count: 512, pc: 0x1000 + n * 512, value: n * 512 + 1, reads: false }));
  const last = observationWindow({ id: 34, start: 16897, count: 64, pc: 0x5200, value: 16897, reads: false });
  const { event } = storeEventCase();
  Object.assign(event, { runId: last.summary.runId, startStopSeq: 16897, endStopSeq: 16961, traceSha256: last.summary.sha256 });
  const template = event.events[0];
  event.events = Array.from({ length: 64 }, (_, n) => ({ ...structuredClone(template), groupIndex: n,
    pc: '0x' + (0x5200 + n).toString(16), beforeStopSeq: 16897 + n, afterStopSeq: 16898 + n,
    stores: [{ address: '0x' + (0x1000 + n * 256).toString(16), bytes: 256,
      beforeHex: '90'.repeat(256), afterHex: 'cc'.repeat(256), changed: true, status: 'observed' }] }));
  last.storeEventData = Buffer.from(JSON.stringify(event));
  last.source.storeEvents = { sha256: hash(last.storeEventData), bytes: last.storeEventData.length };
  windows.push(last);
  const jobs = new AnalysisJobs(); t.after(() => jobs.dispose());
  const result = await jobs.runSettled('vm-observations', { targetSha256: target, windows, phaseModel: true, offset: 16896, limit: 1 });
  assert.equal(jobs.active, null); assert.equal(jobs.queue.length, 0);
  assert.equal(result.phaseModel.codeEpochs.trackedBytes, 16384);
  assert.equal(result.phaseModel.codeEpochs.trackingComplete, false);
  assert.equal(result.phaseModel.codeEpochs.changeCountIsLowerBound, true);
  assert.equal(result.phaseModel.codeEpochs.storeTimeline.pendingBytes, 16384);
  assert.equal(result.phaseModel.codeEpochs.storeTimeline.overlappingBytes, 16384);
  assert.equal(result.phaseModel.codeEpochs.storeTimeline.trackingComplete, false);
  assert.equal(result.phaseModel.phaseVerified, false);
  assert(validatePhaseModel(result, windows));
});
