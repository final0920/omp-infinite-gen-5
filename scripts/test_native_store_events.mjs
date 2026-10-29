// Sidecar/storage/worker tests over synthetic data, never target execution.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { readNativeStoreEvents } from '../source/native_store_events.js';
import { analyzeVmObservations } from '../source/vm_observations.js';
import { saveDebugTrace } from '../source/debug_trace.js';
import { runRecoveryProfile } from '../source/vm_recovery_profile.js';
import { createAnalysisService } from '../analysis_tools.js';
import { storeEventCase } from './fixtures/vm_store_event_cases.mjs';
import { observationHash as hash, observationTarget as target } from './fixtures/vm_observation_cases.mjs';
const decode = (event, f = storeEventCase()) => readNativeStoreEvents(Buffer.from(JSON.stringify(event)), f.window.summary, f.window.data);
test('sidecar binds actual stop identities, trace bytes and decoder enumeration without causal write proof', () => {
  const f = storeEventCase(), value = decode(f.event, f);
  assert.equal(value.events[0].stores[0].afterHex, '8877665544332211'); assert.equal(value.cpuWriteFootprintProved, false);
  const result = analyzeVmObservations({ targetSha256: target, windows: [f.window] });
  const write = result.stopGroups[0].memoryWrites;
  assert.equal(write.status, 'decoded-locations-observed-across-stop'); assert.equal(write.actualWriteCausalityProved, false);
  assert.equal(write.cpuWriteFootprintProved, false); assert.equal(write.pauseIdentityMatched, true);
  assert.deepEqual(write.stores, f.event.events[0].stores); assert.equal(result.windows[0].memoryEpoch, null);
  assert.equal(result.stopGroups[1].memoryWrites.stores.length, 0);
  assert.equal(result.totals.evidenceBytes, f.window.data.length + f.window.storeEventData.length);
});
test('missing followup and changed pause stay unknown rather than becoming zero or unchanged bytes', () => {
  for (const status of ['unavailable', 'deadline', 'pause-changed']) {
    const f = storeEventCase(), event = f.event.events[0];
    Object.assign(event.stores[0], { afterHex: null, changed: null, status }); event.completeDecodedStoreSet = false;
    if (status === 'pause-changed') event.pauseIdentityMatched = false;
    assert.equal(decode(f.event, f).events[0].stores[0].afterHex, null);
  }
});
test('identity, scope, event count, addresses and false completeness are rejected', () => {
  const mutations = [e => { e.runId = '2'.repeat(32); }, e => { e.threadId++; }, e => { e.traceSha256 = '0'.repeat(64); },
    e => { e.cpuWriteFootprintProved = true; }, e => { e.storeOrder = 'actual-write-order'; }, e => { e.events.pop(); },
    e => { e.events[0].pc = '0x1001'; }, e => { e.events[0].afterStopSeq++; }, e => { e.events[0].actualWriteCausalityProved = true; },
    e => { e.events[0].stores[0].address = '0xffffffffffffffff'; }, e => { e.events[0].stores[0].changed = false; },
    e => { e.events[0].stores[0].afterHex = null; }, e => { e.events[0].completeDecodedStoreSet = false; },
    e => { e.events[0].pauseIdentityMatched = false; }, e => { e.businessAccepted = true; }];
  for (const mutate of mutations) { const f = storeEventCase(); mutate(f.event); assert.throws(() => decode(f.event, f), error => error.code === 'INVALID_VM_OBSERVATION'); }
});
test('duplicate fields, pretty JSON and a combined input over 1 MiB are refused', () => {
  const f = storeEventCase();
  for (const value of [JSON.stringify(f.event, null, 2), JSON.stringify(f.event).replace('"threadId":7', '"threadId":1,"threadId":7')])
    assert.throws(() => readNativeStoreEvents(Buffer.from(value), f.window.summary, f.window.data), /encoding/);
  assert.throws(() => readNativeStoreEvents(Buffer.alloc(1024*1024), f.window.summary, f.window.data), /1 MiB/);
});
test('paging cannot hide a corrupted later sidecar event', () => {
  const f = storeEventCase(); f.event.events[1].completeDecodedStoreSet = false;
  f.window.storeEventData = Buffer.from(JSON.stringify(f.event)); f.window.source.storeEvents.sha256 = hash(f.window.storeEventData);
  f.window.source.storeEvents.bytes = f.window.storeEventData.length;
  assert.throws(() => analyzeVmObservations({ targetSha256: target, windows: [f.window], limit: 1 }), /completeness/);
});

async function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-store-events-'));
  const cfg = { artifactDir: root, projectRoot: root }, analysis = createAnalysisService({}, cfg);
  const mgr = { analysis, checkCancelled() {} }, session = { target: path.join(root, 'synthetic-not-executed.exe'), sha256: target };
  t.after(async () => { await analysis.dispose(); assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir()));
    assert.match(path.basename(root), /^ig5-store-events-/); assert.equal(fs.lstatSync(root).isSymbolicLink(), false); fs.rmSync(root, { recursive: true, force: true }); });
  const save = (value = storeEventCase().native, params = { record_events: true }) => saveDebugTrace(cfg, session, value, params);
  const observe = (saved, extra = {}) => runRecoveryProfile(mgr, { recovery: { observations: { recordings: [{ id: saved.traceReportId, sha256: saved.traceReportSha256 }], target_sha256: target, ...extra } } }, cfg);
  return { root, cfg, analysis, mgr, save, observe };
}
test('host saves sidecar blobs then the worker imports the exact same recorded store bytes', async t => {
  const f = await fixture(t), saved = await f.save(), { observations: result } = await f.observe(saved);
  const original = JSON.parse(fs.readFileSync(saved.traceReportPath));
  assert.equal(original.result.storeEvents.actualWriteCausalityProved, false); assert.equal(original.result.storeEvents.groups, 2);
  assert.equal(result.stopGroups[0].memoryWrites.stores[0].beforeHex, '0807060504030201');
  assert.equal(hash(fs.readFileSync(result.reportPath)), result.reportSha256);
  assert.equal(result.nativeTargetExecutedByThisRequest, false); assert.equal(result.businessAccepted, false);
});
test('save requires the requested sidecar and refuses unrequested, wrong hash and wrong trace bindings', async t => {
  const f = await fixture(t), native = storeEventCase().native;
  await assert.rejects(f.save(native, {}), /Unrequested/);
  const missing = structuredClone(native); delete missing.storeEventData; await assert.rejects(f.save(missing), /missing/);
  const hashChanged = structuredClone(native); hashChanged.storeEventSummary.sha256 = '0'.repeat(64); await assert.rejects(f.save(hashChanged), /digest/);
  const changed = storeEventCase(); changed.event.traceSha256 = '0'.repeat(64); changed.native.storeEventData = JSON.stringify(changed.event);
  changed.native.storeEventSummary.sha256 = hash(Buffer.from(changed.native.storeEventData));
  await assert.rejects(f.save(changed.native), /identity/);
});
test('corrupted committed event blob prevents observation output even for page zero', async t => {
  const f = await fixture(t), saved = await f.save();
  const blob = path.join(f.root, 'debug-traces', 'blobs', saved.storeEvents.sha256 + '.bin');
  const before = fs.readdirSync(path.join(f.analysis.artifacts.root, 'records')).length;
  fs.appendFileSync(blob, ' '); await assert.rejects(f.observe(saved, { limit: 1 }), /hash/);
  assert.equal(fs.readdirSync(path.join(f.analysis.artifacts.root, 'records')).length, before);
});
test('host refuses a worker that drops or changes a source-bound store observation', async t => {
  const f = await fixture(t), saved = await f.save(), original = f.analysis.observeNative;
  for (const mutate of [r => { r.stopGroups[0].memoryWrites.stores[0].afterHex = '00'.repeat(8); }, r => { delete r.totals.storeEventBytes; }, r => { delete r.windows[0].storeEvents; }]) {
    f.analysis.observeNative = async (...args) => { const result = await original(...args); mutate(result); return result; };
    await assert.rejects(f.observe(saved), /differs/);
  }
});
