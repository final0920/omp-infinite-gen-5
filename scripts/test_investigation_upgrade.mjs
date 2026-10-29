import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { FailureRecords } from '../source/failure_record.js';
import { capabilityCatalog, readLaunchPolicy } from '../source/capability_catalog.js';
import { investigationBrief } from '../source/investigation_brief.js';
import { loadCases, summarize } from './evals/registry.mjs';

const hash = s => createHash('sha256').update(s).digest('hex');
test('metadata receipts distinguish publication from cleanup without granting retry', () => {
  const failures = new FailureRecords();
  const base = { operation: 'workspace', semanticInputs: { task: 'same' }, error: { code: 'EPERM', message: 'denied', metadataPublished: false, metadataStage: 'publish' } };
  assert.equal(failures.add(base).advice.nextCheck, 'inspect-metadata-publication-failure');
  const committed = failures.add({ ...base, error: { ...base.error, metadataPublished: true, metadataStage: 'lock-release', metadataCleanupConfirmed: false, metadataCleanupError: { code: 'EPERM', stage: 'lock-release' } } });
  assert.equal(committed.advice.nextCheck, 'read-current-metadata-before-retry');
  assert.equal(committed.original.metadataCleanupError.code, 'EPERM');
  assert.equal(committed.advice.executionAuthorized, false);
  assert.equal(failures.add({ ...base, error: { ...base.error, metadataPublished: true, cleanupConfirmed: false } }).advice.nextCheck, 'recover-original-execution-owner');
});
test('failure routing retains receipts and ignores UUID/wording changes supplied outside semantic inputs', () => {
  const failures = new FailureRecords();
  const base = { operation: 'projection', scope: { attachmentId: 'a', dbRevision: 1 }, semanticInputs: { bytes: hash('same-input') }, inputReportHashes: [hash('report')], error: { code: 'MEMORY_GAP', message: 'original failure', cleanupConfirmed: null } };
  const first = failures.add(base);
  const second = failures.add({ ...base, error: { ...base.error, message: 'rephrased failure', reportId: 'new UUID' } });
  assert.equal(second.semanticKey, first.semanticKey);
  assert.equal(second.original.cleanupConfirmed, null);
  assert.equal(second.original.message, 'rephrased failure');
  assert.equal(second.advice.nextCheck, 'design-discriminating-experiment');
  assert.equal(second.advice.cleanupConfirmed, null);
  const retained=failures.add({...base,error:{...base.error,cleanupConfirmed:false}});
  assert.equal(retained.advice.nextCheck,'recover-original-execution-owner');
  assert.notEqual(failures.add({ ...base, scope: { attachmentId: 'b', dbRevision: 1 } }).semanticKey, first.semanticKey);
  assert.equal(failures.add({ ...base, inputReportHashes: [hash('same content in new UUID envelope')] }).semanticKey, first.semanticKey);
  assert.notEqual(failures.add({ ...base, semanticInputs: { bytes: hash('new observation content') } }).semanticKey, first.semanticKey);
  assert.equal(failures.add({ ...base, semanticInputs: null }).comparable, false);
  for (const code of ['RUNTIME_POLICY_BLOCKED','ERUNTIME_POLICY']) {
    const env = failures.add({ ...base, error: { code, message: '4551' } });
    assert.equal(env.advice.category, 'environment');
    assert.equal(env.advice.nextCheck, 'use-offline-evidence-no-native-retry');
  }
});

test('catalog distinguishes file checks, startup, session limits and shared providers without RPC', () => {
  let probes = 0;
  const sessions = new Map([['s', { engine: 'reverse', capabilities: ['decompile'], pending: new Map(), queuedOperations: 0 }]]);
  const mgr = { sessions, alive: () => true, engines: () => [
    { id: 'reverse', provider: 'ghidra', available: true }, { id: 'ghidra', provider: 'ghidra', available: false }, { id: 'x64dbg', available: true }],
    rpc() { probes++; throw new Error('no probe'); }, spawnWorker() { probes++; throw new Error('no launch'); } };
  const result = capabilityCatalog(mgr, {});
  assert.equal(probes, 0);
  assert.equal(result.entries.filter(e => e.operation === 'function-context').map(e => e.provider).join(','), 'ghidra,ghidra');
  assert.equal(result.entries.find(e => e.operation === 'read-bytes' && e.engine === 'reverse').declared, 'unsupported');
  assert.equal(result.entries.find(e => e.operation === 'function-context' && e.engine === 'reverse').startup, 'verified');
  assert.equal(result.entries.find(e => e.engine === 'ghidra').files, 'unknown');
  assert(result.entries.every(e => e.functionalEvidence === 'not-tested'));
  sessions.get('s').queuedOperations=1;
  assert.equal(capabilityCatalog(mgr, {}).entries.find(e => e.engine === 'reverse').session,'busy');
  assert.equal(capabilityCatalog(mgr, {}, {ownQueue:true}).entries.find(e => e.engine === 'reverse').session,'compatible');
  const portable=capabilityCatalog(mgr,{host:{supported:false,id:'unsupported-host'}});
  assert.equal(portable.entries.find(e=>e.operation==='decode-data').declared,'declared');
  assert.equal(portable.entries.find(e=>e.operation==='function-context').declared,'unsupported');
  sessions.get('s').closing = true;
  assert.equal(capabilityCatalog(mgr, {}).entries.find(e => e.engine === 'reverse').session, 'cleanup-pending');
});

test('catalog reads retained application policy without launching, corrupt cache remains unknown', t => {
  if (process.platform !== 'win32') return t.skip('Windows component path contract');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-catalog-'));
  t.after(() => { assert.equal(path.dirname(root), fs.realpathSync(os.tmpdir())); fs.rmSync(root, { recursive: true, force: true }); });
  const component = path.join(root, 'headless.exe'), key = path.win32.resolve(component).toLowerCase();
  const filename = path.join(root, hash(key) + '.json');
  assert.equal(readLaunchPolicy(component, { root }).state, 'no-known-block');
  fs.writeFileSync(filename, JSON.stringify({ schema: 'ig5-runtime-policy-block-v1', component: key, winError: 4551, automaticRetryAllowed: false, recordedAt: new Date().toISOString(), source: 'observed-launch-error', evidence: null }));
  assert.equal(readLaunchPolicy(component, { root }).state, 'blocked');
  fs.writeFileSync(filename, 'broken');
  assert.equal(readLaunchPolicy(component, { root }).state, 'unknown');
});

function briefFixture(count = 1) {
  const scope = { target: 'fixture', projectId: 'p', artifactId: 'a', sha256: hash('fixture'), engine: 'reverse', provider: 'ghidra', attachmentId: 'new', dbRevision: 2 };
  const task = { taskId: 'task', taskRevision: 2, goal: 'Explain the branch', status: 'completed', hypothesis: 'caller hypothesis', conclusion: '', next_step: '', systemEvidence: Array.from({ length: count }, (_, i) => ({ snapshot_id: `snapshot-${i}`, report_id: `report-${i}`, report_sha256: hash(String(i)), function: { ea: '0x140001000' }, stale: i % 2 === 0, staleReasons: i % 2 === 0 ? ['attachment-changed'] : [] })) };
  const opts = { readContext: () => structuredClone(scope), readTask: () => structuredClone(task), readEvidence: () => ({ sections: { decompile: { status: 'partial' } }, responseTruncated: true }), capabilities: { entries: [] } };
  return { scope, task, opts };
}
test('brief paginates all full references, preserves stale and partial status, bounds UTF-8', () => {
  const { opts, task } = briefFixture(64);
  task.goal = '分支'.repeat(2000);
  const seen = new Set(); let cursor; let pages = 0;
  do {
    const result = investigationBrief({ ...opts, maxBytes: 4096, cursor }); pages++;
    assert(Buffer.byteLength(JSON.stringify(result)) <= 4096);
    assert.equal(result.acceptance.status, 'not-assessed');
    assert.equal(result.workStatus, 'completed');
    assert(result.nextExperiments.length <= 3);
    for (const ref of result.evidenceRefs) { assert(!seen.has(ref.snapshotId)); seen.add(ref.snapshotId); assert.equal(ref.sectionStatus.decompile, 'partial'); assert.equal(ref.responseTruncated, true); }
    cursor = result.nextCursor;
  } while (cursor && pages < 64);
  assert.equal(seen.size, 64);
});
test('brief rechecks snapshot once, rejects persistent changes and stale cursors', () => {
  const { opts, task, scope } = briefFixture(20);
  const page = investigationBrief({ ...opts, maxBytes: 4096 });
  task.taskRevision++;
  assert.throws(() => investigationBrief({ ...opts, cursor: page.nextCursor }), { code: 'STALE_SESSION_CONTEXT' });
  let reads = 0;
  const result = investigationBrief({ ...opts, readTask: () => { if (reads++ === 0) return { ...structuredClone(task), taskRevision: 0 }; return structuredClone(task); } });
  assert.equal(result.snapshot.taskRevision, task.taskRevision); assert.equal(reads, 4);
  assert.throws(() => investigationBrief({ ...opts, readContext: () => ({ ...scope, dbRevision: reads++ }) }), { code: 'SNAPSHOT_INCONSISTENT' });
});
test('brief rejects tampered evidence as a fact and preserves its exact reference', () => {
  const { opts } = briefFixture(2);
  const result = investigationBrief({ ...opts, readEvidence: () => { throw Object.assign(new Error('changed'), { code: 'ARTIFACT_CHANGED' }); } });
  assert.equal(result.observations.length, 0);
  assert.equal(result.evidenceRefs[1].failureCode, 'ARTIFACT_CHANGED');
  assert.equal(result.evidenceRefs[1].reportId, 'report-1');
});
test('eval registry includes all 12+8 cases and retains missing/environment failures', () => {
  const cases = loadCases(); assert.equal(cases.length, 20);
  assert.equal(cases.filter(c => c.partition === 'development').length, 12);
  assert.equal(cases.filter(c => c.partition === 'holdout').length, 8);
  const c = cases[0];
  const run = { caseId: c.caseId, variant: 'baseline', repetition: 1, inputSha256: c.input.sha256, budgetDigest: hash(JSON.stringify(c.budget)), model: 'fixed-model', promptSha256: hash('prompt'), cacheCondition: 'cold', answerExposure: 'exposed', status: 'blocked', claimedAccepted: false, independentVerdict: 'unknown', toolCalls: 1, elapsedMs: 2 };
  const result = summarize(cases, [run]);
  assert.equal(result.registeredCases, 20); assert.equal(result.unrunCases.length, 19); assert.equal(result.blockedRuns, 1);
  assert.equal(result.blindRuns, 0); assert.equal(result.acceptedRuns, 0);
  assert.throws(() => summarize(cases, [run, run]));
  assert.throws(() => summarize(cases, [{ ...run, inputSha256: hash('wrong') }]));
});
