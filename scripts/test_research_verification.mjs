import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { Worker } from 'node:worker_threads';
import { AnalysisArtifacts } from '../source/analysis_artifacts.js';
import { AnalysisJobs } from '../source/analysis_jobs.js';
import { runWorkspace } from '../source/investigation_workflow.js';
import { runVmContextProfile } from '../source/vm_context_profile.js';
import { VM_CONTEXT_PROPERTY, vmContextEvidence } from '../source/evidence_adapters/vm_context.js';
import { auditVmContext } from '../source/verifiers/vm_context_audit.js';
import { contextPage } from './fixtures/vm_context_cases.mjs';
import { readInvestigationView } from '../source/investigation_view.js';

const contract = { question: 'Audit observed context candidates', inputDomain: 'The committed model and three typed immediate input kinds',
  returns: 'Not assessed', outputs: 'Candidate derivation only', sideEffects: 'No execution', environment: 'Recorded inputs', exclusions: 'CPU, VM role, business and whole function proof' };
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-verification-')), artifacts = new AnalysisArtifacts(path.join(root, 'data')), jobs = new AnalysisJobs();
  const cfg = { projectRoot: path.join(root, 'projects') }, sha256 = 'a'.repeat(64), target = path.join(root, 'not-executed.exe');
  const context = { target, projectId: `project_${randomUUID()}`, artifactId: `artifact_${sha256}`, sha256, engine: 'reverse', provider: 'ghidra', attachmentId: `attachment_${randomUUID()}`, dbRevision: 0 };
  const session = { engine: 'reverse', target }, mgr = { analysis: { artifacts, jobs }, get: () => session, alive: () => true,
    checkCancelled() {}, evidence: () => ({ ...context }), engines: () => [], sessions: new Map([[target, session]]) };
  const call = (workspace, signal) => runWorkspace(mgr, cfg, { target, workspace }, { agent: { id: 'fixture' }, signal }).workspace;
  // Async actions return the full tool envelope; retain their async semantics.
  const asyncCall = async (workspace, signal) => (await runWorkspace(mgr, cfg, { target, workspace }, { agent: { id: 'fixture' }, signal })).workspace;
  const task = call({ action: 'create', goal: 'Audit context' });
  const get = () => call({ action: 'research-get', id: task.taskId });
  const update = (operation, value, extra = {}) => {
    const before = get();
    return call({ action: 'research-update', id: task.taskId, ...extra, research: { operation, expected_task_revision: before.taskRevision,
      expected_research_revision: before.research?.researchRevision ?? 0, scope_digest: before.scopeDigest, ...(value === undefined ? {} : { value }) } });
  };
  const handlers = [0, 1].map(i => {
    const source = contextPage(i, artifacts), h = artifacts.save({ kind: 'vm-recorded-handlers', action: 'assess', result: source.handlers });
    return { id: h.id, sha256: artifacts.metadata(h.id).result.recordSha256 };
  });
  const model = runVmContextProfile(mgr, { handler_refs: handlers }).context;
  update('initialize', contract);
  const linked = update('link-vm-context', undefined, { report_ref: { id: model.reportId, sha256: model.reportSha256 } });
  const evidence = linked.research.evidenceLinks[0];
  function propose({ property = VM_CONTEXT_PROPERTY, scope = `evidence:${evidence.id}`, verifier = 'vm-context-audit-v1', dependencies = [] } = {}) {
    const result = update('add-obligation', { property, scope, verifier, dependencies });
    return result.research.obligations.at(-1);
  }
  const request = (obligation, experimentId) => {
    const before = get();
    return { expected_task_revision: before.taskRevision, expected_research_revision: before.research.researchRevision, scope_digest: before.scopeDigest,
      evidence_id: evidence.id, obligation_id: obligation.id, ...(experimentId ? { experiment_id: experimentId } : {}) };
  };
  const verify = (obligation, experimentId, signal) => asyncCall({ action: 'research-verify', id: task.taskId, verification: request(obligation, experimentId) }, signal);
  t.after(async () => { await jobs.dispose(); await artifacts.dispose(); assert.equal(path.dirname(root), fs.realpathSync(os.tmpdir())); fs.rmSync(root, { recursive: true, force: true }); });
  return { root, cfg, mgr, context, artifacts, jobs, model, evidence, task, call, asyncCall, get, update, propose, request, verify };
}
test('workbench adapter reads bound task/research snapshots and rejects mutation actions or stale task revisions', t => {
  const f = fixture(t), session = f.mgr.get(f.context.target);
  const list = readInvestigationView(f.mgr, f.cfg, session, { action: 'list' });
  assert.equal(list.tasks[0].taskId, f.task.taskId);
  const before = fs.readdirSync(f.artifacts.directory('records')).length;
  const view = readInvestigationView(f.mgr, f.cfg, session, { action: 'brief', id: f.task.taskId, taskRevision: f.task.taskRevision });
  assert.equal(view.taskId, f.task.taskId); assert.equal(view._ig5.attachmentId,f.context.attachmentId);
  assert.equal(view.snapshot.researchRevision, f.get().research.researchRevision);
  assert.equal(view.acceptance.status,'not-assessed');
  assert.throws(() => readInvestigationView(f.mgr, f.cfg, session, { action: 'brief', id: f.task.taskId, taskRevision: -1 }), /revision changed/);
  for (const action of ['create','update','research-update','research-verify','plan','resume'])
    assert.throws(() => readInvestigationView(f.mgr, f.cfg, session, { action }), /list\/brief only/);
  assert.equal(fs.readdirSync(f.artifacts.directory('records')).length,before);
});
test('independent worker agrees with Python audit and closes only the scoped derivation obligation', async t => {
  const f = fixture(t), obligation = f.propose(), business = f.propose({ property: 'whole-function-business', scope: 'all inputs' });
  const experiment = f.update('add-experiment', { template: 'review-evidence', question: 'Recompute context candidates', inputs: [f.evidence.id], hypotheses: [], obligations: [obligation.id],
    budget: { toolCalls: 1, timeoutMs: 15000, bytes: 8 * 1024 ** 2 }, predictedDivergence: 'Incorrect counters or candidate bindings fail independently' }).research.experiments[0];
  const result = await f.verify(obligation, experiment.id);
  assert.equal(result.status, 'pass'); assert.equal(result.linked, true); assert.equal(result.dataWorkerCleanupConfirmed, true);
  assert.equal(f.jobs.active, null);
  const view = f.get().research;
  assert.equal(view.objectStates.obligations.find(o => o.id === obligation.id).status, 'closed-in-scope');
  assert.equal(view.objectStates.obligations.find(o => o.id === business.id).status, 'open');
  assert.equal(view.acceptanceStatus, 'partial'); assert.equal(view.workStatus, 'active'); assert.equal(view.resourceStatus, 'retained-unknown');
  assert.equal(view.objectStates.experiments[0].resultRefs[0].reportId, result.reportId);
  const full = f.call({ action: 'research-verification', id: f.task.taskId, verification_id: result.reportId }).result;
  assert.equal(full.inputRefs.length, 7); assert.equal(full.outcome.coverage.occurrences, 16);
  assert.equal(full.outcome.coverage.unknownGprs, 6); assert.equal(full.outcome.coverage.unknownStores, 12);
  assert.equal(full.sharedDependencies.sharedDerivationCode, false); assert.equal(full.businessAccepted, false);
  const brief = f.call({ action: 'brief', id: f.task.taskId, max_bytes: 4096 });
  assert.equal(brief.acceptance.status, 'partial'); assert.equal(brief.research.verification.closedInScope, 1);
  assert(Buffer.byteLength(JSON.stringify(brief)) <= 4096);
  const python = spawnSync(path.resolve('runtimes/ghidra/python/python.exe'), ['-I', '-B', 'scripts/verify_vm_context_model.py', f.model.reportPath, f.model.reportSha256], { encoding: 'utf8' });
  assert.equal(python.status, 0, python.stderr); assert.equal(JSON.parse(python.stdout).occurrences, full.outcome.coverage.occurrences);
});
test('VM evidence is byte-bound across database changes; source kind/path/SHA changes are refused', t => {
  const f = fixture(t);
  f.context.dbRevision++; f.context.attachmentId = `attachment_${randomUUID()}`;
  const view = f.get(); assert.equal(view.evidence[0].stale, false); assert(view.research.stale);
  const original = f.artifacts.get(f.model.reportId);
  const badPath = structuredClone(original.result); badPath.sourceReports[0].selection.path = path.join(f.root, 'outside.json');
  const bad = f.artifacts.save({ kind: 'vm-context-model', action: 'derive', result: badPath });
  assert.throws(() => vmContextEvidence(f.artifacts, f.task, { id: bad.id, sha256: f.artifacts.metadata(bad.id).result.recordSha256 }), { code: 'ARTIFACT_CHANGED' });
  assert.throws(() => vmContextEvidence(f.artifacts, f.task, { id: f.model.reportId, sha256: 'f'.repeat(64) }), { code: 'ARTIFACT_CHANGED' });
  assert.throws(() => f.update('link-vm-context', undefined, { report_ref: { path: 'C:/anything', sha256: 'a'.repeat(64) } }), { code: 'INVALID_RESEARCH_REF' });
});
test('new report UUIDs with the same candidate and typed parents do not create duplicate planner work', t => {
  const f = fixture(t), first = f.propose();
  const clone = f.artifacts.save({ kind: 'vm-context-model', action: 'derive', result: f.artifacts.get(f.model.reportId).result });
  const linked = f.update('link-vm-context', undefined, { report_ref: { id: clone.id, sha256: f.artifacts.metadata(clone.id).result.recordSha256 } });
  const alias = linked.research.evidenceLinks.at(-1);
  f.update('add-obligation', { property: VM_CONTEXT_PROPERTY, scope: `evidence:${alias.id}`, verifier: 'vm-context-audit-v1', dependencies: [] });
  const read = f.get();
  assert.equal(read.evidence[0].candidateInputDigest, read.evidence[1].candidateInputDigest);
  const plan = f.call({ action: 'plan', id: f.task.taskId });
  assert.equal(plan.candidates.filter(c => c.kind === 'verify-scoped-candidate').length, 1);
  assert(plan.deferred.some(d => d.reason === 'equivalent-candidate-input-already-covered'));
  assert.equal(f.get().research.objectStates.obligations.find(o => o.id === first.id).status, 'open');
});
test('changed candidate counts, VSP ranking, dictionary or proof boundaries fail independent recomputation', t => {
  const f = fixture(t), original = f.artifacts.get(f.model.reportId);
  for (const mutate of [m => m.roles.vipCandidates[0].observations++, m => m.roles.vspCandidates[0].nearbyAccesses++,
    m => m.observedHandlerDictionary[0].matchedFinalGprs--, m => m.businessAccepted = true,
    m => m.phases.initialization.status = 'proved']) {
    const model = structuredClone(original.result); mutate(model);
    const saved = f.artifacts.save({ kind: 'vm-context-model', action: 'derive', result: model });
    const loaded = vmContextEvidence(f.artifacts, f.task, { id: saved.id, sha256: f.artifacts.metadata(saved.id).result.recordSha256 });
    const result = auditVmContext(loaded.request);
    assert.equal(result.status, 'fail'); assert(result.witness.reason);
  }
});
test('unsupported property or scope and unresolved dependencies cannot run a hidden execution channel', async t => {
  const f = fixture(t), business = f.propose({ property: 'VM role recovered' }), wrongScope = f.propose({ scope: 'entire business' });
  const dependent = f.propose({ dependencies: [business.id] });
  f.jobs.runSettled = () => { throw Error('No worker allowed for an unsupported obligation'); };
  assert.equal((await f.verify(business)).status, 'unsupported');
  assert.equal((await f.verify(wrongScope)).status, 'unsupported');
  assert.equal((await f.verify(dependent)).status, 'unknown');
  assert.deepEqual(f.get().research.objectStates.obligations.map(o=>o.status),['open','open','blocked']);
  const bad = { ...f.request(dependent), command: 'arbitrary command' };
  assert.throws(() => f.call({ action: 'research-verify', id: f.task.taskId, verification: bad }), { code: 'INVALID_VERIFICATION' });
});
test('a concurrent research update keeps a recoverable result and linking never reruns the worker', async t => {
  const f = fixture(t), obligation = f.propose(), realRun = f.jobs.runSettled.bind(f.jobs);
  f.jobs.runSettled = async (...args) => {
    const result = await realRun(...args);
    f.update('add-hypothesis', { proposition: 'Concurrent note', supporting: [], opposing: [], competingExplanations: [] });
    return result;
  };
  const orphan = await f.verify(obligation);
  assert.equal(orphan.status, 'pass'); assert.equal(orphan.linked, false); assert.equal(orphan.reportSaved, true); assert.equal(orphan.code, 'STALE_RESEARCH_REVISION');
  f.jobs.runSettled = () => { throw Error('Recovery must not rerun'); };
  const recovered = await f.asyncCall({ action: 'research-link-verification', id: f.task.taskId,
    verification: f.request(obligation), report_ref: { id: orphan.reportId, sha256: orphan.reportSha256 } });
  assert.equal(recovered.linked, true); assert.equal(recovered.status, 'pass');
  assert.equal(f.get().research.objectStates.obligations[0].status, 'closed-in-scope');
});
test('parent corruption and changed contracts invalidate current acceptance without erasing results', async t => {
  const f = fixture(t), obligation = f.propose(), result = await f.verify(obligation);
  assert.equal(result.status, 'pass');
  const parent = f.evidence.parents[0], filename = path.join(f.artifacts.directory('records'), parent.id + '.json'), original = fs.readFileSync(filename);
  fs.appendFileSync(filename, ' ');
  assert.equal(f.get().evidence[0].integrity, 'unverified');
  assert.equal(f.get().research.objectStates.obligations[0].status, 'open');
  assert.equal(f.get().research.acceptanceStatus, 'unknown');
  fs.writeFileSync(filename, original);
  assert.equal(f.get().research.acceptanceStatus, 'partial');
  f.update('set-contract', { ...contract, inputDomain: 'Changed input domain' });
  assert.equal(f.get().research.acceptanceStatus, 'unknown');
  f.update('set-contract', contract);
  assert.equal(f.get().research.objectStates.obligations[0].staleContract, true);
  const historical = f.call({ action: 'research-verification', id: f.task.taskId, verification_id: result.reportId });
  assert.equal(historical.currentAssessment.status, 'stale-or-unverified'); assert.equal(historical.result.status, 'pass');
  assert(fs.existsSync(path.join(f.artifacts.directory('records'), result.reportId + '.json')));
});
test('smaller experiment budgets and foreign runtime receipts remain unsupported or unverified', async t => {
  const f = fixture(t), obligation = f.propose();
  const experiment = f.update('add-experiment', { template: 'review-evidence', question: 'Too small budget', inputs: [f.evidence.id], hypotheses: [], obligations: [obligation.id],
    budget: { toolCalls: 1, timeoutMs: 1, bytes: 1 }, predictedDivergence: 'Must request an explicit budget revision' }).research.experiments[0];
  const unsupported = await f.verify(obligation, experiment.id);
  assert.equal(unsupported.status, 'unsupported'); assert.equal(unsupported.dataWorkerCleanupConfirmed, null);
  const valid = await f.verify(obligation), result = f.artifacts.get(valid.reportId).result;
  const forged = f.artifacts.save({ kind: 'research-verification', action: 'verify', result: { ...result, runtimeDigest: 'b'.repeat(64) } });
  await assert.rejects(f.asyncCall({ action: 'research-link-verification', id: f.task.taskId, verification: f.request(obligation),
    report_ref: { id: forged.id, sha256: f.artifacts.metadata(forged.id).result.recordSha256 } }), { code: 'VERIFIER_IDENTITY_CHANGED' });
});
test('cancellation stops the owned data worker and does not publish a pass', async t => {
  const f = fixture(t), obligation = f.propose(), controller = new AbortController();
  controller.abort();
  await assert.rejects(f.verify(obligation, undefined, controller.signal), { code: 'ABORT_ERR' });
  assert.equal(f.get().research.verificationRefs.length, 0);
  assert.equal(f.jobs.active, null);
  const request = vmContextEvidence(f.artifacts, f.task, { id: f.model.reportId, sha256: f.model.reportSha256 }).request;
  const active = new AbortController(), promise = f.jobs.runSettled('vm-context-audit', request, active.signal);
  active.abort(); await assert.rejects(promise, { code: 'ABORT_ERR' }); assert.equal(f.jobs.active, null);
});
test('partial report publication distinguishes record bytes from committed metadata and preserves recoverable receipts', async t => {
  const f = fixture(t), obligation = f.propose(), originalWrite = fs.writeFileSync;
  const metadataDirectory = f.artifacts.directory('metadata') + path.sep;
  fs.writeFileSync = function (filename, ...args) {
    if (typeof filename === 'string' && filename.startsWith(metadataDirectory) && filename.endsWith('.partial')) throw Object.assign(Error('fixture metadata unavailable'), { code: 'EACCES' });
    return originalWrite.call(this, filename, ...args);
  };
  let partial;
  try { partial = await f.verify(obligation); } finally { fs.writeFileSync = originalWrite; }
  assert.equal(partial.status, 'error'); assert.equal(partial.verifierStatus, 'pass');
  assert.equal(partial.recordSaved, true); assert.equal(partial.reportSaved, false); assert.equal(partial.linked, false);
  assert(fs.existsSync(path.join(f.artifacts.directory('records'), partial.reportId + '.json')));
  assert.equal(f.get().research.verificationRefs.length, 0);
  const saved = f.artifacts.historyIndex.saved;
  f.artifacts.historyIndex.saved = () => { throw Object.assign(Error('fixture index unavailable'), { code: 'EINDEX' }); };
  let indexed;
  try { indexed = await f.verify(obligation); } finally { f.artifacts.historyIndex.saved = saved; }
  assert.equal(indexed.reportSaved, true); assert.equal(indexed.linked, false); assert.equal(indexed.code, 'EINDEX');
  const recovered = await f.asyncCall({ action: 'research-link-verification', id: f.task.taskId, verification: f.request(obligation),
    report_ref: { id: indexed.reportId, sha256: indexed.reportSha256 } });
  assert.equal(recovered.linked, true); assert.equal(recovered.status, 'pass');
});
test('data-worker time and queue budgets are retained; failed cleanup cannot certify completion', async t => {
  const f = fixture(t), request = vmContextEvidence(f.artifacts, f.task, { id: f.model.reportId, sha256: f.model.reportSha256 }).request;
  const timed = new AnalysisJobs({ timeoutMs: 1 });
  await assert.rejects(timed.runSettled('vm-context-audit', request), { code: 'TIMEOUT' }); assert.equal(timed.active, null); await timed.dispose();
  const queued = new AnalysisJobs(), pending = Array.from({ length: 5 }, () => queued.runSettled('vm-context-audit', request));
  assert.equal(queued.queue.length, 4);
  await assert.rejects(queued.runSettled('vm-context-audit', request), { code: 'BUSY' });
  await Promise.all(pending); assert.equal(queued.active, null); await queued.dispose();
  const originalTerminate = Worker.prototype.terminate;
  // Really terminate the test worker, then simulate a missing confirmation receipt.
  Worker.prototype.terminate = function () { return originalTerminate.call(this).then(() => { throw Error('missing cleanup receipt'); }); };
  const broken = new AnalysisJobs();
  try {
    await assert.rejects(broken.runSettled('vm-context-audit', request), { code: 'WORKER_CLEANUP_FAILED', cleanupConfirmed: false });
    assert.equal(broken.closed, true); assert.equal(broken.active.retained, true);
    await assert.rejects(broken.runSettled('vm-context-audit', request), { code: 'DISPOSED' });
  } finally { Worker.prototype.terminate = originalTerminate; await broken.dispose().catch(() => {}); }
});
