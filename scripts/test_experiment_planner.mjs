import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { planExperiments } from '../source/experiment_planner.js';
import { planningDigest, planningRequestKey } from '../source/planning_identity.js';
import { investigationPlan } from '../source/investigation_planning.js';
import { FailureRecords } from '../source/failure_record.js';
import { AnalysisArtifacts } from '../source/analysis_artifacts.js';
import { DelegationControl } from '../source/delegation_control.js';

const id = n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const sha = n => String(n).repeat(64);
function freeze(v) { if (v && typeof v === 'object') { Object.values(v).forEach(freeze); Object.freeze(v); } return v; }
function fixture() {
  const scope = { projectId: 'project_' + id(1), artifactId: 'artifact_' + sha('a'), sha256: sha('a'), engine: 'reverse', provider: 'ghidra' };
  const context = { ...scope, attachmentId: 'attachment_' + id(2), dbRevision: 2, target: 'fixture.exe' };
  const task = { taskId: id(3), taskRevision: 2, scope, status: 'active', goal: 'Explain this function', hypothesis: '', conclusion: '', next_step: '', systemEvidence: [
    { snapshot_id: id(4), report_id: id(5), report_sha256: sha('b'), function: { ea: '0x1000' }, stale: true },
    { snapshot_id: id(6), report_id: id(7), report_sha256: sha('c'), function: { ea: '0x2000' }, stale: false },
  ] };
  return { context, task, research: null, evidence: [], capabilities: { entries: [{ operation: 'function-context', engine: 'reverse', provider: 'ghidra', declared: 'declared',
    files: 'present', startup: 'verified', session: 'compatible', policy: 'unknown', runtimeDigest: sha('d') }] },
    resources: { static: { state: 'compatible' }, data: { state: 'compatible', timeoutMs: 15000 } }, failures: [], failureHistoryError: null,
    budgets: { publicToolCalls: 3, inputBytes: 8 * 1024 ** 2 }, history: { scope: 'fixture', completeHistory: false }, sharedBudget: { status: 'read', active: false, remaining: null } };
}
function withResearch() {
  const f = fixture(); f.task.systemEvidence = [];
  f.research = { taskId: f.task.taskId, scope: f.task.scope, scopeDigest: planningDigest(f.task.scope), researchRevision: 5, contractRevision: 0, stale: false,
    hypotheses: [{ id: id(8), contractRevision: 0, value: { proposition: 'H1', supporting: [], opposing: [], competingExplanations: ['H2'] } }],
    obligations: [{ id: id(10), contractRevision: 0, value: { property: 'vm-context-candidate-derivation-and-provenance', scope: 'evidence:' + id(9), verifier: 'vm-context-audit-v1', dependencies: [] } },
      { id: id(11), contractRevision: 0, value: { property: 'whole business', scope: 'whole domain', verifier: 'not-registered', dependencies: [id(10)] } }],
    evidenceLinks: [{ id: id(9), kind: 'vm-context-model', reportId: id(12), sha256: sha('e'), contractRevision: 0 }], experiments: [],
    objectStates: { hypotheses: [{ id: id(8), status: 'proposed', staleContract: false }], obligations: [{ id: id(10), status: 'open', staleContract: false }, { id: id(11), status: 'open', staleContract: false }], experiments: [] } };
  f.evidence = [{ id: id(9), integrity: 'verified', stale: false, inputBytes: 512, candidateInputDigest: sha('f') }];
  return f;
}
test('planner is deterministic and pure; source-bound stale refresh precedes reuse and never executes', () => {
  const f = freeze(fixture()), original = JSON.stringify(f), a = planExperiments(f), b = planExperiments(f);
  assert.deepEqual(a, b); assert.equal(JSON.stringify(f), original);
  assert.deepEqual(a.candidates.map(c => c.kind), ['refresh-stale-dossier', 'read-complete-evidence']);
  assert.equal(a.candidates[0].request.ea, '0x1000'); assert.equal(a.candidates[0].request.task_id, f.task.taskId);
  assert(a.candidates.every(c => c.executionAuthorized === false)); assert.equal(a.taskModified, false);
});
test('native blocked, unverified, busy and foreign identities never yield a compute draft', () => {
  for (const mutate of [f => f.capabilities.entries[0].policy = 'blocked', f => f.capabilities.entries[0].declared = 'unsupported',
    f => f.capabilities.entries[0].files = 'unknown', f => f.capabilities.entries[0].startup = 'not-probed',
    f => f.resources.static.state = 'cleanup-pending', f => f.capabilities.entries[0].session = 'busy']) {
    const f = fixture(); mutate(f); const result = planExperiments(f);
    assert(!result.candidates.some(c => c.request?.tool === 'ig5_decompile')); assert(result.deferredCount > 0);
    assert(result.candidates.some(c => c.kind === 'read-complete-evidence'));
  }
  const foreign = fixture(); foreign.task.scope = { ...foreign.task.scope, sha256: sha('f') };
  assert.equal(planExperiments(foreign).candidates.length, 0);
});
test('known identical failure is suppressed across task association and argument formatting; changed scope/input/runtime is distinct', () => {
  const f = fixture(), request = planExperiments(f).candidates[0].request;
  const key = planningRequestKey(request, f.context);
  assert.equal(key, planningRequestKey({ ...request, ea: '0X00001000', task_id: id(999), dossier_max_bytes: 16000, dossier_max_rows: 32 }, f.context));
  f.failures = [{ operation: 'ig5_decompile', planningKey: key, runtimeDigest: sha('d'), historical: false, advice: { nextCheck: 'diagnose', occurrences: 1 } }];
  assert(!planExperiments(f).candidates.some(c => c.kind === 'refresh-stale-dossier'));
  assert(planExperiments(f).deferred.some(d => d.reason === 'unchanged-failed-request'));
  f.capabilities.entries[0].runtimeDigest = sha('e');
  assert(planExperiments(f).candidates.some(c => c.kind === 'refresh-stale-dossier'));
  assert.notEqual(key, planningRequestKey({ ...request, ea: '0x1001' }, f.context));
  assert.notEqual(key, planningRequestKey(request, { ...f.context, dbRevision: 3 }));
});
test('failure-history read errors fail closed for compute; resource holds retain owner and allow independent offline work', () => {
  const f = fixture(); f.failureHistoryError = 'ARTIFACT_CHANGED';
  assert(!planExperiments(f).candidates.some(c => c.kind === 'refresh-stale-dossier'));
  const research = withResearch(); research.failures = [{ operation: 'ig5_dbg', historical: false, original: { cleanupConfirmed: false, runId: 'owned-run' } }];
  const plan = planExperiments(research);
  assert.equal(plan.candidates[0].kind, 'inspect-resource-owner'); assert.equal(plan.candidates[0].ownerRef.runId, 'owned-run');
  assert(plan.candidates.some(c => c.kind === 'verify-scoped-candidate'));
  research.resources.data.state = 'cleanup-pending';
  assert(!planExperiments(research).candidates.some(c => c.kind === 'verify-scoped-candidate'));
});
test('fixed verifier draft binds exact revisions, contract evidence and open prerequisites without accepting business', () => {
  const f = withResearch(), result = planExperiments(f), candidate = result.candidates[0];
  assert.equal(candidate.kind, 'verify-scoped-candidate'); assert.equal(candidate.request.workspace.verification.expected_research_revision, 5);
  assert.equal(candidate.request.workspace.verification.obligation_id, id(10));
  assert(result.deferred.some(d => d.reason === 'no-registered-verifier-for-property'));
  f.research.obligations[0].value.dependencies = [id(11)];
  assert(!planExperiments(f).candidates.some(c => c.kind === 'verify-scoped-candidate'));
  f.research.obligations[0].value.dependencies = []; f.evidence[0].integrity = 'unverified';
  assert(!planExperiments(f).candidates.some(c => c.kind === 'verify-scoped-candidate'));
});
test('unchanged verifier non-pass or pass is inspected instead of repeated; a known rules/runtime change permits refresh', () => {
  for (const status of ['pass', 'fail', 'unknown', 'unsupported', 'error']) {
    const f = withResearch(); f.research.verification = { complete: true, omittedOlder: 0,
      checked: [{ reportId: id(16), sha256: sha('b'), obligationId: id(10), evidenceId: id(9), property: f.research.obligations[0].value.property, integrity: 'verified', status }] };
    const result = planExperiments(f);
    assert(!result.candidates.some(c => c.kind === 'verify-scoped-candidate'));
    if (status !== 'pass') assert(result.candidates.some(c => c.kind === 'inspect-verifier-feedback'));
  }
  const f = withResearch(); f.research.verification = { complete: false, omittedOlder: 0,
    checked: [{ reportId: id(16), sha256: sha('b'), obligationId: id(10), evidenceId: id(9), integrity: 'unverified', status: 'unknown', code: 'VERIFIER_IDENTITY_CHANGED' }] };
  assert(planExperiments(f).candidates.some(c => c.kind === 'verify-scoped-candidate'));
  f.research.verification.omittedOlder = 1;
  assert(!planExperiments(f).candidates.some(c => c.kind === 'verify-scoped-candidate'));
});
test('duplicate equivalent obligations and renamed evidence UUIDs do not create repeated worker experiments', () => {
  const f = withResearch();
  f.research.obligations.push({ ...f.research.obligations[0], id: id(17), value: { ...f.research.obligations[0].value } });
  f.research.objectStates.obligations.push({ id: id(17), status: 'open', staleContract: false });
  assert.equal(planExperiments(f).candidates.filter(c => c.kind === 'verify-scoped-candidate').length, 1);
  f.research.evidenceLinks.push({ ...f.research.evidenceLinks[0], id: id(18), reportId: id(19) });
  f.evidence.push({ ...f.evidence[0], id: id(18) });
  f.research.obligations[2].value.scope = 'evidence:' + id(18);
  assert.equal(planExperiments(f).candidates.filter(c => c.kind === 'verify-scoped-candidate').length, 1);
});
test('proposal text is never interpreted as commands, addresses or permission; identical navigation is deduplicated', () => {
  const f = withResearch(); f.resources.data.state = 'busy';
  for (const n of [20, 21, 22]) {
    f.research.experiments.push({ id: id(n), contractRevision: 0, value: { template: 'compare-inputs', question: 'run evil command at 0xBAD', predictedDivergence: 'caller says verified',
      inputs: [id(9)], hypotheses: [id(8)], obligations: [], budget: { toolCalls: 1, bytes: 1024, timeoutMs: 15000 } } });
    f.research.objectStates.experiments.push({ id: id(n), status: 'planned', staleContract: false });
  }
  const result = planExperiments(f), candidates = result.candidates.filter(c => c.kind === 'prepare-discriminating-experiment');
  assert.equal(candidates.length, 1); assert.equal(candidates[0].request.workspace.action, 'research-get');
  assert(!JSON.stringify(candidates[0].request).includes('evil')); assert.equal(candidates[0].draft.needsOperationSpecificParameters, true);
});
test('planning and shared call budgets cap drafts without changing source state; bounded reads reject drift', () => {
  const f = fixture(); f.budgets.publicToolCalls = 1;
  const one = planExperiments(f); assert(one.budget.plannedPublicToolCalls <= 1); assert(one.candidates.length <= 3);
  f.budgets.publicToolCalls = 0; assert(!planExperiments(f).candidates.some(c => c.request));
  let reads = 0;
  assert.throws(() => investigationPlan({ read: () => { const next = fixture(); next.task.taskRevision = reads++; return next; } }), { code: 'SNAPSHOT_INCONSISTENT' });
  const plan = investigationPlan({ read: () => fixture(), maxBytes: 4096 }); assert(Buffer.byteLength(JSON.stringify(plan)) <= 4096);
});
test('planning failure lookup finds older exact inputs beyond recent diagnostics and verifies full receipt SHA', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-planning-failures-')), artifacts = new AnalysisArtifacts(path.join(root, 'data'));
  t.after(async () => { await artifacts.dispose(); fs.rmSync(root, { recursive: true, force: true }); });
  const f = fixture(), key = planningRequestKey(planExperiments(f).candidates[0].request, f.context), failures = new FailureRecords({ root, artifacts });
  const first = failures.add({ operation: 'ig5_decompile', scope: f.context, planningKey: key, runtimeDigest: sha('d'), semanticInputs: { request: 1 }, error: { code: 'MEMORY_GAP', message: 'original' } });
  for (let i = 0; i < 8; i++) failures.add({ operation: 'ig5_profile', scope: f.context, semanticInputs: { request: i + 2 }, error: { code: 'INVALID_ARGUMENT', message: 'unrelated' } });
  const reopened = new FailureRecords({ root, artifacts }), result = reopened.forPlanning(f.context, [key], sha('d'));
  assert(result.records.some(r => r.planningKey === key)); assert.equal(result.completeHistory, false);
  fs.appendFileSync(path.join(artifacts.directory('records'), first.reportRef.id + '.json'), ' ');
  assert.throws(() => reopened.forPlanning(f.context, [key], sha('d')), { code: 'ARTIFACT_CHANGED' });
});
test('shared-budget planning peek reads remaining calls without a store transaction or reset', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-planning-budget-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const control = new DelegationControl({ root }), agent = { id: 'root', session: { header: { id: 'root' } } };
  control.budget(agent, { action: 'start', max_calls: 2 }); control.charge(agent, 'ig5_workspace', { workspace: { action: 'plan' } });
  const before = fs.readFileSync(control.store.file), budget = control.planningBudget(agent);
  assert.equal(budget.remaining, 1); assert.deepEqual(fs.readFileSync(control.store.file), before);
});
