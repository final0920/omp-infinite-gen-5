import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID, createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { AnalysisArtifacts } from '../source/analysis_artifacts.js';
import { InvestigationStore } from '../source/investigation_store.js';
import { ResearchState, researchScopeDigest } from '../source/research_state.js';
import { runWorkspace, captureDossier } from '../source/investigation_workflow.js';
import { investigationBrief } from '../source/investigation_brief.js';

const hash = s => createHash('sha256').update(s).digest('hex');
const contract = { question: 'Explain the observed return and write', inputDomain: 'The five listed inputs', returns: 'Recorded return', outputs: 'No output stream', sideEffects: 'One observed output slot', environment: 'Fixed fixture', exclusions: 'Unobserved paths and complete function proof' };
const hypothesis = { proposition: 'The low input bit selects the branch', supporting: [], opposing: [], competingExplanations: ['Unrecorded initial state'] };
const obligation = { property: 'candidate derivation and provenance', dependencies: [], scope: 'Specified committed reports', verifier: 'vm-context-independent-audit-v1' };
const experiment = { template: 'compare-inputs', question: 'Does one input bit explain the difference?', inputs: [], hypotheses: [], obligations: [],
  budget: { toolCalls: 2, timeoutMs: 15000, bytes: 65536 }, predictedDivergence: 'Compare both recorded outputs; unknown state may leave the hypothesis unresolved' };
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-research-')), cfg = { projectRoot: path.join(root, 'projects') };
  const sha256 = hash('self authored fixture'), context = { projectId: `project_${randomUUID()}`, artifactId: `artifact_${sha256}`, sha256,
    engine: 'reverse', provider: 'ghidra', attachmentId: `attachment_${randomUUID()}`, dbRevision: 2, target: path.join(root, 'fixture.exe') };
  const notes = new InvestigationStore({ root: cfg.projectRoot }), task = notes.create(context, { goal: 'Explain the fixture' }, 'test');
  const service = new ResearchState({ root: cfg.projectRoot }), artifacts = new AnalysisArtifacts(path.join(root, 'reports'));
  const session = { engine: 'reverse', target: context.target };
  const mgr = { analysis: { artifacts }, investigations: notes, researchState: service, sessions: new Map([[context.target, session]]),
    get: () => session, alive: () => true, checkCancelled() {}, evidence: () => ({ ...context }), engines: () => [] };
  const call = input => runWorkspace(mgr, cfg, { target: context.target, workspace: input }, { agent: { id: 'test' } }).workspace;
  const update = (operation, value, extras = {}) => {
    const current = notes.get(context, task.taskId), state = service.get(current, context);
    return call({ action: 'research-update', id: task.taskId, research: { operation, expected_research_revision: state?.researchRevision ?? 0,
      expected_task_revision: current.taskRevision, scope_digest: researchScopeDigest(current.scope), ...(value === undefined ? {} : { value }) }, ...extras });
  };
  const capture = () => {
    const dossier = { schemaVersion: 1, kind: 'function-dossier', provenance: { ...context }, _ig5: { ...context }, snapshotDigest: hash(randomUUID()),
      function: { ea: '0x140001000', name: 'fixture' }, sections: { decompile: { status: 'ok', data: { code: 'return x & 1;' } },
        cfg: { status: 'truncated' }, callers: { status: 'unsupported' }, callees: { status: 'ok' }, stack: { status: 'error' } },
      responseTruncated: true, limitations: ['Synthetic fixture, no native execution'] };
    return captureDossier(mgr, cfg, dossier, task.taskId, { agent: { id: 'test' } });
  };
  t.after(async () => { await artifacts.dispose(); assert.equal(path.dirname(root), fs.realpathSync(os.tmpdir())); fs.rmSync(root, { recursive: true, force: true }); });
  return { root, cfg, context, notes, task, service, artifacts, mgr, call, update, capture };
}
test('research initialization and four objects persist independently of v1 task completion', t => {
  const f = fixture(t), before = f.notes.get(f.context, f.task.taskId);
  const empty = f.call({ action: 'research-get', id: f.task.taskId });
  assert.equal(empty.initialized, false);
  assert(!fs.existsSync(path.join(f.cfg.projectRoot, 'investigations', 'research-v1')));
  assert.equal(empty.scopeDigest, researchScopeDigest(before.scope));
  let result = f.update('initialize', contract).research;
  assert.equal(result.researchRevision, 0);
  result = f.update('add-hypothesis', hypothesis).research;
  result = f.update('add-obligation', obligation).research;
  result = f.update('add-experiment', { ...experiment, hypotheses: [result.hypotheses[0].id], obligations: [result.obligations[0].id] }).research;
  assert.equal(result.researchRevision, 3);
  assert.deepEqual(f.notes.get(f.context, f.task.taskId), before);
  assert.deepEqual(result.objectStates.obligations.map(o => o.status), ['open']);
  assert.deepEqual(result.objectStates.experiments[0].resultRefs, []);
  const reopened = new ResearchState({ root: f.cfg.projectRoot }).get(before, f.context);
  assert.deepEqual(reopened, result);
  f.notes.update(f.context, f.task.taskId, { expected_task_revision: 0, status: 'completed' }, 'test');
  result = f.call({ action: 'research-get', id: f.task.taskId }).research;
  assert.equal(result.workStatus, 'completed'); assert.equal(result.acceptanceStatus, 'not-assessed');
  assert.equal(result.resourceStatus, 'retained-unknown'); assert(result.stale);
});
test('strict proposals cannot mark hypotheses verified, close obligations or fabricate execution receipts', t => {
  const f = fixture(t); f.update('initialize', contract);
  for (const [operation, value] of [['add-hypothesis', { ...hypothesis, status: 'verified' }],
    ['add-obligation', { ...obligation, status: 'closed' }], ['add-experiment', { ...experiment, resultRefs: [randomUUID()] }],
    ['add-experiment', { ...experiment, command: 'anything' }], ['set-contract', { ...contract, acceptanceStatus: 'accepted-in-scope' }],
    ['add-experiment', { ...experiment, budget: { ...experiment.budget, timeoutMs: 60001 } }]]) {
    assert.throws(() => f.update(operation, value), { code: 'INVALID_RESEARCH' });
  }
  assert.throws(() => f.update('add-hypothesis', { ...hypothesis, supporting: [randomUUID()] }), { code: 'INVALID_RESEARCH_REF' });
  assert.throws(() => f.update('add-obligation', { ...obligation, dependencies: [randomUUID()] }), { code: 'INVALID_RESEARCH_REF' });
  assert.equal(f.call({ action: 'research-get', id: f.task.taskId }).research.researchRevision, 0);
});
test('proposal revisions retain old values and distinguish superseded from verified or executed', t => {
  const f = fixture(t); f.update('initialize', contract);
  let state = f.update('add-hypothesis', hypothesis).research;
  const first = state.hypotheses[0].id;
  const currentTask = f.notes.get(f.context, f.task.taskId);
  const revise = () => f.call({ action: 'research-update', id: f.task.taskId,
    research: { operation: 'revise-hypothesis', entity_id: first, expected_research_revision: state.researchRevision,
      expected_task_revision: currentTask.taskRevision, scope_digest: researchScopeDigest(f.task.scope),
      value: { ...hypothesis, proposition: 'The first interpretation is insufficient' } } });
  state = revise().research;
  assert.equal(state.hypotheses.length, 2); assert.equal(state.hypotheses[0].value.proposition, hypothesis.proposition);
  assert.equal(state.hypotheses[1].supersedes, first);
  assert.deepEqual(state.objectStates.hypotheses.map(h => h.status), ['superseded', 'proposed']);
  assert.throws(revise, { code: 'INVALID_RESEARCH_REF' });
});
test('research CAS, target scope and explicit changed-context acknowledgement preserve previous state', t => {
  const f = fixture(t); f.update('initialize', contract); f.update('add-hypothesis', hypothesis);
  const request = { operation: 'add-obligation', value: obligation, expected_research_revision: 0, expected_task_revision: 0, scope_digest: researchScopeDigest(f.task.scope) };
  assert.throws(() => f.service.mutate(f.task, f.context, request, 'test'), { code: 'STALE_RESEARCH_REVISION' });
  assert.throws(() => f.service.mutate(f.task, f.context, { ...request, scope_digest: hash('another target') }, 'test'), { code: 'RESEARCH_SCOPE_MISMATCH' });
  f.notes.update(f.context, f.task.taskId, { expected_task_revision: 0, goal: 'Revised question' }, 'test');
  assert.throws(() => f.update('add-obligation', obligation), { code: 'STALE_RESEARCH_CONTEXT' });
  assert.throws(() => f.service.mutate(f.notes.get(f.context, f.task.taskId), f.context, request, 'test'), { code: 'STALE_TASK_REVISION' });
  f.update('acknowledge-context');
  f.context.attachmentId = `attachment_${randomUUID()}`; f.context.dbRevision++;
  assert.throws(() => f.update('add-obligation', obligation), { code: 'STALE_RESEARCH_CONTEXT' });
  const result = f.update('acknowledge-context').research;
  assert.equal(result.stale, false); assert.equal(result.hypotheses.length, 1); assert.equal(result.acceptanceStatus, 'not-assessed');
});
test('contract versions survive A to B to A without reviving prior obligations', t => {
  const f = fixture(t); f.update('initialize', contract); f.update('add-obligation', obligation);
  f.update('set-contract', { ...contract, inputDomain: 'Another bounded input domain' });
  const result = f.update('set-contract', contract).research;
  assert.equal(result.contracts.length, 3); assert.equal(result.contractRevision, 2);
  assert.equal(result.contracts[0].digest, result.contractDigest);
  assert.equal(result.objectStates.obligations[0].staleContract, true);
  assert.equal(result.acceptanceStatus, 'not-assessed');
});
test('dossier linking checks task membership, retains partial evidence and rebuilds scoped dependencies', t => {
  const f = fixture(t), saved = f.capture(); f.update('initialize', contract);
  const linked = f.update('link-evidence', undefined, { snapshot_id: saved.snapshotId });
  assert.equal(linked.linked, true); assert.equal(linked.reportSaved, true);
  const link = linked.research.evidenceLinks[0];
  f.update('add-hypothesis', { ...hypothesis, supporting: [link.id] });
  f.update('add-experiment', { ...experiment, inputs: [link.id] });
  const deps = f.call({ action: 'research-dependencies', id: f.task.taskId, evidence_id: link.id });
  assert.equal(deps.dependencies.length, 2); assert.equal(deps.globalStatus, 'partial');
  assert.equal(f.call({ action: 'research-get', id: f.task.taskId }).evidence[0].integrity, 'verified');
  assert.throws(() => f.update('link-evidence', undefined, { snapshot_id: randomUUID() }), { code: 'INVALID_RESEARCH_REF' });
  assert.throws(() => f.update('link-evidence', { path: 'C:/untrusted.json', sha256: hash('untrusted') }, { snapshot_id: saved.snapshotId }), { code: 'INVALID_RESEARCH' });
});
test('failed research association returns the retained report and can recover without collection', t => {
  const f = fixture(t), saved = f.capture(); f.update('initialize', contract);
  const request = { action: 'research-update', id: f.task.taskId, snapshot_id: saved.snapshotId,
    research: { operation: 'link-evidence', expected_research_revision: 0, expected_task_revision: 1, scope_digest: researchScopeDigest(f.task.scope) } };
  f.update('add-hypothesis', hypothesis);
  const failed = f.call(request);
  assert.equal(failed.code, 'STALE_RESEARCH_REVISION'); assert.equal(failed.reportSaved, true); assert.equal(failed.linked, false);
  assert.equal(failed.reportId, saved.reportId);
  request.research.expected_research_revision = 1;
  assert.equal(f.call(request).linked, true);
  assert.equal(fs.readdirSync(f.artifacts.directory('records')).length, 1);
});
test('stored schema tampering and modified report bytes fail closed', t => {
  const f = fixture(t), saved = f.capture(); f.update('initialize', contract); f.update('link-evidence', undefined, { snapshot_id: saved.snapshotId });
  const report = path.join(f.artifacts.directory('records'), saved.reportId + '.json');
  fs.appendFileSync(report, ' ');
  const result = f.call({ action: 'research-get', id: f.task.taskId });
  assert.equal(result.evidence[0].integrity, 'unverified');
  const metadata = f.service.metadata(f.task.taskId), data = JSON.parse(fs.readFileSync(metadata.file));
  data.investigations[f.task.taskId].schema = 'unknown-v2';
  fs.writeFileSync(metadata.file, JSON.stringify(data));
  assert.throws(() => f.call({ action: 'research-get', id: f.task.taskId }), { code: 'RESEARCH_STORE_CORRUPT' });
});
test('post-commit cancellation discloses the committed association rather than claiming rollback', t => {
  const f = fixture(t), saved = f.capture(); f.update('initialize', contract);
  const mutate = f.service.mutate.bind(f.service);
  f.service.mutate = (...args) => {
    const result = mutate(...args);
    f.mgr.checkCancelled = () => { throw Object.assign(new Error('cancelled'), { code: 'ABORT_ERR' }); };
    return result;
  };
  const result = f.update('link-evidence', undefined, { snapshot_id: saved.snapshotId });
  assert.equal(result.researchSaved, true); assert.equal(result.linked, true); assert.equal(result.postCommitContext, 'unavailable');
  assert(result.research.stale); assert.equal(result.code, 'ABORT_ERR');
  assert.equal(f.service.get(f.notes.get(f.context, f.task.taskId), f.context).evidenceLinks.length, 1);
});
test('changes during publication are reported stale and sidecar links reject directory redirection', t => {
  const f = fixture(t); f.update('initialize', contract);
  const mutate = f.service.mutate.bind(f.service);
  f.service.mutate = (...args) => {
    const result = mutate(...args);
    f.notes.update(f.context, f.task.taskId, { expected_task_revision: 0, goal: 'Concurrent question' }, 'other');
    return result;
  };
  const result = f.update('add-hypothesis', hypothesis);
  assert.equal(result.researchSaved, true); assert.equal(result.research.stale, true);
  assert(result.research.staleReasons.includes('task-revision-changed'));
  const external = path.join(f.root, 'outside'); fs.mkdirSync(external);
  const taskDir = path.join(f.cfg.projectRoot, 'investigations', 'research-v1', f.task.taskId);
  const old = taskDir + '-retained'; fs.renameSync(taskDir, old);
  fs.symlinkSync(external, taskDir, process.platform === 'win32' ? 'junction' : 'dir');
  try {
    assert.throws(() => f.service.get(f.notes.get(f.context, f.task.taskId), f.context), { code: 'DIAGNOSTIC_STORE_INVALID' });
    assert.deepEqual(fs.readdirSync(external), []);
  } finally { fs.unlinkSync(taskDir); fs.renameSync(old, taskDir); }
});
test('research caps preserve all unresolved proposals and enforce the UTF-8 state byte limit', t => {
  const f = fixture(t); f.update('initialize', contract);
  for (let i = 0; i < 32; i++) f.update('add-hypothesis', hypothesis);
  assert.throws(() => f.update('add-hypothesis', hypothesis), { code: 'RESEARCH_LIMIT' });
  let accepted = 0;
  for (; accepted < 128; accepted++) {
    try { f.update('add-experiment', { ...experiment, question: '测'.repeat(2048), predictedDivergence: '试'.repeat(2048) }); }
    catch (e) { assert.equal(e.code, 'RESEARCH_LIMIT'); break; }
  }
  assert(accepted > 0 && accepted < 128);
  const state = f.call({ action: 'research-get', id: f.task.taskId }).research;
  assert.equal(state.experiments.length, accepted); assert.equal(state.hypotheses.length, 32);
});
test('brief rereads research revision, rejects persistent changes and keeps research in its UTF-8 budget', t => {
  const f = fixture(t), saved = f.capture(); f.update('initialize', contract); f.update('link-evidence', undefined, { snapshot_id: saved.snapshotId });
  f.update('add-hypothesis', hypothesis);
  const brief = f.call({ action: 'brief', id: f.task.taskId, max_bytes: 4096 });
  assert.equal(brief.snapshot.researchRevision, 2); assert.equal(brief.research.counts.hypotheses, 1);
  assert(Buffer.byteLength(JSON.stringify(brief)) <= 4096);
  assert.equal(brief.acceptance.status, 'not-assessed');
  let reads = 0;
  assert.throws(() => investigationBrief({ readTask: () => f.notes.get(f.context, f.task.taskId), readContext: () => f.context,
    readResearch: () => ({ ...f.service.get(f.notes.get(f.context, f.task.taskId), f.context), researchRevision: reads++ }),
    readEvidence: () => f.artifacts.get(saved.reportId).result, capabilities: { entries: [] } }), { code: 'SNAPSHOT_INCONSISTENT' });
});
test('independent processes cannot both publish the same research revision', async t => {
  const f = fixture(t); f.update('initialize', contract);
  const script = `import { ResearchState } from ${JSON.stringify(new URL('../source/research_state.js', import.meta.url).href)};
    const [root,task,context,input]=process.argv.slice(1).map(JSON.parse);
    try { const r=new ResearchState({root}).mutate(task,context,input,'child'); console.log(JSON.stringify({ok:true,revision:r.researchRevision})); }
    catch(e) { console.log(JSON.stringify({ok:false,code:e.code,message:e.message,stack:e.stack,metadataPublished:e.metadataPublished,metadataStage:e.metadataStage})); }`;
  const input = { operation: 'add-hypothesis', expected_research_revision: 0, expected_task_revision: 0, scope_digest: researchScopeDigest(f.task.scope), value: hypothesis };
  const child = () => new Promise((resolve, reject) => {
    const p = spawn(process.execPath, ['--input-type=module', '-e', script, ...[f.cfg.projectRoot, f.task, f.context, input].map(JSON.stringify)], { windowsHide: true });
    let out = '', err = ''; p.stdout.on('data', x => out += x); p.stderr.on('data', x => err += x);
    p.on('error', reject); p.on('exit', code => code === 0 ? resolve(JSON.parse(out)) : reject(Error(err)));
  });
  const results = await Promise.all([child(), child()]);
  assert.equal(results.filter(r => r.ok).length, 1);
  const failed = results.find(r => !r.ok);
  assert(['STALE_RESEARCH_REVISION', 'STORE_BUSY'].includes(failed.code)
    || failed.code === 'EPERM' && failed.metadataPublished === false && failed.metadataStage === 'publish', JSON.stringify(results));
  assert.equal(f.service.get(f.task, f.context).hypotheses.length, 1);
});
