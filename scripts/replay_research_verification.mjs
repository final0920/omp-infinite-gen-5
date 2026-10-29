// Frozen recorded-input replay through workspace and its real bounded worker.
// Static session context is a fixture; no engine, target, decoder or debugger is started.
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { AnalysisArtifacts, hashBytes, readStableFile } from '../source/analysis_artifacts.js';
import { AnalysisJobs } from '../source/analysis_jobs.js';
import { runWorkspace } from '../source/investigation_workflow.js';
import { VM_CONTEXT_PROPERTY, vmContextEvidence } from '../source/evidence_adapters/vm_context.js';

const [output, artifactRoot, modelId, modelSha] = process.argv.slice(2);
if (!output || !artifactRoot || !path.isAbsolute(output) || !path.isAbsolute(artifactRoot) || fs.existsSync(output)) throw Error('Usage: NEW_OUTPUT_ROOT ANALYSIS_ARTIFACT_ROOT COMMITTED_MODEL_UUID SHA256');
fs.mkdirSync(output);
const artifacts = new AnalysisArtifacts(artifactRoot), jobs = new AnalysisJobs();
try {
  const source = artifacts.get(modelId), sha256 = source.result.targetSha256;
  const target = 'recorded-target:' + sha256, context = { target, projectId: `project_${randomUUID()}`, artifactId: `artifact_${sha256}`, sha256,
    engine: 'reverse', provider: 'ghidra', attachmentId: `attachment_${randomUUID()}`, dbRevision: 0 };
  const session = { target, engine: 'reverse' }, mgr = { analysis: { artifacts, jobs }, get: () => session, alive: () => true, checkCancelled() {},
    evidence: () => ({ ...context }), engines: () => [], sessions: new Map([[target, session]]) };
  const cfg = { projectRoot: path.join(output, 'projects') }, execution = { agent: { id: 'frozen-recording-verification' } };
  const call = async workspace => (await runWorkspace(mgr, cfg, { target, workspace }, execution)).workspace;
  const task = await call({ action: 'create', goal: 'Independently audit frozen VM context candidate derivation' });
  const get = () => call({ action: 'research-get', id: task.taskId });
  const update = async (operation, value, extra = {}) => {
    const before = await get();
    return call({ action: 'research-update', id: task.taskId, ...extra, research: { operation, expected_task_revision: before.taskRevision,
      expected_research_revision: before.research?.researchRevision ?? 0, scope_digest: before.scopeDigest, ...(value === undefined ? {} : { value }) } });
  };
  const prepared = vmContextEvidence(artifacts, task, { id: modelId, sha256: modelSha });
  const inputRefs = [prepared.request.root, ...prepared.request.parents].map(({ id, sha256, path: filename }) => ({ id, sha256, path: filename }));
  await update('initialize', { question: task.goal, inputDomain: 'Exactly the committed context and typed immediate inputs listed by SHA',
    returns: 'No function return acceptance', outputs: 'Independent candidate consistency result', sideEffects: 'No target execution',
    environment: 'Recorded inputs; static session identity supplied by the test fixture', exclusions: 'Original recording/CPU, VM roles, phases, program and business proof' });
  const link = await update('link-vm-context', undefined, { report_ref: { id: modelId, sha256: modelSha } }), evidenceId = link.research.evidenceLinks[0].id;
  const proposed = await update('add-obligation', { property: VM_CONTEXT_PROPERTY, scope: `evidence:${evidenceId}`, verifier: 'vm-context-audit-v1', dependencies: [] });
  const obligationId = proposed.research.obligations[0].id;
  const experiment = await update('add-experiment', { template: 'review-evidence', question: 'Do counts, candidates and dictionary follow the recorded observations?',
    inputs: [evidenceId], hypotheses: [], obligations: [obligationId], budget: { toolCalls: 1, timeoutMs: 15000, bytes: 8 * 1024 ** 2 },
    predictedDivergence: 'A changed count, candidate, unknown result or proof boundary fails the independent check' });
  const planBefore = await call({ action: 'plan', id: task.taskId });
  const candidate = planBefore.candidates.find(c => c.kind === 'verify-scoped-candidate');
  if (!candidate || candidate.request.tool !== 'ig5_workspace' || candidate.request.workspace.verification.experiment_id !== experiment.research.experiments[0].id) throw Error('Planner did not produce the exact grounded verification draft');
  // The replay harness explicitly follows one suggestion. The planner itself never executes it.
  const verified = await call(candidate.request.workspace);
  const planAfter = await call({ action: 'plan', id: task.taskId });
  if (planAfter.candidates.some(c => c.kind === 'verify-scoped-candidate')) throw Error('Planner repeated an already verified obligation');
  const brief = await call({ action: 'brief', id: task.taskId });
  const full = await call({ action: 'research-verification', id: task.taskId, verification_id: verified.reportId });
  for (const ref of inputRefs) if (hashBytes(readStableFile(ref.path, 4 * 1024 ** 2).data) !== ref.sha256) throw Error('Frozen input changed');
  const report = { schema: 'ig5-research-verification-replay-v1', ok: verified.status === 'pass' && verified.linked && verified.dataWorkerCleanupConfirmed,
    sourceImplementation: fileURLToPath(new URL('..', import.meta.url)), execution: { nativeTargetExecuted: false, decoderExecuted: false, modelApiCalled: false, staticContext: 'fixture-only' },
    inputRefs, sourceObservationCounts: source.result.evidence, planBefore, planAfter, verified, brief, fullResult: full.result, frozenInputsUnchanged: true };
  fs.writeFileSync(path.join(output, 'verification-replay.json'), JSON.stringify(report, null, 2), { flag: 'wx' });
  console.log(JSON.stringify({ ok: report.ok, status: verified.status, linked: verified.linked, cleanup: verified.dataWorkerCleanupConfirmed,
    coverage: full.result.outcome.coverage, acceptance: verified.research.acceptanceStatus, report: path.join(output, 'verification-replay.json') }));
  if (!report.ok) process.exitCode = 1;
} finally { await jobs.dispose(); await artifacts.dispose(); }
