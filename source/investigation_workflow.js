import {cffActions,validateCffInput,runCffWorkflow} from './cff_workflow.js';
import { investigationResume } from './investigation_resume.js';
import { caseIndexActions, runCaseIndex, validateCaseIndexInput } from './research_case_bridge.js';
import { methodActions, runMethodQuery, validateMethodInput } from './method_applicability.js';
import { runExperimentShadow, validateShadowInput } from './experiment_shadow.js';
import { candidateActions, validateCandidateInput, runCandidateWorkflow, bitvectorASTSchema } from './candidate_workflow.js';
import { LiftJobs } from './lift_jobs.js';
import { InvestigationStore } from './investigation_store.js';
import { planningContext, investigationPlan } from './investigation_planning.js';
import { jsonToolOutput } from './json_output.js';
import { capabilityCatalog } from './capability_catalog.js';
import { investigationBrief } from './investigation_brief.js';
import { validateSnapshotReport } from './evidence_adapters/dossier.js';
import { ResearchState, researchScopeDigest, researchMutationSchema, researchDigest, validateResearchMutation } from './research_state.js';
import { linkDossierEvidence, inspectResearchEvidence } from './evidence_registry.js';
import { evidenceDependencies } from './evidence_dependencies.js';
import { vmContextEvidence, exactReportRef } from './evidence_adapters/vm_context.js';
import { fixedPropertyEvidence } from './evidence_adapters/fixed_properties.js';
import { verifyResearch, verificationOverlay, loadVerification, readVerificationReport, verificationRequestSchema, validateVerificationRequest } from './verification_registry.js';

export const workspaceSchema = {
  description: 'Static investigation notes and evidence. research-get returns current scopeDigest and independent researchRevision. research-update requires both task/research revisions; link-vm-context accepts only committed report_ref UUID/SHA. link-verifier-evidence accepts committed fixed function/recorded-source reports; research-verify runs the registered bounded property verifier; research-link-verification recovers its saved result after CAS conflict. A narrow pass never accepts the whole contract. Before DSH delegation, read the task then use handoff with current expected_task_revision, question, acceptance and constraints. Child reads exact task evidence; parent reviews returned snapshot IDs. No agent spawning, permission grants or automatic completion.',
  type: 'object', properties: {
    action: { type: 'string', enum: ['create', 'get', 'brief', 'list', 'update', 'evidence', 'handoff', 'claim', 'submit', 'review', 'plan', 'resume', 'research-get', 'research-update', 'research-dependencies', 'research-verify', 'research-link-verification', 'research-verification', ...caseIndexActions, ...methodActions, 'experiment-shadow', ...candidateActions, ...cffActions] },
    source_ref: { type:'object',properties:{id:{type:'string'},sha256:{type:'string',pattern:'^[a-f0-9]{64}$'}},required:['id','sha256'],additionalProperties:false },
    verification_ref: { type:'object',properties:{id:{type:'string'},sha256:{type:'string',pattern:'^[a-f0-9]{64}$'}},required:['id','sha256'],additionalProperties:false },
    candidate_ref: { type:'object',properties:{id:{type:'string'},sha256:{type:'string',pattern:'^[a-f0-9]{64}$'}},required:['id','sha256'],additionalProperties:false },
    root_node: { type:'integer',minimum:0,maximum:2047,description:'candidate-prepare: selected pure root in the complete committed preferred-address projection' },
    candidate_ast: bitvectorASTSchema,
    premise: bitvectorASTSchema,
    mode: { type: 'string', enum: ['off','shadow'], description: 'experiment-shadow only; off returns the original plan, shadow adds independent suggestions; assist unavailable' },
    method_id: { type: 'string', maxLength: 64, description: 'method-applicability: exact fixed method ID from method-registry; read only, never executes a template' },
    query: { type: 'string', minLength: 1, maxLength: 256, description: 'case-search only; explicit current-task private index query' },
    ref: { type: 'object', properties: { id: { type: 'string', maxLength: 64 }, sha256: { type: 'string', pattern: '^[a-f0-9]{64}$' } }, required: ['id','sha256'], additionalProperties: false },
    generation: { type: 'string', description: 'case-search/read: optional exact private generation' },
    expected_generation: { type: 'string', description: 'case-index: exact current generation, or absent' },
    expected_research_revision: { type: 'integer', minimum: 0, description: 'case-index: current research revision' },
    research: researchMutationSchema,
    verification: verificationRequestSchema,
    report_ref: { type: 'object', properties: { id: { type: 'string' }, sha256: { type: 'string', pattern: '^[a-f0-9]{64}$' } }, required: ['id', 'sha256'], additionalProperties: false },
    verification_id: { type: 'string', description: 'Committed verification report UUID already linked to this task' },
    evidence_id: { type: 'string', description: 'research-dependencies: linked evidence UUID in this task' },
    max_bytes: { type: 'integer', minimum: 4096, maximum: 32768, description: 'brief/plan/resume only: UTF-8 JSON budget, default 12288' },
    cursor: { type: 'string', description: 'brief or case-read continuation; bound to exact scope and revisions' },
    handoff_id: { type: 'string', description: 'Child claim/submit, parent post-return review: tracked handoffId. Review without it is integrity precheck only, never delegation acceptance.' },
    question: { type: 'string', maxLength: 2048, description: 'handoff: bounded delegated question; caller statement' },
    acceptance: { type: 'string', maxLength: 2048, description: 'handoff: explicit acceptance criteria; text only, never executed' },
    constraints: { type: 'string', maxLength: 2048, description: 'handoff: responsibility and limits; advisory, not an access-control policy' },
    snapshot_ids: { type: 'array', minItems: 1, maxItems: 8, uniqueItems: true, items: { type: 'string' }, description: 'review: task-bound system snapshots to revalidate; not a semantic completion verdict' },
    id: { type: 'string', description: 'Task UUID returned by create or list' },
    snapshot_id: { type: 'string', description: 'System snapshot UUID from this task; evidence action or research-update link-evidence' },
    expected_task_revision: { type: 'number', description: 'Required for update: use the returned taskRevision, independent of the database revision' },
    goal: { type: 'string', maxLength: 4096 },
    hypothesis: { type: 'string', maxLength: 4096, description: 'Caller statement, not verified evidence; do not include secrets' },
    next_step: { type: 'string', maxLength: 4096 },
    conclusion: { type: 'string', maxLength: 4096, description: 'Caller interpretation, not automatic verification' },
    status: { type: 'string', enum: ['active', 'paused', 'completed'], description: 'Caller-declared work progress' },
  }, required: ['action'], additionalProperties: false,
};

const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
function store(mgr, cfg) { return mgr.investigations ||= new InvestigationStore({ root: cfg.projectRoot }); }
function research(mgr, cfg) { return mgr.researchState ||= new ResearchState({ root: cfg.projectRoot }); }
function context(mgr, args) {
  if (typeof args.target !== 'string' || !args.target.trim()) fail('INVALID_ARGUMENT', 'workspace requires an explicit opened target');
  const session = mgr.get(args.target);
  if (!mgr.alive(session) || session.engine === 'x64dbg') fail('INVALID_ARGUMENT', 'workspace requires an opened static target');
  mgr.checkCancelled();
  return mgr.evidence(session);
}
function actor(execution) {
  const id = execution?.agent?.id || execution?.agent?.sessionId;
  if (typeof id !== 'string' || !id.trim()) fail('AGENT_SCOPE_REQUIRED', 'Task changes require the executing agent identity');
  return id;
}
function fields(input, allowed) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('INVALID_ARGUMENT', 'workspace must be an object');
  for (const name of Object.keys(input)) if (!allowed.includes(name)) fail('INVALID_ARGUMENT', `workspace field is not valid for this action: ${name}`);
}

/** Called under the selected session queue. This changes analysis notes only. */
export function runWorkspace(mgr, cfg, args, execution) {
  if (args.toolset !== undefined || args.history !== undefined) fail('INVALID_ARGUMENT', 'Use workspace separately from toolset/history changes');
  const input = args.workspace;
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('INVALID_ARGUMENT', 'workspace must be an object');
  const { action, id } = input;
  if (caseIndexActions.includes(action)) validateCaseIndexInput(input);
  if (methodActions.includes(action)) validateMethodInput(input);
  if (action === 'experiment-shadow') validateShadowInput(input);
  if (candidateActions.includes(action)) validateCandidateInput(input);
  if (cffActions.includes(action)) validateCffInput(input);
  if (['plan', 'resume'].includes(action)) fields(input, ['action', 'id', 'max_bytes']);
  if (action === 'research-update') validateResearchMutation(input.research);
  if (['research-verify', 'research-link-verification'].includes(action)) validateVerificationRequest(input.verification);
  const scope = context(mgr, args), notes = store(mgr, cfg);
  if (candidateActions.includes(action)||cffActions.includes(action)) {
    if (!execution?.agent?.id) fail('AGENT_SCOPE_REQUIRED','Candidate access requires the actual executing agent');
    mgr.lifter ||= new LiftJobs(cfg);
    const read=()=>{const current=context(mgr,args),task=notes.get(current,id);return {context:current,task,research:research(mgr,cfg).get(task,current)};};
    const controller=new AbortController(),parent=execution?.signal||mgr.scope?.getStore()?.signal,cancel=()=>controller.abort();
    if(parent?.aborted)cancel();else parent?.addEventListener('abort',cancel,{once:true});
    const timer=setTimeout(cancel,Math.min(cfg.requestTimeoutMs||60000,60000));
    const execute=cffActions.includes(action)?runCffWorkflow:runCandidateWorkflow;
    return execute({artifacts:mgr.analysis.artifacts,jobs:mgr.lifter,dataJobs:mgr.analysis.jobs,input,read,signal:controller.signal})
      .then(result=>({workspace:result})).catch(error=>{if(error.code==='UNSUPPORTED_BITVECTOR')return {workspace:{schema:'ig5-bitvector-unsupported-v1',status:'unsupported',reason:error.message,nativeTargetExecuted:false,businessAccepted:false,databaseModified:false,assistEnabled:false}};throw error;})
      .finally(()=>{clearTimeout(timer);parent?.removeEventListener('abort',cancel);});
  }
  if (action === 'experiment-shadow') {
    if (!execution?.agent?.id) fail('AGENT_SCOPE_REQUIRED', 'Shadow access requires the actual executing agent');
    const read = () => {
      const current=context(mgr,args),task=notes.get(current,id),state=research(mgr,cfg).get(task,current);
      let failures=[],failureError=null;
      try { failures=mgr.failures?.recent(current,3)||[]; } catch(error) { failureError=error.code||'FAILURE_HISTORY_UNAVAILABLE'; }
      return {context:current,task,research:state,failures,failureError,relatedTasks:notes.list(current).tasks.filter(other=>other.taskId!==task.taskId)};
    };
    return {workspace:runExperimentShadow({projectRoot:cfg.projectRoot,input,read,artifacts:mgr.analysis.artifacts,
      readPlanning:data=>planningContext({mgr,cfg,args,execution,context:data.context,task:data.task,research:verificationOverlay(mgr.analysis.artifacts,data.task,data.research)}),
      readLegacy:()=>runWorkspace(mgr,cfg,{...args,workspace:{action:'plan',id,...(input.max_bytes!==undefined?{max_bytes:input.max_bytes}:{})}},execution).workspace,
      readFailures:(keys,runtime)=>mgr.failures?.forPlanning?mgr.failures.forPlanning(context(mgr,args),keys,runtime):{records:[],completeHistory:false,error:'FAILURE_HISTORY_UNAVAILABLE'},
    })};
  }
  if (methodActions.includes(action)) {
    if (!execution?.agent?.id) fail('AGENT_SCOPE_REQUIRED', 'Method access requires the actual executing agent');
    return { workspace: runMethodQuery({ projectRoot: cfg.projectRoot, input, artifacts: mgr.analysis.artifacts, read: () => {
      const current = context(mgr, args), task = notes.get(current, id), state = research(mgr, cfg).get(task, current);
      let failures = [], failureError = null;
      try { failures = mgr.failures?.recent(current, 3) || []; } catch (error) { failureError = error.code || 'FAILURE_HISTORY_UNAVAILABLE'; }
      return { context: current, task, research: state, failures, failureError, relatedTasks: notes.list(current).tasks.filter(other => other.taskId !== task.taskId) };
    } }) };
  }
  if (caseIndexActions.includes(action)) {
    return runCaseIndex({ projectRoot: cfg.projectRoot, input, execution, artifacts: mgr.analysis.artifacts, memory: mgr.memory,
      read: () => {
        const current = context(mgr, args), task = notes.get(current, id), state = research(mgr, cfg).get(task, current);
        let failures = [], failureError = null;
        try { failures = mgr.failures?.recent(current, 3) || []; } catch (error) { failureError = error.code || 'FAILURE_HISTORY_UNAVAILABLE'; }
        return { context: current, task, research: state, failures, failureError,
          relatedTasks: notes.list(current).tasks.filter(other => other.taskId !== task.taskId) };
      } }).then(result => ({ workspace: result }));
  }
  if (['plan', 'resume'].includes(action)) {
    fields(input, ['action', 'id', 'max_bytes']);
    return { workspace: (action === 'resume' ? investigationResume : investigationPlan)({ maxBytes: input.max_bytes, read: () => {
      const current = context(mgr, args), task = notes.get(current, id);
      const state = verificationOverlay(mgr.analysis.artifacts, task, research(mgr, cfg).get(task, current));
      return planningContext({ mgr, cfg, args, execution, context: current, task, research: state });
    } }) };
  }
  if (action === 'research-get' || action === 'research-dependencies') {
    fields(input, action === 'research-get' ? ['action', 'id'] : ['action', 'id', 'evidence_id']);
    for (let attempt = 0; attempt < 2; attempt++) {
      const currentScope = context(mgr, args), task = notes.get(currentScope, id), state = verificationOverlay(mgr.analysis.artifacts, task, research(mgr, cfg).get(task, currentScope));
      if (action === 'research-dependencies') {
        if (!state?.evidenceLinks.some(e => e.id === input.evidence_id)) fail('INVALID_RESEARCH_REF', 'Choose linked evidence from this research state');
      }
      const result = action === 'research-dependencies' ? evidenceDependencies(state, input.evidence_id)
        : { taskId: id, taskRevision: task.taskRevision, scopeDigest: researchScopeDigest(task.scope),
          research: state, evidence: state ? inspectResearchEvidence(mgr.analysis.artifacts, task, currentScope, state) : [],
          initialized: state !== null, executionAuthorized: false };
      const endScope = context(mgr, args), endTask = notes.get(endScope, id), endState = research(mgr, cfg).get(endTask, endScope);
      if (task.taskRevision !== endTask.taskRevision || (state?.researchRevision ?? null) !== (endState?.researchRevision ?? null)
        || researchDigest(currentScope) !== researchDigest(endScope)) continue;
      return { workspace: result };
    }
    fail('SNAPSHOT_INCONSISTENT', 'Task, research or database changed during both research reads');
  }
  if (action === 'research-verify' || action === 'research-link-verification') {
    fields(input, action === 'research-verify' ? ['action', 'id', 'verification'] : ['action', 'id', 'verification', 'report_ref']);
    const task = notes.get(scope, id), service = research(mgr, cfg), state = service.get(task, scope), by = actor(execution);
    return runResearchVerification(mgr, args, input, notes, service, task, state, by, execution?.signal);
  }
  if (action === 'research-verification') {
    fields(input, ['action', 'id', 'verification_id']);
    const task = notes.get(scope, id), state = research(mgr, cfg).get(task, scope);
    const ref = state?.verificationRefs?.find(r => r.reportId === input.verification_id);
    if (!ref) fail('INVALID_RESEARCH_REF', 'Verification report is not associated with this research');
    return { workspace: { reportId: ref.reportId, sha256: ref.sha256, ...readVerificationReport(mgr.analysis.artifacts, task, state, ref) } };
  }
  if (action === 'research-update') {
    fields(input, ['action', 'id', 'research', 'snapshot_id', 'report_ref']);
    const task = notes.get(scope, id), service = research(mgr, cfg);
    const vmLink = input.research?.operation === 'link-vm-context', dossierLink = input.research?.operation === 'link-evidence';
    const fixedLink=input.research?.operation==='link-verifier-evidence';
    const linking = vmLink || dossierLink || fixedLink;
    if (!dossierLink && input.snapshot_id !== undefined) fail('INVALID_ARGUMENT', 'snapshot_id is only valid for link-evidence');
    if (!vmLink && !fixedLink && input.report_ref !== undefined) fail('INVALID_ARGUMENT', 'report_ref is only valid for a fixed research evidence link');
    const evidence = dossierLink ? linkDossierEvidence(mgr.analysis.artifacts, task, input.snapshot_id)
      : vmLink ? vmContextEvidence(mgr.analysis.artifacts, task, input.report_ref).link : fixedLink ? fixedPropertyEvidence(mgr.analysis.artifacts,task,input.report_ref).link : null;
    mgr.checkCancelled();
    let result;
    try {
      result = service.mutate(task, scope, input.research, actor(execution), { evidence });
    } catch (error) {
      if (!linking) throw error;
      return { workspace: { reportSaved: true, linked: false, reportId: evidence.reportId, reportSha256: evidence.sha256,
        code: error.code || 'RESEARCH_LINK_FAILED', stage: 'research-cas',
        note: 'Existing immutable report retained; reread research/task state before linking again. No collection was repeated.' } };
    }
    const committed = { researchSaved: true, writtenResearchRevision: result.researchRevision,
      ...(linking ? { reportSaved: true, linked: true, reportId: evidence.reportId, reportSha256: evidence.sha256 } : {}),
      atomicAcrossTaskAndResearch: false };
    try {
      const endScope = context(mgr, args), endTask = notes.get(endScope, id), current = service.get(endTask, endScope);
      return { workspace: { ...committed, research: verificationOverlay(mgr.analysis.artifacts, endTask, current), postCommitContext: 'read' } };
    } catch (error) {
      return { workspace: { ...committed, research: { ...result, stale: true, staleReasons: ['post-commit-context-unavailable'] },
        postCommitContext: 'unavailable', code: error.code || 'RESEARCH_CONTEXT_UNAVAILABLE',
        note: 'Research was committed. Read current task/context before any further change; this is not a rollback.' } };
    }
  }
  if (action === 'brief') {
    fields(input, ['action', 'id', 'max_bytes', 'cursor']);
    let failures = [], failureHistoryError = null;
    try { failures = mgr.failures?.recent(scope) || []; }
    catch(error) { failureHistoryError = error.code || 'FAILURE_HISTORY_UNAVAILABLE'; }
    return { workspace: investigationBrief({ readContext: () => context(mgr, args), readTask: current => notes.get(current, id),
      readResearch: (task, current) => verificationOverlay(mgr.analysis.artifacts, task, research(mgr, cfg).get(task, current)),
      readPlanning: (task, current, state) => planningContext({ mgr, cfg, args, execution, context: current, task, research: state }),
      readEvidence: snapshot => {
        const artifacts = mgr.analysis.artifacts;
        if (artifacts.metadata(snapshot.report_id).result.recordSha256 !== snapshot.report_sha256) fail('ARTIFACT_CHANGED', 'Stored report digest differs from the task reference');
        const report = artifacts.get(snapshot.report_id);
        validateSnapshotReport(snapshot, report);
        return report.result;
      }, capabilities: capabilityCatalog(mgr, cfg, { engine: scope.engine, ownQueue: true }), failures, failureHistoryError,
      maxBytes: input.max_bytes, cursor: input.cursor }) };
  }
  if (action === 'create') {
    fields(input, ['action', 'goal', 'hypothesis', 'next_step']);
    const { action: unused, ...value } = input;
    return { workspace: notes.create(scope, value, actor(execution)) };
  }
  if (action === 'get') {
    fields(input, ['action', 'id']);
    return { workspace: notes.get(scope, id) };
  }
  if (action === 'list') {
    fields(input, ['action']);
    const result = notes.list(scope);
    return { workspace: { ...result, tasks: result.tasks.map(task => ({
      taskId: task.taskId, taskRevision: task.taskRevision, status: task.status,
      goal: task.goal.slice(0, 256), goalTruncated: task.goal.length > 256,
      observations: task.systemEvidence.length,
      staleObservations: task.systemEvidence.filter(entry => entry.stale).length,
      progressIsCallerDeclared: true,
    })) } };
  }
  if (action === 'update') {
    fields(input, ['action', 'id', 'expected_task_revision', 'goal', 'hypothesis', 'next_step', 'conclusion', 'status']);
    const { action: unused, id: unusedId, ...value } = input;
    return { workspace: notes.update(scope, id, value, actor(execution)) };
  }
  if (action === 'claim' || action === 'submit') {
    fields(input, ['action', 'id', 'handoff_id', 'expected_task_revision', ...(action === 'submit' ? ['snapshot_ids'] : [])]);
    const task = notes.get(scope, id);
    if (task.taskRevision !== input.expected_task_revision) fail('STALE_TASK_REVISION', 'Read current task revision before claim or submit');
    if (!mgr.coordination) fail('DELEGATION_UNAVAILABLE', 'Controlled delegation requires the DSH lifecycle bridge');
    if (action === 'claim') return { workspace: mgr.coordination.claim(execution?.agent, input.handoff_id, task, scope) };
    const ids = input.snapshot_ids;
    if (!Array.isArray(ids) || !ids.length || ids.length > 8 || new Set(ids).size !== ids.length || ids.some(x => typeof x !== 'string')) fail('INVALID_ARGUMENT', 'submit requires 1..8 distinct snapshot IDs');
    const snapshots = ids.map(snapshot_id => {
      const snapshot = task.systemEvidence.find(s => s.snapshot_id === snapshot_id);
      if (!snapshot) fail('INVALID_REF', 'Submitted snapshot does not belong to the task');
      return snapshot;
    });
    return { workspace: mgr.coordination.submit(execution?.agent, input.handoff_id, task, scope, snapshots) };
  }
  if (action === 'handoff' || action === 'review') {
    fields(input, action === 'handoff'
      ? ['action', 'id', 'expected_task_revision', 'question', 'acceptance', 'constraints']
      : ['action', 'id', 'expected_task_revision', 'snapshot_ids', 'handoff_id']);
    const by = actor(execution), task = notes.get(scope, id);
    if (!Number.isSafeInteger(input.expected_task_revision) || input.expected_task_revision !== task.taskRevision) {
      fail('STALE_TASK_REVISION', 'Read the task and provide its current expected_task_revision before handoff or review');
    }
    const base = { schemaVersion: 1, taskId: id, taskRevision: task.taskRevision, context: scope,
      requestedBy: by, goal: task.goal, taskStatus: task.status,
      statements: { hypothesis: task.hypothesis, next_step: task.next_step, conclusion: task.conclusion },
      statementOrigin: 'caller-statement', executionAuthorized: false, databaseModified: false,
      taskModified: false, semanticAcceptanceVerified: false };
    if (action === 'handoff') {
      for (const key of ['question', 'acceptance', 'constraints']) {
        if (typeof input[key] !== 'string' || !input[key].trim() || input[key].length > 2048 || input[key].includes('\0')) {
          fail('INVALID_ARGUMENT', `handoff requires nonempty ${key} of at most 2048 characters`);
        }
      }
      return { workspace: { ...base, kind: 'investigation-handoff',
        ...(mgr.coordination && execution?.agent?.session?.header
          ? mgr.coordination.handoff(execution.agent, task, scope)
          : { mode: 'untracked', delegationVerified: false, note: 'No reliable DSH session lineage; formal post-return review unavailable.' }),
        contract: { question: input.question, acceptance: input.acceptance, constraints: input.constraints,
          origin: 'caller-statement', enforced: false },
        evidence: task.systemEvidence, reportsVerified: false,
        startup: [
          'Read ig5_workspace in your own agent scope; enable full only when needed.',
          'Claim handoffId via workspace claim/handoff_id, then read this task again with explicit target and engine; stop if task/database/attachment changed.',
          'Locate the relevant input, processing functions, output and unresolved question; reuse existing evidence before collecting more.',
          'Read selected workspace evidence reports, including partial/truncated/unavailable sections; references alone are not verified reports.',
          'Submit actually read snapshot_ids via workspace submit/handoff_id/current expected_task_revision, then return candidates, coverage and unknowns and finish. Do not mark the shared task completed.',
        ],
        coordination: { sessionsShared: true, constraintsEnforced: false,
          staticWrites: 'Coordinate one writer per database; queues serialize execution, not conflicting intentions.',
          debugControl: 'Existing agent ownership, takeover and public approvals still apply.',
          scheduling: 'The DSH parent dispatches agents; this packet does not spawn or message them.' },
        returnContract: ['taskId', 'taskRevision', 'context', 'candidateConclusion', 'snapshot_ids', 'coverage', 'unknowns', 'next_action'],
      } };
    }
    const ids = input.snapshot_ids;
    if (!Array.isArray(ids) || ids.length < 1 || ids.length > 8 || new Set(ids).size !== ids.length
      || ids.some(value => typeof value !== 'string')) fail('INVALID_ARGUMENT', 'review requires 1..8 distinct task snapshot IDs');
    let delegation = { reviewStage: 'integrity-precheck', delegationVerified: false };
    if (input.handoff_id !== undefined) {
      if (!mgr.coordination) fail('DELEGATION_UNAVAILABLE', 'Controlled review requires the DSH lifecycle bridge');
      delegation = mgr.coordination.review(execution.agent, input.handoff_id, task, scope, ids);
    }
    const evidence = ids.map(snapshot_id => {
      const checked = runWorkspace(mgr, cfg, { target: args.target, workspace: { action: 'evidence', id, snapshot_id } }, execution).workspace;
      return { snapshot: checked.snapshot, analysis: checked.report.analysis,
        responseTruncated: checked.report.responseTruncated,
        sections: Object.fromEntries(Object.entries(checked.report.sections).map(([key, section]) => [key, { status: section.status }])),
        limitations: checked.report.limitations };
    });
    return { workspace: { ...base, ...delegation, kind: 'investigation-evidence-review', reportsVerified: true,
      evidence, staleEvidence: evidence.some(row => row.snapshot.stale),
      note: 'Digest, task membership and provenance were checked. Inspect complete evidence reports and independently assess the acceptance criteria; this does not approve a conclusion or complete a task.' } };
  }
  if (action === 'evidence') {
    fields(input, ['action', 'id', 'snapshot_id']);
    const task = notes.get(scope, id);
    const snapshot = task.systemEvidence.find(entry => entry.snapshot_id === input.snapshot_id);
    if (!snapshot) fail('INVALID_REF', 'Choose a system snapshot belonging to this task');
    const artifacts = mgr.analysis.artifacts;
    const metadata = artifacts.metadata(snapshot.report_id).result;
    if (metadata.recordSha256 !== snapshot.report_sha256) fail('ARTIFACT_CHANGED', 'Stored report digest differs from the task reference');
    const report = artifacts.get(snapshot.report_id);
    validateSnapshotReport(snapshot, report);
    mgr.coordination?.read(execution?.agent, snapshot);
    return { workspace: { taskId: task.taskId, taskRevision: task.taskRevision, snapshot, report: report.result,
      note: 'Historical observations retain their original scope; stale observations require another capture.' } };
  }
  fail('INVALID_ARGUMENT', 'workspace action must be create, get, list, update, evidence, handoff, claim, submit or review');
}

/** Only a system-produced, queued dossier can reach this evidence-writing path. */
export function captureDossier(mgr, cfg, dossier, taskId, execution) {
  const notes = store(mgr, cfg), scope = dossier.provenance, agentId = actor(execution);
  const task = notes.get(scope, taskId);
  const existing = task.systemEvidence.find(entry => entry.digest === dossier.snapshotDigest);
  if (existing) {
    const meta = mgr.analysis.artifacts.metadata(existing.report_id).result;
    if (meta.recordSha256 !== existing.report_sha256) fail('ARTIFACT_CHANGED', 'Existing observation report has changed');
    validateSnapshotReport(existing, mgr.analysis.artifacts.get(existing.report_id));
    return { ok: true, taskId: task.taskId, taskRevision: task.taskRevision, snapshotId: existing.snapshot_id,
      reportId: existing.report_id, reportSha256: existing.report_sha256, duplicate: true };
  }
  mgr.checkCancelled();
  let record, reportSha256 = null, stage = 'report-save';
  try {
    record = mgr.analysis.artifacts.save({ kind: 'function-dossier', action: 'capture', association: scope,
      result: jsonToolOutput(dossier) });
    stage = 'report-verify';
    reportSha256 = mgr.analysis.artifacts.metadata(record.id).result.recordSha256;
    stage = 'task-link';
    const updated = notes.recordSnapshot(scope, taskId, { digest: dossier.snapshotDigest, report_id: record.id,
      report_sha256: reportSha256, function: { ea: dossier.function.ea,
        ...(dossier.function.name ? { name: dossier.function.name.slice(0, 256), ...(dossier.function.name.length > 256 ? { nameTruncated: true } : {}) } : {}) },
      sections: Object.keys(dossier.sections) }, agentId);
    const snapshot = updated.systemEvidence.find(entry => entry.digest === dossier.snapshotDigest);
    return { ok: true, taskId: updated.taskId, taskRevision: updated.taskRevision, snapshotId: snapshot.snapshot_id,
      reportId: snapshot.report_id, reportSha256: snapshot.report_sha256, duplicate: updated.snapshotDeduplicated === true,
      ...(updated.snapshotDeduplicated ? { unusedReportId: record.id, note: 'A concurrent capture already linked this observation; the additional saved report remains retained.' } : {}) };
  } catch (error) {
    // Report creation and task linkage are separate commits. Preserve that fact.
    return { ok: false, taskId, ...(record ? { reportId: record.id } : {}), reportSha256, reportSaved: !!record, taskLinked: false, stage,
      error: String(error.message).slice(0, 512), code: error.code || 'TASK_LINK_FAILED',
      note: record ? 'The report save returned successfully, but verification or task linkage failed. Read the task before retrying; no engine database was changed.'
        : 'Report saving did not complete. Partial report files may remain; no task link or engine database change was made.' };
  }
}

/** Await only the fixed owned data job. Association is a separate CAS commit. */
async function runResearchVerification(mgr, args, input, notes, service, task, state, by, signal) {
  let receipt;
  if (input.action === 'research-link-verification') {
    exactReportRef(input.report_ref);
    const ref = { reportId: input.report_ref.id, sha256: input.report_ref.sha256 };
    if (!state) fail('RESEARCH_NOT_FOUND', 'Initialize research first');
    const result = loadVerification(mgr.analysis.artifacts, task, state, ref);
    if (result.evidenceId !== input.verification.evidence_id || result.obligationId !== input.verification.obligation_id
      || (result.experimentId || undefined) !== input.verification.experiment_id) fail('INVALID_RESEARCH_REF', 'Receipt does not match requested evidence/obligation/experiment');
    receipt = { ref, result, reportSaved: true, dataWorkerCleanupConfirmed: null };
  } else receipt = await verifyResearch(mgr, task, state, input.verification, mgr.scope?.getStore()?.signal || signal);
  if (receipt.publicationFailure) return { workspace: { reportSaved: receipt.reportSaved, recordSaved: receipt.recordSaved,
    ...(receipt.ref ? { reportId: receipt.ref.reportId, reportSha256: receipt.ref.sha256 } : {}), linked: false, stage: 'verification-publication',
    verifierStatus: receipt.result.status, status: 'error', code: receipt.code, error: receipt.error,
    dataWorkerCleanupConfirmed: receipt.dataWorkerCleanupConfirmed, executionAuthorized: false, businessAccepted: false } };
  const base = { reportSaved: true, reportId: receipt.ref.reportId, reportSha256: receipt.ref.sha256,
    status: receipt.result.status, dataWorkerCleanupConfirmed: receipt.dataWorkerCleanupConfirmed, executionAuthorized: false, businessAccepted: false };
  let linked;
  try {
    const currentScope = context(mgr, args), currentTask = notes.get(currentScope, task.taskId), current = service.get(currentTask, currentScope);
    loadVerification(mgr.analysis.artifacts, currentTask, current, receipt.ref);
    linked = service.linkVerification(currentTask, currentScope, input.verification, receipt.ref, by);
  } catch (error) {
    return { workspace: { ...base, linked: false, stage: 'research-cas', code: error.code || 'VERIFICATION_LINK_FAILED',
      note: 'Full immutable verifier result retained. Reread revisions and recover with research-link-verification; do not rerun the experiment.' } };
  }
  try {
    const finalScope = context(mgr, args), finalTask = notes.get(finalScope, task.taskId), finalState = service.get(finalTask, finalScope);
    return { workspace: { ...base, linked: true, writtenResearchRevision: linked.researchRevision,
      research: verificationOverlay(mgr.analysis.artifacts, finalTask, finalState), postCommitContext: 'read' } };
  } catch (error) {
    return { workspace: { ...base, linked: true, writtenResearchRevision: linked.researchRevision,
      postCommitContext: 'unavailable', code: error.code || 'VERIFICATION_CONTEXT_UNAVAILABLE' } };
  }
}
