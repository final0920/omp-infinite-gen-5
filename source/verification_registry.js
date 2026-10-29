import { jsonToolOutput } from './json_output.js';
import { hashBytes } from './analysis_artifacts.js';
import { vmContextEvidence, evidenceReadBudget, committedBytes, exactReportRef } from './evidence_adapters/vm_context.js';
import { researchDigest } from './research_state.js';
import { typedVerificationResult, verifierIdentity, VERIFICATION_STATUSES } from './verification_result.js';

import { fixedPropertyEvidence } from './evidence_adapters/fixed_properties.js';
import { registeredVerifier } from './verifier_catalog.js';
import { CONTEXT_PROPERTY, MODEL_PROPERTY, RECORDED_PROPERTY, PROVENANCE_PROPERTY, samePropertyScope } from './research_properties.js';
import { validateReceiptShape } from './verification_schema.js';
import { evaluateObligations } from './obligation_evaluator.js';

const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
export const verificationRequestSchema = { type: 'object', properties: {
  expected_research_revision: { type: 'integer', minimum: 0 }, expected_task_revision: { type: 'integer', minimum: 0 },
  scope_digest: { type: 'string', pattern: SHA.source }, evidence_id: { type: 'string', pattern: UUID.source }, obligation_id: { type: 'string', pattern: UUID.source },
  experiment_id: { type: 'string', pattern: UUID.source },
}, required: ['expected_research_revision', 'expected_task_revision', 'scope_digest', 'evidence_id', 'obligation_id'], additionalProperties: false };
export function validateVerificationRequest(value) {
  const v = jsonToolOutput(value);
  if (!v || typeof v !== 'object' || Array.isArray(v) || Object.keys(v).some(k => !Object.hasOwn(verificationRequestSchema.properties, k))
    || !Number.isSafeInteger(v.expected_research_revision) || v.expected_research_revision < 0
    || !Number.isSafeInteger(v.expected_task_revision) || v.expected_task_revision < 0 || !SHA.test(v.scope_digest)
    || !UUID.test(v.evidence_id) || !UUID.test(v.obligation_id) || v.experiment_id !== undefined && !UUID.test(v.experiment_id)) fail('INVALID_VERIFICATION', 'Fixed verification requires exact revision/scope/evidence/obligation identifiers');
  return v;
}
function selection(state, input) {
  const evidence = state.evidenceLinks.find(e => e.id === input.evidence_id), obligation = state.obligations.find(o => o.id === input.obligation_id);
  if (!evidence || !obligation || evidence.contractRevision !== state.contractRevision || obligation.contractRevision !== state.contractRevision
    || state.obligations.some(o => o.supersedes === obligation.id)) fail('INVALID_RESEARCH_REF', 'Choose current contract evidence and an unsuperseded obligation');
  if (!['vm-context-model','vm-function-assessment','vm-role-validation'].includes(evidence.kind)) fail('UNSUPPORTED_VERIFIER', 'No fixed verifier for this evidence kind');
  if (input.experiment_id) {
    const experiment = state.experiments.find(e => e.id === input.experiment_id);
    if (!experiment || experiment.contractRevision !== state.contractRevision || state.experiments.some(e => e.supersedes === experiment.id)
      || experiment.value.template !== 'review-evidence' || !experiment.value.inputs.includes(evidence.id)
      || !experiment.value.obligations.includes(obligation.id)) fail('INVALID_RESEARCH_REF', 'Experiment must be a current review-evidence proposal bound to these inputs and obligation');
  }
  return { evidence, obligation };
}
function entryFor(property) { try { return registeredVerifier(property); } catch { return registeredVerifier(CONTEXT_PROPERTY); } }
function exactSupported(obligation,evidence,loaded) {
  const entry=entryFor(obligation.value.property);
  if(entry.propertyId!==obligation.value.property || entry.evidenceKind!==evidence.kind || obligation.value.verifier!==entry.id
    || obligation.value.scope!==`evidence:${evidence.id}`)return false;
  return entry.propertyId===CONTEXT_PROPERTY ? obligation.value.propertyScope===undefined
    : samePropertyScope(obligation.value.propertyScope,loaded.link.propertyScopes?.[entry.propertyId]);
}
function loadInputs(artifacts,task,evidence,budget,property) {
  return evidence.kind==='vm-context-model'?vmContextEvidence(artifacts,task,{id:evidence.reportId,sha256:evidence.sha256},budget)
    : fixedPropertyEvidence(artifacts,task,{id:evidence.reportId,sha256:evidence.sha256},budget,property);
}
function inputRefs(loaded) { return loaded.inputRefs ?? [loaded.request.root,...loaded.request.parents].map(({id,sha256})=>({id,sha256})); }
function receiptScopeCheck(result,args,loaded) {
  if(result.schema==='ig5-verification-result-v1')return; // Readable history only; overlay never promotes v1 to a typed result.
  const expected=typedVerificationResult(args,loaded);
  for(const key of ['propertyId','result','contractRef','obligationRef','subjectRef','scope','verifier','cleanup'])
    if(researchDigest(result[key])!==researchDigest(expected[key]))fail('INVALID_VERIFICATION','Typed receipt binding differs: '+key);
}

export function loadVerification(artifacts, task, state, ref, budget = evidenceReadBudget()) {
  const proof = committedBytes(artifacts, { id: ref.reportId, sha256: ref.sha256 }, 'research-verification', 'verify', budget).record;
  const result = proof.result, identity = verifierIdentity(entryFor(result?.property).propertyId);
  if (!['ig5-verification-result-v1','ig5-verification-result-v2'].includes(result?.schema) || result.taskId !== task.taskId || result.scopeDigest !== state.scopeDigest
    || result.contractDigest !== state.contractDigest || result.contractRevision !== state.contractRevision
    || !VERIFICATION_STATUSES.includes(result.status) || result.outcome?.status !== result.status
    || result.businessAccepted !== false || result.nativeTargetExecuted !== false || result.databaseModified !== false || result.changesExecutionAuthority !== false) fail('STALE_VERIFICATION', 'Verifier identity, contract or receipt changed');
  if(result.schema==='ig5-verification-result-v1')fail('LEGACY_VERIFICATION_READ_ONLY','V1 receipt is retained for historical reading only');
  validateReceiptShape(result);
  const { evidence, obligation } = selection(state, { evidence_id: result.evidenceId, obligation_id: result.obligationId, ...(result.experimentId ? { experiment_id: result.experimentId } : {}) });
  if (hashBytes(Buffer.from(JSON.stringify(obligation))) !== result.obligationDigest || obligation.value.property !== result.property) fail('STALE_VERIFICATION', 'Obligation changed');
  if (result.verifierId !== identity.verifierId || result.rulesDigest !== identity.rulesDigest || result.runtimeDigest !== identity.runtimeDigest
    || researchDigest(result.code) !== researchDigest(identity.code) || researchDigest(result.runtime) !== researchDigest(identity.runtime)) {
    throw Object.assign(new Error('Verifier rules or runtime changed; the old receipt remains historical'), { code: 'VERIFIER_IDENTITY_CHANGED',
      verificationBinding: { obligationId: obligation.id, evidenceId: evidence.id, experimentId: result.experimentId } });
  }
  const loaded = loadInputs(artifacts,task,evidence,budget,result.property);
  if (researchDigest(result.inputRefs) !== researchDigest(inputRefs(loaded)) || researchDigest(loaded.link.parents) !== researchDigest(evidence.parents)) fail('STALE_VERIFICATION', 'Input or typed parent closure differs');
  if ((result.status === 'pass'||result.status==='fail'&&result.outcome.counterexampleValid===true) && (!exactSupported(obligation, evidence, loaded) || result.outcome.nativeTargetExecuted !== false || result.outcome.businessAccepted !== false
    || result.outcome.dataWorkerCleanupConfirmed !== true)) fail('INVALID_VERIFICATION', 'Receipt tries to close an unsupported property or lacks its owned worker cleanup');
  receiptScopeCheck(result,{task,state,obligation,evidence,experimentId:result.experimentId,outcome:result.outcome,inputRefs:result.inputRefs},loaded);
  return result;
}

/** Historical results remain readable even when they cannot support the current contract. */
export function readVerificationReport(artifacts, task, state, ref) {
  const full = committedBytes(artifacts, { id: ref.reportId, sha256: ref.sha256 }, 'research-verification', 'verify').record.result;
  if (!['ig5-verification-result-v1','ig5-verification-result-v2'].includes(full?.schema) || full.taskId !== task.taskId || full.scopeDigest !== state.scopeDigest
    || state.contracts[full.contractRevision]?.digest !== full.contractDigest) fail('INVALID_RESEARCH_REF', 'Historical result is not bound to this research contract history');
  let assessment;
  try { loadVerification(artifacts, task, state, ref); assessment = { status: 'current-inputs-verified', validity:'current' }; }
  catch (error) { assessment = { status: 'stale-or-unverified', validity:['STALE_VERIFICATION','VERIFIER_IDENTITY_CHANGED','VERIFIER_CODE_CHANGED'].includes(error.code)?'stale':'unverified', code: error.code || 'VERIFICATION_READ_FAILED' }; }
  return { result: full, currentAssessment: assessment };
}

/** Revalidate committed result references, never treat the sidecar as a verdict authority. */
export function verificationOverlay(artifacts, task, state) {
  if (!state) return state;
  if(state.schema==='ig5-research-state-v1'&&!state.verificationRefs?.length)return state;
  if(!state.verificationRefs?.length)return {...state,objectStates:{...state.objectStates,obligations:evaluateObligations(state,[])}};
  const budget = evidenceReadBudget(), checked = [];
  const selected = state.verificationRefs.slice(-8), older = state.verificationRefs.length - selected.length;
  for (const ref of selected) {
    try {
      const result = loadVerification(artifacts, task, state, ref, budget);
      const row = { reportId: ref.reportId, sha256: ref.sha256, obligationId: result.obligationId, evidenceId: result.evidenceId,
        experimentId: result.experimentId, status: result.status, integrity: result.schema==='ig5-verification-result-v2'?'verified':'unverified', property: result.property, counterexampleValid:result.outcome.counterexampleValid===true, validity:'current' };
      checked.push(row);
    } catch (error) {
      let binding=error.verificationBinding,historicalInputFailure=false;
      if(!binding) { try {
        const old=committedBytes(artifacts,{id:ref.reportId,sha256:ref.sha256},'research-verification','verify',budget).record.result;
        if(old?.taskId===task.taskId){binding={obligationId:old.obligationId,evidenceId:old.evidenceId,experimentId:old.experimentId};
          historicalInputFailure=old.status==='pass'&&state.evidenceLinks.find(e=>e.id===old.evidenceId)?.kind!=='vm-context-model'
            &&['ARTIFACT_CHANGED','INVALID_VM_OBSERVATION','ENOENT','UNSUPPORTED_EVIDENCE','INVALID_RESEARCH_REF'].includes(error.code);}
      } catch { /* Byte corruption is unverified, never an authenticated old pass. */ } }
      const validity=historicalInputFailure||['STALE_VERIFICATION','VERIFIER_IDENTITY_CHANGED','VERIFIER_CODE_CHANGED'].includes(error.code)?'stale':'unverified';
      checked.push({...ref,...binding,status:'unknown',integrity:validity,validity,code:error.code||'VERIFICATION_READ_FAILED'});
    }
  }
  const projectionComplete=older===0&&!checked.some(p=>['EVIDENCE_READ_LIMIT','INPUT_LIMIT'].includes(p.code));
  const obligations=evaluateObligations(state,checked,{complete:projectionComplete});
  const passed=new Set(obligations.filter(o=>o.status==='closed-in-scope').map(o=>o.id));
  const experiments = state.objectStates.experiments.map(row => ({ ...row, resultRefs: checked.filter(p => p.integrity === 'verified' && p.experimentId === row.id)
    .map(p => ({ reportId: p.reportId, sha256: p.sha256, status: p.status })),
  }));
  return { ...state, objectStates: { ...state.objectStates, obligations, experiments },
    acceptanceStatus: passed.size ? 'partial' : 'unknown',
    verification: { checked, omittedOlder: older, complete: older === 0 && checked.every(p => p.integrity === 'verified'),
      note: 'Only the named evidence-bound property may close. A local pass never accepts the full function contract.' } };
}

/** Fixed data-worker action. No executable, path, script or verifier override is accepted. */
export async function verifyResearch(mgr, task, state, input, signal) {
  const v = validateVerificationRequest(input);
  if (!state || state.researchRevision !== v.expected_research_revision || task.taskRevision !== v.expected_task_revision) fail('STALE_RESEARCH_REVISION', 'Read current task/research before verification');
  if (state.scopeDigest !== v.scope_digest || state.stale) fail('STALE_RESEARCH_CONTEXT', 'Review and acknowledge current research context first');
  const { evidence, obligation } = selection(state, v);
  mgr.checkCancelled();
  const loaded=loadInputs(mgr.analysis.artifacts,task,evidence,evidenceReadBudget(),obligation.value.property);
  const entry=entryFor(obligation.value.property);
  let outcome, dataWorkerCleanupConfirmed = null;
  const experiment = v.experiment_id ? state.experiments.find(e => e.id === v.experiment_id) : null;
  const inputBytes = loaded.inputBytes ?? loaded.request.root.bytes.length + loaded.request.parents.reduce((sum,p)=>sum+p.bytes.length,0);
  if (!exactSupported(obligation, evidence, loaded)) outcome = { status: 'unsupported', reason: 'Only a fixed registered property with exact evidence, subject, contract, domain and environment is supported.' };
  else if (experiment && (experiment.value.budget.bytes < inputBytes || experiment.value.budget.timeoutMs < mgr.analysis.jobs.timeoutMs)) {
    outcome = { status: 'unsupported', reason: 'The proposed experiment budget is smaller than the fixed verifier input or worker envelope; revise the proposal explicitly.' };
  }
  else {
    const current = verificationOverlay(mgr.analysis.artifacts, task, state);
    if (obligation.value.dependencies.some(id => current.objectStates.obligations.find(o => o.id === id)?.status !== 'closed-in-scope')) outcome = { status: 'unknown', reason: 'Unresolved prerequisite obligations' };
    else {
      verifierIdentity(entry.propertyId);
      try {
        if(mgr.analysis.jobs.timeoutMs>entry.budget.timeoutMs) fail('VERIFIER_BUDGET','Configured data worker exceeds the fixed verifier envelope');
        const raw=await mgr.analysis.jobs.runSettled(entry.workerKind,loaded.request,signal);dataWorkerCleanupConfirmed=true;
        outcome=propertyOutcome(entry.propertyId,raw,loaded);
        verifierIdentity(entry.propertyId);
      }
      catch (error) {
        if (signal?.aborted || error.code === 'ABORT_ERR') throw error;
        dataWorkerCleanupConfirmed = error.cleanupConfirmed === false ? false : ['TIMEOUT', 'ANALYSIS_FAILED', 'WORKER_EXIT'].includes(error.code) ? true : null;
        outcome = { status: ['TIMEOUT', 'BUSY'].includes(error.code) ? 'unknown' : 'error', code: error.code || 'VERIFIER_ERROR', reason: String(error.message).slice(0, 512) };
      }
    }
  }
  mgr.checkCancelled();
  outcome = { ...outcome, dataWorkerCleanupConfirmed };
  const result = typedVerificationResult({ task, state, obligation, evidence, experimentId: v.experiment_id, outcome, inputRefs: inputRefs(loaded) },loaded);
  let saved;
  try {
    saved = mgr.analysis.artifacts.save({ kind: 'research-verification', action: 'verify', association: { taskId: task.taskId, scopeDigest: state.scopeDigest }, result }, { maxBytes: 256 * 1024 });
    const sha256 = mgr.analysis.artifacts.metadata(saved.id).result.recordSha256;
    return { ref: { reportId: saved.id, sha256 }, result, reportSaved: true, dataWorkerCleanupConfirmed };
  } catch (error) {
    const commit = error.analysisArtifactCommit;
    let reportSaved = false;
    const ref = saved ? { reportId: saved.id, sha256: hashBytes(Buffer.from(JSON.stringify(saved))) }
      : commit ? { reportId: commit.id, sha256: commit.sha256 } : null;
    if (ref) {
      try {
        committedBytes(mgr.analysis.artifacts, { id: ref.reportId, sha256: ref.sha256 }, 'research-verification', 'verify');
        reportSaved = true;
      } catch { /* Missing metadata is not a committed, readable report. */ }
    }
    return { publicationFailure: true, reportSaved, recordSaved: !!saved || commit?.recordSaved === true, ref, result, dataWorkerCleanupConfirmed,
      code: error.code || 'VERIFICATION_PUBLICATION_FAILED', error: String(error.message).slice(0, 512) };
  }
}

function propertyOutcome(property,raw,loaded) {
  if(property===CONTEXT_PROPERTY)return {...raw,counterexampleValid:raw.status==='fail'&&!!raw.witness};
  if(property===MODEL_PROPERTY) {
    if(raw.schema!=='ig5-finite-function-verification-v1'||raw.targetSha256!==loaded.request.contract.targetSha256||raw.businessAccepted!==false)fail('INVALID_VERIFICATION','Unexpected model verifier output');
    return {status:raw.witness?'fail':raw.exhaustiveFiniteDomain===true&&raw.modelContractAccepted===true?'pass':'unknown',
      counterexampleValid:!!raw.witness,coverage:raw.scope,witness:raw.witness,modelCases:raw.finiteTesting.cases,
      nativeTargetExecuted:false,businessAccepted:false,modelResult:raw};
  }
  if(property===PROVENANCE_PROPERTY&&(raw.schema!=='ig5-recorded-role-validation-v1'||raw.targetSha256!==loaded.request.contract.targetSha256||raw.vmRoleProved!==false||raw.nativeTargetExecuted!==false))fail('INVALID_VERIFICATION','Unexpected provenance verifier output');
  if(property===RECORDED_PROPERTY&&(raw.freshNativeExecution!==false||raw.nativeCpuEquivalenceProved!==false||raw.cpuWriteFootprintProved!==false))fail('INVALID_VERIFICATION','Unexpected recorded verifier scope');
  const runs=raw.runs;
  if(!Array.isArray(runs)||runs.length!==loaded.recordingRuns.length)fail('INVALID_VERIFICATION','Recorded run manifest differs');
  if(runs.some((run,i)=>researchDigest(run.recordingRefs)!==researchDigest(loaded.recordingRuns[i])))fail('INVALID_VERIFICATION','Worker recording source references differ');
  const inputs=[...new Set(property===RECORDED_PROPERTY?runs.filter(r=>r.inDomain).map(r=>r.input):runs.filter(r=>r.inputInDomain).map(r=>r.input.value))].sort();
  const expected=loaded.link.propertyScopes[property]?.domain;
  if(!expected||researchDigest(inputs)!==researchDigest(expected.inputs))return {status:'unknown',reason:'Actual entry inputs differ from the committed scope',nativeTargetExecuted:false,businessAccepted:false};
  if(property===PROVENANCE_PROPERTY)return {status:runs.every(r=>r.rawCaptureRevalidated&&r.matchedGroups>0)?'pass':'unknown',coverage:expected,
    nativeTargetExecuted:false,businessAccepted:false,recordedResult:raw};
  const scopedRuns=runs.filter(r=>r.inDomain),failed=scopedRuns.some(r=>r.status==='fail');
  return {status:failed?'fail':scopedRuns.length&&scopedRuns.every(r=>r.status==='pass')?'pass':'unknown',counterexampleValid:failed,
    coverage:expected,outOfDomainRuns:runs.length-scopedRuns.length,recordedResult:raw,nativeTargetExecuted:false,businessAccepted:false};
}
