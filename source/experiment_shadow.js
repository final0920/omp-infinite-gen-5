import { METHOD_SPECS } from './method_registry.js';
import { captureMethodInputs, evaluateMethodCapture } from './method_applicability.js';
import { planningDigest, planningRequestKey } from './planning_identity.js';
import { planningImplementationDigest } from './planning_runtime.js';

export const SHADOW_VERSION='20261024-experiment-shadow-1';
const fail=(code,message)=>{throw Object.assign(new Error(message),{code});};
const clip=s=>String(s||'').slice(0,512);
export function validateShadowInput(input){
 if(!input||typeof input!=='object'||Array.isArray(input)||input.action!=='experiment-shadow'||Object.keys(input).some(k=>!['action','id','mode','max_bytes'].includes(k)))fail('INVALID_ARGUMENT','Invalid experiment shadow fields');
 if(input.mode!==undefined&&!['off','shadow'].includes(input.mode))fail('INVALID_ARGUMENT','Only off/shadow is available; assist has no accepted benefit evidence');
 if(input.max_bytes!==undefined&&(!Number.isSafeInteger(input.max_bytes)||input.max_bytes<4096||input.max_bytes>32768))fail('INVALID_ARGUMENT','Shadow max_bytes must be 4096..32768');
}
const templates=Object.freeze({
 'known-result-readback':['read-reported-result','Current reported output can be reused for extraction; recovering every algorithm remains a separate unresolved question.',0],
 'address-space-check':['read-bound-source','Check address space and source identity before interpreting addresses.',1],
 'truncated-source-completion':['complete-static-source','Larger bounded source may reveal omitted calls or source; still-truncated output requires another explicit decision.',1],
 'argument-prototype-check':['read-bound-source','Check arguments, ABI and widths; stack/call names alone cannot establish a prototype.',1],
 'conflicting-evidence-review':['review-declared-conflict','Read both declared supporting and opposing sources; different contracts or instances can explain the apparent conflict.',2],
 'callee-family-grouping':['compare-callee-sources','Compare two distinct observed callee bodies while retaining seed/table/input differences as unknown.',3],
 'vm-instance-separation':['compare-callee-sources','Seek distinguishing dataflow or parameters; different addresses do not prove different algorithms, equal structure does not prove equivalence.',3],
});
export const SHADOW_TEMPLATES=Object.freeze([...new Set(Object.values(templates).map(t=>t[0]))]);
/** Fixed templates only, over already hash-bound host observations. No native calls or article interpretation. */
export function draftShadowProposals(data,capture,receipts,planning){
 if(!capture.ready)return [];
 const {context,task}=data,rows=capture.projection.records,dossiers=rows.filter(r=>r.kind==='function-dossier'&&r.status==='observed');
 const snapshotOf=row=>task.systemEvidence.find(s=>s.report_id===row.sourceRef.id&&s.report_sha256===row.sourceRef.sha256);
 const drafts=[];
 for(const receipt of receipts){
  const template=templates[receipt.methodId];if(receipt.status!=='applicable'||!template)continue;
  const method=METHOD_SPECS.find(m=>m.id===receipt.methodId),[templateId,question,priority]=template;
  const selected=receipt.methodId==='truncated-source-completion'?dossiers.filter(r=>Object.values(r.sourceData.sections||{}).some(s=>s.status==='truncated'))
   :templateId==='compare-callee-sources'?dossiers.filter(r=>{
    const calls=r.sourceData.sections?.callees?.data?.calls;
    return Array.isArray(calls)&&new Set(calls.map(c=>c?.ea).filter(e=>typeof e==='string'&&/^0x[0-9a-f]+$/i.test(e)).map(e=>BigInt(e).toString(16))).size>1;
   }):templateId==='read-bound-source'?dossiers: [null];
  // At most 8 source snapshots per method, as in F04. Each pair gives two one-call collection proposals.
  for(const row of selected){
   const snapshot=row?snapshotOf(row):null;if(row&&!snapshot)continue;
   const pair=templateId==='compare-callee-sources'?[...new Set(row.sourceData.sections.callees.data.calls.map(c=>c?.ea).filter(e=>typeof e==='string'&&/^0x[0-9a-f]+$/i.test(e)).map(e=>'0x'+BigInt(e).toString(16)))].sort((a,b)=>BigInt(a)<BigInt(b)?-1:1).slice(0,2):null;
   for(const ea of pair||[null]){
    let request;
    if(templateId==='read-reported-result')request={tool:'ig5_workspace',target:context.target,engine:context.engine,workspace:{action:'get',id:task.taskId}};
    else if(templateId==='review-declared-conflict')request={tool:'ig5_workspace',target:context.target,engine:context.engine,workspace:{action:'research-get',id:task.taskId}};
    else if(templateId==='complete-static-source'||pair)request={tool:'ig5_decompile',target:context.target,engine:context.engine,ea:ea||snapshot.function.ea,style:'dossier',task_id:task.taskId,dossier_max_bytes:64000,dossier_max_rows:128};
    else request={tool:'ig5_workspace',target:context.target,engine:context.engine,workspace:{action:'evidence',id:task.taskId,snapshot_id:snapshot.snapshot_id}};
    const native=request.tool==='ig5_decompile',inputRefs=row?[{...row.sourceRef,projectionDigest:row.projectionDigest}]:receipt.predicates[method.requiredPredicates[0]]?.evidenceRefs.map(e=>({...e.ref,projectionDigest:e.projectionDigest}))||[];
    const competingHypotheses=pair?['Shared transformation with different seed/table/input parameters','Distinct local transformations or VM instances; independently test this alternative']
     :templateId==='complete-static-source'?['Omitted source contains a missing call/condition','Complete source still leaves the hypothesis unresolved']
     :templateId==='review-declared-conflict'?['Sources concern different contracts/instances or stale observations','Current sources require an unresolved semantic conflict review']
     :['Current source supplies the requested bounded information','Source remains incomplete or does not establish the requested claim'];
    const scope={...capture.binding.scope,functionEA:snapshot?.function.ea||null,expressionDigest:null,comparisonPair:pair,selectedCallee:ea,
     contractRevision:capture.binding.contractRevision,contractDigest:capture.binding.contractDigest};
    const estimatedCost={publicToolCalls:1,inputBytes:row?128*1024:0,band:native?'existing-static-dossier-64k-128-rows':'saved-source-read'};
    const identity={schema:'ig5-shadow-dedup-v1',scope,inputRefs,environment:{engine:context.engine,provider:context.provider,attachmentId:context.attachmentId,dbRevision:context.dbRevision,runId:null,moduleEpoch:null,
      runtimeDigest:planning?.capabilities.entries.find(c=>c.operation==='function-context'&&c.engine===context.engine&&c.provider===context.provider)?.runtimeDigest||null},
     templateId,templateVersion:SHADOW_VERSION,request,methodId:method.id,methodVersion:method.version,verifierVersion:method.verifierId,toolImplementation:planningImplementationDigest,budget:estimatedCost};
    drafts.push({templateId,templateVersion:SHADOW_VERSION,question,competingHypotheses,inputRefs,scope,predictedOutcomes:competingHypotheses.map((hypothesis,i)=>({hypothesis,outcome:i?'Missing or divergent information keeps the alternative open; no algorithm/instance equivalence follows.':'Explicit same-scope observations can guide the next comparison; they do not prove this hypothesis.'})),
     existingToolRequest:request,estimatedCost,stopCondition:'Stop on identity/revision drift, incomplete source, cancellation, policy block, unavailable budget or failed cleanup; re-evaluate explicitly.',
     missingPrerequisites:pair?['Independent instance inputs and seed/table/bytecode identities remain unknown; this proposal only collects callee source.']:[],
     dedupKey:planningDigest(identity),dedupIdentity:identity,planningKey:planningRequestKey(request,context,planningImplementationDigest),
     methodRefs:[{id:method.id,version:method.version,receiptDigest:receipt.receiptDigest}],priority,native,
     semanticVerified:false,executionAuthorized:false});
   }
  }
 }
 return drafts;
}
/** Select alternatives within the original total planning envelope; does not reserve or add calls. */
export function selectShadowProposals(drafts,planning,history={records:[],completeHistory:false}){
 const deferred=[],merged=new Map();
 const capability=planning.capabilities.entries.find(c=>c.operation==='function-context'&&c.engine===planning.context.engine&&c.provider===planning.context.provider);
 const runtime=capability?.runtimeDigest||null;
 const cleanup=Object.values(planning.resources).some(r=>r?.state==='cleanup-pending');
 for(const item of drafts){
  if(cleanup){deferred.push({reason:'original-cleanup-priority',key:item.dedupKey});continue;}
  if(item.native&&(planning.resources.static?.state!=='compatible'||!capability||capability.declared!=='declared'||capability.files!=='present'||capability.policy==='blocked'||capability.startup!=='verified'||capability.session!=='compatible')){deferred.push({reason:'static-prerequisite-unavailable',key:item.dedupKey});continue;}
  if(item.native&&history.error){deferred.push({reason:'failure-history-unavailable',key:item.dedupKey});continue;}
  const inputHashes=[...new Set(item.inputRefs.map(r=>r.sha256))].sort();
  const comparableFailures=history.records.filter(f=>!f.historical&&f.planningKey===item.planningKey);
  const sameInputs=f=>!f.inputReportHashes?.length||planningDigest([...new Set(f.inputReportHashes)].sort())===planningDigest(inputHashes);
  const runtimeComparable=f=>!f.runtimeDigest||!runtime||f.runtimeDigest===runtime;
  const failed=item.planningKey&&comparableFailures.find(f=>runtimeComparable(f)&&sameInputs(f));
  if(failed){deferred.push({reason:'unchanged-failed-request',key:item.dedupKey,reportRef:failed.reportRef});continue;}
  const operation=planningDigest(item.existingToolRequest);
  if(merged.has(operation)){const previous=merged.get(operation);previous.methodRefs.push(...item.methodRefs);previous.dedupKeys.push(item.dedupKey);continue;}
  const {priority,native,planningKey,dedupIdentity,...proposal}=item;
  const retryChanges=[];
  if(comparableFailures.some(f=>f.runtimeDigest&&runtime&&f.runtimeDigest!==runtime))retryChanges.push('runtime-identity-changed');
  if(comparableFailures.some(f=>f.inputReportHashes?.length&&!sameInputs(f)))retryChanges.push('bound-input-report-set-changed');
  if(history.records.some(f=>f.planningKey&&f.planningKey!==item.planningKey))retryChanges.push('different-request-key-present-in-bounded-history; previous same-operation identity is not established');
  proposal.dedupKeys=[item.dedupKey];proposal.dedup={completeHistory:false,status:history.error?'unknown':'bounded-comparison-only',retryChanges};
  merged.set(operation,{...proposal,priority});
 }
 let calls=planning.budgets.publicToolCalls,bytes=planning.budgets.inputBytes;const proposals=[];
 for(const item of [...merged.values()].sort((a,b)=>a.priority-b.priority||a.dedupKey.localeCompare(b.dedupKey))){
  if(proposals.length>=3||item.estimatedCost.publicToolCalls>calls||item.estimatedCost.inputBytes>bytes){deferred.push({reason:'original-shared-budget-or-three-proposal-limit',key:item.dedupKey});continue;}
  calls-=item.estimatedCost.publicToolCalls;bytes-=item.estimatedCost.inputBytes;const {priority,...view}=item;proposals.push(view);
 }
 return {proposals,deferred:deferred.slice(0,8),deferredCount:deferred.length,omittedDeferred:Math.max(0,deferred.length-8),
  budget:{publicToolCalls:planning.budgets.publicToolCalls,inputBytes:planning.budgets.inputBytes,plannedPublicToolCalls:planning.budgets.publicToolCalls-calls,plannedInputBytes:planning.budgets.inputBytes-bytes,authority:'Alternative suggestions only; no reservation or additional budget; original dispatcher rechecks and charges.'}};
}
const envStamp=p=>planningDigest({scope:p.context,task:p.task.taskRevision,research:p.research?.researchRevision,capabilities:p.capabilities,resources:p.resources,budget:p.sharedBudget});
export function runExperimentShadow({projectRoot,input,read,readPlanning,readLegacy,readFailures,artifacts}){
 validateShadowInput(input);
 if(input.mode==='off')return readLegacy(); // Exact old path: no method/index/history reads.
 const data=read(),before=captureMethodInputs(projectRoot,()=>data,artifacts),planning=readPlanning(data),legacy=readLegacy();
 const receipts=METHOD_SPECS.map(m=>evaluateMethodCapture(before,m));
 const drafts=draftShadowProposals(data,before,receipts,planning);
 let history={records:[],completeHistory:false,error:'FAILURE_HISTORY_UNAVAILABLE'};
 try{history=readFailures([...new Set(drafts.map(p=>p.planningKey).filter(Boolean))],planning.capabilities.entries.find(c=>c.operation==='function-context'&&c.engine===data.context.engine&&c.provider===data.context.provider)?.runtimeDigest||null);}catch(error){history.error=error.code||'FAILURE_HISTORY_UNAVAILABLE';}
 const selected=selectShadowProposals(drafts,planning,history),endData=read(),after=captureMethodInputs(projectRoot,()=>endData,artifacts),endPlanning=readPlanning(endData);
 if(before.digest!==after.digest||envStamp(planning)!==envStamp(endPlanning)||legacy.snapshot.taskRevision!==data.task.taskRevision||legacy.snapshot.researchRevision!==(data.research?.researchRevision??null)
  ||['projectId','artifactId','sha256','engine','provider','attachmentId','dbRevision'].some(k=>legacy.snapshot[k]!==data.context[k]))fail('SNAPSHOT_INCONSISTENT','Shadow inputs or original planning context changed');
 const historyAfter=readFailuresSafe(readFailures,[...new Set(drafts.map(p=>p.planningKey).filter(Boolean))],planning.capabilities.entries.find(c=>c.operation==='function-context'&&c.engine===data.context.engine&&c.provider===data.context.provider)?.runtimeDigest||null);
 if(planningDigest(history)!==planningDigest(historyAfter))fail('SNAPSHOT_INCONSISTENT','Failure history changed during shadow planning');
 const shadow={schema:'ig5-experiment-shadow-v1',version:SHADOW_VERSION,mode:'shadow',binding:before.binding||null,inputDigest:before.digest,
  status:!before.ready?'needs-evidence':receipts.some(r=>r.reason==='source-integrity-or-history-gap')?'blocked':receipts.every(r=>r.status!=='applicable')?'needs-evidence':'suggestions-only',
  ...selected,methodConditions:receipts.map(r=>({methodId:r.methodId,status:r.status,reason:r.reason,receiptDigest:r.receiptDigest})),
  failureHistory:{completeHistory:false,status:history.error?'unknown':'bounded-index-only',keysSearched:history.keysSearched??0,metadataScanned:history.metadataScanned??0,error:history.error||null},
  executionAuthorized:false,assistEnabled:false,automaticInjection:false,taskModified:false,databaseModified:false,completeHistory:false};
 shadow.receiptDigest=planningDigest(shadow);
 const result={...legacy,shadow};
 // Preserve every byte of the legacy result. Reduce only independent shadow proposals with explicit omissions.
 while(Buffer.byteLength(JSON.stringify(result))>(input.max_bytes??32768)&&shadow.proposals.length){shadow.proposals.pop();shadow.omittedForResponse=(shadow.omittedForResponse||0)+1;shadow.budget.plannedPublicToolCalls=shadow.proposals.reduce((s,p)=>s+p.estimatedCost.publicToolCalls,0);shadow.budget.plannedInputBytes=shadow.proposals.reduce((s,p)=>s+p.estimatedCost.inputBytes,0);}
 delete shadow.receiptDigest;shadow.receiptDigest=planningDigest(shadow);
 if(Buffer.byteLength(JSON.stringify(result))>(input.max_bytes??32768))fail('SHADOW_BUDGET_TOO_SMALL','Increase max_bytes to preserve original plan and mandatory shadow binding');
 return result;
}
function readFailuresSafe(read,keys,runtime){try{return read(keys,runtime);}catch(error){return {records:[],completeHistory:false,error:error.code||'FAILURE_HISTORY_UNAVAILABLE'};}}
