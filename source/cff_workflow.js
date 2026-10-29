import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {buildCffOverlay,bindCffCondition,CFF_VERSION} from './cff_overlay.js';
import {caseTrustedScope} from './research_case_bridge.js';
import {planningDigest} from './planning_identity.js';
import {committedBytes,exactReportRef,evidenceReadBudget} from './evidence_adapters/vm_context.js';
import {validateSnapshotReport} from './evidence_adapters/dossier.js';
import {runCandidateWorkflow} from './candidate_workflow.js';
import {runCffStateWorkflow} from './cff_state_workflow.js';
export const cffActions=Object.freeze(['cff-overlay','cff-read','cff-state']);
const fail=(code,message)=>{throw Object.assign(new Error(message),{code});};
const codeIdentity=planningDigest(['./cff_overlay.js','./cff_workflow.js'].map(name=>({name,sha256:createHash('sha256').update(fs.readFileSync(new URL(name,import.meta.url))).digest('hex')})));
export function validateCffInput(input){
 const fields=input?.action==='cff-overlay'?['action','id','snapshot_id','verification_ref']:input?.action==='cff-read'?['action','id','report_ref']:input?.action==='cff-state'?['action','id','source_ref']:[];
 if(!fields.length||Object.keys(input).some(k=>!fields.includes(k)))fail('INVALID_ARGUMENT','Invalid CFF read-only fields');
 if(input.action==='cff-state')exactReportRef(input.source_ref);
 else if(input.action==='cff-read')exactReportRef(input.report_ref);
 else {if(typeof input.snapshot_id!=='string'||input.snapshot_id.length>64)fail('INVALID_ARGUMENT','CFF requires a task system snapshot ID');if(input.verification_ref!==undefined)exactReportRef(input.verification_ref);}
}
function binding(data){const value=caseTrustedScope(data);if(!value.ready)fail('CFF_CONTEXT_REQUIRED',value.reason);return {scope:value.scope,researchRevision:data.research.researchRevision,contractRevision:data.research.contractRevision};}
function dossierSource(artifacts,data,snapshotId){
 const snapshot=data.task.systemEvidence.find(s=>s.snapshot_id===snapshotId);
 if(!snapshot||snapshot.stale)fail('CFF_SOURCE_REQUIRED','Select a current system dossier belonging to this task');
 const keys=['projectId','artifactId','sha256','engine','provider','attachmentId','dbRevision'];
 if(keys.some(k=>snapshot.context[k]!==data.context[k]))fail('CFF_SOURCE_REQUIRED','Dossier attachment/database identity is stale');
 const ref={id:snapshot.report_id,sha256:snapshot.report_sha256},saved=committedBytes(artifacts,ref,'function-dossier','capture');
 if(saved.bytes.length>128*1024)fail('CFF_SOURCE_LIMIT','Dossier exceeds original 128 KiB evidence envelope');
 return {ref,value:validateSnapshotReport(snapshot,saved.record)};
}
const escape=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
/** Scriptless, self-contained comparison; no remote resources and no embedded raw provider HTML. */
export function renderCffComparison(model){
 const g=model.originalGraph;
 function diagram(overlay){
  const positions=new Map(g.blocks.map((b,i)=>[b.id,{x:30+(i%4)*170,y:35+Math.floor(i/4)*90}]));
  let body='';
  for(const e of g.edges){const a=positions.get(e.from),b=positions.get(e.to);if(a&&b)body+=`<path d="M${a.x+65},${a.y+38} L${b.x+65},${b.y}" stroke="#718096" fill="none"/>`;}
  if(overlay)for(const e of model.overlay.conditionRelations){const a=positions.get(e.from),b=positions.get(e.to);body+=`<path d="M${a.x+60},${a.y+38} L${b.x+60},${b.y}" stroke="#047857" stroke-width="4" fill="none"/>`;}
  if(overlay)for(const route of model.overlay.stateRelations||[])for(const e of route.path){const a=positions.get(e.block),b=positions.get(e.destination);if(a&&b)body+=`<path d="M${a.x+70},${a.y+38} L${b.x+70},${b.y}" stroke="${route.status==='verified-in-scope'?'#047857':'#b45309'}" stroke-width="3" fill="none" stroke-dasharray="5 3"><title>${escape(route.condition)}; ${escape(route.status)}; B${e.block} to B${e.destination}</title></path>`;}
  for(const b of g.blocks){const p=positions.get(b.id),candidate=overlay&&model.dispatcherCandidates.some(d=>d.block===b.id);body+=`<rect x="${p.x}" y="${p.y}" width="135" height="38" fill="${candidate?'#fef3c7':'#edf2f7'}" stroke="#334155"/><text x="${p.x+6}" y="${p.y+24}">B${b.id} ${escape(b.start)}</text>`;}
  return `<svg role="img" aria-label="${overlay?'只读覆盖层':'原始 CFG'}" viewBox="0 0 720 ${Math.max(110,Math.ceil(g.blocks.length/4)*90+25)}">${body}</svg>`;
 }
 const detail=JSON.stringify({sourceRef:model.sourceRef,providerGraphComplete:model.providerGraphComplete,wholeFunctionRecovered:false,dispatcherCandidates:model.dispatcherCandidates,stateDependencies:model.stateDependencies,localRelations:model.overlay.localRelations,conditionRelations:model.overlay.conditionRelations,stateRelations:model.overlay.stateRelations||[],unknownExits:model.overlay.unknownExits},null,2);
 return `<!doctype html><html lang="zh"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>F09 CFG 只读对照</title><style>body{font:15px system-ui;margin:24px;color:#1e293b}main{display:grid;grid-template-columns:1fr 1fr;gap:20px}svg{width:100%}pre{white-space:pre-wrap;overflow-wrap:anywhere}text{font:12px monospace}</style><h1>CFG 原图与只读覆盖层</h1><p>黄色仅 dispatcher 候选，绿色实线为已核验的局部 BV 条件；虚线为入口边条件下状态路由，绿色已在SSA范围复算，棕色仍是候选。原块与原边全部保留；图中连线方向以以下 from/to 回执为准。拓扑路径不证明可达性，未知出口与副作用不删除。全函数恢复：false；CFF 已证明：false。</p><main><section><h2>原始 CFG</h2>${diagram(false)}</section><section><h2>只读覆盖层</h2>${diagram(true)}</section></main><h2>范围、来源、条件与回执</h2><pre>${escape(detail)}</pre></html>`;
}
/** Host derives all scope; original notes, CFG and database remain untouched. */
export async function runCffWorkflow({artifacts,jobs,dataJobs,input,read,signal}){
 validateCffInput(input);if(signal?.aborted)fail('ABORT_ERR','CFF cancelled');
 const data=read(),currentBinding=binding(data);
 if(input.action==='cff-state'||input.action==='cff-read'&&artifacts.metadata(input.report_ref.id).result.kind==='cff-state')return runCffStateWorkflow({artifacts,dataJobs,input,read,signal,render:renderCffComparison});
 if(input.action==='cff-read'){
  const record=committedBytes(artifacts,input.report_ref,'cff-overlay','derive').record;
  if(record.association?.taskId!==data.task.taskId||planningDigest(record.association.scope)!==planningDigest(data.task.scope))fail('RESEARCH_SCOPE_MISMATCH','Overlay belongs to another task');
  const saved=record.result;let validity='current',reason=null;
  try{if(saved.codeIdentity!==codeIdentity||planningDigest(saved.binding)!==planningDigest(currentBinding))fail('STALE_CFF_OVERLAY','Overlay implementation or task revisions changed');
   const source=dossierSource(artifacts,data,saved.snapshotId);if(planningDigest(source.ref)!==planningDigest(saved.sourceRef)||planningDigest(source.value.sections.cfg.data)!==saved.model.originalGraphDigest)fail('ARTIFACT_CHANGED','Original CFG changed');
   if(saved.verificationRef){const checked=await runCandidateWorkflow({jobs,dataJobs,input:{action:'candidate-read',id:input.id,report_ref:saved.verificationRef},read,signal});if(checked.validity!=='current')fail('STALE_CFF_PROOF','Predicate proof is stale');}
   const bytes=artifacts.read(saved.viewRef.ref,1024*1024).data;if(createHash('sha256').update(bytes).digest('hex')!==saved.viewRef.sha256)fail('ARTIFACT_CHANGED','Comparison view bytes changed');
  }catch(error){validity='stale';reason=error.code||'CFF_HISTORY_UNVERIFIED';}
  if(planningDigest(binding(read()))!==planningDigest(currentBinding))fail('SNAPSHOT_INCONSISTENT','Context changed during overlay read');
  return {schema:'ig5-cff-history-v1',reportRef:input.report_ref,validity,reason,summary:saved.summary,viewRef:saved.viewRef,wholeFunctionRecovered:false,databaseModified:false,assistEnabled:false};
 }
 const source=dossierSource(artifacts,data,input.snapshot_id);
 const model=buildCffOverlay(source.value,source.ref);
 if(input.verification_ref){
  const history=await runCandidateWorkflow({jobs,dataJobs,input:{action:'candidate-read',id:input.id,report_ref:input.verification_ref},read,signal});
  if(history.validity!=='current'||history.result.schema!=='ig5-bitvector-verification-v1')fail('CFF_PROOF_REQUIRED','Select a current independent F07 verification receipt');
  const verified=history.result;
  const contractHistory=await runCandidateWorkflow({jobs,dataJobs,input:{action:'candidate-read',id:input.id,report_ref:verified.contractRef},read,signal});
  if(contractHistory.validity!=='current')fail('CFF_PROOF_REQUIRED','Predicate contract is stale');
  const projection=committedBytes(jobs.artifacts,contractHistory.result.sourceRef,'projection','project',evidenceReadBudget()).record.result;
  bindCffCondition(model,projection,contractHistory.result,verified,input.verification_ref);
 }
 if(signal?.aborted)fail('ABORT_ERR','CFF cancelled');
 if(planningDigest(binding(read()))!==planningDigest(currentBinding)||planningDigest(dossierSource(artifacts,read(),input.snapshot_id).ref)!==planningDigest(source.ref))fail('SNAPSHOT_INCONSISTENT','Context changed before overlay save');
 const view=Buffer.from(renderCffComparison(model));if(view.length>1024*1024)fail('CFF_VIEW_LIMIT','Comparison exceeds 1 MiB; original remains available');
 const viewRef=artifacts.put(view),summary={blocks:model.originalGraph.blocks.length,edges:model.originalGraph.edges.length,providerGraphComplete:model.providerGraphComplete,dispatcherCandidates:model.dispatcherCandidates,omittedDispatcherCandidates:model.omittedDispatcherCandidates,localRelations:model.overlay.localRelations.length,verifiedConditions:model.overlay.conditionRelations.length,stateDependencies:model.stateDependencies,unknownExits:model.overlay.unknownExits.slice(0,16),omittedUnknownExits:Math.max(0,model.overlay.unknownExits.length-16)};
 const result={schema:'ig5-cff-report-v1',version:CFF_VERSION,codeIdentity,binding:currentBinding,snapshotId:input.snapshot_id,sourceRef:source.ref,verificationRef:input.verification_ref||null,model,summary,viewRef};
 const record=artifacts.save({kind:'cff-overlay',action:'derive',association:{target:data.context.target,engine:data.context.engine,taskId:data.task.taskId,scope:data.task.scope},result},{maxBytes:1024*1024});
 return {schema:result.schema,reportRef:{id:record.id,sha256:artifacts.metadata(record.id).result.recordSha256},summary,viewRef,
  wholeFunctionRecovered:false,cffProved:false,databaseModified:false,nativeTargetExecuted:false,businessAccepted:false,assistEnabled:false};
}
