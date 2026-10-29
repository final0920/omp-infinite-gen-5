import fs from 'node:fs';
import {hashBytes,readStableFile} from './analysis_artifacts.js';
import {InvestigationStore} from './investigation_store.js';import {ResearchState} from './research_state.js';
import {caseTrustedScope} from './research_case_bridge.js';import {planningDigest} from './planning_identity.js';
import {committedBytes,exactReportRef} from './evidence_adapters/vm_context.js';import {jsonToolOutput} from './json_output.js';
import {CFF_STATE_VERSION} from './cff_state.js';
const fail=(code,message)=>{throw Object.assign(new Error(message),{code});};
const identity=planningDigest(['cff_state.js','cff_state_workflow.js','analysis_worker.js','analysis_jobs.js','../adapters/ghidra/deobfuscation_analysis.py','../adapters/ghidra/microcode_analysis.py'].map(name=>({name,sha256:hashBytes(fs.readFileSync(new URL(name,import.meta.url)))})));
function binding(data){const c=caseTrustedScope(data);if(!c.ready)fail('CFF_CONTEXT_REQUIRED',c.reason);return {scope:c.scope,researchRevision:data.research.researchRevision,contractRevision:data.research.contractRevision};}
function ref(artifacts,saved){return {id:saved.id,sha256:artifacts.metadata(saved.id).result.recordSha256};}
export function admitCffStateSource(mgr,cfg,session,args,execution){
 if(!execution?.agent?.id)fail('AGENT_SCOPE_REQUIRED','Source capture requires actual executing agent');
 if(args.action!=='deobfuscate')fail('INVALID_ARGUMENT','task_id source capture requires action=deobfuscate');
 mgr.checkCancelled();const context=jsonToolOutput(mgr.evidence(session)),notes=mgr.investigations||=new InvestigationStore({root:cfg.projectRoot}),state=mgr.researchState||=new ResearchState({root:cfg.projectRoot}),task=notes.get(context,args.task_id);
 binding({context,task,research:state.get(task,context)});return context;
}
function source(artifacts,sourceRef,data){
 const s=committedBytes(artifacts,sourceRef,'typed-microcode-source','capture'),r=s.record;
 if(r.association?.taskId!==data.task.taskId||planningDigest(r.association.scope)!==planningDigest(data.task.scope)||planningDigest(r.association.context)!==planningDigest(data.context))fail('CFF_SOURCE_REQUIRED','Native SSA belongs to a different task/attachment/database');
 if(s.bytes.length>2*1024**2)fail('CFF_SOURCE_LIMIT','Native source exceeds 2 MiB envelope');
 const blob=artifacts.read(r.outputRef.ref,2*1024**2).data;
 if(hashBytes(blob)!==r.outputRef.sha256||planningDigest(JSON.parse(blob))!==planningDigest(r.result))fail('ARTIFACT_CHANGED','Full native source differs');
 const binary=artifacts.read(r.input.ref,8*1024**2-s.bytes.length-blob.length).data;
 if(hashBytes(binary)!==data.context.sha256||hashBytes(readStableFile(data.context.target,8*1024**2-s.bytes.length-blob.length-binary.length).data)!==data.context.sha256)fail('CFF_SOURCE_REQUIRED','Source bytes no longer match opened target');
 if(r.result.representation!=='Ghidra p-code'||r.result.action!=='deobfuscate'||r.result.idb_modified!==false||r.result.source?.artifactSHA256!==data.context.sha256||r.result.revision!==data.context.dbRevision)fail('CFF_SOURCE_REQUIRED','Bound native HighFunction deobfuscation observation required');
 return r.result;
}

/** Called only on the existing queued ig5_microcode RPC, never accepts a caller graph. */
export function captureCffStateSource(mgr,cfg,session,args,result,execution,expectedContext){
 if(!execution?.agent?.id)fail('AGENT_SCOPE_REQUIRED','Source capture requires actual executing agent');mgr.checkCancelled();
 if(args.action!=='deobfuscate')fail('INVALID_ARGUMENT','task_id source capture requires action=deobfuscate');
 if(!mgr.alive(session)||mgr.get(session.target,session.engine)!==session)fail('SNAPSHOT_INCONSISTENT','Source session replaced during capture');
 const context=jsonToolOutput(mgr.evidence(session));if(planningDigest(context)!==planningDigest(expectedContext))fail('SNAPSHOT_INCONSISTENT','Database changed during capture');
 const notes=mgr.investigations||=new InvestigationStore({root:cfg.projectRoot}),state=mgr.researchState||=new ResearchState({root:cfg.projectRoot}),task=notes.get(context,args.task_id);binding({context,task,research:state.get(task,context)});
 const r=jsonToolOutput(result);if(r.action!=='deobfuscate'||r.representation!=='Ghidra p-code'||r.engine!=='Ghidra'||r.idb_modified!==false||r.source?.artifactSHA256!==context.sha256||r.revision!==context.dbRevision||r.optimization!==null)fail('CFF_SOURCE_REQUIRED','Only original read-only native SSA deobfuscation can be captured');
 const output=Buffer.from(JSON.stringify(r));if(output.length>2*1024**2)fail('CFF_SOURCE_LIMIT','Original SSA source exceeds 2 MiB; no truncated proof is saved');
 const bytes=readStableFile(context.target,Math.min(4*1024**2,Math.floor((8*1024**2-2*output.length-32768)/2))).data;if(hashBytes(bytes)!==context.sha256)fail('CFF_SOURCE_REQUIRED','Current target changed');
 const artifacts=mgr.analysis.artifacts,input=artifacts.put(bytes),outputRef=artifacts.put(output);
 const saved=artifacts.save({kind:'typed-microcode-source',action:'capture',association:{target:context.target,engine:context.engine,taskId:task.taskId,scope:task.scope,context},input,outputRef,result:r},{maxBytes:2*1024**2});
 return {schema:'ig5-typed-microcode-source-v1',sourceRef:ref(artifacts,saved),function:{ea:r.ea,name:r.func},scopeComplete:r.scopeComplete===true,sourceKind:'native-HighFunction-observation',savedFullSource:true,wholeFunctionRecovered:false,nativeTargetExecuted:false,databaseModified:false,assistEnabled:false};
}

export async function runCffStateWorkflow({artifacts,dataJobs,input,read,signal,render}){
 const allowed=input.action==='cff-state'?['action','id','source_ref']:['action','id','report_ref'];
 if(Object.keys(input).some(k=>!allowed.includes(k)))fail('INVALID_ARGUMENT','Invalid CFF state fields');exactReportRef(input.action==='cff-state'?input.source_ref:input.report_ref);
 if(signal?.aborted)fail('ABORT_ERR','CFF state cancelled');const data=read(),current=binding(data);
 if(input.action==='cff-read'){
  const saved=committedBytes(artifacts,input.report_ref,'cff-state','derive').record;if(saved.association?.taskId!==data.task.taskId||planningDigest(saved.association.scope)!==planningDigest(data.task.scope))fail('RESEARCH_SCOPE_MISMATCH','Cross-block report belongs to another task');
  let validity='current',reason=null;try{if(saved.result.identity!==identity||planningDigest(saved.result.binding)!==planningDigest(current))fail('STALE_CFF_OVERLAY','State semantics or contract revision changed');source(artifacts,saved.result.sourceRef,data);const bytes=artifacts.read(saved.result.viewRef.ref,1024**2).data;if(hashBytes(bytes)!==saved.result.viewRef.sha256)fail('ARTIFACT_CHANGED','Cross-block view differs');}catch(e){validity='stale';reason=e.code||'CFF_HISTORY_UNVERIFIED';}
  if(planningDigest(binding(read()))!==planningDigest(current))fail('SNAPSHOT_INCONSISTENT','Context changed during state history read');
  return {schema:'ig5-cff-state-history-v1',reportRef:input.report_ref,validity,reason,summary:saved.result.summary,viewRef:saved.result.viewRef,wholeFunctionRecovered:false,assistEnabled:false};
 }
 const original=source(artifacts,input.source_ref,data),model=await dataJobs.runSettled('cff-state-replay',{report:original,sourceRef:input.source_ref},signal);
 if(signal?.aborted)fail('ABORT_ERR','CFF state cancelled');if(planningDigest(binding(read()))!==planningDigest(current)||planningDigest(source(artifacts,input.source_ref,read()))!==planningDigest(original))fail('SNAPSHOT_INCONSISTENT','Source/contract changed during independent replay');
 const html=Buffer.from(render(model));if(html.length>1024**2)fail('CFF_VIEW_LIMIT','State comparison exceeds 1 MiB');const viewRef=artifacts.put(html);
 const variables=model.stateDependencies.competingVariables.map(c=>({block:c.block,ssa:c.ssa,width:c.width,stateRole:c.stateRole,classification:c.classification,conditionUsers:c.conditionUsers,definitions:c.dependencies.definitions.length,dependenciesTruncated:c.dependencies.truncated}));
 const summary={providerGraphComplete:model.providerGraphComplete,competingVariables:variables,selectedVariable:null,omittedVariables:model.stateDependencies.omittedCandidates,stateRoutes:model.overlay.stateRelations.length,verifiedRoutes:model.overlay.stateRelations.filter(r=>r.status==='verified-in-scope').length,routes:model.overlay.stateRelations.slice(0,8),omittedRoutes:Math.max(0,model.overlay.stateRelations.length-8),unknownExits:model.overlay.unknownExits.slice(0,8),omittedUnknownExits:Math.max(0,model.overlay.unknownExits.length-8),budget:model.budget,cleanupConfirmed:true};
 const result={schema:'ig5-cff-state-report-v1',version:CFF_STATE_VERSION,identity,binding:current,sourceRef:input.source_ref,model,summary,viewRef};
 if(Buffer.byteLength(JSON.stringify(summary))>24576)fail('CFF_RESPONSE_LIMIT','State summary exceeds budget; full original retained');
 const saved=artifacts.save({kind:'cff-state',action:'derive',association:{target:data.context.target,engine:data.context.engine,taskId:data.task.taskId,scope:data.task.scope},result},{maxBytes:4*1024**2});
 return {schema:result.schema,reportRef:ref(artifacts,saved),summary,viewRef,originalRetained:true,wholeFunctionRecovered:false,cffProved:false,nativeTargetExecuted:false,databaseModified:false,businessAccepted:false,assistEnabled:false};
}
