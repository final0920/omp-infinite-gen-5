import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {randomUUID,createHash} from 'node:crypto';
import {AnalysisArtifacts} from '../source/analysis_artifacts.js';
import {InvestigationStore} from '../source/investigation_store.js';
import {ResearchState,researchScopeDigest} from '../source/research_state.js';
import {runWorkspace,captureDossier} from '../source/investigation_workflow.js';
import {FailureRecords} from '../source/failure_record.js';
import {SHADOW_VERSION,validateShadowInput,runExperimentShadow,draftShadowProposals,selectShadowProposals} from '../source/experiment_shadow.js';
import {planningImplementationDigest} from '../source/planning_runtime.js';
import {planningRequestKey} from '../source/planning_identity.js';
import {captureMethodInputs,evaluateMethodCapture} from '../source/method_applicability.js';
import {planningContext} from '../source/investigation_planning.js';
import {METHOD_SPECS} from '../source/method_registry.js';
import {methodPredicates,decideApplicability,runMethodQuery,validateMethodInput} from '../source/method_applicability.js';
import {publicResearchStore} from '../source/knowledge_v2.js';
const hash=b=>createHash('sha256').update(b).digest('hex');
const contract={question:'Read known result without claiming algorithm',inputDomain:'stated inputs',returns:'unknown',outputs:'reported string',sideEffects:'unknown',environment:'owned static fixture',exclusions:'no native proof'};
function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'ig5-method-')),cfg={projectRoot:path.join(root,'projects')},sha256=hash('owned');
 const ctx={projectId:'project_'+randomUUID(),artifactId:'artifact_'+sha256,sha256,engine:'reverse',provider:'ghidra',attachmentId:'attachment_'+randomUUID(),dbRevision:2,target:path.join(root,'owned.exe')};
 const notes=new InvestigationStore({root:cfg.projectRoot}),service=new ResearchState({root:cfg.projectRoot}),artifacts=new AnalysisArtifacts(path.join(root,'reports')),task=notes.create(ctx,{goal:'Investigate'},'owner'),session={engine:'reverse'};
 const mgr={analysis:{artifacts},investigations:notes,researchState:service,get:()=>session,alive:()=>true,checkCancelled(){},evidence:()=>({...ctx})},execution={agent:{id:'owner'}};
 mgr.sessions=new Map([[ctx.target,session]]);mgr.engines=()=>[{id:'reverse',provider:'ghidra',available:true}];session.capabilities=['decompile','cfg','calls','stack'];
 mgr.failures=new FailureRecords({root:cfg.projectRoot,artifacts});
 const call=async input=>(await runWorkspace(mgr,cfg,{target:ctx.target,workspace:{id:task.taskId,...input}},execution)).workspace;
 const read=()=>({context:{...ctx},task:notes.get(ctx,task.taskId),research:service.get(notes.get(ctx,task.taskId),ctx),failures:[],failureError:null,relatedTasks:[]});
 const mutate=(operation,value)=>service.mutate(notes.get(ctx,task.taskId),ctx,{operation,expected_task_revision:notes.get(ctx,task.taskId).taskRevision,expected_research_revision:read().research?.researchRevision??0,scope_digest:researchScopeDigest(ctx),...(value?{value}:{})},'owner');
 const capture=(sections={decompile:{status:'truncated',data:{code:'not executed'}},callees:{status:'ok',data:{total:2,calls:[{ea:'0x2000'},{ea:'0x3000'}]}}},extra={})=>captureDossier(mgr,cfg,{schemaVersion:1,kind:'function-dossier',provenance:{...ctx},_ig5:{...ctx},snapshotDigest:hash(randomUUID()),function:{ea:'0x1000',name:'owned'},sections,responseTruncated:true,...extra},task.taskId,execution);
 const refresh=async()=>{const s=await call({action:'case-status'});return call({action:'case-index',expected_generation:s.generation,expected_task_revision:notes.get(ctx,task.taskId).taskRevision,expected_research_revision:read().research.researchRevision});};
 // Copy the already reviewed F03 immutable public store as fixture DATA; never fetch or execute upstream code.
 const from=path.join(import.meta.dirname,'fixtures','method-public-v2');
 fs.cpSync(from,path.join(cfg.projectRoot,'knowledge-v2'),{recursive:true});
 t.after(async()=>{await artifacts.dispose();assert.equal(path.dirname(root),fs.realpathSync(os.tmpdir()));fs.rmSync(root,{recursive:true,force:true});});
 const method=id=>call({action:'method-applicability',method_id:id});
 return {root,cfg,ctx,notes,task,artifacts,mgr,execution,call,read,mutate,capture,refresh,method,session};
}
const shadow=f=>f.call({action:'experiment-shadow'});
function internal(f){
 const read=()=>({...f.read(),failures:f.mgr.failures.recent(f.ctx,3),failureError:null});
 const readPlanning=data=>planningContext({mgr:f.mgr,cfg:f.cfg,args:{target:f.ctx.target},execution:f.execution,context:data.context,task:data.task,research:data.research});
 const options={projectRoot:f.cfg.projectRoot,input:{action:'experiment-shadow'},read,readPlanning,readLegacy:()=>runWorkspace(f.mgr,f.cfg,{target:f.ctx.target,workspace:{action:'plan',id:f.task.taskId}},f.execution).workspace,readFailures:(keys,runtime)=>f.mgr.failures.forPlanning(f.ctx,keys,runtime),artifacts:f.artifacts};
 return {read,readPlanning,options};
}
test('off is exactly the original planner and never reads methods or private index',async t=>{
 const f=fixture(t),old=await f.call({action:'plan'});assert.deepEqual(await f.call({action:'experiment-shadow',mode:'off'}),old);
 const i=internal(f);assert.deepEqual(runExperimentShadow({...i.options,input:{action:'experiment-shadow',mode:'off'},read:()=>{throw Error('off must not read');}}),old);
 assert(!fs.existsSync(path.join(f.cfg.projectRoot,'private-research-v2')));
});
test('rejects assist, caller requests, probabilities, budgets, source paths and injected templates',async t=>{
 const f=fixture(t);for(const extra of [{mode:'assist'},{execute:true},{existingToolRequest:{}},{confidence:1},{budget:8},{templates:[]},{path:'C:/x'},{max_bytes:40000}]){
  assert.throws(()=>validateShadowInput({action:'experiment-shadow',...extra}));await assert.rejects(f.call({action:'experiment-shadow',...extra}),e=>e.code==='INVALID_ARGUMENT');
 }
});
test('missing contract or stale index yields no proposals, never initializes or publishes',async t=>{
 const f=fixture(t);assert.equal((await shadow(f)).shadow.status,'needs-evidence');f.mutate('initialize',contract);assert.equal((await shadow(f)).shadow.proposals.length,0);assert(!fs.existsSync(path.join(f.cfg.projectRoot,'private-research-v2')));
});
test('shadow preserves all old fields, has at most three fixed contracts, and performs no dispatch or mutation',async t=>{
 const f=fixture(t);f.capture();f.mutate('initialize',contract);await f.refresh();const before=f.read(),legacy=await f.call({action:'plan'});f.mgr.rpc=()=>{throw Error('no execution');};
 const result=await shadow(f),{shadow:s,...unchanged}=result;assert.deepEqual(unchanged,legacy);assert(s.proposals.length<=3&&s.proposals.length>0);assert.equal(s.assistEnabled,false);assert.equal(s.executionAuthorized,false);assert.deepEqual(f.read(),before);
 for(const p of s.proposals){for(const k of ['question','competingHypotheses','inputRefs','scope','predictedOutcomes','existingToolRequest','estimatedCost','stopCondition','missingPrerequisites','dedupKey'])assert(k in p);assert.equal(p.executionAuthorized,false);assert(!['eval','ig5_dbg','ig5_run_idapython'].includes(p.existingToolRequest.tool));}
 const again=await shadow(f);assert.deepEqual(again,result);assert(Buffer.byteLength(JSON.stringify(result))<=32768);
});
test('VS-style multi-callee case proposes two source observations with explicit competing explanations',async t=>{
 const f=fixture(t);f.capture({callees:{status:'ok',data:{total:2,calls:[{ea:'0x4000'},{ea:'0x2000'}]}}},{responseTruncated:false});f.mutate('initialize',contract);await f.refresh();
 const s=(await shadow(f)).shadow,pairs=s.proposals.filter(p=>p.templateId==='compare-callee-sources');assert.equal(pairs.length,2);assert.deepEqual(pairs.map(p=>p.scope.selectedCallee).sort(),['0x2000','0x4000']);
 for(const p of pairs){assert.deepEqual(p.scope.comparisonPair,['0x2000','0x4000']);assert(p.missingPrerequisites.some(x=>x.includes('unknown')));assert(p.competingHypotheses.length>=2);assert.equal(p.methodRefs.length,2);}
});
test('exact persisted failure suppresses unchanged request across manager recreation; changed runtime gets a new key',async t=>{
 const f=fixture(t);f.capture();f.mutate('initialize',contract);await f.refresh();const i=internal(f),data=i.read(),captured=captureMethodInputs(f.cfg.projectRoot,()=>data,f.artifacts),planning=i.readPlanning(data);
 const receipts=METHOD_SPECS.map(m=>evaluateMethodCapture(captured,m)),drafts=draftShadowProposals(data,captured,receipts,planning),item=drafts.find(p=>p.native);assert(item.planningKey);
 const saved=f.mgr.failures.add({operation:item.existingToolRequest.tool,scope:{...f.ctx},semanticInputs:{owned:true},planningKey:item.planningKey,runtimeDigest:null,error:Object.assign(new Error('fixture failure'),{code:'FIXTURE_FAILURE'})});assert(saved.reportSaved);
 f.mgr.failures=new FailureRecords({root:f.cfg.projectRoot,artifacts:f.artifacts});await f.refresh();const s=(await shadow(f)).shadow;assert(s.deferred.some(d=>d.reason==='unchanged-failed-request'));assert(!s.proposals.some(p=>p.existingToolRequest.ea===item.existingToolRequest.ea&&p.templateId===item.templateId));assert.equal(s.failureHistory.completeHistory,false);
 const changed=structuredClone(planning);changed.capabilities.entries.find(c=>c.operation==='function-context').runtimeDigest='b'.repeat(64);
 const changedDraft=draftShadowProposals(data,captured,receipts,changed).find(p=>p.templateId===item.templateId);assert.notEqual(changedDraft.dedupKey,item.dedupKey);
 const knownPreviousRuntime=f.mgr.failures.recent(f.ctx,3).map(f=>({...f,runtimeDigest:'a'.repeat(64)}));
 const retry=selectShadowProposals([changedDraft],changed,{records:knownPreviousRuntime});assert.equal(retry.proposals.length,1);assert(retry.proposals[0].dedup.retryChanges.includes('runtime-identity-changed'));
 const unknownRuntime=selectShadowProposals([changedDraft],changed,{records:f.mgr.failures.recent(f.ctx,3)});assert.equal(unknownRuntime.proposals.length,0);
});
test('budget exhaustion and cleanup priority do not get extra calls from shadow',async t=>{
 const f=fixture(t);f.capture();f.mutate('initialize',contract);await f.refresh();f.mgr.coordination={planningBudget:()=>({active:true,remaining:0,status:'available'})};
 const exhausted=(await shadow(f)).shadow;assert.equal(exhausted.proposals.length,0);assert.equal(exhausted.budget.plannedPublicToolCalls,0);
 f.mgr.coordination=null;f.session.closing=true;const cleanup=(await shadow(f)).shadow;assert.equal(cleanup.proposals.length,0);assert(cleanup.deferred.some(d=>d.reason==='original-cleanup-priority'));
});
test('failure history error defers new static collection and never claims complete duplicate avoidance',async t=>{
 const f=fixture(t);f.capture();f.mutate('initialize',contract);await f.refresh();f.mgr.failures.forPlanning=()=>{throw Object.assign(Error('fixture damaged'),{code:'FIXTURE_HISTORY_UNAVAILABLE'});};
 const s=(await shadow(f)).shadow;assert.equal(s.failureHistory.status,'unknown');assert.equal(s.failureHistory.completeHistory,false);assert(!s.proposals.some(p=>p.existingToolRequest.tool==='ig5_decompile'));
});
test('corrupt or withdrawn evidence blocks proposals; task/contract ABA invalidates and changes binding',async t=>{
 const f=fixture(t);f.capture();f.mutate('initialize',contract);await f.refresh();const a=(await shadow(f)).shadow;
 f.mutate('set-contract',{...contract,question:'B'});f.mutate('set-contract',contract);assert.equal((await shadow(f)).shadow.proposals.length,0);await f.refresh();const b=(await shadow(f)).shadow;assert.notEqual(a.inputDigest,b.inputDigest);assert.notEqual(a.binding.contractRevision,b.binding.contractRevision);
 const snap=f.notes.get(f.ctx,f.task.taskId).systemEvidence[0];fs.appendFileSync(path.join(f.artifacts.directory('records'),snap.report_id+'.json'),' ');const r=(await shadow(f)).shadow;assert.equal(r.status,'blocked');assert.equal(r.proposals.length,0);
});
test('identity drift, budget drift and failure-history drift across the read fail closed',async t=>{
 const f=fixture(t);f.capture();f.mutate('initialize',contract);await f.refresh();const {options}=internal(f);let reads=0;
 assert.throws(()=>runExperimentShadow({...options,read:()=>{if(++reads===2)f.ctx.dbRevision++;return options.read();}}),e=>e.code==='SNAPSHOT_INCONSISTENT');f.ctx.dbRevision--;
 let planReads=0;assert.throws(()=>runExperimentShadow({...options,readPlanning:data=>({...options.readPlanning(data),sharedBudget:{active:true,remaining:++planReads}})}),e=>e.code==='SNAPSHOT_INCONSISTENT');
 let historyReads=0;assert.throws(()=>runExperimentShadow({...options,readFailures:()=>({records:[],completeHistory:false,metadataScanned:++historyReads})}),e=>e.code==='SNAPSHOT_INCONSISTENT');
});
test('response omission changes only shadow, never old candidates, and no silently partial mandatory contract',async t=>{
 const f=fixture(t);f.capture();f.mutate('initialize',contract);await f.refresh();await assert.rejects(f.call({action:'experiment-shadow',max_bytes:4096}),e=>['SHADOW_BUDGET_TOO_SMALL','PLAN_BUDGET_TOO_SMALL'].includes(e.code));
 const r=await shadow(f),{shadow:s,...legacy}=r;assert.deepEqual(legacy,await f.call({action:'plan'}));assert(s.proposals.length<=3);
});
test('bound input changes allow an explicit retry; unknown old inputs conservatively suppress the same failed request',async t=>{
 const f=fixture(t);f.capture();f.mutate('initialize',contract);await f.refresh();const i=internal(f),data=i.read(),captured=captureMethodInputs(f.cfg.projectRoot,()=>data,f.artifacts),planning=i.readPlanning(data);
 const item=draftShadowProposals(data,captured,METHOD_SPECS.map(m=>evaluateMethodCapture(captured,m)),planning).find(p=>p.native);
 const failure={historical:false,planningKey:item.planningKey,runtimeDigest:null,inputReportHashes:['a'.repeat(64)],reportRef:{id:randomUUID(),sha256:'b'.repeat(64)}};
 const changed=selectShadowProposals([item],planning,{records:[failure]});assert.equal(changed.proposals.length,1);assert(changed.proposals[0].dedup.retryChanges.includes('bound-input-report-set-changed'));
 const same=selectShadowProposals([item],planning,{records:[{...failure,inputReportHashes:item.inputRefs.map(r=>r.sha256)}]});assert.equal(same.proposals.length,0);
 const unknown=selectShadowProposals([item],planning,{records:[{...failure,inputReportHashes:[]}]});assert.equal(unknown.proposals.length,0);
});
test('withdrawn reviewed method sources cannot produce their templates; unsupported pure IR never produces candidate execution',async t=>{
 const f=fixture(t);f.capture();f.mutate('initialize',contract);await f.refresh();const store=publicResearchStore(f.cfg.projectRoot),ref=METHOD_SPECS.find(m=>m.id==='address-space-check').sourceRefs[0];
 store.publish({expectedGeneration:store.current().generation,upserts:[],withdrawals:[{ref,reason:'owned test withdrawal',replacementRef:null}]});const s=(await shadow(f)).shadow;
 assert(!s.proposals.some(p=>p.methodRefs.some(m=>m.id==='address-space-check'||m.id==='argument-prototype-check')));
 assert(!s.proposals.some(p=>p.methodRefs.some(m=>m.id==='pure-expression-simplification')));assert.equal(s.methodConditions.find(m=>m.methodId==='pure-expression-simplification').status,'needs-evidence');
});
