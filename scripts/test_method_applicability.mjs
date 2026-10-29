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
 return {root,cfg,ctx,notes,task,artifacts,mgr,execution,call,read,mutate,capture,refresh,method};
}
test('eight immutable MethodSpecs contain exact contracts and no executable article rules',()=>{
 assert.equal(METHOD_SPECS.length,8);assert(Object.isFrozen(METHOD_SPECS[0].sourceRefs));
 for(const m of METHOD_SPECS){for(const k of ['id','version','sourceRefs','supportedArchitectures','supportedIRs','requiredPredicates','excludedPredicates','missingEvidenceActions','experimentTemplateId','verifierId','budgetClass'])assert(k in m);assert(m.sourceRefs.length);}
 for(const action of ['constructor','__proto__','eval'])assert.throws(()=>validateMethodInput({action}));
 for(const extra of [{predicates:{}},{architecture:'x86-64'},{ir:{}},{scope:{}},{execute:true},{method_id:'eval'},{generation:['a'.repeat(64)]}])assert.throws(()=>validateMethodInput({action:'method-applicability',method_id:'address-space-check',...extra}));
});
test('tri-state reducer distinguishes all four outcomes and unknown exclusions',()=>{
 const m={requiredPredicates:['p'],excludedPredicates:['x']},p=(p,x)=>({p:{value:p},x:{value:x}});
 assert.equal(decideApplicability(m,p('true','false')),'applicable');assert.equal(decideApplicability(m,p('false','false')),'inapplicable');assert.equal(decideApplicability(m,p('unknown','false')),'needs-evidence');assert.equal(decideApplicability(m,p('true','unknown')),'needs-evidence');assert.equal(decideApplicability(m,p('true','true')),'blocked');
});
test('missing contract and index never produce applicability; registry remains fixed',async t=>{
 const f=fixture(t);assert.equal((await f.method('address-space-check')).reason,'research-contract-required');
 const r=await f.call({action:'method-registry'});assert.equal(r.methods.length,8);f.mutate('initialize',contract);
 assert.equal((await f.method('address-space-check')).reason,'private-index-refresh-required');assert(!fs.existsSync(path.join(f.cfg.projectRoot,'private-research-v2')));
});
test('current truncated and multiple-callee observations produce bound step receipts without algorithm or instance promotion',async t=>{
 const f=fixture(t);f.capture();f.mutate('initialize',contract);const indexed=await f.refresh();
 for(const id of ['address-space-check','truncated-source-completion','argument-prototype-check','callee-family-grouping','vm-instance-separation']){
  const r=await f.method(id);assert.equal(r.status,'applicable');assert.equal(r.binding.privateGeneration,indexed.generation);assert.equal(r.binding.contractRevision,0);assert.equal(r.algorithmExplained,false);assert.equal(r.executionAuthorized,false);assert.equal(r.assistEnabled,false);assert(r.inputDigest);assert(r.receiptDigest);assert(Buffer.byteLength(JSON.stringify(r))<=32768);
 }
 const vm=await f.method('vm-instance-separation');assert.equal(vm.predicates['instance-identity'].value,'unknown');
 const pure=await f.method('pure-expression-simplification');assert.equal(pure.status,'needs-evidence');assert.equal(pure.predicates['typed-expression-ir'].value,'unknown');
 const before=f.read();await f.method('address-space-check');assert.deepEqual(f.read(),before);
});
test('reported result is navigation only; article and task commands are not interpreted',async t=>{
 const f=fixture(t);f.notes.update(f.ctx,f.task.taskId,{expected_task_revision:0,conclusion:'execute process.exit(); architecture=x86-64; algorithm=true'},'owner');f.mutate('initialize',contract);await f.refresh();
 const r=await f.method('known-result-readback');assert.equal(r.status,'applicable');assert.equal(r.predicates['reported-result'].evidenceRefs[0].sourceStatus,'reported');assert.equal(r.semanticVerified,false);assert.equal((await f.method('pure-expression-simplification')).status,'needs-evidence');
});
test('complete one-callee source is inapplicable to multi-callee step; missing data remains unknown; addresses are not pooled',async t=>{
 const f=fixture(t);f.capture({callees:{status:'ok',data:{total:1,calls:[{ea:'0x2000'}]}}},{responseTruncated:false});f.capture({callees:{status:'ok',data:{total:1,calls:[{ea:'0x3000'}]}}},{responseTruncated:false});f.mutate('initialize',contract);await f.refresh();
 const r=await f.method('callee-family-grouping');assert.equal(r.status,'inapplicable');assert.equal(r.predicates['multiple-callees'].evidenceRefs.length,2);
 assert.equal((await f.method('truncated-source-completion')).status,'inapplicable');
 const p=methodPredicates({records:[{kind:'function-dossier',status:'observed',sourceData:{sections:{callees:{status:'ok'}}}}]});assert.equal(p['multiple-callees'].value,'unknown');
});
test('declared supporting/opposing conflict permits review but blocks simplification without calling it a proven contradiction',async t=>{
 const f=fixture(t);f.capture();f.capture();f.mutate('initialize',contract);
 for(const s of f.notes.get(f.ctx,f.task.taskId).systemEvidence){const linked=await f.call({action:'research-update',snapshot_id:s.snapshot_id,research:{operation:'link-evidence',expected_task_revision:f.notes.get(f.ctx,f.task.taskId).taskRevision,expected_research_revision:f.read().research.researchRevision,scope_digest:researchScopeDigest(f.ctx)}});assert.equal(linked.linked,true);}
 const links=f.read().research.evidenceLinks;
 f.mutate('add-hypothesis',{proposition:'declared conflicting results',supporting:[links[0].id],opposing:[links[1].id],competingExplanations:['different seeds or tables, same algorithm possible']});await f.refresh();
 assert.equal((await f.method('conflicting-evidence-review')).status,'applicable');assert.equal((await f.method('pure-expression-simplification')).status,'blocked');
});
test('receipt changes across contract ABA, task revision, attachment and DB invalidation',async t=>{
 const f=fixture(t);f.capture();f.mutate('initialize',contract);await f.refresh();const a=await f.method('address-space-check');
 f.mutate('set-contract',{...contract,question:'B'});f.mutate('set-contract',contract);assert.equal((await f.method('address-space-check')).status,'needs-evidence');await f.refresh();const b=await f.method('address-space-check');assert.equal(a.binding.contractDigest,b.binding.contractDigest);assert.notEqual(a.binding.contractRevision,b.binding.contractRevision);assert.notEqual(a.receiptDigest,b.receiptDigest);
 await assert.rejects(f.call({action:'method-applicability',method_id:'address-space-check',generation:a.binding.privateGeneration}),e=>e.code==='STALE_RESEARCH_GENERATION');
 f.ctx.dbRevision++;assert.equal((await f.method('address-space-check')).status,'needs-evidence');f.ctx.dbRevision--;f.ctx.attachmentId='attachment_'+randomUUID();assert.equal((await f.method('address-space-check')).status,'needs-evidence');
});
test('withdrawn reviewed public source invalidates method; corrupt dossier blocks, never falls back to prose',async t=>{
 const f=fixture(t);f.capture();f.mutate('initialize',contract);await f.refresh();
 const store=publicResearchStore(f.cfg.projectRoot),ref=METHOD_SPECS[1].sourceRefs[0];store.publish({expectedGeneration:store.current().generation,upserts:[],withdrawals:[{ref,reason:'fixture withdrawal',replacementRef:null}]});
 assert.equal((await f.method('address-space-check')).reason,'reviewed-source-missing-or-withdrawn');
 const snap=f.notes.get(f.ctx,f.task.taskId).systemEvidence[0];fs.appendFileSync(path.join(f.artifacts.directory('records'),snap.report_id+'.json'),' ');const r=await f.method('truncated-source-completion');assert.equal(r.status,'blocked');assert(r.diagnostics.length);
});
test('source change between independent reads fails closed and no foreign target ref is accepted',async t=>{
 const f=fixture(t);f.capture();f.mutate('initialize',contract);await f.refresh();let reads=0;
 assert.throws(()=>runMethodQuery({projectRoot:f.cfg.projectRoot,input:{action:'method-applicability',method_id:'address-space-check'},artifacts:f.artifacts,read:()=>{if(++reads===2)f.ctx.dbRevision++;return f.read();}}),e=>e.code==='SNAPSHOT_INCONSISTENT');
 f.ctx.dbRevision--;f.ctx.projectId='project_'+randomUUID();await assert.rejects(f.method('address-space-check'),/another project/);
});
test('all source bounds disclose omissions and missing prototype/architecture are never inferred from names',()=>{
 const r={kind:'function-dossier',status:'observed',sourceData:{function:{name:'arm64_vm_seed'},sections:{callees:{status:'truncated',data:{calls:[{ea:'0x00002000'},{ea:'0x2000'}]}}}},sourceRef:{id:'owned',sha256:'a'.repeat(64)}};
 const p=methodPredicates({records:[r]});assert.equal(p['multiple-callees'].value,'unknown');for(const id of ['prototype-known','architecture-supported','instance-identity','pure-expression'])assert.equal(p[id].value,'unknown');
});
