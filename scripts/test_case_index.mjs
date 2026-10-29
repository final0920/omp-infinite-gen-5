import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID,createHash } from 'node:crypto';
import { AnalysisArtifacts } from '../source/analysis_artifacts.js';
import { InvestigationStore } from '../source/investigation_store.js';
import { ResearchState,researchScopeDigest } from '../source/research_state.js';
import { runWorkspace,captureDossier } from '../source/investigation_workflow.js';
import { privateResearchStore } from '../source/research_case_index.js';
import { caseTrustedScope,runCaseIndex,validateCaseIndexInput } from '../source/research_case_bridge.js';
import { FailureRecords } from '../source/failure_record.js';
import { installLcmBridge } from '../source/lcm_bridge.js';
import { dossierEvidence } from '../source/evidence_adapters/dossier.js';
import { contextPage } from './fixtures/vm_context_cases.mjs';
import { runVmContextProfile } from '../source/vm_context_profile.js';
const hash=b=>createHash('sha256').update(b).digest('hex');
const contract={question:'Known output versus algorithm explanation',inputDomain:'Only the stated inputs',returns:'One reported output',outputs:'Not yet complete',sideEffects:'Unknown',environment:'Static fixture',exclusions:'No native execution or whole function proof'};
function fixture(t,sha256=hash('owned case fixture')){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'ig5-case-')),cfg={projectRoot:path.join(root,'projects')};
 const ctx={projectId:'project_'+randomUUID(),artifactId:'artifact_'+sha256,sha256,engine:'reverse',provider:'ghidra',attachmentId:'attachment_'+randomUUID(),dbRevision:2,target:path.join(root,'owned.exe')};
 const notes=new InvestigationStore({root:cfg.projectRoot}),service=new ResearchState({root:cfg.projectRoot}),artifacts=new AnalysisArtifacts(path.join(root,'reports'));
 const task=notes.create(ctx,{goal:'Explain string outputs and distinct callee instances'},'owner');
 const session={engine:'reverse',target:ctx.target};
 const agent={id:randomUUID()};agent.session={header:{id:agent.id,cwd:root},log:[]};
 const mgr={analysis:{artifacts},investigations:notes,researchState:service,get:()=>session,alive:()=>true,checkCancelled(){},evidence:()=>({...ctx})};
 mgr.failures=new FailureRecords({root:cfg.projectRoot,artifacts});
 const exec={agent};
 const call=async input=>(await runWorkspace(mgr,cfg,{target:ctx.target,workspace:{id:task.taskId,...input}},exec)).workspace;
 const initialize=()=>service.mutate(notes.get(ctx,task.taskId),ctx,{operation:'initialize',expected_task_revision:notes.get(ctx,task.taskId).taskRevision,expected_research_revision:0,scope_digest:researchScopeDigest(ctx),value:contract},agent.id);
 const state=()=>service.get(notes.get(ctx,task.taskId),ctx);
 const mutate=(operation,value)=>service.mutate(notes.get(ctx,task.taskId),ctx,{operation,expected_task_revision:notes.get(ctx,task.taskId).taskRevision,expected_research_revision:state().researchRevision,scope_digest:researchScopeDigest(ctx),...(value?{value}:{})},agent.id);
 const refresh=async()=>{const before=await call({action:'case-status'});return call({action:'case-index',expected_generation:before.generation,expected_task_revision:notes.get(ctx,task.taskId).taskRevision,expected_research_revision:state().researchRevision});};
 const capture=()=>{const d={schemaVersion:1,kind:'function-dossier',provenance:{...ctx},_ig5:{...ctx},snapshotDigest:hash(randomUUID()),function:{ea:'0x1000',name:'decode_fixture'},sections:{decompile:{status:'ok',data:{code:'return 42; /* observed-output-marker */'}},cfg:{status:'truncated'},callers:{status:'unsupported'},callees:{status:'ok'},stack:{status:'error'}},responseTruncated:true,limitations:['Owned fixture, not a native execution']};return captureDossier(mgr,cfg,d,task.taskId,exec);};
 t.after(async()=>{await mgr.memory?.dispose();await artifacts.dispose();assert.equal(path.dirname(root),fs.realpathSync(os.tmpdir()));fs.rmSync(root,{recursive:true,force:true});});
 return {root,cfg,ctx,notes,task,service,artifacts,mgr,exec,call,initialize,state,mutate,refresh,capture};
}
async function readAll(f,ref){let body='',cursor;do{const r=await f.call({action:'case-read',ref,...(cursor?{cursor}:{})});assert.equal(r.offset,body.length);body+=r.body;cursor=r.nextCursor;assert.equal(r.semanticVerified,false);assert.equal(r.executionAuthorized,false);assert.equal(hash(body.slice(0)),hash(body));if(!cursor)assert.equal(hash(body),r.bodySha256);}while(cursor);return body;}
test('missing research contract returns needs-evidence without creating private directories',async t=>{
 const f=fixture(t),r=await f.call({action:'case-status'});assert.equal(r.status,'needs-evidence');assert.equal(r.reason,'research-contract-required');assert(!fs.existsSync(path.join(f.cfg.projectRoot,'private-research-v2')));
});
test('caller output and complete paginated source remain reported; no algorithm promotion or query writes',async t=>{
 const f=fixture(t);f.notes.update(f.ctx,f.task.taskId,{expected_task_revision:0,conclusion:'known-string-output '+('😀'.repeat(1500))},'owner');f.initialize();
 const before=f.notes.get(f.ctx,f.task.taskId);assert.equal((await f.call({action:'case-search',query:'known-string-output'})).status,'needs-index');
 const indexed=await f.refresh();assert(indexed.indexSaved);const found=await f.call({action:'case-search',query:'known-string-output'});assert.equal(found.total,1);assert.equal(found.items[0].status,'reported');assert.equal(found.items[0].algorithmExplained,'not-established-by-index');
 const body=await readAll(f,found.items[0].ref);assert(body.includes('😀'.repeat(1500)));assert.equal(JSON.parse(body).sourceData.conclusion,before.conclusion);assert.deepEqual(f.notes.get(f.ctx,f.task.taskId),before);
 const again=await f.refresh();assert.equal(again.indexSaved,false);assert.equal(again.generation,indexed.generation);assert(Buffer.byteLength(JSON.stringify(found))<32768);
});
test('runtime rejects caller scopes, status claims, paths, run identity and executable fields before target access',async t=>{
 for(const action of ['__proto__','constructor','toString'])assert.throws(()=>validateCaseIndexInput({action}),e=>e.code==='INVALID_ARGUMENT');
 const f=fixture(t);for(const extra of [{scope:{}},{projectId:f.ctx.projectId},{path:'C:/x'},{status:'verified-in-scope'},{runId:'run1'},{moduleEpoch:'epoch1'},{execute:true},{query:'x',ref:{id:'x',sha256:'a'.repeat(64)}}]){
  await assert.rejects(f.call({action:'case-search',query:'x',...extra}),e=>e.code==='INVALID_ARGUMENT');
 }
 f.initialize();await assert.rejects(f.call({action:'case-index',expected_generation:'absent',expected_task_revision:0,expected_research_revision:-0}),/explicit generation/);
 const saved=f.exec.agent;f.exec.agent=null;await assert.rejects(f.call({action:'case-status'}),e=>e.code==='AGENT_SCOPE_REQUIRED');f.exec.agent=saved;
});
test('CAS, research changes, task changes and contract ABA never silently reuse old fact scope',async t=>{
 const f=fixture(t);f.initialize();const first=await f.refresh();await assert.rejects(f.call({action:'case-index',expected_generation:'absent',expected_task_revision:0,expected_research_revision:0}),e=>e.code==='STALE_RESEARCH_GENERATION');
 f.mutate('add-hypothesis',{proposition:'callee-A and callee-B may implement different instances',supporting:[],opposing:[],competingExplanations:['One algorithm with different parameters']});
 assert.equal((await f.call({action:'case-search',query:'callee'})).status,'needs-refresh');const updated=await f.refresh();assert.notEqual(updated.generation,first.generation);
 const scopeA=(await f.call({action:'case-status'})).scope;
 f.mutate('set-contract',{...contract,question:'Another question'});f.mutate('set-contract',contract);const aba=await f.call({action:'case-status'});assert.equal(aba.status,'needs-refresh');assert.equal(aba.contractRevision,2);assert.equal(aba.scope.contractDigest,scopeA.contractDigest);
 f.notes.update(f.ctx,f.task.taskId,{expected_task_revision:0,conclusion:'new conclusion'},'owner');assert.equal((await f.call({action:'case-status'})).reason,'stale-research-context');
 f.mutate('acknowledge-context');const changed=await f.call({action:'case-status'});assert.equal(changed.status,'needs-index');assert.notEqual(changed.scope.taskRevision,scopeA.taskRevision);
});
test('same SHA in another project, another task and another attachment never grants old ref access',async t=>{
 const f=fixture(t);f.initialize();await f.refresh();const hit=(await f.call({action:'case-search',query:'Explain'})).items[0],original={...f.ctx};
 for(const patch of [{projectId:'project_'+randomUUID()},{sha256:hash('other'),artifactId:'artifact_'+hash('other')},{engine:'ghidra'},{provider:'commercial'}]){
  Object.assign(f.ctx,patch);await assert.rejects(f.call({action:'case-read',ref:hit.ref}),/another project|another target|another.*engine|another project, artifact, engine or provider/);Object.assign(f.ctx,original);
 }
 const other=f.notes.create(f.ctx,{goal:'Another same-target task'},'owner');f.service.mutate(other,f.ctx,{operation:'initialize',expected_task_revision:0,expected_research_revision:0,scope_digest:researchScopeDigest(f.ctx),value:contract},'owner');
 const otherCall=async input=>(await runWorkspace(f.mgr,f.cfg,{target:f.ctx.target,workspace:{id:other.taskId,...input}},f.exec)).workspace;
 assert.equal((await otherCall({action:'case-read',ref:hit.ref})).status,'needs-index');
 f.ctx.attachmentId='attachment_'+randomUUID();assert.equal((await f.call({action:'case-read',ref:hit.ref})).status,'needs-evidence');
 Object.assign(f.ctx,original);f.ctx.dbRevision++;assert.equal((await f.call({action:'case-read',ref:hit.ref})).status,'needs-evidence');
});
test('cursor binds exact generation, source stamp, task scope, ref and Unicode boundaries',async t=>{
 const f=fixture(t);f.notes.update(f.ctx,f.task.taskId,{expected_task_revision:0,conclusion:'long-body '+('😀'.repeat(1600))},'owner');f.initialize();await f.refresh();const ref=(await f.call({action:'case-search',query:'long-body'})).items[0].ref;
 const first=await f.call({action:'case-read',ref});assert(first.nextCursor);const c=JSON.parse(Buffer.from(first.nextCursor,'base64url'));
 for(const patch of [{generation:'a'.repeat(64)},{scope:'b'.repeat(64)},{stamp:'c'.repeat(64)},{offset:-1},{offset:1.5},{ref:{id:'other',sha256:ref.sha256}},{extra:true}]){
  const cursor=Buffer.from(JSON.stringify({...c,...patch})).toString('base64url');await assert.rejects(f.call({action:'case-read',ref,cursor}),e=>e.code==='INVALID_CASE_CURSOR');
 }
 const body=await readAll(f,ref);assert(body.includes('😀'.repeat(1600)));
 f.mutate('add-hypothesis',{proposition:'changed research',supporting:[],opposing:[],competingExplanations:['Another interpretation']});await f.refresh();await assert.rejects(f.call({action:'case-read',ref,cursor:first.nextCursor}),e=>e.code==='INVALID_CASE_CURSOR');
 const history=await f.call({action:'case-read',ref});assert.equal(history.recordState,'superseded');assert.equal(history.status,'stale');assert.equal(history.currentSources,false);
});
test('committed dossier is searchable but truncated CFG and corruption never become a semantic result',async t=>{
 const f=fixture(t);f.capture();f.initialize();await f.refresh();const found=await f.call({action:'case-search',query:'observed-output-marker'});assert.equal(found.total,1);assert.equal(found.items[0].status,'observed');
 const body=JSON.parse(await readAll(f,found.items[0].ref));assert.equal(body.sourceData.sections.cfg.status,'truncated');assert.equal(body.semanticVerified,false);
 const snap=f.notes.get(f.ctx,f.task.taskId).systemEvidence[0],filename=path.join(f.artifacts.directory('records'),snap.report_id+'.json');fs.appendFileSync(filename,' ');
 const stale=await f.call({action:'case-search',query:'observed-output-marker'});assert.equal(stale.status,'needs-refresh');assert.equal(stale.diagnostics[0].code,'ARTIFACT_CHANGED');assert.equal(stale.items,undefined);
 await f.refresh();const old=await f.call({action:'case-read',ref:found.items[0].ref});assert.equal(old.status,'stale');assert.equal(old.recordState,'withdrawn');
});
test('persisted failure receipt is re-bound and caller completion cannot become verified',async t=>{
 const f=fixture(t);f.initialize();const failure=f.mgr.failures.add({operation:'owned-parse',scope:{...f.ctx},semanticInputs:{kind:'fixture'},error:Object.assign(new Error('known failure; retained unknown'),{code:'FIXTURE_FAILURE'})});assert(failure.reportSaved);
 await f.refresh();const found=await f.call({action:'case-search',query:'FIXTURE_FAILURE'});assert.equal(found.items[0].status,'observed');const body=JSON.parse(await readAll(f,found.items[0].ref));assert.equal(body.sourceData.original.code,'FIXTURE_FAILURE');assert.equal(body.algorithmExplained,'not-established-by-index');
 const restored=new FailureRecords({root:f.cfg.projectRoot,artifacts:f.artifacts});assert.equal(restored.recent(f.ctx)[0].reportRef.sha256,failure.reportRef.sha256);
});
test('real LCM bridge provides only executing-session navigation; captured text never enters private facts',async t=>{
 const f=fixture(t);f.initialize();await f.refresh();f.exec.agent.session.log.push({seq:1,type:'user/message',data:{text:'historical secret '+f.task.taskId}});
 f.mgr.memory=installLcmBridge({on(){return ()=>{};}},f.cfg);
 const found=await f.call({action:'case-search',query:'historical secret'});assert.equal(found.total,0);assert.equal(found.historyNavigation.status,'session-navigation-only');assert.equal(found.historyNavigation.contentIndexed,false);assert.equal(found.historyNavigation.reads.length,1);assert(!JSON.stringify(found).includes('historical secret'));
 const recovered=await f.mgr.memory.handle(f.exec.agent,found.historyNavigation.reads[0].memory);assert(recovered.text.includes(f.task.taskId));
});
test('context drift after awaited memory lookup fails closed, and post-commit source drift preserves save receipt',async t=>{
 const f=fixture(t);f.initialize();await f.refresh();f.mgr.memory={async handle(){f.ctx.dbRevision++;return {hits:[]};}};
 await assert.rejects(f.call({action:'case-search',query:'Explain'}),e=>e.code==='SNAPSHOT_INCONSISTENT');f.mgr.memory=null;f.ctx.dbRevision--;
 const data=()=>({context:{...f.ctx},task:f.notes.get(f.ctx,f.task.taskId),research:f.state(),failures:[]});let reads=0;
 const scope=caseTrustedScope(data()).scope,store=privateResearchStore(f.cfg.projectRoot,scope),old=store.current();
 f.mutate('add-hypothesis',{proposition:'new proposal',supporting:[],opposing:[],competingExplanations:['alternative']});
 const result=await runCaseIndex({projectRoot:f.cfg.projectRoot,input:{action:'case-index',id:f.task.taskId,expected_generation:old.generation,expected_task_revision:0,expected_research_revision:f.state().researchRevision},read:()=>{reads++;if(reads===3)throw Error('after commit unavailable');return data();},artifacts:f.artifacts,execution:f.exec});
 assert.equal(result.indexSaved,true);assert.equal(result.postCommitContext,'unavailable');assert.notEqual(result.generation,old.generation);assert.equal(store.current().generation,result.generation);
});
test('bounded source selection discloses omissions and never writes queried text into shared knowledge',async t=>{
 const f=fixture(t);f.initialize();for(let i=0;i<10;i++)f.mutate('add-hypothesis',{proposition:'hypothesis '+i,supporting:[],opposing:[],competingExplanations:['alternative']});await f.refresh();
 const r=await f.call({action:'case-search',query:'hypothesis'});assert.equal(r.omittedSources.hypotheses,2);assert.equal(r.items.length,3);assert(r.omittedMatches>=5);assert(!fs.existsSync(path.join(f.cfg.projectRoot,'knowledge-v1')));assert(!fs.existsSync(path.join(f.cfg.projectRoot,'knowledge-v2')));
});
test('explicit opposing source links remain contested and do not imply an independently decided contradiction',async t=>{
 const f=fixture(t);f.capture();f.capture();f.initialize();
 for(const snapshot of f.notes.get(f.ctx,f.task.taskId).systemEvidence){const task=f.notes.get(f.ctx,f.task.taskId),state=f.state();
  f.service.mutate(task,f.ctx,{operation:'link-evidence',expected_task_revision:task.taskRevision,expected_research_revision:state.researchRevision,scope_digest:researchScopeDigest(f.ctx)},'owner',{evidence:dossierEvidence(f.artifacts,task,snapshot.snapshot_id)});
 }
 const links=f.state().evidenceLinks;
 f.mutate('add-hypothesis',{proposition:'HALT comment conflicts with implementation; result may be preserved',supporting:[links[0].id],opposing:[links[1].id],competingExplanations:['The comment describes an older implementation']});
 await f.refresh();const hit=(await f.call({action:'case-search',query:'HALT'})).items[0];assert.equal(hit.status,'contested');assert.equal(JSON.parse(await readAll(f,hit.ref)).semanticVerified,false);
});
test('verifier history, even stored pass, cannot close an obligation or grant proof through the index',async t=>{
 const f=fixture(t,'a'.repeat(64));f.initialize();
 const parents=[0,1].map(i=>{const saved=f.artifacts.save({kind:'vm-recorded-handlers',action:'assess',result:contextPage(i,f.artifacts).handlers});return {id:saved.id,sha256:f.artifacts.metadata(saved.id).result.recordSha256};});
 const model=runVmContextProfile(f.mgr,{handler_refs:parents}).context;
 await f.call({action:'research-update',report_ref:{id:model.reportId,sha256:model.reportSha256},research:{operation:'link-vm-context',expected_task_revision:0,expected_research_revision:f.state().researchRevision,scope_digest:researchScopeDigest(f.ctx)}});
 const state=f.state(),task=f.notes.get(f.ctx,f.task.taskId);
 const saved=f.artifacts.save({kind:'research-verification',action:'verify',association:{taskId:task.taskId,scopeDigest:state.scopeDigest},result:{status:'pass',contractDigest:state.contractDigest,contractRevision:state.contractRevision,claim:'stored-pass-marker',scope:{targetSha256:f.ctx.sha256},limitations:['synthetic integrity-only report; not a valid typed proof']}},{maxBytes:256*1024});
 f.service.linkVerification(task,f.ctx,{expected_task_revision:task.taskRevision,expected_research_revision:state.researchRevision,scope_digest:state.scopeDigest},{reportId:saved.id,sha256:f.artifacts.metadata(saved.id).result.recordSha256},'owner');
 await f.refresh();const hit=(await f.call({action:'case-search',query:'stored-pass-marker'})).items[0];assert.equal(hit.status,'reported');assert.equal(JSON.parse(await readAll(f,hit.ref)).sourceData.status,'pass');assert.equal(f.state().acceptanceStatus,'not-assessed');
 f.mutate('set-contract',{...contract,question:'changed contract'});await f.refresh();assert.equal((await f.call({action:'case-search',query:'stored-pass-marker'})).items[0].status,'stale');
});
test('new task retrieves prior same-project output while another project stays absent and prior task edits invalidate the index',async t=>{
 const f=fixture(t);
 const prior=f.notes.create(f.ctx,{goal:'Older decoding task'},'owner');f.notes.update(f.ctx,prior.taskId,{expected_task_revision:0,conclusion:'prior-output-token 已知输出，但算法未解释'},'owner');
 const foreign={...f.ctx,projectId:'project_'+randomUUID()},alien=f.notes.create(foreign,{goal:'Other project'},'owner');f.notes.update(foreign,alien.taskId,{expected_task_revision:0,conclusion:'foreign-output-token'},'owner');
 f.initialize();await f.refresh();const found=await f.call({action:'case-search',query:'prior-output-token'});assert.equal(found.total,1);assert.equal(found.items[0].status,'reported');
 const body=JSON.parse(await readAll(f,found.items[0].ref));assert.equal(body.sourceData.taskId,prior.taskId);assert.equal(body.sourceContext.currentFact,false);assert.equal(body.sourceContext.dbRevision,null);assert.equal(body.algorithmExplained,'not-established-by-index');
 assert.equal((await f.call({action:'case-search',query:'foreign-output-token'})).total,0);
 f.notes.update(f.ctx,prior.taskId,{expected_task_revision:1,conclusion:'changed-output-token'},'owner');assert.equal((await f.call({action:'case-search',query:'prior-output-token'})).status,'needs-refresh');
 await f.refresh();assert.equal((await f.call({action:'case-search',query:'prior-output-token'})).total,0);assert.equal((await f.call({action:'case-search',query:'changed-output-token'})).total,1);
});
