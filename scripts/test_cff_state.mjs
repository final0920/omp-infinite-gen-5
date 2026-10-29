import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import os from 'node:os';import path from 'node:path';
import {analyzeCffState} from '../source/cff_state.js';import {captureCffStateSource,admitCffStateSource} from '../source/cff_state_workflow.js';
import {defineAdvancedTools} from '../advanced_tools.js';import {bitvectorHost} from './fixtures/bitvector_host.mjs';
import {stateGraph,pythonStateOracle,capturedStateReport,ssa,constant} from './fixtures/cff_state_cases.mjs';
import {AnalysisJobs} from '../source/analysis_jobs.js';
const pluginRoot=path.resolve(import.meta.dirname,'..'),ref={id:'11111111-1111-4111-8111-111111111111',sha256:'a'.repeat(64)};
const graph=options=>{const g=stateGraph(options);g.deobfuscation=pythonStateOracle(g,pluginRoot);return g;};
test('independent Python and JS agree on cross-block phi incoming routes, competing variables and effect retention',()=>{
 const g=graph(),before=structuredClone(g),r=analyzeCffState(g,ref);assert.deepEqual(g,before);assert.equal(r.stateDependencies.competingVariables.length,2);assert.deepEqual(r.overlay.stateRelations.map(p=>[p.predecessor,p.destination,p.status]),[[0,2,'verified-in-scope'],[2,3,'verified-in-scope'],[3,5,'verified-in-scope']]);
 assert(r.stateDependencies.dependencyEdges.length);assert.equal(r.stateDependencies.selectedVariable,null);assert.equal(r.retainedEffects.stateWritesRemoved,0);assert.equal(r.originalGraph.edges.length,g.edges.length);assert.equal(r.cffProved,false);assert(r.overlay.unknownExits.some(e=>e.opcode==='STORE'));
});
test('predecessor order is semantic: permuting aligned phi slots changes route, never sorts them',()=>{
 const g=stateGraph();g.blocks[1].instructions[0].inputs=[constant(3),constant(2),constant(1)];g.deobfuscation=pythonStateOracle(g,pluginRoot);const r=analyzeCffState(g,ref);assert.equal(r.overlay.stateRelations.find(p=>p.predecessor===0).destination,5);
});
test('loop-carried state reaches conservative fixed point; no global constant or complete recovery claim',()=>{
 const r=analyzeCffState(graph({loop:true}),ref);assert.equal(r.budget.exhausted,false);assert.equal(r.wholeFunctionRecovered,false);assert(r.stateDependencies.dependencyEdges.some(e=>e.from===1&&e.to===5));assert(r.stateDependencies.dependencyEdges.some(e=>e.from===5&&e.to===1));assert(r.overlay.unknownExits.some(e=>e.kind==='unknown-condition'));
});
test('unknown CALL and dispatcher STORE preserve effects and withhold affected routes',()=>{
 const call=analyzeCffState(graph({unknown:true}),ref);assert(!call.overlay.stateRelations.some(r=>r.predecessor===3&&r.status==='verified-in-scope'));assert(call.overlay.unknownExits.some(e=>e.opcode==='CALL'));
 const store=analyzeCffState(graph({sideEffectInDispatcher:true}),ref);assert.equal(store.overlay.stateRelations.length,0);assert(store.overlay.unknownExits.some(e=>e.kind==='unknown-effect-boundary'));
});
test('ordinary switch without SSA state phi is not identified as flattening',()=>{
 const r=analyzeCffState(graph({ordinarySwitch:true}),ref);assert.equal(r.dispatcherCandidates.length,0);assert.equal(r.overlay.stateRelations.length,0);assert.equal(r.cffProved,false);
});
test('partial graph, missing candidate, corrupt Python route cannot become independently verified',()=>{
 for(const mutate of [g=>{g.partial=true;g.scopeComplete=false;},g=>delete g.deobfuscation,g=>g.deobfuscation.dispatcherRoutes.forEach(r=>r.destination=999)]){
  const g=graph();mutate(g);const r=analyzeCffState(g,ref);assert(r.overlay.stateRelations.every(r=>r.status==='candidate'));
 }
});
test('duplicate definitions, conflicting identities, wrong phi arity and non-dominating uses reject',()=>{
 for(const mutate of [g=>g.blocks[1].instructions[1].output=ssa(1),g=>g.blocks[1].instructions[0].inputs[0]=ssa(1,2),g=>g.blocks[1].instructions[0].inputs.pop(),g=>g.blocks[1].instructions[2].inputs[0]=ssa(5)]){
  const g=graph({loop:true});mutate(g);assert.throws(()=>analyzeCffState(g,ref),{code:'UNSUPPORTED_CFF_STATE'});
 }
});
test('wrong branch polarity slots do not produce a proof and endpoint disagreements reject',()=>{
 const g=graph();g.blocks[1].trueSuccessor=999;assert(analyzeCffState(g,ref).overlay.stateRelations.every(r=>r.dispatcher!==1||r.status!=='verified-in-scope'));
 const h=graph();h.edges.pop();assert.throws(()=>analyzeCffState(h,ref),{code:'UNSUPPORTED_CFF_STATE'});
});
function fixture(t){const dir=fs.mkdtempSync(path.join(os.tmpdir(),'ig5-cff-state-')),f=bitvectorHost(dir,pluginRoot);f.session=f.mgr.get();f.session.target=f.context.target;f.mgr.sessions=new Map([[f.context.target,f.session]]);t.after(async()=>{await f.dispose();assert.equal(path.dirname(dir),fs.realpathSync(os.tmpdir()));fs.rmSync(dir,{recursive:true,force:true});});return f;}
function capture(f,options={}){const args={action:'deobfuscate',task_id:f.task.taskId},before=admitCffStateSource(f.mgr,f.cfg,f.session,args,f.execution),r=capturedStateReport(f,pluginRoot,options);return captureCffStateSource(f.mgr,f.cfg,f.session,args,r,f.execution,before);}
test('public RPC opt-in capture, immutable source, actual settled worker and stale history end-to-end',async t=>{
 const f=fixture(t),r=capturedStateReport(f,pluginRoot),seen=[];f.mgr.rpc=async(s,m,a)=>{seen.push({s,m,a});return r;};
 const tool=defineAdvancedTools(f.mgr,f.cfg,()=>{}).find(t=>t.name==='ig5_microcode'),taskBefore=f.notes.get(f.context,f.task.taskId);
 const saved=await tool.execute({target:f.context.target,ea:'0x1000',action:'deobfuscate',task_id:f.task.taskId},f.execution);assert(saved.sourceRef);assert(!('task_id'in seen[0].a));
 const result=await f.call({action:'cff-state',source_ref:saved.sourceRef});assert.equal(result.summary.verifiedRoutes,3);assert.equal(result.summary.cleanupConfirmed,true);assert.equal(f.jobs.active,null);assert.equal(f.lifter.active.size,0);assert.deepEqual(f.notes.get(f.context,f.task.taskId),taskBefore);assert.equal((await f.call({action:'cff-read',report_ref:result.reportRef})).validity,'current');
 const listed=await f.mgr.analysis.artifacts.list({target:f.context.target,engine:'ghidra'});
 for(const id of [saved.sourceRef.id,result.reportRef.id]){
  assert(listed.items.some(row=>row.id===id),'Current target must expose its source and derived report');
  const record=f.mgr.analysis.artifacts.get(id);assert.equal(record.association.target,f.context.target);assert.equal(record.association.engine,'ghidra');
 }
 assert.equal((await f.mgr.analysis.artifacts.list({target:f.context.target+'.other',engine:'ghidra'})).items.length,0);
 assert.equal((await f.mgr.analysis.artifacts.list({target:f.context.target,engine:'reverse'})).items.length,0);
 f.context.dbRevision++;await assert.rejects(f.call({action:'cff-state',source_ref:saved.sourceRef}));
});
test('caller graph/state/budget injection and unauthorized capture fail before RPC',async t=>{
 const f=fixture(t);let calls=0;f.mgr.rpc=()=>{calls++;throw Error('Not dispatched');};const tool=defineAdvancedTools(f.mgr,f.cfg,()=>{}).find(t=>t.name==='ig5_microcode');
 assert.throws(()=>tool.execute({action:'deobfuscate',task_id:f.task.taskId}),{code:'AGENT_SCOPE_REQUIRED'});assert.throws(()=>tool.execute({action:'deobfuscate',task_id:'bad'},f.execution));assert.equal(calls,0);
 const saved=capture(f);for(const extra of [{graph:{}},{state:1},{budget:900000},{verified:true}])await assert.rejects(f.call({action:'cff-state',source_ref:saved.sourceRef,...extra}),{code:'INVALID_ARGUMENT'});
});
test('altered full source/target bytes and cancellation fail closed',async t=>{
 const f=fixture(t),saved=capture(f),a=new AbortController();a.abort();f.execution.signal=a.signal;await assert.rejects(f.call({action:'cff-state',source_ref:saved.sourceRef}),{code:'ABORT_ERR'});f.execution.signal=undefined;
 fs.appendFileSync(f.context.target,'changed');await assert.rejects(f.call({action:'cff-state',source_ref:saved.sourceRef}));
});
test('full saved source tamper cannot acquire a current route receipt',async t=>{
 const f=fixture(t),saved=capture(f),artifacts=f.mgr.analysis.artifacts;
 const record=path.join(artifacts.directory('records'),saved.sourceRef.id+'.json');fs.appendFileSync(record,' ');
 await assert.rejects(f.call({action:'cff-state',source_ref:saved.sourceRef}),{code:'ARTIFACT_CHANGED'});
});
test('contract ABA keeps old report stale even when declaration returns to original bytes',async t=>{
 const f=fixture(t),saved=capture(f),answer=await f.call({action:'cff-state',source_ref:saved.sourceRef});
 for(const value of [{...f.declared,question:'other'},f.declared]){const task=f.notes.get(f.context,f.task.taskId),state=f.research.get(task,f.context);f.research.mutate(task,f.context,{operation:'set-contract',expected_task_revision:task.taskRevision,expected_research_revision:state.researchRevision,scope_digest:state.scopeDigest,value},'owner');}
 assert.equal((await f.call({action:'cff-read',report_ref:answer.reportRef})).validity,'stale');
});
test('actual state replay worker timeout confirms termination before rejecting and releases slot',async()=>{
 const jobs=new AnalysisJobs({timeoutMs:1});try{await assert.rejects(jobs.runSettled('cff-state-replay',{report:graph(),sourceRef:ref}),{code:'TIMEOUT'});assert.equal(jobs.active,null);assert.equal(jobs.queue.length,0);}finally{await jobs.dispose();}
});
