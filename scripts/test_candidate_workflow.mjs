// Synthetic committed source only. These tests never request a native/solver job.
import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import {randomUUID} from 'node:crypto';
import {bitvectorHost} from './fixtures/bitvector_host.mjs';import {identity,constant} from './fixtures/bitvector_cases.mjs';import {researchScopeDigest} from '../source/research_state.js';
const root=path.resolve(import.meta.dirname,'..');
function fixture(t){const directory=fs.mkdtempSync(path.join(os.tmpdir(),'ig5-bv-host-')),f=bitvectorHost(directory,root);t.after(async()=>{await f.dispose();assert.equal(path.dirname(directory),fs.realpathSync(os.tmpdir()));fs.rmSync(directory,{recursive:true,force:true});});return {...f,directory};}
test('prepare binds archived source and current target; read is scope bound and task state is unchanged',async t=>{
 const f=fixture(t),source=f.saveSource(),before=f.notes.get(f.context,f.task.taskId),prepared=await f.call({action:'candidate-prepare',source_ref:source,root_node:3});
 assert.equal(prepared.status,'prepared');assert.equal(prepared.variables[0].name,'ssa_0');assert.deepEqual(f.notes.get(f.context,f.task.taskId),before);assert.equal(f.lifter.active.size,0);
 const read=await f.call({action:'candidate-read',report_ref:prepared.candidateRef});assert.equal(read.validity,'current');assert.equal(read.result.irNativeCorrespondence,'not-proved-by-this-contract');
});
test('source bytes/SHA, IR bytes and current target cannot be silently replaced',async t=>{
 const f=fixture(t),source=f.saveSource();await assert.rejects(f.call({action:'candidate-prepare',source_ref:{...source,sha256:'a'.repeat(64)},root_node:3}),e=>e.code==='ARTIFACT_CHANGED');
 fs.appendFileSync(f.context.target,'mutated');await assert.rejects(f.call({action:'candidate-prepare',source_ref:source,root_node:3}),e=>e.code==='CANDIDATE_SOURCE_MISMATCH');assert.equal(f.lifter.active.size,0);
});
test('source mutation is retained as unsupported and never invokes a fallback native decoder',async t=>{
 const f=fixture(t),source=f.saveSource({op:'LOAD'});f.lifter.request=()=>{throw Error('must not invoke jobs');};
 const result=await f.call({action:'candidate-prepare',source_ref:source,root_node:3});assert.equal(result.status,'unsupported');assert.equal(f.lifter.active.size,0);
});
test('foreign task/project and contract ABA cannot reuse the old candidate subject',async t=>{
 const f=fixture(t),source=f.saveSource(),prepared=await f.call({action:'candidate-prepare',source_ref:source,root_node:3});
 const originalProject=f.context.projectId;f.context.projectId='project_'+randomUUID();await assert.rejects(f.call({action:'candidate-read',report_ref:prepared.candidateRef}));f.context.projectId=originalProject;
 const state=()=>f.research.get(f.notes.get(f.context,f.task.taskId),f.context);
 for(const question of ['B',f.declared.question])f.research.mutate(f.notes.get(f.context,f.task.taskId),f.context,{operation:'set-contract',expected_task_revision:0,expected_research_revision:state().researchRevision,scope_digest:researchScopeDigest(f.context),value:{...f.declared,question}},'f07-fixture');
 assert.equal((await f.call({action:'candidate-read',report_ref:prepared.candidateRef})).validity,'stale');await assert.rejects(f.call({action:'candidate-verify',candidate_ref:prepared.candidateRef,candidate_ast:identity()}),e=>e.code==='STALE_CANDIDATE_CONTRACT');
});
test('caller verified flag, extra variables and output width changes preserve original contract',async t=>{
 const f=fixture(t),source=f.saveSource(),prepared=await f.call({action:'candidate-prepare',source_ref:source,root_node:3});f.lifter.request=()=>{throw Error('invalid candidate must not start');};
 for(const candidate_ast of [{...identity(),verified:true},identity(16),{nodes:[{id:0,op:'var',bits:8,args:[],name:'foreign'}],root:0}])assert.equal((await f.call({action:'candidate-verify',candidate_ref:prepared.candidateRef,candidate_ast})).status,'unsupported');
 assert.equal((await f.call({action:'candidate-read',report_ref:prepared.candidateRef})).validity,'current');
});
test('an infeasible structured premise is retained as an assumption, never preapproved',async t=>{
 const f=fixture(t),source=f.saveSource(),prepared=await f.call({action:'candidate-prepare',source_ref:source,root_node:3,premise:constant(1,'0x0')});assert.equal(prepared.status,'prepared');const read=await f.call({action:'candidate-read',report_ref:prepared.candidateRef});assert.equal(read.result.premiseOrigin,'caller-declared-structured-assumption');assert.equal(read.result.businessAccepted,false);
});
