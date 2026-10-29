import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import os from 'node:os';import path from 'node:path';
import {proposeLocalBitvector} from '../source/bitvector_provider.js';
import {generateLocalCandidate,validateProviderOutput} from '../source/bitvector_provider_adapter.js';
import {evaluateBitvector} from '../source/bitvector_replay.js';import {planningDigest} from '../source/planning_identity.js';
import {AnalysisJobs} from '../source/analysis_jobs.js';
import {declaration,addZero,identity,constant} from './fixtures/bitvector_cases.mjs';import {bitvectorHost} from './fixtures/bitvector_host.mjs';
const root=path.resolve(import.meta.dirname,'..');
function contract(ast=addZero()){return declaration(ast);}
test('single internal provider reduces only validated AST and leaves the original immutable',()=>{
 const c=contract(),before=structuredClone(c),r=proposeLocalBitvector(c);assert.equal(r.status,'candidate');assert.deepEqual(r.candidate,identity());assert.equal(r.verified,false);assert.deepEqual(c,before);assert(r.cost.candidate.operators<r.cost.original.operators);
});
test('no-op retains byte-identical original rather than canonicalizing without benefit',()=>{
 const c=contract({nodes:[{id:0,op:'var',bits:8,args:[],name:'ssa_0'},{id:1,op:'const',bits:8,args:[],value:'0x1'},{id:2,op:'add',bits:8,args:[0,1]}],root:2});
 const r=proposeLocalBitvector(c);assert.equal(r.status,'unchanged');assert.deepEqual(r.candidate,c.original);assert.equal(r.candidateDigest,c.originalDigest);
});
test('double involutions, same-value cancellation, masks and product identities are width exact',()=>{
 const cases=[
  {nodes:[...identity().nodes,{id:1,op:'not',bits:8,args:[0]},{id:2,op:'not',bits:8,args:[1]}],root:2},
  {nodes:[...identity().nodes,{id:1,op:'xor',bits:8,args:[0,0]}],root:1},
  {nodes:[...identity().nodes,{id:1,op:'const',bits:8,args:[],value:'0xff'},{id:2,op:'and',bits:8,args:[0,1]}],root:2},
 ];for(const ast of cases){const c=contract(ast),r=proposeLocalBitvector(c);assert.equal(r.status,'candidate');for(let x=0;x<256;x++)assert.equal(evaluateBitvector(ast,c.variables,{ssa_0:BigInt(x)}),evaluateBitvector(r.candidate,c.variables,{ssa_0:BigInt(x)}));}
});
test('unknown, corrupted, overlimit output and provider verified authority cannot be accepted',()=>{
 const c=contract(),r=proposeLocalBitvector(c);for(const bad of [{...r,verified:true},{...r,candidateDigest:'a'.repeat(64)},{...r,cost:{original:r.cost.original,candidate:{nodes:0,operators:0}}},{...r,work:{...r.work,ruleChecks:513}},{...r,candidate:{...identity(),script:'execute'}}])assert.throws(()=>validateProviderOutput(c,bad));
 assert.throws(()=>proposeLocalBitvector({...c,originalDigest:'a'.repeat(64)}));
});
test('actual settled generation ends worker and cancellation is not a fallback success',async()=>{
 const jobs=new AnalysisJobs();try{const r=await generateLocalCandidate(jobs,contract());assert.equal(r.result.status,'candidate');assert.equal(jobs.active,null);const abort=new AbortController();abort.abort();await assert.rejects(generateLocalCandidate(jobs,contract(),abort.signal),e=>e.code==='ABORT_ERR');}finally{await jobs.dispose();}
});
test('real data-worker deadline terminates the owned worker and retains original without solver',async()=>{
 const jobs=new AnalysisJobs({timeoutMs:1}),c=contract(),digest=planningDigest(c);try{const result=await generateLocalCandidate(jobs,c);assert.equal(result.status,'fallback-original');assert.equal(result.code,'TIMEOUT');assert.equal(jobs.active,null);assert.equal(result.cleanupConfirmed,true);assert.equal(planningDigest(c),digest);}finally{await jobs.dispose();}
});
test('timeout, crash, missing dependency, excess output and invalid result preserve exact original',async()=>{
 const c=contract(),before=planningDigest(c);
 for(const code of ['TIMEOUT','ANALYSIS_FAILED','ERR_MODULE_NOT_FOUND','INPUT_LIMIT']){const result=await generateLocalCandidate({active:null,runSettled(){throw Object.assign(Error('owned fixture'),{code});}},c);assert.equal(result.status,'fallback-original');assert.equal(result.result,null);assert.equal(planningDigest(c),before);}
 const bad=await generateLocalCandidate({active:null,runSettled:async()=>({payload:'x'.repeat(70000)})},c);assert.equal(bad.status,'fallback-original');
});
test('unconfirmed worker cleanup cannot be reported as confirmed fallback cleanup',async()=>{
 const result=await generateLocalCandidate({active:{retained:true},runSettled(){throw Object.assign(Error('retained'),{code:'WORKER_CLEANUP_FAILED',cleanupConfirmed:false});}},contract());assert.equal(result.cleanupConfirmed,false);assert.equal(result.status,'fallback-original');
});
async function host(t){const dir=fs.mkdtempSync(path.join(os.tmpdir(),'ig5-provider-')),f=bitvectorHost(dir,root);t.after(async()=>{await f.dispose();assert.equal(path.dirname(dir),fs.realpathSync(os.tmpdir()));fs.rmSync(dir,{recursive:true,force:true});});return f;}
test('host timeout retains F07 contract and original; no solver dispatched and old manual interface still reads',async t=>{
 const f=await host(t),source=f.saveSource(),prepared=await f.call({action:'candidate-prepare',source_ref:source,root_node:3});f.lifter.request=()=>{throw Error('must not dispatch solver');};const original=f.jobs.runSettled.bind(f.jobs);
 f.jobs.runSettled=async()=>{throw Object.assign(Error('fixture timeout'),{code:'TIMEOUT'});};const result=await f.call({action:'candidate-simplify',candidate_ref:prepared.candidateRef});assert.equal(result.status,'fallback-original');assert.equal(result.verificationAttempted,false);assert.equal(result.originalRetained,true);
 f.jobs.runSettled=original;const history=await f.call({action:'candidate-read',report_ref:prepared.candidateRef});assert.equal(history.validity,'current');assert.deepEqual(history.result.original,prepared.original);
});
test('no-change host skips solver, proposal history is readable and no task is modified',async t=>{
 const f=await host(t),source=f.saveSource({value:'0x1'}),prepared=await f.call({action:'candidate-prepare',source_ref:source,root_node:3}),before=f.notes.get(f.context,f.task.taskId);f.lifter.request=()=>{throw Error('unchanged must not dispatch solver');};
 const result=await f.call({action:'candidate-simplify',candidate_ref:prepared.candidateRef});assert.equal(result.status,'unchanged');assert.equal(result.verificationAttempted,false);assert.equal((await f.call({action:'candidate-read',report_ref:result.proposalRef})).validity,'current');assert.deepEqual(f.notes.get(f.context,f.task.taskId),before);
});
test('corrupt provider output cannot reach independent solver',async t=>{
 const f=await host(t),source=f.saveSource(),prepared=await f.call({action:'candidate-prepare',source_ref:source,root_node:3});f.jobs.runSettled=async()=>({schema:'ig5-bitvector-provider-v1',verified:true});f.lifter.request=()=>{throw Error('corrupt output must not dispatch');};const result=await f.call({action:'candidate-simplify',candidate_ref:prepared.candidateRef});assert.equal(result.status,'fallback-original');assert.equal(result.verificationAttempted,false);
});
