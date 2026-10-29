// Explicit owned synthetic-source / actual pinned SMT + Windows Job + independent data-worker acceptance.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';import {pathToFileURL} from 'node:url';
const option=k=>{const i=process.argv.indexOf(k);assert(i>=0&&process.argv[i+1],k+' required');return path.resolve(process.argv[i+1]);};
const pluginRoot=option('--plugin-root'),out=option('--evidence');assert(!out.toLowerCase().startsWith(pluginRoot.toLowerCase()+path.sep),'Evidence outside product source');fs.mkdirSync(out,{recursive:false});
const load=relative=>import(pathToFileURL(path.join(pluginRoot,relative)).href),{bitvectorHost}=await load('scripts/fixtures/bitvector_host.mjs'),{identity,constant}=await load('scripts/fixtures/bitvector_cases.mjs'),{researchScopeDigest}=await load('source/research_state.js');
const f=bitvectorHost(out,pluginRoot),rows=[];let lastPrepared,lastResult;
try{
 const cases=[
  {id:'8bit-add-zero',options:{},candidate:identity(),expected:'pass'},
  {id:'wrong-zero',options:{},candidate:constant(),expected:'fail'},
  {id:'constant-source-no-variables',options:{},sourceRoot:2,candidate:constant(),expected:'pass'},
  {id:'64bit-add-zero',options:{bits:64},candidate:identity(64),expected:'pass'},
  {id:'64bit-low-byte-is-not-full-value',options:{bits:64},candidate:{nodes:[{id:0,op:'var',bits:64,args:[],name:'ssa_0'},{id:1,op:'extract',bits:8,args:[0],offset:0},{id:2,op:'zext',bits:64,args:[1]}],root:2},expected:'fail'},
  {id:'shift-count-not-masked',options:{op:'INT_LEFT',value:'0x8'},candidate:constant(),expected:'pass'},
  {id:'truncated-add-then-extend',options:{value:'0x1',extend:{op:'INT_ZEXT',bits:16}},sourceRoot:4,candidate:{nodes:[{id:0,op:'var',bits:8,args:[],name:'ssa_0'},{id:1,op:'zext',bits:16,args:[0]},{id:2,op:'const',bits:16,args:[],value:'0x1'},{id:3,op:'add',bits:16,args:[1,2]}],root:3},expected:'fail'},
  {id:'signed-vs-zero-extension',options:{extend:{op:'INT_SEXT',bits:16}},sourceRoot:4,candidate:{nodes:[{id:0,op:'var',bits:8,args:[],name:'ssa_0'},{id:1,op:'zext',bits:16,args:[0]}],root:1},expected:'fail'},
  {id:'infeasible-premise',options:{},premise:constant(1,'0x0'),candidate:identity(),expected:'unsupported'},
  {id:'conditional-zero-only',options:{},premise:{nodes:[{id:0,op:'var',bits:8,args:[],name:'ssa_0'},{id:1,op:'const',bits:8,args:[],value:'0x0'},{id:2,op:'eq',bits:1,args:[0,1]}],root:2},candidate:constant(),expected:'pass'},
  {id:'wrong-under-satisfiable-premise',options:{},premise:{nodes:[{id:0,op:'var',bits:8,args:[],name:'ssa_0'},{id:1,op:'const',bits:8,args:[],value:'0x0'},{id:2,op:'eq',bits:1,args:[0,1]}],root:2},candidate:constant(8,'0x1'),expected:'fail'},
 ];
 for(const c of cases){
  const source=f.saveSource(c.options),prepared=await f.call({action:'candidate-prepare',source_ref:source,root_node:c.sourceRoot??3,...(c.premise?{premise:c.premise}:{})});assert.equal(prepared.status,'prepared');
  const result=await f.call({action:'candidate-verify',candidate_ref:prepared.candidateRef,candidate_ast:c.candidate});assert.equal(result.status,c.expected);assert.equal(result.current,true);assert.equal(result.cleanup.ownedRootExitConfirmed,true);assert.equal(f.lifter.active.size,0);assert.equal(f.jobs.active,null);
  const read=await f.call({action:'candidate-read',report_ref:result.reportRef});assert.equal(read.validity,'current');assert.equal(read.result.status,c.expected);assert(read.result.assessment.queries.length<=2);assert(read.result.assessment.queries.every(q=>q.timeoutMs<=2000));
  if(c.expected==='pass')assert.equal(result.equivalentInIR,true);if(c.expected==='fail')assert.equal(result.counterexampleValid,true);if(c.expected==='unsupported')assert.equal(result.equivalentInIR,false);
  rows.push({id:c.id,source,prepared,result,assessment:read.result.assessment,verifier:read.result.verifier,process:read.result.process});lastPrepared=prepared;lastResult=result;
 }
 const unsupported=await f.call({action:'candidate-verify',candidate_ref:lastPrepared.candidateRef,candidate_ast:{...identity(),verified:true}});assert.equal(unsupported.status,'unsupported');
 const controller=new AbortController();controller.abort();f.execution.signal=controller.signal;await assert.rejects(f.call({action:'candidate-verify',candidate_ref:lastPrepared.candidateRef,candidate_ast:identity()}));f.execution.signal=undefined;assert.equal(f.lifter.active.size,0);
 const state=()=>f.research.get(f.notes.get(f.context,f.task.taskId),f.context);
 for(const question of ['B',f.declared.question])f.research.mutate(f.notes.get(f.context,f.task.taskId),f.context,{operation:'set-contract',expected_task_revision:0,expected_research_revision:state().researchRevision,scope_digest:researchScopeDigest(f.context),value:{...f.declared,question}},'f07-fixture');
 const stale=await f.call({action:'candidate-read',report_ref:lastResult.reportRef});assert.equal(stale.validity,'stale');await assert.rejects(f.call({action:'candidate-verify',candidate_ref:lastPrepared.candidateRef,candidate_ast:identity()}),e=>e.code==='STALE_CANDIDATE_CONTRACT');
 await fs.promises.writeFile(path.join(out,'acceptance.json'),JSON.stringify({schema:'ig5-f07-owned-candidate-runtime-acceptance-v1',cases:rows.length,rows,callerVerifiedRejected:true,preCancelledRejected:true,contractABAStale:true,sourceScope:'owned synthetic committed projection; no actual native decoder or opened engine',actualPinnedSolverAndOwnedProcess:true,actualIndependentSettledDataWorker:true,nativeTargetsExecuted:0,blocked4551Retried:false,realModelRuns:0,assistEnabled:false},null,2));
 console.log(JSON.stringify({cases:rows.length,pass:rows.filter(r=>r.result.status==='pass').length,fail:rows.filter(r=>r.result.status==='fail').length,unsupported:rows.filter(r=>r.result.status==='unsupported').length,actualPinnedSolver:true,source:'synthetic',nativeTargetsExecuted:0,assistEnabled:false}));
}finally{await f.dispose();}
