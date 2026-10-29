// Explicit synthetic-source / actual settled candidate worker + pinned independent solver acceptance.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';import {pathToFileURL} from 'node:url';import {performance} from 'node:perf_hooks';
const option=k=>{const i=process.argv.indexOf(k);assert(i>=0&&process.argv[i+1],k+' required');return path.resolve(process.argv[i+1]);};
const pluginRoot=option('--plugin-root'),out=option('--evidence'),protocolFile=option('--protocol');assert(!out.toLowerCase().startsWith(pluginRoot.toLowerCase()+path.sep));fs.mkdirSync(out,{recursive:false});
const protocol=JSON.parse(fs.readFileSync(protocolFile,'utf8'));assert.equal(protocol.provider,'ig5-local-bv-rewrite-v1');fs.copyFileSync(protocolFile,path.join(out,'preregistered-protocol.json'));
const load=f=>import(pathToFileURL(path.join(pluginRoot,f)).href),{bitvectorHost}=await load('scripts/fixtures/bitvector_host.mjs'),{PROVIDER_CASES,providerProjection}=await load('scripts/fixtures/provider_cases.mjs'),{identity,constant}=await load('scripts/fixtures/bitvector_cases.mjs'),{proposeLocalBitvector}=await load('source/bitvector_provider.js');
assert.deepEqual(PROVIDER_CASES.filter(c=>c.family==='heldout').map(c=>c.id),protocol.heldoutFamilies);
const f=bitvectorHost(out,pluginRoot),rows=[];let checks=0;
try{
 for(const c of PROVIDER_CASES){
  const result=providerProjection(c.ast,f.context.sha256),input=f.lifter.artifacts.put(fs.readFileSync(f.context.target)),outputRef=f.lifter.artifacts.put(Buffer.from(JSON.stringify(result)));
  const record=f.lifter.artifacts.save({kind:'projection',action:'project',target:f.context.target,input,outputRef,process:{childExitConfirmed:true,fixture:true,scope:'synthetic source only'},result},{pretty:true,maxBytes:4*1024**2}),source_ref={id:record.id,sha256:f.lifter.artifacts.metadata(record.id).result.recordSha256};
  const prepared=await f.call({action:'candidate-prepare',source_ref,root_node:c.ast.root,...(c.premise?{premise:c.premise}:{})}),taskBefore=f.notes.get(f.context,f.task.taskId);
  const start=performance.now(),answer=await f.call({action:'candidate-simplify',candidate_ref:prepared.candidateRef}),elapsedMs=performance.now()-start;
  assert.equal(answer.status,c.expected);assert.equal(answer.originalRetained,true);assert.equal(answer.assistEnabled,false);assert.equal(f.jobs.active,null);assert.equal(f.lifter.active.size,0);assert.deepEqual(f.notes.get(f.context,f.task.taskId),taskBefore);
  const history=await f.call({action:'candidate-read',report_ref:answer.proposalRef});assert.equal(history.validity,'current');
  if(c.family==='heldout'){assert.equal(answer.equivalentInIR,true);assert(answer.cost.candidate.nodes<answer.cost.original.nodes);assert(answer.cost.candidate.operators<answer.cost.original.operators);const read=await f.call({action:'candidate-read',report_ref:answer.verification.reportRef});assert.equal(read.result.status,'pass');assert.equal(read.result.cleanup.ownedRootExitConfirmed,true);checks++;}
  if(c.expected==='unchanged')assert.equal(answer.verificationAttempted,false);
  if(c.expected==='candidate-not-accepted'){assert.equal(answer.verification.status,'unsupported');assert.equal(answer.equivalentInIR,false);assert.equal(answer.candidate,null);}
  rows.push({id:c.id,family:c.family,expected:c.expected,source_ref,contractRef:prepared.candidateRef,answer,elapsedMs});
 }
 // Fixed corrupted-provider scenario: a syntactically valid, smaller wrong candidate still must fail F07.
 const prepared=await f.call({action:'candidate-prepare',source_ref:f.saveSource(),root_node:3}),originalRun=f.jobs.runSettled.bind(f.jobs);
 f.jobs.runSettled=async(kind,request,signal)=>{
  if(kind!=='bv-candidate-generate')return originalRun(kind,request,signal);
  const result=proposeLocalBitvector(request.contract);result.candidate=constant();const {planningDigest}=await load('source/planning_identity.js');result.candidateDigest=planningDigest(result.candidate);return result;
 };
 const rejected=await f.call({action:'candidate-simplify',candidate_ref:prepared.candidateRef});assert.equal(rejected.status,'candidate-not-accepted');assert.equal(rejected.verification.status,'fail');assert.equal(rejected.verification.counterexampleValid,true);assert.equal(rejected.candidate,null);f.jobs.runSettled=originalRun;
 const abort=new AbortController();abort.abort();f.execution.signal=abort.signal;await assert.rejects(f.call({action:'candidate-simplify',candidate_ref:prepared.candidateRef}));f.execution.signal=undefined;
 const heldout=rows.filter(r=>r.family==='heldout'),sum=(side,key)=>heldout.reduce((s,r)=>s+r.answer.cost[side][key],0),cost={originalNodes:sum('original','nodes'),candidateNodes:sum('candidate','nodes'),originalOperators:sum('original','operators'),candidateOperators:sum('candidate','operators')};
 assert(cost.candidateOperators<cost.originalOperators);assert.equal(checks,4);
 const acceptance={schema:'ig5-f08-owned-provider-acceptance-v1',provider:'ig5-local-bv-rewrite-v1',cases:rows.length,heldoutPassed:checks,controlsPassed:4,cost,rows,wrongCandidateIndependentlyRejected:rejected,preCancelledRejected:true,originalRetained:true,actualSettledProviderWorker:true,actualPinnedIndependentSolver:true,source:'owned synthetic committed projection; no opened native target or decoder',netBenefit:'Expression node/operator reduction only; wall-clock and end-task/model benefit not claimed',blind:false,realModelRuns:0,assistEnabled:false};
 fs.writeFileSync(path.join(out,'acceptance.json'),JSON.stringify(acceptance,null,2));console.log(JSON.stringify({cases:rows.length,heldout:checks,controls:4,cost,wrongCandidateRejected:true,actualPinnedSolver:true,assist:false}));
}finally{await f.dispose();}
