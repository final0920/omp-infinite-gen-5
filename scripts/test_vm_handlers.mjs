import test from'node:test';import assert from'node:assert/strict';import path from'node:path';import{execFileSync}from'node:child_process';
import{assessRecordedHandler,bindRecordedHandlerControl}from'../source/recorded_handler_eval.js';
import{evaluator}from'../source/flow_state_eval.js';
import{checkedProjectionReferences}from'../source/projection_jobs.js';
import{selectRecordedHandlerBodies}from'../source/vm_handler_window.js';
import{analyzeFlowRecurrences}from'../source/vm_flow_recurrences.js';
import{recurrenceCase}from'./fixtures/flow_recurrence_cases.mjs';
import{replaceObservationRows}from'./fixtures/vm_observation_cases.mjs';
import{runRecoveryProfile,recoveryProfileSchema}from'../source/vm_recovery_profile.js';
import{validateHandlerAssessment}from'../source/vm_handler_profile.js';
import fs from'node:fs';import os from'node:os';import{AnalysisArtifacts}from'../source/analysis_artifacts.js';import{createAnalysisService}from'../analysis_tools.js';
const root=path.resolve(import.meta.dirname,'..'),py=path.join(root,'runtimes/ghidra/python/python.exe');
const cores=JSON.parse(execFileSync(py,['-I','-B','-X','utf8',path.join(root,'scripts/fixtures/recorded_handler_cases.py')],{cwd:root,windowsHide:true,encoding:'utf8',maxBuffer:1024**2}));
const GPRS='rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split(' '),MASK=(1n<<64n)-1n,delta=0x70000000n,hx=n=>'0x'+n.toString(16);
function fixture(index,{taken=true,alias=false}={}){
  const core=structuredClone(cores[index]),state=Object.fromEntries(GPRS.map(g=>[g,0n]));
  Object.assign(state,{rbx:index===0?0x8000n:taken?4n:MASK,r10:index===0?0n:taken?9n:2n,rcx:alias?0x8000n:0xa000n,rsp:0x9000n});
  const groups=[],mapping={runtimeBase:hx(delta),preferredBase:'0x0',mapping:[]},decoded=[];
  for(const[i,p]of core.decodedPath.entries()){
    const pc=hx(BigInt(p.ea)+delta),before={rip:pc,gprs:Object.fromEntries(GPRS.map(g=>[g,hx(state[g])]))},reads=[];
    if(index===0){if(i===0){reads.push({address:'0x8000',bytes:8,littleEndianHex:'efcdab8967452301'});state.rax=0x123456789abcdefn;}if(i===1)state.rax=(~state.rax)&MASK;}
    else{
      if(i===0)state.rbx=(state.rbx+state.r10)&MASK;
      if(index===2&&i===1)state.rsp-=8n;
      if(index===2&&i===2){reads.push({address:hx(state.rsp),bytes:8,littleEndianHex:'0202000000000000'});state.rsp+=8n;state.r10=0x202n;}
    }
    const last=i===core.decodedPath.length-1,condition=index!==1||taken;
    const after={rip:last?(condition?hx(delta+0x2000n):hx(BigInt(p.ea)+delta+BigInt(p.bytes.length/2))):hx(BigInt(core.decodedPath[i+1].ea)+delta),
      gprs:Object.fromEntries(GPRS.map(g=>[g,hx(state[g])]))};
    groups.push({groupIndex:i,intermediateStateAvailable:true,instructions:[{pc,bytes:p.bytes}],before,after,memoryReads:reads});
    mapping.mapping.push({groupIndex:i,runtimePc:pc,preferred:p.ea,bytes:p.bytes});
    decoded.push({pc,bytes:p.bytes,status:'decoded',controlFlow:last,text:p.decoded.mnemonic.toLowerCase(),operands:[]});
  }
  return{core,groups,mapping,decoded};
}
test('direct relative control preserves runtime data and whole ordered memory with aliasing',()=>{
  for(const alias of[false,true]){const q=fixture(0,{alias}),r=assessRecordedHandler(q);validateHandlerAssessment(r,q.core,{groups:q.groups});
    assert.equal(r.status,'consistent-recorded-ordinary-state');assert.equal(r.gprs.length,16);assert.equal(r.control.target,hx(delta+0x2000n));
    assert.equal(r.orderedStores[0].address,alias?'0x8000':'0xa000');assert.equal(r.orderedStores[0].value,'0xfedcba9876543210');assert.equal(r.finiteInitialMemoryBytes.length,8);}
});
test('conditional control checks actual ordinary condition and preserves both successors',()=>{
  for(const taken of[true,false]){const q=fixture(1,{taken}),r=assessRecordedHandler(q);validateHandlerAssessment(r,q.core,{groups:q.groups});
    assert.equal(r.status,'consistent-recorded-ordinary-state');assert.equal(r.control.selectedSuccessor,taken?'taken':'fallthrough');assert.equal(r.control.unselectedContinuationAnalyzed,false);
    q.groups.at(-1).after.rip=taken?r.control.fallthrough:r.control.taken;assert.throws(()=>assessRecordedHandler(q),/condition differs/);}
});
test('saved status stays unknown and post-STORE observations cannot seed an initial flag image',()=>{
  const q=fixture(2),r=assessRecordedHandler(q);validateHandlerAssessment(r,q.core,{groups:q.groups});assert.equal(r.status,'partially-consistent-unknown-preserved');
  assert.equal(r.gprs.filter(g=>g.status==='matched').length,15);assert.equal(r.gprs.find(g=>g.name==='r10').computed,null);assert.equal(r.orderedStores[0].value,null);
  assert.equal(r.finiteInitialMemoryBytes.length,0);assert.equal(r.postStoreUnknownReadBytesNotSeededAsInitial,8);assert.equal(r.unknownValuesFilledFromObservations,false);
});
test('missing or conflicting initial RAM and wrong independent GPR remain refusals',()=>{
  const q=fixture(0);q.groups[0].memoryReads=[];assert.throws(()=>assessRecordedHandler(q),/missing initial RAM/);
  const a=fixture(0);a.groups[1].memoryReads=[{address:'0x8000',bytes:1,littleEndianHex:'00'}];assert.throws(()=>assessRecordedHandler(a),/observations conflict/);
  const b=fixture(2);b.groups.at(-1).after.gprs.r12='0x1';assert.throws(()=>assessRecordedHandler(b),/GPR r12 differs/);
});
test('PC-relative memory, calls and unsupported body instructions cannot be silently rebased',()=>{
  for(const mutate of[q=>q.decoded[0].operands.push({kind:'memory',base:{name:'rip'}}),q=>q.decoded[0].operands.push({kind:'memory',segment:'gs'}),
    q=>q.decoded[0].operands.push({kind:'memory',segment:'fs'}),q=>q.decoded[0].text='call 0x1234',q=>q.decoded[0].text='fstenv [rax]']){
    const q=fixture(0);mutate(q);assert.throws(()=>assessRecordedHandler(q),/PC-relative|unsupported ordinary/);}
});
test('byte mapping, terminal constants and conditional width cannot inherit earlier evidence',()=>{
  for(const mutate of[q=>q.mapping.mapping[0].runtimePc='0x1234',q=>q.core.dag.nodes[q.core.control.target].value='0x2001',q=>q.groups.at(-1).instructions[0].bytes='e900000000']){
    const q=fixture(0);mutate(q);assert.throws(()=>assessRecordedHandler(q));}
  const q=fixture(1);q.core.dag.nodes[q.core.control.condition].bits=64;assert.throws(()=>assessRecordedHandler(q),/width/);
});
test('unlisted stores and malformed or unsupported dead definitions are refused',()=>{
  const q=fixture(0);q.core.stores=[];assert.throws(()=>assessRecordedHandler(q));
  for(const n of[{op:'INT_NEGATE',type:'bv',bits:32,args:[0]},{op:'UNSUPPORTED_DEAD',type:'bv',bits:64,args:[]}]){
    const a=fixture(0);a.core.dag.nodes.push({...n,id:a.core.dag.nodes.length});
    a.core.dag.references+=n.args.length;const ds=[];for(const x of a.core.dag.nodes)ds.push(1+Math.max(0,...x.args.map(i=>ds[i])));a.core.dag.depth=Math.max(...ds);
    assert.throws(()=>assessRecordedHandler(a),/complement width|unsupported source operators/);}
});
test('ones complement follows width masking rather than arithmetic negation',()=>{
  for(const bits of[8,16,32,64,128])for(const x of[0n,1n,(1n<<BigInt(bits))-1n,1n<<BigInt(bits-1)]){
    const m=(1n<<BigInt(bits))-1n,core={dag:{nodes:[{id:0,op:'const',type:'bv',bits,args:[],value:hx(x)},{id:1,op:'INT_NEGATE',type:'bv',bits,args:[0]}]}};
    assert.equal(evaluator(core,{},()=>{throw Error('no RAM')},new Map(),{bytes:0})(1),m^x);}
});
test('host rejects scope, unknown filling, root completeness and count tampering',()=>{
  const q=fixture(2),r=assessRecordedHandler(q);
  for(const mutate of[x=>x.status='consistent-recorded-ordinary-state',x=>x.all16FinalGprsMatched=true,x=>x.unknownValuesFilledFromObservations=true,
    x=>x.gprs.pop(),x=>x.ordinaryRootNodes.pop(),x=>x.memoryByteVisits=4097,x=>x.orderedStores[0].value='0x202',x=>x.businessAccepted=true,x=>x.control.unselectedContinuationAnalyzed=true]){
    const x=structuredClone(r);mutate(x);assert.throws(()=>validateHandlerAssessment(x,q.core,{groups:q.groups}),/worker assessment/);}
});
test('whole-recording body selector uses all eight selected boundaries without manual addresses',()=>{
  const c=recurrenceCase(),req=c.request(),recurrence=analyzeFlowRecurrences(req),r=selectRecordedHandlerBodies({...req,recurrence});
  assert.equal(r.bodies.length,8);assert.equal(r.bodies.filter(b=>b.selectionStatus==='observed-boundary').length,8);assert(r.bodies.every(b=>b.groupCount===1));
  assert.equal(r.allInputWindowsValidated,true);assert.equal(r.vmRoleProved,false);
});
test('last full body may close at a partial next fetch, but missing closure stays unverified',()=>{
  for(const partial of[0,1]){const c=recurrenceCase({repetitions:1,partial}),req=c.request(),recurrence=analyzeFlowRecurrences(req),r=selectRecordedHandlerBodies({...req,recurrence});
    assert.equal(r.bodies[0].completeNextBoundary,partial===1);assert.equal(r.bodies[0].selectionStatus,partial?'observed-boundary':'unverified');}
});
test('body scan still parses a corrupt tail after selected samples',()=>{
  const c=recurrenceCase(),req=c.request(),recurrence=analyzeFlowRecurrences(req);req.windows=[replaceObservationRows(req.windows[0],s=>s.replace(/^f:.*$/m,'f:0x1'))];
  assert.throws(()=>selectRecordedHandlerBodies({...req,recurrence}),/snapshot/);
});
test('changed next-head bytes cannot close a verified body',()=>{
  const c=recurrenceCase({repetitions:2,partial:1}),recurrence=analyzeFlowRecurrences(c.request());c.steps[7].bytes='cc';
  const r=selectRecordedHandlerBodies({...c.request(),recurrence});assert.equal(r.bodies[0].completeNextBoundary,false);assert.match(r.bodies[0].reason,/changed or coalesced/);
});
test('body group and snapshot quotas preserve refusals while scanning to the next source',()=>{
  for(const memory of[false,true]){
    const c=recurrenceCase({repetitions:1,partial:1}),old=c.steps[6],count=memory?128:129;
    const reads=Array.from({length:8},(_,i)=>({address:0xc000n+BigInt(64*i),size:64,value:0n}));
    c.steps.splice(6,1,...Array.from({length:count},(_,i)=>({...old,pc:i===0?old.pc:hx(0xd000n+BigInt(i)),reads:memory?reads:[]})));
    const req=c.request(),recurrence=analyzeFlowRecurrences(req),r=selectRecordedHandlerBodies({...req,recurrence}),b=r.bodies[0];
    assert.equal(b.selectionStatus,'unverified');assert.equal(b.completeNextBoundary,true);assert.equal(b.groups.length,0);assert.equal(b.groupCount,count);
    assert.match(b.reason,memory?/snapshot budget/:/group budget/);assert.equal(r.allInputWindowsValidated,true);
  }
});
test('public handlers is exclusive and rejects caller addresses or opaque values',async()=>{
  assert.equal(recoveryProfileSchema.properties.handlers.additionalProperties,false);
  for(const extra of[{projection_path:['0x1234']},{opaque:1},{proof:'fake'}])await assert.rejects(async()=>runRecoveryProfile({},
    {recovery:{handlers:{recurrences_ref:{id:'bad',sha256:'a'.repeat(64)},target:'C:/fixture',...extra}}},{}),/invalid parameters/);
  assert.throws(()=>runRecoveryProfile({},{recovery:{handlers:{},flow:{}}},{}),/requires exactly/);
});
test('cancelled handler profile does not read metadata or raw target',async()=>{
  let reads=0;const mgr={checkCancelled(){},scope:{getStore(){return{signal:AbortSignal.abort()}}},analysis:{get artifacts(){reads++;throw Error('must not read')}}};
  await assert.rejects(()=>runRecoveryProfile(mgr,{recovery:{handlers:{recurrences_ref:{id:'bad',sha256:'a'.repeat(64)},target:'C:/missing'}}},{}),/cancelled/);assert.equal(reads,0);
});
test('bad committed SHA and non-UUID linked source fail before raw target or native jobs',async()=>{
  const out=fs.mkdtempSync(path.join(os.tmpdir(),'ig5-handler-negative-')),store=new AnalysisArtifacts(path.join(out,'analysis-data'));
  const record=store.save({kind:'vm-flow-recurrences',action:'validate',result:{schema:'ig5-flow-recurrences-v1',sourceFlow:{id:'../../arbitrary',sha256:'a'.repeat(64),path:'C:/arbitrary'}}});
  const digest=store.metadata(record.id).result.recordSha256;await store.dispose();
  const cfg={artifactDir:out,projectRoot:out},mgr={checkCancelled(){}};mgr.analysis=createAnalysisService(mgr,cfg);
  try{
    for(const [sha,error]of[['0'.repeat(64),/committed report SHA/],[digest,/invalid original flow reference/]]){
      await assert.rejects(()=>runRecoveryProfile(mgr,{recovery:{handlers:{recurrences_ref:{id:record.id,sha256:sha},target:path.join(out,'never-created.exe')}}},cfg),error);
      assert.equal(mgr.lifter,undefined);
    }
  }finally{await mgr.analysis.dispose();}
});
