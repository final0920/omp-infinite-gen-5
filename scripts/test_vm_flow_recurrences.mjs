import test from 'node:test';import assert from 'node:assert/strict';
import {analyzeFlowRecurrences} from '../source/vm_flow_recurrences.js';
import {runRecoveryProfile,recoveryProfileSchema} from '../source/vm_recovery_profile.js';
import {recurrenceCase,recount} from './fixtures/flow_recurrence_cases.mjs';
import {replaceObservationRows} from './fixtures/vm_observation_cases.mjs';
import fs from 'node:fs';import os from 'node:os';import path from 'node:path';
import {AnalysisArtifacts,hashBytes} from '../source/analysis_artifacts.js';
import {createAnalysisService} from '../analysis_tools.js';
import {validateFlowRecurrenceResult} from '../source/vm_recurrence_profile.js';
test('first4/last4 complete paths use finite initial RAM and exclude post-STORE reads',()=>{
  const c=recurrenceCase(),r=analyzeFlowRecurrences(c.request());assert.equal(r.counts.sourceByteEvents,13);assert.equal(r.counts.completeDescriptorPaths,12);
  assert.equal(r.counts.selectedOrdinaryConsistent,8);assert.equal(r.counts.pathMismatches,0);assert.deepEqual(r.occurrences.map(o=>o.startGroup),[0,7,14,21,56,63,70,77]);
  assert.deepEqual(r.partialCapturedPaths.map(p=>p.capturedGroups),[2]);assert.equal(r.sourceAddressInputUpdates[0].name,'rsi');assert.deepEqual(r.sourceAddressInputUpdates[0].observedDeltasModulo64,['0x1']);
  assert.equal(r.selectedOrdinaryStateConsistent,true);assert.equal(r.entireRecordingOrdinaryStateVerified,false);assert.equal(r.vmRoleProved,false);
  for(const o of r.occurrences){assert.equal(o.finiteInitialMemoryBytes.length,5);assert.equal(o.postStoreReadBytesNotSeededAsInitial,8);assert.equal(o.all16FinalGprsMatched,true);assert.equal(o.orderedStores.length,1);}
});
test('a corrupt tail after selected samples cannot escape whole-input validation',()=>{
  const c=recurrenceCase(),q=c.request();q.windows=[replaceObservationRows(q.windows[0],s=>s.replace(/^f:.*$/m,'f:0x1'))];
  assert.throws(()=>analyzeFlowRecurrences(q),/snapshot/);
});
test('different instruction path is counted and retained rather than forced through the descriptor',()=>{
  const c=recurrenceCase();c.steps[2].pc='0xdead';const r=analyzeFlowRecurrences(c.request());
  assert.equal(r.counts.completeDescriptorPaths,11);assert.equal(r.counts.pathMismatches,1);assert.equal(r.mismatchExamples[0].failedGroup,2);
  assert.equal(r.counts.sourceByteEvents,13);assert.equal(r.vmRoleProved,false);
});
test('changed opcode at the source PC remains explicit code drift',()=>{
  const c=recurrenceCase();c.steps[0].bytes='cc';const r=analyzeFlowRecurrences(c.request());
  assert.equal(r.counts.changedBytesAtSourcePc,1);assert.equal(r.counts.completeDescriptorPaths,11);assert.equal(r.codeDataCoherenceProved,false);
  assert.equal(r.changedSourceByteExamples[0].observedBytes,'cc');
});
test('missing source RAM never receives an invented zero or a later repair',()=>{
  const c=recurrenceCase();c.steps[0].reads=[];const r=analyzeFlowRecurrences(c.request());
  assert.equal(r.occurrences[0].status,'unverified');assert.match(r.occurrences[0].reason,/missing initial RAM/);assert.equal(r.selectedOrdinaryStateConsistent,false);
});
test('conflicting initial observations retain unknown write/epoch failure',()=>{
  const c=recurrenceCase();c.steps[1].reads.push({address:0x8000n,size:1,value:99n});const r=analyzeFlowRecurrences(c.request());
  assert.equal(r.occurrences[0].status,'unverified');assert.match(r.occurrences[0].reason,/initial RAM observations conflict/);
});
test('post-STORE observed bytes must equal the coherent decoded overlay',()=>{
  const c=recurrenceCase();c.steps[5].reads[0].value=42n;const r=analyzeFlowRecurrences(c.request());
  assert.equal(r.occurrences[0].status,'unverified');assert.match(r.occurrences[0].reason,/post-STORE observation differs/);
});
test('an incorrect ordinary final register is not ignored',()=>{
  const c=recurrenceCase();c.steps[6].before.r12=1n;const r=analyzeFlowRecurrences(c.request());
  assert.equal(r.occurrences[0].status,'unverified');assert.match(r.occurrences[0].reason,/final GPR r12 differs/);
});
test('live opaque values are not inferred from the recorded register',()=>{
  const c=recurrenceCase(),id=c.full.dag.nodes.length;c.full.dag.nodes.push({id,op:'nondeterministic',type:'bv',bits:64,args:[]});c.full.registers.r9=id;c.full.nondeterministicInputs=[{node:id}];recount(c.full);
  const r=analyzeFlowRecurrences(c.request());assert.equal(r.counts.selectedOrdinaryUnverified,8);assert.match(r.occurrences[0].reason,/missing opaque input/);
});
test('unsupported unused definitions do not inherit a successful replay',()=>{
  const c=recurrenceCase(),id=c.full.dag.nodes.length;c.full.dag.nodes.push({id,op:'UNSUPPORTED_DEAD_NODE',type:'bv',bits:64,args:[]});recount(c.full);
  const r=analyzeFlowRecurrences(c.request());assert.equal(r.counts.selectedOrdinaryUnverified,8);assert.match(r.occurrences[0].reason,/unsupported source operators including unused/);
});
test('malformed typed dead definition is rejected before replay',()=>{
  const c=recurrenceCase(),id=c.full.dag.nodes.length;c.full.dag.nodes.push({id,op:'INT_ADD',type:'bv',bits:32,args:[0,0]});recount(c.full);
  assert.throws(()=>analyzeFlowRecurrences(c.request()),/binary widths/);
});
test('unlisted STORE cannot disappear from the full state inventory',()=>{
  const c=recurrenceCase();c.full.stores=[];c.full.currentMemory=c.full.initialMemory;recount(c.full);
  assert.throws(()=>analyzeFlowRecurrences(c.request()),/unlisted STORE/);
});
test('descriptor byte and runtime/preferred coordinate changes cannot inherit a prior flow',()=>{
  for(const mutate of [c=>c.flow.mapping.mapping[1].bytes='cc',c=>c.flow.mapping.mapping[1].runtimePc='0x4000']){
    const c=recurrenceCase();mutate(c);assert.throws(()=>analyzeFlowRecurrences(c.request()),/descriptor\/source binding/);
  }
});
test('overlapping source restarts retain both incomplete mismatches',()=>{
  const c=recurrenceCase();c.steps[2].pc='0x1000';c.steps[2].bytes='0fb606';const r=analyzeFlowRecurrences(c.request());
  assert.equal(r.counts.sourceByteEvents,14);assert.equal(r.counts.completeDescriptorPaths,11);assert.equal(r.counts.pathMismatches,2);
});
test('per-occurrence snapshot quota preserves counts and leaves oversized samples unverified',()=>{
  const c=recurrenceCase({repetitions:1,partial:0,padding:122,noiseReads:8}),r=analyzeFlowRecurrences(c.request());
  assert.equal(r.counts.completeDescriptorPaths,1);assert.equal(r.counts.completePathsExceedingSnapshotBudget,1);assert.equal(r.counts.selectedOrdinaryUnverified,1);
  assert.match(r.occurrences[0].reason,/snapshot budget/);assert.equal(r.sampling.allInputWindowsValidated,true);
});
test('public recurrence accepts only committed report refs and remains exclusive',async()=>{
  assert.equal(recoveryProfileSchema.properties.recurrences.additionalProperties,false);
  await assert.rejects(async()=>runRecoveryProfile({}, {recovery:{recurrences:{flow_ref:{id:'bad',sha256:'a'.repeat(64)},target:'C:/arbitrary'}}},{}),/invalid parameters/);
  await assert.rejects(async()=>runRecoveryProfile({}, {recovery:{recurrences:{flow_ref:{id:'bad',sha256:'a'.repeat(64)}},roles:{}}},{}),/requires exactly/);
  let touched=false;const id={toString(){touched=true;return 'x';}};
  await assert.rejects(async()=>runRecoveryProfile({}, {recovery:{recurrences:{flow_ref:{id,sha256:'a'.repeat(64)}}}},{}),/exact flow report/);assert.equal(touched,false);
});
test('cancelled recurrence refuses before any metadata or analysis dispatch',async()=>{
  let reads=0;const mgr={checkCancelled(){},scope:{getStore(){return{signal:AbortSignal.abort()};}},analysis:{get artifacts(){reads++;throw Error('unexpected read');}}};
  await assert.rejects(async()=>runRecoveryProfile(mgr,{recovery:{recurrences:{flow_ref:{id:'11111111-1111-1111-1111-111111111111',sha256:'a'.repeat(64)}}}},{}),/cancelled/);assert.equal(reads,0);
});
test('host refuses tampered recurrence counts, source bindings, snapshots and proof scope',()=>{
  const c=recurrenceCase(),q=c.request(),r=analyzeFlowRecurrences(q);validateFlowRecurrenceResult(r,q.windows,c.flow);
  for(const mutate of [x=>x.counts.completeDescriptorPaths++,x=>x.counts.selectedOrdinaryConsistent--,x=>x.counts.coalescedSourceEvents++,
    x=>x.sampling.maximumCapturedBytesPerPath++,x=>x.source.windows[0].reportSha256='0'.repeat(64),x=>x.occurrences[0].endGroup++,
    x=>x.entireRecordingOrdinaryStateVerified=true,x=>x.intermediateGprSemanticsVerified=true,x=>x.moduleLoadEpoch='guessed',x=>x.vmRoleProved=true]){
    const x=structuredClone(r);mutate(x);assert.throws(()=>validateFlowRecurrenceResult(x,q.windows,c.flow),/worker result identity/);
  }
});
async function committed(){
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'ig5-recurrence-unit-')),c=recurrenceCase(),w=c.makeWindow();
  const traces=new AnalysisArtifacts(path.join(root,'debug-traces')),analysis=new AnalysisArtifacts(path.join(root,'analysis-data')),lifter=new AnalysisArtifacts(path.join(root,'lifter'));
  const t=traces.save({kind:'debug-trace',action:'record',result:{...w.summary,input:traces.put(w.data)}});
  const tr={id:t.id,sha256:traces.metadata(t.id).result.recordSha256};
  const ref=(s,r)=>({id:r.id,path:path.join(s.root,'records',r.id+'.json'),sha256:s.metadata(r.id).result.recordSha256});
  const full=lifter.save({kind:'projection',action:'project',result:c.full}),prefix=lifter.save({kind:'projection',action:'project',result:c.prefix});
  const window=analysis.save({kind:'vm-flow-window',action:'select',result:{source:{targetSha256:c.flow.targetSha256,identity:{runtimeBase:'0x0'},windows:[{reportId:tr.id,reportSha256:tr.sha256}]}}});
  const body={...c.flow,sourceWindow:ref(analysis,window),evidence:{fullProjection:ref(lifter,full),prefixProjection:ref(lifter,prefix)}};
  const flow=analysis.save({kind:'vm-fetch-control-dependency',action:'analyze',result:body});
  await Promise.all([traces.dispose(),lifter.dispose(),analysis.dispose()]);
  return{root,c,fullRef:ref(lifter,full),flowRef:ref(analysis,flow)};
}
test('committed report chain revalidates original data without any native jobs',async()=>{
  const fixture=await committed(),cfg={artifactDir:fixture.root,projectRoot:fixture.root,requestTimeoutMs:60000},mgr={checkCancelled(){}};
  mgr.analysis=createAnalysisService(mgr,cfg);
  try{
    const response=await runRecoveryProfile(mgr,{recovery:{recurrences:{flow_ref:{id:fixture.flowRef.id,sha256:fixture.flowRef.sha256}}}},cfg),r=response.recurrences;
    assert.equal(r.counts.selectedOrdinaryConsistent,8);assert.equal(r.counts.completeDescriptorPaths,12);assert.equal(r.vmRoleProved,false);assert.equal(mgr.lifter,undefined);
    assert.equal(hashBytes(fs.readFileSync(r.reportPath)),r.reportSha256);
    const saved=JSON.parse(fs.readFileSync(r.reportPath,'utf8')).result;assert.equal(saved.sourceFlow.sha256,fixture.flowRef.sha256);assert.equal(saved.sourceProjections.full.sha256,fixture.fullRef.sha256);
  }finally{await mgr.analysis.dispose();}
});
test('wrong committed flow SHA refuses before linked evidence and worker access',async()=>{
  const fixture=await committed(),cfg={artifactDir:fixture.root,projectRoot:fixture.root},mgr={checkCancelled(){}};mgr.analysis=createAnalysisService(mgr,cfg);
  fs.writeFileSync(fixture.fullRef.path,'invalid linked content');
  try{await assert.rejects(()=>runRecoveryProfile(mgr,{recovery:{recurrences:{flow_ref:{id:fixture.flowRef.id,sha256:'0'.repeat(64)}}}},cfg),/flow report SHA-256 differs/);}
  finally{await mgr.analysis.dispose();}
});
test('changed linked complete projection cannot reuse the old flow reference',async()=>{
  const fixture=await committed(),cfg={artifactDir:fixture.root,projectRoot:fixture.root},mgr={checkCancelled(){}};mgr.analysis=createAnalysisService(mgr,cfg);
  fs.writeFileSync(fixture.fullRef.path,'invalid linked content');
  try{await assert.rejects(()=>runRecoveryProfile(mgr,{recovery:{recurrences:{flow_ref:{id:fixture.flowRef.id,sha256:fixture.flowRef.sha256}}}},cfg),/linked report SHA-256 differs/);}
  finally{await mgr.analysis.dispose();}
});
