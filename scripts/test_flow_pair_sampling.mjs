import test from'node:test';import assert from'node:assert/strict';
import{analyzeFlowRecurrences}from'../source/vm_flow_recurrences.js';import{prepareRecordedFlow}from'../source/recorded_flow_eval.js';
import{flowPairSelection,observeFlowSource}from'../source/flow_pair_sampling.js';import{validateFlowRecurrenceResult}from'../source/vm_recurrence_profile.js';
import{recurrenceCase}from'./fixtures/flow_recurrence_cases.mjs';import{observationHash}from'./fixtures/vm_observation_cases.mjs';
import{runRecoveryProfile}from'../source/vm_recovery_profile.js';
const GPRS='rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split(' '),hx=n=>'0x'+BigInt(n).toString(16);
function result(options={}){const c=recurrenceCase(),req={...c.request(),sampleStrategy:'distinct-source-targets',...options},r=analyzeFlowRecurrences(req);return{c,req,r};}
test('explicit pair diversity selects first occurrence per observed pair and keeps all matches counted',()=>{
  const{req,r,c}=result();validateFlowRecurrenceResult(r,req.windows,c.flow,flowPairSelection('distinct-source-targets'));
  assert.equal(r.counts.completeDescriptorPaths,12);assert.equal(r.counts.selectedCompletePaths,2);assert.deepEqual(r.occurrences.map(o=>o.startGroup),[0,7]);
  assert.deepEqual(r.observedSourceTargetInventory.pairs.map(p=>[p.observedValue,p.completePaths]),[['0x1',6],['0x2',6]]);
  assert.equal(r.observedSourceTargetInventory.inventoryIsOrdinaryStateReplay,false);assert.equal(r.observedSourceTargetInventory.sourceValuesAreOpcodeLabels,false);
});
test('pair pages are deterministic and an empty last page is not a passing replay',()=>{
  const{r}=result({pairOffset:1});assert.deepEqual(r.occurrences.map(o=>o.startGroup),[7]);assert.deepEqual(r.observedSourceTargetInventory.selectedPairOrdinals,[1]);
  const empty=result({pairOffset:255}).r;assert.equal(empty.occurrences.length,0);assert.equal(empty.selectedOrdinaryStateConsistent,false);assert.equal(empty.observedSourceTargetInventory.pairs.length,2);
});
test('default result keeps exact historical first4/last4 shape and no unsolicited inventory',()=>{
  const c=recurrenceCase(),a=analyzeFlowRecurrences(c.request()),b=analyzeFlowRecurrences({...c.request(),sampleStrategy:'first4-last4'});
  assert.deepEqual(a,b);assert.equal(a.occurrences.length,8);assert.equal(Object.hasOwn(a,'observedSourceTargetInventory'),false);
});
test('missing exact source read remains unobserved and is never filled from RAX',()=>{
  const c=recurrenceCase();c.steps[0].reads=[];const r=analyzeFlowRecurrences({...c.request(),sampleStrategy:'distinct-source-targets'}),inv=r.observedSourceTargetInventory;
  assert.equal(inv.sourceReadUnobservedCompletePaths,1);assert.deepEqual(r.occurrences.map(o=>o.startGroup),[7,14]);assert.match(inv.unobservedExamples[0].reason,/missing or conflicting/);
  assert.equal(inv.trackingComplete,false);assert.equal(inv.countsAreLowerBounds,true);
});
test('conflicting exact reads do not become a known tag or receive an invented winner',()=>{
  const c=recurrenceCase();c.steps[0].reads.push({address:0x8000n,size:1,value:99n});const r=analyzeFlowRecurrences({...c.request(),sampleStrategy:'distinct-source-targets'});
  assert.equal(r.observedSourceTargetInventory.sourceReadUnobservedCompletePaths,1);assert.equal(r.observedSourceTargetInventory.pairs[0].firstOccurrence.startGroup,7);
});
test('unknown or RAM-dependent address is refused without inferring it from a recorded pointer',()=>{
  const c=recurrenceCase(),p=prepareRecordedFlow(c.prefix,c.full),nodes=p.full.dag.nodes,id=nodes.length;
  nodes.push({id,op:'nondeterministic',type:'bv',bits:64,args:[]});nodes[p.source].args[1]=id;
  const g={before:{gprs:Object.fromEntries(GPRS.map(n=>[n,'0x0']))},memoryReads:[{address:'0x0',bytes:1,littleEndianHex:'01'}]};
  assert.match(observeFlowSource(p,g).reason,/RAM\/opaque-dependent/);
});
test('failed ordinary replay remains attached to its first observed pair rather than replaced',()=>{
  const c=recurrenceCase();c.steps[6].before.r12=1n;const r=analyzeFlowRecurrences({...c.request(),sampleStrategy:'distinct-source-targets'});
  assert.equal(r.occurrences[0].startGroup,0);assert.equal(r.occurrences[0].status,'unverified');assert.match(r.occurrences[0].reason,/GPR r12 differs/);
});
test('host rejects mutated inventory coverage, ordinals, exact reads, source binding and proof scope',()=>{
  const{r,c,req}=result(),selection=flowPairSelection('distinct-source-targets');
  const mutations=[x=>x.observedSourceTargetInventory.pairs[0].ordinal=-0,x=>x.observedSourceTargetInventory.pairs[0].completePaths++,
    x=>x.observedSourceTargetInventory.pairs[0].observedValue='0x100',x=>x.observedSourceTargetInventory.pairs[0].firstOccurrence.pause=0,
    x=>x.observedSourceTargetInventory.inventoryIsOrdinaryStateReplay=true,x=>x.observedSourceTargetInventory.sourceValuesAreOpcodeLabels=true,
    x=>x.observedSourceTargetInventory.pairs[0].firstOccurrence.sourceRead.value='0x2',x=>x.observedSourceTargetInventory.selectedPairOrdinals.reverse(),
    x=>x.sampling.pairOffset=1,x=>x.observedSourceTargetInventory.trackingComplete=false];
  for(const mutate of mutations){const x=structuredClone(r);mutate(x);assert.throws(()=>validateFlowRecurrenceResult(x,req.windows,c.flow,selection),/worker/);}
});
function manyPairs(){
  const c=recurrenceCase({repetitions:257,partial:1}),original=c.makeWindow(),base=original.summary;
  for(let i=0;i<257;i++)c.steps[i*7+6].pc=hx(0xa000+i);
  const final=c.makeWindow().data.toString('ascii').trim().split('\n').at(-1),windows=[];
  for(let start=0;start<c.steps.length;start+=512){const end=Math.min(start+512,c.steps.length),lines=['h:ig5-native-x64-v1'];
    for(const s of c.steps.slice(start,end)){lines.push('r:'+GPRS.map(g=>hx(s.before[g])).join(':'),'e:0x202');for(const r of s.reads)lines.push('mr:'+hx(r.address)+':'+r.size+':'+hx(r.value));lines.push('i:'+s.pc+':'+s.bytes.length/2+':'+s.bytes);}
    lines.push(end===c.steps.length?final:'f:'+GPRS.map(g=>hx(c.steps[end].before[g])).join(':')+':'+c.steps[end].pc+':0x202');
    const data=Buffer.from(lines.join('\n')+'\n'),id='00000000-0000-0000-0000-'+(windows.length+1).toString(16).padStart(12,'0');
    windows.push({source:{...original.source,reportId:id},summary:{...base,instructionCount:end-start,confirmedStepStops:end-start,startStopSeq:start+1,endStopSeq:end+1,
      entry:c.steps[start].pc,exit:c.steps[end-1].pc,bytes:data.length,sha256:observationHash(data)},data});
  }
  return{...c.request(),windows,sampleStrategy:'distinct-source-targets'};
}
test('256-pair inventory bound keeps unindexed occurrences and full-input scanning explicit',()=>{
  const req=manyPairs(),r=analyzeFlowRecurrences(req);validateFlowRecurrenceResult(r,req.windows,req.flow,flowPairSelection('distinct-source-targets'));
  assert.equal(r.counts.completeDescriptorPaths,257);assert.equal(r.observedSourceTargetInventory.pairs.length,256);assert.equal(r.observedSourceTargetInventory.unindexedCompletePaths,1);
  assert.equal(r.observedSourceTargetInventory.trackingComplete,false);assert.equal(r.observedSourceTargetInventory.countsAreLowerBounds,true);assert.equal(r.occurrences.length,8);
  assert.equal(r.counts.selectedOrdinaryUnverified,8);assert.equal(r.sampling.allInputWindowsValidated,true);
});
test('strategy and page validation precedes any report reads and refuses nonprimitive coercion',async()=>{
  for(const input of[{sample_strategy:'unknown'},{pair_offset:0},{sample_strategy:'distinct-source-targets',pair_offset:-0},{sample_strategy:'distinct-source-targets',pair_offset:256}]){
    await assert.rejects(async()=>runRecoveryProfile({}, {recovery:{recurrences:{flow_ref:{id:'bad',sha256:'a'.repeat(64)},...input}}},{}),/invalid strategy or pair offset/);}
  let touched=false;await assert.rejects(async()=>runRecoveryProfile({}, {recovery:{recurrences:{flow_ref:{id:'bad',sha256:'a'.repeat(64)},sample_strategy:{toString(){touched=true;return'distinct-source-targets'}}}}},{}),/invalid strategy/);assert.equal(touched,false);
});
