import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyFetchFlow } from '../source/vm_fetch_flow.js';
import { mapVmFlowBytes } from '../source/vm_flow_mapping.js';
import { selectVmFlowWindow } from '../source/vm_flow_window.js';
import { runRecoveryProfile, recoveryProfileSchema } from '../source/vm_recovery_profile.js';
import { observationWindow, replaceObservationRows, observationTarget } from './fixtures/vm_observation_cases.mjs';
// Synthetic typed SSA reports, never presented as native or CPU evidence.
function core({prefix=false,independent=false,cancel=false,extraNode=false,store=true}={}){
  const nodes=[],add=(op,type,args,extra={})=>{const id=nodes.length;nodes.push({id,op,type,args,...extra});return id;};
  const names='rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split(' ');
  const initialRegisters=Object.fromEntries(names.map(name=>[name,add('input','bv',[],{bits:64,name})]));
  const memory=add('initial_memory','memory',[],{name:'M0',addressBits:64,elementBits:8});
  if(extraNode)add('const','bv',[],{bits:64,value:'0x44'});
  const source=add('load_le','bv',[memory,initialRegisters.rsi],{bits:8,size:1});
  const extended=add('INT_ZEXT','bv',[source],{bits:64}),registers={...initialRegisters,rax:extended};
  let target=initialRegisters.rdx,currentMemory=memory;const stores=[];
  if(!prefix){
    const idx=cancel?add('INT_XOR','bv',[extended,extended],{bits:64}):extended;
    const four=add('const','bv',[],{bits:64,value:'0x4'}),offset=add('INT_MULT','bv',[idx,four],{bits:64});
    const address=add('INT_ADD','bv',[initialRegisters.r11,offset],{bits:64});
    const table=add('load_le','bv',[memory,address],{bits:32,size:4}),signed=add('INT_SEXT','bv',[table],{bits:64});
    if(!independent)target=add('INT_ADD','bv',[signed,initialRegisters.r11],{bits:64});
    registers.r8=target;
    if(store){const eight=add('const','bv',[],{bits:64,value:'0x8'}),sp=add('INT_SUB','bv',[initialRegisters.rsp,eight],{bits:64});
      currentMemory=add('store_le','memory',[memory,sp,target],{size:8});stores.push({instructionIndex:1,pcodeIndex:0,address:sp,value:target,size:8,beforeMemory:memory,afterMemory:currentMemory});}
  }
  const control={kind:prefix?'direct':'return',source:prefix?'0x1000':'0x1003',target};
  const projectionPath=prefix?['0x1000']:['0x1000','0x1003'];
  const result={schema:'ig5-pcode-opaque-status-projection-v1',projectionMode:'opaque-status',targetSha256:'a'.repeat(64),
    nativeTargetExecuted:false,databaseModified:false,businessAccepted:false,wholeBinaryVerified:false,
    projectionPath,decodedPath:projectionPath.map(ea=>({ea,bytes:ea==='0x1000'?'0fb606':'c3',decoded:{pcode:[]}})),
    initialRegisters,registers,initialMemory:memory,currentMemory,stores,control,nondeterministicInputs:[],opaqueEffects:[],statistics:{pcodeOperations:prefix?3:7}};
  const depths=nodes.map((n,i)=>1+Math.max(0,...n.args.map(id=>0))); // overwritten in topological order
  nodes.forEach((n,i)=>depths[i]=1+Math.max(0,...n.args.map(id=>depths[id])));
  result.dag={nodes,references:nodes.reduce((s,n)=>s+n.args.length,0)+35+4*stores.length,depth:Math.max(...depths)};
  return result;
}
test('complete coherent memory graph links source-index-table-control and retains all stores/state',()=>{
  const r=classifyFetchFlow(core({prefix:true}),core());
  assert.equal(r.status,'source-indexed-load-reaches-indirect-target');assert.equal(r.indexedReads.length,1);
  assert.equal(r.preserved.orderedStores,1);assert.equal(r.preserved.all16FinalGprs,true);
  assert.deepEqual(r.target.initialInputs.sort(),['r11','rsi']);assert.equal(r.vmRoleProved,false);assert.equal(r.semanticNonconstancyProved,false);
});
test('narrow read merely near an unrelated indirect target is rejected as a target dependency',()=>{
  const r=classifyFetchFlow(core({prefix:true}),core({independent:true}));
  assert.equal(r.status,'source-absent-from-target-expression');assert.equal(r.indexedReads.length,0);assert.equal(r.preserved.orderedStores,1);
});
test('syntactic canceled index never becomes a nonconstancy or VM proof',()=>{
  const r=classifyFetchFlow(core({prefix:true}),core({cancel:true}));
  assert.equal(r.semanticNonconstancyProved,false);assert.equal(r.vmRoleProved,false);
  assert.match(r.ordinaryProgramAmbiguity,/ordinary indexed jump tables/);
});
test('source identity is structural and does not depend on equal node IDs',()=>{
  const r=classifyFetchFlow(core({prefix:true}),core({extraNode:true}));
  assert.notEqual(r.sourceLoad.prefixNode,r.sourceLoad.matchedFullNodes[0]);assert.equal(r.indexedReads.length,1);
});
test('changed initial memory address cannot inherit a former source node signature',()=>{
  const p=core({prefix:true});const n=p.dag.nodes.find(n=>n.op==='load_le');n.args[1]=p.initialRegisters.rdi;
  const r=classifyFetchFlow(p,core());assert.equal(r.status,'source-absent-from-target-expression');
});
test('different bytes/raw pcode/hash or omitted GPR state cannot receive a dependency report',()=>{
  for(const change of [p=>p.decodedPath[0].bytes='90',p=>p.targetSha256='b'.repeat(64),p=>delete p.registers.r15]){
    const p=core({prefix:true});change(p);assert.throws(()=>classifyFetchFlow(p,core()),/Invalid fetch/);
  }
});
test('tampered references and direct control do not pass as an indirect flow',()=>{
  const f=core();f.dag.references--;assert.throws(()=>classifyFetchFlow(core({prefix:true}),f),/accounting/);
  const d=core();d.control.kind='direct';assert.throws(()=>classifyFetchFlow(core({prefix:true}),d),/non-indirect/);
});
test('contiguous window preserves every intervening stop and exact seed source',()=>{
  const w=observationWindow({count:5}),seed={groupIndex:1,recordingId:w.source.reportId,pc:'0x1001',bytes:'90'};
  const r=selectVmFlowWindow({targetSha256:observationTarget,windows:[w],seed});
  assert.deepEqual(r.groups.map(g=>g.groupIndex),[1,2,3,4]);assert.equal(r.allInputWindowsValidated,true);
  assert.throws(()=>selectVmFlowWindow({targetSha256:observationTarget,windows:[w],seed:{...seed,pc:'0x1002'}}),/exact source/);
});
test('window omission cannot hide a corrupt later native snapshot',()=>{
  const w=observationWindow({count:256}),bad=replaceObservationRows(w,s=>s.replace(/^f:.*$/m,'f:0x1'));
  assert.throws(()=>selectVmFlowWindow({targetSha256:observationTarget,windows:[bad],seed:{groupIndex:0,recordingId:w.source.reportId,pc:'0x1000',bytes:'90'}}),/snapshot/);
  const r=selectVmFlowWindow({targetSha256:observationTarget,windows:[w],seed:{groupIndex:0,recordingId:w.source.reportId,pc:'0x1000',bytes:'90'}});
  assert.equal(r.groups.length,128);assert.equal(r.distinctByteSites,128);assert.equal(r.stoppedFor,'stop-group-budget');
});
function pe(){
  const b=Buffer.alloc(1024);b.write('MZ');b.writeUInt32LE(0x80,0x3c);b.writeUInt32LE(0x4550,0x80);b.writeUInt16LE(0x8664,0x84);b.writeUInt16LE(1,0x86);b.writeUInt16LE(0xf0,0x94);
  b.writeUInt16LE(0x20b,0x98);b.writeBigUInt64LE(0x140000000n,0x98+24);const s=0x98+0xf0;
  b.writeUInt32LE(0x1000,s+12);b.writeUInt32LE(32,s+16);b.writeUInt32LE(512,s+20);b.writeUInt32LE(0x60000020,s+36);b[512]=0x90;return b;
}
const mappedGroup=(pc='0x700000001000')=>({groupIndex:0,recordingId:'synthetic',intermediateStateAvailable:true,instructions:[{pc,bytes:'90'}]});
test('raw mapping uses independently supplied runtime base and exact original opcode bytes',()=>{
  const r=mapVmFlowBytes(pe(),'0x700000000000',[mappedGroup()]);assert.equal(r.mapping[0].preferred,'0x140001000');assert.equal(r.mapping[0].fileOffset,512);
  const high=mapVmFlowBytes(pe(),'0xfeed000000000000',[mappedGroup('0xfeed000000001000')]);assert.equal(high.mapping[0].preferred,'0x140001000');
});
test('nonexecutable/different/unmapped bytes and missing intermediate states are refused',()=>{
  const b=pe();b.writeUInt32LE(0x40000040,0x98+0xf0+36);assert.throws(()=>mapVmFlowBytes(b,'0x700000000000',[mappedGroup()]),/mapping/);
  const wrong=pe();wrong[512]=0xcc;assert.throws(()=>mapVmFlowBytes(wrong,'0x700000000000',[mappedGroup()]),/mapping/);
  assert.throws(()=>mapVmFlowBytes(pe(),'0x700000000000',[mappedGroup('0x700000002000')]),/mapping/);
  assert.throws(()=>mapVmFlowBytes(pe(),'0x700000000000',[{...mappedGroup(),intermediateStateAvailable:false}]),/intermediate/);
});
test('public flow schema cannot mix recovery modes or accept caller proof/decoder overrides',async()=>{
  assert.equal(recoveryProfileSchema.properties.flow.additionalProperties,false);
  await assert.rejects(async()=>runRecoveryProfile({}, {recovery:{flow:{},roles:{}}},{}),/requires exactly/);
  await assert.rejects(async()=>runRecoveryProfile({}, {recovery:{flow:{roles_ref:{id:'x',sha256:'a'.repeat(64)},target:'C:/x',projection_decoder:'native'}}},{}),/Invalid recorded flow/);
});
test('semantic assessment is an explicit Boolean opt-in and refuses truthy coercions before reads',async()=>{
  assert.equal(recoveryProfileSchema.properties.flow.properties.semantic_check.type,'boolean');
  for(const semantic_check of ['true',1,null,{}])await assert.rejects(async()=>runRecoveryProfile({}, {recovery:{flow:{roles_ref:{id:'x',sha256:'a'.repeat(64)},target:'C:/x',semantic_check}}},{}),/semantic_check must be Boolean/);
});
test('invalid non-string role identities are refused without invoking coercion hooks',async()=>{
  let touched=false;const id={toString(){touched=true;return 'x';}};
  await assert.rejects(async()=>runRecoveryProfile({}, {recovery:{flow:{roles_ref:{id,sha256:'a'.repeat(64)},target:'C:/x'}}},{}),/exact role report/);
  assert.equal(touched,false);
});
test('cancelled flow refuses before metadata reads or native analysis dispatch',async()=>{
  let reads=0;const mgr={checkCancelled(){},scope:{getStore(){return{signal:AbortSignal.abort()};}},analysis:{get artifacts(){reads++;throw Error('unexpected read');}}};
  await assert.rejects(()=>runRecoveryProfile(mgr,{recovery:{flow:{roles_ref:{id:'11111111-1111-1111-1111-111111111111',sha256:'a'.repeat(64)},target:'C:/x'}}},{}),{code:'ABORT_ERR'});
  assert.equal(reads,0);
});
test('shared fanout DAG preview has linear work and explicit bounded truncation',()=>{
  const f=core();let previous=f.control.target;
  for(let i=0;i<96;i++){const id=f.dag.nodes.length;f.dag.nodes.push({id,op:'INT_ADD',type:'bv',args:[previous,previous],bits:64});previous=id;}
  f.control.target=previous;f.registers.r8=previous;
  const depths=[];for(const n of f.dag.nodes)depths.push(1+Math.max(0,...n.args.map(i=>depths[i])));
  f.dag.depth=Math.max(...depths);f.dag.references=f.dag.nodes.reduce((n,row)=>n+row.args.length,0)+35+4*f.stores.length;
  const r=classifyFetchFlow(core({prefix:true}),f);assert(r.target.expression.length<=2048);assert.equal(r.target.expressionPreviewTruncated,true);
});
