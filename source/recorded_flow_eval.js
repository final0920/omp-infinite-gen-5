// Finite recorded ordinary-state consistency. No CPU, opaque-value inference,
// missing-RAM fill, state composition, or execution of machine instructions.
import { classifyFetchFlow } from './vm_fetch_flow.js';
import { evaluator } from './flow_state_eval.js';
const GPRS='rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split(' '),MASK=(1n<<64n)-1n;
const fail=m=>{throw new Error('Recorded ordinary flow refused: '+m);},hex=v=>'0x'+v.toString(16);
const uint=v=>{if(typeof v!=='string'||!/^0x[0-9a-f]{1,16}$/.test(v))fail('uint64 snapshot');return BigInt(v);};
const integer=(v,min,max)=>Number.isSafeInteger(v)&&!Object.is(v,-0)&&v>=min&&v<=max;
export function typedRecordedSource(core,{conditional=false}={}){
  const nodes=core.dag.nodes,unsupported=new Set();
  for(const n of nodes){
    if(typeof n.op!=='string'||!/^[a-zA-Z0-9_]{1,64}$/.test(n.op))fail('operator identity');
    if(n.type==='bv'?!integer(n.bits,1,128):n.type!=='memory'||n.bits!==undefined)fail('typed node width');
    const a=n.args.map(i=>nodes[i]),shape=(count,type='bv')=>{if(a.length!==count||n.type!==type)fail('operator shape');};
    const bvs=()=>{if(a.some(x=>x.type!=='bv'))fail('bitvector operand');};
    if(n.op==='input'){shape(0);if(!GPRS.includes(n.name)||n.bits!==64||core.initialRegisters[n.name]!==n.id)fail('initial GPR identity');}
    else if(n.op==='initial_memory'){shape(0,'memory');if(n.id!==core.initialMemory||n.addressBits!==64||n.elementBits!==8)fail('initial RAM identity');}
    else if(n.op==='nondeterministic'){shape(0);if(n.bits!==64)fail('opaque width');}
    else if(n.op==='const'){shape(0);if(typeof n.value!=='string'||!/^0x[0-9a-fA-F]+$/.test(n.value)||n.value.length>34||BigInt(n.value)>=(1n<<BigInt(n.bits)))fail('constant width');}
    else if(['INT_ADD','INT_SUB','INT_MULT','INT_AND','INT_OR','INT_XOR'].includes(n.op)){shape(2);bvs();if(a.some(x=>x.bits!==n.bits))fail('binary widths');}
    else if(n.op==='INT_NEGATE'){shape(1);bvs();if(a[0].bits!==n.bits)fail('complement width');}
    else if(n.op==='extract'){shape(1);bvs();if(!integer(n.offset,0,127)||n.offset+n.bits>a[0].bits)fail('extract width');}
    else if(n.op==='concat'){bvs();if(n.type!=='bv'||a.length<2||a.reduce((s,x)=>s+x.bits,0)!==n.bits)fail('concat width');}
    else if(['INT_ZEXT','INT_SEXT'].includes(n.op)){shape(1);bvs();if(a[0].bits>n.bits)fail('extension width');}
    else if(['BOOL_AND','BOOL_OR','BOOL_NEGATE','INT_EQUAL','INT_NOTEQUAL','INT_LESS','INT_SLESS','INT_CARRY','INT_SCARRY'].includes(n.op)){
      shape(n.op==='BOOL_NEGATE'?1:2);bvs();if(n.bits!==8||(!n.op.startsWith('BOOL_')&&a[0].bits!==a[1].bits))fail('Boolean widths');
    }else if(n.op==='POPCOUNT'){shape(1);bvs();}
    else if(['load_le','store_le'].includes(n.op)){
      const load=n.op==='load_le';shape(load?2:3,load?'bv':'memory');
      if(!integer(n.size,1,16)||a[0].type!=='memory'||a[1].type!=='bv'||a[1].bits!==64
        ||(load?n.bits!==n.size*8:a[2].type!=='bv'||a[2].bits!==n.size*8))fail('memory operation width');
    }else unsupported.add(n.op);
  }
  if(nodes.filter(n=>n.op==='input').length!==16||nodes.filter(n=>n.op==='initial_memory').length!==1)fail('ordinary initial state');
  for(const id of Object.values(core.registers))if(nodes[id]?.type!=='bv'||nodes[id].bits!==64)fail('final GPR width');
  const targets=conditional&&core.control.kind==='conditional'?[core.control.taken,core.control.fallthrough]:[core.control.target];
  if(nodes[core.currentMemory]?.type!=='memory'||targets.some(i=>nodes[i]?.type!=='bv'||nodes[i].bits!==64)
    ||conditional&&core.control.kind==='conditional'&&(nodes[core.control.condition]?.type!=='bv'||nodes[core.control.condition].bits!==8))fail('final memory/target');
  let memory=core.initialMemory,lastInstruction=-1,lastPcode=-1;
  for(const s of core.stores){
    if(!integer(s.instructionIndex,0,core.projectionPath.length-1)||!integer(s.pcodeIndex,0,1000000)||!integer(s.size,1,16)
      ||s.instructionIndex<lastInstruction||(s.instructionIndex===lastInstruction&&s.pcodeIndex<=lastPcode)||s.beforeMemory!==memory)fail('ordered STORE provenance');
    const n=nodes[s.afterMemory];
    if(n?.op!=='store_le'||n.size!==s.size||JSON.stringify(n.args)!==JSON.stringify([s.beforeMemory,s.address,s.value]))fail('STORE node binding');
    memory=s.afterMemory;lastInstruction=s.instructionIndex;lastPcode=s.pcodeIndex;
  }
  if(memory!==core.currentMemory)fail('final STORE memory chain');
  const recorded=new Set(core.stores.map(s=>s.afterMemory));
  if(nodes.some(n=>n.op==='store_le'&&!recorded.has(n.id))||recorded.size!==core.stores.length)fail('unlisted STORE definition');
  return [...unsupported].sort();
}
const closure=(nodes,root)=>{const seen=new Set(),todo=[root];while(todo.length){const i=todo.pop();if(seen.has(i))continue;seen.add(i);todo.push(...nodes[i].args);}return seen;};
export function prepareRecordedFlow(prefix,full){
  const dependency=classifyFetchFlow(prefix,full),unsupported=[...new Set([...typedRecordedSource(prefix),...typedRecordedSource(full)])].sort();
  const source=dependency.sourceLoad.matchedFullNodes[0];if(!Number.isSafeInteger(source))fail('source LOAD absent from complete state');
  const nodes=full.dag.nodes,inputs=id=>[...new Set([...closure(nodes,id)].filter(i=>nodes[i].op==='input').map(i=>nodes[i].name))].sort();
  return {full,dependency,source,unsupported,sourceAddressInputs:inputs(nodes[source].args[1]),
    indexedAddressInputs:dependency.indexedReads.map(r=>({node:r.node,inputs:inputs(r.addressNode)}))};
}
export function replayRecordedFlow(prepared,groups){
  const {full,dependency,source,unsupported}=prepared;
  if(unsupported.length)fail('unsupported source operators including unused definitions: '+unsupported.join(','));
  if(!Array.isArray(groups)||groups.length!==full.projectionPath.length||groups.length>128)fail('complete descriptor observations required');
  const initial=Object.fromEntries(GPRS.map(g=>[g,uint(groups[0].before.gprs[g])])),seed=new Map(),overlay=new Map(),work={bytes:0};
  const read=a=>{if(!seed.has(a))fail('missing initial RAM byte '+hex(a));return seed.get(a);};
  const at=evaluator(full,initial,read,new Map(),work),stores=[];let postStoreReadBytes=0;
  for(const [step,g] of groups.entries()){
    if(g.intermediateStateAvailable!==true||g.instructions.length!==1)fail('missing intermediate recorded state');
    for(const r of g.memoryReads){
      if(![1,2,4,8,16,32,64].includes(r.bytes)||typeof r.littleEndianHex!=='string'||!new RegExp(`^[0-9a-f]{${r.bytes*2}}$`).test(r.littleEndianHex))fail('memory observation');
      const address=uint(r.address),bytes=Buffer.from(r.littleEndianHex,'hex');
      for(let i=0;i<bytes.length;i++){
        const a=(address+BigInt(i))&MASK,b=bytes[i];
        if(overlay.has(a)){if(overlay.get(a)!==b)fail('post-STORE observation differs; unknown writes/epochs remain possible');postStoreReadBytes++;}
        else if(seed.has(a)){if(seed.get(a)!==b)fail('initial RAM observations conflict; unknown writes/epochs remain possible');}
        else{if(seed.size>=4096)fail('finite initial RAM budget');seed.set(a,b);}
      }
    }
    for(const s of full.stores)if(s.instructionIndex===step){
      const address=at(s.address),value=at(s.value);at(s.beforeMemory);at(s.afterMemory);
      for(let i=0;i<s.size;i++)overlay.set((address+BigInt(i))&MASK,Number((value>>BigInt(i*8))&255n));
      stores.push({instructionIndex:step,pcodeIndex:s.pcodeIndex,address:hex(address),value:hex(value),bytes:s.size});
    }
  }
  for(const g of GPRS)if(at(full.registers[g])!==uint(groups.at(-1).after.gprs[g]))fail('final GPR '+g+' differs');
  if(at(full.control.target)!==uint(groups.at(-1).after.rip))fail('terminal target differs');
  const finalMemory=at(full.currentMemory);if(finalMemory.overlay.size!==overlay.size||[...overlay].some(([a,b])=>finalMemory.overlay.get(a)!==b))fail('ordinary final memory differs');
  const sourceNode=full.dag.nodes[source];
  return {status:'consistent-recorded-ordinary-state',all16InitialGprsUsed:true,all16FinalGprsMatched:true,terminalTargetMatched:true,allOrderedDecodedStoresReplayed:true,
    sourceAddress:hex(at(sourceNode.args[1])),sourceValue:hex(at(source)),sourceBytes:sourceNode.size,
    indexedReads:dependency.indexedReads.map(r=>({node:r.node,address:hex(at(r.addressNode)),value:hex(at(r.node)),bytes:r.bytes})),
    target:hex(at(full.control.target)),targetKind:full.control.kind,
    sourceAddressInputUpdates:prepared.sourceAddressInputs.map(g=>({name:g,before:hex(initial[g]),after:groups.at(-1).after.gprs[g],deltaModulo64:hex((uint(groups.at(-1).after.gprs[g])-initial[g])&MASK)})),
    indexedAddressInputValues:prepared.indexedAddressInputs.map(r=>({node:r.node,inputs:r.inputs.map(g=>({name:g,value:hex(initial[g])}))})),
    finiteInitialMemoryBytes:[...seed].map(([a,value])=>({address:hex(a),value})),postStoreReadBytesNotSeededAsInitial:postStoreReadBytes,memoryByteVisits:work.bytes,
    orderedStores:stores,initialGprs:groups[0].before.gprs,finalGprs:groups.at(-1).after.gprs,
    observedFlagsValidatedByRecordingParser:true,projectedFlagsModeledOrCompared:false,intermediateGprSemanticsVerified:false,opaqueOutputsCoordinated:false,
    nativeTargetExecuted:false,instructionSemanticsProved:false,nativeReachabilityProved:false,vmRoleProved:false,businessAccepted:false};
}
