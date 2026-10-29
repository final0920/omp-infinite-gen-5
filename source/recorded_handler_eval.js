// Finite ordinary-state assessment of an observed body between two fetches.
// Preferred-only cores bind relative control PCs. Separately tagged recorded
// cores decode at runtime PCs. Ordinary GPR/data/RAM is never rebased or filled.
import { checkedProjectionReferences } from './projection_jobs.js';
import { validateOpaqueProjection } from './projection_opaque.js';
import { typedRecordedSource } from './recorded_flow_eval.js';
import { evaluator } from './flow_state_eval.js';
import {validateRecordedCoordinateBinding} from './recorded_projection_coordinates.js';
const GPRS='rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split(' '),MASK=(1n<<64n)-1n;
const fail=m=>{throw Object.assign(new Error('Recorded handler assessment refused: '+m),{code:'INVALID_RECORDED_HANDLER'});},hex=x=>'0x'+x.toString(16);
const uint=x=>{if(typeof x!=='string'||!/^0x[0-9a-f]{1,16}$/.test(x))fail('uint64 observation');return BigInt(x);};
const DATA=new Set('mov movzx movsx movsxd cdqe and or xor cmp add sub not pushfq pop test stc cmc bswap rol sal shl adc sbb lea nop clc rcl xchg shr cqo setns btc bsr'.split(' '));
// Register CMOV admission still requires the complete raw/byte-bound dead-frame
// recognizer in the projection planner; this set grants no live-result model.
for(const suffix of ['o','no','c','nc','b','nae','ae','nb','z','nz','e','ne','be','na','a','nbe','s','ns','p','pe','np','po','l','nge','ge','nl','le','ng','g','nle'])DATA.add('cmov'+suffix);
function relative(bytes,pc){
  const b=Buffer.from(bytes,'hex'),next=(pc+BigInt(b.length))&MASK;let displacement,conditional=false;
  if(b.length===5&&b[0]===0xe9)displacement=BigInt(b.readInt32LE(1));
  else if(b.length===2&&b[0]===0xeb)displacement=BigInt(b.readInt8(1));
  else if(b.length===2&&b[0]>=0x70&&b[0]<=0x7f){displacement=BigInt(b.readInt8(1));conditional=true;}
  else if(b.length===6&&b[0]===0x0f&&b[1]>=0x80&&b[1]<=0x8f){displacement=BigInt(b.readInt32LE(2));conditional=true;}
  else return null;
  return{conditional,taken:(next+displacement)&MASK,fallthrough:next};
}
/** Reject PC-bearing data and CALLs instead of adjusting ordinary constants.
 * This deliberately limited data-instruction set is not an x64 relocation or
 * CPU equivalence proof. Both complete decoder records remain authoritative.
 */
export function bindRecordedHandlerControl(core,groups,mapping,decoded){
  if(!Array.isArray(groups)||!groups.length||groups.length>128||groups.length!==core.projectionPath.length
    ||mapping?.mapping?.length!==groups.length||!Array.isArray(decoded)||decoded.length!==groups.length)fail('complete byte descriptor required');
  const nodes=core.dag.nodes,c=core.control;
  const runtimeInput=core.recordedCoordinates?.input;
  if(runtimeInput){validateRecordedCoordinateBinding(core,runtimeInput);if(runtimeInput.runtimeBase!==mapping.runtimeBase||runtimeInput.preferredBase!==mapping.preferredBase)fail('recorded coordinate base differs');}
  else if(Object.hasOwn(core,'recordedCoordinates')||Object.hasOwn(core,'originalPreferredPath'))fail('incomplete recorded coordinate tag');
  const constant=(id,value)=>{const n=nodes[id];if(n?.op!=='const'||n.type!=='bv'||n.bits!==64||uint(n.value)!==value)fail('preferred terminal control constant');};
  let terminal;
  for(const [i,g]of groups.entries()){
    const m=mapping.mapping[i],d=decoded[i],p=core.decodedPath[i],ins=g.instructions?.[0];
    if(g.intermediateStateAvailable!==true||g.instructions.length!==1||!ins||m.runtimePc!==ins.pc||m.bytes!==ins.bytes||m.groupIndex!==g.groupIndex
      ||p.ea!==(runtimeInput?ins.pc:m.preferred)||core.projectionPath[i]!==(runtimeInput?ins.pc:m.preferred)||p.bytes!==ins.bytes||p.decoded?.size!==ins.bytes.length/2
      ||d?.status!=='decoded'||d.pc!==ins.pc||d.bytes!==ins.bytes
      ||uint(m.runtimePc)-uint(mapping.runtimeBase)!==uint(m.preferred)-uint(mapping.preferredBase))fail('decoder/mapping/recording binding');
    if(runtimeInput){const r=runtimeInput.rows[i];if(r.groupIndex!==g.groupIndex||r.recordingId!==g.recordingId||r.preferred!==m.preferred||r.runtimePc!==ins.pc||r.fileOffset!==m.fileOffset||r.bytes!==ins.bytes||r.pauseBefore!==g.pauseSequence?.before||r.pauseAfter!==g.pauseSequence?.after)fail('original recorded coordinate row differs');}
    if(d.operands.some(o=>o.kind==='register'&&!runtimeInput&&['rip','eip','ip'].includes(o.name)
      ||o.kind==='memory'&&(['fs','gs'].includes(o.segment)||[o.base,o.index,o.segment].some(r=>r&&(['fs','gs'].includes(r.name)||!runtimeInput&&['rip','eip','ip'].includes(r.name))))))fail('PC-relative or unmodeled segment data');
    const runtime=relative(ins.bytes,uint(ins.pc)),preferred=relative(ins.bytes,uint(m.preferred));
    if(runtime){
      if(d.controlFlow!==true)fail('relative control decoder disagreement');
      if(i<groups.length-1){
        if(runtime.conditional||uint(groups[i+1].before.rip)!==runtime.taken||uint(g.after.rip)!==runtime.taken)fail('unmodeled intermediate control');
      }else{
        if(c.source!==(runtimeInput?ins.pc:m.preferred)||c.transfer!==undefined||c.returnAddress!==undefined)fail('terminal source or CALL');
        if(runtime.conditional){
          if(c.kind!=='conditional'||c.conditionRule!=='nonzero-is-taken')fail('conditional terminal');
          constant(c.taken,runtimeInput?runtime.taken:preferred.taken);constant(c.fallthrough,runtimeInput?runtime.fallthrough:preferred.fallthrough);
        }else{if(c.kind!=='direct')fail('direct terminal');constant(c.target,runtimeInput?runtime.taken:preferred.taken);}
        terminal=runtime;
      }
    }else{
      // The finite mnemonic list protects the old preferred-only control
      // mapping. A complete runtime-byte binding needs no data relocation;
      // every raw operation and flag barrier still passed the same projector.
      if(d.controlFlow!==false||!runtimeInput&&!DATA.has(d.text.split(/\s/)[0].toLowerCase())||i===groups.length-1&&!runtimeInput)fail('unsupported ordinary instruction/control at '+i+': '+d.text);
      const next=(uint(ins.pc)+BigInt(ins.bytes.length/2))&MASK;
      if(uint(g.after.rip)!==next||i<groups.length-1&&g.after.rip!==groups[i+1].before.rip)fail('non-control successor');
      if(i===groups.length-1){if(c.kind!=='fallthrough'||c.source!==ins.pc||c.transfer!==undefined||c.returnAddress!==undefined)fail('runtime fallthrough terminal');constant(c.target,next);terminal={kind:'fallthrough',conditional:false,taken:next,fallthrough:next};}
    }
  }
  if(!terminal)fail('terminal byte-bound successor absent');
  return terminal;
}
function roots(core){return[...Object.values(core.registers),core.initialMemory,core.currentMemory,
  ...core.stores.flatMap(s=>[s.address,s.value,s.beforeMemory,s.afterMemory]),
  ...(core.control.kind==='conditional'?[core.control.condition,core.control.taken,core.control.fallthrough]:[core.control.target])];}
export function assessRecordedHandler({core,groups,mapping,decoded}){
  if(core?.schema!=='ig5-pcode-opaque-status-projection-v1'||core.projectionMode!=='opaque-status'
    ||['nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'].some(k=>core[k]!==false)
    ||Object.keys(core.initialRegisters||{}).sort().join(',')!==[...GPRS].sort().join(',')
    ||Object.keys(core.registers||{}).sort().join(',')!==[...GPRS].sort().join(','))fail('full ordinary-state source or scope');
  checkedProjectionReferences(core);validateOpaqueProjection(core);
  const unsupported=typedRecordedSource(core,{conditional:true});if(unsupported.length)fail('unsupported source operators including dead definitions: '+unsupported.join(','));
  const terminal=bindRecordedHandlerControl(core,groups,mapping,decoded),nodes=core.dag.nodes,opaqueAncestors=[];
  for(const n of nodes)opaqueAncestors.push([...new Set([...(n.op==='nondeterministic'?[n.id]:[]),...n.args.flatMap(id=>opaqueAncestors[id])])]);
  const initial=Object.fromEntries(GPRS.map(g=>[g,uint(groups[0].before.gprs[g])])),seed=new Map(),overlay=new Map(),work={bytes:0};
  const read=a=>{if(!seed.has(a))fail('missing initial RAM byte '+hex(a));return seed.get(a);};
  const at=evaluator(core,initial,read,new Map(),work),value=id=>opaqueAncestors[id].length?null:at(id),stores=[];
  let postStoreKnownReads=0,postStoreUnknownReads=0;
  for(const [i,g]of groups.entries()){
    for(const r of g.memoryReads){
      if(![1,2,4,8,16,32,64].includes(r.bytes)||typeof r.littleEndianHex!=='string'||!new RegExp(`^[0-9a-f]{${r.bytes*2}}$`).test(r.littleEndianHex))fail('memory observation');
      const address=uint(r.address),bytes=Buffer.from(r.littleEndianHex,'hex');
      for(let j=0;j<bytes.length;j++){
        const a=(address+BigInt(j))&MASK,b=bytes[j];
        if(overlay.has(a)){
          if(overlay.get(a)===null)postStoreUnknownReads++;
          else{if(overlay.get(a)!==b)fail('post-STORE observation differs');postStoreKnownReads++;}
        }else if(seed.has(a)){if(seed.get(a)!==b)fail('initial RAM observations conflict');}
        else{if(seed.size>=4096)fail('finite initial RAM budget');seed.set(a,b);}
      }
    }
    for(const s of core.stores)if(s.instructionIndex===i){
      const address=value(s.address),v=value(s.value);if(address===null)fail('opaque-dependent STORE address; no later RAM seeded');
      for(let j=0;j<s.size;j++)overlay.set((address+BigInt(j))&MASK,v===null?null:Number((v>>BigInt(8*j))&255n));
      stores.push({instructionIndex:i,pcodeIndex:s.pcodeIndex,address:hex(address),value:v===null?null:hex(v),bytes:s.size,
        valueStatus:v===null?'unknown-preserved':'replayed',opaqueInputs:opaqueAncestors[s.value]});
    }
  }
  const gprs=GPRS.map(name=>{
    const id=core.registers[name],v=value(id),observed=groups.at(-1).after.gprs[name];
    if(v!==null&&v!==uint(observed))fail('final GPR '+name+' differs');
    return{name,node:id,status:v===null?'unknown-preserved':'matched',computed:v===null?null:hex(v),observed,opaqueInputs:opaqueAncestors[id]};
  });
  const condition=terminal.conditional?value(core.control.condition):1n;
  if(condition===null)fail('opaque-dependent terminal condition');
  const target=terminal.conditional&&condition===0n?terminal.fallthrough:terminal.taken;
  if(target!==uint(groups.at(-1).after.rip))fail('terminal relative target or condition differs');
  const exact=stores.every(s=>s.valueStatus==='replayed')&&gprs.every(r=>r.status==='matched')&&postStoreUnknownReads===0;
  if(exact){
    const m=at(core.currentMemory);if(m.overlay.size!==overlay.size||[...overlay].some(([a,b])=>m.overlay.get(a)!==b))fail('ordinary final memory differs');
    roots(core).forEach(id=>at(id));
  }
  return{schema:'ig5-recorded-handler-assessment-v1',status:exact?'consistent-recorded-ordinary-state':'partially-consistent-unknown-preserved',
    all16FinalGprsMatched:gprs.every(r=>r.status==='matched'),gprs,orderedStores:stores,allOrderedDecodedStoresReplayed:stores.every(s=>s.valueStatus==='replayed'),
    terminalTargetMatched:true,control:{kind:core.control.kind,target:hex(target),condition:terminal.conditional?hex(condition):null,
      taken:terminal.kind==='fallthrough'?null:hex(terminal.taken),fallthrough:terminal.conditional||terminal.kind==='fallthrough'?hex(terminal.fallthrough):null,
      selectedSuccessor:terminal.conditional?(condition===0n?'fallthrough':'taken'):terminal.kind==='fallthrough'?'fallthrough':'direct',unselectedContinuationAnalyzed:false},
    codeCoordinateScope:core.recordedCoordinates?'Exact original/recorded byte mapping with runtime-PC Java decoding; ordinary GPR/data/RAM untouched, no global code epoch proof':'Only byte-bound relative control PCs; original runtime GPR/data/RAM and complete preferred-address DAG unchanged',
    allOrdinaryStateRootsPreserved:true,ordinaryRootNodes:roots(core),fullOriginalProjectionRequired:true,
    opaqueInputs:core.nondeterministicInputs,opaqueOutputsCoordinated:false,unknownValuesFilledFromObservations:false,
    finiteInitialMemoryBytes:[...seed].map(([a,value])=>({address:hex(a),value})),postStoreKnownReadBytesNotSeededAsInitial:postStoreKnownReads,
    postStoreUnknownReadBytesNotSeededAsInitial:postStoreUnknownReads,memoryByteVisits:work.bytes,
    projectedFlagsModeledOrCompared:false,intermediateGprSemanticsVerified:false,independentCpuStoreFootprintProved:false,
    nativeTargetExecuted:false,instructionSemanticsProved:false,nativeReachabilityProved:false,vmRoleProved:false,businessAccepted:false,wholeBinaryVerified:false};
}
