import {evaluator} from './flow_state_eval.js';
const fail=m=>{throw Error('Recorded flow pair sampling refused: '+m);};
export function flowPairSelection(strategy='first4-last4',offset=undefined){
  if(!['first4-last4','distinct-source-targets'].includes(strategy)||offset!==undefined&&(strategy!=='distinct-source-targets'
    ||!Number.isSafeInteger(offset)||Object.is(offset,-0)||offset<0||offset>255))fail('invalid strategy or pair offset');
  return{strategy,pairOffset:offset??0};
}
/** Only a pure initial-GPR address expression and exact recorded read bytes.
 * This inventories observations, not complete instruction-state semantics.
 */
export function observeFlowSource(prepared,group){
  try{
    const{full,source}=prepared,nodes=full.dag.nodes,address=nodes[source].args[1],seen=new Set(),todo=[address];
    if(prepared.unsupported.length)fail('unsupported typed source');
    while(todo.length){const id=todo.pop();if(seen.has(id))continue;seen.add(id);if(['load_le','store_le','initial_memory','nondeterministic'].includes(nodes[id].op))fail('RAM/opaque-dependent source address');todo.push(...nodes[id].args);}
    if(nodes[source].args[0]!==full.initialMemory)fail('source is not an initial-RAM read');
    const initial=Object.fromEntries(Object.entries(group.before.gprs).map(([k,v])=>[k,BigInt(v)]));
    const at=evaluator(full,initial,()=>fail('address needs missing RAM'),new Map(),{bytes:0}),value=at(address),bytes=nodes[source].size;
    const reads=group.memoryReads.filter(r=>BigInt(r.address)===value&&r.bytes===bytes);
    if(!reads.length||reads.some(r=>r.littleEndianHex!==reads[0].littleEndianHex)||!new RegExp(`^[0-9a-f]{${bytes*2}}$`).test(reads[0].littleEndianHex))fail('missing or conflicting exact source read');
    const raw=Buffer.from(reads[0].littleEndianHex,'hex');
    return{status:'observed',address:'0x'+value.toString(16),bytes,value:'0x'+BigInt('0x'+raw.reverse().toString('hex')).toString(16)};
  }catch(e){return{status:'unobserved',reason:String(e.message).slice(0,256)};}
}
