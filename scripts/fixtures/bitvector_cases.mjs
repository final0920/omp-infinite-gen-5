import {planningDigest} from '../../source/planning_identity.js';
import {BV_VERSION,truePremise} from '../../source/bitvector_contract.js';
export const variable=(bits=8)=>({id:0,op:'var',bits,args:[],name:'ssa_0'});
export const constant=(bits=8,value='0x0')=>({nodes:[{id:0,op:'const',bits,args:[],value}],root:0});
export const identity=(bits=8)=>({nodes:[variable(bits)],root:0});
export const addZero=(bits=8)=>({nodes:[variable(bits),{id:1,op:'const',bits,args:[],value:'0x0'},{id:2,op:'add',bits,args:[0,1]}],root:2});
export function declaration(original=addZero(),premise=truePremise()){
 return {schema:'ig5-bitvector-contract-v1',version:BV_VERSION,variables:[{name:'ssa_0',bits:original.nodes[0].bits,sourceNode:0,sourceName:'rax'}],original,premise,originalDigest:planningDigest(original),premiseDigest:planningDigest(premise)};
}
export function assessment(contract,candidate,{premiseStatus='sat',differenceStatus='unsat',value='0x1'}={}){
 return {schema:'ig5-bitvector-solver-v1',originalDigest:contract.originalDigest,candidateDigest:planningDigest(candidate),premiseDigest:contract.premiseDigest,premiseStatus,differenceStatus,
  premiseWitness:{v0:value,f07_dummy:'0x0'},counterexample:{v0:value,f07_dummy:'0x0'},queries:[{status:premiseStatus},...(premiseStatus==='sat'?[{status:differenceStatus}]:[])]};
}
/** Synthetic ordinary projection bytes; not a native decoding or CPU proof. */
export function projectionCase(targetSha256,{bits=8,op='INT_ADD',value='0x0',extend=null}={}){
 const nodes=[{id:0,op:'input',type:'bv',bits,args:[],name:'rax'},{id:1,op:'initial_memory',type:'memory',args:[]},{id:2,op:'const',type:'bv',bits,args:[],value},{id:3,op,type:'bv',bits,args:[0,2]}];
 let selected=3;if(extend){nodes.push({id:4,op:extend.op,type:'bv',bits:extend.bits,args:[3]});selected=4;}
 const depth=extend?3:2;
 return {schema:'ig5-pcode-projection-v1',targetSha256,projectionPath:['0x1000'],projectionRegisters:['rax'],initialRegisters:{rax:0},registers:{rax:selected},initialMemory:1,currentMemory:1,stores:[],control:{kind:'return',target:2},dag:{nodes,references:extend?8:7,depth},nativeTargetExecuted:false,databaseModified:false,businessAccepted:false,wholeBinaryVerified:false,fixtureScope:'owned synthetic IR; no native decoder started'};
}
