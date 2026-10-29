import {validateBVContract,validateBitvectorAST} from './bitvector_contract.js';
import {planningDigest} from './planning_identity.js';
export const PROVIDER_ID='ig5-local-bv-rewrite-v1';
export const PROVIDER_VERSION='20261024-local-bv-1';
export const PROVIDER_LIMITS=Object.freeze({visitedNodes:128,ruleChecks:512,rewrites:64,passes:1,outputBytes:65536});
export const PROVIDER_RULES=Object.freeze(['zero-identity','unit-product','zero-product','same-sub-xor','idempotent-bitwise','all-ones-mask','double-involution','constant-branch','same-branches','full-extract','mba-disjoint-sum']);
const failure=reason=>Object.assign(new Error(reason),{code:'CANDIDATE_PROVIDER_LIMIT'});
/** Single internal candidate source. No solver, evaluator, filesystem, dynamic code or upstream oracle. */
export function proposeLocalBitvector(contract){
 validateBVContract(contract);
 const original=contract.original,arena=[],interned=new Map(),mapped=[],steps=[];let checks=0;
 const same=(a,b)=>a===b,zero=id=>arena[id].op==='const'&&arena[id].value==='0x0';
 const one=id=>arena[id].op==='const'&&arena[id].value==='0x1';
 const all=id=>arena[id].op==='const'&&BigInt(arena[id].value)===(1n<<BigInt(arena[id].bits))-1n;
 function intern(node){const {id:unused,...body}=node,key=planningDigest(body);if(interned.has(key))return interned.get(key);if(arena.length>=128)throw failure('Candidate arena exceeds 128 nodes');const id=arena.length;arena.push({id,...body});interned.set(key,id);return id;}
 function attempt(condition,id,rule){if(++checks>512)throw failure('Candidate rule-check budget exceeded');return condition?{id,rule}:null;}
 for(const source of original.nodes){
  const node={...source,args:source.args.map(i=>mapped[i])},args=node.args;let replacement=null;
  if(args.length===2){
   const [a,b]=args;
   replacement=attempt(['add','or','xor','shl','lshr','ashr'].includes(node.op)&&zero(b),a,'zero-identity')
    ||attempt(['add','or','xor'].includes(node.op)&&zero(a),b,'zero-identity')
    ||attempt(node.op==='sub'&&zero(b),a,'zero-identity')
    ||attempt(node.op==='mul'&&(one(a)||one(b)),one(a)?b:a,'unit-product')
    ||attempt(['mul','and'].includes(node.op)&&(zero(a)||zero(b)),zero(a)?a:b,'zero-product')
    ||attempt(['sub','xor'].includes(node.op)&&same(a,b),null,'same-sub-xor')
    ||attempt(['and','or'].includes(node.op)&&same(a,b),a,'idempotent-bitwise')
    ||attempt(node.op==='and'&&(all(a)||all(b)),all(a)?b:a,'all-ones-mask');
   if(!replacement&&node.op==='add'){
    // (x XOR y) + 2*(x AND y) == x+y modulo the exact same bit width.
    for(const [first,second] of [[a,b],[b,a]]){
     if(++checks>512)throw failure('Candidate rule-check budget exceeded');
     const x=arena[first],m=arena[second];
     if(x.op!=='xor'||m.op!=='mul')continue;
     const mul=m.args.map(i=>arena[i]);let conjunction=null;
     if(mul[0].op==='const'&&mul[0].value==='0x2')conjunction=mul[1];
     if(mul[1].op==='const'&&mul[1].value==='0x2')conjunction=mul[0];
     if(conjunction?.op==='and'&&conjunction.bits===node.bits&&x.bits===node.bits
      &&((x.args[0]===conjunction.args[0]&&x.args[1]===conjunction.args[1])||(x.args[0]===conjunction.args[1]&&x.args[1]===conjunction.args[0]))){replacement={id:intern({op:'add',bits:node.bits,args:x.args}),rule:'mba-disjoint-sum'};break;}
    }
   }
  }else if(args.length===1){
   const a=arena[args[0]];
   replacement=attempt(['not','neg'].includes(node.op)&&a.op===node.op,a.args[0],'double-involution')
    ||attempt(node.op==='extract'&&node.offset===0&&node.bits===a.bits,args[0],'full-extract');
  }else if(node.op==='ite'){
   replacement=attempt(same(args[1],args[2]),args[1],'same-branches')
    ||attempt(arena[args[0]].op==='const',zero(args[0])?args[2]:args[1],'constant-branch');
  }
  if(replacement){
   if(steps.length>=64)throw failure('Candidate rewrite budget exceeded');
   if(replacement.id===null)replacement.id=intern({op:'const',bits:node.bits,args:[],value:'0x0'});
   mapped.push(replacement.id);steps.push({sourceNode:source.id,rule:replacement.rule});
  }else mapped.push(intern(node));
 }
 // Export only the reachable closure; no hidden discarded-node proof or side-effect removal.
 const nodes=[],ids=new Map();
 function copy(id){if(ids.has(id))return ids.get(id);const node=arena[id],args=node.args.map(copy),fresh=nodes.length;nodes.push({...node,id:fresh,args});ids.set(id,fresh);return fresh;}
 const ast={nodes,root:copy(mapped[original.root])},checked=validateBitvectorAST(ast,contract.variables);
 const cost=value=>({nodes:value.nodes.length,operators:value.nodes.filter(n=>!['var','const'].includes(n.op)).length});
 const originalCost=cost(original),candidateCost=cost(ast),improved=candidateCost.nodes<originalCost.nodes&&candidateCost.operators<originalCost.operators;
 const candidate=improved?checked.ast:structuredClone(original);
 const result={schema:'ig5-bitvector-provider-v1',providerId:PROVIDER_ID,providerVersion:PROVIDER_VERSION,originalDigest:contract.originalDigest,premiseDigest:contract.premiseDigest,
  status:improved?'candidate':'unchanged',candidate,candidateDigest:planningDigest(candidate),cost:{original:originalCost,candidate:improved?candidateCost:originalCost,metric:'reachable nodes and non-leaf operators; no runtime/model benefit claim'},
  work:{visitedNodes:original.nodes.length,ruleChecks:checks,rewrites:steps.length,passes:1},steps,verified:false,nativeTargetExecuted:false,businessAccepted:false};
 if(Buffer.byteLength(JSON.stringify(result))>65536)throw failure('Candidate output exceeds 64 KiB');return result;
}
