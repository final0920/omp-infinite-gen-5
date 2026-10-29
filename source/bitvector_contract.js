import { jsonToolOutput } from './json_output.js';
import { planningDigest } from './planning_identity.js';
export const BV_VERSION='20261024-bv-contract-1';
export const BV_LIMITS=Object.freeze({variables:6,nodes:128,depth:32,bits:64,jsonBytes:65536});
const fail=(message,code='UNSUPPORTED_BITVECTOR')=>{throw Object.assign(new Error(message),{code});};
const integer=(n,lo,hi)=>Number.isSafeInteger(n)&&!Object.is(n,-0)&&n>=lo&&n<=hi;
const keys=(v,k)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===k.sort().join();
const binary=['add','sub','mul','and','or','xor','shl','lshr','ashr','eq','ult','slt'];
/** Typed DAG, never executable text. No implicit width conversions or unknown dependencies. */
export function validateBitvectorAST(input,variables){
 const ast=jsonToolOutput(input);
 if(!keys(ast,['nodes','root'])||!Array.isArray(ast.nodes)||!ast.nodes.length||ast.nodes.length>128||!integer(ast.root,0,ast.nodes.length-1)||Buffer.byteLength(JSON.stringify(ast))>65536)fail('Bounded AST nodes/root required');
 const depths=[],used=new Set();
 ast.nodes.forEach((n,i)=>{
  if(!n||!integer(n.id,0,127)||n.id!==i||!integer(n.bits,1,64)||!Array.isArray(n.args)||n.args.length>6||n.args.some(x=>!integer(x,0,i-1)))fail('AST topology, width or arguments unsupported');
  const extra=n.op==='const'?['value']:n.op==='var'?['name']:n.op==='extract'?['offset']:[];
  if(!keys(n,['id','op','bits','args',...extra]))fail('Unknown AST fields or operator metadata');
  const args=n.args.map(a=>ast.nodes[a]);
  if(n.op==='const'){
   if(n.args.length||typeof n.value!=='string'||!/^0x(?:0|[1-9a-f][a-f0-9]{0,15})$/.test(n.value)||BigInt(n.value)>=1n<<BigInt(n.bits))fail('Constant must be canonical unsigned in-width hex');
  }else if(n.op==='var'){
   const v=variables.find(v=>v.name===n.name);if(n.args.length||!v||v.bits!==n.bits)fail('Variable SSA identity or width differs');used.add(n.name);
  }else if(binary.includes(n.op)){
   if(args.length!==2||args[0].bits!==args[1].bits||( ['eq','ult','slt'].includes(n.op)?n.bits!==1:n.bits!==args[0].bits))fail('Binary width/arity differs; conversions must be explicit');
  }else if(['not','neg'].includes(n.op)){
   if(args.length!==1||n.bits!==args[0].bits)fail('Unary width/arity differs');
  }else if(['zext','sext'].includes(n.op)){
   if(args.length!==1||n.bits<=args[0].bits)fail('Extension must strictly increase width');
  }else if(n.op==='extract'){
   if(args.length!==1||!integer(n.offset,0,63)||n.offset+n.bits>args[0].bits)fail('Explicit extraction range differs');
  }else if(n.op==='concat'){
   if(args.length<2||n.bits!==args.reduce((s,a)=>s+a.bits,0))fail('Concat must list exact high-to-low widths');
  }else if(n.op==='ite'){
   if(args.length!==3||args[0].bits!==1||args[1].bits!==n.bits||args[2].bits!==n.bits)fail('ITE requires a one-bit predicate and equal branch widths');
  }else fail('LOAD/CALL/PHI/flags/undefined or unknown operator unsupported');
  const depth=1+Math.max(0,...n.args.map(a=>depths[a]));if(depth>32)fail('AST depth exceeds 32');depths.push(depth);
 });
 const closure=new Set(),visit=id=>{if(closure.has(id))return;closure.add(id);ast.nodes[id].args.forEach(visit);};visit(ast.root);
 if(closure.size!==ast.nodes.length)fail('Disconnected/dead candidate nodes are not accepted');
 return {ast,digest:planningDigest(ast),bits:ast.nodes[ast.root].bits,usedVariables:[...used].sort(),depth:depths[ast.root]};
}
export const truePremise=()=>({nodes:[{id:0,op:'const',bits:1,args:[],value:'0x1'}],root:0});
const operators={INT_ADD:'add',INT_SUB:'sub',INT_MULT:'mul',INT_AND:'and',INT_OR:'or',INT_XOR:'xor',INT_NEGATE:'not',INT_2COMP:'neg',INT_LEFT:'shl',INT_RIGHT:'lshr',INT_SRIGHT:'ashr',INT_ZEXT:'zext',INT_SEXT:'sext',PIECE:'concat'};
/** Only the selected closure is pure; other state effects remain in the original report. */
export function extractProjectionExpression(projection,root){
 const rows=projection?.dag?.nodes;if(!Array.isArray(rows)||!integer(root,0,rows.length-1))fail('Select a committed projection root');
 const nodes=[],mapping=new Map(),variables=[];
 function visit(id,depth=1){
  if(depth>32||mapping.size>=128)fail('Source closure exceeds AST bounds');if(mapping.has(id))return mapping.get(id);
  const n=rows[id];if(!n||n.id!==id||n.type!=='bv'||!integer(n.bits,1,64)||!Array.isArray(n.args)||n.args.some(a=>!integer(a,0,id-1)))fail('Source contains non-BV or unknown dependency');
  let op,extra={},args;
  if(n.op==='input'){
   // Only initial ordinary GPR input identities. Opaque/flags/nondeterministic inputs are never cut away.
   if(!/^(?:rax|rcx|rdx|rbx|rsp|rbp|rsi|rdi|r8|r9|r10|r11|r12|r13|r14|r15)$/.test(n.name)||projection.initialRegisters?.[n.name]!==id)fail('Source input is not a bound initial ordinary GPR');
   op='var';extra.name='ssa_'+id;if(!variables.some(v=>v.name===extra.name))variables.push({name:extra.name,bits:n.bits,sourceNode:id,sourceName:n.name});
   if(variables.length>6)fail('At most six source SSA variables');args=[];
  }else if(n.op==='const'){
   op='const';if(typeof n.value!=='string'||!/^0x[0-9a-f]+$/i.test(n.value))fail('Source constant encoding unsupported');extra.value='0x'+BigInt(n.value).toString(16);args=[];
  }else if(n.op==='extract'){
   op='extract';extra.offset=n.offset;args=n.args.map(a=>visit(a,depth+1));
  }else if(n.op==='COPY'){
   if(n.args.length!==1||rows[n.args[0]]?.bits!==n.bits)fail('COPY width differs');const mapped=visit(n.args[0],depth+1);mapping.set(id,mapped);return mapped;
  }else {op=operators[n.op];if(!op)fail('Source operator has no fixed pure BV adapter: '+String(n.op));args=n.args.map(a=>visit(a,depth+1));}
  if(n.args.length&&args.length!==n.args.length)fail('Source dependency was dropped');
  const index=nodes.length;nodes.push({id:index,op,bits:n.bits,args,...extra});mapping.set(id,index);return index;
 }
 const selected=visit(root);variables.sort((a,b)=>a.sourceNode-b.sourceNode);const original={nodes,root:selected};
 validateBitvectorAST(original,variables);return {original,variables};
}
export function validateBVContract(value){
 if(!value||value.schema!=='ig5-bitvector-contract-v1'||value.version!==BV_VERSION||!Array.isArray(value.variables)||value.variables.length>6||new Set(value.variables.map(v=>v.name)).size!==value.variables.length)fail('Unsupported candidate contract');
 for(const v of value.variables)if(!keys(v,['name','bits','sourceNode','sourceName'])||!/^ssa_[0-9]+$/.test(v.name)||!integer(v.bits,1,64)||!integer(v.sourceNode,0,2047)||v.name!=='ssa_'+v.sourceNode)fail('Contract SSA binding differs');
 const original=validateBitvectorAST(value.original,value.variables),premise=validateBitvectorAST(value.premise,value.variables);
 if(premise.bits!==1||original.ast.nodes.length+premise.ast.nodes.length>128)fail('Source + premise must fit 128 nodes and premise must be one bit');
 if(original.digest!==value.originalDigest||premise.digest!==value.premiseDigest)fail('Contract AST digest differs','ARTIFACT_CHANGED');
 return value;
}
