// Fixed expression families; semantic expected outcomes are checked by the independent F07 solver.
const make=build=>{const nodes=[],add=(op,bits,args=[],extra={})=>{const id=nodes.length;nodes.push({id,op,bits,args,...extra});return id;};const root=build(add);return {nodes,root};};
const variable=(add,bits,index=0)=>add('var',bits,[],{name:'ssa_'+index});
const c=(add,bits,value)=>add('const',bits,[],{value});
export const PROVIDER_CASES=Object.freeze([
 {id:'nested-identities-16bit',family:'heldout',expected:'verified-candidate',ast:make(a=>{const x=variable(a,16),z=c(a,16,'0x0'),one=c(a,16,'0x1'),sum=a('add',16,[x,z]);return a('mul',16,[sum,one]);})},
 {id:'double-complement-32bit',family:'heldout',expected:'verified-candidate',ast:make(a=>{const x=variable(a,32),n=a('not',32,[x]);return a('not',32,[n]);})},
 {id:'subself-under-nontrivial-context-64bit',family:'heldout',expected:'verified-candidate',ast:make(a=>{const x=variable(a,64),same=a('sub',64,[x,x]);return a('xor',64,[x,same]);})},
 {id:'mba-two-input-32bit',family:'heldout',expected:'verified-candidate',ast:make(a=>{const x=variable(a,32),y=variable(a,32,1),xor=a('xor',32,[x,y]),and=a('and',32,[y,x]),two=c(a,32,'0x2'),twice=a('mul',32,[two,and]);return a('add',32,[twice,xor]);})},
 {id:'unchanged-x-plus-one',family:'control',expected:'unchanged',ast:make(a=>{const x=variable(a,8),one=c(a,8,'0x1');return a('add',8,[x,one]);})},
 {id:'wrong-MBA-coefficient',family:'control',expected:'unchanged',ast:make(a=>{const x=variable(a,32),y=variable(a,32,1),xor=a('xor',32,[x,y]),and=a('and',32,[x,y]),three=c(a,32,'0x3'),times=a('mul',32,[three,and]);return a('add',32,[xor,times]);})},
 {id:'infeasible-premise',family:'control',expected:'candidate-not-accepted',premise:{nodes:[{id:0,op:'const',bits:1,args:[],value:'0x0'}],root:0},ast:make(a=>{const x=variable(a,8),z=c(a,8,'0x0');return a('add',8,[x,z]);})},
 {id:'mixed-width-extend-order',family:'control',expected:'unchanged',ast:make(a=>{const x=variable(a,8),one=c(a,8,'0x1'),sum=a('add',8,[x,one]);return a('zext',16,[sum]);})},
]);
export function providerProjection(ast,targetSha256){
 const ops={var:'input',add:'INT_ADD',sub:'INT_SUB',mul:'INT_MULT',and:'INT_AND',or:'INT_OR',xor:'INT_XOR',not:'INT_NEGATE',neg:'INT_2COMP',zext:'INT_ZEXT',sext:'INT_SEXT',shl:'INT_LEFT',lshr:'INT_RIGHT',ashr:'INT_SRIGHT',concat:'PIECE',const:'const',extract:'extract'};
 const gprs=['rax','rcx','rdx','rbx','rsp','rbp'],initialRegisters={};let v=0;
 const nodes=ast.nodes.map(n=>{const {name,...rest}=n,node={...rest,op:ops[n.op],type:'bv'};if(n.op==='var'){node.name=gprs[v++];initialRegisters[node.name]=n.id;}return node;});
 const mem=nodes.length;nodes.push({id:mem,op:'initial_memory',type:'memory',args:[]});
 const depths=[];for(const n of nodes)depths.push(1+Math.max(0,...n.args.map(i=>depths[i])));
 const references=nodes.reduce((s,n)=>s+n.args.length,0)+Object.keys(initialRegisters).length+1+2+1;
 return {schema:'ig5-pcode-projection-v1',targetSha256,projectionPath:['0x1000'],projectionRegisters:['rax'],initialRegisters,registers:{rax:ast.root},initialMemory:mem,currentMemory:mem,stores:[],control:{kind:'return',target:ast.root},dag:{nodes,references,depth:Math.max(...depths)},nativeTargetExecuted:false,databaseModified:false,businessAccepted:false,wholeBinaryVerified:false,fixtureScope:'owned synthetic IR; no actual decoder'};
}
