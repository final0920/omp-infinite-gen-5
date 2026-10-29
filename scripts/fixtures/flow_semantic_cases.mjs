// Synthetic typed IR, never a native recording or CPU/VM equivalence claim.
export function semanticCore({prefix=false,cancelIndex=false,cancelTarget=false,independent=false,unsupported=false}={}){
  const nodes=[],add=(op,type,args,extra={})=>{const id=nodes.length;nodes.push({id,op,type,args,...extra});return id;};
  const initialRegisters=Object.fromEntries('rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split(' ').map(name=>[name,add('input','bv',[],{bits:64,name})]));
  const memory=add('initial_memory','memory',[],{name:'M0',addressBits:64,elementBits:8});
  const source=add('load_le','bv',[memory,initialRegisters.rsi],{bits:8,size:1}),extended=add('INT_ZEXT','bv',[source],{bits:64});
  const registers={...initialRegisters,rax:extended};let target=initialRegisters.rdx,currentMemory=memory;const stores=[];
  if(!prefix){
    const idx=cancelIndex?add('INT_XOR','bv',[extended,extended],{bits:64}):extended;
    const four=add('const','bv',[],{bits:64,value:'0x4'}),offset=add('INT_MULT','bv',[idx,four],{bits:64});
    const address=add('INT_ADD','bv',[initialRegisters.r11,offset],{bits:64}),table=add('load_le','bv',[memory,address],{bits:32,size:4});
    const signed=add('INT_SEXT','bv',[table],{bits:64});
    if(!independent)target=add('INT_ADD','bv',[signed,initialRegisters.r11],{bits:64});
    if(cancelTarget)target=add('INT_XOR','bv',[target,target],{bits:64});
    registers.r8=target;
    const eight=add('const','bv',[],{bits:64,value:'0x8'}),sp=add('INT_SUB','bv',[initialRegisters.rsp,eight],{bits:64});
    currentMemory=add('store_le','memory',[memory,sp,target],{size:8});
    stores.push({instructionIndex:1,pcodeIndex:0,address:sp,value:target,size:8,beforeMemory:memory,afterMemory:currentMemory});
    if(unsupported)add('UNSUPPORTED_DEAD_NODE','bv',[],{bits:64});
  }
  const projectionPath=prefix?['0x1000']:['0x1000','0x1003'],depths=[];
  for(const n of nodes)depths.push(1+Math.max(0,...n.args.map(i=>depths[i])));
  return {schema:'ig5-pcode-opaque-status-projection-v1',projectionMode:'opaque-status',targetSha256:'a'.repeat(64),
    nativeTargetExecuted:false,databaseModified:false,businessAccepted:false,wholeBinaryVerified:false,projectionPath,
    decodedPath:projectionPath.map(ea=>({ea,bytes:ea==='0x1000'?'0fb606':'c3',decoded:{pcode:[]}})),
    initialRegisters,registers,initialMemory:memory,currentMemory,stores,control:{kind:prefix?'direct':'return',source:prefix?'0x1000':'0x1003',target},
    nondeterministicInputs:[],opaqueEffects:[],statistics:{pcodeOperations:prefix?3:7},
    dag:{nodes,references:nodes.reduce((s,n)=>s+n.args.length,0)+35+4*stores.length,depth:Math.max(...depths)}};
}
