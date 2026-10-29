// Independent BigInt evaluation for finite paired-state solver witnesses.
// It does not execute machine instructions, infer missing RAM, or prove CPU
// semantics. Missing finite memory observations always stop witness acceptance.
import { classifyFetchFlow } from './vm_fetch_flow.js';
const MASK=(1n<<64n)-1n,hex=n=>'0x'+n.toString(16),mask=bits=>(1n<<BigInt(bits))-1n;
const GPRS='rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15'.split(' ');
const fail=m=>{throw new Error('Flow witness replay refused: '+m);};
const uint=(v,bits)=>{if(typeof v!=='string'||!/^0x[0-9a-f]+$/.test(v)||v.length>2+Math.ceil(bits/4))fail('invalid bitvector');const n=BigInt(v);if(n>mask(bits))fail('bitvector width');return n;};
const signed=(v,bits)=>BigInt.asIntN(bits,v);
export function evaluator(core,initial,readByte,opaque,work){
  const nodes=core.dag.nodes,cache=new Map();
  const at=(id,depth=0)=>{
    if(cache.has(id))return cache.get(id);
    if(depth>128||!Number.isSafeInteger(id)||id<0||id>=nodes.length)fail('DAG range/depth');
    const n=nodes[id];if(n.id!==id||!Array.isArray(n.args)||n.args.some(i=>!Number.isSafeInteger(i)||i<0||i>=id))fail('DAG order');
    const args=n.args.map(i=>at(i,depth+1)),widths=n.args.map(i=>nodes[i].bits);let value;
    const memoryByte=(m,a)=>{if(++work.bytes>4096)fail('memory work budget');return m.overlay.has(a)?m.overlay.get(a):m.base(a);};
    if(n.op==='input'){if(!GPRS.includes(n.name)||n.bits!==64)fail('GPR');value=initial[n.name];}
    else if(n.op==='nondeterministic'){if(!opaque.has(id))fail('missing opaque input');value=opaque.get(id);}
    else if(n.op==='const')value=uint(n.value,n.bits);
    else if(n.op==='initial_memory')value={base:readByte,overlay:new Map()};
    else if(n.op==='extract')value=args[0]>>BigInt(n.offset);
    else if(n.op==='concat'){value=0n;for(let i=0;i<args.length;i++)value=(value<<BigInt(widths[i]))|args[i];}
    else if(n.op==='INT_ZEXT')value=args[0];
    else if(n.op==='INT_SEXT')value=signed(args[0],widths[0]);
    else if(n.op==='INT_ADD')value=args[0]+args[1];
    else if(n.op==='INT_SUB')value=args[0]-args[1];
    else if(n.op==='INT_MULT')value=args[0]*args[1];
    else if(n.op==='INT_AND')value=args[0]&args[1];
    else if(n.op==='INT_OR')value=args[0]|args[1];
    else if(n.op==='INT_XOR')value=args[0]^args[1];
    else if(n.op==='INT_NEGATE')value=~args[0];
    else if(n.op==='BOOL_AND')value=BigInt(args[0]!==0n&&args[1]!==0n);
    else if(n.op==='BOOL_OR')value=BigInt(args[0]!==0n||args[1]!==0n);
    else if(n.op==='BOOL_NEGATE')value=BigInt(args[0]===0n);
    else if(n.op==='INT_EQUAL')value=BigInt(args[0]===args[1]);
    else if(n.op==='INT_NOTEQUAL')value=BigInt(args[0]!==args[1]);
    else if(n.op==='INT_LESS')value=BigInt(args[0]<args[1]);
    else if(n.op==='INT_SLESS')value=BigInt(signed(args[0],widths[0])<signed(args[1],widths[1]));
    else if(n.op==='INT_CARRY')value=BigInt(args[0]+args[1]>mask(widths[0]));
    else if(n.op==='INT_SCARRY'){
      const a=signed(args[0],widths[0]),b=signed(args[1],widths[1]),c=BigInt.asIntN(widths[0],a+b);
      value=BigInt((a<0n)===(b<0n)&&(a<0n)!==(c<0n));
    }else if(n.op==='POPCOUNT'){value=0n;let bits=args[0];while(bits){value+=bits&1n;bits>>=1n;}}
    else if(n.op==='load_le'){
      value=0n;for(let i=0;i<n.size;i++)value|=BigInt(memoryByte(args[0],(args[1]+BigInt(i))&MASK))<<BigInt(8*i);
    }else if(n.op==='store_le'){
      value={base:args[0].base,overlay:new Map(args[0].overlay)};
      for(let i=0;i<n.size;i++){if(++work.bytes>4096)fail('store work budget');value.overlay.set((args[1]+BigInt(i))&MASK,Number((args[2]>>BigInt(8*i))&255n));}
    }else fail('unsupported operator '+n.op);
    if(n.type==='bv'){if(typeof value!=='bigint')fail('non-bitvector value');value&=mask(n.bits);}
    else if(n.type!=='memory'||!value?.overlay)fail('memory value');
    cache.set(id,value);return value;
  };
  return at;
}
export function replayFlowWitness(core,assessment,witness){
  const state=witness.state;if(!state||Object.keys(state.initialRegisters||{}).sort().join(',')!==[...GPRS].sort().join(','))fail('initial GPR set');
  const initial=Object.fromEntries(GPRS.map(g=>[g,uint(state.initialRegisters[g],64)]));
  if(!Array.isArray(state.initialMemoryBytes)||state.initialMemoryBytes.length>256||!Array.isArray(state.opaqueInputs)||state.opaqueInputs.length>2048)fail('finite state budget');
  const memory=new Map();for(const r of state.initialMemoryBytes){const a=uint(r.address,64);if(!Number.isSafeInteger(r.value)||Object.is(r.value,-0)||r.value<0||r.value>255||memory.has(a))fail('initial RAM byte');memory.set(a,r.value);}
  const opaque=new Map();for(const r of state.opaqueInputs){if(!Number.isSafeInteger(r.node)||core.dag.nodes[r.node]?.op!=='nondeterministic'||opaque.has(r.node))fail('opaque identity');opaque.set(r.node,uint(r.value,64));}
  const base=a=>{if(!memory.has(a))fail('unobserved finite RAM byte '+hex(a));return memory.get(a);},work={bytes:0};
  const before=evaluator(core,initial,base,opaque,work),sourceNode=state.sourceNode,source=core.dag.nodes[sourceNode];
  if(source?.op!=='load_le'||![1,2].includes(source.size)||source.args[0]!==core.initialMemory||state.sourceAddressNode!==source.args[1])fail('source identity');
  const sourceAddress=before(source.args[1]),oldSource=before(sourceNode),changedSource=uint(state.changedSourceValue,source.bits),changedBytes=new Map();
  for(let i=0;i<source.size;i++)changedBytes.set((sourceAddress+BigInt(i))&MASK,Number((changedSource>>BigInt(8*i))&255n));
  const after=evaluator(core,initial,a=>changedBytes.has(a)?changedBytes.get(a):base(a),opaque,work);
  if(after(sourceNode)!==changedSource||oldSource===changedSource)fail('source mutation differs');
  const index=core.dag.nodes[state.indexReadNode];if(index?.op!=='load_le'||state.indexReadNode!==assessment.indexReadNode||index.args[1]!==assessment.addressNode)fail('indexed-read identity');
  for(const i of assessment.coupledIndexLoads)if(before(i)!==after(i))fail('index LOAD coupling');
  const oldIndex=before(index.args[1]),newIndex=after(index.args[1]),oldTarget=before(core.control.target),newTarget=after(core.control.target);
  if(['index-change','target-premises','target-change'].includes(witness.kind)&&oldIndex===newIndex)fail('index not changed');
  if(['target-premises','target-change'].includes(witness.kind))for(const i of assessment.coupledOtherTargetLoads)if(before(i)!==after(i))fail('target LOAD coupling');
  if(witness.kind==='target-change'&&oldTarget===newTarget)fail('target not changed');
  if(!['source-premises','index-change','target-premises','target-change'].includes(witness.kind))fail('unknown witness kind');
  // Keep every ordinary final-state/memory/ordered-store root in the replay.
  for(const id of Object.values(core.registers)){before(id);after(id);}before(core.currentMemory);after(core.currentMemory);
  for(const s of core.stores)for(const k of ['address','value','beforeMemory','afterMemory']){before(s[k]);after(s[k]);}
  return {query:witness.query,kind:witness.kind,verified:true,sourceAddress:hex(sourceAddress),oldSource:hex(oldSource),changedSource:hex(changedSource),
    oldIndex:hex(oldIndex),changedIndex:hex(newIndex),oldTarget:hex(oldTarget),changedTarget:hex(newTarget),
    all16InitialGprsCoupled:true,opaqueInputsCoupled:true,exactInitialSourceByteStore:true,allOrdinaryFinalGprMemoryAndOrderedStoreRootsReplayed:true,
    orderedStores:core.stores.length,memoryByteVisits:work.bytes,nativeReachabilityProved:false,recordedEnvironmentUsed:false};
}
export function replayFlowAssessment({prefix,full,assessment}){
  const dependency=classifyFetchFlow(prefix,full),nodes=full.dag.nodes;
  if(assessment?.schema!=='ig5-flow-semantic-assessment-v1'||assessment.assessmentComplete!==true
    ||assessment.targetSha256!==full.targetSha256||assessment.sourceLoadSignature!==dependency.sourceLoad.signature
    ||assessment.sourceLoadNode!==dependency.sourceLoad.matchedFullNodes[0]||assessment.sourceBytes!==dependency.sourceLoad.bytes
    ||assessment.sourceAddressNode!==nodes[assessment.sourceLoadNode]?.args[1]||nodes[assessment.sourceLoadNode]?.args[0]!==full.initialMemory
    ||assessment.hostWitnessReplayVerified!==false||['nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified','vmRoleProved','instructionSemanticsProved'].some(k=>assessment[k]!==false)
    ||!Array.isArray(assessment.queries)||assessment.queries.length>128||!Array.isArray(assessment.assessments)||assessment.assessments.length>4
    ||assessment.indexedReadsTotal!==dependency.indexedReads.length||assessment.indexedReadsAssessed!==Math.min(4,dependency.indexedReads.length)
    ||assessment.assessments.length!==assessment.indexedReadsAssessed||assessment.indexedReadCoverageComplete!==(dependency.indexedReads.length<=4)
    ||assessment.sourceValidation?.wholeSourceDagValidated!==true||assessment.sourceValidation.explicitCuts?.length!==0||assessment.sourceValidation.weakenedLoadNodes?.length!==0)fail('assessment source/scope');
  const closure=root=>{const seen=new Set(),todo=[root];while(todo.length){const i=todo.pop();if(seen.has(i))continue;seen.add(i);todo.push(...nodes[i].args);}return seen;};
  const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b),matches=dependency.sourceLoad.matchedFullNodes,indexed=dependency.indexedReads.map(r=>r.node);
  if([...closure(assessment.sourceAddressNode)].some(i=>['load_le','initial_memory','store_le','nondeterministic'].includes(nodes[i].op)))fail('RAM-dependent source address');
  const roots=[...new Set([...Object.values(full.registers),full.initialMemory,full.currentMemory,full.control.target,assessment.sourceLoadNode,assessment.sourceAddressNode,
    ...full.stores.flatMap(s=>['address','value','beforeMemory','afterMemory'].map(k=>s[k])),...dependency.indexedReads.map(r=>r.addressNode)])];
  const needed=[...new Set(roots.flatMap(i=>[...closure(i)]))].sort((a,b)=>a-b);
  if(!same(assessment.roots,roots)||!same(assessment.neededNodes,needed))fail('ordinary roots or closure omitted');
  const targetLoads=[...closure(full.control.target)].filter(i=>nodes[i].op==='load_le').sort((a,b)=>a-b);
  let cursor=0;
  for(let i=0;i<assessment.assessments.length;i++){
    const a=assessment.assessments[i],index=dependency.indexedReads[i];
    const otherIndex=[...closure(index.addressNode)].filter(n=>nodes[n].op==='load_le'&&!matches.includes(n)).sort((a,b)=>a-b);
    const otherTarget=targetLoads.filter(n=>!matches.includes(n)&&!indexed.includes(n));
    if(a.indexReadNode!==index.node||a.addressNode!==index.addressNode||!same(a.coupledIndexLoads,otherIndex)||!same(a.coupledOtherTargetLoads,otherTarget)
      ||!Array.isArray(a.queries)||!Array.isArray(a.witnesses)||a.witnesses.length>4)fail('index or LOAD coupling');
    let count=1;
    const first=assessment.queries[cursor];if(first?.status==='sat'){
      count=2;if(assessment.queries[cursor+1]?.status==='sat'){
        count=3;if(assessment.queries[cursor+2]?.status==='sat')count=4;
      }
    }
    if(!same(a.queries,Array.from({length:count},(_,j)=>cursor+j))||a.indexMayChange!==(count>=3)
      ||a.targetMayChangeWithIndex!==(count===4&&assessment.queries[cursor+3]?.status==='sat'))fail('assessment query sequence');
    const suffix=['source-premises','address-change','target-premises','target-change'],kinds=['source-premises','index-change','target-premises','target-change'];
    for(let j=0;j<count;j++){
      const q=assessment.queries[cursor+j];
      if(!q||q.name!==`index-${index.node}-${suffix[j]}`||!['sat','unsat','unknown','unverified'].includes(q.status))fail('query identity/status');
      const witnesses=a.witnesses.filter(w=>w.query===cursor+j);
      if(witnesses.length!==(q.status==='sat'?1:0)||witnesses.some(w=>w.kind!==kinds[j]||w.state.sourceNode!==assessment.sourceLoadNode
        ||w.state.sourceAddressNode!==assessment.sourceAddressNode||w.state.nativeReachabilityProved!==false||w.state.recordedEnvironmentUsed!==false))fail('query witness binding');
    }
    cursor+=count;
  }
  if(cursor!==assessment.queries.length)fail('unreferenced queries');
  const rows=[];
  for(const a of assessment.assessments||[])for(const witness of a.witnesses||[])rows.push(replayFlowWitness(full,a,witness));
  const satQueries=(assessment.queries||[]).map((q,i)=>q.status==='sat'?i:-1).filter(i=>i>=0);
  if(rows.length!==satQueries.length||new Set(rows.map(r=>r.query)).size!==rows.length||satQueries.some(i=>!rows.some(r=>r.query===i)))fail('SAT witness coverage');
  return {schema:'ig5-flow-semantic-witness-replay-v1',hostWitnessReplayVerified:true,verifiedSatQueries:rows.length,replays:rows,
    semanticNonconstancyProved:(assessment.assessments||[]).some(a=>a.targetMayChangeWithIndex&&a.witnesses.some(w=>w.kind==='target-change')),
    semanticNonconstancyScope:'Existential paired selected-path ordinary IR states with one coherent initial source-byte store and listed LOAD-value couplings',
    nativeTargetExecuted:false,instructionSemanticsProved:false,vmRoleProved:false,businessAccepted:false};
}
