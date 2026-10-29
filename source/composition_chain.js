// Independent structural validation of definitional state boundaries. This is
// serialization/provenance validation, not a CPU/solver equivalence certificate.
const names = 'rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15'.split(' ');
const same = (a,b) => JSON.stringify(a) === JSON.stringify(b);
const need = (ok,message) => { if (!ok) throw new Error('Transition chain: '+message); };

export function validateTransitionChain(result,plan,reference,state) {
  const nodes=result.dag.nodes, layers=result.layers, bindings=new Set(), depths=[];
  need(plan.strategy==='sequence' && result.representation==='transition-chain' &&
    Array.isArray(layers) && layers.length===result.steps.length, 'explicit sequence/layer scope mismatch');
  need(names.every((name,id)=>result.initialRegisters[name]===id && nodes[id]?.op==='input' &&
    nodes[id].name===name && nodes[id].type==='bv' && nodes[id].bits===64 && nodes[id].args.length===0) &&
    result.initialMemory===16 && nodes[16]?.op==='initial_memory' && nodes[16].args.length===0,'initial state identity mismatch');
  for(const list of [result.stores,result.sideExits]) {
    let previous=-1;
    for(const item of list) {
      need(Number.isSafeInteger(item.stepIndex) && item.stepIndex>=previous && item.stepIndex<layers.length && item.stepIndex>=0,'STORE/exit application order mismatch');
      previous=item.stepIndex;
    }
  }
  const constant=(id,value,bits) => nodes[id]?.op==='const' && nodes[id].bits===bits && nodes[id].value==='0x'+BigInt(value).toString(16);
  const operation=(id,op,args,bits=8) => {
    const n=nodes[id];
    if(n?.op===op && n.bits===bits && same(n.args,args)) return true;
    if(args.every(a=>nodes[a]?.op==='const')) {
      const v=args.map(a=>BigInt(nodes[a].value));let expected;
      if(op==='BOOL_NEGATE') expected=Number(!v[0]);
      if(op==='BOOL_AND') expected=Number(!!v[0]&&!!v[1]);
      if(op==='INT_EQUAL') expected=Number(v[0]===v[1]);
      return expected!==undefined && constant(id,expected,bits);
    }
    return false;
  };
  const guarded=(id,entry,condition,negated=false) => {
    const n=nodes[id];
    const chosen=c=>negated?operation(c,'BOOL_NEGATE',[condition]):c===condition;
    if(n?.op==='BOOL_AND' && n.bits===8 && n.args[0]===entry && chosen(n.args[1])) return true;
    // The composer only folds when both operands are literal constants.
    if(nodes[entry]?.op==='const' && nodes[condition]?.op==='const') {
      const truth=BigInt(nodes[condition].value)!==0n;
      return constant(id,Number(BigInt(nodes[entry].value)!==0n && (negated?!truth:truth)),8);
    }
    return false;
  };
  let previous={registers:result.initialRegisters,currentMemory:result.initialMemory,pathGuard:result.boundaries[0].entryGuard};
  need(constant(previous.pathGuard,1,8),'initial guard must be true');
  let start=18;
  layers.forEach((layer,i)=>{
    const b=result.boundaries[i], ids=[...Object.values(layer.registers??{}),layer.currentMemory,layer.pathGuard];
    need(layer.stepIndex===i && layer.nodeStart===start && Number.isSafeInteger(layer.nodeEnd) &&
      layer.nodeEnd>start && layer.nodeEnd<=nodes.length && layer.nodeEnd===layer.pathGuard+1,'layer node interval mismatch');
    state(layer.inputRegisters);reference(layer.inputMemory,'memory');reference(layer.entryGuard,'bv',8);
    state(layer.registers);reference(layer.currentMemory,'memory');reference(layer.pathGuard,'bv',8);
    need(same(layer.inputRegisters,previous.registers) && layer.inputMemory===previous.currentMemory &&
      layer.entryGuard===previous.pathGuard,'application must consume the complete preceding state');
    need(same(layer.registers,b.registers) && layer.currentMemory===b.currentMemory &&
      layer.pathGuard===b.continuedGuard && layer.entryGuard===b.entryGuard,'boundary must export the exact bound state');
    const entries=new Set([...Object.values(layer.inputRegisters),layer.inputMemory,layer.entryGuard]);
    const checkBinding=(id,name,type,bits)=>{
      const n=nodes[id];
      need(Number.isSafeInteger(id) && id>=start && id<layer.nodeEnd && !bindings.has(id) &&
        n?.op==='state_binding' && n.name===name && n.stateIndex===i+1 && n.type===type && n.bits===bits && n.args.length===0 &&
        same(Object.keys(n).sort(),['id','op','type','args','source','stateIndex','name',...(bits===undefined?[]:['bits'])].sort()) &&
        Number.isSafeInteger(n.source) && n.source>=0 && n.source<id,'invalid or unbound state equality');
      reference(n.source,type,bits);bindings.add(id);
    };
    names.forEach(name=>checkBinding(layer.registers[name],name,'bv',64));
    checkBinding(layer.currentMemory,'memory','memory');checkBinding(layer.pathGuard,'guard','bv',8);
    need(new Set(ids).size===18,'all state variables must be distinct');
    for(let id=start;id<layer.nodeEnd;id++) {
      const n=nodes[id];
      need(!['input','initial_memory'].includes(n.op),'only the initial state may introduce free inputs');
      for(const ref of [...n.args,...(n.op==='state_binding'?[n.source]:[])]) {
        need(Number.isSafeInteger(ref) && ref>=0 && ref<id &&
          (ref>=start || entries.has(ref) || nodes[ref]?.op==='const'),'expression bypasses the preceding state boundary');
      }
    }
    const stores=result.stores.filter(s=>s.stepIndex===i);let memory=layer.inputMemory,lastPosition=-1;
    for(const s of stores) {
      const n=nodes[s.afterMemory],position=s.instructionIndex*129+s.pcodeIndex;
      need(s.templateIndex===b.templateIndex && s.guard===layer.entryGuard && s.beforeMemory===memory &&
        Number.isSafeInteger(position) && position>lastPosition && n?.op==='store_le' && n.size===s.size &&
        same(n.args,[s.beforeMemory,s.address,s.value]),'ordered STORE or entry guard mismatch');
      memory=s.afterMemory;lastPosition=position;
    }
    need(nodes[layer.currentMemory].source===memory,'post-state must preserve the entire ordered memory');
    need(same(result.templates[b.templateIndex].instructions.map(r=>r.ea),plan.paths[i]),'template applications differ from the explicit plan');
    const exits=result.sideExits.filter(e=>e.stepIndex===i),next=plan.paths[i+1]?.[0],c=b.control,guardSource=nodes[layer.pathGuard].source;
    if(!next || ['direct','fallthrough'].includes(c.kind)) {
      need(exits.length===0 && guardSource===layer.entryGuard,'direct/final continuation mismatch');
      if(next)need(constant(c.target,BigInt(next),64),'direct successor mismatch');
    } else {
      need(exits.length===1,'each selected conditional/dynamic edge requires its complementary exit');
      const e=exits[0];
      need(same(e.registers,layer.registers) && e.currentMemory===layer.currentMemory,'side exit lost the post-control state');
      if(c.kind==='conditional') {
        const take=constant(c.taken,BigInt(next),64),fall=constant(c.fallthrough,BigInt(next),64);
        need(take!==fall && e.target===(take?c.fallthrough:c.taken) &&
          guarded(guardSource,layer.entryGuard,c.condition,!take) && guarded(e.guard,layer.entryGuard,c.condition,take),'conditional edge/complement mismatch');
      } else {
        need(plan.indirect_mode==='guarded-target' && ['indirect','return'].includes(c.kind) && e.controlKind===c.kind &&
          e.target===c.target && constant(e.selectedTarget,BigInt(next),64) &&
          operation(e.selectionCondition,'INT_EQUAL',[c.target,e.selectedTarget]) &&
          guarded(guardSource,layer.entryGuard,e.selectionCondition) && guarded(e.guard,layer.entryGuard,e.selectionCondition,true),'dynamic edge/complement mismatch');
      }
    }
    previous={registers:layer.registers,currentMemory:layer.currentMemory,pathGuard:layer.pathGuard};start=layer.nodeEnd;
  });
  need(start===nodes.length && bindings.size===layers.length*18 && result.dag.bindingCount===bindings.size &&
    nodes.filter(n=>n.op==='state_binding').every(n=>bindings.has(n.id)) &&
    same(result.registers,previous.registers) && result.currentMemory===previous.currentMemory && result.pathGuard===previous.pathGuard &&
    same(result.control,result.boundaries.at(-1).control),'unbound extra node or final state mismatch');
  nodes.forEach(n=>depths.push(1+Math.max(0,...[...n.args,...(n.op==='state_binding'?[n.source]:[])].map(id=>depths[id]))));
  need(result.dag.expandedDependencyDepth===Math.max(...depths),'expanded dependency depth mismatch');
  return {layersChecked:layers.length,bindingsChecked:bindings.size,
    bindingTypes:{gpr64:layers.length*16,memory:layers.length,guard8:layers.length},
    stateContinuityTransitionsChecked:layers.length-1,orderedStoresAndEntryGuardsChecked:result.stores.length,
    memoryBindingSourcesChecked:layers.length,postControlSideExitStatesChecked:result.sideExits.length,
    bindingSourcesEarlierAndTypeMatched:true,allStateNamesAndIndicesChecked:true,
    bothDepthsAndAllReferencesAccounted:true};
}
