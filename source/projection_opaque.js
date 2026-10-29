import { hashBytes } from './analysis_artifacts.js';

const gprs='rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15'.split(' ');
const offsets=[0,8,16,24,32,40,48,56,128,136,144,152,160,168,176,184];
const rawPins={push:'b716d890dc722444a6cf52e3952e04226c48692030b1ca45b8f4f4fffe0fe539',tsc:'c169e67f4e1028f5c1ee5f6440bd50b32a59486ae2b28d734fedb5d309d8c599',bswap:'b850ce16167269126f00e2e292f71d5d1fe16b3db75293d863977d34ea2bc964'};
const canonical=v=>JSON.stringify(v,(_k,x)=>x&&typeof x==='object'&&!Array.isArray(x)?Object.fromEntries(Object.keys(x).sort().map(k=>[k,x[k]])):x);
const fail=()=>{throw new Error('Projection returned inconsistent opaque-effect scope or provenance');};
const flagBits={cf:0,pf:2,af:4,zf:6,sf:7,of:11},flagOffsets={cf:0x200,pf:0x202,af:0x204,zf:0x206,sf:0x207,of:0x20b};

function statusDefinitions(result){
  if(!Array.isArray(result.flagPolicies)||result.flagPolicies.length!==result.decodedPath.length)fail();
  let known={};const before=[];
  for(let i=0;i<result.decodedPath.length;i++){
    before.push({...known});const row=result.decodedPath[i],p=result.flagPolicies[i];
    if(!p||!['classified','unknown'].includes(p.status)||(p.status==='classified'||Object.hasOwn(p,'codeBytes'))&&p.codeBytes!==row.bytes)fail();
    const names=['defined','preserved','undefined','unmodeled'];
    if(names.some(k=>!Array.isArray(p[k])||p[k].some(n=>!Object.hasOwn(flagBits,n))||new Set(p[k]).size!==p[k].length)||
       new Set(names.flatMap(k=>p[k])).size!==6)fail();
    // Architectural undefined and decoder unmodeled are independent reasons
    // to block the same flag. They may overlap; defined/preserved may not.
    const blocked=new Set([...p.undefined,...p.unmodeled]);
    if(p.defined.some(n=>p.preserved.includes(n)||blocked.has(n))||p.preserved.some(n=>blocked.has(n)))fail();
    if(p.status!=='classified'){known={};continue;}
    const written=new Set(),needed=new Set();let internal=false;
    for(const op of row.decoded.pcode){
      if(['BRANCH','CBRANCH'].includes(op.opcode)&&op.inputs?.[0]?.space==='const')internal=true;
      for(const v of op.inputs??[])if(v?.space==='register')for(const [n,a]of Object.entries(flagOffsets)){
        const offset=Number(BigInt(v.offset));if(offset<=a&&a<offset+v.size&&!written.has(n))needed.add(n);}
      const v=op.output;if(v?.space==='register')for(const [n,a]of Object.entries(flagOffsets)){
        const offset=Number(BigInt(v.offset));if(offset<=a&&a<offset+v.size)written.add(n);}
    }
    const next=Object.fromEntries(Object.entries(known).filter(([n])=>p.preserved.includes(n)));
    if(!internal&&[...needed].every(n=>Object.hasOwn(known,n)))for(const n of p.defined){if(!written.has(n))fail();next[n]=i;}
    known=next;
  }
  return before;
}

function statusImage(result,e,expected,inputs,statusStep){
  const r=e.flagImageRefinement,mask=Object.keys(expected).reduce((m,n)=>m|(1n<<BigInt(flagBits[n])),0n),unknown=((1n<<64n)-1n)^mask;
  const flags=Object.keys(expected).sort((a,b)=>flagBits[a]-flagBits[b]).map(n=>({name:n,bit:flagBits[n],definitionInstructionIndex:expected[n]}));
  if(!r||r.method!=='defined-status-pcode-overlay-v1'||r.knownMask!=='0x'+mask.toString(16)||r.unknownMask!=='0x'+unknown.toString(16)||
     canonical(r.knownFlags)!==canonical(flags)||r.freshInputBits!==64||r.effectiveUnknownBits!==64-flags.length||r.initialFlagValuesSupplied!==false||r.unmodeledBitsRemainUnknown!==true)fail();
  const stores=result.stores.filter(s=>s.instructionIndex===e.instructionIndex),input=inputs.find(x=>x.instructionIndex===e.instructionIndex),nodes=result.dag.nodes;
  if(!input||stores.length!==1||r.valueNode!==stores[0].value)fail();
  const get=(id,op,bits,arity)=>{const n=Number.isSafeInteger(id)&&!Object.is(id,-0)&&id>=0?nodes[id]:null;
    if(!n||n.op!==op||n.type!=='bv'||n.bits!==bits||!Array.isArray(n.args)||n.args.length!==arity||
       op!=='const'&&(statusStep===undefined?Object.hasOwn(n,'statusOverlayStep'):n.statusOverlayStep!==statusStep))fail();return n;};
  const constant=(id,bits,v)=>{const n=get(id,'const',bits,0);if(n.value!=='0x'+v.toString(16))fail();};
  let cursor=r.valueNode;
  for(const f of [...flags].reverse()){
    const join=get(cursor,'INT_OR',64,2),placed=get(join.args[1],'INT_MULT',64,2),wide=get(placed.args[0],'INT_ZEXT',64,1),boolean=get(wide.args[0],'INT_NOTEQUAL',8,2);
    constant(placed.args[1],64,1n<<BigInt(f.bit));constant(boolean.args[1],8,0n);
    const flag=nodes[boolean.args[0]];if(!flag||flag.type!=='bv'||flag.bits!==8)fail();cursor=join.args[0];
  }
  if(flags.length){const and=get(cursor,'INT_AND',64,2);if(and.args[0]!==input.node)fail();constant(and.args[1],64,unknown);}
  else if(cursor!==input.node)fail();
}

/** Rebind every approximation and free value to the complete owned decode. */
export function validateOpaqueProjection(result, {namePrefix='', nodeRange=null,statusStep=undefined}={}) {
  const effects=result.opaqueEffects,inputs=result.nondeterministicInputs,nodes=result.dag?.nodes;
  const status=result.projectionMode==='opaque-status';
  if(!['opaque-effects','opaque-status'].includes(result.projectionMode)||!Array.isArray(effects)||effects.length>128||!Array.isArray(inputs)||
     inputs.length>effects.length||!Array.isArray(nodes)||nodes.length>2048||!Array.isArray(result.path)||
     !Array.isArray(result.decodedPath)||result.path.length!==result.decodedPath.length||result.path.some((r,i)=>r.ea!==result.decodedPath[i]?.ea)||
     ['pathGuard','branchPoints','sideExits'].some(k=>Object.hasOwn(result,k)))fail();
  const definitions=status?statusDefinitions(result):null;
  const seen=new Set();let rawTotal=0,replacedTotal=0;
  for(const e of effects){
    const i=e.instructionIndex,row=result.decodedPath[i];
    if(!Number.isSafeInteger(i)||i<0||seen.has(i)||!row||e.source!==row.ea||e.codeBytes!==row.bytes||
       !Array.isArray(row.decoded?.pcode)||e.rawOperationCount!==row.decoded.pcode.length||
       e.rawPcodeSemanticSha256!==hashBytes(Buffer.from(canonical(row.decoded.pcode)))||
       e.unknownBits!==(status&&e.kind==='unknown-pushed-flag-image'?64-Object.keys(definitions[i]??{}).length:64)||e.conservativeSuperset!==true||e.observedValuesUsed!==false||e.architectureProved!==false||e.flagsPreserved!==true||
       canonical(result.path[i]?.opaqueEffect)!==canonical(e))fail();
    seen.add(i);let count,required,semantic=row.decoded.pcode;
    if(e.kind==='unknown-pushed-flag-image'&&row.bytes==='9c'&&row.decoded.mnemonic==='PUSHFQ'){
      const flags=status?Object.keys(definitions[i]).length:0;count=3+(flags?1+4*flags:0);required=rawPins.push;
      if(Object.hasOwn(e,'flagImageRefinement')!==status)fail();}
    else if(e.kind==='fresh-timestamp64'&&row.bytes==='0f31'&&row.decoded.mnemonic==='RDTSC'){count=5;required=rawPins.tsc;}
    else if(e.kind==='undefined-bswap16-full-gpr'&&/^66(?:4[0-7])?0fc[8-f]$/.test(row.bytes)&&row.decoded.mnemonic==='BSWAP'){
      const code=Buffer.from(row.bytes,'hex'),rex=code.length===4?code[1]:0;
      const number=(code.at(-1)-0xc8)+(rex&1?8:0);
      if(e.destination!==gprs[number])fail();count=1;required=rawPins.bswap;semantic=JSON.parse(JSON.stringify(semantic));
      for(const op of semantic)for(const v of [op.output,...op.inputs])if(v?.space==='register'){
        if(v.offset!=='0x'+offsets[number].toString(16))fail();v.offset='0x0';}
    }else fail();
    if(e.kind!=='unknown-pushed-flag-image'&&Object.hasOwn(e,'flagImageRefinement'))fail();
    if(e.replacementOperationCount!==count||hashBytes(Buffer.from(canonical(semantic)))!==required)fail();rawTotal+=e.rawOperationCount;replacedTotal+=count;
    if(e.kind==='unknown-pushed-flag-image'&&e.rawStorePcodeIndex!==56)fail();
  }
  if(result.path.some((r,i)=>Object.hasOwn(r,'opaqueEffect')!==seen.has(i)))fail();
  if(result.decodedPath.some((r,i)=>(r.bytes==='9c'||r.bytes==='0f31'||/^66(?:4[0-7])?0fc[8-f]$/.test(r.bytes))&&!seen.has(i)))fail();
  for(const e of effects)if(e.kind==='unknown-pushed-flag-image'){
    const stores=result.stores?.filter(s=>s.instructionIndex===e.instructionIndex);
    if(stores?.length!==1||stores[0].pcodeIndex!==56||stores[0].replacementPcodeIndex!==e.replacementOperationCount-1||stores[0].size!==8)fail();
  }
  const inputNodes=new Set();
  for(const x of inputs){
    const e=effects.find(e=>e.instructionIndex===x.instructionIndex),n=nodes[x.node];
    if(!e||inputNodes.has(x.node)||!Number.isSafeInteger(x.node)||x.node<0||!n||n.op!=='nondeterministic'||n.type!=='bv'||n.bits!==64||
       n.args?.length!==0||n.name!==namePrefix+'opaque_'+x.instructionIndex||n.kind!==e.kind||n.source!==e.source||
       x.bits!==64||x.kind!==e.kind||x.source!==e.source)fail();inputNodes.add(x.node);
  }
  if(nodes.some((n,i)=>(!nodeRange || (i>=nodeRange[0]&&i<nodeRange[1]))&&n.op==='nondeterministic'&&!inputNodes.has(i)))fail();
  if(status)for(const e of effects)if(e.kind==='unknown-pushed-flag-image')statusImage(result,e,definitions[e.instructionIndex],inputs,statusStep);
  const s=result.statistics,m=result.memoryNormalization;
  if(!s||s.abstractedInstructions!==effects.length||s.abstractedRawOperations!==rawTotal||s.replacementOperations!==replacedTotal||
     s.pcodeOperations!==result.decodedPath.reduce((sum,r)=>sum+(r.decoded?.pcode?.length??Infinity),0)||
     !m||m.method!=='exact-ordered-byte-forwarding'||m.maxStoreVisits!==4096||!Number.isSafeInteger(m.storeVisits)||m.storeVisits<0||m.storeVisits>4096||
     m.observedValuesUsed!==false||m.independentSMTProof!==false)fail();
}
