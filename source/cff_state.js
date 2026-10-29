import {planningDigest} from './planning_identity.js';

export const CFF_STATE_VERSION='20261024-cff-crossblock-1';
const BOTTOM=Symbol('bottom'),TOP=Symbol('unknown'),known=x=>typeof x==='bigint';
const effects=new Set(['LOAD','STORE','CALL','CALLIND','CALLOTHER','INDIRECT','BRANCHIND','RETURN']);
const fail=message=>{throw Object.assign(new Error(message),{code:'UNSUPPORTED_CFF_STATE'});};
const int=(n,max)=>Number.isSafeInteger(n)&&!Object.is(n,-0)&&n>=0&&n<=max;
const width=n=>n&&int(n.size,8)&&n.size>0?n.size*8:null;
const key=n=>n&&n.kind!=='constant'&&int(n.id,0x7fffffff)&&width(n)&&typeof n.space==='string'?`${n.id}:${n.space}:${n.size}`:null;
const literal=n=>n?.kind==='constant'&&width(n)&&n.valueComplete!==false&&!n.offsetOnly&&typeof n.value==='string'&&/^0x[0-9a-f]{1,16}$/.test(n.value)&&BigInt(n.value)<(1n<<BigInt(width(n)))?BigInt(n.value):TOP;
const meet=(a,b)=>a===BOTTOM?b:b===BOTTOM?a:a===b?a:TOP;
const signed=(v,b)=>BigInt.asIntN(b,v);

/** Independent JS recomputation of a committed native SSA observation. No Python imports/solver/eval. */
export function analyzeCffState(report,sourceRef){
 if(!report||report.representation!=='Ghidra p-code'||!Array.isArray(report.blocks)||!Array.isArray(report.edges)||report.blocks.length>128||report.edges.length>512)fail('Bounded native HighFunction graph required (128 blocks/512 edges)');
 const blocks=new Map(),defs=new Map(),identities=new Map(),locations=new Map(),nodeRows=new Map();let operations=0,steps=0,exhausted=false;
 const tick=()=>{if(steps>=100000){exhausted=true;return false;}steps++;return true;};
 const admissionTick=()=>{if(!tick())throw Object.assign(new Error('CFF state admission work budget exhausted; original retained'),{code:'CFF_STATE_LIMIT'});};
 for(const block of report.blocks){
  if(!int(block.id,65535)||blocks.has(block.id)||!Array.isArray(block.instructions)||!Array.isArray(block.preds)||!Array.isArray(block.succs))fail('Invalid native block identity');
  if(block.preds.some(n=>!int(n,65535))||block.succs.some(n=>!int(n,65535))||new Set(block.preds).size!==block.preds.length||new Set(block.succs).size!==block.succs.length)fail('Invalid ordered adjacency');
  blocks.set(block.id,block);let ordinary=false;
  for(let i=0;i<block.instructions.length;i++){
   admissionTick();
   if(++operations>2048)fail('At most 2048 source operations');const op=block.instructions[i];
   if(!op||op.index!==i||typeof op.mnemonic!=='string'||!Array.isArray(op.inputs)||op.inputs.length>128||!op.inputsTruncated&&op.totalInputs!==op.inputs.length)fail('Invalid native operation');
   if(op.mnemonic==='MULTIEQUAL'){if(ordinary)fail('Phi must precede ordinary operations');if(op.inputs.length!==block.preds.length)fail('Phi inputs must match the exact native predecessor order');}else ordinary=true;
   for(const n of [...op.inputs,op.output])if(n){
    admissionTick();
    if(!width(n)||!['constant','register','unique','memory','stack'].includes(n.kind)||typeof n.space!=='string'||n.space.length>128)fail('Unsupported native operand width/kind');
    if(n.kind==='constant'){if(!known(literal(n)))fail('Incomplete constant');continue;}
    const k=key(n);if(!k)fail('Stable SSA identity required');
    const identity=planningDigest({id:n.id,space:n.space,size:n.size,offset:n.offset,kind:n.kind});
    if(identities.has(n.id)&&identities.get(n.id)!==identity)fail('SSA identity has conflicting type/address');identities.set(n.id,identity);nodeRows.set(k,n);
   }
   const k=key(op.output);if(op.output&&!k)fail('Operation output must have a unique SSA identity');if(op.mnemonic==='MULTIEQUAL'&&!k)fail('Phi output required');if(k){if(defs.has(k))fail('Duplicate SSA definition');defs.set(k,op);locations.set(k,{block:block.id,index:i});}
  }
 }
 if(!blocks.has(report.entryBlock))fail('Native entry block missing');
 const edgeKeys=new Set();let graphComplete=report.scopeComplete===true&&report.partial===false&&report.truncated===false&&report.total_blocks===blocks.size;
 for(const e of report.edges){if(!e||!int(e.from,65535)||!int(e.to,65535)||edgeKeys.has(`${e.from}:${e.to}`))fail('Invalid or duplicate native edge');edgeKeys.add(`${e.from}:${e.to}`);if(!blocks.has(e.from)||!blocks.has(e.to))graphComplete=false;}
 for(const b of blocks.values()){
  if(b.truncated||b.edgesTruncated||b.omittedPreds?.length||b.omittedSuccs?.length||b.uninspectedPreds||b.uninspectedSuccs||b.totalPreds!==b.preds.length||b.totalSuccs!==b.succs.length)graphComplete=false;
  for(const n of b.preds)if(!edgeKeys.has(`${n}:${b.id}`)||!blocks.get(n)?.succs.includes(b.id))fail('Native predecessor disagreement');
  for(const n of b.succs)if(!edgeKeys.has(`${b.id}:${n}`)||!blocks.get(n)?.preds.includes(b.id))fail('Native successor disagreement');
  if(b.instructions.some(op=>op.inputsTruncated||op.outputOmitted))graphComplete=false;
 }
 if([...edgeKeys].some(e=>{const [a,b]=e.split(':').map(Number);return !blocks.get(a)?.succs.includes(b)||!blocks.get(b)?.preds.includes(a);}))fail('Native edge/adjacency disagreement');
 // Def-use dominance is checked before folding. PHI inputs belong to incoming edges.
 const reachable=new Set([report.entryBlock]),queue=[report.entryBlock];for(let i=0;i<queue.length;i++)for(const n of blocks.get(queue[i]).succs)if(blocks.has(n)&&!reachable.has(n)){reachable.add(n);queue.push(n);}
 const dom=new Map([...reachable].map(id=>[id,id===report.entryBlock?new Set([id]):new Set(reachable)]));let changed=true;
 for(let round=0;changed&&round<128;round++){changed=false;for(const id of reachable){admissionTick();if(id===report.entryBlock)continue;const preds=blocks.get(id).preds.filter(p=>reachable.has(p));let next=preds.length?new Set(dom.get(preds[0])):new Set();for(const p of preds.slice(1))next=new Set([...next].filter(n=>{admissionTick();return dom.get(p).has(n);}));next.add(id);if(next.size!==dom.get(id).size||[...next].some(n=>!dom.get(id).has(n))){dom.set(id,next);changed=true;}}}
 if(changed)fail('Dominance did not converge');
 for(const b of blocks.values())if(reachable.has(b.id))for(const op of b.instructions)op.inputs.forEach((n,i)=>{
  admissionTick();
  const loc=locations.get(key(n));if(!loc)return;const use=op.mnemonic==='MULTIEQUAL'?b.preds[i]:b.id;
  if(!reachable.has(use))return;
  if(!dom.get(use)?.has(loc.block)||op.mnemonic!=='MULTIEQUAL'&&loc.block===b.id&&loc.index>=op.index)fail('SSA use is not dominated by its definition');
 });
 const values=new Map(),liveEdges=new Set(),liveBlocks=new Set([report.entryBlock]);
 const read=(n,override)=>n?.kind==='constant'?literal(n):override?.has(key(n))?override.get(key(n)):values.get(key(n))??(defs.has(key(n))?BOTTOM:TOP);
 function evaluate(op,override){
  if(!tick()||!width(op.output)||effects.has(op.mnemonic)||op.inputsTruncated||op.outputOmitted)return TOP;
  const args=op.inputs,ws=args.map(width),bits=width(op.output),code=op.mnemonic,v=args.map(n=>read(n,override)),mask=(1n<<BigInt(bits))-1n;
  const same=args.length===2&&key(args[0])&&key(args[0])===key(args[1])&&['register','unique'].includes(args[0].kind);
  if(same&&ws[0]===bits&&['INT_XOR','INT_SUB'].includes(code))return 0n;
  if(v.some(x=>x===TOP))return TOP;if(v.some(x=>x===BOTTOM))return BOTTOM;
  let x=v[0],y=v[1],answer;
  if(code==='COPY'&&args.length===1&&ws[0]===bits)answer=x;
  else if(['INT_ZEXT','INT_SEXT'].includes(code)&&args.length===1&&ws[0]<bits)answer=code==='INT_SEXT'?signed(x,ws[0]):x;
  else if(code==='SUBPIECE'&&args.length===2&&y*8n+BigInt(bits)<=BigInt(ws[0]))answer=x>>(y*8n);
  else if(code==='PIECE'&&args.length===2&&ws[0]+ws[1]===bits)answer=(x<<BigInt(ws[1]))|y;
  else if(['INT_NEGATE','INT_2COMP'].includes(code)&&args.length===1&&ws[0]===bits)answer=code==='INT_NEGATE'?~x:-x;
  else if(['BOOL_NEGATE','BOOL_AND','BOOL_OR','BOOL_XOR'].includes(code)&&bits===8&&ws.every(w=>w===8)&&args.length===(code==='BOOL_NEGATE'?1:2))answer=BigInt(code==='BOOL_NEGATE'?x===0n:code==='BOOL_AND'?x!==0n&&y!==0n:code==='BOOL_OR'?x!==0n||y!==0n:(x!==0n)!==(y!==0n));
  else if(args.length===2&&ws[0]===ws[1]&&['INT_EQUAL','INT_NOTEQUAL','INT_LESS','INT_LESSEQUAL','INT_SLESS','INT_SLESSEQUAL'].includes(code)&&bits===8)answer=BigInt(code==='INT_EQUAL'?x===y:code==='INT_NOTEQUAL'?x!==y:code==='INT_LESS'?x<y:code==='INT_LESSEQUAL'?x<=y:code==='INT_SLESS'?signed(x,ws[0])<signed(y,ws[1]):signed(x,ws[0])<=signed(y,ws[1]));
  else if(args.length===2&&ws[0]===bits&&['INT_LEFT','INT_RIGHT','INT_SRIGHT'].includes(code)&&y<BigInt(bits))answer=code==='INT_LEFT'?x<<y:code==='INT_RIGHT'?x>>y:signed(x,bits)>>y;
  else if(args.length===2&&ws.every(w=>w===bits)){
   if(code==='INT_ADD')answer=x+y;else if(code==='INT_SUB')answer=x-y;else if(code==='INT_MULT')answer=x*y;else if(code==='INT_AND')answer=x&y;else if(code==='INT_OR')answer=x|y;else if(code==='INT_XOR')answer=x^y;
  }
  return answer===undefined?TOP:answer&mask;
 }
 function phi(b,op,override,predecessor){let answer=BOTTOM;if(op.inputsTruncated)return TOP;for(let i=0;i<b.preds.length;i++)if(liveEdges.has(`${b.preds[i]}:${b.id}`)&&(predecessor===undefined||predecessor===b.preds[i])){if(width(op.inputs[i])!==width(op.output))return TOP;answer=meet(answer,read(op.inputs[i],override));}return answer;}
 function successors(b,override){const end=b.instructions.at(-1);if(end?.mnemonic!=='CBRANCH')return {next:b.succs,decision:null};if(end.inputs.length!==2||end.inputsTruncated||b.succs.length!==2||!b.succs.includes(b.trueSuccessor)||!b.succs.includes(b.falseSuccessor)||b.trueSuccessor===b.falseSuccessor)return {next:b.succs,decision:null};const value=read(end.inputs[1],override);if(value===BOTTOM)return {next:[],decision:null};if(!known(value))return {next:b.succs,decision:null};return {next:[value!==0n?b.trueSuccessor:b.falseSuccessor],decision:{block:b.id,instruction:end.index,condition:'0x'+value.toString(16),destination:value!==0n?b.trueSuccessor:b.falseSuccessor}};}
 changed=true;while(changed&&!exhausted){changed=false;for(const b of blocks.values())if(liveBlocks.has(b.id)){
  for(const op of b.instructions){const k=key(op.output);if(!k)continue;const next=meet(values.get(k)??BOTTOM,op.mnemonic==='MULTIEQUAL'?phi(b,op):evaluate(op));if(next!==values.get(k)){values.set(k,next);changed=true;}if(exhausted)break;}
  for(const n of successors(b).next)if(blocks.has(n)&&!liveEdges.has(`${b.id}:${n}`)){liveEdges.add(`${b.id}:${n}`);liveBlocks.add(n);changed=true;}
 }if(!changed)for(const [k]of defs)if(liveBlocks.has(locations.get(k).block)&&(values.get(k)??BOTTOM)===BOTTOM){values.set(k,TOP);changed=true;}if(!tick())break;}
 const python=report.deobfuscation,independentCandidate=python?.algorithm==='sccp-bitvector-v1'&&python.partial===false&&python.budget?.exhausted===false;
 const candidates=[],routes=[],unknown=[],dependencyEdges=[];let dependencyEdgesTruncated=false;
 function closure(root){const seen=new Set(),todo=[key(root)],rows=[];let cut=false;while(todo.length){if(!tick()){cut=true;break;}const k=todo.pop();if(!k||seen.has(k))continue;if(seen.size>=128){cut=true;break;}seen.add(k);const op=defs.get(k),loc=locations.get(k);rows.push({ssa:nodeRows.get(k)?.id,space:nodeRows.get(k)?.space,width:width(nodeRows.get(k)),definition:loc||null,opcode:op?.mnemonic||'free-input',value:known(values.get(k))?'0x'+values.get(k).toString(16):'unknown',unknownEffect:!!op&&effects.has(op.mnemonic)});if(op)for(let i=0;i<op.inputs.length;i++){if(!tick()){cut=true;break;}const parent=key(op.inputs[i]);if(parent){if(dependencyEdges.length<4096)dependencyEdges.push({from:nodeRows.get(k).id,to:op.inputs[i].id,definitionBlock:loc.block,phiPredecessor:op.mnemonic==='MULTIEQUAL'?blocks.get(loc.block).preds[i]:null});else{dependencyEdgesTruncated=true;cut=true;}todo.push(parent);}}}return {definitions:rows,truncated:cut};}
 let totalCandidates=0;
 for(const b of blocks.values())for(const op of b.instructions)if(op.mnemonic==='MULTIEQUAL'){
  totalCandidates++;if(candidates.length>=8)continue;const k=key(op.output),users=[...blocks.values()].flatMap(block=>block.instructions.filter(o=>o.mnemonic==='CBRANCH').map(o=>({block:block.id,root:o.inputs[1]}))).filter(o=>{const seen=new Set(),todo=[key(o.root)];while(todo.length){if(!tick())return false;const cur=todo.pop();if(cur===k)return true;if(!cur||seen.has(cur)||seen.size>=128)continue;seen.add(cur);for(const n of defs.get(cur)?.inputs||[]){if(!tick())return false;todo.push(key(n));}}return false;});
  candidates.push({block:b.id,ssa:op.output.id,width:width(op.output),stateRole:'candidate',classification:'unknown',competingInterpretations:['ordinary-switch','protocol-state-machine','interpreter','flattening-state'],conditionUsers:users.map(u=>u.block),incoming:op.inputs.map((n,i)=>({predecessor:b.preds[i],sourceSSA:n.kind==='constant'?null:n.id,constant:known(literal(n))?'0x'+literal(n).toString(16):null})),dependencies:closure(op.output)});
 }
 for(const b of blocks.values())if(b.instructions.some(op=>op.mnemonic==='MULTIEQUAL'))for(const pred of b.preds){
  if(routes.length>=64){unknown.push({kind:'route-output-limit',status:'unknown'});break;}if(!liveEdges.has(`${pred}:${b.id}`))continue;
  let current=b.id,previous=pred,override=new Map(),path=[],assignments=[],visited=new Set(),stopped='non-dispatcher-boundary';
  for(let count=0;count<16;count++){
   if(visited.has(current)){stopped='cycle-boundary';break;}visited.add(current);const block=blocks.get(current);
   if(!block||block.instructions.at(-1)?.mnemonic!=='CBRANCH')break;
   if(block.instructions.some(op=>effects.has(op.mnemonic))){stopped='unknown-effect-boundary';break;}
   const incoming=new Map(override);for(const op of block.instructions){const k=key(op.output);if(!k)continue;const value=op.mnemonic==='MULTIEQUAL'?phi(block,op,incoming,previous):evaluate(op,override);override.set(k,value);if(op.mnemonic==='MULTIEQUAL'&&known(value)&&assignments.length<8)assignments.push({ssa:op.output.id,width:width(op.output),value:'0x'+value.toString(16)});}
   const next=successors(block,override);if(!next.decision){stopped='unknown-condition';break;}path.push({block:current,destination:next.next[0],condition:next.decision.condition});previous=current;current=next.next[0];if(count===15)stopped='path-limit';
  }
  if(!path.length){unknown.push({kind:stopped,dispatcher:b.id,predecessor:pred,status:'unknown'});continue;}
  const candidate=python?.dispatcherRoutes?.find(r=>r.predecessor===pred&&r.dispatcher===b.id&&r.destination===current&&planningDigest(r.path)===planningDigest(path)&&planningDigest(r.stateEvidence)===planningDigest(assignments)&&!r.pathTruncated&&!r.stateEvidenceTruncated);
  const accepted=graphComplete&&!exhausted&&independentCandidate&&!!candidate&&stopped!=='path-limit';
  routes.push({predecessor:pred,dispatcher:b.id,destination:current,path,stateEvidence:assignments,status:accepted?'verified-in-scope':'candidate',scope:'native-SSA-incoming-edge-conditioned-route-only',condition:`execution has just traversed original edge ${pred}->${b.id}`,boundary:stopped,sourceRef,receipt:{version:CFF_STATE_VERSION,sourceGraphDigest:planningDigest(report.blocks),pathDigest:planningDigest(path),independentJSRecomputed:true,pythonCandidateMatched:!!candidate,fixpointFinished:!exhausted,originalEdges:path.map(p=>({from:p.block,to:p.destination}))},otherEdgesRemoved:false,nativeCorrespondenceProved:false});
 }
 for(const b of blocks.values())for(const op of b.instructions)if(effects.has(op.mnemonic))unknown.push({kind:'retained-effect',block:b.id,instruction:op.index,opcode:op.mnemonic,status:'unknown'});
 if(!graphComplete)unknown.push({kind:'partial-native-graph',status:'unknown'});if(exhausted)unknown.push({kind:'work-budget-exhausted',status:'unknown'});
 if(!graphComplete||exhausted)for(const r of routes)r.status='candidate';
 return {schema:'ig5-cff-crossblock-model-v1',version:CFF_STATE_VERSION,sourceRef,originalGraph:{entryBlock:report.entryBlock,blocks:report.blocks,edges:report.edges,total_blocks:report.total_blocks},originalGraphDigest:planningDigest(report.blocks),providerGraphComplete:graphComplete,dispatcherCandidates:candidates,stateDependencies:{status:'typed-native-SSA-backward-dependencies',competingVariables:candidates,selectedVariable:null,dependencyEdges,dependencyEdgesTruncated,omittedCandidates:Math.max(0,totalCandidates-8)},overlay:{originalEdges:report.edges.map(e=>({...e,status:'observed'})),localRelations:[],conditionRelations:[],stateRelations:routes,unknownExits:unknown},budget:{steps,maxSteps:100000,exhausted},independentCandidateAvailable:independentCandidate,retainedEffects:{allOriginalBlocks:true,allOriginalEdges:true,stateWritesRemoved:0,storesCallsVolatileExceptions:'retained-with-unknown-semantics'},wholeFunctionRecovered:false,cffProved:false,nativeTargetExecuted:false,databaseModified:false,businessAccepted:false,assistEnabled:false};
}
