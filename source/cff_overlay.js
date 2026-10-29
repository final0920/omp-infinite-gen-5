import {planningDigest} from './planning_identity.js';

export const CFF_VERSION='20261024-cff-overlay-1';
const fail=message=>{throw Object.assign(new Error(message),{code:'UNSUPPORTED_CFF_CFG'});};
const id=n=>Number.isSafeInteger(n)&&n>=0&&n<=65535;
const address=s=>typeof s==='string'&&/^0x[0-9a-f]{1,16}$/.test(s);

/** Topology only. No disassembly/decompiler text is interpreted as instructions or state writes. */
export function buildCffOverlay(dossier,sourceRef){
 const section=dossier.sections?.cfg,g=section?.data;
 if(!g||!Array.isArray(g.blocks)||!Array.isArray(g.edges)||g.blocks.length>128||g.edges.length>512)fail('CFG requires at most 128 blocks and 512 edges; original evidence remains available');
 const blocks=new Map(),out=new Map(),incoming=new Map(),unknown=[];
 for(const b of g.blocks){
  if(!b||!id(b.id)||blocks.has(b.id)||!address(b.start)||!address(b.end)||BigInt(b.start)>=BigInt(b.end))fail('CFG block identity/range is invalid or duplicated');
  blocks.set(b.id,b);out.set(b.id,[]);incoming.set(b.id,[]);
 }
 const ordered=[...blocks.values()].sort((a,b)=>BigInt(a.start)<BigInt(b.start)?-1:1);
 for(let i=1;i<ordered.length;i++)if(BigInt(ordered[i].start)<BigInt(ordered[i-1].end))fail('Overlapping CFG blocks cannot bind local conditions');
 const keys=new Set();
 for(let i=0;i<g.edges.length;i++){
  const e=g.edges[i];if(!e||!id(e.from)||!id(e.to)||keys.has(`${e.from}:${e.to}`))fail('Invalid or duplicate CFG edge');
  keys.add(`${e.from}:${e.to}`);
  if(!blocks.has(e.from)||!blocks.has(e.to))unknown.push({kind:'missing-endpoint',edgeIndex:i,from:e.from,to:e.to,status:'unknown'});
  if(blocks.has(e.from))out.get(e.from).push(e.to);
  if(blocks.has(e.to))incoming.get(e.to).push(e.from);
 }
 let adjacencyKnown=true;
 for(const b of blocks.values())for(const [field,expected] of [['succs',out.get(b.id)],['preds',incoming.get(b.id)]]){
  if(!Array.isArray(b[field])){adjacencyKnown=false;continue;}
  if(b[field].some(x=>!id(x))||new Set(b[field]).size!==b[field].length)fail('Invalid CFG adjacency');
  if(planningDigest([...b[field]].sort((a,c)=>a-c))!==planningDigest([...expected].sort((a,c)=>a-c)))unknown.push({kind:'adjacency-disagreement',block:b.id,field,status:'unknown'});
 }
 const countsKnown=Number.isSafeInteger(g.total_blocks)&&Number.isSafeInteger(g.total_edges);
 const complete=section.status==='ok'&&section.completeness?.provider==='complete'&&section.completeness?.response==='complete'&&!dossier.responseTruncated&&countsKnown&&g.total_blocks===g.blocks.length&&g.total_edges===g.edges.length&&adjacencyKnown&&!unknown.length;
 // Even a complete provider topology says nothing about exception/indirect edges omitted by its model.
 unknown.push({kind:'provider-unmodelled-control-and-exceptions',status:'unknown',target:null});
 if(!complete)unknown.push({kind:'partial-or-unattested-cfg',status:'unknown',target:null});
 function reaches(start,target){const seen=new Set(),queue=[start];for(let n=0;n<queue.length;n++){const current=queue[n];if(current===target)return true;if(seen.has(current))continue;seen.add(current);for(const next of out.get(current)||[])if(!seen.has(next))queue.push(next);}return false;}
 const compared=[];
 for(const b of blocks.values())if(out.get(b.id).length>=2){
  const successors=out.get(b.id),returning=successors.filter(n=>reaches(n,b.id));
  compared.push({block:b.id,status:'candidate',fanout:successors.length,incoming:incoming.get(b.id).length,returningBranches:returning,
   topologyCompatibleWithDispatcher:returning.length>=2&&incoming.get(b.id).length>=2,
   alternatives:['ordinary-switch','protocol-state-machine','interpreter','flattening-dispatcher'],
   classification:'unknown',stateVariableSelection:'unknown',semanticEvidenceRequired:true});
 }
 compared.sort((a,b)=>Number(b.topologyCompatibleWithDispatcher)-Number(a.topologyCompatibleWithDispatcher)||b.returningBranches.length-a.returningBranches.length||b.fanout-a.fanout||a.block-b.block);
 const candidates=compared.slice(0,8),transitions=[];
 // A path witness is a checkable relation in the reported graph, never a feasible state transition.
 for(const d of candidates)for(const next of out.get(d.block)){
  if(transitions.length>=64)break;
  const path=[d.block,next],seen=new Set([d.block]);let current=next;
  while(blocks.has(current)&&!seen.has(current)&&out.get(current).length===1&&path.length<=128){seen.add(current);current=out.get(current)[0];path.push(current);}
  const valid=complete&&path.every((n,i)=>!i||keys.has(`${path[i-1]}:${n}`))&&path.every(n=>blocks.has(n));
  transitions.push({from:d.block,to:current,path,status:valid?'verified-in-scope':'candidate',
   condition:'interior blocks have exactly one reported successor',scope:'reported-CFG-topology-only',
   conditionFeasibility:'unknown',sourceRef,originalBlocks:[...new Set(path)],
   receipt:{version:CFF_VERSION,graphDigest:planningDigest(g),pathDigest:planningDigest(path),singleSuccessorInterior:path.slice(1,-1).every(n=>out.get(n)?.length===1)}});
 }
 return {schema:'ig5-cff-overlay-v1',version:CFF_VERSION,sourceRef,function:dossier.function,
  originalGraph:structuredClone(g),originalGraphDigest:planningDigest(g),providerGraphComplete:complete,
  graphCompleteness:'provider-topology-only',dispatcherCandidates:candidates,omittedDispatcherCandidates:Math.max(0,compared.length-8),
  stateDependencies:{status:'unknown',reason:'CFG has no typed SSA read/write adapter; text is not semantic evidence',competingVariables:[],selectedVariable:null},
  overlay:{originalEdges:g.edges.map((e,index)=>({...e,index,status:blocks.has(e.from)&&blocks.has(e.to)?'observed':'unknown',assurance:'provider-reported-CFG-edge'})),localRelations:transitions,conditionRelations:[],unknownExits:unknown},
  retainedEffects:{allOriginalBlocks:true,allOriginalEdges:true,stateWritesRemoved:0,storesCallsVolatileExceptions:'preserved-with-unknown-semantics'},
  wholeFunctionRecovered:false,cffProved:false,nativeTargetExecuted:false,databaseModified:false,businessAccepted:false,assistEnabled:false};
}

/** Bind an independently checked constant predicate to the exact original terminal conditional. */
export function bindCffCondition(overlay,projection,contract,verification,receiptRef){
 const c=projection.control,nodes=projection.dag?.nodes;
 if(contract.premiseOrigin!=='unconditional-true'||verification.status!=='pass'||verification.replay?.equivalentInIR!==true||c?.kind!=='conditional'||c.conditionRule!=='nonzero-is-taken'||c.condition!==contract.sourceRoot)fail('Only an unconditional current F07 pass on the exact terminal condition is supported');
 const candidate=verification.candidate,root=candidate?.nodes?.[candidate.root];
 if(candidate?.nodes?.length!==1||root?.op!=='const')fail('Condition receipt must prove one exact constant');
 const from=overlay.originalGraph.blocks.find(b=>address(c.source)&&BigInt(b.start)<=BigInt(c.source)&&BigInt(c.source)<BigInt(b.end));
 const last=projection.projectionPath?.at(-1),first=projection.projectionPath?.[0];
 if(!from||first!==from.start||last!==c.source||projection.projectionPath.some(ea=>!address(ea)||BigInt(ea)<BigInt(from.start)||BigInt(ea)>=BigInt(from.end)))fail('Predicate projection must stay within one original block from its exact start');
 const chosen=BigInt(root.value)===0n?'fallthrough':'taken',target=nodes?.[c[chosen]];
 if(target?.op!=='const'||!address(target.value))fail('Conditional successor must be a preferred-address constant');
 const to=overlay.originalGraph.blocks.find(b=>BigInt(b.start)===BigInt(target.value));
 if(!to||!overlay.overlay.originalEdges.some(e=>e.from===from.id&&e.to===to.id))fail('Proved IR successor is not an original CFG edge');
 const relation={from:from.id,to:to.id,status:'verified-in-scope',scope:'selected-pure-BV-terminal-condition-only',condition:{source:contract.sourceRef,root:contract.sourceRoot,digest:contract.originalDigest,constant:root.value,premiseDigest:contract.premiseDigest},
  receipt:receiptRef,originalBlocks:[from.id,to.id],nativeCorrespondence:'not-proved',otherEdgesRemoved:false};
 overlay.overlay.conditionRelations.push(relation);
 overlay.stateDependencies={status:'observed-pure-expression-dependencies',sourceRef:contract.sourceRef,root:contract.sourceRoot,
  competingVariables:contract.variables.map(v=>({...v,status:'candidate',stateRole:'unknown',writes:'unknown'})),selectedVariable:null,globalStateRelations:'unknown'};
 return relation;
}
