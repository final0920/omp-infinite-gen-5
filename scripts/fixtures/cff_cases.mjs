import {randomUUID,createHash} from 'node:crypto';
import fs from 'node:fs';
import {captureDossier} from '../../source/investigation_workflow.js';
import {researchScopeDigest} from '../../source/research_state.js';
import {providerProjection} from './provider_cases.mjs';

export function graph(edges,ids=[0,1,2,3]){
 return {total_blocks:ids.length,total_edges:edges.length,blocks:ids.map(id=>({id,start:'0x'+(0x1000+id*0x10).toString(16),end:'0x'+(0x1010+id*0x10).toString(16),succs:edges.filter(e=>e[0]===id).map(e=>e[1]),preds:edges.filter(e=>e[1]===id).map(e=>e[0]),first:'STORE CALL volatile <script>never execute</script>',last:'opaque'})),edges:edges.map(([from,to])=>({from,to}))};
}
export const CFG_CASES=Object.freeze([
 {id:'dispatcher-shaped',graph:graph([[0,1],[0,2],[1,0],[2,0],[2,3]]),compatible:true},
 {id:'ordinary-switch',graph:graph([[0,1],[0,2],[1,3],[2,3]]),compatible:false},
 {id:'protocol-state-machine',graph:graph([[0,1],[0,2],[1,0],[2,0],[2,3]]),compatible:true},
 {id:'interpreter',graph:graph([[0,1],[0,2],[1,0],[2,0],[2,3]]),compatible:true},
 {id:'competing-dispatchers',graph:graph([[0,1],[0,2],[1,0],[1,2],[2,0],[2,1],[2,3]]),compatible:true},
]);
export function dossier(context,g,options={}){
 return {schemaVersion:1,kind:'function-dossier',provenance:{...context},_ig5:{...context},snapshotDigest:createHash('sha256').update(randomUUID()).digest('hex'),function:{ea:'0x1000',name:'Owned synthetic CFF fixture'},analysis:{complete:true,partial:false},responseTruncated:false,
  sections:{cfg:{status:'ok',completeness:{provider:'complete',stored:'complete',response:'complete'},data:structuredClone(g)}},...options};
}
export function captureCff(f,g=CFG_CASES[0].graph,options={}){
 const d=dossier(f.context,g,options),captured=captureDossier(f.mgr,f.cfg,d,f.task.taskId,f.execution);
 if(!captured.ok)throw new Error(JSON.stringify(captured));
 const task=f.notes.get(f.context,f.task.taskId),state=f.research.get(task,f.context);
 f.research.mutate(task,f.context,{operation:'acknowledge-context',expected_task_revision:task.taskRevision,expected_research_revision:state.researchRevision,scope_digest:researchScopeDigest(f.context)},'f09-fixture');
 return {d,captured};
}
/** Exact synthetic IR fixture. Actual solver evidence is separate from source/native correspondence. */
export function saveCondition(f,{wrongRoot=false,source='0x1000'}={}){
 const ast={nodes:[{id:0,op:'var',bits:8,args:[],name:'ssa_0'},{id:1,op:'sub',bits:8,args:[0,0]}],root:1};
 const result=providerProjection(ast,f.context.sha256),nodes=result.dag.nodes;
 const taken=nodes.length;nodes.push({id:taken,op:'const',type:'bv',bits:64,args:[],value:'0x1010'});
 const fallthrough=nodes.length;nodes.push({id:fallthrough,op:'const',type:'bv',bits:64,args:[],value:'0x1020'});
 result.control={kind:'conditional',condition:wrongRoot?0:1,taken,fallthrough,source,conditionRule:'nonzero-is-taken'};
 result.dag.references+=2;
 const input=f.lifter.artifacts.put(fs.readFileSync(f.context.target)),outputRef=f.lifter.artifacts.put(Buffer.from(JSON.stringify(result)));
 const record=f.lifter.artifacts.save({kind:'projection',action:'project',target:f.context.target,input,outputRef,process:{childExitConfirmed:true,fixture:true,scope:'SYNTHETIC IR ONLY; no native decoder'},result},{maxBytes:4*1024**2});
 return {id:record.id,sha256:f.lifter.artifacts.metadata(record.id).result.recordSha256};
}
