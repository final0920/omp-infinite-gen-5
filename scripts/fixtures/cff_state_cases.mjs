import fs from 'node:fs';import path from 'node:path';import {spawnSync} from 'node:child_process';import assert from 'node:assert/strict';
export const ssa=(id,size=1)=>({id,size,space:'unique',offset:'0x'+(id*16).toString(16),kind:'unique'});
export const constant=(value,size=1)=>({size,space:'const',kind:'constant',value:'0x'+BigInt(value).toString(16),valueComplete:true});
const operation=(mnemonic,output,...inputs)=>({mnemonic,output,inputs,totalInputs:inputs.length,inputsTruncated:false,outputOmitted:false,ea:'0x1000',text:mnemonic,sequence:{time:0,order:0}});
const block=(id,ops,preds,succs,t=null,f=null)=>({id,start:'0x'+(0x1000+16*id).toString(16),end:'0x'+(0x100f+16*id).toString(16),endInclusive:true,instructions:ops.map((o,index)=>({...o,index,ea:'0x'+(0x1000+16*id+index).toString(16)})),preds,succs,totalPreds:preds.length,totalSuccs:succs.length,omittedPreds:[],omittedSuccs:[],uninspectedPreds:0,uninspectedSuccs:0,truncated:false,edgesTruncated:false,trueSuccessor:t,falseSuccessor:f});
const branch=c=>operation('CBRANCH',null,constant(0x1020,8),c);
export function stateGraph({unknown=false,sideEffectInDispatcher=false,loop=false,ordinarySwitch=false}={}){
 const state=ssa(1),other=ssa(2),condition=ssa(3),condition2=ssa(4),increment=ssa(5),unknownValue=ssa(9);
 const initial=ssa(10),next=ssa(11),last=ssa(12);
 const phis=[operation('MULTIEQUAL',state,initial,loop?increment:next,unknown?unknownValue:last),operation('MULTIEQUAL',other,constant(7),constant(8),constant(9))];
 const blocks=[block(0,[operation('COPY',initial,constant(1))],[],[1]),block(1,[...phis,...(sideEffectInDispatcher?[operation('STORE',null,constant(0),constant(0x2000,8),constant(5))]:[]),operation('INT_EQUAL',condition,state,constant(1)),branch(condition)],[0,2,3],[2,4],2,4),
  block(2,[...(loop?[operation('INT_ADD',increment,state,constant(1))]:[operation('COPY',next,constant(2))]),operation('STORE',null,constant(0),constant(0x2000,8),constant(5))],[1],[1]),
  block(3,[...(unknown?[operation('CALL',unknownValue,constant(0x9000,8))]:[operation('COPY',last,constant(3))])],[4],[1]),
  block(4,[operation('INT_EQUAL',condition2,state,constant(2)),branch(condition2)],[1],[3,5],3,5),block(5,[operation('RETURN',null,constant(0))],[4],[])];
 if(ordinarySwitch){blocks[1].instructions=blocks[1].instructions.filter(o=>o.mnemonic!=='MULTIEQUAL').map((o,index)=>({...o,index}));}
 const edges=blocks.flatMap(b=>b.succs.map(to=>({from:b.id,to})));
 return {representation:'Ghidra p-code',entryBlock:0,blocks,edges,total_blocks:blocks.length,returned_instructions:blocks.reduce((n,b)=>n+b.instructions.length,0),total_instructions:blocks.reduce((n,b)=>n+b.instructions.length,0),scopeComplete:true,scopePartial:false,partial:false,truncated:false};
}
export function pythonStateOracle(graph,pluginRoot){
 const run=spawnSync(path.join(pluginRoot,'runtimes/ghidra/python/python.exe'),['-I','-B','-X','utf8',path.join(pluginRoot,'scripts/fixtures/cff_state_oracle.py')],{input:JSON.stringify(graph),encoding:'utf8',timeout:15000,maxBuffer:2*1024**2,windowsHide:true});
 assert.equal(run.status,0,run.stderr);return JSON.parse(run.stdout);
}
export function capturedStateReport(f,pluginRoot,options={}){
 const graph=stateGraph(options),deobfuscation=pythonStateOracle(graph,pluginRoot);
 return {...graph,ok:true,engine:'Ghidra',action:'deobfuscate',idb_modified:false,revision:f.context.dbRevision,optimization:null,ea:'0x1000',func:'owned_state_fixture',actualStage:'firstpass',source:{engine:'Ghidra',representation:'native HighFunction dataflow',language:'x86:LE:64:default',artifactSHA256:f.context.sha256},deobfuscation,fixtureScope:'Owned synthetic SSA; real pure Python oracle and JS worker, no native Ghidra/target execution'};
}
