// Synthetic recording declarations and typed IR only. Never imported into the
// configured native recording store, executed, or counted as CPU/VM evidence.
import {classifyFetchFlow} from '../../source/vm_fetch_flow.js';
import {observationHash,observationTarget} from './vm_observation_cases.mjs';
const GPRS='rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split(' '),hx=v=>'0x'+BigInt(v).toString(16),mask=(1n<<64n)-1n;
export function recount(core){
  const depths=[];for(const n of core.dag.nodes)depths.push(1+Math.max(0,...n.args.map(i=>depths[i])));
  core.dag.references=core.dag.nodes.reduce((s,n)=>s+n.args.length,0)+35+4*core.stores.length+core.nondeterministicInputs.length;
  core.dag.depth=Math.max(...depths);return core;
}
function stateCore(prefix,padding){
  const nodes=[],add=(op,type,args,extra={})=>{const id=nodes.length;nodes.push({id,op,type,args,...extra});return id;};
  const initialRegisters=Object.fromEntries(GPRS.map(name=>[name,add('input','bv',[],{bits:64,name})])),registers={...initialRegisters};
  const memory=add('initial_memory','memory',[],{name:'M0',addressBits:64,elementBits:8});
  const source=add('load_le','bv',[memory,initialRegisters.rsi],{bits:8,size:1}),extended=add('INT_ZEXT','bv',[source],{bits:64});registers.rax=extended;
  let currentMemory=memory,target=initialRegisters.rdx;const stores=[];
  if(!prefix){
    const one=add('const','bv',[],{bits:64,value:'0x1'});registers.rsi=add('INT_ADD','bv',[initialRegisters.rsi,one],{bits:64});
    const four=add('const','bv',[],{bits:64,value:'0x4'}),offset=add('INT_MULT','bv',[extended,four],{bits:64});
    const address=add('INT_ADD','bv',[initialRegisters.r11,offset],{bits:64}),table=add('load_le','bv',[memory,address],{bits:32,size:4});
    const signed=add('INT_SEXT','bv',[table],{bits:64});registers.r8=add('INT_ADD','bv',[signed,initialRegisters.r11],{bits:64});
    const eight=add('const','bv',[],{bits:64,value:'0x8'}),sp=add('INT_SUB','bv',[initialRegisters.rsp,eight],{bits:64});
    currentMemory=add('store_le','memory',[memory,sp,registers.r8],{size:8});stores.push({instructionIndex:4+padding,pcodeIndex:0,address:sp,value:registers.r8,size:8,beforeMemory:memory,afterMemory:currentMemory});
    target=add('load_le','bv',[currentMemory,sp],{bits:64,size:8});registers.rsp=add('INT_ADD','bv',[sp,eight],{bits:64});
  }
  const decodedPath=[{ea:'0x1000',bytes:'0fb606'},{ea:'0x1003',bytes:'4883c601'},
    ...Array.from({length:padding},(_,i)=>({ea:hx(0x2000+i),bytes:'90'})),{ea:'0x1007',bytes:'4d630483'},{ea:'0x100b',bytes:'4d01d8'},{ea:'0x100e',bytes:'4150'},{ea:'0x1010',bytes:'c3'}]
    .slice(0,prefix?1:undefined).map(r=>({...r,decoded:{pcode:[]}}));
  return recount({schema:'ig5-pcode-opaque-status-projection-v1',projectionMode:'opaque-status',targetSha256:observationTarget,
    nativeTargetExecuted:false,databaseModified:false,businessAccepted:false,wholeBinaryVerified:false,projectionPath:decodedPath.map(r=>r.ea),decodedPath,
    initialRegisters,registers,initialMemory:memory,currentMemory,stores,control:{kind:prefix?'direct':'return',source:decodedPath.at(-1).ea,target},
    nondeterministicInputs:[],opaqueEffects:[],statistics:{pcodeOperations:prefix?3:20},dag:{nodes}});
}
export function recurrenceCase({repetitions=12,partial=2,padding=0,noiseReads=0}={}){
  const prefix=stateCore(true,padding),full=stateCore(false,padding),dependency=classifyFetchFlow(prefix,full);
  const flow={...dependency,seed:{pc:'0x1000',bytes:'0fb606'},mapping:{runtimeBase:'0x0',preferredBase:'0x0',mapping:full.decodedPath.map(r=>({runtimePc:r.ea,preferred:r.ea,bytes:r.bytes}))}};
  const steps=[],registers=Object.fromEntries(GPRS.map(g=>[g,0n]));registers.rsi=0x8000n;registers.r11=0x9000n;registers.rsp=0xa000n;
  const append=(pc,bytes,reads,change)=>{steps.push({pc,bytes,before:{...registers},reads});change?.();};
  function path(index,maximum=full.decodedPath.length){
    const source=1+index%2,offset=0x80+source,target=0x9000+offset;let written=0n;
    for(const [i,row] of full.decodedPath.entries()){
      if(i>=maximum)break;
      const isPadding=i>=2&&i<2+padding,op=i<2?i:isPadding?-1:i-padding;
      const reads=isPadding?Array.from({length:noiseReads},(_,n)=>({address:0xb000n+64n*BigInt(n),size:64,value:0n})):
        op===0?[{address:registers.rsi,size:1,value:BigInt(source)}]:op===2?[{address:registers.r11+BigInt(source*4),size:4,value:BigInt(offset)}]:
        op===5?[{address:registers.rsp,size:8,value:written}]:[];
      append(row.ea,row.bytes,reads,()=>{
        if(op===0)registers.rax=BigInt(source);else if(op===1)registers.rsi++;
        else if(op===2)registers.r8=BigInt(offset);else if(op===3)registers.r8+=registers.r11;
        else if(op===4){registers.rsp-=8n;written=registers.r8;}else if(op===5)registers.rsp+=8n;
      });
    }
    return target;
  }
  let endPc='0x1000';for(let i=0;i<repetitions;i++){const target=path(i);append(hx(target),'90',[]);}
  if(partial){path(repetitions,partial);endPc=full.decodedPath[partial].ea;}
  else endPc='0x1000';
  const makeWindow=()=>{
    const rows=['h:ig5-native-x64-v1'];for(const s of steps){
      rows.push('r:'+GPRS.map(g=>hx(s.before[g]&mask)).join(':'),'e:0x202');
      for(const r of s.reads)rows.push('mr:'+hx(r.address)+':'+r.size+':'+hx(r.value));
      rows.push('i:'+s.pc+':'+s.bytes.length/2+':'+s.bytes);
    }
    rows.push('f:'+GPRS.map(g=>hx(registers[g]&mask)).join(':')+':'+endPc+':0x202');
    const data=Buffer.from(rows.join('\n')+'\n');return{source:{reportId:'11111111-1111-1111-1111-111111111111',reportSha256:'b'.repeat(64),locationFingerprint:'c'.repeat(64),image:null},
      summary:{targetSha256:observationTarget,nativeTargetExecuted:true,format:'ig5.x86-recording.v1',finalSnapshotIncluded:true,finalSnapshotCurrent:true,runId:'synthetic-unit-data',threadId:7,
        startStopSeq:1,endStopSeq:steps.length+1,instructionCount:steps.length,confirmedStepStops:steps.length,runtimeBase:'0x0',entry:steps[0].pc,exit:steps.at(-1).pc,initialFlags:'0x202',stopReason:'instruction-budget',bytes:data.length,sha256:observationHash(data)},data};
  };
  return{prefix,full,flow,steps,makeWindow,request:()=>({targetSha256:observationTarget,prefix,full,flow,windows:[makeWindow()]})};
}
