// Synthetic data fixtures only. Never imported into native recording stores.
import {buildPE64Fixture} from './pe64.mjs';
import {hashBytes} from '../../source/analysis_artifacts.js';
import {mapVmFlowBytes} from '../../source/vm_flow_mapping.js';
import {makeRecordedCoordinateInput} from '../../source/recorded_projection_coordinates.js';
export const GPRS='rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split(' ');
export function recordedCoordinateCase(runtimeBase=0x7ff700000000n){
 const data=Buffer.from(buildPE64Fixture().image),code=['488d0520000000','48894500','488b4d00','48ba2710004001000000'];data.fill(0x90,0x400,0x800);
 const hx=x=>'0x'+x.toString(16),recordingId='11111111-1111-4111-8111-111111111111',state=Object.fromEntries(GPRS.map((g,i)=>[g,hx(BigInt(i+1))]));state.rbp='0x8000';
 const groups=[],decoded=[];let offset=0x1000,stored;
 for(const [i,bytes]of code.entries()){
  Buffer.from(bytes,'hex').copy(data,0x400+offset-0x1000);const pc=hx(runtimeBase+BigInt(offset)),before={rip:pc,gprs:{...state}},memoryReads=[];
  if(i===0)state.rax=hx(runtimeBase+0x1027n);
  if(i===1)stored=BigInt(state.rax);
  if(i===2){state.rcx=hx(stored);const b=Buffer.alloc(8);b.writeBigUInt64LE(stored);memoryReads.push({address:state.rbp,bytes:8,littleEndianHex:b.toString('hex')});}
  if(i===3)state.rdx='0x140001027';
  const after={rip:hx(runtimeBase+BigInt(offset+bytes.length/2)),gprs:{...state}};
  groups.push({groupIndex:i,recordingId,intermediateStateAvailable:true,instructions:[{pc,bytes}],before,after,memoryReads,pauseSequence:{before:i+10,after:i+11}});
  decoded.push({pc,bytes,status:'decoded',controlFlow:false,text:i===0?'lea rax, [rip + 0x20]':i===3?'movabs rdx, 0x140001027':'mov',operands:i===0?[{kind:'memory',base:{name:'rip'}}]:[]});
  offset+=bytes.length/2;
 }
 const targetSha256=hashBytes(data),mapping=mapVmFlowBytes(data,hx(runtimeBase),groups),body={groups},source={identity:{runId:'synthetic-unit-only',threadId:1},windows:[{reportId:recordingId,reportSha256:'a'.repeat(64),traceSha256:'b'.repeat(64)}]};
 const ref={id:'22222222-2222-4222-8222-222222222222',sha256:'c'.repeat(64)};
 return{data,targetSha256,mapping,body,groups,decoded,input:makeRecordedCoordinateInput({targetSha256,mapping,body,source,recurrencesRef:ref,selectionRef:ref})};
}
