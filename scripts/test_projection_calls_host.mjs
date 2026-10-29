import test from 'node:test';import assert from 'node:assert/strict';import {validateDirectCallControl} from '../source/projection_jobs.js';
const fixture=()=>({control:{kind:'direct',source:'0x140001000',target:0,transfer:'call',returnAddress:'0x140001005'},
 nodes:[{id:0,op:'const',type:'bv',bits:64,args:[],value:'0x140001020'}],decoded:[{ea:'0x140001000',bytes:'e81b000000',decoded:{mnemonic:'CALL',size:5}}]});
test('host validates preferred uint64 return address and signed rel32 target from actual CALL bytes',()=>{
 const f=fixture();assert.doesNotThrow(()=>validateDirectCallControl(f.control,f.nodes,f.decoded));
 f.decoded[0].bytes='e8fbffffff';f.nodes[0].value='0x140001000';assert.doesNotThrow(()=>validateDirectCallControl(f.control,f.nodes,f.decoded));
});
test('forged call type, address, source, decoder or target cannot be imported',()=>{
 for(const mutate of [f=>{f.control.kind='return';},f=>{f.control.transfer='jump';},f=>{delete f.control.transfer;},f=>{f.control.returnAddress='0x140001006';},
  f=>{f.control.returnAddress=0x1005;},f=>{f.nodes[0].value='0x140001021';},f=>{f.nodes[0].bits=32;},f=>{f.nodes[0].op='input';},
  f=>{f.control.source='0x140001001';},f=>{f.decoded[0].bytes='e91b000000';},f=>{f.decoded[0].decoded.mnemonic='NOP';},f=>{f.decoded[0].decoded.size=6;}]){
  const f=fixture();mutate(f);assert.throws(()=>validateDirectCallControl(f.control,f.nodes,f.decoded),/CALL/);
 }
});
test('existing non-call control retains its previous contract',()=>{
 for(const c of [{kind:'fallthrough',target:1},{kind:'return',source:'0x1',target:0}])assert.doesNotThrow(()=>validateDirectCallControl(c,[],[]));
});
test('zero displacement requires complete original stack/store and CALL-or-BRANCH target shape',()=>{
 const v=(space,offset)=>({space,offset,size:8}),rsp=()=>v('register','0x20'),c=x=>v('const',x);
 const make=()=>{const f=fixture();f.decoded[0].bytes='e800000000';f.nodes[0].value='0x140001005';f.decoded[0].decoded.pcode=[
  {opcode:'INT_SUB',output:rsp(),inputs:[rsp(),c('0x8')]},
  {opcode:'STORE',output:null,inputs:[{kind:'address-space',space:'ram',spaceId:3},rsp(),c('0x140001005')]},
  {opcode:'BRANCH',output:null,inputs:[v('ram','0x140001005')]}];return f;};
 for(const op of['CALL','BRANCH']){const f=make();f.decoded[0].decoded.pcode[2].opcode=op;assert.doesNotThrow(()=>validateDirectCallControl(f.control,f.nodes,f.decoded));}
 const f=make();f.decoded[0].decoded.pcode[1].inputs[0]={spaceId:3,space:'ram',kind:'address-space'};assert.doesNotThrow(()=>validateDirectCallControl(f.control,f.nodes,f.decoded));
 for(const mutate of [f=>f.decoded[0].decoded.pcode.pop(),f=>f.decoded[0].decoded.pcode[0].inputs[1].offset='0x10',f=>f.decoded[0].decoded.pcode[1].inputs[2].offset='0x140001006',f=>f.decoded[0].decoded.pcode[2].inputs[0].offset='0x140001006',f=>f.decoded[0].decoded.pcode[2].opcode='CBRANCH',f=>f.decoded[0].decoded.pcode[1].inputs[0].spaceId=2,f=>f.decoded[0].decoded.pcode[1].inputs[2].size=4,f=>f.decoded[0].decoded.pcode[0].output.extra='ignored']){
  const f=make();mutate(f);assert.throws(()=>validateDirectCallControl(f.control,f.nodes,f.decoded));
 }
});
