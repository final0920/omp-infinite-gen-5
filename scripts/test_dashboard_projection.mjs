import test from 'node:test';import assert from 'node:assert/strict';
import {ig5DashDefinition} from '../source/dashboard_projection.js';
const definition=ig5DashDefinition(),call=(id,name='ig5_ir')=>({type:'tool/call',data:{callId:id,name}});
const reply=(id,isError=false)=>({type:'tool/result',data:{message:{toolCallId:id,isError,content:[{type:'text',text:'actual logged result'}]}}});
const fold=events=>events.reduce(definition.apply,definition.init());
test('actual DSH toolCallId settles completed calls and replayed errors only once',()=>{
  const state=fold([call('a'),reply('a',true),reply('a',true)]);
  assert.equal(definition.stateVersion,2);assert.equal(state.running,null);assert.equal(state.calls,1);assert.equal(state.errors,1);assert.deepEqual(state.pending,{});
});
test('one result cannot hide a second pending analysis',()=>{
  const middle=fold([call('a'),call('b','ig5_decompile'),reply('a')]);assert.equal(middle.running,'ig5_decompile');assert.deepEqual(middle.pending,{b:'ig5_decompile'});
  const done=definition.apply(middle,reply('b'));assert.equal(done.running,null);assert.equal(done.calls,2);
});
test('invalid ids, foreign names, duplicate calls and unrelated results do not settle activity',()=>{
  const initial=fold([call('a'),call('a')]);assert.equal(initial.calls,1);
  for(const event of [call(undefined),call(''),call(1),call('a','read'),reply('foreign'),
    {type:'tool/result',data:{message:{name:'ig5_ir',content:[]}}},
    {type:'tool/result',data:{message:{toolCallId:'a',name:'ig5_decompile'}}}])assert.deepEqual(definition.apply(initial,event),initial);
});
test('legacy message/data callId formats remain supported without guessing ownership',()=>{
  for(const data of [{message:{callId:'a'}},{callId:'a',message:{}},{toolCallId:'a',message:{}}]){
    assert.equal(fold([call('a'),{type:'tool/result',data}]).running,null);
  }
});
test('pending UI state stays bounded and prototype-like ids remain ordinary keys',()=>{
  const events=Array.from({length:40},(_,i)=>call('x'+i));const state=fold(events);
  assert.equal(Object.keys(state.pending).length,32);assert.equal(state.calls,40);
  assert.deepEqual(definition.apply(state,reply('x0')),state);
  const special=fold([call('__proto__'),reply('__proto__')]);assert.equal(special.running,null);assert.deepEqual(special.pending,{});
});
