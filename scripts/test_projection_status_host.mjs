import test from'node:test';import assert from'node:assert/strict';import path from'node:path';import{execFileSync}from'node:child_process';
import{validateOpaqueProjection}from'../source/projection_opaque.js';import{checkedProjectionReferences,validateProjection}from'../source/projection_jobs.js';
import{validateComposition}from'../source/composition_jobs.js';
const ROOT=path.resolve(import.meta.dirname,'..'),py=path.join(ROOT,'runtimes/ghidra/python/python.exe');
const fixtures=JSON.parse(execFileSync(py,['-I','-B','-X','utf8','-c',`
import sys,json,copy
from pathlib import Path
root=Path.cwd();sys.path[:0]=[str(root/'worker'),str(root/'scripts')]
from test_pcode_status import ADD,PUSH,POP,TSC,BSWAP,BARRIERS
from test_pcode_projection import append_path
from pcode_projection import GPRS,project
result=[]
for path in [append_path(copy.deepcopy(ADD),copy.deepcopy(PUSH),copy.deepcopy(POP)),[copy.deepcopy(PUSH)],[copy.deepcopy(TSC)],[copy.deepcopy(BSWAP)]]:
 r=project(path,list(GPRS),mode='opaque-status');r['decodedPath']=[{'ea':i['ea'],'bytes':i['codeBytes'],'decoded':i} for i in path];result.append(r)
for barrier in BARRIERS:
 path=append_path(copy.deepcopy(barrier),copy.deepcopy(ADD),copy.deepcopy(PUSH),copy.deepcopy(POP))
 r=project(path,list(GPRS),mode='opaque-status');r['decodedPath']=[{'ea':i['ea'],'bytes':i['codeBytes'],'decoded':i} for i in path];result.append(r)
print(json.dumps(result))
`],{cwd:ROOT,encoding:'utf8',windowsHide:true,maxBuffer:1024**2}));
const check=r=>{validateOpaqueProjection(r);assert.equal(checkedProjectionReferences(r),r.dag.references)};

test('new mode explicitly validates the canonical status mask/bit tree and counts all roots',()=>{
 for(const r of fixtures)assert.doesNotThrow(()=>check(r));
 assert.equal(fixtures[0].opaqueEffects[0].flagImageRefinement.knownMask,'0x8c5');
 const args={target:'C:/fixture.exe',level:'project',projection_mode:'opaque-status',projection_path:['0x1000'],projection_registers:['rax']};
 assert.equal(validateProjection(args).projection_mode,'opaque-status');assert.throws(()=>validateProjection({...args,initial_flags:'0x0'}));
 assert.doesNotThrow(()=>validateComposition({target:'C:/fixture.exe',level:'compose',composition_plan:{strategy:'sequence',representation:'transition-chain',template_mode:'opaque-status',paths:[['0x1000']]}}));
 assert.throws(()=>validateComposition({target:'C:/fixture.exe',level:'compose',composition_plan:{strategy:'sequence',representation:'flat',template_mode:'opaque-status',paths:[['0x1000']]}}));
});

test('architectural undefined and decoder unmodeled overlap is legitimate but never defined/preserved',()=>{
 for(const original of fixtures.slice(4)){
  assert(original.flagPolicies[0].undefined.includes('of')&&original.flagPolicies[0].unmodeled.includes('of'));
  assert.doesNotThrow(()=>check(original));
  for(const mutate of [r=>r.flagPolicies[0].defined.push('of'),r=>r.flagPolicies[0].preserved.push('of'),r=>r.flagPolicies[0].unmodeled.push('of')]){
   const r=structuredClone(original);mutate(r);assert.throws(()=>check(r));
  }
 }
});

const corruptions={
 'wrong known mask':r=>r.opaqueEffects[0].flagImageRefinement.knownMask='0x8d5',
 'wrong unknown mask':r=>r.opaqueEffects[0].flagImageRefinement.unknownMask='0xffffffffffffffff',
 'wrong effective unknown bits':r=>r.opaqueEffects[0].unknownBits=64,
 'wrong fresh input width':r=>r.opaqueEffects[0].flagImageRefinement.freshInputBits=59,
 'unmodeled AF made known':r=>r.opaqueEffects[0].flagImageRefinement.knownFlags.push({name:'af',bit:4,definitionInstructionIndex:0}),
 'wrong source definition':r=>r.opaqueEffects[0].flagImageRefinement.knownFlags[0].definitionInstructionIndex=1,
 'missing known flag':r=>r.opaqueEffects[0].flagImageRefinement.knownFlags.pop(),
 'different flag value root':r=>r.opaqueEffects[0].flagImageRefinement.valueNode=0,
 'caller values supplied':r=>r.opaqueEffects[0].flagImageRefinement.initialFlagValuesSupplied=true,
 'unknown ambient bits lost':r=>r.opaqueEffects[0].flagImageRefinement.unmodeledBitsRemainUnknown=false,
 'declared policy from another encoding':r=>r.flagPolicies[0].codeBytes='90',
 'unknown producer policy':r=>r.flagPolicies[0].status='unknown',
 'fake raw flag definition':r=>{r.flagPolicies[0].defined.push('af');r.flagPolicies[0].unmodeled=[]},
 'wrong source status offset name':r=>r.flagPolicies[0].defined[0]='if',
 'hidden refinement in old mode':r=>r.projectionMode='opaque-effects',
 'wrong replacement work count':r=>r.opaqueEffects[0].replacementOperationCount=3,
 'wrong original STORE index':r=>r.stores[0].pcodeIndex=23,
 'wrong replacement STORE index':r=>r.stores[0].replacementPcodeIndex=2,
 'missing overlay root reference':r=>r.dag.references--,
 'wrong mask node':r=>{let id=r.stores[0].value;for(let i=0;i<5;i++)id=r.dag.nodes[id].args[0];r.dag.nodes[id].op='INT_OR'},
 'wrong bit placement':r=>{const join=r.dag.nodes[r.stores[0].value],placed=r.dag.nodes[join.args[1]];placed.op='INT_ADD'},
 'wrong normalized flag width':r=>{const join=r.dag.nodes[r.stores[0].value],placed=r.dag.nodes[join.args[1]],wide=r.dag.nodes[placed.args[0]],bool=r.dag.nodes[wide.args[0]];bool.bits=64},
};
for(const[label,mutate]of Object.entries(corruptions))test('reject status overlay '+label,()=>{const r=structuredClone(fixtures[0]);mutate(r);assert.throws(()=>check(r));});
