import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
import {hashBytes} from '../source/analysis_artifacts.js';import {validateProjection} from '../source/projection_jobs.js';import {validateOpaqueProjection} from '../source/projection_opaque.js';
const data=JSON.parse(fs.readFileSync(new URL('./fixtures/projection_opaque.json',import.meta.url))),raw=data.instructions[0];
const canonical=v=>JSON.stringify(v,(_k,x)=>x&&typeof x==='object'&&!Array.isArray(x)?Object.fromEntries(Object.keys(x).sort().map(k=>[k,x[k]])):x);
function fixture(){const e={kind:'unknown-pushed-flag-image',codeBytes:'9c',rawPcodeSemanticSha256:hashBytes(Buffer.from(canonical(raw.pcode))),rawOperationCount:57,replacementOperationCount:3,
 unknownBits:64,conservativeSuperset:true,observedValuesUsed:false,architectureProved:false,flagsPreserved:true,instructionIndex:0,source:raw.ea,rawStorePcodeIndex:56};
return {projectionMode:'opaque-effects',opaqueEffects:[e],nondeterministicInputs:[{node:0,bits:64,kind:e.kind,source:e.source,instructionIndex:0}],
 dag:{nodes:[{id:0,op:'nondeterministic',type:'bv',bits:64,args:[],name:'opaque_0',kind:e.kind,source:e.source}]},path:[{ea:raw.ea,opaqueEffect:e}],
 decodedPath:[{ea:raw.ea,bytes:'9c',decoded:structuredClone(raw)}],stores:[{instructionIndex:0,pcodeIndex:56,replacementPcodeIndex:2,size:8}],statistics:{abstractedInstructions:1,abstractedRawOperations:57,replacementOperations:3,pcodeOperations:57},
 memoryNormalization:{method:'exact-ordered-byte-forwarding',maxStoreVisits:4096,storeVisits:0,observedValuesUsed:false,independentSMTProof:false}};}
test('opaque mode is explicit and no observation parameter is accepted',()=>{
 const a={target:'C:/fixture.exe',level:'project',projection_path:['0x1000'],projection_registers:['rax'],projection_mode:'opaque-effects'};
 assert.equal(validateProjection(a).projection_mode,'opaque-effects');assert.throws(()=>validateProjection({...a,opaque_value:'0x1'}));
 assert.throws(()=>validateProjection({...a,projection_mode:['strict','opaque-effects']}));
});
test('host independently rebinds complete original PUSHFQ semantics and unknown source',()=>assert.doesNotThrow(()=>validateOpaqueProjection(fixture())));
test('tampered provenance, counters, decoded effects and unknown definitions reject',()=>{
 for(const mutate of [f=>{f.opaqueEffects[0].rawPcodeSemanticSha256='0'.repeat(64);},f=>{f.opaqueEffects[0].rawOperationCount=56;},f=>{f.opaqueEffects[0].codeBytes='669c';},
  f=>{f.opaqueEffects[0].unknownBits=32;},f=>{f.opaqueEffects[0].observedValuesUsed=true;},f=>{f.opaqueEffects[0].conservativeSuperset=false;},f=>{f.opaqueEffects[0].architectureProved=true;},
  f=>{f.opaqueEffects[0].source='0x1';},f=>{f.nondeterministicInputs[0].node=1;},f=>{f.dag.nodes[0].name='rax';},f=>{f.dag.nodes[0].bits=32;},f=>{f.dag.nodes[0].args=[0];},
  f=>{f.statistics.pcodeOperations=3;},f=>{f.memoryNormalization.maxStoreVisits=4097;},f=>{f.memoryNormalization.storeVisits=4097;},f=>{f.memoryNormalization.independentSMTProof=true;},
  f=>{f.pathGuard=0;},f=>{f.path[0].ea='0x1';},f=>{f.nondeterministicInputs=[];},f=>{f.opaqueEffects=[];delete f.path[0].opaqueEffect;f.statistics.abstractedInstructions=0;},
  f=>{f.decodedPath[0].decoded.pcode.at(-1).inputs[2].size=4;f.opaqueEffects[0].rawPcodeSemanticSha256=hashBytes(Buffer.from(canonical(f.decodedPath[0].decoded.pcode)));}]){
  const f=fixture();mutate(f);assert.throws(()=>validateOpaqueProjection(f),/opaque-effect/);
 }
});
