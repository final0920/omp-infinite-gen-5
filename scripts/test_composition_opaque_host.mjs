import test from 'node:test';import assert from 'node:assert/strict';import path from 'node:path';import {spawnSync} from 'node:child_process';
import {validateCompositionPlan,validateCompositionResult} from '../source/composition_jobs.js';
import {PROJECTION_RUNTIME_PIN} from '../source/projection_jobs.js';
const root=path.resolve(import.meta.dirname,'..');
const p=spawnSync(path.join(root,'runtimes/ghidra/python/python.exe'),['-I','-B','-X','utf8',path.join(import.meta.dirname,'test_composition_opaque.py'),'--fixtures'],{windowsHide:true,maxBuffer:4*1024**2});
assert.equal(p.status,0,p.stderr?.toString());
const cases=JSON.parse(p.stdout.toString()).map(({core,paths})=>{
  const plan=validateCompositionPlan({strategy:'sequence',paths,representation:'transition-chain',template_mode:'opaque-effects'});
  const unique=[...new Map(core.templates.flatMap(t=>t.instructions).map(r=>[r.ea,r])).values()];
  const decodedPath=unique.map(r=>({ea:r.ea,bytes:r.codeBytes,decoded:{ea:r.ea,size:r.size,mnemonic:r.mnemonic,operands:r.operands,pcode:r.pcode}}));
  const result={...core,schema:'ig5-pcode-opaque-transition-chain-v1',representationSchema:core.schema,
    publicToolRouteExposed:true,compositionPlan:plan,targetSha256:'b'.repeat(64),runtimeManifestPin:PROJECTION_RUNTIME_PIN,
    decodedPath,compositionLimits:core.internalPrototypeLimits,decodeStatistics:{instructions:unique.length,
      rawPcodeOperations:unique.reduce((n,r)=>n+r.pcode.length,0),providedAddressOccurrences:paths.flat().length}};
  return {result,selected:{composition_plan:plan}};
});
const verify=c=>validateCompositionResult(c.result,c.selected,'b'.repeat(64));
test('all real opaque pure translations validate with fresh identities and host summaries',()=>{
  for(const c of cases){const v=verify(c);assert.equal(v.liveFreshUnknowns,3);assert.equal(v.bindingsChecked,54);
    assert.deepEqual(v.bindingTypes,{gpr64:48,memory:3,guard8:3});assert.equal(v.reportSchema,'ig5-pcode-opaque-transition-chain-v1');}
});
test('explicit opaque mode requires a sequence transition chain',()=>{
  for(const extra of [{representation:'flat'},{representation:undefined},{template_mode:'opaque'},{template_mode:null},{unknown_values:{}}])
    assert.throws(()=>validateCompositionPlan({strategy:'sequence',paths:[['0x1']],representation:'transition-chain',template_mode:'opaque-effects',...extra}));
});
const mutations=[
 ['scope/schema',c=>c.result.schema='ig5-pcode-transition-chain-v1'],
 ['mode',c=>delete c.result.templateMode],
 ['raw effect',c=>c.result.templates[0].opaqueEffects[0].rawOperationCount--],
 ['effect omission',c=>c.result.templates[0].opaqueEffects=[]],
 ['live input omission',c=>c.result.nondeterministicInputs.pop()],
 ['shared unknown',c=>c.result.nondeterministicInputs[1].node=c.result.nondeterministicInputs[0].node],
 ['unknown name reused',c=>{const id=c.result.nondeterministicInputs[1].node;c.result.dag.nodes[id].name='step_0_opaque_0';}],
 ['wrong application',c=>c.result.nondeterministicInputs[1].stepIndex=0],
 ['wrong instruction',c=>c.result.nondeterministicInputs[0].instructionIndex=1],
 ['concrete unknown value',c=>c.result.dag.nodes[c.result.nondeterministicInputs[0].node].value='0x1'],
 ['supplied unknown assignment',c=>c.result.nondeterministicInputs[0].value='0x1'],
 ['raw STORE index',c=>c.result.stores[0].pcodeIndex=2],
 ['replacement STORE index',c=>delete c.result.stores[0].replacementPcodeIndex],
 ['raw work undercount',c=>c.result.statistics.expandedAbstractedRawOperations=3],
 ['normalization budget reset',c=>c.result.memoryNormalization.storeVisits=4097],
 ['fit scope',c=>c.result.fitsPublicFixedPathLimits=!c.result.fitsPublicFixedPathLimits],
];
for(const [name,change]of mutations)test('reject opaque '+name,()=>{const c=structuredClone(cases[0]);change(c);assert.throws(()=>verify(c));});
test('strict chain must not accept undeclared opaque state',()=>{
  const c=structuredClone(cases[0]);delete c.selected.composition_plan.template_mode;c.result.compositionPlan=c.selected.composition_plan;
  c.result.schema='ig5-pcode-transition-chain-v1';c.result.representationSchema='ig5-internal-state-transition-chain-v1';
  assert.throws(()=>verify(c));
});
