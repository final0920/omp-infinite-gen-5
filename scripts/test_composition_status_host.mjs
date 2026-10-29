import test from'node:test';import assert from'node:assert/strict';import path from'node:path';import{spawnSync}from'node:child_process';
import{validateCompositionPlan,validateCompositionResult}from'../source/composition_jobs.js';import{PROJECTION_RUNTIME_PIN}from'../source/projection_jobs.js';
const root=path.resolve(import.meta.dirname,'..'),p=spawnSync(path.join(root,'runtimes/ghidra/python/python.exe'),['-I','-B','-X','utf8',path.join(import.meta.dirname,'test_composition_status.py'),'--fixtures'],{windowsHide:true,maxBuffer:4*1024**2});
assert.equal(p.status,0,p.stderr?.toString());
const cases=JSON.parse(p.stdout).map(({core,paths})=>{
 const plan=validateCompositionPlan({strategy:'sequence',paths,representation:'transition-chain',template_mode:'opaque-status'}),unique=[...new Map(core.templates.flatMap(t=>t.instructions).map(r=>[r.ea,r])).values()];
 const decodedPath=unique.map(r=>({ea:r.ea,bytes:r.codeBytes,decoded:{ea:r.ea,size:r.size,mnemonic:r.mnemonic,operands:r.operands,pcode:r.pcode}}));
 return {selected:{composition_plan:plan},result:{...core,schema:'ig5-pcode-opaque-status-transition-chain-v1',representationSchema:core.schema,publicToolRouteExposed:true,compositionPlan:plan,
  targetSha256:'b'.repeat(64),runtimeManifestPin:PROJECTION_RUNTIME_PIN,decodedPath,compositionLimits:core.internalPrototypeLimits,
  decodeStatistics:{instructions:unique.length,rawPcodeOperations:unique.reduce((n,r)=>n+r.pcode.length,0),providedAddressOccurrences:paths.flat().length}}};
});const check=c=>validateCompositionResult(c.result,c.selected,'b'.repeat(64));
test('all six real pure status chains validate exact bindings fresh images and original budgets',()=>{
 for(const c of cases){const v=check(c);assert.equal(v.reportSchema,'ig5-pcode-opaque-status-transition-chain-v1');assert.equal(v.bindingsChecked,c.result.steps.length*18);assert(v.opaqueEffectsRebound)}
});
test('new mode requires sequence/chain and rejects caller flags values summaries',()=>{
 for(const extra of[{representation:'flat'},{strategy:'constant-loop'},{initial_flags:'0x0'},{flagImages:[]},{observed_values:{}}])
  assert.throws(()=>validateCompositionPlan({...cases[0].selected.composition_plan,...extra}));
});
const mutate={
 'wrong schema':c=>c.result.schema='ig5-pcode-opaque-transition-chain-v1',
 'old mode':c=>c.result.templateMode='opaque-effects',
 'missing layer images':c=>delete c.result.layers[0].flagImages,
 'missing source policies':c=>delete c.result.templates[0].flagPolicies,
 'template global value':c=>c.result.templates[0].opaqueEffects[0].flagImageRefinement.valueNode=c.result.layers[0].flagImages[0].valueNode,
 'wrong producer':c=>c.result.templates[0].opaqueEffects[0].flagImageRefinement.knownFlags[0].definitionInstructionIndex=1,
 'AF made known':c=>c.result.templates[0].opaqueEffects[0].flagImageRefinement.knownFlags.push({name:'af',bit:4,definitionInstructionIndex:0}),
 'wrong unknown width':c=>c.result.templates[0].opaqueEffects[0].unknownBits=64,
 'wrong fresh input width':c=>c.result.templates[0].opaqueEffects[0].flagImageRefinement.freshInputBits=59,
 'missing mask bit':c=>c.result.templates[0].opaqueEffects[0].flagImageRefinement.knownMask='0x8c4',
 'shared image root':c=>c.result.layers[1].flagImages[0].valueNode=c.result.layers[0].flagImages[0].valueNode,
 'wrong image instruction':c=>c.result.layers[0].flagImages[0].instructionIndex=0,
 'observed image supplied':c=>c.result.layers[0].flagImages[0].value='0x44',
 'missing image root reference':c=>c.result.dag.references--,
 'wrong overlay step':c=>c.result.dag.nodes[c.result.layers[1].flagImages[0].valueNode].statusOverlayStep=0,
 'shared unknown input':c=>c.result.nondeterministicInputs[1].node=c.result.nondeterministicInputs[0].node,
 'initial flags exported':c=>c.result.templates[0].flagsExported=true,
 'raw operations undercounted':c=>c.result.statistics.expandedAbstractedRawOperations--,
 'STORE reordered':c=>c.result.stores.reverse(),
 'binding made free':c=>{let id=c.result.layers[0].registers.r10;c.result.dag.nodes[id].op='input'},
 'unknown budget extended':c=>c.result.memoryNormalization.maxStoreVisits=4097,
};for(const[label,f]of Object.entries(mutate))test('reject status composition '+label,()=>{const c=structuredClone(cases[0]);f(c);assert.throws(()=>check(c));});
test('old strict and opaque modes cannot accept hidden flag image metadata',()=>{
 for(const mode of['strict','opaque-effects']){const c=structuredClone(cases[0]);c.selected.composition_plan.template_mode=mode;c.result.compositionPlan=c.selected.composition_plan;
  c.result.templateMode=mode;c.result.schema=mode==='strict'?'ig5-pcode-transition-chain-v1':'ig5-pcode-opaque-transition-chain-v1';
  c.result.representationSchema=mode==='strict'?'ig5-internal-state-transition-chain-v1':'ig5-internal-opaque-transition-chain-v1';assert.throws(()=>check(c));}
});
