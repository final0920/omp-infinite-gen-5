// Actual pure-Python translation -> independent JS serialization validation.
// Decoder/native process integration is verified by the separate runtime test.
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {validateCompositionPlan,validateCompositionResult} from '../source/composition_jobs.js';
import {PROJECTION_RUNTIME_PIN} from '../source/projection_jobs.js';
const root=path.resolve(import.meta.dirname,'..');
const child=spawnSync(path.join(root,'runtimes/ghidra/python/python.exe'),['-I','-B','-X','utf8',path.join(import.meta.dirname,'test_transition_chain.py'),'--fixtures'],{windowsHide:true,maxBuffer:4*1024**2});
assert.equal(child.status,0,child.stderr?.toString());
const cases=JSON.parse(child.stdout.toString()).map(({core,paths,indirect_mode})=>{
  const plan=validateCompositionPlan({strategy:'sequence',paths,representation:'transition-chain',...(indirect_mode?{indirect_mode}:{})});
  const decoded=new Map(core.templates.flatMap(t=>t.instructions).map(r=>[r.ea,{ea:r.ea,bytes:r.codeBytes,
    decoded:{ea:r.ea,size:r.size,mnemonic:r.mnemonic,operands:r.operands,pcode:r.pcode}}]));
  const decodedPath=[...new Set(paths.flat())].map(a=>decoded.get(a));
  const result={...core,representationSchema:core.schema,schema:'ig5-pcode-transition-chain-v1',publicToolRouteExposed:true,
    targetSha256:'a'.repeat(64),runtimeManifestPin:PROJECTION_RUNTIME_PIN,compositionPlan:plan,decodedPath,
    compositionLimits:core.internalPrototypeLimits,decodeStatistics:{instructions:decoded.size,
      rawPcodeOperations:decodedPath.reduce((n,r)=>n+r.decoded.pcode.length,0),providedAddressOccurrences:paths.flat().length}};
  return {result,selected:{composition_plan:plan}};
});
const verify=({result,selected})=>validateCompositionResult(result,selected,'a'.repeat(64));
test('all four real pure translations satisfy the independent host validator',()=>cases.forEach(verify));
test('host and worker plans keep legacy defaults and reject unsupported chain inputs',()=>{
  assert.equal(validateCompositionPlan({strategy:'sequence',paths:[['0x1']]}).representation,undefined);
  for(const representation of [null,true,{},'chain']) assert.throws(()=>validateCompositionPlan({strategy:'sequence',paths:[['0x1']],representation}));
  assert.throws(()=>validateCompositionPlan({strategy:'constant-loop',prefix:['0x1'],body:['0x2'],suffix:[['0x3']],representation:'transition-chain'}),/explicit sequence/);
});
const changes=[
 ['missing source',r=>delete r.dag.nodes[r.layers[0].registers.rax].source],
 ['future source',r=>r.dag.nodes[r.layers[0].registers.rax].source=r.dag.nodes.length-1],
 ['independent input',r=>r.dag.nodes[r.layers[0].registers.rax].op='input'],
 ['wrong type',r=>r.dag.nodes[r.layers[0].currentMemory].type='bv'],
 ['wrong state index',r=>r.dag.nodes[r.layers[0].registers.rax].stateIndex=9],
 ['reused state',r=>r.layers[1].registers.rax=r.layers[0].registers.rax],
 ['wrong incoming state',r=>r.layers[1].inputRegisters.rax=r.initialRegisters.rax],
 ['memory discarded',r=>r.dag.nodes[r.layers[0].currentMemory].source=r.initialMemory],
 ['binding omitted',r=>r.dag.bindingCount--],
 ['roots omitted',r=>r.dag.references--],
 ['expanded depth forged',r=>r.dag.expandedDependencyDepth=1],
 ['public scope forged',r=>r.schema='ig5-pcode-composition-v1'],
 ['side exit state discarded',r=>r.sideExits[0].registers.rsp=r.initialRegisters.rsp],
 ['complement discarded',r=>r.sideExits=[]],
 ['STORE assigned final guard',r=>r.stores[0].guard=r.pathGuard],
 ['application lost',r=>r.steps.pop()],
];
for(const [name,change] of changes)test('reject forged '+name,()=>{
  const selectedCase=name.startsWith('side')||name.startsWith('complement')?cases[2]:name.startsWith('memory')||name.startsWith('STORE')?cases[1]:cases[0];
  const c=structuredClone(selectedCase);change(c.result);assert.throws(()=>verify(c));
});
test('dynamic selector and complementary guard cannot be replaced with constants',()=>{
  for(const f of [r=>r.sideExits[0].selectionCondition=r.boundaries[0].entryGuard,
    r=>r.sideExits[0].guard=r.boundaries[0].entryGuard,r=>r.sideExits[0].selectedTarget=r.control.target]) {
    const c=structuredClone(cases[2]);f(c.result);assert.throws(()=>verify(c));
  }
});
