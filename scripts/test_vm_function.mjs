import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createAnalysisService } from '../analysis_tools.js';
import { runRecoveryProfile } from '../source/vm_recovery_profile.js';
import { buildBytecodeGraph,decodeBytecode,executeBytecode,deriveExecutableProgram,bytecodeHash } from '../source/vm_bytecode.js';
import { verifyFiniteFunction } from '../source/verifiers/vm_function_verify.js';
import { branchMemoryCode,ownedVmImage,ownedBranchVmFixture,bytecodeContract } from './fixtures/vm_bytecode_cases.mjs';
import { buildPhaseContextCase } from './fixtures/vm_phase_context_cases.mjs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

function fixture(t) {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'ig5-finite-vm-')),cfg={artifactDir:path.join(root,'artifacts'),projectRoot:path.join(root,'projects')};
  const analysis=createAnalysisService({},cfg),mgr={analysis,checkCancelled(){}};
  for(const k of ['rpc','get','performDebug','approve','spawnWorker','run'])mgr[k]=()=>assert.fail('Data-only route cannot execute targets');
  t.after(async()=>{await analysis.dispose();assert.equal(path.dirname(root),fs.realpathSync(os.tmpdir()));assert(path.basename(root).startsWith('ig5-finite-vm-'));fs.rmSync(root,{recursive:true,force:true});});
  const ref=v=>({id:v.reportId,sha256:v.reportSha256});
  const call=async(mode,input)=>(await runRecoveryProfile(mgr,{recovery:{[mode]:input}},cfg))[mode];
  const save=(kind,action,result)=>{const v=analysis.artifacts.save({kind,action,result});return{id:v.id,sha256:analysis.artifacts.metadata(v.id).result.recordSha256};};
  async function program(image=branchMemoryCode,mutate=()=>{}) {
    const sha=bytecodeHash(image),contract=bytecodeContract(sha,image.length!==branchMemoryCode.length);mutate(contract);
    const c=ref(await call('declare_contract',{contract})),file=path.join(root,sha+'.bin');fs.writeFileSync(file,image);
    const p=await call('program',{image_ref:{path:file,sha256:sha},contract_ref:c});return{view:p,ref:ref(p),contractRef:c,contract,file};
  }
  return{root,cfg,mgr,analysis,ref,call,save,program};
}
test('source-bound native-owned image and branching bytecode both verify all 256 input-model cases and output bytes',async t=>{
  const f=fixture(t);
  assert.equal(bytecodeHash(ownedVmImage()),'71d1ceaedaebeb572c63c33485405fa7612beab047aff0c00f96044bd92223f0');
  assert.equal(bytecodeHash(ownedBranchVmFixture().image),'d9bf31e34c5e95307f88fcc7ce544101bd61e566c284a4622afc9700f29da61c');
  for(const image of [branchMemoryCode,ownedVmImage(),ownedBranchVmFixture().image]) {
    const p=await f.program(image),v=await f.call('function_check',{program_ref:p.ref}),r=f.analysis.artifacts.get(v.reportId).result;
    assert.equal(r.status,'pass');assert.equal(r.finiteTesting.cases,256);assert.equal(r.exhaustiveFiniteDomain,true);assert.equal(r.modelContractAccepted,true);
    assert.equal(r.universalProof,false);assert.equal(r.nativeCpuEquivalenceProved,false);assert.equal(r.businessAccepted,false);
    assert.equal(r.dataWorkerCleanupConfirmed,true);assert.equal(f.analysis.jobs.active,null);
    if(image===branchMemoryCode)assert(r.coverage.observedModelEdges.some(x=>x.startsWith('3:0->9'))&&r.coverage.observedModelEdges.some(x=>x.startsWith('3:0->5')));
  }
});
test('full-width domain is finite testing only; outside-domain samples cannot silently widen the contract',async t=>{
  const f=fixture(t),p=await f.program(ownedVmImage(),c=>{c.input.bits=64;c.input.maximum='0xffffffffffffffff';});
  const v=await f.call('function_check',{program_ref:p.ref,sample_inputs:['0x1','0x100','0x12345678']}),r=f.analysis.artifacts.get(v.reportId).result;
  assert.equal(r.status,'partial');assert.equal(r.finiteTesting.status,'pass');assert.equal(r.finiteTesting.cases,5);assert.equal(r.exhaustiveFiniteDomain,false);assert.equal(r.modelContractAccepted,false);
  assert.equal(r.recordedFunctionEvidence.status,'not-supplied');
  const q=await f.program();await assert.rejects(f.call('function_check',{program_ref:q.ref,sample_inputs:['0x100']}));
});
test('write-after-read state, explicit branches and all ordered stores survive handler boundaries',()=>{
  const p=deriveExecutableProgram(branchMemoryCode,bytecodeContract(bytecodeHash(branchMemoryCode)));
  const even=executeBytecode(p.model,1n),odd=executeBytecode(p.model,0n);
  assert.equal(even.returnValue,'0x8');assert.equal(even.memoryHex,'0800000000000000');
  assert.equal(odd.returnValue,'0x52');assert.equal(odd.orderedStores.length,3);
  assert(even.path.some(x=>x.pc===10&&x.opcode===4));assert(!odd.path.some(x=>x.pc===10));
  assert(p.graph.complete);assert(p.graph.nodes.every(n=>n.source.bytes&&n.decoded.stateEffects.memory));
});
test('same position with different rolling keys stays distinct; invalid targets and state caps never become returns',()=>{
  const g=buildBytecodeGraph({codeHex:'0600',decoder:'xor-key-v1',initialKey:0,sourceSha256:'a'.repeat(64)});
  assert(g.unresolvedEdges.length);assert.equal(g.nodes[0].decoded.kind,'jump');
  const sameAddress=g.nodes.filter(n=>n.identity.bytecodePosition===0);assert.equal(sameAddress.length,2);
  assert.notEqual(sameAddress[0].identity.decodeState.key,sameAddress[1].identity.decodeState.key);assert.notEqual(sameAddress[0].id,sameAddress[1].id);
  const a=decodeBytecode(Buffer.from('00','hex'),0,0,'xor-key-v1'),b=decodeBytecode(Buffer.from('00','hex'),0,1,'xor-key-v1');
  assert.notEqual(a.opcode,b.opcode);
  const limited=buildBytecodeGraph({codeHex:branchMemoryCode.toString('hex'),sourceSha256:bytecodeHash(branchMemoryCode),stateLimit:2});
  assert.equal(limited.complete,false);assert(limited.unresolvedEdges.some(e=>/budget|not-decoded/.test(e.reason)));
  assert(limited.edges.every(e=>limited.nodes.some(n=>n.id===e.to)));
  assert.throws(()=>executeBytecode({codeHex:'0600',decoder:'plain',initialKey:0},0n,{stepLimit:8}),{code:'VM_PROGRAM_LIMIT'});
});
test('forged model, bytecode, contract memory footprint and mutable source never acquire a verifier pass',async t=>{
  const f=fixture(t),p=await f.program(),record=f.analysis.artifacts.get(p.ref.id).result;
  record.model.codeHex='00';const forged=f.save('vm-executable-program','derive',record);
  const before=fs.readdirSync(f.analysis.artifacts.directory('records')).length;
  await assert.rejects(f.call('function_check',{program_ref:forged}),/semantic model changed/);
  assert.equal(fs.readdirSync(f.analysis.artifacts.directory('records')).length,before);
  fs.writeFileSync(p.file,'changed');await assert.rejects(f.call('program',{image_ref:{path:p.file,sha256:p.contract.targetSha256},contract_ref:p.contractRef}),/SHA differs/);
  const c=bytecodeContract(bytecodeHash(branchMemoryCode));c.outputs.memory=[];assert.throws(()=>deriveExecutableProgram(branchMemoryCode,c),/layout differs/);
  const fresh=deriveExecutableProgram(branchMemoryCode,bytecodeContract(bytecodeHash(branchMemoryCode)));fresh.graph.nodes[0].decoded.kind='return-output';
  assert.throws(()=>verifyFiniteFunction({program:fresh,contract:bytecodeContract(bytecodeHash(branchMemoryCode))}),/source differs/);
});
test('raw context validation rebinds actual bytes and entry inputs; metadata-only candidate derivation cannot launder altered bodies',async t=>{
  const f=fixture(t),a=await buildPhaseContextCase(f.analysis,f.cfg,{runId:'first',inputValue:'0x1'}),b=await buildPhaseContextCase(f.analysis,f.cfg,{runId:'held-out',inputValue:'0x2'});
  const c=bytecodeContract('a'.repeat(64));c.normalReturn='native-ret';
  const contractRef=f.ref(await f.call('declare_contract',{contract:c}));
  const comparison=f.ref(await f.call('role_compare',{context_refs:[f.ref(a.model),f.ref(b.model)],contract_ref:contractRef}));
  const v=await f.call('role_validate',{comparison_ref:comparison,recording_bindings:[a,b].map(x=>({context_ref:f.ref(x.model),recordings:[x.debugRef]}))});
  const r=f.analysis.artifacts.get(v.reportId).result;
  assert.equal(r.independence.rawCaptureRevalidated,true);assert.equal(r.independence.distinctEntryInputs,2);assert.equal(r.independence.distinctObservedRuns,2);
  assert(r.runs.every(row=>row.matchedGroups===16));assert.equal(r.vmRoleProved,false);assert.equal(r.independence.independentVmInstances,'unknown');
  assert(r.predictions.some(p=>p.heldOut.every(x=>x.status==='matches-recorded-relation')));
  const bad=await buildPhaseContextCase(f.analysis,f.cfg,{tamperBody:true}),badComparison=f.ref(await f.call('role_compare',{context_refs:[f.ref(bad.model)],contract_ref:contractRef}));
  await assert.rejects(f.call('role_validate',{comparison_ref:badComparison,recording_bindings:[{context_ref:f.ref(bad.model),recordings:[bad.debugRef]}]}),/no longer matches/);
});

test('different contexts and entry values from the same raw run do not establish cross-run independence',async t=>{
  const f=fixture(t),a=await buildPhaseContextCase(f.analysis,f.cfg,{runId:'same-raw-run',inputValue:'0x1'}),b=await buildPhaseContextCase(f.analysis,f.cfg,{runId:'same-raw-run',inputValue:'0x2'});
  const c=bytecodeContract('a'.repeat(64));c.normalReturn='native-ret';
  const contractRef=f.ref(await f.call('declare_contract',{contract:c}));
  const comparison=f.ref(await f.call('role_compare',{context_refs:[f.ref(a.model),f.ref(b.model)],contract_ref:contractRef}));
  const v=await f.call('role_validate',{comparison_ref:comparison,recording_bindings:[a,b].map(x=>({context_ref:f.ref(x.model),recordings:[x.debugRef]}))});
  const r=f.analysis.artifacts.get(v.reportId).result;
  assert.equal(r.independence.rawCaptureRevalidated,true);
  assert.equal(r.independence.distinctEntryInputs,2);
  assert.equal(r.independence.distinctObservedRuns,1);
  assert.equal(r.status,'insufficient-independent-runs');
  assert.equal(r.vmRoleProved,false);
});

test('independent Python interpreter/reference reproduces both finite transcripts and rejects a fresh forged proof upgrade',async t=>{
  const f=fixture(t),python=fileURLToPath(new URL('../runtimes/ghidra/python/python.exe',import.meta.url)),audit=fileURLToPath(new URL('./audit_vm_function.py',import.meta.url));
  for(const image of [branchMemoryCode,ownedVmImage(),ownedBranchVmFixture().image]) {
    const p=await f.program(image),v=await f.call('function_check',{program_ref:p.ref});
    const run=spawnSync(python,['-I','-B',audit,v.reportPath],{encoding:'utf8',timeout:15000,maxBuffer:256*1024,windowsHide:true});
    assert.equal(run.status,0,run.stderr);assert.equal(JSON.parse(run.stdout).cases,256);
    const forged=f.analysis.artifacts.get(v.reportId).result;forged.universalProof=true;
    const ref=f.save('vm-function-assessment','assess',forged),bad=spawnSync(python,['-I','-B',audit,path.join(f.analysis.artifacts.directory('records'),ref.id+'.json')],{encoding:'utf8',timeout:15000,maxBuffer:256*1024,windowsHide:true});
    assert.notEqual(bad.status,0);assert.match(bad.stderr,/universalProof/);
  }
});
test('cancellation retains the original data-worker cleanup boundary and publishes no function pass',async t=>{
  const f=fixture(t),p=await f.program(),controller=new AbortController();controller.abort();f.mgr.scope={getStore:()=>({signal:controller.signal})};
  const before=fs.readdirSync(f.analysis.artifacts.directory('records')).length;
  await assert.rejects(f.call('function_check',{program_ref:p.ref}),{code:'ABORT_ERR'});
  assert.equal(f.analysis.jobs.active,null);assert.equal(fs.readdirSync(f.analysis.artifacts.directory('records')).length,before);
});
