import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import path from 'node:path';import os from 'node:os';
import {smallVm} from './fixtures/vm_instance_cases.mjs';import {validateVmInstance,vmInstanceIdentity,compareVmInstances,executeSmallVm,checkVmInstances} from '../source/vm_instances.js';import {runRecoveryProfile,recoveryProfileSchema} from '../source/vm_recovery_profile.js';import {createAnalysisService} from '../analysis_tools.js';import {hashBytes} from '../source/analysis_artifacts.js';
test('identity binds code, bytecode, table, full decoder, run, memory epoch and declared role mapping',()=>{
 const base=smallVm(),variants=[smallVm({seed:1}),smallVm({tableSwap:true}),smallVm({bits:16}),smallVm({rotate:2}),smallVm({subtract:'operand-minus-acc'}),smallVm({runId:'other'}),smallVm({memoryEpoch:'next'}),smallVm({roles:{vip:'r12',accumulator:'r11',result:'r10'}}),{...base,codeSha256:'b'.repeat(64)}];
 for(const v of variants){const r=compareVmInstances([base,v]);assert.equal(r.pairs[0].status,'distinct');assert.equal(r.pairs[0].mergeAllowed,false);assert.equal(r.pairs[0].nativeMergeAllowed,false);}
 assert.equal(compareVmInstances([base,structuredClone(base)]).pairs[0].status,'same-declared-identity');
});
test('each missing identity field keeps identity unknown, including two equal unknown values',()=>{
 for(const k of ['codeSha256','table','decode','runId','memoryEpoch','roles']){const m=smallVm();m[k]=null;assert.equal(vmInstanceIdentity(m).id,null);assert.equal(compareVmInstances([m,structuredClone(m)]).pairs[0].status,'unknown');assert.equal(compareVmInstances([m,m]).pairs[0].mergeAllowed,false);}
});
test('correctly encoded different seeds retain behavior but identity differs; transplanted seed/table mapping does not silently generalize',()=>{
 const a=smallVm(),b=smallVm({seed:9}),c=smallVm({tableSwap:true}),bad={...a,decode:{...a.decode,seed:9}};
 assert.equal(executeSmallVm(a,'0x1','0x0').returnValue,executeSmallVm(b,'0x1','0x0').returnValue);assert.notEqual(executeSmallVm(a,'0x1','0x0').returnValue,executeSmallVm(c,'0x1','0x0').returnValue);assert.equal(executeSmallVm(bad,'0x1','0x0').status,'unknown');
});
test('HALT preserves initial result and distinguishes result from accumulator/input',()=>{
 const m=smallVm({haltOnly:true});assert.equal(executeSmallVm(m,'0x7','0x0').returnValue,'0x0');assert.equal(executeSmallVm(m,'0x7','0x39').returnValue,'0x39');const r=checkVmInstances([m]);assert.equal(r.checks[0].initialResultSensitivity,true);assert.equal(r.checks[0].status,'pass-in-finite-model');assert.equal(r.businessAccepted,false);
});
test('width, zero/full rotation boundaries and subtract direction independently reproduce finite results',()=>{
 for(const bits of [8,16,32,64])for(const rotate of [0,bits-1])for(const subtract of ['acc-minus-operand','operand-minus-acc'])assert.equal(checkVmInstances([smallVm({bits,rotate,subtract})]).checks[0].status,'pass-in-finite-model');
});
test('unknown table, missing HALT and truncated operands cannot pass',()=>{
 for(const bytecodeHex of ['ff','01','0200']){const r=checkVmInstances([{...smallVm(),bytecodeHex}]);assert.equal(r.checks[0].status,'unknown');assert.equal(r.allModelsChecked,false);}
});
test('extra claimed proof/oracle fields, invalid widths/roles/range and aggregate budget reject',()=>{
 for(const mutate of [m=>m.verified=true,m=>m.decode.bits=128,m=>m.roles.vip=m.roles.result,m=>m.contract.maximum='0x100',m=>m.table=[0]]){const m=smallVm();mutate(m);assert.throws(()=>validateVmInstance(m));}
 const m=smallVm();m.contract.maximum='0xff';assert.throws(()=>checkVmInstances([m,m,m]),/1024/);
});
function fixture(t){const root=fs.mkdtempSync(path.join(os.tmpdir(),'ig5-instances-')),cfg={artifactDir:path.join(root,'artifacts'),projectRoot:path.join(root,'projects')},analysis=createAnalysisService({},cfg),mgr={analysis,checkCancelled(){}};t.after(async()=>{await analysis.dispose();assert.equal(path.dirname(root),fs.realpathSync(os.tmpdir()));fs.rmSync(root,{recursive:true,force:true});});
 const call=(mode,input)=>runRecoveryProfile(mgr,{recovery:{[mode]:input}},cfg),source=model=>{const bytes=Buffer.from(JSON.stringify(model)),filename=path.join(root,hashBytes(bytes)+'.json');if(!fs.existsSync(filename))fs.writeFileSync(filename,bytes,{flag:'wx'});return {path:filename,sha256:hashBytes(bytes)};};return {root,analysis,mgr,call,source};}
test('existing recovery route captures exact source snapshots, checks in actual settled worker and retains old entry schemas',async t=>{
 const f=fixture(t),source=f.source(smallVm()),r=(await f.call('instances',{source_refs:[source]})).instances;assert.equal(r.identities.length,1);assert(recoveryProfileSchema.properties.function_check);assert(recoveryProfileSchema.properties.instances);fs.writeFileSync(source.path,'original may be removed after immutable capture');
 const result=(await f.call('instance_check',{comparison_ref:r.reportRef})).instance_check;assert.equal(result.checks[0].status,'pass-in-finite-model');assert.equal(f.analysis.jobs.active,null);const full=f.analysis.artifacts.get(result.reportRef.id).result;assert.equal(full.dataWorkerCleanupConfirmed,true);assert.equal(full.checks[0].transcript.length,32);
});
test('fresh SHA forged comparison, changed source bytes and extra invocation fields fail closed',async t=>{
 const f=fixture(t),s=f.source(smallVm()),r=(await f.call('instances',{source_refs:[s]})).instances,full=f.analysis.artifacts.get(r.reportRef.id).result;full.identities[0].id='a'.repeat(64);const forged=f.analysis.artifacts.save({kind:'vm-instance-comparison',action:'instances',result:full});
 await assert.rejects(f.call('instance_check',{comparison_ref:{id:forged.id,sha256:f.analysis.artifacts.metadata(forged.id).result.recordSha256}}));fs.appendFileSync(s.path,' ');await assert.rejects(f.call('instances',{source_refs:[s]}));await assert.rejects(f.call('instance_check',{comparison_ref:r.reportRef,oracle:'code'}));
});
test('cancelled check produces no new receipt and leaves original data worker slot free',async t=>{
 const f=fixture(t),s=f.source(smallVm()),r=(await f.call('instances',{source_refs:[s]})).instances,controller=new AbortController();controller.abort();f.mgr.scope={getStore:()=>({signal:controller.signal})};const before=fs.readdirSync(f.analysis.artifacts.directory('records')).length;
 await assert.rejects(f.call('instance_check',{comparison_ref:r.reportRef}),{code:'ABORT_ERR'});assert.equal(fs.readdirSync(f.analysis.artifacts.directory('records')).length,before);assert.equal(f.analysis.jobs.active,null);
});
