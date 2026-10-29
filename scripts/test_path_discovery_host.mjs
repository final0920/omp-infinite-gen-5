import test from'node:test';import assert from'node:assert/strict';import fs from'node:fs';import os from'node:os';import path from'node:path';
import{validateDiscovery,validateDiscoveryResult,runDiscovery,DISCOVERY_PIN}from'../source/path_discovery_jobs.js';
import{AnalysisArtifacts,hashBytes}from'../source/analysis_artifacts.js';import{defineIntegrationTools}from'../integration_tools.js';
const RUNTIME='8fc4ae42f775f0139aa5f184c912db71f77e68d661c14564ab6f4820d434abea';
function pe(code='90c3'){
 const b=Buffer.alloc(1024);b.write('MZ');b.writeUInt32LE(0x80,0x3c);b.writeUInt32LE(0x4550,0x80);b.writeUInt16LE(0x8664,0x84);b.writeUInt16LE(1,0x86);b.writeUInt16LE(0xf0,0x94);b.writeUInt16LE(0x22,0x96);
 const o=0x98;b.writeUInt16LE(0x20b,o);b.writeUInt32LE(0x1000,o+16);b.writeBigUInt64LE(0x140000000n,o+24);b.writeUInt32LE(0x1000,o+32);b.writeUInt32LE(0x200,o+36);b.writeUInt32LE(0x2000,o+56);b.writeUInt32LE(0x200,o+60);b.writeUInt32LE(16,o+108);
 const s=o+0xf0;b.write('.text',s);b.writeUInt32LE(0x200,s+8);b.writeUInt32LE(0x1000,s+12);b.writeUInt32LE(0x200,s+16);b.writeUInt32LE(0x200,s+20);b.writeUInt32LE(0x60000020,s+36);Buffer.from(code,'hex').copy(b,0x200);return b;
}
const data=pe(),selected={ea:'0x140001000',max_instructions:128,follow_direct_calls:false};
function report(){return{schema:'ig5-path-discovery-v1',status:'partial',recoveryStatus:'unverified',targetSha256:hashBytes(data),runtimeManifestPin:RUNTIME,decoderManifestPin:DISCOVERY_PIN,decoder:'pinned-triton-disassembly-only',entry:selected.ea,maxInstructions:128,followDirectCalls:false,candidateOnly:true,pathSemanticsValidated:false,nativeReachabilityProved:false,nativeTargetExecuted:false,databaseModified:false,businessAccepted:false,wholeBinaryVerified:false,candidatePath:['0x140001000','0x140001001'],instructions:[{ea:'0x140001000',size:1,bytes:'90',text:'nop',controlFlow:false,branch:false,control:{kind:'fallthrough',successors:['0x140001001']}},{ea:'0x140001001',size:1,bytes:'c3',text:'ret',controlFlow:true,branch:false,control:{kind:'return',successors:[]}}],stop:{reason:'return',next:null}};}
const check=r=>validateDiscoveryResult(r,selected,data,hashBytes(data));
test('candidate scope and byte-backed forward path validate without claiming semantics',()=>{assert.doesNotThrow(()=>check(report()));assert.deepEqual(validateDiscovery({target:'C:/owned.exe',level:'discover',ea:'0X140001000'.replace('0X','0x')}),selected);});
test('discovery refuses observations, decoder injection, irrelevant parameters and enlarged limits',()=>{
 const a={target:'C:/owned.exe',level:'discover',ea:'0x140001000'};
 for(const extra of [{initial_flags:'0x0'},{projection_path:['0x140001000']},{projection_decoder:'java'},{composition_plan:{}},{max_instructions:129},{max_instructions:0},{max_instructions:true},{max_instructions:null},{follow_direct_calls:1},{follow_direct_calls:null},{ea:'0x0'},{ea:'0x10000000000000000'},{target:'relative.exe'},{action:'analyze'}])assert.throws(()=>validateDiscovery({...a,...extra}));
});
test('following direct calls must be explicitly requested and retains exact callee/return-address bytes',()=>{
 const b=pe('e800000000c3'),r=report();r.targetSha256=hashBytes(b);r.followDirectCalls=true;r.candidatePath=['0x140001000','0x140001005'];r.instructions[0]={ea:'0x140001000',size:5,bytes:'e800000000',text:'call 0x140001005',controlFlow:true,branch:false,control:{kind:'call',successors:['0x140001005'],returnAddress:'0x140001005'}};r.instructions[1].ea='0x140001005';assert.doesNotThrow(()=>validateDiscoveryResult(r,{...selected,follow_direct_calls:true},b,hashBytes(b)));assert.throws(()=>validateDiscoveryResult(r,selected,b,hashBytes(b)));
 r.instructions[0].control.returnAddress='0x140001006';assert.throws(()=>validateDiscoveryResult(r,{...selected,follow_direct_calls:true},b,hashBytes(b)));
});
const mutations={
 'changed original byte':r=>r.instructions[0].bytes='91',
 'wrong target digest':r=>r.targetSha256='a'.repeat(64),
 'wrong dependency pin':r=>r.decoderManifestPin='a'.repeat(64),
 'semantics upgraded':r=>r.pathSemanticsValidated=true,
 'business upgraded':r=>r.businessAccepted=true,
 'path order lost':r=>r.candidatePath.reverse(),
 'size fabricated':r=>r.instructions[0].size=2,
 'successor fabricated':r=>r.instructions[0].control.successors=['0x140001003'],
 'control says fallthrough on return':r=>r.instructions[1].controlFlow=false,
 'stop omitted':r=>delete r.stop,
 'cycle falsely reported':r=>r.stop={reason:'cycle',next:'0x140001000'},
 'budget falsely reported':r=>r.stop={reason:'instruction-budget',next:'0x140001002'},
 'overlap inserted':r=>r.instructions[1].ea='0x140001000',
 'address outside executable bytes':r=>{r.instructions[0].ea=r.entry='0x140000000';r.candidatePath[0]=r.entry;},
 'stopping terminal dropped':r=>r.stop={reason:'return',next:null,proof:true},
};
for(const[n,mutate]of Object.entries(mutations))test('reject discovery '+n,()=>{const r=report();mutate(r);assert.throws(()=>check(r));});
test('nonexecutable section and malformed PE byte mapping refuse',()=>{
 const noexec=Buffer.from(data);noexec.writeUInt32LE(0x40000020,0x188+36);assert.throws(()=>validateDiscoveryResult(report(),selected,noexec,hashBytes(data)));
 const outside=Buffer.from(data);outside.writeUInt32LE(0xfffffff0,0x188+20);assert.throws(()=>validateDiscoveryResult(report(),selected,outside,hashBytes(data)));
 assert.throws(()=>validateDiscoveryResult(report(),selected,Buffer.from('MZ'),hashBytes(data)));
});
test('busy/cancelled requests stop before target I/O and discovery shares the owned pool',async()=>{
 const args={target:'C:/does-not-exist.exe',level:'discover',ea:'0x1000'};
 await assert.rejects(runDiscovery({closed:false,active:new Set([1,2])},args),/busy/);await assert.rejects(runDiscovery({closed:true,active:new Set()},args),/cancelled/);
 const mgr={lifter:{closed:true,active:new Set()}},t=defineIntegrationTools(mgr,{projectRoot:'C:/fixture'}).find(t=>t.name==='ig5_ir');assert(t.parameters.properties.level.enum.includes('discover'));await assert.rejects(t.execute(args),/cancelled/);
});
test('actual artifact import binds private stdout digest and keeps candidate-only metadata',async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'ig5-discovery-host-')),target=path.join(directory,'owned.exe');fs.writeFileSync(target,data);
 const artifacts=new AnalysisArtifacts(path.join(directory,'analysis'));fs.mkdirSync(path.join(artifacts.root,'jobs'));const jobs={closed:false,active:new Set(),artifacts,async request(p,_signal,kind){assert.equal(kind,'discover');const raw=Buffer.from(JSON.stringify(report())+'\n');fs.writeFileSync(path.join(artifacts.root,'jobs',p.job_id,'stdout.log'),raw);return{targetSha256:p.sha256,runtimeManifestPin:RUNTIME,outputBytes:raw.length,outputSha256:hashBytes(raw),processBudgetMs:49000,sharedBudgetMs:50000,process:{status:'completed',exitCode:0,limitReason:null,pid:1234,elapsedMs:100,childExitConfirmed:true,jobAssignedAtCreation:true,activeProcessLimit:1,memoryLimitBytes:2147483648}};}};
 try{const r=await runDiscovery(jobs,{target,level:'discover',ea:selected.ea});assert(r.candidateOnly);assert.equal(r.pathSemanticsValidated,false);assert.equal(r.instructionCount,2);assert.equal(hashBytes(fs.readFileSync(r.reportPath)),r.reportSha256);}
 finally{await artifacts.dispose();/* Retain small owned fixture/evidence; no recursive deletion. */}
});
