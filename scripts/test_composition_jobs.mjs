// Plain-data/transport fixtures only. No Python, decoder, PE or database executes.
import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID,createHash } from 'node:crypto';
import { LiftJobs } from '../source/lift_jobs.js';
import { PROJECTION_RUNTIME_PIN } from '../source/projection_jobs.js';
import { validateComposition,validateCompositionPlan,resolveCompositionPlan,compositionAddresses,runComposition } from '../source/composition_jobs.js';
import { defineIntegrationTools } from '../integration_tools.js';

const directory=fs.mkdtempSync(path.join(os.tmpdir(),'ig5-composition-jobs-'));
const target=path.join(directory,'data.bin');fs.writeFileSync(target,'inert input, never executed');
const selected={target,level:'compose',composition_plan:{strategy:'sequence',paths:[['0x140001000']]}};
const tick=()=>new Promise(resolve=>setImmediate(resolve));
const request=()=>({job_id:randomUUID(),sha256:'a'.repeat(64),...validateComposition(selected)});
const ack=(child,result={ok:true})=>child.frame({id:1,nonce:child.sent[0].params.nonce,cleanupConfirmed:true,result});
function fixture(onRequest){
 const children=[];
 const jobs=new LiftJobs({artifactDir:path.join(directory,randomUUID()),host:{id:'win32-x64'},requestTimeoutMs:2000,
  ghidra:{available:true,pythonExe:'never-started.exe'}},{stopTimeoutMs:50,spawnProcess(exe,args,options){
   assert.equal(exe,'never-started.exe');assert.equal(options.windowsHide,true);assert.equal(options.shell,undefined);
   const child=new EventEmitter();Object.assign(child,{pid:91000+children.length,args,sent:[],kills:0,stdout:new EventEmitter(),stderr:new EventEmitter(),stdin:new EventEmitter()});
   child.frame=value=>child.stdout.emit('data',Buffer.from(JSON.stringify(value)+'\n'));
   child.exit=()=>{if(!child.exited){child.exited=true;child.emit('exit',0);}};
   child.close=()=>{if(!child.closed){child.closed=true;child.emit('close',0);}};
   child.finish=()=>{child.exit();child.close();};child.kill=()=>{child.kills++;};
   child.stdin.write=raw=>{const message=JSON.parse(raw);child.sent.push(message);onRequest?.(child,message);};child.stdin.end=()=>{};
   children.push(child);queueMicrotask(()=>child.frame({ig5:'ready'}));return child;
  }});return {jobs,children};
}
function reportData(params){
 const names='rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15'.split(' ');
 const registers=Object.fromEntries(names.map((n,i)=>[n,i]));
 const nodes=names.map((name,id)=>({id,op:'input',type:'bv',bits:64,args:[],name}));
 nodes.push({id:16,op:'initial_memory',type:'memory',args:[],name:'M0'},
  {id:17,op:'const',type:'bv',bits:8,args:[],value:'0x1'},
  {id:18,op:'const',type:'bv',bits:64,args:[],value:'0x140001001'});
 const control={kind:'fallthrough',target:18,source:'0x140001000'};
 const instruction={ea:'0x140001000',size:1,codeBytes:'90',mnemonic:'NOP',operands:'',pcode:[]};
 return {schema:'ig5-pcode-composition-v1',representationSchema:'ig5-internal-closed-path-composition-v1',status:'translated-unverified',
  publicToolRouteExposed:true,backend:'fixture data',targetSha256:params.sha256,runtimeManifestPin:PROJECTION_RUNTIME_PIN,
  nativeTargetExecuted:false,databaseModified:false,businessAccepted:false,wholeBinaryVerified:false,
  compositionPlan:params.composition_plan,decodedPath:[{ea:'0x140001000',bytes:'90',decoded:{ea:'0x140001000',size:1,mnemonic:'NOP',operands:'',pcode:[]}}],
  decodeStatistics:{instructions:1,rawPcodeOperations:0,providedAddressOccurrences:1},
  initialRegisters:registers,registers,initialMemory:16,currentMemory:16,pathGuard:17,control,stores:[],sideExits:[],
  steps:[0],templates:[{id:0,instructions:[instruction],initialFlagsSupplied:false,flagsExported:false}],
  boundaries:[{stepIndex:0,templateIndex:0,entryGuard:17,continuedGuard:17,registers,currentMemory:16,control}],
  dag:{nodes,references:56,depth:1},statistics:{templates:1,steps:1,distinctInstructions:1,logicalInstructions:1,logicalPcodeOperations:0,expandedMemoryBytes:0,dagNodes:19},
  memoryNormalization:{method:'exact-ordered-byte-forwarding',maxStoreVisits:4096,storeVisits:0,forwardedBytes:0,disjointStoreBypasses:0,
   unknownAliasFallbacks:0,budgetFallbacks:0,cacheHits:0,observedValuesUsed:false,independentSMTProof:false},
  compositionLimits:{steps:64,distinctInstructions:128,logicalInstructions:1024,logicalPcodeOperations:65536,memoryBytes:1024,dagNodes:2048,dagReferences:8192,dagDepth:128,reportBytes:4*1024**2},scope:{evidence:'fixture only'}};
}
function reportFixture(change=()=>{}){
 const h=fixture();h.jobs.request=async(params,_signal,kind)=>{
  assert.equal(kind,'compose');const result=reportData(params);
  const reply={runtimeManifestPin:PROJECTION_RUNTIME_PIN,targetSha256:params.sha256,
   process:{childExitConfirmed:true,status:'completed',exitCode:0,jobAssignedAtCreation:true,activeProcessLimit:1,memoryLimitBytes:2*1024**3}};
  const mutation=change(result,reply)||{};const bytes=Buffer.from(JSON.stringify(result));
  fs.writeFileSync(path.join(h.jobs.artifacts.root,'jobs',params.job_id,'stdout.log'),bytes,{flag:'wx'});
  return {...reply,outputBytes:bytes.length,outputSha256:createHash('sha256').update(bytes).digest('hex'),...mutation};
 };return h;
}

test('composition preserves uint64 addresses, immutable plans and between-template repeats',()=>{
 const plan={strategy:'sequence',paths:[['0xABCDEF0123456789','0xffffffffffffffff'],['0xABCDEF0123456789']]};const before=structuredClone(plan);
 const actual=validateCompositionPlan(plan);assert.deepEqual(plan,before);
 assert.deepEqual(actual.paths[0],['0xabcdef0123456789','0xffffffffffffffff']);assert.equal(actual.indirect_mode,'reject');
 assert.deepEqual(compositionAddresses(actual),actual.paths[0]);
 const loop=validateCompositionPlan({strategy:'constant-loop',prefix:['0x1'],body:['0x2'],suffix:[['0x3']],indirect_mode:'guarded-target'});
 assert.deepEqual(compositionAddresses(loop),['0x1','0x2','0x3']);
});
test('composition refuses guessed counts, observed values, summaries, malformed paths and mixed plans',()=>{
 const plans=[null,[],{}, {strategy:'other',paths:[['0x1']]},{strategy:'sequence'},
  ...['body','certificate','repeat_count','initial_flags','input_values','worker'].map(key=>({...selected.composition_plan,[key]:32})),
  ...[[],['0x0'],['0x1','0x01'],['0x10000000000000000'],[1],['1'],Array(1)].map(p=>({strategy:'sequence',paths:[p]})),
  ...[null,true,'guarded',1].map(indirect_mode=>({strategy:'sequence',paths:[['0x1']],indirect_mode})),
  {strategy:'constant-loop',prefix:['0x1'],body:['0x2'],suffix:[]},
  {strategy:'constant-loop',prefix:['0x1'],body:['0x2'],suffix:[['0x3']],paths:[['0x4']]}];
 for(const p of plans)assert.throws(()=>validateCompositionPlan(p));
 let accessed=0;const accessor={paths:[['0x1']]};Object.defineProperty(accessor,'strategy',{get(){accessed++;return 'sequence';},enumerable:true});
 assert.throws(()=>validateCompositionPlan(accessor));assert.equal(accessed,0);
});
test('composition counts provided occurrences and distinct addresses, not just templates',()=>{
 const addresses=n=>Array.from({length:n},(_,i)=>'0x'+(i+1).toString(16));
 assert.doesNotThrow(()=>validateCompositionPlan({strategy:'sequence',paths:Array(64).fill(addresses(16))}));
 for(const paths of [[],Array(65).fill(['0x1']),Array(61).fill(addresses(17)),[addresses(128),['0x81']],[addresses(129)]]) {
  assert.throws(()=>validateCompositionPlan({strategy:'sequence',paths}));
 }
});
test('all cross-mode parameters reject before I/O and other levels refuse composition_plan',async()=>{
 let calls=0;const forbidden=()=>{calls++;throw new Error('unexpected route');};
 const mgr={get:forbidden,rpc:forbidden,lifter:{request:forbidden},trace:{run:forbidden},kernel:{run:forbidden}};
 const tool=defineIntegrationTools(mgr,{projectRoot:directory}).find(t=>t.name==='ig5_ir');
 assert(tool.parameters.properties.level.enum.includes('compose'));assert.equal(tool.parameters.properties.composition_plan.properties.paths.maxItems,64);
 for(const level of ['raw','high','kernel','trace','lift','project'])await assert.rejects(async()=>tool.execute({...selected,level}),/compose/);
 for(const [key,value] of Object.entries({ea:'0x1',initial_flags:'0x0',projection_path:['0x1'],projection_mode:'strict',projection_registers:['rax'],traces:[],lift_inline:[],action:'analyze',max_blocks:1,expression:'rax',worker:'other.py'})) {
  await assert.rejects(async()=>tool.execute({...selected,[key]:value}));
 }
 assert.equal(calls,0);
});
test('compose and project share fixed owned worker and two-slot capacity',async()=>{
 const h=fixture();const first=h.jobs.request(request(),undefined,'compose'),second=h.jobs.request({job_id:randomUUID()},undefined,'project');await tick();
 assert.deepEqual(h.children.map(c=>c.sent[0].method),['compose','project']);
 assert(h.children.every(c=>c.args.some(a=>a.endsWith(path.join('worker','ig5_project.py')))));
 await assert.rejects(h.jobs.request({},undefined,'lift'),/maximum two/);
 const [a,b]=h.children;a.frame({id:1,nonce:b.sent[0].params.nonce,cleanupConfirmed:true,result:{wrong:true}});await tick();assert.equal(h.jobs.active.size,2);
 ack(a);await first;assert.equal(h.jobs.active.size,2);a.finish();assert.equal(h.jobs.active.size,1);assert.equal(b.kills,0);
 ack(b);await second;b.finish();await h.jobs.dispose();assert.equal(h.jobs.active.size,0);
});
test('compose cancellation retains owner until ACK plus exit and leaves companion untouched',async()=>{
 const h=fixture((child,message)=>{if(message.id===0)queueMicrotask(()=>ack(child));});const controller=new AbortController();
 const first=h.jobs.request(request(),controller.signal,'compose'),second=h.jobs.request({},undefined,'project');await tick();controller.abort();
 await assert.rejects(first,/cancelled/);assert.equal(h.jobs.active.size,2);const [a,b]=h.children;
 assert.deepEqual(a.sent[1],{id:0,method:'cancel',params:{requestId:1,nonce:a.sent[0].params.nonce}});assert.equal(b.sent.length,1);assert.equal(b.kills,0);
 a.finish();ack(b);await second;b.finish();await h.jobs.dispose();assert.equal(h.jobs.active.size,0);
});
test('compose missing cleanup ACK retains owner after actual root exit',async()=>{
 const h=fixture((child,m)=>{if(m.id===1)queueMicrotask(()=>child.finish());});
 await assert.rejects(h.jobs.request(request(),undefined,'compose'),/worker exited/);assert.equal(h.jobs.active.size,1);
 await assert.rejects(h.jobs.dispose(),/cleanup unconfirmed/);
});
test('compose drains matching final ACK after root exit and before stdout close',async()=>{
 const h=fixture();const pending=h.jobs.request(request(),undefined,'compose');await tick();const [child]=h.children;
 child.exit();await tick();assert.equal(h.jobs.active.size,1);ack(child,{drained:true});child.close();
 assert.deepEqual(await pending,{drained:true});assert.equal(h.jobs.active.size,0);await h.jobs.dispose();
});
test('compose imports bounded immutable multiline report with unverified state scope',async()=>{
 const h=reportFixture(),tool=defineIntegrationTools({lifter:h.jobs},{projectRoot:directory}).find(t=>t.name==='ig5_ir');
 const value=await tool.execute(selected);assert.equal(value.status,'partial');assert.equal(value.recoveryStatus,'unverified');
 assert.equal(value.businessAccepted,false);assert.equal(value.wholeBinaryVerified,false);assert.equal(h.children.length,0);
 const bytes=fs.readFileSync(value.reportPath);assert.equal(createHash('sha256').update(bytes).digest('hex'),value.reportSha256);
 const record=JSON.parse(bytes);assert.deepEqual(record.result.compositionPlan,validateComposition(selected).composition_plan);
 assert.equal(value.dagReferences,record.result.dag.references);
 assert(bytes.includes(10));assert.deepEqual(h.jobs.artifacts.get(value.reportId),record);await h.jobs.dispose();
});
test('inconsistent plan, process, flags closure, references or work cannot commit a report',async()=>{
 const changes=[r=>{r.schema='other';},r=>{r.publicToolRouteExposed=false;},r=>{r.targetSha256='0'.repeat(64);},r=>{r.runtimeManifestPin='0'.repeat(64);},
  r=>{r.compositionPlan={strategy:'sequence',paths:[['0x2']]};},r=>{r.decodedPath=[{ea:'0x2'}];},r=>{r.businessAccepted=true;},
  r=>{delete r.registers.rax;},r=>{r.pathGuard=999;},r=>{r.dag.references--;},r=>{r.dag.depth=129;},r=>{r.statistics.logicalInstructions=1025;},
  r=>{r.statistics.expandedMemoryBytes=1025;},r=>{r.templates[0].flagsExported=true;},r=>{r.boundaries[0].stepIndex=1;},
  r=>{r.statistics.logicalInstructions=2;},r=>{r.templates[0].instructions[0].codeBytes='91';},r=>{r.decodeStatistics.providedAddressOccurrences=2;},
  r=>{r.inferredRepeat={observedValuesUsed:true};},(_r,p)=>{p.process.childExitConfirmed=false;},(_r,p)=>{p.process.jobAssignedAtCreation=false;},
  r=>{delete r.memoryNormalization;},r=>{r.memoryNormalization.observedValuesUsed=true;},r=>{r.memoryNormalization.storeVisits=4097;},
  (_r,p)=>{p.process.activeProcessLimit=2;},(_r,p)=>{p.process.memoryLimitBytes=4*1024**3;},(_r,p)=>{p.process.status='limited';},
  ()=>({outputSha256:'0'.repeat(64)}),()=>({outputBytes:1})];
 for(const change of changes){const h=reportFixture(change);await assert.rejects(runComposition(h.jobs,selected));
  assert.deepEqual(fs.readdirSync(path.join(h.jobs.artifacts.root,'records')),[]);await h.jobs.dispose();}
});
test('compose formatting expansion is charged against final 4 MiB report budget',async()=>{
 const h=reportFixture(r=>{r.formattingBudgetFixture=Array(600000).fill(0);});
 await assert.rejects(runComposition(h.jobs,selected),error=>error.code==='RESULT_LIMIT');
 assert.deepEqual(fs.readdirSync(path.join(h.jobs.artifacts.root,'records')),[]);await h.jobs.dispose();
});
test('busy or pre-cancelled compose does not read a missing target or stage a job',async()=>{
 const h=fixture(),args={...selected,target:path.join(directory,'missing.bin')};const controller=new AbortController();controller.abort();
 await assert.rejects(runComposition(h.jobs,args,controller.signal),/cancelled/);h.jobs.active.add({});h.jobs.active.add({});
 await assert.rejects(runComposition(h.jobs,args),/maximum two/);assert.deepEqual(fs.readdirSync(path.join(h.jobs.artifacts.root,'jobs')),[]);
 assert.equal(h.children.length,0);h.jobs.active.clear();await h.jobs.dispose();
});
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
function planFile(bytes=Buffer.from(JSON.stringify(selected.composition_plan))){
 const file=path.join(directory,randomUUID()+'.json');fs.writeFileSync(file,bytes);
 return {target,level:'compose',composition_plan_ref:{path:file,sha256:sha(bytes)}};
}
test('plan reference is exclusive data with exact fields; every other level refuses it before routing',async()=>{
 const args=planFile();assert.deepEqual(validateComposition(args),{composition_plan_ref:args.composition_plan_ref});
 const bad=[{target,level:'compose'}, {...args,composition_plan:selected.composition_plan},
  ...[null,[],{}, {path:args.composition_plan_ref.path}, {...args.composition_plan_ref,certificate:true},
   {...args.composition_plan_ref,path:'relative.json'}, {...args.composition_plan_ref,path:'x'.repeat(4097)},
   {...args.composition_plan_ref,sha256:'A'.repeat(64)}, {...args.composition_plan_ref,sha256:12}].map(composition_plan_ref=>({...args,composition_plan_ref}))];
 for(const value of bad)assert.throws(()=>validateComposition(value));
 let accessed=0;const ref={sha256:args.composition_plan_ref.sha256};Object.defineProperty(ref,'path',{enumerable:true,get(){accessed++;return args.composition_plan_ref.path;}});
 assert.throws(()=>validateComposition({...args,composition_plan_ref:ref}));assert.equal(accessed,0);
 const tool=defineIntegrationTools({get(){throw Error('unexpected route');}},{projectRoot:directory}).find(t=>t.name==='ig5_ir');
 assert.deepEqual(tool.parameters.properties.composition_plan_ref.required,['path','sha256']);
 for(const level of ['raw','high','kernel','trace','lift','project'])await assert.rejects(async()=>tool.execute({...args,level}),/compose/);
});
test('a 64-application reference preserves all ordered addresses and binds normalized data separately',()=>{
 const raw={strategy:'sequence',paths:Array.from({length:64},()=>['0xABCDEF0123456789','0xFFFFFFFFFFFFFFFF'])};
 const bytes=Buffer.from(JSON.stringify(raw,null,2)+'\n'),args=planFile(bytes),actual=resolveCompositionPlan(validateComposition(args));
 const expected=validateCompositionPlan(raw);assert.deepEqual(actual.selected,{composition_plan:expected});assert.deepEqual(actual.planBytes,bytes);
 assert.equal(actual.compositionInput.pathApplications,64);assert.equal(actual.compositionInput.providedAddressOccurrences,128);
 assert.equal(actual.compositionInput.distinctInstructions,2);assert.equal(actual.compositionInput.sha256,sha(bytes));
 assert.equal(actual.compositionInput.normalizedPlanSha256,sha(Buffer.from(JSON.stringify(expected))));
 assert.notEqual(actual.compositionInput.sha256,actual.compositionInput.normalizedPlanSha256);
 assert.deepEqual(JSON.parse(fs.readFileSync(args.composition_plan_ref.path)),raw);
});
test('file inputs keep original address-only validation, UTF-8, non-link and 64 KiB boundaries',()=>{
 for(const bytes of [Buffer.from('not JSON'),Buffer.from([0xff]),Buffer.from('\ufeff{}'),Buffer.from('null'),
  Buffer.from(JSON.stringify({...selected.composition_plan,repeat_count:32})),
  Buffer.from(JSON.stringify({strategy:'sequence',paths:[['0x1','0x01']]}))]) {
  const args=planFile(bytes);assert.throws(()=>resolveCompositionPlan(validateComposition(args)));
 }
 const base=Buffer.from(JSON.stringify(selected.composition_plan)),exact=Buffer.concat([base,Buffer.alloc(65536-base.length,32)]);
 assert.equal(resolveCompositionPlan(validateComposition(planFile(exact))).compositionInput.bytes,65536);
 const oversized=planFile(Buffer.concat([exact,Buffer.from(' ')]));
 assert.throws(()=>resolveCompositionPlan(validateComposition(oversized)),/exceeds/);
 const args=planFile();assert.throws(()=>resolveCompositionPlan(validateComposition({...args,composition_plan_ref:{...args.composition_plan_ref,sha256:'0'.repeat(64)}})),/SHA-256 mismatch/);
 const link=path.join(directory,randomUUID()+'.json');fs.symlinkSync(args.composition_plan_ref.path,link,'file');
 assert.throws(()=>resolveCompositionPlan(validateComposition({...args,composition_plan_ref:{...args.composition_plan_ref,path:link}})),/non-linked/);
 assert.throws(()=>resolveCompositionPlan(validateComposition({...args,composition_plan_ref:{...args.composition_plan_ref,path:directory}})),/regular/);
});
test('reference import sends only the normalized plan to worker and retains immutable source receipt/blob',async()=>{
 const args=planFile(),raw=fs.readFileSync(args.composition_plan_ref.path),h=reportFixture(),request=h.jobs.request;
 h.jobs.request=async(params,...rest)=>{
  assert.deepEqual(Object.keys(params).sort(),['composition_plan','job_id','sha256']);
  assert.deepEqual(params.composition_plan,validateComposition(selected).composition_plan);
  fs.writeFileSync(args.composition_plan_ref.path,'changed after snapshot');return request(params,...rest);
 };
 const value=await runComposition(h.jobs,args),record=JSON.parse(fs.readFileSync(value.reportPath));
 assert.deepEqual(record.compositionInput,value.compositionInput);assert.equal(value.compositionInput.pathApplications,1);
 assert.equal(value.compositionInput.sha256,sha(raw));assert.deepEqual(h.jobs.artifacts.read(value.compositionInput.ref).data,raw);
 assert.deepEqual(record.result.compositionPlan,validateComposition(selected).composition_plan);
 assert.equal(value.businessAccepted,false);assert.equal(value.wholeBinaryVerified,false);await h.jobs.dispose();
});
test('rejected worker request records verified file digest and exact64 counts without creating a report',async()=>{
 const raw={strategy:'sequence',paths:Array.from({length:64},()=>['0x140001000'])},args=planFile(Buffer.from(JSON.stringify(raw))),h=fixture();
 h.jobs.request=async(params)=>{assert.equal(params.composition_plan.paths.length,64);throw Object.assign(Error('expanded memory byte budget exceeded'),{code:'EXPECTED_REFUSAL'});};
 await assert.rejects(runComposition(h.jobs,args),error=>error.code==='EXPECTED_REFUSAL'&&error.message.includes(args.composition_plan_ref.sha256)&&
  error.message.includes('providedTemplates=64; addressOccurrences=64')&&error.message.includes('expanded memory byte budget exceeded'));
 assert.deepEqual(fs.readdirSync(path.join(h.jobs.artifacts.root,'records')),[]);
 assert.equal(h.jobs.artifacts.read('sha256:'+args.composition_plan_ref.sha256).data.toString(),JSON.stringify(raw));await h.jobs.dispose();
});
test('hash failure rejects before target reads/process/staging; busy and cancelled references do no I/O',async()=>{
 const args=planFile(),h=fixture();args.target=path.join(directory,'missing-target');args.composition_plan_ref.sha256='0'.repeat(64);
 await assert.rejects(runComposition(h.jobs,args),/SHA-256 mismatch/);
 assert.deepEqual(fs.readdirSync(path.join(h.jobs.artifacts.root,'jobs')),[]);assert.equal(h.children.length,0);
 args.composition_plan_ref.path=path.join(directory,'missing-plan');const controller=new AbortController();controller.abort();
 await assert.rejects(runComposition(h.jobs,args,controller.signal),/cancelled/);h.jobs.active.add({});h.jobs.active.add({});
 await assert.rejects(runComposition(h.jobs,args),/maximum two/);assert.equal(h.children.length,0);
 h.jobs.active.clear();await h.jobs.dispose();
});
test.after(()=>{assert.equal(fs.realpathSync(directory),path.resolve(directory));assert(path.basename(directory).startsWith('ig5-composition-jobs-'));fs.rmSync(directory,{recursive:true});});
