// Actual public tool / fixed protocol root / owned SLEIGH compute child.
// The generated PE is read only as data; no target binary is executed.
import assert from 'node:assert/strict';
import {spawn,spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
const scriptDir=path.dirname(fileURLToPath(import.meta.url));
const directory=process.argv[2],root=process.argv[3]||path.dirname(scriptDir);
const planReferences=process.argv[4]==='--plan-references';
assert(directory&&path.isAbsolute(directory)&&path.isAbsolute(root)&&(!process.argv[4]||planReferences),'Usage: node test_composition_runtime.mjs NEW-ABSOLUTE-OUTPUT [PLUGIN-ROOT] [--plan-references]');
assert.equal(fs.realpathSync(root),path.resolve(root));
const hash=b=>createHash('sha256').update(b).digest('hex');
const ref=p=>{const b=fs.readFileSync(p);return {path:p,bytes:b.length,sha256:hash(b)};};
const {buildPE64Fixture}=await import(pathToFileURL(path.join(root,'scripts/fixtures/pe64.mjs')));
const {defineIntegrationTools}=await import(pathToFileURL(path.join(root,'integration_tools.js')));
const {LiftJobs}=await import(pathToFileURL(path.join(root,'source/lift_jobs.js')));
fs.mkdirSync(directory,{recursive:false});assert.equal(fs.realpathSync(directory),path.resolve(directory));
const image=Buffer.from(buildPE64Fixture().image);image.fill(0x90,0x400,0x800);
const definitions=new Map();
const place=(rva,codes)=>codes.map(code=>{
 const ea='0x'+(0x140000000n+BigInt(rva)).toString(16),bytes=Buffer.from(code,'hex');
 assert(rva>=0x1000&&rva+bytes.length<=0x1400);bytes.copy(image,0x400+rva-0x1000);
 definitions.set(ea,code);rva+=bytes.length;return ea;
});
const linear=place(0x1000,['48b82a00000000000000','4889c1']);
const counter=place(0x1040,['bb03000000','4883eb01','75fa','4889d8']);
const dynamic=place(0x1080,['ffe0']),ret=place(0x10c0,['c3']),destination=place(0x1100,['4889c1']);
const store=place(0x1140,['488907','ffe2']),storeDestination=place(0x1180,['48891e']);
const flags=place(0x11c0,['f9','0f92c0']);
const memory=place(0x1200,['488b07','488b1e','ebf8']);
const tooMuchMemory=place(0x1240,['488b07','488906','448a07','ebf5']);
const nontermination=place(0x1280,['bb64000000','4883eb01','75fa','4889d8']);
const tooManyInstructions=place(0x12c0,['bb3f000000',...Array(20).fill('90'),'4883eb01','75e6','4889d8']);
const deepMemory=place(0x1300,['488b07','488906','ebf8']);
const sequence=(paths,guarded=false)=>({strategy:'sequence',paths,...(guarded?{indirect_mode:'guarded-target'}:{})});
const loop=addresses=>({strategy:'constant-loop',prefix:addresses.slice(0,-1),body:addresses.slice(1,-1),suffix:[addresses.slice(-1)]});
const cases=[
 {id:'sequence',plan:sequence(linear.map(a=>[a])),accepted:true},
 {id:'constant-loop',plan:loop(counter),accepted:true},
 {id:'guarded-indirect',plan:sequence([dynamic,destination],true),accepted:true},
 {id:'guarded-return',plan:sequence([ret,destination],true),accepted:true},
 {id:'guarded-stores',plan:sequence([store,storeDestination],true),accepted:true},
 {id:'memory-limit-exact',plan:sequence(Array(64).fill(memory)),accepted:true},
 {id:'indirect-default-rejected',plan:sequence([dynamic,destination]),accepted:false,error:'explicit guarded-target'},
 {id:'cross-template-flags-rejected',plan:sequence(flags.map(a=>[a])),accepted:false,error:'initial architectural flags'},
 {id:'memory-over-limit',plan:sequence(Array(64).fill(tooMuchMemory)),accepted:false,error:'expanded memory byte budget'},
 {id:'unknown-loop',plan:{strategy:'constant-loop',prefix:counter.slice(1,-1),body:counter.slice(1,-1),suffix:[counter.slice(-1)]},accepted:false,error:'constant closed-state condition'},
 {id:'loop-no-exit-within-limit',plan:loop(nontermination),accepted:false,error:'step budget'},
 {id:'expanded-instruction-over-limit',plan:loop(tooManyInstructions),accepted:false,error:'logical instruction budget'},
 {id:'memory-DAG-depth-over-limit',plan:sequence(Array(64).fill(deepMemory)),accepted:false,error:'DAG depth budget'},
];
const target=path.join(directory,'composition-fixture.exe');fs.writeFileSync(target,image,{flag:'wx'});const targetPin=ref(target);
const sourceNames=['integration_tools.js','source/composition_jobs.js','source/lift_jobs.js','source/worker_transport.js',
 'worker/ig5_project.py','worker/projection_worker.py','worker/composition_selection.py','worker/projection_composition.py',
 'worker/pcode_projection.py','worker/projection_call.py','worker/projection_flags.py','worker/projection_bsr.py','worker/projection_bsf.py','worker/composition_memory.py','worker/lift_process.py',
 'scripts/test_composition_runtime.mjs','scripts/test_composition_runtime_verify.py','scripts/fixtures/pe64.mjs','runtimes/manifest.json'];
const pins=sourceNames.map(name=>({name,...ref(path.join(root,name))}));
const processes=[],rows=[],python=path.join(root,'runtimes/ghidra/python/python.exe');
const cfg={artifactDir:directory,projectRoot:path.join(directory,'projects'),host:{id:'win32-x64'},requestTimeoutMs:60000,ghidra:{available:true,pythonExe:python}};
const jobs=new LiftJobs(cfg,{spawnProcess(exe,args,options){
 assert.equal(exe,python);assert(args.includes(path.join(root,'worker/ig5_project.py')));assert.equal(options.windowsHide,true);
 const child=spawn(exe,args,options),row={pid:child.pid,args,stdin:'',stdout:'',stderr:'',exited:false,closed:false};processes.push(row);
 const write=child.stdin.write.bind(child.stdin);child.stdin.write=(chunk,...rest)=>{row.stdin+=String(chunk);assert(row.stdin.length<=128*1024);return write(chunk,...rest);};
 child.stdout.on('data',b=>{row.stdout+=String(b);assert(row.stdout.length<=4*1024**2);});
 child.stderr.on('data',b=>{row.stderr+=String(b);assert(row.stderr.length<=4*1024**2);});
 child.once('exit',(code,signal)=>{row.exited=true;row.exitCode=code;row.exitSignal=signal;});
 row.closedPromise=new Promise(resolve=>child.once('close',()=>{row.closed=true;resolve();}));return child;
}});
const forbidden=()=>{throw new Error('Composition must not open/access a database');};
const tool=defineIntegrationTools({lifter:jobs,get:forbidden,rpc:forbidden,current:forbidden},cfg).find(t=>t.name==='ig5_ir');
const snapshot=()=>({schema:1,planInputMode:planReferences?'sha256-file':'inline',sourcePins:pins,target:targetPin,cases:rows,processes:processes.map(({closedPromise,...r})=>r),
 activeRequests:jobs.active.size,nativeTargetExecuted:false,databaseModified:false,businessAccepted:false,wholeBinaryVerified:false});
const save=()=>fs.writeFileSync(path.join(directory,'runtime-results.json'),JSON.stringify(snapshot(),null,2));
async function closed(row){let timer;try{await Promise.race([row.closedPromise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('Owned root did not close')),5000);})]);}finally{clearTimeout(timer);}assert(row.exited&&row.closed);}
try{
 for(const spec of cases){
  const planPath=path.join(directory,spec.id+'.plan.json'),planBytes=Buffer.from(JSON.stringify(spec.plan,null,2)+'\n');
  if(planReferences)fs.writeFileSync(planPath,planBytes,{flag:'wx'});
  const args={target,level:'compose',...(planReferences?{composition_plan_ref:{path:planPath,sha256:hash(planBytes)}}:{composition_plan:spec.plan})};let result,error;
  try{result=await tool.execute(args);}catch(e){error=e;}
  assert.equal(processes.length,rows.length+1);const process=processes.at(-1);await closed(process);
  const sent=process.stdin.trim().split(/\r?\n/).filter(Boolean).map(s=>JSON.parse(s));
  const frames=process.stdout.trim().split(/\r?\n/).filter(Boolean).map(s=>JSON.parse(s));
  assert.equal(sent.length,1);assert.equal(sent[0].method,'compose');const ack=frames.find(f=>f.id===1);
  assert.equal(ack?.nonce,sent[0].params.nonce);assert.equal(ack?.cleanupConfirmed,true);assert.equal(jobs.active.size,0);
  const childPath=path.join(directory,'lifter/jobs',sent[0].params.job_id,'request.json');const child=JSON.parse(fs.readFileSync(childPath));
  assert.deepEqual(child.composition_plan,sent[0].params.composition_plan);assert.equal(hash(fs.readFileSync(child.target)),targetPin.sha256);
  if(planReferences){assert(!Object.hasOwn(child,'composition_plan_ref'));assert(!Object.hasOwn(sent[0].params,'composition_plan_ref'));
   assert.equal(hash(fs.readFileSync(planPath)),args.composition_plan_ref.sha256);
   const expectedPaths=spec.plan.strategy==='sequence'?spec.plan.paths:[spec.plan.prefix,spec.plan.body,...spec.plan.suffix];
   const actualPaths=child.composition_plan.strategy==='sequence'?child.composition_plan.paths:[child.composition_plan.prefix,child.composition_plan.body,...child.composition_plan.suffix];
   assert.deepEqual(actualPaths,expectedPaths);assert.equal(child.composition_plan.indirect_mode,spec.plan.indirect_mode||'reject');}
  assert(child.budget_ms>0&&child.budget_ms<=sent[0].params.budget_ms&&sent[0].params.budget_ms<=50000);
  const row={id:spec.id,args,expectedAccepted:spec.accepted,rejected:!!error,rootPid:process.pid,rootExited:true,rootClosed:true,
   nonceMatched:true,cleanupConfirmed:true,childRequest:ref(childPath)};
  if(error){row.message=error.message;assert(ack.error&&!ack.result);
   if(planReferences){assert(error.message.endsWith(ack.error.message));assert(error.message.includes(args.composition_plan_ref.sha256));
    if(spec.id==='memory-over-limit')assert(error.message.includes('providedTemplates=64; addressOccurrences=256'));}
   else assert.equal(ack.error.message,error.message);}
  else{
   assert.equal(result.status,'partial');assert.equal(result.recoveryStatus,'unverified');
   for(const key of ['nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'])assert.equal(result[key],false);
   assert.equal(result.process.jobAssignedAtCreation,true);assert.equal(result.process.childExitConfirmed,true);
   assert.equal(result.process.activeProcessLimit,1);assert.equal(result.process.memoryLimitBytes,2*1024**3);assert.equal(result.process.exitCode,0);
   const bytes=fs.readFileSync(result.reportPath);assert(bytes.length<=4*1024**2);assert.equal(hash(bytes),result.reportSha256);
   const report=JSON.parse(bytes);assert.deepEqual(report.result.compositionPlan,child.composition_plan);
   if(planReferences){assert.deepEqual(result.compositionInput,report.compositionInput);assert.equal(result.compositionInput.sha256,hash(planBytes));
    assert.equal(result.compositionInput.normalizedPlanSha256,hash(Buffer.from(JSON.stringify(child.composition_plan))));
    assert.deepEqual(jobs.artifacts.read(result.compositionInput.ref).data,planBytes);
    if(spec.id==='memory-limit-exact')assert.equal(result.compositionInput.pathApplications,64);}
   for(const decoded of report.result.decodedPath){assert.equal(decoded.bytes,definitions.get(decoded.ea));assert.equal(decoded.decoded.size,decoded.bytes.length/2);}
   row.result=result;
  }
  rows.push(row);save();assert.equal(row.rejected,!spec.accepted,spec.id+': '+(error?.message||'unexpected accept'));
  if(error)assert.match(error.message,new RegExp(spec.error));assert.deepEqual(ref(target),targetPin);
  console.log(JSON.stringify({id:spec.id,observed:error?'rejected':'accepted'}));
 }
 for(const pin of pins)assert.deepEqual(ref(pin.path),{path:pin.path,bytes:pin.bytes,sha256:pin.sha256});
 const verify=spawnSync(python,['-I','-B',path.join(scriptDir,'test_composition_runtime_verify.py'),path.join(directory,'runtime-results.json')],
  {cwd:root,windowsHide:true,encoding:'utf8',timeout:60000,maxBuffer:4*1024**2});
 fs.writeFileSync(path.join(directory,'semantic-verifier.stdout.json'),verify.stdout||'');fs.writeFileSync(path.join(directory,'semantic-verifier.stderr.log'),verify.stderr||'');
 assert.equal(verify.status,0,verify.stderr||verify.stdout);
 fs.writeFileSync(path.join(directory,'verified.json'),JSON.stringify({...snapshot(),verification:JSON.parse(verify.stdout),runtimeResultsSHA256:hash(fs.readFileSync(path.join(directory,'runtime-results.json')))},null,2));
}catch(error){save();fs.writeFileSync(path.join(directory,'failure.json'),JSON.stringify({message:error.message,stack:error.stack},null,2));throw error;}
finally{await jobs.dispose();await jobs.artifacts.dispose();}
