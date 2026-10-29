// Real public compose route, fixed decoder and owned Job. Generated PE is data only.
import assert from 'node:assert/strict';import fs from 'node:fs';import path from 'node:path';
import {spawn,spawnSync} from 'node:child_process';import {createHash} from 'node:crypto';import {fileURLToPath,pathToFileURL} from 'node:url';
const scriptDir=path.dirname(fileURLToPath(import.meta.url)),out=process.argv[2],root=process.argv[3]||path.dirname(scriptDir);
assert(out&&path.isAbsolute(out)&&path.isAbsolute(root));assert.equal(fs.realpathSync(root),path.resolve(root));fs.mkdirSync(out,{recursive:false});
const hash=b=>createHash('sha256').update(b).digest('hex'),pin=f=>{const b=fs.readFileSync(f);return {path:f,bytes:b.length,sha256:hash(b)};};
const {buildPE64Fixture}=await import(pathToFileURL(path.join(root,'scripts/fixtures/pe64.mjs')));
const {defineIntegrationTools}=await import(pathToFileURL(path.join(root,'integration_tools.js')));
const {LiftJobs}=await import(pathToFileURL(path.join(root,'source/lift_jobs.js')));
const image=Buffer.from(buildPE64Fixture().image);image.fill(0x90,0x400,0x800);const definitions=new Map();
const place=(rva,codes)=>codes.map(code=>{const address='0x'+(0x140000000n+BigInt(rva)).toString(16),bytes=Buffer.from(code,'hex');
 assert(rva>=0x1000&&rva+bytes.length<=0x1400);bytes.copy(image,0x400+rva-0x1000);definitions.set(address,code);rva+=bytes.length;return address;});
const stack=place(0x1000,['50','c3']),patched=place(0x1040,['488907','885f03','488b0f']),partial=place(0x1080,['488907','488b4ffd']);
const disjoint=place(0x10c0,['488907','48895f10','488b0f']),destination=place(0x1100,['4889c1']);
const unknown=place(0x1140,['488907','48891e','488b0f']);
const counter=place(0x1180,['c60703','8a07','2c01','8807','75f8','0fb607']);
const affine=place(0x11c0,['4889fa','488d7220','4883ee20','488907','488b0e']);
const sequence=(paths,guarded=false)=>({strategy:'sequence',paths,...(guarded?{indirect_mode:'guarded-target'}:{})});
const specs=[
 {id:'push-ret-one-template',plan:sequence([stack]),accepted:true,forwarded:true},
 {id:'push-ret-across-templates',plan:sequence(stack.map(a=>[a])),accepted:true,forwarded:true},
 {id:'latest-narrow-store',plan:sequence(patched.map(a=>[a])),accepted:true,forwarded:true},
 {id:'partial-before-store',plan:sequence(partial.map(a=>[a])),accepted:true,forwarded:true},
 {id:'known-disjoint-store',plan:sequence(disjoint.map(a=>[a])),accepted:true,forwarded:true},
 {id:'unknown-alias-barrier',plan:sequence(unknown.map(a=>[a])),accepted:true,unknown:true},
 {id:'memory-controlled-loop',plan:{strategy:'constant-loop',prefix:counter.slice(0,-1),body:counter.slice(1,-1),suffix:[counter.slice(-1)]},accepted:true,forwarded:true},
 {id:'unknown-memory-loop-refused',plan:{strategy:'constant-loop',prefix:counter.slice(1,-1),body:counter.slice(1,-1),suffix:[counter.slice(-1)]},accepted:false,error:'constant closed-state condition'},
 {id:'affine-address-identity',plan:sequence([affine.slice(0,3),...affine.slice(3).map(a=>[a])]),accepted:true,forwarded:true},
 {id:'push-ret-guarded-reentry',plan:sequence([...stack.map(a=>[a]),destination],true),accepted:true,forwarded:true},
 {id:'push-ret-default-reentry-refused',plan:sequence([...stack.map(a=>[a]),destination]),accepted:false,error:'explicit guarded-target'},
];
const target=path.join(out,'memory-fixture.exe');fs.writeFileSync(target,image,{flag:'wx'});const targetPin=pin(target);
const sources=['integration_tools.js','source/composition_jobs.js','source/lift_jobs.js','source/worker_transport.js','worker/ig5_project.py','worker/projection_worker.py',
 'worker/composition_selection.py','worker/projection_composition.py','worker/composition_memory.py','worker/pcode_projection.py','worker/projection_flags.py',
 'worker/projection_bsr.py','worker/projection_bsf.py','worker/projection_call.py','worker/lift_process.py','scripts/test_composition_memory_runtime.mjs','scripts/test_composition_memory_runtime_verify.py','scripts/fixtures/pe64.mjs','runtimes/manifest.json'].map(f=>({file:f,...pin(path.join(root,f))}));
const processes=[],cases=[],python=path.join(root,'runtimes/ghidra/python/python.exe'),cfg={artifactDir:out,projectRoot:path.join(out,'projects'),host:{id:'win32-x64'},requestTimeoutMs:60000,ghidra:{available:true,pythonExe:python}};
const jobs=new LiftJobs(cfg,{spawnProcess(exe,args,options){assert.equal(exe,python);assert(args.includes(path.join(root,'worker/ig5_project.py')));assert.equal(options.windowsHide,true);
 const child=spawn(exe,args,options),row={pid:child.pid,args,stdin:'',stdout:'',stderr:'',exited:false,closed:false};processes.push(row);
 const write=child.stdin.write.bind(child.stdin);child.stdin.write=(b,...rest)=>{row.stdin+=String(b);assert(row.stdin.length<=65536);return write(b,...rest);};
 for(const stream of ['stdout','stderr'])child[stream].on('data',b=>{row[stream]+=String(b);assert(row[stream].length<=4*1024**2);});
 child.once('exit',code=>{row.exited=true;row.exitCode=code;});row.closePromise=new Promise(resolve=>child.once('close',()=>{row.closed=true;resolve();}));return child;}});
const forbidden=()=>{throw Error('Unexpected database or target execution route');};
const tool=defineIntegrationTools({lifter:jobs,get:forbidden,rpc:forbidden},cfg).find(t=>t.name==='ig5_ir');
const snapshot=()=>({schema:1,pluginRoot:root,sourcePins:sources,target:targetPin,cases,processes:processes.map(({closePromise,...p})=>p),activeRequests:jobs.active.size,
 nativeTargetExecuted:false,databaseModified:false,businessAccepted:false,wholeBinaryVerified:false});
const save=()=>fs.writeFileSync(path.join(out,'runtime-results.json'),JSON.stringify(snapshot(),null,2));
try{
 for(const spec of specs){const file=path.join(out,spec.id+'.plan.json'),bytes=Buffer.from(JSON.stringify(spec.plan,null,2)+'\n');fs.writeFileSync(file,bytes,{flag:'wx'});
  const args={target,level:'compose',composition_plan_ref:{path:file,sha256:hash(bytes)}};let result,error;try{result=await tool.execute(args);}catch(e){error=e;}
  assert.equal(processes.length,cases.length+1);const process=processes.at(-1);let timer;
  try{await Promise.race([process.closePromise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Owned root close missing')),5000);})]);}finally{clearTimeout(timer);}
  const sent=process.stdin.trim().split(/\r?\n/).map(s=>JSON.parse(s)),ack=process.stdout.trim().split(/\r?\n/).map(s=>JSON.parse(s)).find(f=>f.id===1);
  assert(process.exited&&process.closed);assert.equal(sent.length,1);assert.equal(sent[0].method,'compose');assert.equal(ack?.nonce,sent[0].params.nonce);assert.equal(ack?.cleanupConfirmed,true);assert.equal(jobs.active.size,0);
  const row={id:spec.id,args,expectedAccepted:spec.accepted,rejected:!!error,rootPid:process.pid,rootExited:true,rootClosed:true,nonceMatched:true,cleanupConfirmed:true};
  if(error){row.message=error.message;assert(ack.error);assert.match(error.message,new RegExp(spec.error));assert(error.message.includes(args.composition_plan_ref.sha256));}
  else{const report=JSON.parse(fs.readFileSync(result.reportPath));assert.equal(pin(result.reportPath).sha256,result.reportSha256);
   assert.deepEqual(result.compositionInput,report.compositionInput);assert.equal(result.compositionInput.sha256,args.composition_plan_ref.sha256);
   assert.deepEqual(report.result.compositionPlan,sent[0].params.composition_plan);
   assert(result.process.jobAssignedAtCreation&&result.process.childExitConfirmed);assert.equal(result.process.activeProcessLimit,1);assert.equal(result.process.memoryLimitBytes,2*1024**3);
   for(const key of ['nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'])assert.equal(result[key],false);
   for(const r of report.result.decodedPath)assert.equal(r.bytes,definitions.get(r.ea));
   if(spec.forwarded)assert(result.memoryNormalization.forwardedBytes>0,spec.id);
   if(spec.unknown){assert(result.memoryNormalization.unknownAliasFallbacks>0);const node=report.result.dag.nodes[report.result.registers.rcx];assert.equal(node.op,'load_le');assert.equal(node.args[0],report.result.currentMemory);}
   row.result=result;}
  cases.push(row);save();assert.equal(row.rejected,!spec.accepted,spec.id+': '+error?.message);assert.deepEqual(pin(target),targetPin);console.log(JSON.stringify({id:spec.id,observed:error?'refused':'accepted',normalization:result?.memoryNormalization}));
 }
 for(const p of sources)assert.equal(pin(p.path).sha256,p.sha256);
 const verify=spawnSync(python,['-I','-B',path.join(root,'scripts/test_composition_memory_runtime_verify.py'),path.join(out,'runtime-results.json')],{windowsHide:true,encoding:'utf8',timeout:60000,maxBuffer:4*1024**2});
 fs.writeFileSync(path.join(out,'semantic-verifier.stdout.json'),verify.stdout||'');fs.writeFileSync(path.join(out,'semantic-verifier.stderr.log'),verify.stderr||'');assert.equal(verify.status,0,verify.stderr||verify.stdout);
 fs.writeFileSync(path.join(out,'verified.json'),JSON.stringify({...snapshot(),verification:JSON.parse(verify.stdout)},null,2));
}catch(error){save();fs.writeFileSync(path.join(out,'failure.json'),JSON.stringify({message:error.message,stack:error.stack},null,2));throw error;}
finally{await jobs.dispose();await jobs.artifacts.dispose();}
