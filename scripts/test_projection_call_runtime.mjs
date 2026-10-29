// Real readonly public routes, raw AMD64 PE bytes; targets are never executed.
import assert from 'node:assert/strict';import fs from 'node:fs';import path from 'node:path';import {spawn,spawnSync} from 'node:child_process';import {createHash} from 'node:crypto';import {fileURLToPath,pathToFileURL} from 'node:url';
const scriptDir=path.dirname(fileURLToPath(import.meta.url)),out=process.argv[2],root=process.argv[3]||path.dirname(scriptDir),actualArgsPath=process.argv[4],entryGraphPath=process.argv[5];
assert(out&&path.isAbsolute(out)&&path.isAbsolute(root));assert(!!actualArgsPath===!!entryGraphPath,'Actual-sample args and merged graph must be provided together');fs.mkdirSync(out,{recursive:false});
const hash=b=>createHash('sha256').update(b).digest('hex'),pin=f=>{const b=fs.readFileSync(f);return {path:f,bytes:b.length,sha256:hash(b)};};
const {buildPE64Fixture}=await import(pathToFileURL(path.join(root,'scripts/fixtures/pe64.mjs'))),{LiftJobs}=await import(pathToFileURL(path.join(root,'source/lift_jobs.js'))),{defineIntegrationTools}=await import(pathToFileURL(path.join(root,'integration_tools.js')));
const image=Buffer.from(buildPE64Fixture().image);image.fill(0x90,0x400,0x800);
const put=(rva,hex)=>Buffer.from(hex,'hex').copy(image,0x400+rva-0x1000);
put(0x1000,'e81b00000090');put(0x1020,'4889c8c3');put(0x1040,'e8ffffff7f');put(0x1080,'e800000080');put(0x10c0,'66e81a000000');put(0x1100,'ffd0');
const target=path.join(out,'direct-call-fixture.exe');fs.writeFileSync(target,image,{flag:'wx'});
const names='rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15'.split(' '),project=addresses=>({target,level:'project',projection_path:addresses,projection_registers:names});
const compose=paths=>({target,level:'compose',composition_plan:{strategy:'sequence',paths}});
const original=actualArgsPath?JSON.parse(fs.readFileSync(actualArgsPath)):null,actual=original?.arguments,entry=entryGraphPath?JSON.parse(fs.readFileSync(entryGraphPath)):null;
if(actual){assert.equal(actual.level,'project');assert.equal(pin(actual.target).sha256,'5f9c1b6fcb019366f835d8f02d9ec3b2957fe619e039410d07f288a9c73f63f0');}
let entryPlanRef;
if(actual){const file=path.join(out,'actual-entry-full.plan.json'),bytes=Buffer.from(JSON.stringify({strategy:'sequence',paths:[entry.rows.map(r=>r.ea)]},null,2)+'\n');
 fs.writeFileSync(file,bytes,{flag:'wx'});entryPlanRef={path:file,sha256:hash(bytes)};}
const specs=[{id:'project-terminal-call',args:project(['0x140001000']),accepted:true},
 {id:'project-call-callee-return',args:project(['0x140001000','0x140001020','0x140001023']),accepted:true},
 {id:'compose-call-callee-return',args:compose([['0x140001000'],['0x140001020','0x140001023']]),accepted:true},
 {id:'compose-terminal-call',args:compose([['0x140001000']]),accepted:true},
 {id:'rel32-positive-limit',args:project(['0x140001040']),accepted:true},
 {id:'rel32-negative-limit',args:project(['0x140001080']),accepted:true},
 {id:'call-fallthrough-is-not-callee',args:project(['0x140001000','0x140001005']),accepted:false,error:'branch/path mismatch'},
 {id:'prefixed-call-refused',args:project(['0x1400010c0']),accepted:false,error:'CALL|Control|control'},
 {id:'indirect-call-refused',args:project(['0x140001100']),accepted:false,error:'CALLIND'},
 ...(actual?[{id:'actual-ultra-same-entry-call-request',args:actual,accepted:true},
 {id:'actual-ultra-local-table-base-definition',args:{...actual,projection_path:['0x140052117']},accepted:true},
 {id:'actual-ultra-full-entry-flags-still-refused',args:{...actual,projection_path:entry.rows.map(r=>r.ea)},accepted:false,error:'Unsupported architectural register'},
 {id:'actual-ultra-compose-entry-flags-still-refused',args:{target:actual.target,level:'compose',composition_plan_ref:entryPlanRef},accepted:false,error:'Unsupported architectural register'},
 {id:'actual-ultra-rdtsc-still-refused',args:{...actual,projection_path:['0x1400520e1']},accepted:false,error:'CALLOTHER'},
 {id:'actual-ultra-undefined-bswap-still-refused',args:{...actual,projection_path:['0x14005211e'],projection_registers:['r11']},accepted:false,error:'undefined 16-bit BSWAP'}]:[]),
];
const sourceFiles=['integration_tools.js','source/projection_jobs.js','source/composition_jobs.js','source/lift_jobs.js','source/worker_transport.js','worker/ig5_project.py','worker/projection_worker.py','worker/pcode_projection.py','worker/projection_call.py','worker/projection_flags.py','worker/projection_bsr.py','worker/projection_bsf.py','worker/projection_composition.py','worker/composition_memory.py','worker/composition_selection.py','worker/lift_process.py','scripts/test_projection_call_runtime.mjs','scripts/test_projection_call_runtime_verify.py','runtimes/manifest.json'].map(file=>({file,...pin(path.join(root,file))}));
const processes=[],cases=[],cfg={artifactDir:out,projectRoot:path.join(out,'projects'),host:{id:'win32-x64'},requestTimeoutMs:60000,ghidra:{available:true,pythonExe:path.join(root,'runtimes/ghidra/python/python.exe')}};
const jobs=new LiftJobs(cfg,{spawnProcess(exe,args,options){assert.equal(exe,cfg.ghidra.pythonExe);assert(args.includes(path.join(root,'worker/ig5_project.py')));assert.equal(options.windowsHide,true);
 const child=spawn(exe,args,options),r={pid:child.pid,args,stdin:'',stdout:'',stderr:'',exited:false,closed:false};processes.push(r);
 const write=child.stdin.write.bind(child.stdin);child.stdin.write=(b,...a)=>{r.stdin+=String(b);assert(r.stdin.length<=65536);return write(b,...a);};
 for(const s of ['stdout','stderr'])child[s].on('data',b=>{r[s]+=String(b);assert(r[s].length<=4*1024**2);});
 child.once('exit',code=>{r.exited=true;r.exitCode=code;});r.closedPromise=new Promise(resolve=>child.once('close',()=>{r.closed=true;resolve();}));return child;}});
const forbidden=()=>{throw Error('No database or target execution is permitted');},tool=defineIntegrationTools({lifter:jobs,get:forbidden,rpc:forbidden},cfg).find(t=>t.name==='ig5_ir');
const snapshot=()=>({schema:1,pluginRoot:root,sourcePins:sourceFiles,fixture:pin(target),actualRequest:actualArgsPath?pin(actualArgsPath):null,entryGraph:entryGraphPath?pin(entryGraphPath):null,cases,processes:processes.map(({closedPromise,...r})=>r),activeRequests:jobs.active.size,nativeTargetExecuted:false,businessAccepted:false,wholeBinaryVerified:false});
const save=()=>fs.writeFileSync(path.join(out,'runtime-results.json'),JSON.stringify(snapshot(),null,2));
try{
 for(const spec of specs){let result,error;try{result=await tool.execute(spec.args);}catch(e){error=e;}
  assert.equal(processes.length,cases.length+1);const r=processes.at(-1);let timer;try{await Promise.race([r.closedPromise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Owned root did not close')),5000);})]);}finally{clearTimeout(timer);}
  const sent=r.stdin.trim().split(/\r?\n/).map(s=>JSON.parse(s)),ack=r.stdout.trim().split(/\r?\n/).map(s=>JSON.parse(s)).find(m=>m.id===1);
  assert(r.exited&&r.closed);assert.equal(sent.length,1);assert.equal(sent[0].method,spec.args.level);assert.equal(ack?.nonce,sent[0].params.nonce);assert.equal(ack?.cleanupConfirmed,true);assert.equal(jobs.active.size,0);
  const row={id:spec.id,args:spec.args,expectedAccepted:spec.accepted,rejected:!!error,rootPid:r.pid,rootExited:true,rootClosed:true,nonceMatched:true,cleanupConfirmed:true};
  if(error){row.message=error.message;assert(ack.error);assert.match(error.message,new RegExp(spec.error));}
  else{assert.equal(pin(result.reportPath).sha256,result.reportSha256);assert.equal(result.status,'partial');assert(result.process.jobAssignedAtCreation&&result.process.childExitConfirmed);
   assert.equal(result.process.activeProcessLimit,1);assert.equal(result.process.memoryLimitBytes,2*1024**3);
   for(const k of ['nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'])assert.equal(result[k],false);
   if(spec.id==='actual-ultra-same-entry-call-request'){assert.deepEqual(spec.args,original.arguments);assert.equal(result.control.transfer,'call');assert.equal(result.control.returnAddress,'0x1400141b4');}
   row.result=result;}
  cases.push(row);save();assert.equal(row.rejected,!spec.accepted,spec.id+': '+error?.message);console.log(JSON.stringify({id:spec.id,observed:error?'refused':'accepted'}));
 }
 for(const f of sourceFiles)assert.equal(pin(f.path).sha256,f.sha256);
 const verify=spawnSync(cfg.ghidra.pythonExe,['-I','-B',path.join(root,'scripts/test_projection_call_runtime_verify.py'),path.join(out,'runtime-results.json')],{windowsHide:true,encoding:'utf8',timeout:60000,maxBuffer:4*1024**2});
 fs.writeFileSync(path.join(out,'semantic-verifier.stdout.json'),verify.stdout||'');fs.writeFileSync(path.join(out,'semantic-verifier.stderr.log'),verify.stderr||'');assert.equal(verify.status,0,verify.stderr||verify.stdout);
 fs.writeFileSync(path.join(out,'verified.json'),JSON.stringify({...snapshot(),verification:JSON.parse(verify.stdout)},null,2));
}catch(error){save();fs.writeFileSync(path.join(out,'failure.json'),JSON.stringify({message:error.message,stack:error.stack},null,2));throw error;}
finally{await jobs.dispose();await jobs.artifacts.dispose();}
