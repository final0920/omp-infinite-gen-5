// Owned PE read-only discovery -> unchanged explicit Java projection.
import fs from'node:fs';import path from'node:path';import assert from'node:assert/strict';import{spawn}from'node:child_process';import{createHash}from'node:crypto';import{pathToFileURL}from'node:url';
const argv=process.argv.slice(2),opt=k=>argv[argv.indexOf(k)+1],hash=b=>createHash('sha256').update(b).digest('hex');
for(const k of['--plugin-root','--out','--cases','--cases-sha'])assert(argv.includes(k));
const ROOT=fs.realpathSync(opt('--plugin-root')),OUT=path.resolve(opt('--out'));fs.mkdirSync(OUT,{recursive:false});const raw=fs.readFileSync(opt('--cases'));assert(raw.length<=65536);assert.equal(hash(raw),opt('--cases-sha'));const specs=JSON.parse(raw);
const cfg={artifactDir:OUT,projectRoot:path.join(OUT,'projects'),host:{id:'win32-x64'},requestTimeoutMs:60000,ghidra:{available:true,pythonExe:path.join(ROOT,'runtimes/ghidra/python/python.exe')}},roots=[],cases=[];
const{LiftJobs}=await import(pathToFileURL(path.join(ROOT,'source/lift_jobs.js'))),{defineIntegrationTools}=await import(pathToFileURL(path.join(ROOT,'integration_tools.js')));
const jobs=new LiftJobs(cfg,{spawnProcess(exe,args,options){assert(options.windowsHide);const child=spawn(exe,args,options),r={pid:child.pid,stdin:'',stdout:'',stderr:'',exited:false};roots.push(r);const w=child.stdin.write.bind(child.stdin);child.stdin.write=(x,...rest)=>{r.stdin+=String(x);assert(Buffer.byteLength(r.stdin)<=65536);return w(x,...rest)};
 for(const s of['stdout','stderr'])child[s].on('data',x=>{r[s]+=x.toString();assert(Buffer.byteLength(r[s])<=4*1024**2)});child.once('exit',(code,signal)=>{r.exited=true;r.exitCode=code;r.signal=signal});r.closed=new Promise(resolve=>child.once('close',resolve));return child;}});
const forbidden=()=>{throw Error('No target execution or database access')},tool=defineIntegrationTools({lifter:jobs,get:forbidden,rpc:forbidden,current:forbidden},cfg).find(t=>t.name==='ig5_ir');
const save=()=>fs.writeFileSync(path.join(OUT,'observed.json'),JSON.stringify({cases,roots:roots.map(({closed,...r})=>r),activeRequests:jobs.active.size,nativeTargetExecuted:false,businessAccepted:false,wholeBinaryVerified:false},null,2)+'\n');
async function call(args,role){let value,error;const start=roots.length;try{value=await tool.execute(args)}catch(e){error=e}
 let ack=false,exit=false;if(roots.length>start){const r=roots.at(-1);await r.closed;const sent=r.stdin.trim().split(/\r?\n/).map(JSON.parse).find(x=>x.id===1),reply=r.stdout.trim().split(/\r?\n/).map(JSON.parse).find(x=>x.id===1);assert.equal(reply.nonce,sent.params.nonce);assert.equal(reply.cleanupConfirmed,true);assert(r.exited);ack=exit=true;}
 const row={role,args,rejected:!!error,...(error?{error:error.message,analysisFailure:error.analysisFailure}:{result:value}),spawnedRoots:roots.length-start,cleanupACKConfirmed:ack,rootExitConfirmed:exit};cases.push(row);save();assert.equal(jobs.active.size,0);return row;
}
try{
 for(const spec of specs.cases){assert.equal(hash(fs.readFileSync(spec.target)),spec.targetSha256);const d=await call({target:spec.target,level:'discover',ea:spec.ea,...(Object.hasOwn(spec,'followDirectCalls')?{follow_direct_calls:spec.followDirectCalls}:{}),...(spec.maximum?{max_instructions:spec.maximum}:{})},spec.id+'-discover');
  if(spec.discoverReject){assert(d.rejected);assert(d.error.includes(spec.discoverReject),d.error);assert(d.analysisFailure);console.log(JSON.stringify({id:spec.id,expectedDiscoveryRefusal:true,error:d.error}));continue;}
  assert.equal(d.rejected,false,d.error);assert.equal(d.result.candidateOnly,true);assert.equal(d.result.pathSemanticsValidated,false);if(spec.stop)assert.equal(d.result.stop.reason,spec.stop);if(spec.instructions)assert.equal(d.result.instructionCount,spec.instructions);
  if(spec.projectMode){const p=await call({target:spec.target,level:'project',projection_decoder:'java',projection_path:d.result.candidatePath,projection_registers:'rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15'.split(' '),projection_mode:spec.projectMode},spec.id+'-project');
   if(spec.projectReject){assert(p.rejected);assert(p.error.includes(spec.projectReject),p.error)}else{assert.equal(p.rejected,false,p.error);const c=JSON.parse(fs.readFileSync(p.result.reportPath,'utf8')).result;assert.deepEqual(c.projectionPath,d.result.candidatePath);assert.equal(c.nativeTargetExecuted,false);assert.equal(c.businessAccepted,false);assert.equal(hash(fs.readFileSync(p.result.reportPath)),p.result.reportSha256);}
  }
  console.log(JSON.stringify({id:spec.id,stop:d.result.stop,instructions:d.result.instructionCount,candidatePath:d.result.candidatePath}));
 }
 save();fs.writeFileSync(path.join(OUT,'verified.json'),JSON.stringify({passed:true,pluginRoot:ROOT,cases,casesInput:{path:opt('--cases'),sha256:opt('--cases-sha')},allStartedRootsSameNonceACKAndActualExitConfirmed:true,activeRequests:0,nativeTargetExecuted:false,businessAccepted:false,wholeBinaryVerified:false},null,2)+'\n',{flag:'wx'});
}finally{await jobs.dispose();await jobs.artifacts.dispose()}
