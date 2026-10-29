// Real public Java route, cancellation and owned child cleanup. PE bytes are data.
import assert from 'node:assert/strict';import {spawn} from 'node:child_process';
import fs from 'node:fs';import path from 'node:path';import {pathToFileURL} from 'node:url';
import {buildPE64Fixture} from './fixtures/pe64.mjs';
const out=process.argv[2],main=process.argv[3]||path.resolve(import.meta.dirname,'..');
assert(out&&path.isAbsolute(out)&&path.isAbsolute(main));fs.mkdirSync(out,{recursive:false});
assert.equal(fs.realpathSync(out),out);
const {defineIntegrationTools}=await import(pathToFileURL(path.join(main,'integration_tools.js')));
const {LiftJobs}=await import(pathToFileURL(path.join(main,'source/lift_jobs.js')));
const {hashBytes}=await import(pathToFileURL(path.join(main,'source/analysis_artifacts.js')));
const image=Buffer.from(buildPE64Fixture().image);image.fill(0x90,0x400,0x800);
const ea=rva=>'0x'+(0x140000000n+BigInt(rva)).toString(16),put=(rva,hex)=>Buffer.from(hex,'hex').copy(image,0x400+rva-0x1000);
put(0x1000,'488d0411c3');put(0x1080,'4839d8771090');put(0x1100,'9c58');put(0x1120,'50c3');
put(0x1140,'e81b000000');put(0x1160,'488d0411c3');put(0x1180,'4883eb0875fa');put(0x13ff,'0f');
const target=path.join(out,'java-fixture-data.exe');fs.writeFileSync(target,image,{flag:'wx'});
const roots=[],cases=[],cfg={artifactDir:out,projectRoot:path.join(out,'projects'),host:{id:'win32-x64'},requestTimeoutMs:60000,
  ghidra:{available:true,pythonExe:path.join(main,'runtimes/ghidra/python/python.exe')}};
let activeSignal;
const jobs=new LiftJobs(cfg,{spawnProcess(executable,args,options){
  assert.equal(executable,cfg.ghidra.pythonExe);assert.equal(options.windowsHide,true);assert.equal(options.shell,undefined);
  const child=spawn(executable,args,options),row={pid:child.pid,stdin:'',stdout:'',stderr:'',exited:false,closed:false};roots.push(row);
  const write=child.stdin.write.bind(child.stdin);child.stdin.write=(value,...rest)=>{row.stdin+=String(value);assert(row.stdin.length<=128*1024);return write(value,...rest);};
  for(const stream of ['stdout','stderr'])child[stream].on('data',value=>{row[stream]+=String(value);assert(row[stream].length<=1024**2);});
  child.once('exit',code=>{row.exited=true;row.exitCode=code;});row.done=new Promise(resolve=>child.once('close',()=>{row.closed=true;resolve();}));return child;
}});
const forbidden=()=>{throw Error('Static projection must not open a DB or execute a target');};
const tool=defineIntegrationTools({lifter:jobs,get:forbidden,rpc:forbidden,current:forbidden,scope:{getStore(){return{signal:activeSignal};}}},cfg).find(t=>t.name==='ig5_ir');
const project=(rvas,extra={})=>({target,level:'project',projection_decoder:'java',projection_path:rvas.map(ea),projection_registers:['rax','rsp'],...extra});
const specs=[
 {id:'java-lea',args:project([0x1000])},
 {id:'java-guarded-side-exit',args:project([0x1080,0x1083,0x1085],{projection_mode:'guarded-path'})},
 {id:'java-opaque-push-pop',args:project([0x1100,0x1101],{projection_mode:'opaque-effects'})},
 {id:'java-composed-push-ret',args:{target,level:'compose',projection_decoder:'java',composition_plan:{strategy:'sequence',paths:[[ea(0x1120)],[ea(0x1121)]]}}},
 {id:'java-direct-call-callee-return',args:project([0x1140,0x1160,0x1164])},
 {id:'java-free-counter-loop-refused',args:{target,level:'compose',projection_decoder:'java',composition_plan:{strategy:'constant-loop',prefix:[ea(0x1180),ea(0x1184)],body:[ea(0x1180),ea(0x1184)],suffix:[[ea(0x1186)]]}},reject:/constant|input-dependent/i},
 {id:'java-truncated-encoding-refused',args:project([0x13ff]),reject:/Java projection decode failed/},
 {id:'java-undefined-flags-refused',args:project([0x1083]),reject:/undefined initial architectural flags/},
];
const snapshot=()=>({schema:'ig5-public-java-runtime-v1',pluginRoot:main,target:{path:target,sha256:hashBytes(image)},cases,
 roots:roots.map(({done,...r})=>r),activeRequests:jobs.active.size,nativeTargetExecuted:false,databaseModified:false,businessAccepted:false,wholeBinaryVerified:false});
const save=()=>fs.writeFileSync(path.join(out,'runtime-results.json'),JSON.stringify(snapshot(),null,2));
async function closed(row){let timer;try{await Promise.race([row.done,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Owned protocol root close unconfirmed')),5000);})]);}finally{clearTimeout(timer);}
  assert(row.exited&&row.closed);const request=row.stdin.trim().split(/\r?\n/).map(JSON.parse).find(m=>m.id===1),reply=row.stdout.trim().split(/\r?\n/).map(JSON.parse).find(m=>m.id===1);
  assert(request&&reply);assert.equal(reply.nonce,request.params.nonce);assert.equal(reply.cleanupConfirmed,true);assert.equal(jobs.active.size,0);return{request,reply};}
try{
 for(const spec of specs){let result,error;const before=roots.length;
  try{result=await tool.execute(spec.args);}catch(e){error=e;}
  assert.equal(roots.length,before+1,`${spec.id}: ${error?.message}`);const root=roots.at(-1);await closed(root);
  const row={id:spec.id,args:spec.args,rejected:!!error,rootPid:root.pid,rootExited:true,rootClosed:true,cleanupConfirmed:true,...(error?{error:error.message,analysisFailure:error.analysisFailure}:{result})};cases.push(row);save();
  if(spec.reject){assert(error,spec.id);assert.match(error.message,spec.reject);
   assert(error.analysisFailure,`Failure receipt absent: ${error.message}`);assert.equal(error.analysisFailure.status,'failed-unverified');
   const bytes=fs.readFileSync(error.analysisFailure.reportPath);assert.equal(hashBytes(bytes),error.analysisFailure.reportSha256);
   const report=JSON.parse(bytes);for(const key of ['nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'])assert.equal(report[key],false);
   if(spec.id==='java-truncated-encoding-refused'){assert.match(error.message,/Instruction boundary exceeds available bytes/);assert.equal(error.analysisFailure.failedStage,'java-decode');assert.equal(report.result.processStages.length,1);}
   if(spec.id==='java-undefined-flags-refused'){assert.equal(error.analysisFailure.failedStage,'state-computation');assert.equal(report.result.processStages.length,2);}
  }
  else{assert(!error,error?.message);assert.equal(result.projectionDecoder,'java');assert.equal(result.processStages.length,2);
   const raw=fs.readFileSync(result.reportPath);assert.equal(hashBytes(raw),result.reportSha256);const core=JSON.parse(raw).result;
   if(spec.id==='java-guarded-side-exit')assert.equal(core.sideExits.length,1);
   if(spec.id==='java-opaque-push-pop'){assert.equal(core.opaqueEffects.length,1);assert.equal(core.stores.length,1);}
   if(spec.id==='java-composed-push-ret'){
    assert.equal(core.stores.length,1);assert.equal(core.dag.nodes[core.control.target].name,'rax');
    const mask=(1n<<64n)-1n;
    const evaluate=(id,rsp)=>{const n=core.dag.nodes[id];if(n.op==='input'){assert.equal(n.name,'rsp');return rsp;}
     if(n.op==='const')return BigInt(n.value);const a=n.args.map(i=>evaluate(i,rsp));assert(['INT_ADD','INT_SUB'].includes(n.op));return(n.op==='INT_ADD'?a[0]+a[1]:a[0]-a[1])&mask;};
    for(const rsp of [0n,1n,7n,8n,mask-7n,mask])assert.equal(evaluate(core.registers.rsp,rsp),rsp);
   }
   for(const key of ['nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'])assert.equal(core[key],false);
  }
  console.log(JSON.stringify({id:spec.id,observed:error?'refused':'accepted'}));
 }
 // Wait for the actual suspended-and-job-assigned JVM marker, confirm its PID
 // is live now, then cancel through the same public request signal.
 const controller=new AbortController();activeSignal=controller.signal;
 const operation=tool.execute(project([0x1000])).then(result=>({result}),error=>({error}));
 const start=Date.now();let marker;
 while(!marker){
  assert(Date.now()-start<10000,'No live Java child observed for cancellation');
  for(const name of fs.readdirSync(path.join(jobs.artifacts.root,'jobs'))){
   const file=path.join(jobs.artifacts.root,'jobs',name,'java-decode/started.json');
   if(!fs.existsSync(file))continue;const row=JSON.parse(fs.readFileSync(file));
   if(roots.at(-1)?.stdin.includes(row.nonce)){marker={...row,path:file};break;}
  }
  if(!marker)await new Promise(resolve=>setTimeout(resolve,10));
 }
 assert.equal(marker.jobAssignedAtCreation,true);assert.equal(marker.nativeTargetExecuted,false);process.kill(marker.pid,0);
 controller.abort();const observed=await operation;activeSignal=undefined;assert(observed.error,'Cancelled analysis unexpectedly committed output');
 const root=roots.at(-1);await closed(root);assert.throws(()=>process.kill(marker.pid,0));
 cases.push({id:'java-live-child-cancel',rejected:true,error:observed.error.message,observedLiveChild:marker,childAbsentAfterCleanup:true,rootPid:root.pid,rootExited:true,rootClosed:true,cleanupConfirmed:true});save();
 assert.equal(hashBytes(fs.readFileSync(target)),hashBytes(image));
 fs.writeFileSync(path.join(out,'verified.json'),JSON.stringify({...snapshot(),passed:true},null,2));
 console.log(JSON.stringify({passed:true,cases:cases.length,accepted:cases.filter(r=>!r.rejected).length,refused:cases.filter(r=>r.rejected).length,activeRequests:jobs.active.size}));
}catch(error){save();fs.writeFileSync(path.join(out,'failure.json'),JSON.stringify({message:error.message,stack:error.stack},null,2));throw error;}
finally{await jobs.dispose();await jobs.artifacts.dispose();}
