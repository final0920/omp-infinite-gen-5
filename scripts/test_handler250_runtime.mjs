// Public byte-bound Java status-mode fixture; every target remains data.
import fs from'node:fs';import path from'node:path';import assert from'node:assert/strict';
import{spawn}from'node:child_process';import{pathToFileURL}from'node:url';import{createHash}from'node:crypto';
const argv=process.argv.slice(2),option=k=>argv[argv.indexOf(k)+1],hash=b=>createHash('sha256').update(b).digest('hex');
for(const k of['--plugin-root','--out','--discovery','--discovery-sha'])assert(argv.includes(k));
const ROOT=fs.realpathSync(option('--plugin-root')),OUT=path.resolve(option('--out'));fs.mkdirSync(OUT,{recursive:false});
const read=p=>JSON.parse(fs.readFileSync(p,'utf8')),raw=fs.readFileSync(option('--discovery'));assert(raw.length<=65536);assert.equal(hash(raw),option('--discovery-sha'));
const d=JSON.parse(raw);assert.equal(d.targetSha256,'5f9c1b6fcb019366f835d8f02d9ec3b2957fe619e039410d07f288a9c73f63f0');assert.equal(hash(fs.readFileSync(d.target)),d.targetSha256);
assert.equal(d.rows.length,27);assert.equal(d.rows[0].ea,'0x140055f66');assert.equal(d.rows[15].ea,'0x140052124');
const registers='rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15'.split(' '),addresses=d.rows.map(r=>r.ea);
const args=(mode,path=addresses)=>({target:d.target,level:'project',projection_decoder:'java',projection_mode:mode,projection_path:path,projection_registers:registers});
const specs=[{id:'legacy-opaque27',args:args('opaque-effects'),stores:4},{id:'status-prefix15',args:args('opaque-status',addresses.slice(0,15)),stores:3},
 {id:'status-dispatch27',args:args('opaque-status'),stores:4},{id:'strict-pushfq-refused',args:args('strict'),reject:/Unsupported architectural register/},
 {id:'supplied-initial-flags-refused',args:{...args('opaque-status'),initial_flags:'0x0'},reject:/accepts only/,preflight:true},
 {id:'status-flat-compose-refused',args:{target:d.target,level:'compose',projection_decoder:'java',composition_plan:{strategy:'sequence',representation:'flat',template_mode:'opaque-status',paths:[addresses]}},reject:/requires an explicit transition-chain sequence/,preflight:true}];
const roots=[],cases=[],cfg={artifactDir:OUT,projectRoot:path.join(OUT,'projects'),host:{id:'win32-x64'},requestTimeoutMs:60000,ghidra:{available:true,pythonExe:path.join(ROOT,'runtimes/ghidra/python/python.exe')}};
const{LiftJobs}=await import(pathToFileURL(path.join(ROOT,'source/lift_jobs.js'))),{defineIntegrationTools}=await import(pathToFileURL(path.join(ROOT,'integration_tools.js')));
const jobs=new LiftJobs(cfg,{spawnProcess(exe,args,options){assert.equal(options.windowsHide,true);const c=spawn(exe,args,options),r={pid:c.pid,stdin:'',stdout:'',stderr:'',exited:false,closed:false};roots.push(r);
 const write=c.stdin.write.bind(c.stdin);c.stdin.write=(x,...rest)=>{r.stdin+=String(x);assert(Buffer.byteLength(r.stdin)<=65536);return write(x,...rest)};
 for(const s of['stdout','stderr'])c[s].on('data',x=>{r[s]+=x.toString();assert(Buffer.byteLength(r[s])<=4*1024**2)});
 c.once('exit',(code,signal)=>{r.exited=true;r.exitCode=code;r.exitSignal=signal});r.done=new Promise(resolve=>c.once('close',()=>{r.closed=true;resolve()}));return c}});
const forbidden=()=>{throw Error('No target execution or database access')};const tool=defineIntegrationTools({lifter:jobs,get:forbidden,rpc:forbidden,current:forbidden},cfg).find(x=>x.name==='ig5_ir');
const save=()=>fs.writeFileSync(path.join(OUT,'observed.json'),JSON.stringify({pluginRoot:ROOT,cases,roots:roots.map(({done,...r})=>r),activeRequests:jobs.active.size,nativeTargetExecuted:false,businessAccepted:false,wholeBinaryVerified:false},null,2)+'\n');
try{
 for(const spec of specs){const count=roots.length;let result,error;try{result=await tool.execute(spec.args)}catch(e){error=e}
  let cleanupConfirmed,rootExitConfirmed;
  if(roots.length>count){const r=roots.at(-1);await r.done;const sent=r.stdin.trim().split(/\r?\n/).map(JSON.parse).find(x=>x.id===1),reply=r.stdout.trim().split(/\r?\n/).map(JSON.parse).find(x=>x.id===1);
   assert.equal(reply.nonce,sent.params.nonce);cleanupConfirmed=reply.cleanupConfirmed;rootExitConfirmed=r.exited&&r.closed;assert.equal(cleanupConfirmed,true);assert(rootExitConfirmed)}
  cases.push({id:spec.id,args:spec.args,result,rejected:!!error,...(error?{error:error.message,analysisFailure:error.analysisFailure}:{}),spawnedRoots:roots.length-count,cleanupConfirmed,rootExitConfirmed});save();assert.equal(jobs.active.size,0);
  if(spec.reject){assert(error);assert.match(error.message,spec.reject);if(spec.preflight)assert.equal(roots.length,count);else assert(error.analysisFailure)}
  else{assert.ifError(error);assert.equal(roots.length,count+1);assert.equal(hash(fs.readFileSync(result.reportPath)),result.reportSha256);const core=read(result.reportPath).result;
   assert.equal(core.stores.length,spec.stores);assert.equal(result.dagReferences,core.dag.references);assert.deepEqual(Object.keys(core.registers).sort(),[...registers].sort());
   const head=JSON.stringify(result,null,1).slice(0,512);for(const [key,value]of Object.entries({reportSchema:core.schema,nodeCount:core.dag.nodes.length,dagReferences:core.dag.references,storeCount:core.stores.length,businessAccepted:false,wholeBinaryVerified:false}))assert(head.includes(JSON.stringify(key)+': '+JSON.stringify(value)),key+' missing from bounded preview head');
   assert.deepEqual(core.projectionPath,spec.args.projection_path);for(let i=0;i<core.decodedPath.length;i++){assert.equal(core.decodedPath[i].bytes,d.rows[i].bytes);assert.equal(core.decodedPath[i].decoded.size,d.rows[i].size)}
   for(const key of['nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'])assert.equal(core[key],false);
   const e=core.opaqueEffects[0];assert.equal(core.opaqueEffects.length,1);assert.equal(e.instructionIndex,7);
   if(spec.id.startsWith('status-')){assert.equal(e.unknownBits,59);assert.equal(e.flagImageRefinement.freshInputBits,64);assert.equal(e.flagImageRefinement.effectiveUnknownBits,59)}
   if(spec.id.startsWith('status-')){assert.equal(core.schema,'ig5-pcode-opaque-status-projection-v1');assert.equal(e.flagImageRefinement.knownMask,'0x8c5');assert.equal(e.flagImageRefinement.unknownMask,'0xfffffffffffff73a');assert.equal(e.flagImageRefinement.knownFlags.length,5);assert(e.flagImageRefinement.knownFlags.every(x=>x.definitionInstructionIndex===4));assert.equal(e.replacementOperationCount,24)}
   else{assert.equal(core.schema,'ig5-pcode-opaque-projection-v1');assert.equal(e.replacementOperationCount,3);assert.equal(e.flagImageRefinement,undefined)}
  }
  console.log(JSON.stringify({id:spec.id,rejected:!!error,spawnedRoots:roots.length-count,reportPath:result?.reportPath,reportSha256:result?.reportSha256,error:error?.message}));
 }
 save();fs.writeFileSync(path.join(OUT,'verified.json'),JSON.stringify({passed:true,pluginRoot:ROOT,cases,allStartedRootsExited:true,allStartedRootsCleanupACKs:true,activeRequests:0,
  discovery:{path:option('--discovery'),sha256:option('--discovery-sha')},nativeTargetExecuted:false,businessAccepted:false,wholeBinaryVerified:false,
  scope:'Official byte-bound Java raw translation, fresh opaque-status data and host overlay checks. Strict refusal and external initial flags/compose refusal retained. Independent semantic/CPU/business proof separate.'},null,2)+'\n',{flag:'wx'});
}finally{await jobs.dispose();await jobs.artifacts.dispose()}
