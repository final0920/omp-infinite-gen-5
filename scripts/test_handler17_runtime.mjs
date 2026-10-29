// Owned fixed-image learning fixture, public read-only Java project/compose.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';
import {spawn}from'node:child_process';import{pathToFileURL}from'node:url';import{createHash}from'node:crypto';
const argv=process.argv.slice(2),option=k=>argv[argv.indexOf(k)+1],hash=b=>createHash('sha256').update(b).digest('hex');
assert(argv.includes('--out')&&argv.includes('--plugin-root')&&argv.includes('--discovery')&&argv.includes('--discovery-sha'));
const ROOT=fs.realpathSync(option('--plugin-root')),OUT=path.resolve(option('--out'));fs.mkdirSync(OUT,{recursive:false});
const read=p=>JSON.parse(fs.readFileSync(p,'utf8')),discoveryRaw=fs.readFileSync(option('--discovery'));assert(discoveryRaw.length<=65536);
assert.equal(hash(discoveryRaw),option('--discovery-sha'));const discovery=JSON.parse(discoveryRaw);
assert.equal(discovery.targetSha256,'5f9c1b6fcb019366f835d8f02d9ec3b2957fe619e039410d07f288a9c73f63f0');
assert.equal(hash(fs.readFileSync(discovery.target)),discovery.targetSha256);assert.equal(discovery.rows.length,10);
const prior='C:/Users/IG5User/.dsh/ig5/artifacts/modern-protection-20261014/tool-research/opaque-chain-20261016-v1-source/verified.json';
assert.equal(hash(fs.readFileSync(prior)),'529a1990936b79689c531d9f7a1754c4e305ec3a5a9f4dc8fc38e98b94121601');
const old=read(prior).cases.find(c=>c.id==='entry-plus16'),paths=old.args.composition_plan.paths;
const incoming=[...paths,paths[1]],handler=discovery.rows.map(r=>r.ea),dispatch=paths[1].slice(-12);
assert.equal(handler[0],'0x1400525ca');assert.equal(dispatch[0],'0x140052124');
const registers='rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15'.split(' ');
const specs=[{id:'entry-plus17',args:{target:discovery.target,level:'compose',projection_decoder:'java',composition_plan:{...old.args.composition_plan,paths:incoming}},stores:55,layers:18},
 {id:'literal-push6',args:{target:discovery.target,level:'project',projection_decoder:'java',projection_path:handler.slice(0,6),projection_registers:registers},stores:1},
 {id:'literal-push-and-stack-check10',args:{target:discovery.target,level:'project',projection_decoder:'java',projection_path:handler,projection_registers:registers},stores:1},
 {id:'literal-fast-dispatch22',args:{target:discovery.target,level:'project',projection_decoder:'java',projection_mode:'guarded-path',projection_path:[...handler,...dispatch],projection_registers:registers},stores:2,exits:1},
 {id:'combined133-distinct-refused',args:{target:discovery.target,level:'compose',projection_decoder:'java',composition_plan:{...old.args.composition_plan,paths:[...incoming,[...handler,...dispatch]]}},reject:/distinct.*(?:budget|128)|(?:budget|128).*distinct/i,preflight:true}];
if(argv.includes('--next-discovery')){
 assert(argv.includes('--next-discovery-sha'));const raw=fs.readFileSync(option('--next-discovery'));assert(raw.length<=65536);assert.equal(hash(raw),option('--next-discovery-sha'));
 const next=JSON.parse(raw);assert.equal(next.targetSha256,discovery.targetSha256);assert.equal(next.rows.length,16);assert.equal(next.rows[0].ea,'0x1400545e7');
 const prefix=next.rows.map(r=>r.ea);specs.splice(specs.length-1,0,
  {id:'context137-check16',args:{target:discovery.target,level:'project',projection_decoder:'java',projection_path:prefix,projection_registers:registers},stores:1,discoveryRows:next.rows},
  {id:'context137-fast28',args:{target:discovery.target,level:'project',projection_decoder:'java',projection_mode:'guarded-path',projection_path:[...prefix,...dispatch],projection_registers:registers},stores:2,exits:1,discoveryRows:next.rows});
}
const roots=[],cases=[];const cfg={artifactDir:OUT,projectRoot:path.join(OUT,'projects'),host:{id:'win32-x64'},requestTimeoutMs:60000,
 ghidra:{available:true,pythonExe:path.join(ROOT,'runtimes/ghidra/python/python.exe')}};
const {LiftJobs}=await import(pathToFileURL(path.join(ROOT,'source/lift_jobs.js')));
const {defineIntegrationTools}=await import(pathToFileURL(path.join(ROOT,'integration_tools.js')));
const jobs=new LiftJobs(cfg,{spawnProcess(exe,args,options){assert.equal(options.windowsHide,true);const c=spawn(exe,args,options);
 const r={pid:c.pid,stdin:'',stdout:'',stderr:'',exited:false,closed:false};roots.push(r);const write=c.stdin.write.bind(c.stdin);
 c.stdin.write=(x,...rest)=>{r.stdin+=String(x);assert(Buffer.byteLength(r.stdin)<=65536);return write(x,...rest)};
 for(const stream of ['stdout','stderr'])c[stream].on('data',v=>{r[stream]+=v.toString();assert(Buffer.byteLength(r[stream])<=4*1024**2)});
 c.once('exit',(code,signal)=>{r.exited=true;r.exitCode=code;r.exitSignal=signal});r.done=new Promise(resolve=>c.once('close',()=>{r.closed=true;resolve()}));return c;}});
const forbidden=()=>{throw Error('No target execution or database route permitted')};
const tool=defineIntegrationTools({lifter:jobs,get:forbidden,rpc:forbidden,current:forbidden},cfg).find(t=>t.name==='ig5_ir');
const save=()=>fs.writeFileSync(path.join(OUT,'observed.json'),JSON.stringify({pluginRoot:ROOT,discovery:{path:option('--discovery'),sha256:option('--discovery-sha')},cases,
 roots:roots.map(({done,...r})=>r),activeRequests:jobs.active.size,nativeTargetExecuted:false,businessAccepted:false,wholeBinaryVerified:false},null,2)+'\n');
try{
 for(const spec of specs){
  const count=roots.length;let result,error;try{result=await tool.execute(spec.args)}catch(e){error=e}
  let cleanupConfirmed,rootExitConfirmed;
  if(roots.length>count){const r=roots.at(-1);await r.done;const sent=r.stdin.trim().split(/\r?\n/).map(JSON.parse).find(x=>x.id===1),reply=r.stdout.trim().split(/\r?\n/).map(JSON.parse).find(x=>x.id===1);
   assert.equal(reply.nonce,sent.params.nonce);cleanupConfirmed=reply.cleanupConfirmed;rootExitConfirmed=r.exited&&r.closed;
   assert.equal(cleanupConfirmed,true);assert(rootExitConfirmed);}
  cases.push({id:spec.id,args:spec.args,result,rejected:!!error,...(error?{error:error.message,analysisFailure:error.analysisFailure}:{}),cleanupConfirmed,rootExitConfirmed,spawnedRoots:roots.length-count});save();
  assert.equal(jobs.active.size,0);
  if(spec.reject){assert(error);assert.match(error.message,spec.reject);if(spec.preflight)assert.equal(roots.length,count)}
  else{assert.ifError(error);assert.equal(roots.length,count+1);assert.equal(hash(fs.readFileSync(result.reportPath)),result.reportSha256);const core=read(result.reportPath).result;
   assert.equal(core.stores.length,spec.stores);assert.deepEqual(Object.keys(core.registers).sort(),[...registers].sort());assert.equal(result.dagReferences,core.dag.references);
   if(spec.layers)assert.equal(core.layers.length,spec.layers);if(spec.exits)assert.equal(core.sideExits.length,spec.exits);
   for(const key of ['nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'])assert.equal(core[key],false);
   if(spec.id!=='entry-plus17')for(const row of spec.discoveryRows??discovery.rows.slice(0,spec.id==='literal-push6'?6:10)){const actual=core.decodedPath.find(r=>r.ea===row.ea);assert(actual);assert.equal(actual.bytes,row.bytes);assert.equal(actual.decoded.size,row.size)}
  }
  console.log(JSON.stringify({id:spec.id,rejected:!!error,spawnedRoots:roots.length-count,...(result?{reportPath:result.reportPath,reportSha256:result.reportSha256,statistics:result.statistics}:{error:error.message})}));
 }
 save();fs.writeFileSync(path.join(OUT,'verified.json'),JSON.stringify({passed:true,pluginRoot:ROOT,cases,allStartedRootsExited:true,allStartedRootsCleanupACKs:true,activeRequests:0,
  discovery:{path:option('--discovery'),sha256:option('--discovery-sha')},nativeTargetExecuted:false,businessAccepted:false,wholeBinaryVerified:false,
  scope:'Actual official Java fixed-byte translation. All16 GPRs, ordered memory and complementary stack-check exit retained. Independent semantic proof, native reachability and complete business acceptance separate.'},null,2)+'\n',{flag:'wx'});
}finally{await jobs.dispose();await jobs.artifacts.dispose()}
