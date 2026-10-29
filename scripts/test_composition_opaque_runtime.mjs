// Real public Java route over owned Ultra raw bytes. No PE or database executes.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';
import {spawn}from'node:child_process';import{pathToFileURL}from'node:url';import{createHash}from'node:crypto';
const argv=process.argv.slice(2),option=k=>argv[argv.indexOf(k)+1],hash=b=>createHash('sha256').update(b).digest('hex');
assert(argv.includes('--out')&&argv.includes('--plugin-root'));
const ROOT=fs.realpathSync(option('--plugin-root')),OUT=path.resolve(option('--out'));fs.mkdirSync(OUT,{recursive:false});
const prior='C:/Users/IG5User/Desktop/无限五代/_research/entry-context-invariants-20261016-v1',read=p=>JSON.parse(fs.readFileSync(p,'utf8'));
const entry=read(path.join(prior,'entry-public-verified.json'));
assert(entry.passed&&hash(fs.readFileSync(entry.result.reportPath))===entry.result.reportSha256);
const a=read(path.join(prior,'handler-public-verified.json')).cases.find(c=>c.id==='first-handler-and-dispatch27');
const b=read(path.join(prior,'handler136-public-verified.json')).cases.find(c=>c.id==='second-handler-and-dispatch22');
assert.equal(hash(fs.readFileSync(entry.args.target)),'5f9c1b6fcb019366f835d8f02d9ec3b2957fe619e039410d07f288a9c73f63f0');
const suffix=n=>Array.from({length:n/2},()=>[a.args.projection_path,b.args.projection_path]).flat(),cases=[],roots=[];
const cfg={artifactDir:OUT,projectRoot:path.join(OUT,'projects'),host:{id:'win32-x64'},requestTimeoutMs:60000,
 ghidra:{available:true,pythonExe:path.join(ROOT,'runtimes/ghidra/python/python.exe')}};
const{LiftJobs}=await import(pathToFileURL(path.join(ROOT,'source/lift_jobs.js')));
const{defineIntegrationTools}=await import(pathToFileURL(path.join(ROOT,'integration_tools.js')));
const jobs=new LiftJobs(cfg,{spawnProcess(exe,args,options){assert.equal(options.windowsHide,true);const c=spawn(exe,args,options);
 const r={pid:c.pid,stdin:'',stdout:'',stderr:'',exited:false,closed:false};roots.push(r);const write=c.stdin.write.bind(c.stdin);
 c.stdin.write=(x,...rest)=>{r.stdin+=String(x);assert(r.stdin.length<=65536);return write(x,...rest);};
 for(const s of['stdout','stderr'])c[s].on('data',v=>{r[s]+=v.toString();assert(Buffer.byteLength(r[s])<4*1024**2);});
 c.once('exit',(code,signal)=>{r.exited=true;r.exitCode=code;r.exitSignal=signal;});r.done=new Promise(resolve=>c.once('close',()=>{r.closed=true;resolve();}));return c;}});
const forbidden=()=>{throw Error('Only existing read-only composition route permitted');};
const tool=defineIntegrationTools({lifter:jobs,get:forbidden,rpc:forbidden,current:forbidden},cfg).find(t=>t.name==='ig5_ir');
const specs=[{id:'entry-only',paths:[entry.args.projection_path],live:1,effects:4,stores:21},
 {id:'entry-plus2',paths:[entry.args.projection_path,...suffix(2)],live:1,effects:4,stores:25},
 {id:'entry-plus16',paths:[entry.args.projection_path,...suffix(16)],live:1,effects:4,stores:53},
 {id:'repeat-entry',paths:[entry.args.projection_path,entry.args.projection_path],live:2,effects:8,stores:42},
 {id:'strict-entry-refused',paths:[entry.args.projection_path],strict:true,reject:/unsupported|undefined|unmodeled|flags|BSWAP|CALLOTHER/i},
 {id:'entry-plus24-memory-refused',paths:[entry.args.projection_path,...suffix(24)],reject:/expanded memory byte budget exceeded/}];
const save=()=>fs.writeFileSync(path.join(OUT,'observed.json'),JSON.stringify({pluginRoot:ROOT,cases,roots:roots.map(({done,...r})=>r),activeRequests:jobs.active.size,
 entryReference:{path:entry.result.reportPath,sha256:entry.result.reportSha256},nativeTargetExecuted:false,businessAccepted:false,wholeBinaryVerified:false},null,2)+'\n');
try{
 for(const spec of specs){
  const args={target:entry.args.target,level:'compose',projection_decoder:'java',composition_plan:{strategy:'sequence',paths:spec.paths,
   indirect_mode:'guarded-target',representation:'transition-chain',...(spec.strict?{}:{template_mode:'opaque-effects'})}};
  let result,error;try{result=await tool.execute(args);}catch(e){error=e;}
  const root=roots.at(-1);await root.done;
  const sent=root.stdin.trim().split(/\r?\n/).map(JSON.parse).find(r=>r.id===1),reply=root.stdout.trim().split(/\r?\n/).map(JSON.parse).find(r=>r.id===1);
  cases.push({id:spec.id,args,result,rejected:!!error,...(error?{error:error.message,analysisFailure:error.analysisFailure}:{}),
   cleanupConfirmed:reply?.cleanupConfirmed,rootExitConfirmed:root.exited&&root.closed});save();
  assert.equal(reply.nonce,sent.params.nonce);assert.equal(reply.cleanupConfirmed,true);assert(root.exited&&root.closed);assert.equal(jobs.active.size,0);
  if(spec.reject){assert(error?.analysisFailure);assert.match(error.message,spec.reject);}
  else{
   assert.ifError(error);assert.equal(hash(fs.readFileSync(result.reportPath)),result.reportSha256);const core=read(result.reportPath).result;
   assert.equal(core.schema,'ig5-pcode-opaque-transition-chain-v1');assert.equal(core.nondeterministicInputs.length,spec.live);
   assert.equal(core.statistics.expandedAbstractedInstructions,spec.effects);assert.equal(core.stores.length,spec.stores);
   assert.equal(core.layers.length,spec.paths.length);assert.equal(core.sideExits.length,spec.paths.length-1);
   assert.equal(result.representationValidation.liveFreshUnknowns,spec.live);assert.equal(result.representationValidation.memoryBindingSourcesChecked,spec.paths.length);
   for(const k of['nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'])assert.equal(core[k],false);
  }
  console.log(JSON.stringify({id:spec.id,rejected:!!error,...(result?{statistics:result.statistics,retainedDepth:result.retainedExpressionDepth,
   expandedDepth:result.expandedDependencyDepth,hostValidation:result.representationValidation,reportPath:result.reportPath}:{error:error.message})}));
 }
 save();fs.writeFileSync(path.join(OUT,'verified.json'),JSON.stringify({passed:true,pluginRoot:ROOT,cases,allRootsExited:true,allCleanupACKs:true,activeRequests:0,
  entryReference:{path:entry.result.reportPath,sha256:entry.result.reportSha256},nativeTargetExecuted:false,businessAccepted:false,wholeBinaryVerified:false,
  scope:'Explicit conservative fixed-code state-chain translation. Old strict refusal and original memory budget refusal remain. No exact CPU, relocation/native reachability or complete protected-business proof.'},null,2)+'\n',{flag:'wx'});
}finally{await jobs.dispose();await jobs.artifacts.dispose();}
