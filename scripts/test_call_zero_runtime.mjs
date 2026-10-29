// Fixed generated CALL rel0 PE as data; never execute the target.
import fs from'node:fs';import path from'node:path';import assert from'node:assert/strict';
import{spawn}from'node:child_process';import{pathToFileURL}from'node:url';import{createHash}from'node:crypto';
const argv=process.argv.slice(2),option=k=>argv[argv.indexOf(k)+1],hash=b=>createHash('sha256').update(b).digest('hex');
for(const k of['--plugin-root','--out','--cases','--cases-sha'])assert(argv.includes(k));
const ROOT=fs.realpathSync(option('--plugin-root')),OUT=path.resolve(option('--out'));fs.mkdirSync(OUT,{recursive:false});
const raw=fs.readFileSync(option('--cases'));assert(raw.length<=65536);assert.equal(hash(raw),option('--cases-sha'));const specs=JSON.parse(raw);
assert.equal(specs.targetSha256,'ef19e116449f152151b6f1a3a63d56da78acd2e4a0e98cbcca6486aa038d756b');
for(const s of specs.cases){assert(['project','compose'].includes(s.args.level));assert.equal(s.args.projection_decoder,'java');assert.equal(hash(fs.readFileSync(s.args.target)),specs.targetSha256)}
const cfg={artifactDir:OUT,projectRoot:path.join(OUT,'projects'),host:{id:'win32-x64'},requestTimeoutMs:60000,
 ghidra:{available:true,pythonExe:path.join(ROOT,'runtimes/ghidra/python/python.exe')}},roots=[],cases=[];
const{LiftJobs}=await import(pathToFileURL(path.join(ROOT,'source/lift_jobs.js'))),{defineIntegrationTools}=await import(pathToFileURL(path.join(ROOT,'integration_tools.js')));
const jobs=new LiftJobs(cfg,{spawnProcess(exe,args,options){assert.equal(options.windowsHide,true);const c=spawn(exe,args,options),r={pid:c.pid,stdin:'',stdout:'',stderr:'',exited:false,closed:false};roots.push(r);
 const write=c.stdin.write.bind(c.stdin);c.stdin.write=(x,...rest)=>{r.stdin+=String(x);assert(Buffer.byteLength(r.stdin)<=65536);return write(x,...rest)};
 for(const s of['stdout','stderr'])c[s].on('data',x=>{r[s]+=x.toString();assert(Buffer.byteLength(r[s])<=4*1024**2)});
 c.once('exit',(code,signal)=>{r.exited=true;r.exitCode=code;r.exitSignal=signal});r.done=new Promise(resolve=>c.once('close',()=>{r.closed=true;resolve()}));return c}});
const forbidden=()=>{throw Error('No target execution or database access')};const tool=defineIntegrationTools({lifter:jobs,get:forbidden,rpc:forbidden,current:forbidden},cfg).find(x=>x.name==='ig5_ir');
const read=p=>JSON.parse(fs.readFileSync(p,'utf8')),save=()=>fs.writeFileSync(path.join(OUT,'observed.json'),JSON.stringify({pluginRoot:ROOT,cases,roots:roots.map(({done,...r})=>r),activeRequests:jobs.active.size,nativeTargetExecuted:false,businessAccepted:false,wholeBinaryVerified:false},null,2)+'\n');
try{
 for(const spec of specs.cases){let result,error,cleanupConfirmed,rootExitConfirmed;const count=roots.length;
  try{result=await tool.execute(spec.args)}catch(e){error=e}
  if(roots.length>count){const r=roots.at(-1);await r.done;const sent=r.stdin.trim().split(/\r?\n/).map(JSON.parse).find(x=>x.id===1),reply=r.stdout.trim().split(/\r?\n/).map(JSON.parse).find(x=>x.id===1);
   assert.equal(reply.nonce,sent.params.nonce);assert.equal(reply.cleanupConfirmed,true);assert(r.exited&&r.closed);cleanupConfirmed=true;rootExitConfirmed=true}
  cases.push({id:spec.id,args:spec.args,result,rejected:!!error,...(error?{error:error.message,analysisFailure:error.analysisFailure}:{}),spawnedRoots:roots.length-count,cleanupConfirmed,rootExitConfirmed});save();assert.equal(jobs.active.size,0);
  if(spec.reject){assert(error);assert(error.message.includes(spec.reject),error.message);if(spec.preflight)assert.equal(roots.length,count);else assert(error.analysisFailure)}
  else{assert.ifError(error);assert.equal(roots.length,count+1);assert.equal(hash(fs.readFileSync(result.reportPath)),result.reportSha256);const c=read(result.reportPath).result;
   for(const k of['nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'])assert.equal(c[k],false);
   assert.equal(c.dag.references,result.dagReferences);
   assert.equal(c.stores.length,1);assert.equal(c.stores[0].pcodeIndex,1);
   const terminal=spec.id==='zero-terminal';if(terminal){assert.equal(c.control.transfer,'call');assert.equal(c.control.returnAddress,'0x140001005');assert.equal(c.path[0].directCall.decoderControlOpcode,'BRANCH');}
   else{assert.equal(c.control.kind,'return');if(spec.args.level==='compose')assert.equal(c.boundaries[0].control.transfer,'call');}
   if(spec.stores!==undefined)assert.equal(c.stores.length,spec.stores);
   if(spec.args.level==='project'){
    assert.deepEqual(c.projectionPath,spec.args.projection_path);assert.equal(c.schema,'ig5-pcode-projection-v1');
    assert.equal(Object.keys(c.registers).length,16);assert.equal(c.decodedPath.length,spec.args.projection_path.length);
   }else{
   assert.equal(c.layers.length,spec.args.composition_plan.paths.length);
   const head=JSON.stringify(result,null,1).slice(0,512);for(const [key,value]of Object.entries({reportSchema:c.schema,nodeCount:c.dag.nodes.length,dagReferences:c.dag.references,storeCount:c.stores.length,sideExitCount:c.sideExits.length,businessAccepted:false,wholeBinaryVerified:false}))assert(head.includes(JSON.stringify(key)+': '+JSON.stringify(value)),key+' missing from bounded preview head');
   assert.equal(c.dag.bindingCount,c.layers.length*18);assert.equal(Object.keys(c.registers).length,16);
   assert.deepEqual(c.templates.map(t=>t.instructions.map(r=>r.ea)),spec.args.composition_plan.paths.filter((p,i,a)=>a.findIndex(q=>JSON.stringify(p)===JSON.stringify(q))===i));
   if(spec.args.composition_plan.template_mode==='opaque-status'){
    assert.equal(c.schema,'ig5-pcode-opaque-status-transition-chain-v1');assert.equal(c.templateMode,'opaque-status');
    const n=c.layers.reduce((n,l)=>n+l.flagImages.length,0);assert.equal(n,c.layers.length-(spec.noFlagImageLayers??0));
    assert.equal(result.statusFlagImageCount,n);assert.equal(result.representationValidation.statusFlagImagesChecked,n);assert.equal(result.representationValidation.statusFlagsExported,false);
    assert.equal(new Set(c.nondeterministicInputs.map(x=>x.node)).size,c.nondeterministicInputs.length);
   }
   }
  }
  console.log(JSON.stringify({id:spec.id,rejected:!!error,refs:result?.dagReferences,reportPath:result?.reportPath,error:error?.message}));
 }
 save();fs.writeFileSync(path.join(OUT,'verified.json'),JSON.stringify({passed:true,pluginRoot:ROOT,cases,allStartedRootsExited:true,allStartedRootsCleanupACKs:true,activeRequests:0,casesInput:{path:option('--cases'),sha256:option('--cases-sha')},nativeTargetExecuted:false,businessAccepted:false,wholeBinaryVerified:false},null,2)+'\n',{flag:'wx'});
}finally{await jobs.dispose();await jobs.artifacts.dispose()}
