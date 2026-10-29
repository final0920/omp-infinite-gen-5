// Read-only real pinned Java decoding + public ig5_ir route. Never runs a PE.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';import {pathToFileURL} from 'node:url';import {createHash} from 'node:crypto';
const args=process.argv.slice(2),option=name=>args[args.indexOf(name)+1],hash=b=>createHash('sha256').update(b).digest('hex');
assert(args.includes('--out') && args.includes('--plugin-root'),'Explicit new output directory and plugin root required');
const MAIN=fs.realpathSync(option('--plugin-root')),OUT=path.resolve(option('--out'));fs.mkdirSync(OUT,{recursive:false});
const prior='C:/Users/IG5User/Desktop/无限五代/_research/entry-context-invariants-20261016-v1';
const read=p=>JSON.parse(fs.readFileSync(p,'utf8'));
const first=read(path.join(prior,'handler-public-verified.json')).cases.find(c=>c.id==='first-handler-and-dispatch27');
const second=read(path.join(prior,'handler136-public-verified.json')).cases.find(c=>c.id==='second-handler-and-dispatch22');
assert.equal(hash(fs.readFileSync(first.args.target)),'5f9c1b6fcb019366f835d8f02d9ec3b2957fe619e039410d07f288a9c73f63f0');
const cfg={artifactDir:OUT,projectRoot:path.join(OUT,'projects'),host:{id:'win32-x64'},requestTimeoutMs:60000,
  ghidra:{available:true,pythonExe:path.join(MAIN,'runtimes/ghidra/python/python.exe')}};
const {LiftJobs}=await import(pathToFileURL(path.join(MAIN,'source/lift_jobs.js')));
const {defineIntegrationTools}=await import(pathToFileURL(path.join(MAIN,'integration_tools.js')));
const cases=[],roots=[],sourceFiles=['worker/projection_composition.py','worker/composition_selection.py','worker/projection_worker.py',
  'worker/ig5_project.py','source/composition_jobs.js','source/composition_chain.js','integration_tools.js'];
const pins=sourceFiles.map(file=>({file,sha256:hash(fs.readFileSync(path.join(MAIN,file)))}));
const jobs=new LiftJobs(cfg,{spawnProcess(exe,argv,options){
  assert.equal(options.windowsHide,true);const c=spawn(exe,argv,options),r={pid:c.pid,stdin:'',stdout:'',stderr:'',exited:false,closed:false};roots.push(r);
  const w=c.stdin.write.bind(c.stdin);c.stdin.write=(x,...rest)=>{r.stdin+=String(x);assert(r.stdin.length<=65536);return w(x,...rest);};
  for(const s of ['stdout','stderr'])c[s].on('data',b=>{r[s]+=b.toString();assert(Buffer.byteLength(r[s])<4*1024**2);});
  c.once('exit',(code,signal)=>{r.exited=true;r.exitCode=code;r.exitSignal=signal;});
  r.done=new Promise(resolve=>c.once('close',()=>{r.closed=true;resolve();}));return c;
}});
const forbidden=()=>{throw Error('Only existing read-only public IR permitted');};
const tool=defineIntegrationTools({lifter:jobs,get:forbidden,rpc:forbidden,current:forbidden},cfg).find(t=>t.name==='ig5_ir');
const save=()=>fs.writeFileSync(path.join(OUT,'observed.json'),JSON.stringify({pluginRoot:MAIN,pins,cases,
  roots:roots.map(({done,...r})=>r),activeRequests:jobs.active.size,nativeTargetExecuted:false,businessAccepted:false,wholeBinaryVerified:false},null,2)+'\n');
try {
  for(const applications of [2,4,8,16,0]) {
    const flat=applications===0,count=flat?16:applications;
    const plan={strategy:'sequence',indirect_mode:'guarded-target',paths:Array.from({length:count/2},()=>[first.args.projection_path,second.args.projection_path]).flat(),
      ...(flat?{}:{representation:'transition-chain'})};
    const call={target:first.args.target,level:'compose',projection_decoder:'java',composition_plan:plan};
    let result,error;try{result=await tool.execute(call);}catch(e){error=e;}
    const root=roots.at(-1);await root.done;
    const sent=root.stdin.trim().split(/\r?\n/).map(JSON.parse).find(r=>r.id===1),reply=root.stdout.trim().split(/\r?\n/).map(JSON.parse).find(r=>r.id===1);
    const row={applications:count,representation:flat?'flat':'transition-chain',args:call,result,rejected:!!error,
      ...(error?{error:error.message,analysisFailure:error.analysisFailure}:{}),cleanupConfirmed:reply?.cleanupConfirmed,rootExitConfirmed:root.exited&&root.closed};
    cases.push(row);save();assert.equal(reply.nonce,sent.params.nonce);assert.equal(reply.cleanupConfirmed,true);assert(root.exited&&root.closed);assert.equal(jobs.active.size,0);
    if(flat){assert(error?.analysisFailure);assert.match(error.message,/DAG depth budget exceeded/);}
    else {
      assert.ifError(error);assert.equal(hash(fs.readFileSync(result.reportPath)),result.reportSha256);
      const core=read(result.reportPath).result;assert.equal(core.schema,'ig5-pcode-transition-chain-v1');
      assert.equal(core.layers.length,count);assert.equal(core.stores.length,count*2);assert.equal(core.sideExits.length,count-1);
      assert.equal(core.statistics.logicalInstructions,count*49/2);assert.equal(core.statistics.expandedMemoryBytes,count*38);
      assert.equal(core.dag.bindingCount,count*18);assert.equal(result.javaDecoder.runtimeAssetCount,614);
      for(const k of ['nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'])assert.equal(core[k],false);
    }
    console.log(JSON.stringify({applications:count,representation:row.representation,rejected:!!error,
      ...(result?{statistics:result.statistics,retainedDepth:result.retainedExpressionDepth,expandedDepth:result.expandedDependencyDepth,reportPath:result.reportPath}:{error:error.message})}));
  }
  save();fs.writeFileSync(path.join(OUT,'verified.json'),JSON.stringify({passed:true,cases,pins,pluginRoot:MAIN,allRootsExited:true,allCleanupACKs:true,activeRequests:0,
    nativeTargetExecuted:false,businessAccepted:false,wholeBinaryVerified:false,
    scope:'Explicit chain acceptance and unchanged default flat refusal are distinct. Real byte-bound decoding/translation only; no native reachability, exact3.8 or protected-business proof.'},null,2)+'\n',{flag:'wx'});
} finally {await jobs.dispose();await jobs.artifacts.dispose();}
