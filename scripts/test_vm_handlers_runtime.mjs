// Explicit historical-recording + fixed Java projection acceptance. Never runs
// a protected target and never retries blocked debugger/SLEIGH components.
import fs from'node:fs';import path from'node:path';import{pathToFileURL}from'node:url';import{createHash}from'node:crypto';import assert from'node:assert/strict';
const option=(k,optional=false)=>{const i=process.argv.indexOf(k);if(i<0&&optional)return undefined;assert(i>=0&&process.argv[i+1],k+' required');return process.argv[i+1];};
const root=path.resolve(option('--plugin-root')),file=path.resolve(option('--recurrence')),digest=option('--sha256'),out=path.resolve(option('--evidence')),
  original=path.resolve(option('--recording-artifacts')),sourceBase=path.dirname(path.dirname(path.dirname(file))),load=f=>import(pathToFileURL(path.join(root,f)));
fs.mkdirSync(out,{recursive:true});const b=fs.readFileSync(file);assert.equal(createHash('sha256').update(b).digest('hex'),digest);const record=JSON.parse(b);
const sf=JSON.parse(fs.readFileSync(record.result.sourceFlow.path)).result,target=sf.originalTarget.label;
const{createAnalysisService}=await load('analysis_tools.js'),{runRecoveryProfile}=await load('source/vm_recovery_profile.js'),{LiftJobs}=await load('source/lift_jobs.js');
const cfg={artifactDir:original,projectRoot:out,requestTimeoutMs:60000,host:{id:'win32-x64'},ghidra:{available:true,pythonExe:path.join(root,'runtimes/ghidra/python/python.exe')}},mgr={checkCancelled(){}};
mgr.analysis=createAnalysisService(mgr,{...cfg,artifactDir:sourceBase});mgr.lifter=new LiftJobs({...cfg,artifactDir:out});
const args={recovery:{handlers:{recurrences_ref:{id:record.id,sha256:digest},target}}},result={schema:'ig5-recorded-handlers-runtime-acceptance-v1',pluginRoot:root,
  sourceRecurrence:{path:file,sha256:digest},args,nativeTargetExecuted:false,blockedRuntimeRetried:false,quarantinedEnigmaAccessed:false};
try{
  const start=Date.now();result.response=await runRecoveryProfile(mgr,args,cfg);result.elapsedMs=Date.now()-start;const r=result.response.handlers;
  assert.equal(r.schema,'ig5-recorded-handlers-v1');assert.equal(r.counts.selectedBodies,6);assert.equal(r.counts.projectedBodies,6);assert.equal(r.counts.ordinaryConsistent,4);
  assert.equal(r.counts.partialUnknownPreserved,2);assert.equal(r.counts.unverified,0);assert.equal(r.budgets.distinctSites,81);assert.equal(r.budgets.logicalInstructions,162);
  assert.deepEqual(r.bodies.map(x=>x.sourceValue),['0x88','0x6d','0x4e','0xcb','0x1f','0xa8']);
  assert.deepEqual(r.bodies.map(x=>x.matchedFinalGprs),[16,15,16,16,16,15]);assert.deepEqual(r.bodies.map(x=>x.orderedStores),[1,3,1,1,1,3]);
  assert.equal(r.bodies[3].control.kind,'conditional');assert.equal(r.bodies[3].control.unselectedContinuationAnalyzed,false);
  assert.equal(r.businessAccepted,false);assert.equal(r.vmRoleProved,false);assert.equal(r.wholeVmRecovered,false);
  assert.equal(createHash('sha256').update(fs.readFileSync(r.reportPath)).digest('hex'),r.reportSha256);
  result.passed=true;
}catch(e){result.passed=false;result.error=e.message;process.exitCode=1;}
finally{await mgr.lifter.dispose();await mgr.analysis.dispose();fs.writeFileSync(path.join(out,'result.json'),JSON.stringify(result,null,2)+'\n',{flag:'wx'});}
console.log(JSON.stringify({passed:result.passed,error:result.error,counts:result.response?.handlers.counts,bodies:result.response?.handlers.bodies,elapsedMs:result.elapsedMs}));
