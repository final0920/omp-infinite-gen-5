// Explicit offline genuine-recording pipeline. Never executes a PE, invokes
// headless/native SLEIGH, or accesses the quarantined Enigma target.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
const option = key => { const i=process.argv.indexOf(key);assert(i>=0&&process.argv[i+1],key+' required');return path.resolve(process.argv[i+1]); };
const root=option('--plugin-root'),source=option('--roles-results'),output=option('--evidence');
fs.mkdirSync(output,{recursive:true});
const load=file=>import(pathToFileURL(path.join(root,file)).href);
const {runRecoveryProfile}=await load('source/vm_recovery_profile.js'),{createAnalysisService}=await load('analysis_tools.js');
const index=JSON.parse(fs.readFileSync(source,'utf8')),catalog=JSON.parse(fs.readFileSync(index.catalog.path,'utf8').replace(/^\uFEFF/,''));
const c=index.results.find(c=>c.name==='ultra-first-four-windows'),original=catalog.find(c=>c.name==='ultra-first-four-windows');assert(c&&original);
const raw=fs.readFileSync(c.preview.reportPath);assert.equal(createHash('sha256').update(raw).digest('hex'),c.preview.reportSha256);
const sourceRecord=JSON.parse(fs.readFileSync(path.join(original.artifactDir,'debug-traces/records',original.input.recordings[0].id+'.json'),'utf8'));
const target=sourceRecord.target||sourceRecord.result.target;assert(target);
const cfg={artifactDir:original.artifactDir,projectRoot:output,requestTimeoutMs:60000,host:{id:'win32-x64'},ghidra:{available:true,pythonExe:path.join(root,'runtimes/ghidra/python/python.exe')}};
const mgr={checkCancelled(){},scope:{getStore(){return {signal:undefined};}}};
mgr.analysis=createAnalysisService(mgr,{...cfg,artifactDir:path.dirname(path.dirname(path.dirname(c.preview.reportPath)))});
const args={recovery:{flow:{roles_ref:{id:path.basename(c.preview.reportPath,'.json'),sha256:c.preview.reportSha256},target}}};
if(process.argv.includes('--semantic-check'))args.recovery.flow.semantic_check=true;
const result={schema:'ig5-vm-flow-runtime-acceptance-v1',pluginRoot:root,sourceRoleReport:{path:c.preview.reportPath,sha256:c.preview.reportSha256},args,
  nativeTargetExecuted:false,blockedRuntimeRetried:false,enigmaTargetAccessed:false};
try{
  const start=Date.now();result.response=await runRecoveryProfile(mgr,args,cfg);result.elapsedMs=Date.now()-start;
  const f=result.response.flow;assert.equal(f.status,'source-indexed-load-reaches-indirect-target');assert.equal(f.instructionCount,12);
  assert.equal(f.preserved.orderedStores,1);assert.equal(f.preserved.rawPcodeOperations,111);
  assert.equal(f.indexedReads.length,1);assert.equal(f.sourceLoad.bytes,1);assert.equal(f.vmRoleProved,false);assert.equal(f.businessAccepted,false);
  if(args.recovery.flow.semantic_check){assert.equal(f.schema,'ig5-fetch-control-assessed-v1');assert.equal(f.semanticNonconstancyProved,true);
    assert.equal(f.semanticAssessment.hostWitnessReplayVerified,true);assert.equal(f.semanticAssessment.queries.length,4);}
  assert.equal(createHash('sha256').update(fs.readFileSync(f.reportPath)).digest('hex'),f.reportSha256);
  result.passed=true;console.log(JSON.stringify({passed:true,elapsedMs:result.elapsedMs,flow:f}));
}catch(e){result.passed=false;result.error=e.message;process.exitCode=1;console.log(JSON.stringify({error:e.message}));}
finally{await mgr.lifter?.dispose();await mgr.analysis.dispose();fs.writeFileSync(path.join(output,'result.json'),JSON.stringify(result,null,2)+'\n',{flag:'wx'});}
