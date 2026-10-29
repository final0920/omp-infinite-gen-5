// Explicit data-only genuine historical acceptance. No executable is opened or
// run; the committed flow and its original recording reports are revalidated.
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
const option=(k,required=true)=>{const i=process.argv.indexOf(k);if(i<0&&!required)return undefined;assert(i>=0&&process.argv[i+1],k+' required');return process.argv[i+1];};
const root=path.resolve(option('--plugin-root')),file=path.resolve(option('--source-flow')),digest=option('--sha256'),out=path.resolve(option('--evidence'));
fs.mkdirSync(out,{recursive:true});
const raw=fs.readFileSync(file);assert.equal(createHash('sha256').update(raw).digest('hex'),digest);const source=JSON.parse(raw);
const artifacts=path.dirname(path.dirname(path.dirname(file))),recordingArtifacts=path.resolve(option('--recording-artifacts',false)||artifacts);
const load=f=>import(pathToFileURL(path.join(root,f)).href),{createAnalysisService}=await load('analysis_tools.js'),{runRecoveryProfile}=await load('source/vm_recovery_profile.js');
const cfg={artifactDir:recordingArtifacts,projectRoot:out,requestTimeoutMs:60000},mgr={checkCancelled(){},scope:{getStore(){return{signal:undefined};}}};
mgr.analysis=createAnalysisService(mgr,{...cfg,artifactDir:artifacts});
const args={recovery:{recurrences:{flow_ref:{id:source.id,sha256:digest}}}},result={schema:'ig5-flow-recurrence-runtime-acceptance-v1',pluginRoot:root,sourceFlow:{path:file,sha256:digest},args,
  nativeTargetExecuted:false,blockedRuntimeRetried:false,quarantinedEnigmaAccessed:false};
try{
  const before=Date.now();result.response=await runRecoveryProfile(mgr,args,cfg);result.elapsedMs=Date.now()-before;const r=result.response.recurrences;
  assert.equal(r.schema,'ig5-flow-recurrences-v1');assert.equal(r.counts.sourceByteEvents,78);assert.equal(r.counts.completeDescriptorPaths,77);assert.equal(r.counts.pathMismatches,0);
  assert.equal(r.counts.selectedCompletePaths,8);assert.equal(r.counts.selectedOrdinaryConsistent,8);assert.equal(r.counts.selectedOrdinaryUnverified,0);
  assert.equal(r.partialCapturedPaths.length,1);assert.equal(r.partialCapturedPaths[0].capturedGroups,6);assert.equal(r.selectedOrdinaryStateConsistent,true);
  assert.equal(r.sourceAddressInputUpdates[0].name,'rsi');assert.deepEqual(r.sourceAddressInputUpdates[0].observedDeltasModulo64,['0x1']);
  assert.deepEqual(r.selectedSourceTargetPairs.map(p=>p.sourceValue).sort(),['0x4e','0x88']);assert.equal(r.vmRoleProved,false);assert.equal(r.independentInputCoverageProved,false);
  assert.equal(createHash('sha256').update(fs.readFileSync(r.reportPath)).digest('hex'),r.reportSha256);assert.equal(mgr.lifter,undefined);
  result.passed=true;
}catch(error){result.passed=false;result.error=error.message;process.exitCode=1;}
finally{await mgr.analysis.dispose();fs.writeFileSync(path.join(out,'result.json'),JSON.stringify(result,null,2)+'\n',{flag:'wx'});}
console.log(JSON.stringify(result));
