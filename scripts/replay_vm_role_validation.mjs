// Explicit old single-run negative acceptance. No entry/input/VM-instance proof is fabricated.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath,pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';
const option=(k,f)=>{const i=process.argv.indexOf(k);return i<0?f:process.argv[i+1];};
const plugin=path.resolve(option('--plugin-root',fileURLToPath(new URL('..',import.meta.url))));
const dir=path.resolve(option('--artifact-dir','')),out=path.resolve(option('--evidence',''));
assert(option('--artifact-dir')&&option('--evidence')&&!fs.existsSync(out),'Explicit source and fresh evidence directory required');
fs.mkdirSync(out,{recursive:true});
const {createAnalysisService}=await import(pathToFileURL(path.join(plugin,'analysis_tools.js')));
const {runRecoveryProfile}=await import(pathToFileURL(path.join(plugin,'source/vm_recovery_profile.js')));
const cfg={artifactDir:dir,projectRoot:path.join(out,'projects')},analysis=createAnalysisService({},cfg),mgr={analysis,checkCancelled(){}};
for(const k of ['rpc','get','performDebug','approve','spawnWorker','run','close'])mgr[k]=()=>assert.fail('Offline validation cannot execute targets');
const context={id:'840eab55-71d8-485f-8b17-5a51ee12864d',sha256:'3c969bf00943b018665f2855110b5fb2039dc86c5690557034745aa77a3f3f50'};
const ref=v=>({id:v.reportId,sha256:v.reportSha256}),calls=[];
const call=async(mode,input)=>{const result=(await runRecoveryProfile(mgr,{recovery:{[mode]:input}},cfg))[mode];calls.push({mode,input,result});return result;};
try {
  assert.equal(analysis.artifacts.metadata(context.id).result.recordSha256,context.sha256);
  const model=analysis.artifacts.get(context.id).result,selectionRef=model.sourceReports[0].selection;
  assert.equal(analysis.artifacts.metadata(selectionRef.id).result.recordSha256,selectionRef.sha256);
  const source=analysis.artifacts.get(selectionRef.id).result.source;
  const contract={schema:'ig5-function-contract-v1',targetSha256:model.targetSha256,entryRva:'0x0',normalReturn:'native-ret',
    input:{register:'rcx',bits:64,minimum:'0x0',maximum:'0xffffffffffffffff'},outputs:{returnRegister:'rax',memory:[]},
    environment:'single-threaded-no-external-calls',exclusions:['Entry RVA 0 is an unverified negative-test proposal; this is not the actual function contract','All business acceptance excluded']};
  const c=ref(await call('declare_contract',{contract})),comparison=ref(await call('role_compare',{context_refs:[context],contract_ref:c}));
  const recordings=source.windows.map(w=>({id:w.reportId,sha256:w.reportSha256}));
  const v=await call('role_validate',{comparison_ref:comparison,recording_bindings:[{context_ref:context,recordings}]}),result=analysis.artifacts.get(v.reportId).result;
  assert.equal(result.independence.distinctObservedRuns,1);assert.equal(result.independence.rawCaptureRevalidated,true);
  assert.equal(result.independence.distinctEntryInputs,0);assert.equal(result.vmRoleProved,false);assert.equal(result.businessAccepted,false);
  assert.equal(result.runs[0].entryMatched,false);assert.equal(analysis.jobs.active,null);
  const receipt={schema:'ig5-recorded-role-negative-acceptance-v1',ok:true,sourceContext:context,calls,result,
    dataWorkerCleanupConfirmed:true,nativeTargetExecuted:false,scope:'Original single-run context raw rebinding only; deliberately unverified entry remains rejected'};
  fs.writeFileSync(path.join(out,'acceptance.json'),JSON.stringify(receipt,null,2),{flag:'wx'});
  console.log(JSON.stringify({ok:true,originalWindows:recordings.length,matchedGroups:result.runs[0].matchedGroups,status:result.status,entryMatched:false,evidence:out}));
} finally {await analysis.dispose();}
