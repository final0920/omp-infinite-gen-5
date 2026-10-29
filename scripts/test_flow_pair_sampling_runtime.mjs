// Explicit real committed-flow data-only acceptance. No PE or native job.
import fs from'node:fs';import path from'node:path';import{pathToFileURL}from'node:url';import{createHash}from'node:crypto';import assert from'node:assert/strict';
const option=(key,optional=false)=>{const i=process.argv.indexOf(key);if(i<0&&optional)return undefined;assert(i>=0&&process.argv[i+1],key+' required');return process.argv[i+1]};
const root=path.resolve(option('--plugin-root')),file=path.resolve(option('--source-flow')),digest=option('--sha256'),original=path.resolve(option('--recording-artifacts')),
  out=path.resolve(option('--evidence')),offsetText=option('--pair-offset',true)??'0',expected=option('--expected-pairs',true),load=f=>import(pathToFileURL(path.join(root,f)));
assert(/^(0|[1-9][0-9]*)$/.test(offsetText)&&Number(offsetText)<=255,'pair offset 0..255');
const offset=Number(offsetText),raw=fs.readFileSync(file);assert.equal(createHash('sha256').update(raw).digest('hex'),digest);const record=JSON.parse(raw);
fs.mkdirSync(out,{recursive:true});const cfg={artifactDir:original,projectRoot:out,requestTimeoutMs:60000},mgr={checkCancelled(){}};
const{createAnalysisService}=await load('analysis_tools.js'),{runRecoveryProfile}=await load('source/vm_recovery_profile.js');
mgr.analysis=createAnalysisService(mgr,{...cfg,artifactDir:path.dirname(path.dirname(path.dirname(file)))});
const args={recovery:{recurrences:{flow_ref:{id:record.id,sha256:digest},sample_strategy:'distinct-source-targets',pair_offset:offset}}},result={schema:'ig5-flow-pair-runtime-acceptance-v1',pluginRoot:root,
  sourceFlow:{path:file,sha256:digest},args,nativeTargetExecuted:false,peFileRead:false,businessAccepted:false};
try{
  const start=Date.now();result.response=await runRecoveryProfile(mgr,args,cfg);result.elapsedMs=Date.now()-start;const r=result.response.recurrences,inv=r.observedSourceTargetInventory;
  assert.equal(r.sampling.strategy,'first-per-observed-source-target-pair-page');assert.equal(r.sampling.pairOffset,offset);assert.equal(r.sampling.allInputWindowsValidated,true);
  assert(inv&&inv.pairs.length<=8&&inv.fullInventoryInReport===true);assert.equal(inv.previewPairOffset,offset);
  if(expected!==undefined){assert(/^[1-9][0-9]*$/.test(expected));assert.equal(inv.pairsTotal,Number(expected));}
  assert(r.counts.selectedCompletePaths>0,'Expected a nonempty observed pair page');assert.equal(r.counts.selectedOrdinaryConsistent,r.counts.selectedCompletePaths);assert.equal(r.counts.selectedOrdinaryUnverified,0);
  assert.equal(inv.inventoryIsOrdinaryStateReplay,false);assert.equal(inv.sourceValuesAreOpcodeLabels,false);assert.equal(r.vmRoleProved,false);assert.equal(r.businessAccepted,false);
  assert.equal(createHash('sha256').update(fs.readFileSync(r.reportPath)).digest('hex'),r.reportSha256);assert.equal(mgr.lifter,undefined);result.passed=true;
  const preview=JSON.stringify(r).slice(0,512);assert(preview.includes(r.reportId)&&preview.includes(r.reportSha256)&&preview.includes('"businessAccepted":false'));
}catch(e){result.passed=false;result.error=e.message;process.exitCode=1;}
finally{await mgr.analysis.dispose();fs.writeFileSync(path.join(out,'result.json'),JSON.stringify(result,null,2)+'\n',{flag:'wx'})}
console.log(JSON.stringify({passed:result.passed,error:result.error,pairOffset:offset,pairs:result.response?.recurrences?.observedSourceTargetInventory?.pairsTotal,selected:result.response?.recurrences?.selectedSourceTargetPairs,elapsedMs:result.elapsedMs}));
