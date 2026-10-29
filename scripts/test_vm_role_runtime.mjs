// Offline historical recordings and actual owned disassembly process. Never
// opens a PE, requests debugger approval, starts a target or retries headless.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
const option = name => { const index = process.argv.indexOf(name); assert(index >= 0 && process.argv[index + 1], name + ' required'); return path.resolve(process.argv[index + 1]); };
const root = option('--plugin-root'), output = option('--evidence'), catalog = option('--catalog');
fs.mkdirSync(output,{recursive:true});
const load = file => import(pathToFileURL(path.join(root,file)).href);
const { runRecoveryProfile } = await load('source/vm_recovery_profile.js');
const { createAnalysisService } = await load('analysis_tools.js');
const cases = JSON.parse(fs.readFileSync(catalog,'utf8').replace(/^\uFEFF/,''));
assert(Array.isArray(cases)&&cases.length<=16);
const results=[];
for(const testCase of cases){
  const cfg={artifactDir:testCase.artifactDir,projectRoot:path.join(output,testCase.name),requestTimeoutMs:60000,
    host:{id:'win32-x64'},ghidra:{available:true,pythonExe:path.join(root,'runtimes/ghidra/python/python.exe')}};
  const mgr={checkCancelled(){},scope:{getStore(){return {signal:undefined};}}};
  const analysis=mgr.analysis=createAnalysisService(mgr,{...cfg,artifactDir:path.join(output,testCase.name)});
  const {offset,limit,...input}=testCase.input;
  const start=Date.now();
  try{
    const value=await runRecoveryProfile(mgr,{recovery:{roles:input}},cfg);
    const raw=fs.readFileSync(value.roles.reportPath),record=JSON.parse(raw);
    assert.equal(createHash('sha256').update(raw).digest('hex'),value.roles.reportSha256);
    assert.equal(value.roles.businessAccepted,false);assert.equal(value.roles.vmModelProved,false);
    assert.equal(record.result.evidence.process.childExitConfirmed,true);
    results.push({name:testCase.name,status:'completed-offline-only',elapsedMs:Date.now()-start,input,preview:value.roles,
      streamSites:record.result.streamCandidates.map(s=>({pc:s.pc,bytes:s.bytes,samples:s.samples.length})),
      unresolvedSites:record.result.sites.filter(s=>s.decoder.status!=='decoded').map(s=>s.decoder)});
  }catch(error){results.push({name:testCase.name,status:'failed',elapsedMs:Date.now()-start,error:error.message});process.exitCode=1;}
  finally{await mgr.lifter?.dispose();await analysis.dispose();}
}
fs.writeFileSync(path.join(output,'results.json'),JSON.stringify({schema:'ig5-vm-role-runtime-regression-v1',
  nativeTargetExecuted:false,blockedRuntimeRetried:false,catalog:{path:catalog,sha256:createHash('sha256').update(fs.readFileSync(catalog)).digest('hex')},results},null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify(results.map(({name,status,elapsedMs,preview,error})=>({name,status,elapsedMs,counts:preview?.counts,streams:preview?.streamCandidateCount,contexts:preview?.contextCandidateCount,error}))));
