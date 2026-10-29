// Offline acceptance over owned bytes and optional pre-existing native recordings. Never launches a target.
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL,fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { branchMemoryCode,ownedVmImage,ownedBranchVmFixture,bytecodeContract } from './fixtures/vm_bytecode_cases.mjs';

import {selectNativeAcceptances,copyNativeCaptures} from './fixtures/native_acceptance_sources.mjs';

const option=(key,fallback)=>{const at=process.argv.indexOf(key);return at<0?fallback:process.argv[at+1];};
const plugin=path.resolve(option('--plugin-root',fileURLToPath(new URL('..',import.meta.url)))),out=path.resolve(option('--evidence',''));
assert(option('--evidence')&&out!==plugin&&!out.startsWith(plugin+path.sep)&&!fs.existsSync(out),'Choose a fresh evidence directory outside the plugin');
fs.mkdirSync(out,{recursive:true});
const hash=b=>createHash('sha256').update(b).digest('hex');
const {createAnalysisService}=await import(pathToFileURL(path.join(plugin,'analysis_tools.js')));
const {runRecoveryProfile}=await import(pathToFileURL(path.join(plugin,'source/vm_recovery_profile.js')));
const cfg={artifactDir:path.join(out,'artifacts'),projectRoot:path.join(out,'projects')},analysis=createAnalysisService({},cfg),mgr={analysis,checkCancelled(){}};
for(const key of ['rpc','get','performDebug','approve','spawnWorker','run','close'])mgr[key]=()=>assert.fail('Offline acceptance cannot execute a target');
const ref=view=>({id:view.reportId,sha256:view.reportSha256}),calls=[],inputs=[];
async function invoke(mode,input) {const value=(await runRecoveryProfile(mgr,{recovery:{[mode]:input}},cfg))[mode];calls.push({mode,input,result:value});return value;}
try {
const nativeRoot=option('--native-root'), runOptions=[];
for(let i=2;i<process.argv.length;i++)if(process.argv[i]==='--native-run') {
  assert(process.argv[i+1]&&!process.argv[i+1].startsWith('--'),'Missing --native-run folder');runOptions.push(process.argv[++i]);
}
assert(!runOptions.length||nativeRoot,'--native-run requires --native-root');
const selected=nativeRoot?selectNativeAcceptances(nativeRoot,runOptions):null;
const sources=[['branch-memory',branchMemoryCode],['owned-native-image',ownedVmImage()],['owned-branch-native-image',ownedBranchVmFixture().image]];
const nativeSource=selected?sources.find(([name,bytes])=>name!=='branch-memory'&&hash(bytes)===selected.receipt.targetSha256):null;
assert(!selected||nativeSource,'Selected native target is not a registered owned PE');
const recordingRuns=selected?copyNativeCaptures(selected,cfg.artifactDir,hash(nativeSource[1]),inputs):[];
const reports=[];
  for(const [name,bytes] of sources) {
    const contract=bytecodeContract(hash(bytes),name!=='branch-memory'),file=path.join(out,name+'.bin');fs.writeFileSync(file,bytes,{flag:'wx'});
    const declared=await invoke('declare_contract',{contract}),program=await invoke('program',{image_ref:{path:file,sha256:hash(bytes)},contract_ref:ref(declared)});
    const checked=await invoke('function_check',{program_ref:ref(program),...(nativeSource&&name===nativeSource[0]&&recordingRuns.length?{recording_runs:recordingRuns}:{})});
    const body=analysis.artifacts.get(checked.reportId).result;assert.equal(body.status,'pass');assert.equal(body.finiteTesting.cases,256);assert.equal(body.exhaustiveFiniteDomain,true);
    for(const flag of ['universalProof','nativeCpuEquivalenceProved','businessAccepted','wholeVmRecovered'])assert.equal(body[flag],false);
    if(nativeSource&&name===nativeSource[0])assert.equal(body.recordedFunctionEvidence.status,'pass');
    const python=path.join(plugin,'runtimes','ghidra','python','python.exe'),audit=path.join(plugin,'scripts','audit_vm_function.py');
    const independent=spawnSync(python,['-I','-B','-X','utf8',audit,checked.reportPath],{encoding:'utf8',timeout:15000,maxBuffer:256*1024,windowsHide:true});
    assert.equal(independent.status,0,independent.stderr);
    reports.push({name,program:ref(program),verification:ref(checked),path:checked.reportPath,independentAudit:JSON.parse(independent.stdout),
      finiteCases:body.finiteTesting.cases,modelEdges:body.coverage.observedModelEdges.length,recordedFunctionEvidence:body.recordedFunctionEvidence,
      nativeTargetExecuted:false,businessAccepted:false});
  }
  const result={schema:'ig5-function-model-acceptance-v1',ok:true,pluginRoot:plugin,reports,inputs,calls,nativeSelection:selected?{...selected.source,selection:selected.selection}:null,
    dataWorkerCleanupConfirmed:analysis.jobs.active===null,nativeTargetExecuted:false,
    scope:'Independent finite model-domain verification and optional offline checks of original native captures; no new native collection or native CPU/universal proof'};
  fs.writeFileSync(path.join(out,'acceptance.json'),JSON.stringify(result,null,2),{flag:'wx'});
  console.log(JSON.stringify({ok:true,models:reports.length,finiteCases:reports.map(r=>r.finiteCases),recordedRuns:recordingRuns.length,evidence:out}));
} finally {await analysis.dispose();}
