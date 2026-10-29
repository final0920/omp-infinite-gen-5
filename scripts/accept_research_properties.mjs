// Offline longitudinal acceptance. Reads sealed native recordings, never launches the target.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { propertyCase } from './fixtures/research_property_cases.mjs';
import { selectNativeAcceptances, copyNativeCaptures } from './fixtures/native_acceptance_sources.mjs';
import { MODEL_PROPERTY, RECORDED_PROPERTY } from '../source/research_properties.js';
import { prepareSemanticSkeleton, probeSemanticSkeleton } from './evals/semantic_discovery/suite.mjs';
const option=k=>{const n=process.argv.indexOf(k);return n<0?undefined:process.argv[n+1];};
const output=path.resolve(option('--evidence')??''),nativeRoot=option('--native-root');
assert(option('--evidence')&&!fs.existsSync(output),'Choose a fresh evidence directory');
assert(nativeRoot&&option('--native-run'),'Explicit sealed native batch selection required');
fs.mkdirSync(output);const inputs=[];
const selected=selectNativeAcceptances(nativeRoot,[option('--native-run')]);
const recordingRuns=copyNativeCaptures(selected,path.join(output,'artifacts'),selected.receipt.targetSha256,inputs);
const f=await propertyCase(output,recordingRuns);
let result;
try {
  const audit=spawnSync(fileURLToPath(new URL('../runtimes/ghidra/python/python.exe',import.meta.url)),['-I','-B','-X','utf8',fileURLToPath(new URL('./audit_vm_function.py',import.meta.url)),f.assessment.reportPath],{encoding:'utf8',timeout:15000,maxBuffer:256*1024,windowsHide:true});
  assert.equal(audit.status,0,audit.stderr);const independentAudit=JSON.parse(audit.stdout);
  const model=f.propose(MODEL_PROPERTY),native=f.propose(RECORDED_PROPERTY);
  const modelReceipt=await f.verify(model);assert.equal(modelReceipt.status,'pass');
  assert.deepEqual(f.get().research.objectStates.obligations.map(o=>o.status),['closed-in-scope','open']);
  const nativeReceipt=await f.verify(native);assert.equal(nativeReceipt.status,'pass');
  assert(f.get().research.objectStates.obligations.every(o=>o.status==='closed-in-scope'));
  const nativeFull=f.analysis.artifacts.get(nativeReceipt.reportId).result,modelFull=f.analysis.artifacts.get(modelReceipt.reportId).result;
  const widened=structuredClone(native.value.propertyScope);widened.domain.inputs.push('0x2');widened.domain.inputs.sort();
  const unsupported=await f.verify(f.propose(RECORDED_PROPERTY,{propertyScope:widened}));assert.equal(unsupported.status,'unsupported');
  const closed=f.get();
  const debugFiles=inputs.filter(p=>p.path.includes(path.sep+'blobs'+path.sep)),rawFile=path.join(f.cfg.artifactDir,'debug-traces','blobs',path.basename(debugFiles[0].path)),rawBytes=fs.readFileSync(rawFile);
  fs.appendFileSync(rawFile,'x');const rawChanged=f.get();
  assert.deepEqual(rawChanged.research.objectStates.obligations.slice(0,2).map(o=>o.status),['closed-in-scope','stale']);fs.writeFileSync(rawFile,rawBytes);
  // Corrupt only the immutable report's on-disk bytes and restore them after observing invalidation.
  const file=path.join(f.analysis.artifacts.directory('records'),f.program.reportId+'.json'),original=fs.readFileSync(file);
  fs.appendFileSync(file,' ');const changed=f.get();
  assert(changed.research.objectStates.obligations.every(o=>o.status!=='closed-in-scope'));
  fs.writeFileSync(file,original);
  f.update('set-contract',{...f.contract,inputDomain:'Changed research contract domain'});
  assert(f.get().research.objectStates.obligations.every(o=>o.status==='stale'));
  const historical=f.call({action:'research-verification',id:f.task.taskId,verification_id:modelReceipt.reportId});assert.equal(historical.result.status,'pass');
  assert.equal(historical.currentAssessment.status,'stale-or-unverified');
  const suite=prepareSemanticSkeleton(path.join(output,'semantic-suite'),20261023),isolation=probeSemanticSkeleton(suite);
  result={schema:'ig5-research-property-acceptance-v1',ok:true,independentAudit,nativeSelection:selected.source,inputs,taskId:f.task.taskId,
    model:{receipt:modelReceipt.reportId,cases:modelFull.outcome.modelCases,domain:modelFull.scope.domain,status:modelReceipt.status},
    native:{receipt:nativeReceipt.reportId,inputs:nativeFull.scope.domain.inputs,runs:nativeFull.outcome.recordedResult.runs.length,status:nativeReceipt.status},
    expandedNativeScope:unsupported.status,closedBeforeChanges:closed.research.objectStates.obligations,
    rawTamperStates:rawChanged.research.objectStates.obligations,sourceTamperStates:changed.research.objectStates.obligations,contractChangeStates:f.get().research.objectStates.obligations,
    originalPassRetained:historical.result.status,isolation,
    unknowns:['All native inputs outside the explicitly recorded input set','Complete CPU semantics and intermediate write footprint','Independent isolated model investigation'],
    nativeTargetExecuted:false,dataWorkerCleanupConfirmed:f.analysis.jobs.active===null,businessAccepted:false};
} finally { await f.analysis.dispose(); }
fs.writeFileSync(path.join(output,'acceptance.json'),JSON.stringify(result,null,2)+'\n',{flag:'wx'});
process.stdout.write(JSON.stringify(result,null,2)+'\n');
