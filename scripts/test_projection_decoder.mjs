import test from 'node:test';import assert from 'node:assert/strict';
import fs from 'node:fs';import os from 'node:os';import path from 'node:path';
import {JAVA_PROJECTION_RUNTIME_PIN,JAVA_PROJECTION_HELPER_PIN,selectProjectionDecoder,validateDecoderEvidence} from '../source/projection_decoder.js';
import {validateProjection} from '../source/projection_jobs.js';
import {validateComposition,resolveCompositionPlan} from '../source/composition_jobs.js';
import {hashBytes} from '../source/analysis_artifacts.js';
import {defineIntegrationTools} from '../integration_tools.js';
const directory=fs.mkdtempSync(path.join(os.tmpdir(),'ig5-java-decoder-data-'));
test.after(()=>fs.rmSync(directory,{recursive:true,force:true}));
const target=path.join(directory,'not-executable-data.bin');fs.writeFileSync(target,'data only');
const project={target,level:'project',projection_path:['0x140001000'],projection_registers:['rax']};
const plan={strategy:'sequence',paths:[['0x140001000']]};
const clone=value=>structuredClone(value);
test('decoder selection is closed and available only on project/compose public routes',async()=>{
  assert.deepEqual(selectProjectionDecoder({}),{});
  for(const value of ['java','native'])assert.equal(validateProjection({...project,projection_decoder:value}).projection_decoder,value);
  for(const value of [null,false,0,'Java','auto','shell'])assert.throws(()=>validateProjection({...project,projection_decoder:value}));
  const tool=defineIntegrationTools({},{projectRoot:directory}).find(t=>t.name==='ig5_ir');
  assert.deepEqual(tool.parameters.properties.projection_decoder.enum,['native','java']);
  for(const level of ['raw','high','lift','trace'])await assert.rejects(async()=>tool.execute({target,level,projection_decoder:'java'}),/projection_decoder requires/);
});
test('file plan resolution retains decoder selection without forwarding its source reference',()=>{
  const file=path.join(directory,'plan.json');const bytes=Buffer.from(JSON.stringify(plan));fs.writeFileSync(file,bytes);
  const selected=validateComposition({target,level:'compose',projection_decoder:'java',composition_plan_ref:{path:file,sha256:hashBytes(bytes)}});
  const resolved=resolveCompositionPlan(selected);
  assert.equal(resolved.selected.projection_decoder,'java');assert(!Object.hasOwn(resolved.selected,'composition_plan_ref'));
  assert.deepEqual(resolved.selected.composition_plan,validateComposition({target,level:'compose',composition_plan:plan}).composition_plan);
});
const input=Buffer.from('fixed prepared byte data\n'),output=Buffer.from('fixed decoder output data\n');
fs.writeFileSync(path.join(directory,'java-input.json'),input);fs.mkdirSync(path.join(directory,'java-decode'));fs.writeFileSync(path.join(directory,'java-decode/stdout.log'),output);
const processRow=(pid,elapsedMs)=>({pid,status:'completed',exitCode:0,childExitConfirmed:true,jobAssignedAtCreation:true,activeProcessLimit:1,memoryLimitBytes:2*1024**3,elapsedMs});
const final=processRow(102,20);
const reply={projectionDecoder:'java',javaDecoderManifestPin:JAVA_PROJECTION_RUNTIME_PIN,sharedBudgetMs:50000,process:final,
  processStages:[{stage:'java-decode',budgetMs:49000,process:processRow(101,1000)},{stage:'state-computation',budgetMs:48000,process:final}]};
const result={projectionDecoder:'java',javaDecoder:{runtimeManifestPin:JAVA_PROJECTION_RUNTIME_PIN,upstreamManifestPin:'8fc4ae42f775f0139aa5f184c912db71f77e68d661c14564ab6f4820d434abea',helperSha256:JAVA_PROJECTION_HELPER_PIN,language:'x86:LE:64:default',runtimeAssetCount:614,inputSha256:hashBytes(input),outputSha256:hashBytes(output)}};
test('both process cleanups and shared deadline plus staged file digests are required',()=>{
  validateDecoderEvidence({projection_decoder:'java'},result,reply,directory);
  for(const mutate of [r=>{r.processStages[0].process.childExitConfirmed=false;},r=>{r.processStages[0].process.jobAssignedAtCreation=false;},r=>{r.processStages[0].process.activeProcessLimit=2;},r=>{r.processStages[0].process.exitCode=1;},r=>{r.processStages[1].budgetMs=50000;},r=>{r.processStages.pop();},r=>{r.javaDecoderManifestPin='0'.repeat(64);},r=>{r.process={...r.process,pid:103};}]){
    const r=clone(reply);mutate(r);assert.throws(()=>validateDecoderEvidence({projection_decoder:'java'},result,r,directory));
  }
});
test('unrequested route, wrong helper and modified stage files are refused',()=>{
  assert.throws(()=>validateDecoderEvidence({},result,reply,directory));
  validateDecoderEvidence({}, {}, {}, directory);
  const changed=clone(result);changed.javaDecoder.helperSha256='0'.repeat(64);
  assert.throws(()=>validateDecoderEvidence({projection_decoder:'java'},changed,reply,directory));
  fs.writeFileSync(path.join(directory,'java-decode/stdout.log'),'changed');
  assert.throws(()=>validateDecoderEvidence({projection_decoder:'java'},result,reply,directory),/digest mismatch/);
  fs.writeFileSync(path.join(directory,'java-decode/stdout.log'),output);
});
