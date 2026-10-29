import fs from 'node:fs';import path from 'node:path';
import {bitvectorHost} from '../../fixtures/bitvector_host.mjs';import {smallVm} from '../../fixtures/vm_instance_cases.mjs';import {AnalysisJobs} from '../../../source/analysis_jobs.js';
export async function runModelAlgorithm(task,runRoot){
 if(task.id==='owned-bv-add-zero'){
  const root=path.join(runRoot,'algorithm');fs.mkdirSync(root,{recursive:false});const pluginRoot=path.resolve(import.meta.dirname,'../../..'),f=bitvectorHost(fs.realpathSync(root),pluginRoot);
  try{const prepared=await f.call({action:'candidate-prepare',source_ref:f.saveSource(),root_node:3}),v=await f.call({action:'candidate-simplify',candidate_ref:prepared.candidateRef});return {scope:'actual provider/pinned solver/independent replay on synthetic IR',status:v.status,code:v.code??null,reason:v.reason??null,equivalentInIR:v.equivalentInIR,cost:v.cost,verification:v.verification??null,originalRetained:v.originalRetained,wholeFunctionRecovered:false,nativeProved:false};}finally{await f.dispose();}
 }
 const model=smallVm({haltOnly:true});model.contract={...model.contract,minimum:'0x0',maximum:'0x7'};const jobs=new AnalysisJobs();try{const checked=await jobs.runSettled('vm-instance-check',{models:[model]});return {scope:'actual existing bounded worker on declared small VM',schema:checked.schema,checks:checked.checks.map(({transcript,...c})=>c),initialResults:task.raw.initialResults,haltSemantics:task.raw.semantics,wholeFunctionRecovered:false,nativeProved:false,cleanupConfirmed:jobs.active===null};}finally{await jobs.dispose();}
}
