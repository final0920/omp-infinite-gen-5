// Explicit owned pinned-solver acceptance on synthetic IR only. No PE executes.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { semanticCore } from './fixtures/flow_semantic_cases.mjs';
const option=k=>{const i=process.argv.indexOf(k);assert(i>=0&&process.argv[i+1],k+' required');return path.resolve(process.argv[i+1]);};
const root=option('--plugin-root'),out=option('--evidence'),load=f=>import(pathToFileURL(path.join(root,f)).href);
fs.mkdirSync(out,{recursive:true});
const {LiftJobs}=await load('source/lift_jobs.js'),{runFlowSemantics}=await load('source/flow_semantics_jobs.js'),{createAnalysisService}=await load('analysis_tools.js');
const {replayFlowAssessment}=await load('source/flow_state_eval.js');
const cfg={artifactDir:out,projectRoot:out,requestTimeoutMs:60000,host:{id:'win32-x64'},ghidra:{available:true,pythonExe:path.join(root,'runtimes/ghidra/python/python.exe')}};
const jobs=new LiftJobs(cfg),analysis=createAnalysisService({},cfg),rows=[];let failures=0,mutationChecks=0;
try{
  for(const c of [{name:'positive',options:{},statuses:['sat','sat','sat','sat'],positive:true},
    {name:'canceled-index',options:{cancelIndex:true},statuses:['sat','unsat'],positive:false},
    {name:'canceled-target',options:{cancelTarget:true},statuses:['sat','sat','sat','unsat'],positive:false},
    {name:'unrelated-target',options:{independent:true},incomplete:true},
    {name:'unsupported-dead-node',options:{unsupported:true},incomplete:true}]){
    const prefix=semanticCore({prefix:true}),full=semanticCore(c.options),reply=await runFlowSemantics(jobs,analysis,prefix,full);
    assert.equal(reply.result.assessmentComplete,!c.incomplete);assert.equal(reply.replay.semanticNonconstancyProved,!!c.positive);
    assert.equal(reply.result.nativeTargetExecuted,false);assert.equal(reply.result.businessAccepted,false);
    if(c.statuses)assert.deepEqual(reply.result.queries.map(q=>q.status),c.statuses);
    if(c.positive){
      assert.equal(reply.replay.verifiedSatQueries,4);
      const mutations=[a=>a.targetSha256='b'.repeat(64),a=>a.sourceLoadSignature='0'.repeat(64),a=>a.sourceLoadNode++,a=>a.sourceAddressNode++,
        a=>a.roots.pop(),a=>a.neededNodes.pop(),a=>a.sourceValidation.weakenedLoadNodes.push(17),
        a=>a.assessments[0].coupledOtherTargetLoads.push(17),a=>a.assessments[0].targetMayChangeWithIndex=false,
        a=>a.assessments[0].witnesses.pop(),a=>a.assessments[0].witnesses[0].query=3,
        a=>a.assessments[0].witnesses[0].state.sourceNode++,a=>a.assessments[0].witnesses[0].state.initialRegisters.rax='0x10000000000000000',
        a=>a.assessments[0].witnesses[0].state.initialMemoryBytes=[],a=>a.assessments[0].witnesses[0].state.initialMemoryBytes[0].value=-0,
        a=>a.assessments[0].witnesses[0].state.nativeReachabilityProved=true,a=>a.assessments[0].witnesses[3].kind='index-change'];
      for(const mutate of mutations){const a=structuredClone(reply.result);mutate(a);assert.throws(()=>replayFlowAssessment({prefix,full,assessment:a}),/refused/i);mutationChecks++;}
    }
    rows.push({name:c.name,passed:true,reportPath:reply.reportPath,reportSha256:reply.reportSha256,queryStatuses:reply.result.queries.map(q=>q.status),
      semanticNonconstancyProved:reply.replay.semanticNonconstancyProved,assessmentComplete:reply.result.assessmentComplete});
  }
}catch(error){failures++;rows.push({passed:false,error:error.message});console.error(error.stack);}
finally{await jobs.dispose();await analysis.dispose();}
const result={schema:'ig5-flow-semantic-runtime-acceptance-v1',passed:failures===0,pluginRoot:root,rows,mutationChecks,
  nativeTargetExecuted:false,syntheticIrOnly:true,vmRoleProved:false,businessAccepted:false};
fs.writeFileSync(path.join(out,'result.json'),JSON.stringify(result,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify(result));if(failures)process.exitCode=1;
