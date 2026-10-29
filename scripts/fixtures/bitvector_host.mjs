import fs from 'node:fs';import path from 'node:path';import {randomUUID,createHash} from 'node:crypto';
import {AnalysisArtifacts} from '../../source/analysis_artifacts.js';import {AnalysisJobs} from '../../source/analysis_jobs.js';
import {LiftJobs} from '../../source/lift_jobs.js';import {InvestigationStore} from '../../source/investigation_store.js';
import {ResearchState,researchScopeDigest} from '../../source/research_state.js';import {runWorkspace} from '../../source/investigation_workflow.js';
import {projectionCase} from './bitvector_cases.mjs';
export function bitvectorHost(root,pluginRoot){
 const bytes=Buffer.from('F07 owned synthetic bytes; never a native executable or decoder result'),sha256=createHash('sha256').update(bytes).digest('hex'),target=path.join(root,'owned-source.bin');fs.writeFileSync(target,bytes,{flag:'wx'});
 const cfg={home:path.join(root,'policy-home'),projectRoot:path.join(root,'projects'),artifactDir:path.join(root,'artifacts'),requestTimeoutMs:60000,host:{id:'win32-x64'},ghidra:{available:true,pythonExe:path.join(pluginRoot,'runtimes/ghidra/python/python.exe')}};
 const context={target,projectId:'project_'+randomUUID(),artifactId:'artifact_'+sha256,sha256,engine:'ghidra',provider:'ghidra',attachmentId:'attachment_'+randomUUID(),dbRevision:0};
 const notes=new InvestigationStore({root:cfg.projectRoot}),research=new ResearchState({root:cfg.projectRoot}),lifter=new LiftJobs(cfg),jobs=new AnalysisJobs(),artifacts=new AnalysisArtifacts(path.join(root,'analysis'));
 const task=notes.create(context,{goal:'Owned fixture: selected IR equality only'},'f07-fixture'),declared={question:'Selected IR equality under declared premise',inputDomain:'Exact SSA BV widths',returns:'Selected expression only',outputs:'No external output claim',sideEffects:'Not removed',environment:'Owned synthetic IR; actual solver job only',exclusions:'No native, CPU, VM or business proof'};
 research.mutate(task,context,{operation:'initialize',expected_task_revision:0,expected_research_revision:0,scope_digest:researchScopeDigest(context),value:declared},'f07-fixture');
 const session={engine:'ghidra'},mgr={lifter,analysis:{jobs,artifacts},investigations:notes,researchState:research,get:()=>session,alive:()=>true,checkCancelled(){},evidence:()=>({...context})},execution={agent:{id:'f07-fixture'}};
 const call=async input=>(await runWorkspace(mgr,cfg,{target,workspace:{id:task.taskId,...input}},execution)).workspace;
 function saveSource(options={}){
  const result=projectionCase(sha256,options),input=lifter.artifacts.put(bytes),outputRef=lifter.artifacts.put(Buffer.from(JSON.stringify(result)));
  const saved=lifter.artifacts.save({kind:'projection',action:'project',target,input,outputRef,process:{childExitConfirmed:true,fixture:true,scope:'SYNTHETIC SOURCE; not native process evidence'},result},{pretty:true,maxBytes:4*1024**2});
  return {id:saved.id,sha256:lifter.artifacts.metadata(saved.id).result.recordSha256};
 }
 return {context,cfg,notes,research,task,lifter,jobs,mgr,execution,call,saveSource,declared,async dispose(){await lifter.dispose();await jobs.dispose();await artifacts.dispose();}};
}
