import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { createAnalysisService } from '../../analysis_tools.js';
import { runVmProgression } from '../../source/vm_program.js';
import { runWorkspace } from '../../source/investigation_workflow.js';
import { bytecodeHash } from '../../source/vm_bytecode.js';
import { ownedBranchVmFixture, bytecodeContract } from './vm_bytecode_cases.mjs';
import { registeredVerifier } from '../../source/verifier_catalog.js';

export async function propertyCase(root,recordingRuns=[]) {
  const cfg={artifactDir:path.join(root,'artifacts'),projectRoot:path.join(root,'projects')},analysis=createAnalysisService({},cfg);
  const image=ownedBranchVmFixture().image,sha256=bytecodeHash(image),target=path.join(root,'owned-branch.exe');fs.writeFileSync(target,image);
  const context={target,projectId:`project_${randomUUID()}`,artifactId:`artifact_${sha256}`,sha256,engine:'reverse',provider:'ghidra',attachmentId:`attachment_${randomUUID()}`,dbRevision:0};
  const session={engine:'reverse',target};
  const mgr={analysis,checkCancelled(){},get:()=>session,alive:()=>true,evidence:()=>({...context}),engines:()=>[],sessions:new Map([[target,session]])};
  for(const k of ['rpc','performDebug','approve','spawnWorker','run'])mgr[k]=()=>{throw Error('Offline fixture cannot execute targets');};
  const workspace=w=>runWorkspace(mgr,cfg,{target,workspace:w},{agent:{id:'research-property-acceptance'}});
  const call=w=>workspace(w).workspace;
  const asyncCall=async w=>(await workspace(w)).workspace;
  const task=call({action:'create',goal:'Close exact model and recorded obligations independently'});
  const get=()=>call({action:'research-get',id:task.taskId});
  const update=(operation,value,extra={})=>{
    const now=get();return call({action:'research-update',id:task.taskId,...extra,research:{operation,expected_task_revision:now.taskRevision,
      expected_research_revision:now.research?.researchRevision??0,scope_digest:now.scopeDigest,...(value===undefined?{}:{value})}});
  };
  const contract={question:'Fixed branch reference behavior',inputDomain:'Exact structured scopes on individual obligations',returns:'RAX',outputs:'8 bytes at RVA 0x3000',sideEffects:'Recorded paths only',environment:'single-threaded-no-external-calls',exclusions:'Native unexecuted inputs and complete CPU semantics remain unknown'};
  update('initialize',contract);
  const invoke=async(mode,input)=>(await runVmProgression(mgr,mode,input,cfg))[mode];
  const ref=view=>({id:view.reportId,sha256:view.reportSha256});
  const declared=await invoke('declare_contract',{contract:bytecodeContract(sha256,true)});
  const program=await invoke('program',{image_ref:{path:target,sha256},contract_ref:ref(declared)});
  const assessment=await invoke('function_check',{program_ref:ref(program),recording_runs:recordingRuns});
  update('link-verifier-evidence',undefined,{report_ref:ref(assessment)});
  const evidence=get().research.evidenceLinks[0];
  const propose=(property,changes={})=>update('add-obligation',{property,scope:`evidence:${evidence.id}`,verifier:registeredVerifier(property).id,dependencies:[],
    ...(evidence.propertyScopes[property]?{propertyScope:evidence.propertyScopes[property]}:{}),...changes}).research.obligations.at(-1);
  const request=o=>{const now=get();return{expected_task_revision:now.taskRevision,expected_research_revision:now.research.researchRevision,scope_digest:now.scopeDigest,evidence_id:evidence.id,obligation_id:o.id};};
  const verify=o=>asyncCall({action:'research-verify',id:task.taskId,verification:request(o)});
  return {root,cfg,analysis,mgr,task,contract,context,evidence,get,update,propose,request,verify,call,asyncCall,invoke,ref,assessment,program};
}
