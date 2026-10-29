import { loadObservationWindows } from './vm_observation_profile.js';
import { committedBytes, evidenceReadBudget, vmContextEvidence, exactReportRef } from './evidence_adapters/vm_context.js';
import { loadComparedContexts, compareVmRoles } from './vm_role_compare.js';
import { createPhaseContext } from './vm_phase_context.js';
import { analyzeVmObservations } from './vm_observations.js';
import { observedCodeVersion } from './code_epoch_map.js';
import { planningDigest } from './planning_identity.js';
import { validateFunctionContract, exactData, boundedDataArray } from './vm_function_contract.js';

const fail = message => { throw Object.assign(new Error(message),{code:'INVALID_VM_ROLE_VALIDATION'}); };
function selectedRelation(model,parents,family,name) {
  const values=[];
  for(const refs of model.sourceReports) {
    const recurrence=parents.get(refs.recurrence.id),selection=parents.get(refs.selection.id);
    if(family==='vipCandidates')for(const o of recurrence.occurrences)values.push(...o.sourceAddressInputUpdates.filter(x=>x.name===name).map(x=>x.deltaModulo64));
    else if(family==='dispatchBaseCandidates')for(const o of recurrence.occurrences)for(const read of o.indexedAddressInputValues)values.push(...read.inputs.filter(x=>x.name===name).map(x=>x.value));
    else for(const b of selection.bodies)values.push('0x'+((BigInt(b.groups.at(-1).after.gprs[name])-BigInt(b.groups[0].before.gprs[name]))&((1n<<64n)-1n)).toString(16));
  }
  return [...new Set(values)].sort();
}
export async function prepareRoleValidation(mgr,cfg,input) {
  exactData(input,['comparison_ref','recording_bindings']);
  const artifacts=mgr.analysis.artifacts,budget=evidenceReadBudget();
  const compared=committedBytes(artifacts,input.comparison_ref,'vm-role-comparison','compare',budget).record.result;
  const declared=committedBytes(artifacts,compared.contractRef,'vm-function-contract','declare',budget).record.result;
  if(declared.authority!=='caller-declared-scope'||declared.businessAccepted!==false)fail('Contract scope differs');
  const contract=validateFunctionContract(declared.contract);
  const contexts=loadComparedContexts(artifacts,compared.sourceContexts,contract.targetSha256,()=>mgr.checkCancelled(),budget);
  if(planningDigest(compared)!==planningDigest(compareVmRoles(contexts,compared.contractRef,contract.targetSha256)))fail('Comparison changed');
  boundedDataArray(input.recording_bindings,8,1);
  if(input.recording_bindings.length!==contexts.length)fail('Exactly one binding per compared context required');
  const requests=[];let bytes=budget.bytes,instructions=0;
  for(let i=0;i<contexts.length;i++) {
    const binding=input.recording_bindings[i];exactData(binding,['context_ref','recordings']);exactReportRef(binding.context_ref);
    if(planningDigest(binding.context_ref)!==planningDigest(contexts[i].ref))fail('Binding order/context differs');
    const {windows}=await loadObservationWindows(mgr,cfg,{recordings:binding.recordings,target_sha256:contract.targetSha256});
    bytes+=windows.reduce((n,w)=>n+w.data.length+(w.storeEventData?.length??0),0);
    instructions+=windows.reduce((n,w)=>n+w.summary.instructionCount,0);
    if(bytes>16*1024**2||instructions>50000)fail('Combined raw/context evidence exceeds original default 16 MiB/50k limits');
    requests.push({context:vmContextEvidence(artifacts,{scope:{sha256:contract.targetSha256}},contexts[i].ref,budget).request,windows});
  }
  return {comparisonRef:input.comparison_ref,contractRef:compared.contractRef,contract,requests,bytes};
}

/** Rebind every selected fetch/body to all original windows before deriving input or held-out evidence. */
export function validateRecordedRoles(request) {
  const {contract}=request;validateFunctionContract(contract);
  const rows=[],models=[];let totalBoundGroups=0;
  for(const input of request.requests) {
    const correlation=createPhaseContext(input.context,input.windows,contract.targetSha256);
    const code=new Map();let first=null,last=null;
    const observations=analyzeVmObservations({targetSha256:contract.targetSha256,windows:input.windows,limit:1},(group,{source,summary})=>{
      first??=group;last=group;
      const versions=group.instructions.map(ins=>({version:observedCodeVersion(contract.targetSha256,group,ins,source,summary)}));
      correlation.observe(group,versions);
      for(const item of versions) {
        const runtimePc=item.version.binding.pc,key=runtimePc+':'+item.version.contentSha256;
        code.set(key,{runtimePc,bytes:item.version.binding.bytes,contentSha256:item.version.contentSha256,moduleMappingVerified:false});
        if(code.size>4096)fail('Code comparison exceeds 4096 observed versions');
      }
    });
    const annotation=correlation.finish();totalBoundGroups+=annotation.matchedGroups;
    if(totalBoundGroups>2048)fail('Combined context correlation exceeds 2048 bound groups');
    const initial=input.windows[0],final=input.windows.at(-1),base=BigInt(initial.summary.runtimeBase);
    const entryMatched=contract.normalReturn==='native-ret'&&BigInt(first.before.rip)===base+BigInt(contract.entryRva);
    const value=BigInt(first.before.gprs.rcx),inDomain=value>=BigInt(contract.input.minimum)&&value<=BigInt(contract.input.maximum);
    const returned=entryMatched&&final.summary.stopReason==='returned'&&last.instructions.length===1&&last.instructions[0].bytes==='c3'
      &&BigInt(last.before.gprs.rsp)===BigInt(first.before.gprs.rsp)&&BigInt(last.after.gprs.rsp)===BigInt(last.before.gprs.rsp)+8n;
    const location=initial.executionLocation;
    const executionInstance=location?.serverInstanceId&&location?.sessionId?planningDigest([location,observations.identity.runId,observations.identity.threadId]):null;
    const model=JSON.parse(Buffer.from(input.context.root.bytes)).result;
    const parents=new Map(input.context.parents.map(p=>[p.id,JSON.parse(Buffer.from(p.bytes)).result]));
    rows.push({contextRef:{id:input.context.root.id,sha256:input.context.root.sha256},identity:observations.identity,
      recordingRefs:input.windows.map(w=>({id:w.source.reportId,sha256:w.source.reportSha256})),rawCaptureRevalidated:true,
      matchedGroups:annotation.matchedGroups,entryMatched,inputInDomain:entryMatched&&inDomain,
      input:entryMatched?{register:'rcx',bits:contract.input.bits,value:'0x'+value.toString(16)}:null,
      normalReturnObserved:returned,executionInstance,vmInstance:null,vmInstanceAssurance:'unknown; execution identity does not establish a logical VM instance',
      observedCodeVersions:[...code.values()].sort((a,b)=>a.runtimePc.localeCompare(b.runtimePc)||a.contentSha256.localeCompare(b.contentSha256)),
      unknownGprResults:model.evidence.unknownGprResults,unknownStoreValues:model.evidence.unknownStoreValues,
      handlerCpuSemanticsReproved:false,codeStableBetweenObservations:false});
    models.push({model,parents});
  }
  const predictions=[];
  if(models.length>1)for(const family of ['vipCandidates','dispatchBaseCandidates','vspCandidates'])for(const candidate of models[0].model.roles[family]) {
    const predictionsForHeldOut=models.slice(1).map(({model,parents},i)=>{
      const actual=model.roles[family].find(c=>c.name===candidate.name);
      const expected=selectedRelation(models[0].model,models[0].parents,family,candidate.name),observed=actual?selectedRelation(model,parents,family,candidate.name):null;
      return {contextIndex:i+1,status:actual&&planningDigest(expected)===planningDigest(observed)?'matches-recorded-relation':'counterexample',expected,observed};
    });
    predictions.push({family,name:candidate.name,trainingContext:0,heldOut:predictionsForHeldOut,scope:'selected recorded relations only; not unseen-input generalization'});
  }
  const distinctInputs=new Set(rows.filter(r=>r.inputInDomain).map(r=>r.input.value)).size;
  const distinctRuns=new Set(rows.map(r=>r.identity.runId)).size;
  return {schema:'ig5-recorded-role-validation-v1',targetSha256:contract.targetSha256,comparisonRef:request.comparisonRef,contractRef:request.contractRef,
    status:distinctRuns>1?'raw-bound-cross-run-candidates':'insufficient-independent-runs',runs:rows,predictions,
    independence:{rawCaptureRevalidated:true,distinctObservedRuns:distinctRuns,
      distinctEntryInputs:distinctInputs,entryInputsComplete:rows.every(r=>r.entryMatched&&r.inputInDomain),
      distinctExecutionInstances:new Set(rows.map(r=>r.executionInstance).filter(Boolean)).size,independentVmInstances:'unknown',
      addressNormalization:'none; raw runtime PCs and GPR/data values retained; no verified module mapping supplied'},
    keyStatePrediction:{status:'unsupported',reason:'No committed key-state dependency model'},
    competingExplanations:[{kind:'ordinary-switch',status:'unresolved'},{kind:'buffer-iteration',status:'unresolved'}],
    vmRoleProved:false,nativeTargetExecuted:false,businessAccepted:false,changesExecutionAuthority:false};
}
