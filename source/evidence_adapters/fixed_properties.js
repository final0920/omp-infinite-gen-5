import path from 'node:path';
import { committedBytes, evidenceReadBudget, vmContextEvidence } from './vm_context.js';
import { MODEL_PROPERTY, RECORDED_PROPERTY, PROVENANCE_PROPERTY, validatePropertyScope } from '../research_properties.js';
import { planningDigest } from '../planning_identity.js';
import { deriveExecutableProgram } from '../vm_bytecode.js';
import { validateFunctionContract } from '../vm_function_contract.js';
import { readObservationWindows } from '../vm_observation_profile.js';
import { compareVmRoles, loadComparedContexts } from '../vm_role_compare.js';
const fail = message => { throw Object.assign(new Error(message),{code:'UNSUPPORTED_EVIDENCE'}); };
const same = (a,b) => planningDigest(a)===planningDigest(b);
const uniqueRefs = refs => {
  const result=new Map();
  for(const ref of refs) { if(result.has(ref.id)&&!same(result.get(ref.id),ref)) fail('Conflicting raw recording references');result.set(ref.id,ref); }
  if(result.size>48) fail('At most 48 source reports in a research verification closure');
  return [...result.values()];
};

/** Scope comes from structured contracts and exact recorded references, never a caller's prose. */
export function fixedPropertyEvidence(artifacts,task,ref,budget=evidenceReadBudget(),propertyId=null) {
  const sharedBudget=budget;budget={bytes:sharedBudget.bytes,cache:new Map()};
  const metadata=artifacts.metadata(ref.id).result;
  const kind=metadata.kind;
  if(!['vm-function-assessment','vm-role-validation'].includes(kind)) fail('No fixed property adapter for this report kind');
  const root=committedBytes(artifacts,ref,kind,kind==='vm-function-assessment'?'assess':'validate',budget),saved=root.record.result;
  if(saved?.targetSha256!==task.scope.sha256) fail('Evidence target differs');
  const read=(r,k,a)=>committedBytes(artifacts,r,k,a,budget);
  const declaration=read(saved.contractRef,'vm-function-contract','declare');
  if(declaration.record.result.authority!=='caller-declared-scope'||declaration.record.result.businessAccepted!==false)fail('Function scope is not a supported declaration');
  const contract=validateFunctionContract(declaration.record.result.contract);
  if(contract.targetSha256!==task.scope.sha256)fail('Contract target differs');
  let request,subjectRef,properties,recordingRuns=[];
  if(kind==='vm-function-assessment') {
    if(saved.schema!=='ig5-finite-function-verification-v1')fail('No executable finite model in this assessment');
    const program=read(saved.programRef,'vm-executable-program','derive').record.result;
    const {contractRef,...executable}=program;
    if(!same(contractRef,saved.contractRef)||!same(executable,deriveExecutableProgram(Buffer.from(program.sourceImageHex,'hex'),contract)))fail('Executable subject or function contract differs');
    if(!Array.isArray(saved.recordedFunctionEvidence?.runs)||saved.recordedFunctionEvidence.runs.length>8)fail('Bounded recorded runs required');
    recordingRuns=saved.recordedFunctionEvidence.runs.map(r=>r.recordingRefs);
    subjectRef=saved.programRef;properties=[MODEL_PROPERTY,RECORDED_PROPERTY];
    request={program:executable,contract,sampleInputs:[],recordedRuns:[]};
  } else {
    if(saved.schema!=='ig5-recorded-role-validation-v1'||!Array.isArray(saved.runs)||!saved.runs.length||saved.runs.length>8)fail('Bounded raw role validation required');
    const compared=read(saved.comparisonRef,'vm-role-comparison','compare').record.result;
    const contexts=loadComparedContexts(artifacts,compared.sourceContexts,contract.targetSha256,()=>{},budget);
    if(!same(compared.contractRef,saved.contractRef)||!same(compared,compareVmRoles(contexts,compared.contractRef,contract.targetSha256))
      ||saved.runs.length!==contexts.length)fail('Comparison closure changed');
    const requests=contexts.map((c,i)=>{
      if(!same(saved.runs[i].contextRef,c.ref))fail('Context order differs');
      return {context:vmContextEvidence(artifacts,task,c.ref,budget).request};
    });
    request={comparisonRef:saved.comparisonRef,contractRef:saved.contractRef,contract,requests};
    recordingRuns=saved.runs.map(r=>r.recordingRefs);subjectRef=saved.comparisonRef;properties=[PROVENANCE_PROPERTY];
  }
  const refs=uniqueRefs(recordingRuns.flat());
  let bytes=budget.bytes,instructions=0;
  const effectiveRuns=propertyId===MODEL_PROPERTY?[]:recordingRuns;
  const windows=effectiveRuns.map(recordings=>{
    const result=readObservationWindows({checkCancelled(){}},{artifactDir:path.dirname(artifacts.root)},{recordings,target_sha256:contract.targetSha256},budget);
    bytes=budget.bytes;
    instructions+=result.windows.reduce((n,w)=>n+w.summary.instructionCount,0);
    if(bytes>8*1024**2||instructions>50000)fail('Research evidence exceeds 8 MiB/50k read envelope');
    return result.windows;
  });
  // Include raw bytes in this shared read budget, including repeated windows. No hidden unbounded rereads.
  budget.bytes=bytes;
  if(kind==='vm-function-assessment')request.recordedRuns=windows.map(w=>({windows:w}));
  else request.requests.forEach((r,i)=>{r.windows=windows[i];});
  const common={targetSha256:contract.targetSha256,subjectRef,contractRef:saved.contractRef,environmentRef:planningDigest({environment:contract.environment,exclusions:contract.exclusions,entryRva:contract.entryRva,outputs:contract.outputs,normalReturn:contract.normalReturn})};
  const propertyScopes={};
  if(properties.includes(MODEL_PROPERTY))propertyScopes[MODEL_PROPERTY]=validatePropertyScope({...common,domain:{kind:'integer-range',bits:contract.input.bits,minimum:contract.input.minimum,maximum:contract.input.maximum}});
  if(refs.length) {
    const inputs=[...new Set(saved.runs?saved.runs.filter(r=>r.inputInDomain).map(r=>r.input.value):saved.recordedFunctionEvidence.runs.filter(r=>r.inDomain).map(r=>r.input))].sort();
    for(const p of properties.filter(p=>p!==MODEL_PROPERTY))propertyScopes[p]=validatePropertyScope({...common,domain:{kind:'recorded-inputs',inputs,recordingRefs:refs}});
  }
  const parents=[...budget.cache.values()].filter(p=>p.id!==root.id).map(p=>({id:p.id,sha256:p.sha256,kind:p.record.kind}));
  for(const [id,p] of budget.cache) { if(sharedBudget.cache.has(id)&&sharedBudget.cache.get(id).sha256!==p.sha256)fail('Conflicting source identity');sharedBudget.cache.set(id,p); }
  sharedBudget.bytes=budget.bytes;
  if(sharedBudget.cache.size>64)fail('Research source report count exceeds 64');
  const link={kind,assurance:'committed-fixed-property-inputs',reportId:root.id,sha256:root.sha256,targetSha256:contract.targetSha256,dependencyType:'immutable-bytes',parents,
    supportedProperties:properties,propertyScopes,limitations:['Exact structured scope only; no whole-function, universal CPU or unexecuted native-input acceptance.']};
  return {link,request,root,recordingRefs:refs,recordingRuns:effectiveRuns,inputBytes:bytes,inputRefs:[{id:root.id,sha256:root.sha256},...parents.map(({id,sha256})=>({id,sha256})),...(propertyId===MODEL_PROPERTY?[]:refs)]};
}
