import path from 'node:path';
import {BV_VERSION,extractProjectionExpression,validateBVContract,validateBitvectorAST,truePremise} from './bitvector_contract.js';
import {runBitvectorSolver} from './bitvector_solver.js';
import {committedBytes,exactReportRef,evidenceReadBudget} from './evidence_adapters/vm_context.js';
import {caseTrustedScope} from './research_case_bridge.js';
import {planningDigest} from './planning_identity.js';
import {checkedProjectionReferences} from './projection_jobs.js';
import {hashBytes,readStableFile} from './analysis_artifacts.js';
import {generateLocalCandidate,localProviderIdentity,validateProviderOutput} from './bitvector_provider_adapter.js';
export const candidateActions=Object.freeze(['candidate-prepare','candidate-verify','candidate-read','candidate-simplify']);
const fail=(code,message)=>{throw Object.assign(new Error(message),{code});};
export const bitvectorASTSchema={type:'object',properties:{root:{type:'integer',minimum:0,maximum:127},nodes:{type:'array',minItems:1,maxItems:128,items:{type:'object',properties:{id:{type:'integer',minimum:0,maximum:127},op:{type:'string',maxLength:24},bits:{type:'integer',minimum:1,maximum:64},args:{type:'array',maxItems:6,items:{type:'integer',minimum:0,maximum:127}},value:{type:'string',maxLength:18},name:{type:'string',maxLength:32},offset:{type:'integer',minimum:0,maximum:63}},required:['id','op','bits','args'],additionalProperties:false}}},required:['root','nodes'],additionalProperties:false};
export function validateCandidateInput(input){
 const fields={'candidate-prepare':['action','id','source_ref','root_node','premise'],'candidate-verify':['action','id','candidate_ref','candidate_ast'],'candidate-read':['action','id','report_ref'],'candidate-simplify':['action','id','candidate_ref']};
 if(!input||!Object.hasOwn(fields,input.action)||Object.keys(input).some(k=>!fields[input.action].includes(k)))fail('INVALID_ARGUMENT','Invalid candidate contract fields');
 exactReportRef(input[input.action==='candidate-prepare'?'source_ref':['candidate-verify','candidate-simplify'].includes(input.action)?'candidate_ref':'report_ref']);
 if(input.action==='candidate-prepare'&&(!Number.isSafeInteger(input.root_node)||Object.is(input.root_node,-0)||input.root_node<0||input.root_node>2047))fail('INVALID_ARGUMENT','Select source root_node 0..2047');
 if(input.action==='candidate-verify'&&(!input.candidate_ast||typeof input.candidate_ast!=='object'))fail('INVALID_ARGUMENT','A bounded candidate_ast object is required');
}
function binding(data){
 const trusted=caseTrustedScope(data);if(!trusted.ready)fail('CANDIDATE_CONTEXT_REQUIRED',trusted.reason);
 return {scope:trusted.scope,researchRevision:data.research.researchRevision,contractRevision:data.research.contractRevision};
}
function readProjection(artifacts,ref,rootNode,context){
 const budget=evidenceReadBudget(),source=committedBytes(artifacts,ref,'projection','project',budget),report=source.record,r=report.result;
 if(r.schema!=='ig5-pcode-projection-v1'||r.targetSha256!==context.sha256||report.input?.sha256!==context.sha256||path.resolve(report.target).toLowerCase()!==path.resolve(context.target).toLowerCase()
  ||report.process?.childExitConfirmed!==true||['nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'].some(k=>r[k]!==false))fail('CANDIDATE_SOURCE_MISMATCH','Source must be a committed ordinary preferred-address projection of this exact target');
 checkedProjectionReferences(r);
 const output=artifacts.read(report.outputRef.ref,Math.min(4*1024**2,8*1024**2-budget.bytes)).data;budget.bytes+=output.length;
 if(hashBytes(output)!==report.outputRef.sha256||planningDigest(JSON.parse(output))!==planningDigest(r))fail('ARTIFACT_CHANGED','Original full IR blob differs');
 const binary=artifacts.read(report.input.ref,8*1024**2-budget.bytes).data;budget.bytes+=binary.length;
 if(hashBytes(binary)!==context.sha256)fail('ARTIFACT_CHANGED','Original source bytes differ');
 // Current target is only read, never decoded or executed. Charge the re-read against the same 8 MiB envelope.
 const current=readStableFile(context.target,8*1024**2-budget.bytes).data;
 if(hashBytes(current)!==context.sha256)fail('CANDIDATE_SOURCE_MISMATCH','Current target bytes differ from opened identity');
 return {...extractProjectionExpression(r,rootNode),sourceInputSha256:context.sha256,inputBytes:budget.bytes+current.length};
}
function savedRef(artifacts,record){return {id:record.id,sha256:artifacts.metadata(record.id).result.recordSha256};}
const authority={nativeTargetExecuted:false,databaseModified:false,businessAccepted:false,wholeBinaryVerified:false,changesExecutionAuthority:false,assistEnabled:false};
function loadContract(artifacts,ref,data){
 const record=committedBytes(artifacts,ref,'bitvector-contract','prepare').record;
 if(record.association?.taskId!==data.task.taskId||planningDigest(record.association?.scope)!==planningDigest(data.task.scope))fail('RESEARCH_SCOPE_MISMATCH','Candidate contract is outside the current task/target');
 const value=validateBVContract(record.result);
 if(planningDigest(value.binding)!==planningDigest(binding(data)))fail('STALE_CANDIDATE_CONTRACT','Task, database, research or contract changed; prepare a new explicit candidate contract');
 const source=readProjection(artifacts,value.sourceRef,value.sourceRoot,data.context);
 if(planningDigest(source.original)!==value.originalDigest||planningDigest(source.variables)!==planningDigest(value.variables))fail('ARTIFACT_CHANGED','Contract no longer matches the original selected IR');
 return value;
}
/** Explicit prepare/check/read under the original static queue. Saved receipts do not close old obligations. */
export async function runCandidateWorkflow({jobs,dataJobs,input,read,signal}){
 validateCandidateInput(input);const data=read(),artifacts=jobs.artifacts,currentBinding=binding(data);
 const association={taskId:data.task.taskId,scope:data.task.scope};
 if(input.action==='candidate-read'){
  const metadata=artifacts.metadata(input.report_ref.id).result,kind=metadata.kind;
  if(!['bitvector-contract','bitvector-verification','bitvector-proposal'].includes(kind))fail('INVALID_RESEARCH_REF','Select a committed candidate contract, proposal or verification receipt');
  const record=committedBytes(artifacts,input.report_ref,kind,kind==='bitvector-contract'?'prepare':kind==='bitvector-proposal'?'generate':'verify').record;
  if(record.association?.taskId!==data.task.taskId||planningDigest(record.association.scope)!==planningDigest(data.task.scope))fail('RESEARCH_SCOPE_MISMATCH','Candidate history is outside this task');
  let validity='current',reason=null;
  try{
   if(kind==='bitvector-contract')loadContract(artifacts,input.report_ref,data);
   else if(kind==='bitvector-proposal'){
    const c=loadContract(artifacts,record.result.contractRef,data);
    if(planningDigest(c.binding)!==planningDigest(record.result.binding))fail('STALE_CANDIDATE_CONTRACT','Proposal binding differs');
    if(planningDigest(localProviderIdentity())!==planningDigest(record.result.providerIdentity))fail('PROVIDER_IDENTITY_CHANGED','Provider rules/dependencies changed');
    if(record.result.provider?.result)validateProviderOutput(c,record.result.provider.result);
   }else{
    const c=loadContract(artifacts,record.result.contractRef,data);
    if(planningDigest(c.binding)!==planningDigest(record.result.binding))fail('STALE_CANDIDATE_CONTRACT','Receipt binding differs');
    let total=c.sourceInputBytes+Buffer.byteLength(JSON.stringify(record.result));
    if(!Array.isArray(record.result.queryEvidence)||record.result.queryEvidence.length>4)fail('ARTIFACT_CHANGED','Receipt query evidence shape differs');
    for(const ref of record.result.queryEvidence){const bytes=artifacts.read(ref.ref,Math.min(1024**2,8*1024**2-total)).data;total+=bytes.length;if(bytes.length!==ref.bytes||hashBytes(bytes)!==ref.sha256)fail('ARTIFACT_CHANGED','Receipt query/model evidence differs');}
    const {bitvectorVerifierIdentity}=await import('./bitvector_solver.js');
    if(planningDigest(bitvectorVerifierIdentity())!==planningDigest(record.result.verifier))fail('VERIFIER_IDENTITY_CHANGED','Verifier code or runtime changed');
   }
  }catch(error){validity='stale';reason=error.code||'CANDIDATE_HISTORY_UNVERIFIED';}
  if(planningDigest(binding(read()))!==planningDigest(currentBinding))fail('SNAPSHOT_INCONSISTENT','Candidate scope changed during history read');
  const body=JSON.stringify(record.result);if(Buffer.byteLength(body)>32768)fail('CANDIDATE_RESPONSE_LIMIT','Read the saved full report; receipt exceeds 32 KiB');
  return {schema:'ig5-candidate-history-v1',ref:input.report_ref,validity,reason,result:record.result,...authority};
 }
 if(input.action==='candidate-prepare'){
  const source=readProjection(artifacts,input.source_ref,input.root_node,data.context),premise=validateBitvectorAST(input.premise??truePremise(),source.variables);
  const contract=validateBVContract({schema:'ig5-bitvector-contract-v1',version:BV_VERSION,binding:currentBinding,sourceRef:input.source_ref,sourceRoot:input.root_node,
   sourceInputSha256:source.sourceInputSha256,sourceInputBytes:source.inputBytes,original:source.original,originalDigest:planningDigest(source.original),variables:source.variables,premise:premise.ast,premiseDigest:premise.digest,
   premiseOrigin:input.premise?'caller-declared-structured-assumption':'unconditional-true',irNativeCorrespondence:'not-proved-by-this-contract',...authority});
  if(planningDigest(binding(read()))!==planningDigest(currentBinding))fail('SNAPSHOT_INCONSISTENT','Candidate context changed before contract save');
  const record=artifacts.save({kind:'bitvector-contract',action:'prepare',association,result:contract},{maxBytes:65536});
  return {schema:contract.schema,status:'prepared',candidateRef:savedRef(artifacts,record),variables:contract.variables,original:contract.original,premise:contract.premise,originalDigest:contract.originalDigest,premiseDigest:contract.premiseDigest,binding:currentBinding,...authority};
 }
 const contract=loadContract(artifacts,input.candidate_ref,data);
 if(input.action==='candidate-simplify'){
  const generated=await generateLocalCandidate(dataJobs,contract,signal);
  let current=true,staleReason=null;
  try{loadContract(artifacts,input.candidate_ref,read());}catch(error){current=false;staleReason=error.code||'POST_PROVIDER_CONTEXT_UNAVAILABLE';}
  const proposal={schema:'ig5-bitvector-proposal-v1',contractRef:input.candidate_ref,binding:currentBinding,providerIdentity:generated.identity,provider:generated,originalDigest:contract.originalDigest,currentAtGeneration:current,...authority};
  const record=artifacts.save({kind:'bitvector-proposal',action:'generate',association,result:proposal},{pretty:true,maxBytes:128*1024}),proposalRef=savedRef(artifacts,record);
  const base={schema:proposal.schema,proposalRef,reportSaved:true,providerId:generated.identity.id,providerVersion:generated.identity.version,originalRetained:true,originalDigest:contract.originalDigest,providerCleanupConfirmed:generated.cleanupConfirmed,current,staleReason,...authority};
  if(!current||generated.result?.status!=='candidate')return {...base,status:!current?'stale':generated.result?.status||'fallback-original',reason:generated.reason||null,code:generated.code||null,cost:generated.result?.cost||null,verificationAttempted:false,equivalentInIR:false};
  const candidate=generated.result.candidate;
  try{
   const verified=await runCandidateWorkflow({jobs,dataJobs,input:{action:'candidate-verify',id:input.id,candidate_ref:input.candidate_ref,candidate_ast:candidate},read,signal});
   const accepted=verified.current&&verified.status==='pass'&&verified.equivalentInIR===true;
   return {...base,status:accepted?'verified-candidate':'candidate-not-accepted',candidate:accepted?candidate:null,candidateDigest:generated.result.candidateDigest,cost:generated.result.cost,verificationAttempted:true,verification:verified,equivalentInIR:accepted,originalRetained:true};
  }catch(error){
   if(signal?.aborted||['ABORT_ERR','DISPOSED'].includes(error.code))throw error;
   return {...base,status:'fallback-original',verificationAttempted:true,equivalentInIR:false,code:error.code||'CANDIDATE_VERIFICATION_FAILED',reason:'Independent verification failed or cleanup unavailable; original retained; saved proposal is not proof'};
  }
 }
 const candidate=validateBitvectorAST(input.candidate_ast,contract.variables);
 if(candidate.bits!==contract.original.nodes[contract.original.root].bits)fail('UNSUPPORTED_BITVECTOR','Candidate result width differs');
 const result=await runBitvectorSolver(jobs,dataJobs,contract,candidate.ast,signal);
 const receipt={schema:'ig5-bitvector-verification-v1',status:result.replay.status,contractRef:input.candidate_ref,binding:currentBinding,
  originalDigest:contract.originalDigest,candidateDigest:candidate.digest,premiseDigest:contract.premiseDigest,sourceRef:contract.sourceRef,sourceRoot:contract.sourceRoot,
  original:contract.original,candidate:candidate.ast,premise:contract.premise,variables:contract.variables,verifier:result.verifier,assessment:result.assessment,replay:result.replay,
  queryEvidence:result.queryEvidence,process:result.process,cleanup:result.cleanup,irNativeCorrespondence:contract.irNativeCorrespondence,acceptedScope:'Only selected pure BV expression under the exact declared satisfiable premise; no other register/flags/memory/control effects removed',...authority};
 let current=true,staleReason=null;
 try{loadContract(artifacts,input.candidate_ref,read());}catch(error){current=false;staleReason=error.code||'POST_VERIFY_SOURCE_UNAVAILABLE';}
 const record=artifacts.save({kind:'bitvector-verification',action:'verify',association,result:receipt},{pretty:true,maxBytes:256*1024});
 return {schema:receipt.schema,status:current?receipt.status:'unknown',computedStatus:receipt.status,current,staleReason,reportSaved:true,reportRef:savedRef(artifacts,record),
  premiseSatisfiable:result.replay.premiseSatisfiable,equivalentInIR:current&&result.replay.equivalentInIR,counterexampleValid:current&&result.replay.counterexampleValid,counterexample:result.replay.counterexample,
  originalDigest:receipt.originalDigest,candidateDigest:receipt.candidateDigest,premiseDigest:receipt.premiseDigest,cleanup:receipt.cleanup,...authority};
}
