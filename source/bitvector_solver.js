import fs from 'node:fs';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {readStableFile,hashBytes} from './analysis_artifacts.js';
import {validateBVContract,validateBitvectorAST} from './bitvector_contract.js';
import {verifierIdentity} from './verification_result.js';
export const BV_SOLVER_PIN='65bf673f1c4304cc2c09076e3b96e368da9e0df72aa0badeba0c2a5cae392934';
const root=fileURLToPath(new URL('../',import.meta.url)),runtimePin='8fc4ae42f775f0139aa5f184c912db71f77e68d661c14564ab6f4820d434abea';
const files=['source/bitvector_contract.js','source/bitvector_replay.js','source/bitvector_solver.js','source/candidate_workflow.js','source/verification_result.js','source/analysis_worker.js','source/analysis_jobs.js','source/lift_jobs.js','source/worker_transport.js','source/analysis_artifacts.js','worker/bitvector_verify.py','worker/ig5_project.py','worker/flow_semantics.py','worker/lift_process.py','worker/lift_runtime.py','scripts/composition_domain_smt.py'];
const code=Object.fromEntries(files.map(name=>[name,hashBytes(readStableFile(path.join(root,name),1024**2).data)]));
const fail=message=>{throw Object.assign(new Error(message),{code:'INVALID_BITVECTOR_SOLVER_EVIDENCE'});};
export function bitvectorVerifierIdentity(){
 for(const [name,sha] of Object.entries(code))if(hashBytes(readStableFile(path.join(root,name),1024**2).data)!==sha)fail('Verifier code changed after module load; reload required');
 const inventory=readStableFile(path.join(root,'worker/trace_vendor/ig5-manifest.json'),4*1024**2).data;
 if(hashBytes(inventory)!==BV_SOLVER_PIN)fail('Solver inventory pin differs');
 const manifest=JSON.parse(inventory),row=manifest.files.find(r=>r.path.includes('/libz3-'));
 if(!row||path.resolve(root,'worker/trace_vendor',row.path).toLowerCase().startsWith(path.resolve(root,'worker/trace_vendor').toLowerCase()+path.sep)===false)fail('Solver library inventory path differs');
 const bytes=readStableFile(path.join(root,'worker/trace_vendor',row.path),64*1024**2).data;
 if(hashBytes(bytes)!==row.sha256)fail('Solver library hash differs');
 const execution=verifierIdentity();
 return {id:'ig5-bv-independent-verifier-v1',version:1,code,rulesDigest:hashBytes(Buffer.from(JSON.stringify(code))),runtime:execution.runtime,runtimeDigest:execution.runtimeDigest,solverManifestPin:BV_SOLVER_PIN,solverDllSha256:row.sha256,solverDistributionVersion:manifest.version,solverLibrary:row.path,nodeRuntimeVersion:process.version,solverVersionPolicy:'Actual pinned-library C API version recorded separately in assessment; no candidate-provider verifier trusted'};
}
/** Reuses the original two-slot Windows Job lifecycle, then the original settled 64MiB data worker. */
export async function runBitvectorSolver(jobs,dataJobs,contract,candidate,signal){
 validateBVContract(contract);const checked=validateBitvectorAST(candidate,contract.variables),identity=bitvectorVerifierIdentity();
 if(checked.bits!==contract.original.nodes[contract.original.root].bits)fail('Candidate result width differs');
 const raw=Buffer.from(JSON.stringify({schema:'ig5-bitvector-solver-input-v1',contract,candidate:checked.ast}));if(raw.length>65536)fail('Candidate request exceeds 64 KiB');
 const input=jobs.artifacts.put(raw),jobId=randomUUID(),parent=path.join(jobs.artifacts.root,'jobs');
 if(fs.realpathSync(parent)!==parent)fail('Physical jobs root required');fs.mkdirSync(path.join(parent,jobId));
 const reply=await jobs.request({job_id:jobId,sha256:input.sha256},signal,'bv-candidate'),p=reply?.process;
 const owned=[...jobs.active].find(item=>item.jobId===jobId);
 if(owned){let timer;try{await Promise.race([owned.stopped,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Object.assign(new Error('Candidate root exit not confirmed; capacity retained'),{code:'WORKER_CLEANUP_FAILED',cleanupConfirmed:false})),5000);})]);}finally{clearTimeout(timer);}}
 if(reply.targetSha256!==input.sha256||reply.runtimeManifestPin!==runtimePin||p?.status!=='completed'||p.exitCode!==0||p.limitReason!==null||p.childExitConfirmed!==true||p.jobAssignedAtCreation!==true||p.activeProcessLimit!==1||p.memoryLimitBytes!==2*1024**3
  ||!Number.isSafeInteger(reply.sharedBudgetMs)||reply.sharedBudgetMs<1||reply.sharedBudgetMs>50000||!Number.isSafeInteger(reply.processBudgetMs)||reply.processBudgetMs<1||reply.processBudgetMs>reply.sharedBudgetMs||!Number.isSafeInteger(p.elapsedMs)||p.elapsedMs<0||p.elapsedMs>reply.processBudgetMs+100)fail('Owned candidate process or budget differs');
 const directory=path.join(parent,jobId),{data}=readStableFile(path.join(directory,'stdout.log'),1024**2);
 if(data.length!==reply.outputBytes||hashBytes(data)!==reply.outputSha256)fail('Candidate solver output SHA differs');
 const assessment=JSON.parse(data),evidence=[];
 if(assessment.schema!=='ig5-bitvector-solver-v1'||assessment.inputSha256!==input.sha256||assessment.originalDigest!==contract.originalDigest||assessment.premiseDigest!==contract.premiseDigest||assessment.candidateDigest!==checked.digest||assessment.solverManifestPin!==BV_SOLVER_PIN||assessment.solverDllSha256!==identity.solverDllSha256
  ||typeof assessment.solverVersion!=='string'||!/^\d+\.\d+\.\d+\.\d+$/.test(assessment.solverVersion)||!Array.isArray(assessment.queries)||assessment.queries.length>2||['nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'].some(k=>assessment[k]!==false))fail('Solver result binding differs');
 let bytes=data.length;
 for(const [i,q] of assessment.queries.entries()){
  if(q.name!==['candidate-premise','candidate-difference'][i]||!['sat','unsat','unknown','unverified'].includes(q.status)||!Number.isSafeInteger(q.timeoutMs)||q.timeoutMs<1||q.timeoutMs>2000||q.checkSatCalls!==1||![0,1].includes(q.modelReadCalls)||q.modelCommandConditionalOnSat!==true
   ||!Number.isSafeInteger(q.encodedSexpressions)||q.encodedSexpressions<1||q.encodedSexpressions>2048||!Number.isSafeInteger(q.encodedAtomTokens)||q.encodedAtomTokens<1||q.encodedAtomTokens>8192||!Number.isSafeInteger(q.encodedDepth)||q.encodedDepth<1||q.encodedDepth>128)fail('Solver query budget/identity differs');
  for(const [kind,ext,max] of [['query','smt2',1024**2],['model','model.txt',65536]]){
   const ref=q[kind];if(!ref){if(kind==='query'||q.status==='sat')fail('Missing solver query/model');continue;}
   if(ref.name!==`q${String(i).padStart(3,'0')}.${ext}`||!Number.isSafeInteger(ref.bytes)||ref.bytes<1||ref.bytes>max)fail('Unexpected solver evidence file');
   const body=readStableFile(path.join(directory,'semantic-queries',ref.name),max).data;bytes+=body.length;
   if(bytes>4*1024**2||(contract.sourceInputBytes??0)+raw.length+bytes>8*1024**2||body.length!==ref.bytes||hashBytes(body)!==ref.sha256)fail('Query/model bytes or combined input budget differ');
   evidence.push({queryIndex:i,kind,...jobs.artifacts.put(body)});
  }
 }
 const replay=await dataJobs.runSettled('bv-candidate-replay',{contract,candidate:checked.ast,assessment},signal);
 if(replay.schema!=='ig5-bitvector-replay-v1'||!['pass','fail','unknown','unsupported'].includes(replay.status)||replay.businessAccepted!==false||replay.nativeTargetExecuted!==false||replay.databaseModified!==false||replay.wholeBinaryVerified!==false)fail('Independent replay result differs');
 bitvectorVerifierIdentity();
 return {assessment,replay,process:p,input,queryEvidence:evidence,combinedOutputBytes:bytes,verifier:identity,cleanup:{ownedChildExitConfirmed:true,ownedRootExitConfirmed:true,dataWorkerCleanupConfirmed:true}};
}
