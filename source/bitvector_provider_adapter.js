import {fileURLToPath} from 'node:url';
import {readStableFile,hashBytes} from './analysis_artifacts.js';
import {validateBitvectorAST,validateBVContract} from './bitvector_contract.js';
import {planningDigest} from './planning_identity.js';
import {jsonToolOutput} from './json_output.js';
import {PROVIDER_ID,PROVIDER_VERSION,PROVIDER_LIMITS,PROVIDER_RULES} from './bitvector_provider.js';
const files=['bitvector_provider.js','bitvector_provider_adapter.js','bitvector_contract.js','analysis_worker.js','analysis_jobs.js'];
const code=Object.fromEntries(files.map(name=>[name,hashBytes(readStableFile(fileURLToPath(new URL(name,import.meta.url)),1024**2).data)]));
const fail=message=>{throw Object.assign(new Error(message),{code:'INVALID_CANDIDATE_PROVIDER_OUTPUT'});};
export function localProviderIdentity(){
 for(const [file,sha] of Object.entries(code))if(hashBytes(readStableFile(fileURLToPath(new URL(file,import.meta.url)),1024**2).data)!==sha)fail('Provider code changed after load; reload required');
 return {id:PROVIDER_ID,version:PROVIDER_VERSION,code,rulesDigest:planningDigest(code),limits:PROVIDER_LIMITS,dependencies:{kind:'internal-original-JavaScript',nodeVersion:process.version,externalPackages:[],upstreamCommit:null,license:'Project original code; repository LICENSE applies',oracleFiles:[],pickleLoaded:false}};
}
export function validateProviderOutput(contract,input){
 validateBVContract(contract);const result=jsonToolOutput(input);
 if(Buffer.byteLength(JSON.stringify(result))>65536||result.schema!=='ig5-bitvector-provider-v1'||result.providerId!==PROVIDER_ID||result.providerVersion!==PROVIDER_VERSION||result.originalDigest!==contract.originalDigest||result.premiseDigest!==contract.premiseDigest
  ||!['candidate','unchanged'].includes(result.status)||result.verified!==false||result.nativeTargetExecuted!==false||result.businessAccepted!==false)fail('Provider identity or output bounds differ');
 const checked=validateBitvectorAST(result.candidate,contract.variables);
 if(checked.digest!==result.candidateDigest||checked.bits!==contract.original.nodes[contract.original.root].bits)fail('Candidate width or digest differs');
 const cost=ast=>({nodes:ast.nodes.length,operators:ast.nodes.filter(n=>!['var','const'].includes(n.op)).length});
 const original=cost(contract.original),candidate=cost(checked.ast);
 if(planningDigest(original)!==planningDigest(result.cost?.original)||planningDigest(candidate)!==planningDigest(result.cost?.candidate))fail('Provider cost was not reproduced');
 const improved=candidate.nodes<original.nodes&&candidate.operators<original.operators;
 if((result.status==='candidate')!==improved||result.status==='unchanged'&&checked.digest!==contract.originalDigest)fail('Unchanged provider must retain exact original');
 const w=result.work;
 if(!w||w.visitedNodes!==contract.original.nodes.length||w.passes!==1||!Number.isSafeInteger(w.ruleChecks)||w.ruleChecks<0||w.ruleChecks>512||!Number.isSafeInteger(w.rewrites)||w.rewrites<0||w.rewrites>64
  ||!Array.isArray(result.steps)||result.steps.length!==w.rewrites||result.steps.some(s=>!Number.isSafeInteger(s.sourceNode)||s.sourceNode<0||s.sourceNode>=contract.original.nodes.length||!PROVIDER_RULES.includes(s.rule)))fail('Provider work receipt exceeds fixed bounds');
 return result;
}
/** One existing settled data-worker request. Failures preserve original and do not start the solver. */
export async function generateLocalCandidate(dataJobs,contract,signal){
 validateBVContract(contract);const identity=localProviderIdentity();
 if(signal?.aborted)throw Object.assign(new Error('Candidate generation cancelled'),{code:'ABORT_ERR'});
 try{
  const raw=await dataJobs.runSettled('bv-candidate-generate',{contract},signal);
  const result=validateProviderOutput(contract,raw);localProviderIdentity();
  return {identity,result,cleanupConfirmed:true};
 }catch(error){
  if(signal?.aborted||['ABORT_ERR','DISPOSED'].includes(error.code))throw error;
  return {identity,result:null,status:'fallback-original',code:error.code||'CANDIDATE_PROVIDER_FAILED',cleanupConfirmed:error.cleanupConfirmed!==false&&!dataJobs.active,reason:'Candidate provider unavailable/invalid; original contract and expression retained, no solver dispatched'};
 }
}
