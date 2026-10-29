import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { readStableFile, hashBytes } from './analysis_artifacts.js';
const PIN='65bf673f1c4304cc2c09076e3b96e368da9e0df72aa0badeba0c2a5cae392934';
const RUNTIME='8fc4ae42f775f0139aa5f184c912db71f77e68d661c14564ab6f4820d434abea';
const fail=()=>{throw new Error('Flow semantics returned inconsistent process, source, query or evidence scope');};
export async function runFlowSemantics(jobs,analysis,prefix,full,signal){
  if(jobs.closed||signal?.aborted)throw new Error('Flow semantics cancelled');
  if(jobs.active.size>=2)throw new Error('Analysis busy; maximum two owned requests');
  const raw=Buffer.from(JSON.stringify({schema:'ig5-flow-semantic-input-v1',prefix,full}));if(raw.length>4*1024**2)fail();
  const input=jobs.artifacts.put(raw),jobId=randomUUID(),parent=path.join(jobs.artifacts.root,'jobs');
  if(fs.realpathSync(parent)!==parent||!fs.lstatSync(parent).isDirectory())fail();
  const directory=path.join(parent,jobId);fs.mkdirSync(directory);
  const reply=await jobs.request({job_id:jobId,sha256:input.sha256},signal,'flow-semantics'),p=reply?.process;
  if(reply?.targetSha256!==input.sha256||reply.runtimeManifestPin!==RUNTIME||p?.status!=='completed'||p.exitCode!==0||p.limitReason!==null
    ||p.childExitConfirmed!==true||p.jobAssignedAtCreation!==true||p.activeProcessLimit!==1||p.memoryLimitBytes!==2*1024**3
    ||!Number.isSafeInteger(p.pid)||p.pid<1||!Number.isSafeInteger(p.elapsedMs)||p.elapsedMs<0
    ||!Number.isSafeInteger(reply.sharedBudgetMs)||reply.sharedBudgetMs<1||reply.sharedBudgetMs>50000
    ||!Number.isSafeInteger(reply.processBudgetMs)||reply.processBudgetMs<1||reply.processBudgetMs>reply.sharedBudgetMs
    ||p.elapsedMs>reply.processBudgetMs+100||!Number.isSafeInteger(reply.outputBytes)||reply.outputBytes<1||reply.outputBytes>1024**2)fail();
  const {data}=readStableFile(path.join(directory,'stdout.log'),1024**2);
  if(data.length!==reply.outputBytes||hashBytes(data)!==reply.outputSha256)fail();
  const result=JSON.parse(data.toString('utf8'));
  if(result.schema!=='ig5-flow-semantic-assessment-v1'||result.inputSha256!==input.sha256||result.targetSha256!==full.targetSha256
    ||result.solverManifestPin!==PIN||!/^[a-f0-9]{64}$/.test(result.solverDllSha256||'')||typeof result.assessmentComplete!=='boolean'
    ||!Array.isArray(result.queries)||result.queries.length>128||!Array.isArray(result.assessments)||result.assessments.length>4
    ||['nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified','vmRoleProved','instructionSemanticsProved','hostWitnessReplayVerified'].some(k=>result[k]!==false))fail();
  let bytes=data.length;const evidence=[];
  for(const [i,q] of result.queries.entries()){
    if(!['sat','unsat','unknown','unverified'].includes(q.status)||!Number.isSafeInteger(q.timeoutMs)||q.timeoutMs<1||q.timeoutMs>2000
      ||q.checkSatCalls!==1||![0,1].includes(q.modelReadCalls)||(q.model&&q.modelReadCalls!==1)||(q.status==='sat'&&q.modelReadCalls!==1)
      ||(q.status!=='unverified'&&q.modelReadCalls!==(q.model?1:0))
      ||!Number.isSafeInteger(q.encodedSexpressions)||q.encodedSexpressions<1||q.encodedSexpressions>2048
      ||!Number.isSafeInteger(q.encodedAtomTokens)||q.encodedAtomTokens<1||q.encodedAtomTokens>8192
      ||!Number.isSafeInteger(q.encodedDepth)||q.encodedDepth<1||q.encodedDepth>128)fail();
    for(const [key,ext,max] of [['query','smt2',1024**2],['model','model.txt',65536]]){
      const item=q[key];if(!item){if(key==='query'||q.status==='sat')fail();continue;}
      if(item.name!==`q${String(i).padStart(3,'0')}.${ext}`||!Number.isSafeInteger(item.bytes)||item.bytes<1||item.bytes>max||!/^[a-f0-9]{64}$/.test(item.sha256||''))fail();
      const {data:body}=readStableFile(path.join(directory,'semantic-queries',item.name),max);bytes+=body.length;
      if(bytes>4*1024**2||body.length!==item.bytes||hashBytes(body)!==item.sha256)fail();
      evidence.push({queryIndex:i,kind:key,name:item.name,...jobs.artifacts.put(body)});
    }
  }
  const replay=result.assessmentComplete?await analysis.replayVmFlowWitnesses({prefix,full,assessment:result},signal):{
    schema:'ig5-flow-semantic-witness-replay-v1',hostWitnessReplayVerified:false,semanticNonconstancyProved:false,
    reason:'Incomplete assessment retained; no partial queries promoted',nativeTargetExecuted:false,instructionSemanticsProved:false,vmRoleProved:false,businessAccepted:false};
  if(replay?.schema!=='ig5-flow-semantic-witness-replay-v1'||typeof replay.semanticNonconstancyProved!=='boolean'
    ||replay.nativeTargetExecuted!==false||replay.instructionSemanticsProved!==false||replay.vmRoleProved!==false||replay.businessAccepted!==false
    ||(replay.semanticNonconstancyProved&&replay.hostWitnessReplayVerified!==true))fail();
  const record=jobs.artifacts.save({kind:'flow-semantic-assessment',action:'assess',input,
    inputMeaning:'Internally produced complete projection JSON; input SHA is not the PE target SHA',process:p,result,replay,queryEvidence:evidence,
    combinedOutputBytes:bytes},{pretty:true,maxBytes:4*1024**2});
  return {result,replay,process:p,reportPath:path.join(jobs.artifacts.root,'records',record.id+'.json'),reportSha256:jobs.artifacts.metadata(record.id).result.recordSha256};
}
