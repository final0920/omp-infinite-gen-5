import path from 'node:path';
import { createHash } from 'node:crypto';
import { privateResearchStore } from './research_case_index.js';
import { validateScope, scopeKey, plain, text, refValid, sameRef } from './research_v2_contract.js';
import { researchDigest } from './research_state.js';
import { dossierEvidence, validateSnapshotReport } from './evidence_adapters/dossier.js';
import { readStableFile, hashBytes } from './analysis_artifacts.js';

const fail=(code,message)=>{throw Object.assign(new Error(message),{code});};
const sha=b=>createHash('sha256').update(b).digest('hex');
const clipped=(s,n)=>{let end=Math.min(s.length,n);if(end<s.length&&/[\uD800-\uDBFF]/.test(s[end-1]))end--;return s.slice(0,end);};
const identity=['projectId','artifactId','sha256','engine','provider'];
const controls={
  'case-status':['action','id'],
  'case-index':['action','id','expected_generation','expected_task_revision','expected_research_revision'],
  'case-search':['action','id','query','generation'],
  'case-read':['action','id','ref','generation','cursor'],
};
export const caseIndexActions=Object.freeze(Object.keys(controls));
export const CASE_INDEX_LIMITS=Object.freeze({ sourcesPerKind:8, records:64, matches:3, pageChars:2048, responseBytes:32768 });
export function validateCaseIndexInput(input){
 if(!plain(input)||!Object.hasOwn(controls,input.action)||Object.keys(input).some(k=>!controls[input.action].includes(k)))fail('INVALID_ARGUMENT','Invalid private case index fields');
 if(input.action==='case-search'&&!text(input.query,256))fail('INVALID_ARGUMENT','Case search needs 1..256 characters');
 if(input.action==='case-read'&&(!refValid(input.ref)||input.cursor!==undefined&&!text(input.cursor,2048)))fail('INVALID_ARGUMENT','Case read requires exact ref and optional cursor');
 const generation=v=>v==='absent'||typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
 if(input.generation!==undefined&&!generation(input.generation))fail('INVALID_ARGUMENT','Invalid private generation');
 if(input.action==='case-index'&&(!generation(input.expected_generation)||['expected_task_revision','expected_research_revision'].some(k=>!Number.isSafeInteger(input[k])||input[k]<0||Object.is(input[k],-0))))fail('INVALID_ARGUMENT','Index refresh requires explicit generation and task/research revisions');
}
/** Only an internal host read closure supplies these values. No public scope/path/run parameters. */
export function caseTrustedScope({context,task,research}){
 if(!context||!task||!research)return {ready:false,reason:'research-contract-required'};
 if(identity.some(k=>task.scope?.[k]!==context[k]||research.scope?.[k]!==context[k])||task.taskId!==research.taskId)fail('RESEARCH_SCOPE_MISMATCH','Private index task/research belongs to another target');
 if(context.artifactId!=='artifact_'+context.sha256||!/^project_[a-f0-9-]{36}$/.test(context.projectId)||!/^attachment_[a-f0-9-]{36}$/.test(context.attachmentId))fail('RESEARCH_SCOPE_MISMATCH','Trusted static identity is incomplete');
 if(research.stale||research.taskRevision!==task.taskRevision||research.context?.attachmentId!==context.attachmentId||research.context?.dbRevision!==context.dbRevision)return {ready:false,reason:'stale-research-context'};
 const scope=validateScope({kind:'private',projectId:context.projectId,artifactSha256:context.sha256,engine:context.engine,provider:context.provider,
  attachmentId:context.attachmentId,dbRevision:context.dbRevision,taskId:task.taskId,taskRevision:task.taskRevision,contractDigest:research.contractDigest,
  runId:null,moduleEpoch:null});
 return {ready:true,scope};
}
export function projectCaseSources(data,artifacts){
 const {context,task,research}=data, result=[],diagnostics=[],omitted={};
 const add=(id,kind,status,claim,sourceData,sourceRef,sourceContext,observedAt)=>{
  if(result.length>=CASE_INDEX_LIMITS.records)fail('CASE_INDEX_LIMIT','Private projection exceeds 64 records; no implicit truncation');
  const bytes=Buffer.from(JSON.stringify(sourceData)),digest=sha(bytes);
  result.push({id,kind,status,claim,sourceData,sourceRef:sourceRef||{id:task.taskId,sha256:digest},sourceContext:sourceContext||context,
   contentSha256:sourceRef?.sha256||digest,observedAt,projectionDigest:digest});
 };
 add('task-'+task.taskId,'task-statement','reported',task.conclusion||task.goal,
  {taskId:task.taskId,taskRevision:task.taskRevision,status:task.status,goal:task.goal,hypothesis:task.hypothesis,conclusion:task.conclusion,next_step:task.next_step},null,null,task.updatedAt);
 const related=(data.relatedTasks||[]);omitted.relatedTasks=Math.max(0,related.length-8);
 for(const other of related.slice(0,8)){
  if(identity.some(k=>other.scope?.[k]!==context[k])||other.taskId===task.taskId)fail('RESEARCH_SCOPE_MISMATCH','Related task is outside the trusted project/artifact/engine scope');
  add('related-task-'+other.taskId,'related-task-statement','reported',other.conclusion||other.goal,
   {taskId:other.taskId,taskRevision:other.taskRevision,scope:other.scope,status:other.status,goal:other.goal,hypothesis:other.hypothesis,conclusion:other.conclusion,next_step:other.next_step,
    attachmentAndDatabaseBinding:'not-recorded-for-caller-statements',read:{tool:'ig5_workspace',target:context.target,engine:context.engine,workspace:{action:'get',id:other.taskId}}},null,
   {...other.scope,attachmentId:null,dbRevision:null,currentFact:false},other.updatedAt);
  // A localRef authenticates the source projection, not the current task or current DB.
  const row=result.at(-1);row.sourceRef={id:other.taskId,sha256:row.projectionDigest};
 }
 for(const kind of ['hypotheses','obligations','experiments']){
  const all=research[kind]||[],selected=all.slice(-8);omitted[kind]=all.length-selected.length;
  for(const item of selected){
   const state=research.objectStates?.[kind]?.find(x=>x.id===item.id);
   const status=state?.staleContract||state?.status==='superseded'?'stale':kind==='hypotheses'&&item.value.supporting?.length&&item.value.opposing?.length?'contested':'reported';
   add(kind+'-'+item.id,kind,status,item.value.proposition||item.value.property||item.value.question,
    {item,state:state||null,researchRevision:research.researchRevision,contractRevision:research.contractRevision},null,null,item.createdAt||research.updatedAt);
  }
 }
 const snapshots=task.systemEvidence.slice(-8);omitted.dossiers=Math.max(0,task.systemEvidence.length-snapshots.length);
 for(const snapshot of snapshots){
  try{
   dossierEvidence(artifacts,task,snapshot.snapshot_id);
   const bytes=readStableFile(path.join(artifacts.directory('records'),snapshot.report_id+'.json'),128*1024).data;
   if(hashBytes(bytes)!==snapshot.report_sha256)fail('ARTIFACT_CHANGED','Dossier changed after membership validation');
   const report=JSON.parse(bytes);validateSnapshotReport(snapshot,report);
   add('dossier-'+snapshot.snapshot_id,'function-dossier',snapshot.stale?'stale':'observed',`Function ${snapshot.function.ea}: ${snapshot.sections.join(', ')}`,
    report.result,{id:snapshot.report_id,sha256:snapshot.report_sha256},snapshot.context,snapshot.recordedAt);
  }catch(error){diagnostics.push({kind:'dossier',id:snapshot.snapshot_id,code:error.code||'EVIDENCE_READ_FAILED'});}
 }
 // Fixed full-report integrity only. A verifier's stored status is not re-accepted here.
 const verification=(research.verificationRefs||[]).slice(-8);omitted.verification=Math.max(0,(research.verificationRefs||[]).length-verification.length);
 for(const ref of verification){try{
  if(artifacts.metadata(ref.reportId).result.recordSha256!==ref.sha256)fail('ARTIFACT_CHANGED','Verification metadata differs');
  const bytes=readStableFile(path.join(artifacts.directory('records'),ref.reportId+'.json'),256*1024).data;
  if(hashBytes(bytes)!==ref.sha256)fail('ARTIFACT_CHANGED','Verification report bytes differ');
  const report=JSON.parse(bytes);
  if(report.id!==ref.reportId||report.kind!=='research-verification'||report.action!=='verify'||report.association?.taskId!==task.taskId||report.association?.scopeDigest!==research.scopeDigest)fail('RESEARCH_SCOPE_MISMATCH','Verification association differs');
  const oldContract=report.result?.contractDigest!==research.contractDigest||report.result?.contractRevision!==research.contractRevision;
  add('verification-'+ref.reportId,'verifier-history',oldContract?'stale':'reported','Historical verifier result; current validity must be read with research-verification',report.result,
   {id:ref.reportId,sha256:ref.sha256},{association:report.association,historicalScope:report.result?.scope||null,currentValidity:'not-assessed-by-index'},research.updatedAt);
 }catch(error){diagnostics.push({kind:'verification',id:ref.reportId,code:error.code||'EVIDENCE_READ_FAILED'});}}
 for(const f of data.failures||[]){
  if(!refValid(f.reportRef)||identity.some(k=>f.scope?.[k]!==context[k])){diagnostics.push({kind:'failure',code:'FAILURE_SCOPE_OR_COMMIT_UNAVAILABLE'});continue;}
  // FailureRecords.recent has already re-read and hashed this committed fixed report.
  add('failure-'+f.reportRef.id,'failure',f.historical?'stale':'observed',`${f.operation}: ${f.original.code}`,
   {operation:f.operation,original:f.original,scope:f.scope,semanticKey:f.semanticKey,planningKey:f.planningKey||null,runtimeDigest:f.runtimeDigest,advice:f.advice,observedAt:f.observedAt},
   f.reportRef,f.scope,f.observedAt);
 }
 if(data.failureError)diagnostics.push({kind:'failure',code:data.failureError});
 const stamp=researchDigest({context,task,research,records:result,diagnostics,omitted});
 return {records:result,stamp,diagnostics,omitted};
}
function recordOf(row,scope,stamp){
 const body=JSON.stringify({schema:'ig5-private-case-note-v1',kind:row.kind,claim:row.claim,sourceRef:row.sourceRef,sourceContext:row.sourceContext,sourceData:row.sourceData,
  taskRevision:scope.taskRevision,sourceStatus:row.status,algorithmExplained:'not-established-by-index',semanticVerified:false,executionAuthorized:false},null,2);
 const note='source-stamp:'+stamp;
 return {id:row.id,kind:'case-fact',scope,metadata:{title:clipped(row.kind+': '+row.claim,160),tags:[row.kind,'private','navigation-only'],contentKind:'original-note',
  sources:[{type:'local-case',url:null,author:'IG5 trusted task/report projection',publishedAt:null,retrievedAt:row.observedAt,contentSha256:row.contentSha256,commit:null,parserVersion:'case-host-projection-v1',license:'private local reference',rightsStatus:'local-reference-only',review:'reviewed',qualityReview:{traceability:2,specificity:1,reproducibility:0,boundaries:2,relevance:1,reviewer:'fixed-host-adapter',notes:'Integrity and provenance only; no semantic or algorithm acceptance'},verificationLevel:'unverified',correctionRefs:[],localRef:row.sourceRef}],
  reviewNotes:[note,'Output, caller conclusion, recorded observation and algorithm explanation remain distinct.'],caseId:scope.taskId,subject:row.kind,
  claim:clipped(row.claim,2048),status:row.status,observedAt:row.observedAt,unknowns:'Algorithm explanation, current proof validity, live run/module epoch and business correctness are not established by this index.',supersedes:[],contradicts:[]},
  body,searchText:clipped(row.kind+' '+row.claim+' '+JSON.stringify(row.sourceData),4096),supersedes:null};
}
function bounded(result){if(Buffer.byteLength(JSON.stringify(result))>CASE_INDEX_LIMITS.responseBytes)fail('CASE_RESPONSE_LIMIT','Private response exceeds 32 KiB; no silent truncation');return result;}
function stampOf(data,artifacts){const trust=caseTrustedScope(data);return {...trust,...(trust.ready?{projection:projectCaseSources(data,artifacts)}:{})};}
/** Explicit maintenance and read bridge; called under the original static-session queue. */
export async function runCaseIndex({projectRoot,input,read,artifacts,memory,execution}){
 validateCaseIndexInput(input);
 if(!execution?.agent?.id)fail('AGENT_SCOPE_REQUIRED','Private case access requires the actual executing agent');
 const beforeData=read(),before=stampOf(beforeData,artifacts);
 const base={schema:'ig5-private-case-response-v1',mode:'explicit-read',semanticVerified:false,executionAuthorized:false,automaticInjection:false,algorithmExplained:'not-established-by-index',completeHistory:false,liveRunBound:false};
 if(!before.ready)return {...base,status:'needs-evidence',reason:before.reason,indexSaved:false};
 const {scope,projection:p}=before,store=privateResearchStore(projectRoot,scope),captured=store.current();
 if(input.generation!==undefined&&input.generation!==captured.generation)fail('STALE_RESEARCH_GENERATION','Private generation changed; query again');
 const active=(captured.snapshot?.entries||[]).filter(e=>e.state==='active');
 const current=!!captured.snapshot&&active.every(e=>e.metadata.reviewNotes.includes('source-stamp:'+p.stamp));
 let result={...base,status:current?'current':captured.snapshot?'needs-refresh':'needs-index',generation:captured.generation,scope,sourceStamp:p.stamp,
  researchRevision:beforeData.research.researchRevision,contractRevision:beforeData.research.contractRevision,diagnostics:p.diagnostics,omittedSources:p.omitted,
  searchScope:'metadata + first 4096 UTF-16 units of explicit source projection',indexSaved:false};
 if(input.action==='case-index'){
  if(input.expected_task_revision!==scope.taskRevision)fail('STALE_TASK_REVISION','Task changed before index refresh');
  if(input.expected_research_revision!==beforeData.research.researchRevision)fail('STALE_RESEARCH_REVISION','Research changed before index refresh');
  if(input.expected_generation!==captured.generation)fail('STALE_RESEARCH_GENERATION','Private index changed before refresh');
  const after=stampOf(read(),artifacts);if(!after.ready||scopeKey(after.scope)!==scopeKey(scope)||after.projection.stamp!==p.stamp)fail('SNAPSHOT_INCONSISTENT','Sources changed before private index commit');
  const upserts=[],withdrawals=[];
  for(const row of p.records){const proposed=recordOf(row,scope,p.stamp),old=active.find(e=>e.ref.id===row.id);
   if(old){const oldData=store.read(old.ref,captured);if(researchDigest(oldData.record.metadata)===researchDigest(proposed.metadata)&&oldData.body===proposed.body&&oldData.record.searchText===proposed.searchText)continue;proposed.supersedes=old.ref;}
   const {scope:unused,...item}=proposed;upserts.push(item);
  }
  for(const old of active)if(!p.records.some(r=>r.id===old.ref.id))withdrawals.push({ref:old.ref,reason:'Source no longer selected by the bounded trusted projection; original record retained',replacementRef:null});
  let receipt=null;
  try{if(upserts.length||withdrawals.length)receipt=store.publish({expectedGeneration:captured.generation,upserts,withdrawals});}
  catch(error){if(error.generationSaved)return bounded({...base,status:'needs-refresh',indexSaved:true,generation:error.publishedGeneration,cleanupConfirmed:error.cleanupConfirmed??false,code:error.code||'CASE_PUBLICATION_CLEANUP_FAILED',note:'Generation committed; preserve the unknown lock and inspect current sources before retrying.'});throw error;}
  result={...result,status:'current',mode:'explicit-index-refresh',indexSaved:!!receipt,generation:receipt?.generation||captured.generation,publication:receipt,records:p.records.length};
 }else if(input.action==='case-read'&&current){
  const data=store.read(input.ref,captured);let offset=0;
  if(input.cursor){let c;try{c=JSON.parse(Buffer.from(input.cursor,'base64url').toString('utf8'));}catch{fail('INVALID_CASE_CURSOR','Invalid private cursor');}
   if(!plain(c)||Object.keys(c).sort().join(',')!=='generation,offset,ref,scope,stamp'||c.generation!==captured.generation||c.scope!==scopeKey(scope)||c.stamp!==p.stamp||!refValid(c.ref)||!sameRef(c.ref,input.ref)||!Number.isSafeInteger(c.offset)||Object.is(c.offset,-0)||c.offset<0||c.offset>data.body.length)fail('INVALID_CASE_CURSOR','Private cursor does not match scope, sources, generation and ref');offset=c.offset;
  }
  if(offset>0&&/[\uDC00-\uDFFF]/.test(data.body[offset]||'')&&/[\uD800-\uDBFF]/.test(data.body[offset-1]))fail('INVALID_CASE_CURSOR','Cursor splits Unicode');
  let end=Math.min(data.body.length,offset+2048);if(end<data.body.length&&/[\uD800-\uDBFF]/.test(data.body[end-1]))end--;
  const currentSources=data.entry.state==='active'&&data.record.metadata.reviewNotes.includes('source-stamp:'+p.stamp);
  result={...result,ref:input.ref,recordState:data.entry.state,currentSources,status:currentSources?data.record.metadata.status:'stale',sourceStatus:data.record.metadata.status,title:data.record.metadata.title,sourceRefs:data.record.metadata.sources.map(s=>s.localRef),body:data.body.slice(offset,end),bodySha256:sha(data.body),offset,
   nextCursor:end<data.body.length?Buffer.from(JSON.stringify({generation:captured.generation,offset:end,ref:input.ref,scope:scopeKey(scope),stamp:p.stamp})).toString('base64url'):null};
 }else if(input.action==='case-search'&&current){
  const terms=input.query.normalize('NFKC').toLowerCase().split(/\s+/).filter(Boolean);
  const matches=active.filter(e=>terms.every(t=>(e.metadata.title+' '+e.searchText).normalize('NFKC').toLowerCase().includes(t)));
  result={...result,total:matches.length,omittedMatches:Math.max(0,matches.length-3),items:matches.slice(0,3).map(e=>({ref:e.ref,title:e.metadata.title,status:e.metadata.status,scoreMeaning:'keyword-match-only',algorithmExplained:'not-established-by-index'}))};
 }
 if(input.action==='case-search'){
  const agent=execution.agent,session=agent.session,cwd=session?.header?.cwd;
  if(memory&&session?.header?.id===agent.id&&typeof cwd==='string'&&path.isAbsolute(cwd)){
   try{const found=await memory.handle(agent,{action:'search',query:'"'+scope.taskId+'"',limit:3});
    if(agent.session!==session||session.header.cwd!==cwd||session.header.id!==agent.id)fail('LCM_SCOPE_CHANGED','Host session/workspace changed during history lookup');
    result.historyNavigation={status:'session-navigation-only',captureComplete:found.captureComplete===true,scope:'executing DSH session + cwd; UUID mention does not authenticate a project fact',exhaustive:false,
     reads:found.hits.slice(0,3).map(hit=>({tool:'ig5_profile',memory:{action:'read',ref:hit.ref}})),contentIndexed:false,semanticVerified:false};
   }catch(error){if(error.code==='LCM_SCOPE_CHANGED')throw error;result.historyNavigation={status:'unavailable',code:error.code||'LCM_UNAVAILABLE',contentIndexed:false};}
  }else result.historyNavigation={status:'unavailable',code:'LCM_SCOPE_REQUIRED',contentIndexed:false};
 }
 try{const end=stampOf(read(),artifacts);if(!end.ready||scopeKey(end.scope)!==scopeKey(scope)||end.projection.stamp!==p.stamp)fail('SNAPSHOT_INCONSISTENT','Current task/source context changed during private case operation');}
 catch(error){if(result.indexSaved)return bounded({...base,status:'needs-refresh',indexSaved:true,generation:result.generation,publication:result.publication,postCommitContext:'unavailable',code:error.code||'CASE_CONTEXT_UNAVAILABLE'});throw error;}
 return bounded(result);
}
