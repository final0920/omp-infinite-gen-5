// Explicit OFFLINE development replay. The manager below is a fixture, not an opened native session.
import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import {randomUUID,createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {auditCases,readEvidence} from './fusion/evidence.mjs';
import {InvestigationStore} from '../source/investigation_store.js';
import {ResearchState,researchScopeDigest} from '../source/research_state.js';
import {AnalysisArtifacts} from '../source/analysis_artifacts.js';
import {runWorkspace} from '../source/investigation_workflow.js';
const [bundlePath,caseRoot,output]=process.argv.slice(2),sha=b=>createHash('sha256').update(b).digest('hex');
for(const p of [bundlePath,caseRoot,output])assert(p&&path.isAbsolute(p),'Use absolute CASE_BUNDLE CASE_ROOT NEW_OUTPUT');
const source=path.resolve(fileURLToPath(new URL('..',import.meta.url)));
for(const root of [caseRoot,source])assert(!path.resolve(output).toLowerCase().startsWith(path.resolve(root).toLowerCase()+path.sep)&&path.resolve(output).toLowerCase()!==path.resolve(root).toLowerCase(),'Output must be outside source and read-only case tree');
await fs.mkdir(output);const bundleBytes=await fs.readFile(bundlePath),bundle=JSON.parse(bundleBytes);
const integrity=await auditCases(bundle,caseRoot);await fs.writeFile(path.join(output,'source-integrity.json'),JSON.stringify(integrity,null,2));
for(const sample of bundle.samples){const read=await readEvidence(caseRoot,sample.path);assert.equal(read.sha256,sample.sha256);}
const cfg={projectRoot:path.join(output,'isolated-projects')},notes=new InvestigationStore({root:cfg.projectRoot}),service=new ResearchState({root:cfg.projectRoot}),artifacts=new AnalysisArtifacts(path.join(output,'isolated-artifacts'));
const context={projectId:'project_'+randomUUID(),artifactId:'artifact_'+bundle.samples[1].sha256,sha256:bundle.samples[1].sha256,engine:'ghidra',provider:'ghidra',attachmentId:'attachment_'+randomUUID(),dbRevision:0,target:path.join(output,'NOT-AN-OPENED-NATIVE-TARGET.so')};
const session={engine:'ghidra',target:context.target},mgr={analysis:{artifacts},investigations:notes,researchState:service,get:()=>session,alive:()=>true,checkCancelled(){},evidence:()=>({...context})};
const execution={agent:{id:'offline-development-replay'}},results=[];
try{for(const c of bundle.cases){
 const task=notes.create(context,{goal:c.question,hypothesis:c.hypotheses.join('; '),next_step:c.expectedDecision},execution.agent.id);
 const conclusion=JSON.stringify({caseId:c.caseId,bundleSha256:sha(bundleBytes),retrospectiveSourceStatus:c.status,locatedResult:c.locatedResult,observations:c.observations,laterCorrection:c.laterCorrection,unknowns:c.unknowns,sourceRefs:c.sourceRefs,redaction:c.redaction,timeline:c.timeline});
 assert(conclusion.length<=4096,'Do not truncate the accepted retrospective projection');
 const updated=notes.update(context,task.taskId,{expected_task_revision:0,conclusion},execution.agent.id);
 const state=service.mutate(updated,context,{operation:'initialize',expected_task_revision:updated.taskRevision,expected_research_revision:0,scope_digest:researchScopeDigest(context),value:{question:c.question,inputDomain:'Retrospective source-bound development case only',returns:'Historical reported output; not a proof',outputs:c.locatedResult,sideEffects:'Not independently assessed',environment:'Offline fixture; no native target is opened',exclusions:c.unknowns}},execution.agent.id);
 const call=async input=>(await runWorkspace(mgr,cfg,{target:context.target,workspace:{id:task.taskId,...input}},execution)).workspace;
 const before=await call({action:'case-status'});assert.equal(before.status,'needs-index');
 const indexed=await call({action:'case-index',expected_generation:'absent',expected_task_revision:updated.taskRevision,expected_research_revision:state.researchRevision});
 const found=await call({action:'case-search',query:c.caseId});assert.equal(found.total,1);assert.equal(found.items[0].status,'reported');assert.equal(found.algorithmExplained,'not-established-by-index');
 let body='',cursor;do{const page=await call({action:'case-read',ref:found.items[0].ref,...(cursor?{cursor}:{})});assert.equal(page.offset,body.length);body+=page.body;cursor=page.nextCursor;if(!cursor)assert.equal(sha(body),page.bodySha256);}while(cursor);
 const recovered=JSON.parse(JSON.parse(body).sourceData.conclusion);assert.equal(recovered.locatedResult,c.locatedResult);assert.equal(recovered.retrospectiveSourceStatus,c.status);assert.deepEqual(recovered.sourceRefs,c.sourceRefs);
 const unseen='never-created-case-44dfb0';assert.equal((await call({action:'case-search',query:unseen})).total,0);
 results.push({caseId:c.caseId,taskId:task.taskId,generation:indexed.generation,ref:found.items[0].ref,sourceStatusRetained:recovered.retrospectiveSourceStatus,indexStatus:'reported',retrieved:true,uncreatedCaseQuery:0,relatedTaskOmitted:indexed.omittedSources.relatedTasks,algorithmExplained:false,nativeTargetOpened:false});
 }}finally{await artifacts.dispose();}
const receipt={schema:'ig5-f04-offline-case-acceptance-v1',scope:'offline-fixture-manager; not actual native session or blind/model evaluation',cases:results.length,results,sourceIntegrityMatched:true,sourceBytesUnmodified:true,publicExportAllowed:false,liveIndexModified:false,nativeExecutions:0,sourceBundleSha256:sha(bundleBytes)};
await fs.writeFile(path.join(output,'acceptance.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify({cases:results.length,found:results.filter(x=>x.retrieved).length,scope:receipt.scope,publicExportAllowed:false}));
