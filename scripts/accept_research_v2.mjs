// Explicit isolated data acceptance. Reads existing v1/case inputs; never alters them.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {readKnowledgeBytes,decodeKnowledgeText,knowledgeHash as hash} from '../source/knowledge_io.js';
import {runKnowledge,validateKnowledgeCatalog} from '../source/knowledge_catalog.js';
import {publishPublicKnowledgeV2} from '../source/knowledge_publish_v2.js';
import {publicResearchStore} from '../source/knowledge_v2.js';
import {privateResearchStore,queryPrivateResearch} from '../source/research_case_index.js';
import {publicDocument,privateFact,privateScope,reviewedSource} from './fixtures/research_v2.mjs';
import {readLegacyKnowledge} from '../source/knowledge_v2_compat.js';
import {inventory} from './fusion/evidence.mjs';

export async function main([inputProject,casesFile,output]) {
  if(![inputProject,casesFile,output].every(p=>p && path.isAbsolute(p)))throw Error('Use absolute V1_PROJECT_ROOT PRIVATE_CASES_JSON NEW_OUTPUT_DIRECTORY');
  const realParent=fs.realpathSync(path.dirname(output)),destination=path.join(realParent,path.basename(output));
  for(const input of [inputProject,path.dirname(casesFile)]) {const root=fs.realpathSync(input);assert(!destination.toLowerCase().startsWith(root.toLowerCase()+path.sep) && destination.toLowerCase()!==root.toLowerCase());}
  const source=readLegacyKnowledge(inputProject).bytes;if(!source)throw Error('Existing v1 data required');validateKnowledgeCatalog(JSON.parse(decodeKnowledgeText(source)));
  const caseBytes=readKnowledgeBytes(casesFile,1048576),cases=JSON.parse(decodeKnowledgeText(caseBytes));assert.equal(cases.schema,'ig5-private-decision-cases-v1');assert.equal(cases.publicExportAllowed,false);assert(cases.cases.length>=12);
  fs.mkdirSync(output);const project=path.join(output,'public-fixture');fs.mkdirSync(path.join(project,'knowledge-v1'),{recursive:true});fs.writeFileSync(path.join(project,'knowledge-v1','catalog.json'),source,{flag:'wx'});
  const cfg={projectRoot:project},legacyRefs=[];let offset=0;
  do{const page=runKnowledge(cfg,{action:'documents',offset,limit:10});legacyRefs.push(...page.items.map(x=>x.ref));offset=page.nextOffset;}while(offset!==null);
  const readAll=ref=>{let cursor,body='',pages=0,sha;do{const p=runKnowledge(cfg,{action:'read',ref,...(cursor?{cursor}:{})});assert.equal(p.offset,body.length);body+=p.body;pages++;sha=p.bodySha256;cursor=p.nextCursor;}while(cursor);assert.equal(hash(body),sha);return {ref,pages,bodySha256:sha};};
  const before=legacyRefs.map(readAll),fixture=publicDocument('v2-isolated-acceptance','Synthetic F02 contract fixture only.\n\n'+'位向量数据'.repeat(8000));
  const first=publishPublicKnowledgeV2({projectRoot:project,expectedGeneration:'absent',upserts:[fixture],withdrawals:[]}),store=publicResearchStore(project),ref=store.current().snapshot.entries[0].ref,oldPage=runKnowledge(cfg,{action:'read',ref});
  assert(store.read(ref).record.body.bytes>65536);
  const second=publishPublicKnowledgeV2({projectRoot:project,expectedGeneration:first.generation,upserts:[{...fixture,body:fixture.body+' Revised fixture.',supersedes:ref}],withdrawals:[]});
  assert.throws(()=>runKnowledge(cfg,{action:'read',ref,cursor:oldPage.nextCursor}),{code:'INVALID_KNOWLEDGE_CURSOR'});assert.equal(runKnowledge(cfg,{action:'read',ref}).recordState,'superseded');
  const replacement=store.current().snapshot.entries.find(e=>e.state==='active').ref;
  const withdrawn=publishPublicKnowledgeV2({projectRoot:project,expectedGeneration:second.generation,upserts:[],withdrawals:[{ref:replacement,reason:'Isolated fixture only; not reviewed research',replacementRef:null}]});
  assert.equal(runKnowledge(cfg,{action:'read',ref:replacement}).recordState,'withdrawn');const after=legacyRefs.map(readAll);assert.deepEqual(after,before);
  const privateRoot=path.join(output,'private-fixture'),scope={...privateScope(),projectId:cases.projectId,artifactSha256:cases.cases[0].artifactSha256,attachmentId:'offline-f00-case-contract',taskId:'offline-f00-review',contractDigest:hash('Offline retrospective F00 evidence; not a live target context')};
  const now=new Date().toISOString(),facts=cases.cases.map(c=>{
    const item=privateFact(c.caseId);Object.assign(item.metadata,{title:c.question,caseId:c.caseId,subject:c.caseId,claim:c.locatedResult,status:c.status,observedAt:now,unknowns:c.unknowns,tags:['VS1.5','retrospective',c.status]});
    item.body=JSON.stringify({question:c.question,hypotheses:c.hypotheses,historicalAction:c.historicalAction,laterCorrection:c.laterCorrection,sourceRefs:c.sourceRefs,timeline:c.timeline});
    item.searchText=c.question+' '+c.laterCorrection;const source=reviewedSource(item.body,'local-case');Object.assign(source,{author:'F00–01 retrospective case audit',retrievedAt:now,contentSha256:hash(JSON.stringify(c)),localRef:{id:c.caseId,sha256:hash(JSON.stringify(c))},qualityReview:{traceability:2,specificity:1,reproducibility:0,boundaries:2,relevance:1,reviewer:'F00–01 local review',notes:'Source integrity and retrospective summary only; no independent native semantics'}});item.metadata.sources=[source];return item;
  });
  const privateStore=privateResearchStore(privateRoot,scope),privateReceipt=privateStore.publish({expectedGeneration:'absent',upserts:facts,withdrawals:[]}),halt=queryPrivateResearch(privateRoot,scope,{query:'HALT'});assert.equal(halt.items[0].status,'contested');
  const privateRef=halt.items[0].ref;assert.throws(()=>queryPrivateResearch(privateRoot,{...scope,projectId:'foreign'}, {ref:privateRef}),{code:'RESEARCH_REF_MISMATCH'});
  const copied=path.join(output,'foreign-copy');fs.mkdirSync(copied);fs.cpSync(privateStore.root,path.join(copied,'knowledge-v2'),{recursive:true});assert.throws(()=>runKnowledge({projectRoot:copied},{action:'status'}),{code:'RESEARCH_SCOPE_MISMATCH'});
  // Rehearse data rollback in an explicitly owned copy, keeping all v2 bytes quarantined.
  const rollback=path.join(output,'rollback-data');fs.mkdirSync(rollback);fs.cpSync(project,rollback,{recursive:true});
  const from=path.resolve(rollback,'knowledge-v2'),to=path.resolve(rollback,'saved-knowledge-v2'),owned=fs.realpathSync(rollback);
  for(const target of [from,to])assert(target.startsWith(owned+path.sep) && target!==owned);
  const inventoryBefore=await inventory(from);fs.renameSync(from,to);const inventoryAfter=await inventory(to);assert.equal(inventoryBefore.digest,inventoryAfter.digest);
  const fenceFile=path.join(rollback,'knowledge-v1','catalog.json'),fence=JSON.parse(fs.readFileSync(fenceFile));assert.equal(fence.schema,'ig5-knowledge-compat-fence-v2');const preserved=readKnowledgeBytes(path.join(rollback,'knowledge-v1','history',fence.legacyCatalogSha256+'.json'),1048576);assert.equal(hash(preserved),fence.legacyCatalogSha256);fs.writeFileSync(fenceFile,preserved);validateKnowledgeCatalog(JSON.parse(decodeKnowledgeText(preserved)));assert.equal(hash(preserved),hash(source));
  assert.equal(hash(readLegacyKnowledge(inputProject).bytes),hash(source));assert.equal(hash(readKnowledgeBytes(casesFile,1048576)),hash(caseBytes));
  const result={schema:'ig5-f02-isolated-acceptance-v1',legacyCatalogSha256:hash(source),legacyDocuments:before,legacyReferencesUnchanged:true,newBodyBytes:store.read(ref).record.body.bytes,initialGeneration:first.generation,finalGeneration:withdrawn.generation,privateFacts:privateReceipt.records,privateBinding:'offline-development-contract-not-active-host-context',haltStatus:halt.items[0].status,crossProjectRejected:true,privateAsPublicRejected:true,rollback:{scope:'isolated-data-copy',v2FilesRetained:inventoryAfter.files.length,legacyBytesRestored:true,liveDataChanged:false},inputsUnchanged:true,networkPerformed:false,targetExecuted:false,semanticVerified:false,assistAllowed:false};
  fs.writeFileSync(path.join(output,'acceptance.json'),JSON.stringify(result,null,2),{flag:'wx'});return result;
}
if(process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url))main(process.argv.slice(2)).then(r=>console.log(JSON.stringify(r,null,2))).catch(e=>{console.error(e);process.exitCode=1;});
