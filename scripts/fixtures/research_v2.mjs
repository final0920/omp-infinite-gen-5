import {knowledgeHash} from '../../source/knowledge_io.js';
export function reviewedSource(body='fixture body',type='web') {
  return {type,url:type==='local-case'?null:'https://example.org/research/fixture',author:'Synthetic test fixture',publishedAt:null,retrievedAt:'2026-10-24T00:00:00.000Z',contentSha256:knowledgeHash(body),commit:null,parserVersion:'fixture-1',license:'original fixture',rightsStatus:'original-notes-with-links',review:'reviewed',qualityReview:{traceability:0,specificity:0,reproducibility:0,boundaries:0,relevance:0,reviewer:'synthetic-fixture',notes:'Synthetic test data; not a reviewed external source'},verificationLevel:'reference-only',correctionRefs:[],localRef:type==='local-case'?{id:'case-fixture',sha256:knowledgeHash('fixture-case')}:null};
}
export function publicDocument(id='v2-doc',body='fixture body') {
  return {id,kind:'document',metadata:{title:'Fixture research document',tags:['fixture','MBA'],sources:[reviewedSource(body)],reviewNotes:['Synthetic fixture; never a research source or proof.'],contentKind:'original-note',methodIds:['mba-synthesis']},body,searchText:'fixture MBA reviewed metadata only',supersedes:null};
}
export function publicMethod() {
  const record=publicDocument('v2-method');record.kind='method';delete record.metadata.methodIds;
  Object.assign(record.metadata,{category:'mba',prerequisites:['Exact widths'],limitations:['No target proof'],steps:['Read inputs'],verification:'Independent verifier required',integration:'research-only',relatedTools:['ig5_ir']});return record;
}
export const privateScope=()=>({kind:'private',projectId:'fixture-project',artifactSha256:knowledgeHash('fixture-artifact'),engine:'ghidra',provider:'ghidra',attachmentId:'fixture-attachment',dbRevision:1,taskId:'fixture-task',taskRevision:1,contractDigest:knowledgeHash('fixture-contract'),runId:null,moduleEpoch:null});
export function privateFact(id='case-fixture') {
  const record=publicDocument(id,'Historical output is known; implementation explanation remains open.');record.kind='case-fact';delete record.metadata.methodIds;record.metadata.sources=[reviewedSource(record.body,'local-case')];
  Object.assign(record.metadata,{caseId:id,subject:'fixture-output',claim:'Output known does not prove implementation',status:'reported',observedAt:'2026-10-24T00:00:00.000Z',unknowns:'No independent semantic oracle',supersedes:[],contradicts:[]});return record;
}
