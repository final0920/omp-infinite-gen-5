import path from 'node:path';
import { ResearchV2Store } from './research_v2_store.js';
import { RESEARCH_V2_LIMITS } from './research_v2_contract.js';

/** Public-only adapter. Private roots/scopes are never accepted from query arguments. */
export function publicResearchStore(projectRoot) {return new ResearchV2Store({root:path.join(path.resolve(projectRoot),'knowledge-v2'),scope:{kind:'public'}});}
function displayMetadata(record) {
  const m=record.metadata,source=m.sources[0];
  return {schema:record.kind==='document'?'ig5-source-document-v2':'ig5-method-card-v2',id:record.id,...m,
    ...(record.kind==='document'?{author:source.author,sourceUrl:source.url,license:source.license}:{reviewStatus:'reference-only'}),researchScope:'public-reference-only'};
}
export function loadPublicResearchV2(cfg) {
  if(!cfg.projectRoot)return null;
  const store=publicResearchStore(cfg.projectRoot),captured=store.current();if(!captured.snapshot)return null;
  const entries=captured.snapshot.entries.map(e=>({ref:e.ref,card:displayMetadata({id:e.ref.id,kind:e.kind,metadata:e.metadata}),searchText:e.searchText,state:e.state,reason:e.reason,replacementRef:e.replacementRef,v2:true}));
  return {generation:captured.generation,entries,limits:RESEARCH_V2_LIMITS,read(ref) {
    const data=store.read(ref,captured);
    return {card:{...displayMetadata(data.record),body:data.body},paragraphs:data.record.body.paragraphs,bodySha256:data.record.body.sha256,state:data.entry.state,reason:data.entry.reason,replacementRef:data.entry.replacementRef};
  }};
}
