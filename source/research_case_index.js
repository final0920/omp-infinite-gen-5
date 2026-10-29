import path from 'node:path';
import { ResearchV2Store } from './research_v2_store.js';
import { validateScope, scopeKey, plain, text } from './research_v2_contract.js';
import { knowledgeFail as fail } from './knowledge_io.js';

/** F02 internal contract. F04 must pass context resolved by the host, never a tool's projectId. */
export function privateResearchStore(projectRoot,trustedScope) {
  if(typeof projectRoot!=='string' || !path.isAbsolute(projectRoot))fail('INVALID_ARGUMENT','Explicit private project root required');
  const scope=validateScope(trustedScope);if(scope.kind!=='private')fail('RESEARCH_SCOPE_MISMATCH','Private index requires trusted project context');
  return new ResearchV2Store({root:path.join(path.resolve(projectRoot),'private-research-v2',scopeKey(scope)),scope});
}
export function queryPrivateResearch(projectRoot,trustedScope,input={}) {
  if(!plain(input) || Object.keys(input).some(k=>!['query','ref','generation'].includes(k)))fail('INVALID_ARGUMENT','Unknown private research query field');
  const {query,ref,generation}=input;
  if(ref!==undefined && query!==undefined || ref===undefined && !text(query,256))fail('INVALID_ARGUMENT','Choose bounded private query or exact reference');
  const store=privateResearchStore(projectRoot,trustedScope),current=store.current();
  if(generation!==undefined && generation!==current.generation)fail('STALE_RESEARCH_GENERATION','Private context generation changed');
  if(ref!==undefined) {
    const data=store.read(ref,current);
    return {generation:current.generation,ref,scope:validateScope(trustedScope),metadata:data.record.metadata,body:data.body,state:data.entry.state,semanticVerified:false,executionAuthorized:false};
  }
  const terms=query.normalize('NFKC').toLowerCase().split(/\s+/).filter(Boolean);
  const matches=(current.snapshot?.entries || []).filter(e=>e.state==='active' && terms.every(t=>(e.metadata.title+' '+e.searchText+' '+e.metadata.tags.join(' ')).normalize('NFKC').toLowerCase().includes(t)));
  return {generation:current.generation,scope:validateScope(trustedScope),total:matches.length,items:matches.slice(0,3).map(e=>({ref:e.ref,title:e.metadata.title,status:e.metadata.status || 'reference-only',scoreMeaning:'keyword-match-only'})),omitted:Math.max(0,matches.length-3),semanticVerified:false,executionAuthorized:false};
}
