// Explicit maintenance publication; not imported by index.js or HTTP routes.
import fs from 'node:fs';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {validateKnowledgeCatalog} from './knowledge_catalog.js';
import {knowledgeSeeds} from './knowledge_seeds.js';
import {publicResearchStore} from './knowledge_v2.js';
import {readLegacyKnowledge,writeKnowledgeFence} from './knowledge_v2_compat.js';
import {assertKnowledgePath,readKnowledgeBytes,decodeKnowledgeText,knowledgeFail as fail} from './knowledge_io.js';
import {describeBody,validateMetadata,validateRecord,exact,refValid,text,digest} from './research_v2_contract.js';

export function publishPublicKnowledgeV2({projectRoot,expectedGeneration,upserts=[],withdrawals=[],validateOnly=false}) {
  if(typeof projectRoot!=='string' || !path.isAbsolute(projectRoot) || typeof validateOnly!=='boolean' || !(expectedGeneration==='absent' || digest(expectedGeneration))
    || !Array.isArray(upserts) || !Array.isArray(withdrawals) || upserts.length+withdrawals.length<1 || upserts.length+withdrawals.length>256)fail('INVALID_RESEARCH_PUBLICATION','Explicit public generation CAS and bounded batch required');
  for(const u of upserts) {
    if(!exact(u,['id','kind','metadata','body','searchText','supersedes']) || !(u.supersedes===null || refValid(u.supersedes)))fail('INVALID_RESEARCH_RECORD','Invalid public record input');
    validateMetadata(u.kind,u.metadata,{kind:'public'});
    validateRecord({schema:'ig5-research-record-v2',id:u.id,kind:u.kind,scope:{kind:'public'},metadata:u.metadata,body:describeBody(u.body),searchText:u.searchText},{kind:'public'});
  }
  for(const w of withdrawals)if(!exact(w,['ref','reason','replacementRef']) || !refValid(w.ref) || !text(w.reason,512) || !(w.replacementRef===null || refValid(w.replacementRef)))fail('INVALID_RESEARCH_WITHDRAWAL','Invalid withdrawal');
  const inspect=()=>{
    const legacy=readLegacyKnowledge(projectRoot,{fingerprint:true}),catalog=legacy.bytes?validateKnowledgeCatalog(legacy.data):{cards:[],documents:[]};
    const oldIds=new Set([...knowledgeSeeds,...catalog.cards,...catalog.documents].map(x=>x.id));
    if(upserts.some(u=>oldIds.has(u.id)))fail('KNOWLEDGE_ID_CONFLICT','v2 cannot override a frozen v1 or bundled identity');
    const current=publicResearchStore(projectRoot).current();if(current.generation!==expectedGeneration)fail('STALE_RESEARCH_GENERATION','Inspect current generation before publishing');
    return legacy;
  };
  if(validateOnly){inspect();return {schema:'ig5-public-research-validation-v2',inputAndCasValid:true,publicationConflictsAndQuotaChecked:false,generationSaved:false,compatibilityFenceSaved:false};}
  const dir=path.join(path.resolve(projectRoot),'knowledge-v1');assertKnowledgePath(dir);fs.mkdirSync(dir,{recursive:true});assertKnowledgePath(dir);
  const lockFile=path.join(dir,'import.lock'),owner=randomUUID();let lock;
  try{lock=fs.openSync(lockFile,'wx');}catch(error){if(error.code==='EEXIST')fail('KNOWLEDGE_IMPORT_BUSY','v1/v2 compatibility lock exists; preserve it');throw error;}
  let fenced=false,primary=null,receipt=null;
  try {
    fs.writeFileSync(lock,JSON.stringify({owner,pid:process.pid}));fs.fsyncSync(lock);
    const legacy=inspect(),legacySha=writeKnowledgeFence(projectRoot,legacy);fenced=true;
    receipt=publicResearchStore(projectRoot).publish({expectedGeneration,upserts,withdrawals});
    return {...receipt,compatibilityFenceSaved:true,legacyCatalogSha256:legacySha};
  }catch(error){primary=error;Object.assign(error,{compatibilityFenceSaved:fenced});throw error;}
  finally {
    try {
      const own=fs.fstatSync(lock),current=fs.lstatSync(lockFile),content=JSON.parse(decodeKnowledgeText(readKnowledgeBytes(lockFile,1024)));
      if(current.dev!==own.dev || current.ino!==own.ino || content.owner!==owner)fail('RESEARCH_CLEANUP_UNCONFIRMED','Compatibility lock identity changed');
      fs.closeSync(lock);lock=null;fs.unlinkSync(lockFile);
    }catch(error){if(lock!==null)fs.closeSync(lock);if(primary)Object.assign(primary,{cleanupConfirmed:false});else{Object.assign(error,{generationSaved:receipt?.generationSaved || false,publishedGeneration:receipt?.generation || null,compatibilityFenceSaved:fenced,cleanupConfirmed:false});throw error;}}
  }
}
