import fs from 'node:fs';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {readKnowledgeBytes,decodeKnowledgeText,knowledgeHash as hash,knowledgeFail as fail,assertKnowledgePath} from './knowledge_io.js';
import {exact,digest} from './research_v2_contract.js';

export function readLegacyKnowledge(projectRoot,{fingerprint=false}={}) {
  const dir=path.join(path.resolve(projectRoot),'knowledge-v1'),file=path.join(dir,'catalog.json');
  const raw=readKnowledgeBytes(file,1048576,true);if(!raw)return {bytes:null,data:null,fenced:false,catalogSha256:'absent'};
  let value;try{value=JSON.parse(decodeKnowledgeText(raw));}catch{fail('INVALID_KNOWLEDGE_FILE','Legacy catalog is invalid UTF-8 JSON');}
  if(value?.schema!=='ig5-knowledge-compat-fence-v2')return {bytes:raw,data:value,fenced:false,catalogSha256:fingerprint?hash(raw):null};
  if(!exact(value,['schema','legacyCatalogSha256']) || !digest(value.legacyCatalogSha256))fail('INVALID_KNOWLEDGE_FILE','Invalid compatibility fence');
  const bytes=readKnowledgeBytes(path.join(dir,'history',value.legacyCatalogSha256+'.json'),1048576);
  if(hash(bytes)!==value.legacyCatalogSha256)fail('KNOWLEDGE_HISTORY_CONFLICT','Frozen v1 catalog digest mismatch');
  let data;try{data=JSON.parse(decodeKnowledgeText(bytes));}catch{fail('INVALID_KNOWLEDGE_FILE','Frozen v1 catalog is invalid JSON');}
  return {bytes,data,fenced:true,catalogSha256:fingerprint?hash(raw):null,legacyCatalogSha256:value.legacyCatalogSha256};
}

// Caller holds the original v1 import.lock and has validated the legacy bytes.
export function writeKnowledgeFence(projectRoot,previous) {
  if(previous.fenced)return previous.legacyCatalogSha256;
  const dir=path.join(path.resolve(projectRoot),'knowledge-v1'),file=path.join(dir,'catalog.json');
  assertKnowledgePath(dir);fs.mkdirSync(path.join(dir,'history'),{recursive:true});assertKnowledgePath(dir);
  const legacy=previous.bytes || Buffer.from(JSON.stringify({schema:'ig5-knowledge-catalog-v1',cards:[],documents:[]})),sha=hash(legacy),history=path.join(dir,'history',sha+'.json');
  const existing=readKnowledgeBytes(history,1048576,true);
  if(existing && hash(existing)!==sha)fail('KNOWLEDGE_HISTORY_CONFLICT','History content address changed');
  if(!existing){const fd=fs.openSync(history,'wx');try{fs.writeFileSync(fd,legacy);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
  const current=readKnowledgeBytes(file,1048576,true);
  if((current?hash(current):'absent')!==previous.catalogSha256)fail('STALE_KNOWLEDGE_CATALOG','v1 changed before compatibility fence');
  const stage=path.join(dir,'.compat-'+randomUUID()+'.stage'),fd=fs.openSync(stage,'wx');
  try{fs.writeFileSync(fd,JSON.stringify({schema:'ig5-knowledge-compat-fence-v2',legacyCatalogSha256:sha}));fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
  assertKnowledgePath(dir);fs.renameSync(stage,file);return sha;
}
