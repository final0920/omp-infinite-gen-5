import { knowledgeHash as hash, knowledgeFail as fail } from './knowledge_io.js';
import { planningDigest } from './planning_identity.js';
import { safeResearchUrl } from './knowledge_documents.js';

export const RESEARCH_V2_LIMITS = Object.freeze({ indexBytes: 1048576, entries: 256, recordBytes: 65536, bodyBytes: 262144, chunkBytes: 16384, paragraphs: 1024, storeBytes: 67108864, storeFiles: 16384 });
export const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype && Object.values(Object.getOwnPropertyDescriptors(v)).every(d=>'value' in d);
export const digest = v => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
export const text = (v,n=1024) => typeof v === 'string' && !!v.trim() && v.length<=n && !v.includes('\0') && Buffer.from(v).toString('utf8')===v;
export const exact = (v,keys) => plain(v) && Object.keys(v).sort().join(',') === [...keys].sort().join(',');
export const refValid = v => exact(v,['id','sha256']) && typeof v.id==='string' && /^[a-z0-9][a-z0-9-]{0,63}$/.test(v.id) && digest(v.sha256);
export const sameRef = (a,b) => !!a && !!b && a.id===b.id && a.sha256===b.sha256;
const integer = v => Number.isSafeInteger(v) && !Object.is(v,-0) && v>=0;
export const isoDate = v => {try{return typeof v==='string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(v) && new Date(v).toISOString()===v;}catch{return false;}};
export const stringList = (v,n=16,width=512,empty=false) => Array.isArray(v) && v.length<=(n) && (empty || v.length>0) && v.every(x=>text(x,width)) && new Set(v).size===v.length;

export function validateScope(scope) {
  if(exact(scope,['kind']) && scope.kind==='public')return {kind:'public'};
  const keys=['kind','projectId','artifactSha256','engine','provider','attachmentId','dbRevision','taskId','taskRevision','contractDigest','runId','moduleEpoch'];
  if(!exact(scope,keys) || scope.kind!=='private' || !digest(scope.artifactSha256) || !digest(scope.contractDigest)
    || ['projectId','engine','provider','attachmentId','taskId'].some(k=>!text(scope[k],128)) || !integer(scope.dbRevision) || !integer(scope.taskRevision)
    || !(scope.runId===null && scope.moduleEpoch===null || text(scope.runId,128) && text(scope.moduleEpoch,128)))fail('INVALID_RESEARCH_SCOPE','Private research requires complete trusted context, revisions and paired run/epoch');
  return JSON.parse(JSON.stringify(scope));
}
export const scopeKey = scope => planningDigest(validateScope(scope));
export function validateSource(source,scope) {
  const keys=['type','url','author','publishedAt','retrievedAt','contentSha256','commit','parserVersion','license','rightsStatus','review','qualityReview','verificationLevel','correctionRefs','localRef'];
  if(!exact(source,keys) || !['git','web','paper','local-case'].includes(source.type) || !text(source.author,160) || !digest(source.contentSha256)
    || !isoDate(source.retrievedAt) || !(source.publishedAt===null || typeof source.publishedAt==='string' && /^\d{4}-\d{2}-\d{2}$/.test(source.publishedAt) && isoDate(source.publishedAt+'T00:00:00.000Z'))
    || !text(source.parserVersion,128) || !text(source.license,256) || !['original-notes-with-links','redistribution-permitted','local-reference-only','metadata-only'].includes(source.rightsStatus)
    || source.review!=='reviewed' || !['reference-only','reproduced-in-scope','unverified'].includes(source.verificationLevel)
    || !Array.isArray(source.correctionRefs) || source.correctionRefs.length>16 || source.correctionRefs.some(r=>!refValid(r)))fail('INVALID_RESEARCH_SOURCE','Invalid typed reviewed source');
  const q=source.qualityReview;
  if(!exact(q,['traceability','specificity','reproducibility','boundaries','relevance','reviewer','notes']) || [['traceability',2],['specificity',2],['reproducibility',3],['boundaries',2],['relevance',1]].some(([k,max])=>!integer(q[k]) || q[k]>max) || !text(q.reviewer,128) || !text(q.notes,512))fail('INVALID_RESEARCH_SOURCE','Explicit bounded quality review required; scores are not truth probabilities');
  if(source.type==='local-case') {
    if(scope.kind!=='private' || source.url!==null || source.commit!==null || !refValid(source.localRef))fail('RESEARCH_SCOPE_MISMATCH','Local cases are private, source-bound references');
  } else if(!safeResearchUrl(source.url) || source.localRef!==null || source.type==='git' && (typeof source.commit!=='string' || !/^[a-f0-9]{40}$/.test(source.commit) || !new URL(source.url).pathname.split('/').includes(source.commit)) || source.type!=='git' && source.commit!==null)
    fail('INVALID_RESEARCH_SOURCE','Source URL and exact git commit must agree; URLs are data, not fetch authorization');
  return JSON.parse(JSON.stringify(source));
}
export function validateMetadata(kind,metadata,scope) {
  const base=['title','tags','sources','reviewNotes','contentKind'];
  const method=['category','prerequisites','limitations','steps','verification','integration','relatedTools'];
  const document=['methodIds'];
  const fact=['caseId','subject','claim','status','observedAt','unknowns','supersedes','contradicts'];
  const extra=kind==='method'?method:kind==='document'?document:kind==='case-fact'?fact:null;
  if(!extra || !exact(metadata,[...base,...extra]) || !text(metadata.title,160) || !stringList(metadata.tags,16,128) || !stringList(metadata.reviewNotes,8)
    || !['original-note','licensed-text'].includes(metadata.contentKind) || !Array.isArray(metadata.sources) || !metadata.sources.length || metadata.sources.length>8)fail('INVALID_RESEARCH_RECORD','Invalid v2 record metadata');
  metadata.sources.forEach(s=>validateSource(s,scope));
  if(metadata.contentKind==='licensed-text' && metadata.sources.some(s=>!['redistribution-permitted','local-reference-only'].includes(s.rightsStatus) || /^unknown$/i.test(s.license)))fail('RESEARCH_RIGHTS_REQUIRED','Licensed text requires explicit reviewed rights; unknown rights permit metadata and original notes only');
  if(kind==='method' && (!['mba','control-flow','vm','workflow','homology','crypto'].includes(metadata.category) || ['prerequisites','limitations','steps','relatedTools'].some(k=>!stringList(metadata[k]))
    || metadata.relatedTools.some(x=>!/^ig5_[a-z_]+$/.test(x)) || !text(metadata.verification,1024) || !['research-only','existing-read-only-tools','available-reference'].includes(metadata.integration)))fail('INVALID_RESEARCH_RECORD','Invalid method-v2 conditions');
  if(kind==='document' && (!Array.isArray(metadata.methodIds) || metadata.methodIds.length>16 || metadata.methodIds.some(id=>typeof id!=='string' || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(id)) || new Set(metadata.methodIds).size!==metadata.methodIds.length))fail('INVALID_RESEARCH_RECORD','Invalid related methods');
  if(kind==='case-fact' && (scope.kind!=='private' || metadata.contentKind!=='original-note' || ['caseId','subject','claim','unknowns'].some(k=>!text(metadata[k],2048)) || !['reported','observed','contested','stale'].includes(metadata.status)
    || !isoDate(metadata.observedAt) || ['supersedes','contradicts'].some(k=>!Array.isArray(metadata[k]) || metadata[k].length>16 || metadata[k].some(r=>!refValid(r)))))fail('INVALID_RESEARCH_RECORD','Private facts cannot import verified status or incomplete provenance');
  return JSON.parse(JSON.stringify(metadata));
}
export function describeBody(body) {
  if(!text(body,RESEARCH_V2_LIMITS.bodyBytes) || Buffer.byteLength(body)>RESEARCH_V2_LIMITS.bodyBytes)fail('RESEARCH_BODY_LIMIT','Body exceeds v2 limit; explicit extraction/ranges required, never silent truncation');
  const bytes=Buffer.from(body),chunks=[];
  for(let offset=0;offset<bytes.length;) {
    let end=Math.min(offset+RESEARCH_V2_LIMITS.chunkBytes,bytes.length);
    while(end<bytes.length && (bytes[end]&0xc0)===0x80)end--;
    const part=bytes.subarray(offset,end);chunks.push({sha256:hash(part),bytes:part.length});offset=end;
  }
  const paragraphs=[...body.matchAll(/[\s\S]+?(?:\r?\n[ \t]*\r?\n|$)/g)].map((m,i)=>({id:'p'+(i+1),start:m.index,end:m.index+m[0].length,sha256:hash(m[0])}));
  if(paragraphs.length>RESEARCH_V2_LIMITS.paragraphs)fail('RESEARCH_BODY_LIMIT','Paragraph index exceeds v2 limit');
  return {sha256:hash(bytes),bytes:bytes.length,chunks,paragraphs};
}
export function validateRecord(record,scope) {
  if(!exact(record,['schema','id','kind','scope','metadata','body','searchText']) || record.schema!=='ig5-research-record-v2' || typeof record.id!=='string' || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(record.id)
    || scopeKey(record.scope)!==scopeKey(scope) || !text(record.searchText,4096))fail('RESEARCH_SCOPE_MISMATCH','Record identity or scope mismatch');
  validateMetadata(record.kind,record.metadata,scope);
  const b=record.body;
  if(!exact(b,['sha256','bytes','chunks','paragraphs']) || !digest(b.sha256) || !integer(b.bytes) || b.bytes<1 || b.bytes>RESEARCH_V2_LIMITS.bodyBytes || !Array.isArray(b.chunks) || !b.chunks.length || b.chunks.length>17
    || b.chunks.some(c=>!exact(c,['sha256','bytes']) || !digest(c.sha256) || !integer(c.bytes) || c.bytes<1 || c.bytes>RESEARCH_V2_LIMITS.chunkBytes) || b.chunks.reduce((s,c)=>s+c.bytes,0)!==b.bytes
    || !Array.isArray(b.paragraphs) || !b.paragraphs.length || b.paragraphs.length>RESEARCH_V2_LIMITS.paragraphs)fail('INVALID_RESEARCH_RECORD','Invalid body shard descriptor');
  let end=0;
  for(const [i,p] of b.paragraphs.entries()) {if(!exact(p,['id','start','end','sha256']) || p.id!=='p'+(i+1) || p.start!==end || !integer(p.end) || p.end<=p.start || p.end>b.bytes || !digest(p.sha256))fail('INVALID_RESEARCH_RECORD','Invalid exact paragraph reference');end=p.end;}
  if(Buffer.byteLength(JSON.stringify(record))>RESEARCH_V2_LIMITS.recordBytes)fail('RESEARCH_RECORD_LIMIT','Record metadata exceeds v2 limit');
  return JSON.parse(JSON.stringify(record));
}
export function validateSnapshot(value,scope) {
  if(!exact(value,['schema','scope','parent','revision','publishedAt','entries']) || value.schema!=='ig5-research-generation-v2' || scopeKey(value.scope)!==scopeKey(scope)
    || !(value.parent===null || digest(value.parent)) || !integer(value.revision) || !isoDate(value.publishedAt) || !Array.isArray(value.entries) || value.entries.length>RESEARCH_V2_LIMITS.entries)fail('INVALID_RESEARCH_GENERATION','Invalid generation or private context');
  const refs=new Set(),active=new Set();
  for(const e of value.entries) {
    if(!exact(e,['ref','kind','metadata','searchText','bodySha256','state','reason','replacementRef']) || !refValid(e.ref) || refs.has(e.ref.sha256) || !text(e.searchText,4096) || !digest(e.bodySha256)
      || !['active','superseded','withdrawn'].includes(e.state) || (e.state==='active'?e.reason!==null:e.reason===null || !text(e.reason,512)) || !(e.replacementRef===null || refValid(e.replacementRef)))fail('INVALID_RESEARCH_GENERATION','Invalid immutable reference or withdrawal state');
    validateMetadata(e.kind,e.metadata,scope);refs.add(e.ref.sha256);
    if(e.state==='active') {if(active.has(e.ref.id))fail('RESEARCH_ID_CONFLICT','Only one active version per identity');active.add(e.ref.id);}
  }
  for(const e of value.entries)if(e.replacementRef && !value.entries.some(x=>sameRef(x.ref,e.replacementRef)))fail('INVALID_RESEARCH_GENERATION','Replacement must be a published reference in this scope');
  for(const e of value.entries)if(e.kind==='case-fact' && [...e.metadata.supersedes,...e.metadata.contradicts].some(r=>!value.entries.some(x=>sameRef(x.ref,r))))fail('RESEARCH_REF_MISMATCH','Fact relationships cannot cross this private index scope');
  return JSON.parse(JSON.stringify(value));
}
