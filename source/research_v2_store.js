import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { assertKnowledgePath, readKnowledgeBytes, decodeKnowledgeText, knowledgeHash as hash, knowledgeFail as fail } from './knowledge_io.js';
import { RESEARCH_V2_LIMITS as limits, validateScope, scopeKey, validateMetadata, validateRecord, validateSnapshot, describeBody, exact, refValid, sameRef, text, digest } from './research_v2_contract.js';

const json = value => Buffer.from(JSON.stringify(value));
const captures = new WeakMap();
const freezeTree = value => {if(value && typeof value==='object'){Object.values(value).forEach(freezeTree);Object.freeze(value);}return value;};
const capture = (store,value) => {freezeTree(value);captures.get(store).add(value);return value;};
const parse = bytes => {try{return JSON.parse(decodeKnowledgeText(bytes));}catch(error){if(error.code)throw error;fail('INVALID_RESEARCH_JSON','Research data must be strict UTF-8 JSON');}};
function assertRoot(root) {assertKnowledgePath(root);if(fs.existsSync(root) && !fs.lstatSync(root).isDirectory())fail('INVALID_RESEARCH_ROOT','Research root must be a directory');}

/** Immutable shards and generations, one atomic pointer. No host routes or execution. */
export class ResearchV2Store {
  constructor({root,scope}) {
    if(typeof root!=='string' || !path.isAbsolute(root))fail('INVALID_RESEARCH_ROOT','Explicit absolute research root required');
    this.root=path.resolve(root);this.scope=freezeTree(validateScope(scope));this.scopeDigest=scopeKey(this.scope);captures.set(this,new WeakSet());
  }
  _file(kind,sha) {if(!['chunks','records','generations'].includes(kind) || !digest(sha))fail('INVALID_RESEARCH_REF','Invalid content address');return path.join(this.root,kind,sha+(kind==='chunks'?'.txt':'.json'));}
  current() {
    const raw=readKnowledgeBytes(path.join(this.root,'CURRENT.json'),4096,true);
    if(!raw)return capture(this,{generation:'absent',snapshot:null});
    const pointer=parse(raw);
    if(!exact(pointer,['schema','scopeDigest','generation']) || pointer.schema!=='ig5-research-pointer-v2' || pointer.scopeDigest!==this.scopeDigest || !digest(pointer.generation))fail('RESEARCH_SCOPE_MISMATCH','Pointer belongs to another context or unsupported format');
    const bytes=readKnowledgeBytes(this._file('generations',pointer.generation),limits.indexBytes);
    if(hash(bytes)!==pointer.generation)fail('RESEARCH_DIGEST_MISMATCH','Generation bytes changed');
    return capture(this,{generation:pointer.generation,snapshot:validateSnapshot(parse(bytes),this.scope)});
  }
  read(ref,snapshot=this.current()) {
    if(!refValid(ref))fail('INVALID_RESEARCH_REF','Exact published reference required');
    if(!captures.get(this).has(snapshot) || !snapshot.snapshot || scopeKey(snapshot.snapshot.scope)!==this.scopeDigest || !snapshot.snapshot.entries.some(e=>sameRef(e.ref,ref)))fail('RESEARCH_REF_MISMATCH','Reference was not published in this exact project context');
    const entry=snapshot.snapshot.entries.find(e=>sameRef(e.ref,ref));
    const bytes=readKnowledgeBytes(this._file('records',ref.sha256),limits.recordBytes);
    if(hash(bytes)!==ref.sha256)fail('RESEARCH_DIGEST_MISMATCH','Record bytes changed');
    const record=validateRecord(parse(bytes),this.scope);
    if(record.id!==ref.id || record.kind!==entry.kind || record.body.sha256!==entry.bodySha256 || JSON.stringify(record.metadata)!==JSON.stringify(entry.metadata) || record.searchText!==entry.searchText)fail('RESEARCH_DIGEST_MISMATCH','Index and record disagree');
    const parts=record.body.chunks.map(c=>{const b=readKnowledgeBytes(this._file('chunks',c.sha256),limits.chunkBytes);if(b.length!==c.bytes || hash(b)!==c.sha256)fail('RESEARCH_DIGEST_MISMATCH','Body shard changed');return b;});
    const bodyBytes=Buffer.concat(parts),body=decodeKnowledgeText(bodyBytes);
    if(bodyBytes.length!==record.body.bytes || hash(bodyBytes)!==record.body.sha256 || JSON.stringify(describeBody(body))!==JSON.stringify(record.body))fail('RESEARCH_DIGEST_MISMATCH','Full body or exact paragraph index changed');
    return {record,body,entry,generation:snapshot.generation,semanticVerified:false};
  }
  _put(kind,bytes) {
    const sha=hash(bytes),file=this._file(kind,sha),max=kind==='chunks'?limits.chunkBytes:kind==='records'?limits.recordBytes:limits.indexBytes;
    if(bytes.length>max)fail('RESEARCH_PUBLICATION_LIMIT','Immutable object exceeds its limit');
    assertRoot(path.dirname(file));fs.mkdirSync(path.dirname(file),{recursive:true});assertRoot(path.dirname(file));
    const prior=readKnowledgeBytes(file,max,true);
    if(prior) {if(hash(prior)!==sha)fail('RESEARCH_DIGEST_MISMATCH','Existing immutable content address is corrupt');return sha;}
    const stage=path.join(path.dirname(file),'.'+randomUUID()+'.stage');
    const fd=fs.openSync(stage,'wx');
    try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
    // Cooperative writers hold the store lock; never replace an existing history object.
    if(fs.existsSync(file))fail('RESEARCH_HISTORY_CONFLICT','Content appeared during publication');
    fs.renameSync(stage,file);return sha;
  }
  _usage() {
    let bytes=0,files=0,visited=0;
    const walk=(dir,depth=0)=>{if(depth>2)fail('RESEARCH_STORE_LIMIT','Unexpected nested research directory');assertRoot(dir);const directory=fs.opendirSync(dir);try{for(let item;(item=directory.readSync())!==null;) {
      if(++visited>limits.storeFiles)fail('RESEARCH_STORE_LIMIT','Research directory entry budget exceeded');
      const name=path.join(dir,item.name),stat=fs.lstatSync(name);
      if(stat.isSymbolicLink() || stat.isFile() && stat.nlink!==1)fail('KNOWLEDGE_LINK_REJECTED','Research quota includes only owned non-linked paths');
      if(stat.isDirectory())walk(name,depth+1);else if(stat.isFile()){bytes+=stat.size;files++;}else fail('INVALID_RESEARCH_FILE','Unknown research path type');
      if(bytes>limits.storeBytes || files>limits.storeFiles)fail('RESEARCH_STORE_LIMIT','Store quota includes histories and abandoned stages; no automatic deletion');
    }}finally{directory.closeSync();}};
    if(fs.existsSync(this.root))walk(this.root);return {bytes,files};
  }
  publish({expectedGeneration,upserts=[],withdrawals=[]}) {
    if(!(expectedGeneration==='absent' || digest(expectedGeneration)) || !Array.isArray(upserts) || !Array.isArray(withdrawals) || upserts.length+withdrawals.length<1 || upserts.length+withdrawals.length>limits.entries)fail('INVALID_RESEARCH_PUBLICATION','Bounded explicit CAS publication required');
    // Validate all caller values before creating any persistent files.
    const prepared=upserts.map(item=>{
      if(!exact(item,['id','kind','metadata','body','searchText','supersedes']) || typeof item.id!=='string' || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(item.id) || !text(item.searchText,4096) || !(item.supersedes===null || refValid(item.supersedes)))fail('INVALID_RESEARCH_RECORD','Explicit record metadata, body, search summary and supersession required');
      validateMetadata(item.kind,item.metadata,this.scope);
      const body=describeBody(item.body),record=validateRecord({schema:'ig5-research-record-v2',id:item.id,kind:item.kind,scope:this.scope,metadata:item.metadata,body,searchText:item.searchText},this.scope);
      return {record,body:item.body,supersedes:item.supersedes};
    });
    if(new Set(prepared.map(p=>p.record.id)).size!==prepared.length)fail('RESEARCH_ID_CONFLICT','Duplicate identity in publication');
    for(const w of withdrawals)if(!exact(w,['ref','reason','replacementRef']) || !refValid(w.ref) || !text(w.reason,512) || !(w.replacementRef===null || refValid(w.replacementRef)))fail('INVALID_RESEARCH_WITHDRAWAL','Exact withdrawal reference, reason and replacement required');
    assertRoot(this.root);fs.mkdirSync(this.root,{recursive:true});assertRoot(this.root);
    const lockFile=path.join(this.root,'publish.lock'),owner=randomUUID();
    let lock;try{lock=fs.openSync(lockFile,'wx');}catch(error){if(error.code==='EEXIST')fail('RESEARCH_PUBLISH_BUSY','Publication lock exists; no automatic reclamation');throw error;}
    let saved=false,published=null,primary=null,stage=null;
    try {
      fs.writeFileSync(lock,json({owner,pid:process.pid,scopeDigest:this.scopeDigest}));fs.fsyncSync(lock);
      const before=this.current();if(before.generation!==expectedGeneration)fail('STALE_RESEARCH_GENERATION','Generation changed; inspect before retrying');
      const entries=structuredClone(before.snapshot?.entries || []),pending=[];
      for(const p of prepared) {
        const sha=hash(json(p.record)),ref={id:p.record.id,sha256:sha},existing=entries.find(e=>e.state==='active' && e.ref.id===ref.id);
        if(existing && sameRef(existing.ref,ref)) {if(p.supersedes!==null && !sameRef(p.supersedes,existing.ref))fail('RESEARCH_SUPERSESSION_MISMATCH','Unchanged record has an unrelated supersession');continue;}
        if(existing) {if(!sameRef(p.supersedes,existing.ref))fail('RESEARCH_SUPERSESSION_MISMATCH','Changed identity requires its exact current reference');existing.state='superseded';existing.reason='explicit-version-replacement';existing.replacementRef=ref;}
        else if(p.supersedes!==null)fail('RESEARCH_SUPERSESSION_MISMATCH','Supersession requires a current active version');
        if(entries.some(e=>sameRef(e.ref,ref)))fail('RESEARCH_HISTORY_CONFLICT','Withdrawn/superseded bytes cannot be silently reactivated');
        entries.push({ref,kind:p.record.kind,metadata:p.record.metadata,searchText:p.record.searchText,bodySha256:p.record.body.sha256,state:'active',reason:null,replacementRef:null});pending.push(p);
      }
      for(const w of withdrawals) {
        const entry=entries.find(e=>sameRef(e.ref,w.ref));if(!entry || entry.state!=='active')fail('RESEARCH_REF_MISMATCH','Only an exact active reference can be withdrawn');
        entry.state='withdrawn';entry.reason=w.reason;entry.replacementRef=w.replacementRef;
      }
      if((before.snapshot?.revision ?? -1)>=Number.MAX_SAFE_INTEGER)fail('RESEARCH_REVISION_OVERFLOW','Generation revision cannot advance');
      const snapshot=validateSnapshot({schema:'ig5-research-generation-v2',scope:this.scope,parent:before.generation==='absent'?null:before.generation,revision:(before.snapshot?.revision ?? -1)+1,publishedAt:new Date().toISOString(),entries},this.scope);
      const manifest=json(snapshot);if(manifest.length>limits.indexBytes)fail('RESEARCH_PUBLICATION_LIMIT','Generation metadata exceeds v2 limit');
      const usage=this._usage();
      const reservation=manifest.length+4096+pending.reduce((n,p)=>n+Buffer.byteLength(p.body)+json(p.record).length,0);
      if(usage.bytes+reservation>limits.storeBytes || usage.files+pending.reduce((n,p)=>n+p.record.body.chunks.length+1,2)>limits.storeFiles)fail('RESEARCH_STORE_LIMIT','Publication exceeds retained-store quota');
      for(const p of pending) {
        const bytes=Buffer.from(p.body);let offset=0;
        for(const chunk of p.record.body.chunks){this._put('chunks',bytes.subarray(offset,offset+chunk.bytes));offset+=chunk.bytes;}
        this._put('records',json(p.record));
      }
      published=this._put('generations',manifest);
      // Re-read every reference before publishing; previous histories must remain readable too.
      const candidate=capture(this,{generation:published,snapshot});for(const e of snapshot.entries)this.read(e.ref,candidate);
      if(this.current().generation!==before.generation)fail('STALE_RESEARCH_GENERATION','Pointer changed during publication');
      const pointer=json({schema:'ig5-research-pointer-v2',scopeDigest:this.scopeDigest,generation:published});
      stage=path.join(this.root,'.CURRENT-'+owner+'.stage');const fd=fs.openSync(stage,'wx');try{fs.writeFileSync(fd,pointer);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
      assertRoot(this.root);fs.renameSync(stage,path.join(this.root,'CURRENT.json'));stage=null;saved=true;
      return {schema:'ig5-research-publish-receipt-v2',previousGeneration:before.generation,generation:published,generationSaved:true,cleanupConfirmed:true,records:snapshot.entries.length,executionAuthorized:false};
    } catch(error){primary=error;Object.assign(error,{generationSaved:saved,publishedGeneration:saved?published:null});throw error;}
    finally {
      try {
        if(stage) {const st=fs.lstatSync(stage);if(!st.isFile() || st.isSymbolicLink() || st.nlink!==1)fail('RESEARCH_CLEANUP_UNCONFIRMED','Pointer stage changed');fs.unlinkSync(stage);}
        const current=fs.lstatSync(lockFile),own=fs.fstatSync(lock),content=parse(readKnowledgeBytes(lockFile,1024));
        if(current.dev!==own.dev || current.ino!==own.ino || content.owner!==owner)fail('RESEARCH_CLEANUP_UNCONFIRMED','Publication lock ownership changed');
        fs.closeSync(lock);lock=null;fs.unlinkSync(lockFile);
      } catch(error){if(lock!==null)fs.closeSync(lock);if(primary)Object.assign(primary,{cleanupConfirmed:false,cleanupError:error.code || 'RESEARCH_CLEANUP_UNCONFIRMED'});else{Object.assign(error,{generationSaved:saved,publishedGeneration:saved?published:null,cleanupConfirmed:false});throw error;}}
    }
  }
}
