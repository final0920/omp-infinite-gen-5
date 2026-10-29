// Explicit offline maintenance entry. Never fetches URLs or executes source content.
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {publishPublicKnowledgeV2} from '../source/knowledge_publish_v2.js';
import {readKnowledgeBytes,decodeKnowledgeText,knowledgeHash as hash,knowledgeFail as fail} from '../source/knowledge_io.js';
import {exact,digest,RESEARCH_V2_LIMITS} from '../source/research_v2_contract.js';

export function main(argv) {
  const options={};
  for(let i=0;i<argv.length;i++) {
    const arg=argv[i];if(arg==='--validate-only'){if(options.validateOnly)fail('INVALID_ARGUMENT','Duplicate flag');options.validateOnly=true;continue;}
    const names={'--manifest':'manifest','--input-root':'inputRoot','--project-root':'projectRoot','--expected-generation':'expectedGeneration'};
    if(!names[arg] || options[names[arg]]!==undefined || !argv[i+1] || argv[i+1].startsWith('--'))fail('INVALID_ARGUMENT','Use --manifest FILE --input-root DIR --project-root DIR --expected-generation absent|HASH [--validate-only]');
    options[names[arg]]=argv[++i];
  }
  for(const key of ['manifest','inputRoot','projectRoot'])if(typeof options[key]!=='string' || !path.isAbsolute(options[key]))fail('INVALID_ARGUMENT','Explicit absolute paths required');
  const raw=readKnowledgeBytes(options.manifest,RESEARCH_V2_LIMITS.indexBytes),manifest=JSON.parse(decodeKnowledgeText(raw));
  if(!exact(manifest,['schema','upserts','withdrawals']) || manifest.schema!=='ig5-public-research-import-v2' || !Array.isArray(manifest.upserts) || manifest.upserts.length>256 || !Array.isArray(manifest.withdrawals))fail('INVALID_RESEARCH_PUBLICATION','Invalid explicit v2 manifest');
  const upserts=manifest.upserts.map(item=>{
    if(!exact(item,['id','kind','metadata','bodyPath','bodySha256','searchText','supersedes']) || typeof item.bodyPath!=='string' || !/\.(md|txt)$/i.test(item.bodyPath) || item.bodyPath.includes('\\') || item.bodyPath.includes(':') || item.bodyPath.startsWith('/') || item.bodyPath.split('/').some(p=>!p || p==='.' || p==='..') || !digest(item.bodySha256))fail('INVALID_RESEARCH_RECORD','Use relative text path and exact reviewed body SHA');
    const bodyBytes=readKnowledgeBytes(path.join(options.inputRoot,item.bodyPath),RESEARCH_V2_LIMITS.bodyBytes);
    if(hash(bodyBytes)!==item.bodySha256)fail('IMPORT_CONTENT_MISMATCH','Body bytes changed after review');
    const {bodyPath,bodySha256,...record}=item;return {...record,body:decodeKnowledgeText(bodyBytes)};
  });
  return {...publishPublicKnowledgeV2({projectRoot:options.projectRoot,expectedGeneration:options.expectedGeneration,upserts,withdrawals:manifest.withdrawals,validateOnly:options.validateOnly || false}),manifestSha256:hash(raw)};
}
if(process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  try{console.log(JSON.stringify(main(process.argv.slice(2)),null,2));}
  catch(error){console.error(JSON.stringify({code:error.code || 'RESEARCH_PUBLICATION_FAILED',message:error.message,generationSaved:error.generationSaved || false,publishedGeneration:error.publishedGeneration || null,compatibilityFenceSaved:error.compatibilityFenceSaved || false,cleanupConfirmed:error.cleanupConfirmed ?? null}));process.exitCode=1;}
}
