import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {performance} from 'node:perf_hooks';
import {runKnowledge} from '../source/knowledge_catalog.js';
import {readLegacyKnowledge} from '../source/knowledge_v2_compat.js';
const [baselineFile,projectRoot,output]=process.argv.slice(2);
if(![baselineFile,projectRoot,output].every(p=>p && path.isAbsolute(p)))throw Error('Use absolute BASELINE_CATALOG_MODULE PROJECT_ROOT NEW_JSON_OUTPUT');
const baseline=(await import(pathToFileURL(baselineFile).href)).runKnowledge;
const percentile=(values,p)=>[...values].sort((a,b)=>a-b)[Math.min(values.length-1,Math.floor(values.length*p))];
function measure(run,cfg,input) {for(let i=0;i<30;i++)run(cfg,input);const samples=[];let result;for(let i=0;i<250;i++){const start=performance.now();result=run(cfg,input);samples.push(performance.now()-start);}return {medianMs:percentile(samples,.5),p95Ms:percentile(samples,.95),returnedBytes:Buffer.byteLength(JSON.stringify(result))};}
const rounds=[];for(let r=0;r<5;r++){
  const entry={};for(const name of (r%2?['v2-code','v1-code']:['v1-code','v2-code']))entry[name]=measure(name==='v1-code'?baseline:runKnowledge,{projectRoot},{action:'search',query:'MBA'});rounds.push(entry);
}
const legacy=readLegacyKnowledge(projectRoot).bytes;
const result={schema:'ig5-f02-query-cost-v1',environment:{node:process.version,platform:process.platform},scope:'local warm-cache explicit-query timing; not model benefit or a formal latency non-inferiority trial',sameLegacyCatalogBytes:legacy?.length || 0,rounds,off:{baseline:measure(baseline,{knowledge:false},{action:'status'}),current:measure(runKnowledge,{knowledge:false},{action:'status'})},memory:process.memoryUsage(),v2FullCorpusBenefitMeasured:false,assistAllowed:false};
fs.writeFileSync(output,JSON.stringify(result,null,2),{flag:'wx'});console.log(JSON.stringify(result,null,2));
