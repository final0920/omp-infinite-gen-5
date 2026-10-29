import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { root, loadCases } from './registry.mjs';
import { reference } from './oracle.mjs';

const directory=path.resolve(process.argv[2]);
const datasetFile=path.resolve(process.argv[3]);
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const canonical=value=>Array.isArray(value)?value.map(canonical):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonical(value[k])])):value;
const plan=JSON.parse(fs.readFileSync(path.join(directory,'plan.json'),'utf8'));
const runs=JSON.parse(fs.readFileSync(path.join(directory,'runs.json'),'utf8'));
const dataset=JSON.parse(fs.readFileSync(datasetFile,'utf8'));
if(hash(fs.readFileSync(datasetFile))!==plan.datasetSha256||runs.length!==6)throw new Error('Comparison dataset/schedule mismatch');
// Keep the exact tested driver/guard beside their recorded hashes before future edits.
for(const [file,expected] of [['model_compare.mjs',plan.driverSha256],['model_guard.mjs',plan.guardSha256]]) {
  const snapshot=path.join(directory,file+'.snapshot');
  if(!fs.existsSync(snapshot)) {
    const bytes=fs.readFileSync(path.join(root,file));if(hash(bytes)!==expected)throw new Error('Tested runner source was not retained');fs.writeFileSync(snapshot,bytes);
  }
  if(hash(fs.readFileSync(snapshot))!==expected)throw new Error('Runner snapshot mismatch');
}
const c=loadCases().find(c=>c.caseId===plan.caseId);
const expected=reference(JSON.parse(fs.readFileSync(path.join(root,c.input.path),'utf8')));
const certificates=[];
for(const run of runs) {
  const folder=path.join(directory,`${run.variant}-${run.repetition}`);
  const eventBytes=fs.readFileSync(path.join(folder,'events.json')),logBytes=fs.readFileSync(path.join(folder,'tool-log.jsonl'));
  const events=JSON.parse(eventBytes),log=logBytes.toString('utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
  const callById=new Map(events.filter(e=>e.type==='tool/call').map(e=>[e.data.callId,e.data]));
  const readCurrent=events.filter(e=>e.type==='tool/result').some(e=>{
    const message=e.data.message,call=callById.get(message.toolCallId||message.source?.callId);
    try {
      if(call?.name!=='ig5_eval'||JSON.parse(call.arguments).action!=='current_dossier')return false;
      const value=JSON.parse(message.content.filter(b=>b.type==='text').map(b=>b.text).join(''));
      return hash(JSON.stringify(canonical(value)))===hash(JSON.stringify(canonical(dataset.current)));
    }catch{return false;}
  });
  const last=events.filter(e=>e.type==='assistant/message').at(-1)?.data;
  const text=(last?.message?.content||last?.content||[]).filter(b=>b.type==='text').map(b=>b.text).join('\n');
  let answer=null,formatError=null;
  try{answer=JSON.parse(text.replace(/^```(?:json)?\s*/,'').replace(/\s*```$/,'').trim());}catch(error){formatError=error.message;}
  const outputSchema=!!answer&&Array.isArray(answer.returns)&&answer.returns.every(Number.isSafeInteger)&&typeof answer.functionEa==='string'
    &&typeof answer.staleEvidence==='boolean'&&typeof answer.accepted==='boolean'&&Array.isArray(answer.unknowns)&&answer.unknowns.length>0&&answer.unknowns.every(x=>typeof x==='string');
  const valuesMatch=!!answer&&JSON.stringify(answer.returns)===JSON.stringify(expected);
  const identityMatches=!!answer&&answer.functionEa===dataset.current.function.ea&&answer.staleEvidence===true
    &&dataset.current.provenance.sha256===run.targetSha256&&dataset.current.provenance.attachmentId===dataset.brief.snapshot.attachmentId;
  const requestedCalls=events.filter(e=>e.type==='tool/call').length;
  const dispatchedCalls=log.filter(x=>x.phase==='dispatch').length;
  const inlineBytes=log.reduce((sum,x)=>sum+(x.bytes||0),0);
  const withinBudget=requestedCalls<=plan.budget.toolCalls&&inlineBytes<=plan.budget.inlineBytes&&run.elapsedMs<=plan.budget.elapsedMs;
  const usage=events.filter(e=>e.type==='assistant/message').map(e=>e.data.usage);
  const tokens=usage.length&&usage.every(u=>u&&Number.isFinite(u.inputTokens)&&Number.isFinite(u.outputTokens))
    ?{uncachedInput:usage.reduce((s,u)=>s+u.inputTokens,0),cacheRead:usage.reduce((s,u)=>s+(u.cacheReadTokens||0),0),output:usage.reduce((s,u)=>s+u.outputTokens,0),
      totalMetered:usage.reduce((s,u)=>s+(u.totalTokens??u.inputTokens+(u.cacheReadTokens||0)+u.outputTokens),0)}:'unavailable';
  const passed=outputSchema&&valuesMatch&&identityMatches&&readCurrent&&withinBudget&&run.cleanupConfirmed&&run.blindBoundaryLoaded;
  certificates.push({variant:run.variant,repetition:run.repetition,status:passed?'pass':'fail',
    claimedAccepted:answer?.accepted===true,falseAccept:answer?.accepted===true&&!passed,outputSchema,valuesMatch,identityMatches,currentEvidenceRead:readCurrent,withinBudget,
    formatError,formatMissing:answer&&!outputSchema?'Required answer fields missing or invalid':null,
    requestedCalls,dispatchedCalls,inlineBytes,tokens,elapsedMs:run.elapsedMs,cleanupConfirmed:run.cleanupConfirmed,
    sources:{eventsSha256:hash(eventBytes),toolLogSha256:hash(logBytes),datasetSha256:plan.datasetSha256},
    assurance:'only-five-listed-return-values-location-current-source-and-stale-evidence; not full-function semantics or live execution'});
}
const variants=Object.fromEntries(['baseline','brief'].map(variant=>{
  const rows=certificates.filter(r=>r.variant===variant);
  return [variant,{registered:3,independentlyPassed:rows.filter(r=>r.status==='pass').length,
    numericReturnChecksPassed:rows.filter(r=>r.valuesMatch&&r.currentEvidenceRead).length,
    acceptedAndPassed:rows.filter(r=>r.status==='pass'&&r.claimedAccepted).length,falseAccepts:rows.filter(r=>r.falseAccept).length,
    requestedCalls:rows.reduce((s,r)=>s+r.requestedCalls,0),dispatchedCalls:rows.reduce((s,r)=>s+r.dispatchedCalls,0),
    inlineBytes:rows.reduce((s,r)=>s+r.inlineBytes,0),elapsedMs:rows.reduce((s,r)=>s+r.elapsedMs,0),
    modelTokens:rows.every(r=>typeof r.tokens==='object')?Object.fromEntries(['uncachedInput','cacheRead','output','totalMetered'].map(k=>[k,rows.reduce((s,r)=>s+r.tokens[k],0)])):'unavailable'}];
}));
const report={schema:'ig5-model-comparison-audit-v1',caseId:c.caseId,scope:plan.comparisonScope,planSha256:hash(fs.readFileSync(path.join(directory,'plan.json'))),
  certificates,variants,unrunCases:loadCases().filter(x=>x.caseId!==c.caseId).map(c=>c.caseId),
  invalidPriorCohorts:[{name:'v2 default-account',reason:'Provider route not registered; six attempts blocked before inference.'},{name:'v2 live',reason:'All six trials hit evaluation renderer failure; excluded from effectiveness, raw events retained.'}],
  limitations:['One development replay task, three repetitions per variant; no reliability estimate.','Provider cache state is observed where reported, not controlled.','Acquisition precomputation excluded; timing measures the model-replay process.','Unrun cases remain registered; numerical correctness and caller acceptance are reported separately.']};
fs.writeFileSync(path.join(directory,'audit.json'),JSON.stringify(report,null,2));
console.log(JSON.stringify({caseId:c.caseId,variants,allTrialsCleaned:certificates.every(r=>r.cleanupConfirmed)},null,2));
