import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { root, loadCases } from './registry.mjs';
import { reference } from './oracle.mjs';

const hash = x => createHash('sha256').update(x).digest('hex');
const output = path.resolve(process.argv[2] || path.join(root,'../../../_research/ig5-eval-model-v2-20261021'));
const datasetPath = path.resolve(process.argv[3] || path.join(root,'../../../_research/ig5-eval-verified-v2-20261021/pilot-evidence.json'));
const provider = process.env.IG5_EVAL_PROVIDER || 'deepseek-account';
const model = process.env.IG5_EVAL_MODEL || 'deepseek-v4-flash';
const providerPatch = process.env.IG5_EVAL_PROVIDER_PATCH;
const electron = path.join(process.env.LOCALAPPDATA,'Programs/DeepSeek Harness/DeepSeek Harness.exe');
const cli = path.join(path.dirname(electron),'resources/app.asar/dsh/node_modules/@deepseek-ai/dsh-desktop-host/lib/cli.js');
fs.mkdirSync(output,{recursive:true});
const dataset = JSON.parse(fs.readFileSync(datasetPath,'utf8'));
const c = loadCases().find(c=>c.caseId===dataset.caseId);
const spec = JSON.parse(fs.readFileSync(path.join(root,c.input.path),'utf8'));
const expected = reference(spec);
// Same contract/prompt/model and budgets; only retrieval view changes.
const prompt = `这是一次只读调查恢复评测。${dataset.question}\n合同：${JSON.stringify(dataset.contract)}\n先读简报（若工具无brief则读task），仅回取必要证据；旧身份不能当作当前证据。不得执行目标或读取文件。最终仅输出合同约定的JSON，unknowns写清覆盖范围。`;
const plan = {schema:'ig5-model-comparison-plan-v1',caseId:c.caseId,variants:['baseline','brief'],repetitions:3,provider,model,
  datasetSha256:hash(fs.readFileSync(datasetPath)),promptSha256:hash(prompt),budget:c.budget,cacheCondition:'fresh-session; provider-side cache uncontrolled',
  driverSha256:hash(fs.readFileSync(fileURLToPath(import.meta.url))),guardSha256:hash(fs.readFileSync(new URL('model_guard.mjs',import.meta.url))),
  isolation:'All tool executions except fixed JSON evidence retrieval denied by host middleware. No oracle/source/command action exists.',
  comparisonScope:'real-model immutable-native-evidence replay pilot; not live acquisition or all twenty tasks'};
fs.writeFileSync(path.join(output,'plan.json'),JSON.stringify(plan,null,2));

async function one(variant,repetition) {
  const runDir=path.join(output,`${variant}-${repetition}`);fs.mkdirSync(runDir,{recursive:true});
  const log=path.join(runDir,'tool-log.jsonl'), patch=path.join(runDir,'guard.patch.yml');
  fs.writeFileSync(patch,JSON.stringify([{insert:[{id:'ig5-eval-isolation',name:fileURLToPath(new URL('model_guard.mjs',import.meta.url)),config:{dataset:datasetPath,variant,log}}]}]));
  const child=spawn(electron,['--expose-internals',cli,'--profile','ig5-eval-v2',...(providerPatch ? ['--patch',path.resolve(providerPatch)] : []),'--patch',patch],{cwd:runDir,windowsHide:true,
    env:{...process.env,ELECTRON_RUN_AS_NODE:'1',DSH_HOME:path.join(process.env.USERPROFILE,'.dsh'),DSH_TELEMETRY_DISABLED:'1',DSH_MAX_TOKENS_AS_SUCCESS:'false'}});
  const pending=new Map(),events=[];let seq=0,buffer='',received=false,idleResolve,exited=false;
  const idle=new Promise(resolve=>{idleResolve=resolve;});
  child.stdout.on('data',chunk=>{buffer+=chunk.toString();let at;while((at=buffer.indexOf('\n'))>=0){const line=buffer.slice(0,at);buffer=buffer.slice(at+1);let m;try{m=JSON.parse(line);}catch{continue;}
    if(m.id!==undefined && !m.method){const p=pending.get(m.id);if(p){pending.delete(m.id);m.error?p.reject(Object.assign(new Error(m.error.message),{code:m.error.code})):p.resolve(m.result);}}
    if(m.method==='session.event'){events.push(m.params.event);if(m.params.event.type==='agent/inbox/spliced')received=true;}
    if(m.method==='session.status'&&received&&m.params.status==='idle')idleResolve();
    if(m.method&&m.id!==undefined)child.stdin.write(JSON.stringify({jsonrpc:'2.0',id:m.id,error:{code:-32601,message:'No interactive permissions in this evaluation'}})+'\n');
  }});
  child.stderr.on('data',()=>{}); // Provider diagnostics are kept out of user-visible output.
  child.on('exit',()=>{exited=true;for(const p of pending.values())p.reject(new Error('SDK exited'));pending.clear();idleResolve();});
  function request(method,params,timeout=30000){return new Promise((resolve,reject)=>{const id=++seq;const timer=setTimeout(()=>{pending.delete(id);reject(new Error(`SDK ${method} timeout`));},timeout);pending.set(id,{resolve:x=>{clearTimeout(timer);resolve(x);},reject:e=>{clearTimeout(timer);reject(e);}});child.stdin.write(JSON.stringify({jsonrpc:'2.0',id,method,params})+'\n');});}
  const result={caseId:c.caseId,variant,repetition,inputSha256:c.input.sha256,targetSha256:dataset.targetSha256,budgetDigest:hash(JSON.stringify(c.budget)),model,provider,
    promptSha256:hash(prompt),cacheCondition:plan.cacheCondition,answerExposure:'isolated',status:'blocked',claimedAccepted:false,independentVerdict:'unknown',toolCalls:0,elapsedMs:0,
    replay:true,cleanupConfirmed:false,extraHumanHints:0,modelTokens:'unavailable'};
  const started=Date.now();
  try {
    await request('initialize',{cwd:runDir,provider,model,maxTokens:3072});
    await request('session/prompt',{sessionId:`ig5-eval-${randomUUID()}`,contentBlocks:[{type:'text',text:prompt}]});
    let idleTimer;await Promise.race([idle,new Promise((_,reject)=>{idleTimer=setTimeout(()=>reject(new Error('SDK model run timeout')),120000);})]).finally(()=>clearTimeout(idleTimer));
    const assistant=events.filter(e=>e.type==='assistant/message').at(-1);
    const content=assistant?.data?.message?.content||assistant?.data?.content||[];
    const text=content.filter(b=>b.type==='text').map(b=>b.text).join('\n');
    const candidate=text.replace(/^```(?:json)?\s*/,'').replace(/\s*```$/,'').trim();
    let answer;
    try {
      answer=JSON.parse(candidate);
      if(typeof answer.accepted!=='boolean'||!Array.isArray(answer.returns)||!answer.returns.every(Number.isSafeInteger)
        ||typeof answer.functionEa!=='string'||typeof answer.staleEvidence!=='boolean'||!Array.isArray(answer.unknowns)||!answer.unknowns.length
        ||answer.unknowns.some(x=>typeof x!=='string'))throw new Error('Required output fields missing or invalid');
    }catch(error){throw Object.assign(new Error(error.message),{code:'EVAL_OUTPUT_INVALID'});}
    result.answer=answer;result.claimedAccepted=answer.accepted===true;result.status='completed';
    const correct=JSON.stringify(answer.returns)===JSON.stringify(expected)&&answer.functionEa===dataset.current.function.ea&&answer.staleEvidence===true&&Array.isArray(answer.unknowns)&&answer.unknowns.length>0;
    result.independentVerdict=correct?'pass':'fail';
  } catch(error){result.error={code:error.code||'EVAL_MODEL_UNAVAILABLE',message:String(error.message).slice(0,300)};if(events.some(e=>e.type==='assistant/message'))result.status='failed';}
  finally {
    result.elapsedMs=Date.now()-started;
    if(!exited){try{await request('shutdown',{},10000);}catch{}child.stdin.end();}
    if(!exited)await Promise.race([new Promise(resolve=>child.once('exit',resolve)),new Promise(resolve=>setTimeout(resolve,5000))]);
    result.cleanupConfirmed=exited;
    const logs=fs.existsSync(log)?fs.readFileSync(log,'utf8').trim().split('\n').filter(Boolean).map(JSON.parse):[];
    result.toolCalls=logs.filter(x=>x.phase==='dispatch').length;result.inlineBytes=logs.reduce((sum,x)=>sum+(x.bytes||0),0);
    result.investigationCalls=new Set(logs.filter(x=>x.action).map(x=>x.action)).size;result.invalidRepeats=logs.filter(x=>x.action).length-result.investigationCalls;
    result.modelReached=events.some(e=>e.type==='assistant/message');result.blindBoundaryLoaded=logs.some(x=>x.boundary==='only-ig5_eval');
    const usage=events.filter(e=>e.type==='assistant/message').map(e=>e.data.usage);
    if(usage.length&&usage.every(u=>u&&Number.isFinite(u.inputTokens)&&Number.isFinite(u.outputTokens)))result.modelTokens={
      uncachedInput:usage.reduce((s,u)=>s+u.inputTokens,0),cacheRead:usage.reduce((s,u)=>s+(u.cacheReadTokens||0),0),output:usage.reduce((s,u)=>s+u.outputTokens,0)};
    if(result.independentVerdict==='pass'&&!logs.some(x=>x.action==='current_dossier'))result.independentVerdict='fail';
    result.withinBudget=result.toolCalls<=c.budget.toolCalls&&result.inlineBytes<=c.budget.inlineBytes&&result.elapsedMs<=c.budget.elapsedMs;
    if(!result.withinBudget&&result.independentVerdict==='pass')result.independentVerdict='fail';
    if(!result.blindBoundaryLoaded)result.answerExposure='unavailable';
    fs.writeFileSync(path.join(runDir,'events.json'),JSON.stringify(events,null,2));fs.writeFileSync(path.join(runDir,'result.json'),JSON.stringify(result,null,2));
  }
  return result;
}
const results=[];
for(let repetition=1;repetition<=3;repetition++)for(const variant of ['baseline','brief']) {
  const result=await one(variant,repetition);results.push(result);fs.writeFileSync(path.join(output,'runs.json'),JSON.stringify(results,null,2));
  console.log(JSON.stringify({variant,repetition,status:result.status,verdict:result.independentVerdict,calls:result.toolCalls,cleanup:result.cleanupConfirmed,error:result.error?.code}));
  if(!result.cleanupConfirmed)throw new Error('SDK cleanup unconfirmed; stop before starting another trial');
}
fs.writeFileSync(path.join(output,'comparison.json'),JSON.stringify({schema:'ig5-model-comparison-v1',plan,variants:Object.fromEntries(['baseline','brief'].map(v=>{
  const rows=results.filter(r=>r.variant===v);return [v,{registered:3,completed:rows.filter(r=>r.claimedAccepted&&r.independentVerdict==='pass').length,falseAccepts:rows.filter(r=>r.claimedAccepted&&r.independentVerdict==='fail').length,
    blocked:rows.filter(r=>r.status==='blocked').length,toolCalls:rows.reduce((s,r)=>s+r.toolCalls,0),elapsedMs:rows.reduce((s,r)=>s+r.elapsedMs,0)}];})),
  effectivenessAssessed:results.every(r=>r.modelReached&&r.blindBoundaryLoaded),limitations:['Single finite replay task; no reliability or VM recovery conclusion.','Fresh sessions do not disable provider-side caching.']},null,2));
