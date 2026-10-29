import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {auditCases,readEvidence,localPath,sha256} from './fusion/evidence.mjs';
import {freezeProtocol,judgeDecisionEvents,summarizeRuns as summarizeRaw} from './evals/fusion/protocol.mjs';
const summarizeRuns=(frozen,runs)=>summarizeRaw(frozen,runs,{'dev-1':'contested'});

test('case audit binds original file bytes and line ranges without promoting reported claims',async t=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'ig5-fusion-'));
  t.after(async()=>{assert.equal(await fs.realpath(path.dirname(root)),await fs.realpath(os.tmpdir()));await fs.rm(root,{recursive:true,force:true});});
  await fs.writeFile(path.join(root,'source.txt'),'old claim\nnew claim\n');
  const ref={path:'source.txt',sha256:sha256('old claim\nnew claim\n'),startLine:1,endLine:2,rangeSha256:sha256('old claim\nnew claim')};
  const item={caseId:'x',projectId:'p',artifactSha256:'a'.repeat(64),status:'contested',timeline:'retrospective-order-unverified',sourceRefs:[ref],hypotheses:['clear','keep']};
  for(const k of ['question','visibleInput','observations','historicalAction','locatedResult','laterCorrection','unknowns','redaction','expectedDecision'])item[k]='review required';
  const bundle={schema:'ig5-private-decision-cases-v1',projectId:'p',partition:'development',publicExportAllowed:false,cases:Array.from({length:12},(_,i)=>({...item,caseId:'case-'+i}))};
  assert.equal((await auditCases(bundle,root)).caseCount,12);
  assert.equal((await auditCases(bundle,root)).semanticVerified,false);
  const bad=structuredClone(bundle);bad.cases[0].sourceRefs[0].endLine=99;await assert.rejects(auditCases(bad,root));
  const promoted=structuredClone(bundle);promoted.cases[0].status='verified-in-scope';await assert.rejects(auditCases(promoted,root));
  await fs.appendFile(path.join(root,'source.txt'),'changed');await assert.rejects(auditCases(bundle,root));
  for(const p of ['../secret','a/../secret','C:/secret','a\\b','/absolute'])assert.throws(()=>localPath(root,p));
  await fs.link(path.join(root,'source.txt'),path.join(root,'alias.txt'));await assert.rejects(readEvidence(root,'alias.txt'));
});

const input=()=>({schema:'ig5-fusion-eval-input-v1',model:'unresolved-model-no-runs',route:'unresolved',parameters:{temperature:0},context:'frozen-dev-input',toolVersion:'baseline',corpusGeneration:'v1',promptSha256:'b'.repeat(64),budget:{toolCalls:20,tokens:16000,elapsedMs:120000,returnedBytes:65536},thresholds:{falseAccepts:0,boundaryViolations:0,nonInferiorityPercentagePoints:5,offOverheadPercent:10},tasks:[{id:'dev-1',family:'family-1',partition:'development',project:'VS1.5',inputSha256:'a'.repeat(64),judgeSha256:sha256('contested')}]});
test('paired protocol rejects family leakage, altered budgets, duplicate runs and unbound judgments',()=>{
  const frozen=freezeProtocol(input()),task=frozen.manifest.tasks[0];
  const events=[{type:'decision',value:'contested',sourceRefs:['d'.repeat(64)]}];
  const judge=judgeDecisionEvents(task,events,'contested');
  const run={taskId:task.id,group:'A',repetition:1,protocolSha256:frozen.sha256,controls:frozen.manifest.controls,status:'completed',events,judge,cost:{toolCalls:1,tokens:20,elapsedMs:5,returnedBytes:80},cleanupConfirmed:true};
  assert.equal(summarizeRuns(frozen,[run]).perGroup.A.passed,1);
  assert.equal(summarizeRaw(frozen,[run]).perGroup.A.passed,0);
  assert.throws(()=>summarizeRuns(frozen,[{...run,judge:{...judge,verdict:'fail'}}]));
  assert.equal(summarizeRuns(frozen,[run]).blindRuns,0);
  assert.equal(summarizeRuns(frozen,[]).perGroup.E.missing,3);
  assert.throws(()=>summarizeRuns(frozen,[run,run]));
  assert.throws(()=>summarizeRuns(frozen,[{...run,events:[]} ]));
  assert.throws(()=>summarizeRuns(frozen,[{...run,controls:{...run.controls,model:'different'}}]));
  assert.equal(summarizeRuns(frozen,[{...run,cost:{...run.cost,tokens:16001}}]).perGroup.A.passed,0);
  assert.equal(summarizeRuns(frozen,[{...run,cleanupConfirmed:false}]).perGroup.A.passed,0);
  const leak=input();leak.tasks.push({...leak.tasks[0],id:'holdout',partition:'holdout',inputSha256:'e'.repeat(64),project:'other'});assert.throws(()=>freezeProtocol(leak));
  const vs=input();vs.tasks[0].partition='holdout';assert.throws(()=>freezeProtocol(vs));
  assert.equal(judgeDecisionEvents(task,[{type:'decision',value:'contested'}],'contested').verdict,'unknown');
  const wrong=[{type:'decision',value:'accepted',sourceRefs:['d'.repeat(64)]},{type:'accept',value:true}];
  assert.equal(summarizeRuns(frozen,[{...run,events:wrong,judge:judgeDecisionEvents(task,wrong,'contested')}]).perGroup.A.falseAccepts,1);
});
