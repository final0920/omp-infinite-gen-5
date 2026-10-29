import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {AnalysisArtifacts} from '../source/analysis_artifacts.js';
import {contextPage} from './fixtures/vm_context_cases.mjs';
import {runVmContextProfile} from '../source/vm_context_profile.js';
import {vmContextEvidence} from '../source/evidence_adapters/vm_context.js';
import {auditVmContext} from '../source/verifiers/vm_context_audit.js';
import {capabilityCatalog} from '../source/capability_catalog.js';
import {loadCases,summarize} from './evals/registry.mjs';

test('write-only native STORE candidates agree with independent JS/Python and reject VSP alterations',async t=>{
  const root=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'ig5-review-fix-')),store=new AnalysisArtifacts(path.join(root,'artifacts'));
  t.after(async()=>{await store.dispose();assert.equal(path.dirname(root),fs.realpathSync(os.tmpdir()));assert(path.basename(root).startsWith('ig5-review-fix-'));fs.rmSync(root,{recursive:true,force:true});});
  const p=contextPage(0);
  for(const b of p.selection.bodies){const g=b.groups[0];g.memoryReads=[];g.memoryWrites={status:'decoded-locations-observed-across-stop',stores:[{address:g.before.gprs.rbp,bytes:8,status:'unavailable',afterHex:null}]};}
  const ref=r=>({id:r.id,sha256:store.metadata(r.id).result.recordSha256});
  const recurrence=store.save({kind:'vm-flow-recurrences',action:'validate',result:p.recurrence});
  const selection=store.save({kind:'vm-handler-windows',action:'select',result:p.selection});
  p.handlers.sourceRecurrence=ref(recurrence);p.handlers.sourceSelection={...ref(selection),path:path.join(store.directory('records'),selection.id+'.json')};
  const h=store.save({kind:'vm-recorded-handlers',action:'assess',result:p.handlers});
  const c=runVmContextProfile({analysis:{artifacts:store},checkCancelled(){}},{handler_refs:[ref(h)]}).context;
  assert.equal(c.roles.vspCandidates.find(r=>r.name==='rbp').nearbyAccesses,8);
  const task={scope:{sha256:p.handlers.targetSha256}};
  const js=report=>auditVmContext(vmContextEvidence(store,task,ref(report)).request);
  const python=report=>spawnSync(path.resolve('runtimes/ghidra/python/python.exe'),['-I','-B','-X','utf8','scripts/verify_vm_context_model.py',path.join(store.directory('records'),report.id+'.json'),ref(report).sha256],{encoding:'utf8',timeout:15000,windowsHide:true});
  const full=store.get(c.reportId);assert.equal(js(full).status,'pass');assert.equal(python(full).status,0);
  for(const alter of [r=>r.roles.vspCandidates=[],r=>r.roles.vspCandidates[0].nearbyAccesses++,r=>r.roles.vspCandidates[0].vmRoleProved=true,r=>r.roles.vspCandidates[0].name='r15']){
    const result=structuredClone(full.result);alter(result);const bad=store.save({kind:'vm-context-model',action:'derive',result});
    assert.equal(js(bad).status,'fail');assert.notEqual(python(bad).status,0);
  }
});

test('guest readiness never verifies local debugging or inherits local policy',()=>{
  const guest={engine:'x64dbg',executionLocation:{kind:'vmci-guest',guestCID:123,bundleSha256:'b'.repeat(64),profileSha256:'a'.repeat(64),serverInstanceId:'server',sessionId:'session'},pending:new Map()};
  const mgr={sessions:new Map([['guest',guest]]),alive:()=>true,engines:()=>[{id:'x64dbg',provider:'x64dbg',available:true}]};
  const entries=capabilityCatalog(mgr,{host:{id:'win32-x64',supported:true},x64dbg:{}}).entries.filter(c=>c.operation==='record-execution');
  const local=entries.find(e=>e.executionLocation==='local'),remote=entries.find(e=>e.executionLocation==='vmci-guest');
  assert.equal(local.startup,'not-probed');assert.notEqual(local.session,'compatible');
  assert.equal(remote.startup,'verified');assert.equal(remote.session,'compatible');assert.equal(remote.executionBinding.guestCID,123);
  assert.equal(remote.policy,'unknown');assert.equal(remote.launchPolicy,undefined);assert.equal(remote.runtimeDigest,guest.executionLocation.bundleSha256);
});

test('strict eval acceptance requires all frozen budgets and cleanup; old records stay unverified',()=>{
  const cases=loadCases(),c=cases[0],hash=v=>createHash('sha256').update(v).digest('hex');
  const run={caseId:c.caseId,variant:'baseline',repetition:1,status:'completed',claimedAccepted:true,independentVerdict:'pass',answerExposure:'exposed',
    toolCalls:1,elapsedMs:1,inlineBytes:1,cleanupConfirmed:true,inputSha256:c.input.sha256,budgetDigest:hash(JSON.stringify(c.budget)),model:'fixture',promptSha256:hash('prompt'),cacheCondition:'cold'};
  assert.equal(summarize(cases,[run]).acceptedRuns,1);
  for(const change of [{inlineBytes:c.budget.inlineBytes+1},{inlineBytes:undefined},{inlineBytes:-1},{cleanupConfirmed:false},{cleanupConfirmed:undefined},{status:'failed'},{toolCalls:c.budget.toolCalls+1},{elapsedMs:c.budget.elapsedMs+1}]){
    const r=summarize(cases,[{...run,...change}]);assert.equal(r.acceptedRuns,0);assert.equal(r.acceptanceUnverified,1);assert.equal(r.unrunCases.length,19);
  }
});
