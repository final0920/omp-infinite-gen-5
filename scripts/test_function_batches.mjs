import test from 'node:test';
import assert from 'node:assert/strict';
import { AsyncLocalStorage } from 'node:async_hooks';
import path from 'node:path';
import { uxrHost } from './fixtures/uxr_host.mjs';
import { FunctionBatches } from '../source/function_batches.js';
import { ResultArtifacts } from '../source/result_artifacts.js';
const provenance = { target: 'fixture', projectId: 'p', artifactId: 'a', sha256: 'a'.repeat(64), engine: 'ghidra', provider: 'ghidra', attachmentId: 'attach', dbRevision: 1 };
function fixture(t) {
  const h = uxrHost(t), session = { ...provenance, cache: new Map(), capabilities: ['decompile','cfg','calls','stack'] };
  let rpcs=0, charges=0, limit=1000;
  const mgr = { cfg: {}, scope: new AsyncLocalStorage(), functionResults: new ResultArtifacts(path.join(h.root, 'results')),
    coordination: { charge() { if (charges >= limit) throw Object.assign(new Error('exhausted'), { code: 'IG5_SHARED_BUDGET_EXHAUSTED' }); charges++; } },
    evidence: () => ({ ...session, cache: undefined, capabilities: undefined }), get: () => session, alive: () => true,
    checkCancelled() { if (mgr.scope.getStore()?.signal?.aborted) throw Object.assign(new Error('cancelled'), { code: 'ABORT_ERR' }); },
    async rpc(_s, method, args) { rpcs++; return { ea: args.ea, name: 'f', ...(method === 'decompile' ? { code: 'int f() {return 1;}', complete: true } : method === 'cfg' ? { blocks: [], edges: [] } : method === 'calls' ? { calls: [], total: 0 } : { members: [] }) }; } };
  // Use the exact public evidence keys (no session implementation fields).
  mgr.evidence = () => Object.fromEntries(Object.keys(provenance).map(k => [k,session[k]]));
  const batches = new FunctionBatches(h.root);
  const execute = input => batches.execute(mgr, session, { batch: input }, { agent: {} });
  return { ...h, mgr, session, batches, execute, get rpcs() { return rpcs; }, get charges() { return charges; }, setLimit(n) { limit=n; } };
}
test('72 explicit functions run serially, resume committed items, and retain per-item refs with bounded charging', async t => {
  const f=fixture(t), functions=Array.from({ length:72 },(_,i)=>'0x'+(4096+i*16).toString(16));
  const created=await f.execute({ action:'create',functions }); let task=created;
  for(let i=0;i<9;i++) task=await f.execute({ action:'run',id:created.id });
  assert.equal(task.counts.completed,72); assert.equal(f.rpcs,72*5); assert.equal(f.charges,9*7);
  await f.execute({ action:'run',id:created.id }); assert.equal(f.rpcs,360);
  assert(task.items.every(i=>i.attempts===1&&i.resultRef.sha256.length===64));
  await assert.rejects(f.execute({ action:'create',functions:[functions[0],functions[0]] }), { code:'INVALID_BATCH_ARGUMENT' });
});
test('interruption after artifact commit resumes without repeating provider work', async t => {
  const f=fixture(t), created=await f.execute({ action:'create',functions:['0x1000'] });
  const original=f.batches.update.bind(f.batches); let interrupt=false;
  const save=f.mgr.functionResults.save.bind(f.mgr.functionResults);
  f.mgr.functionResults.save=(...args)=>{const ref=save(...args);interrupt=true;return ref;};
  f.batches.update=(...args)=>{if(interrupt) throw new Error('simulated process interruption before state commit');return original(...args);};
  await assert.rejects(f.execute({ action:'run',id:created.id })); assert.equal(f.rpcs,5);
  const restarted=new FunctionBatches(f.root);
  const task=await restarted.execute(f.mgr,f.session,{batch:{action:'run',id:created.id}},{agent:{}});
  assert.equal(task.counts.completed,1);assert.equal(f.rpcs,5);
});
test('budget exhaustion leaves pending items, cancellation is persistent, and new revisions cannot mix', async t => {
  const f=fixture(t), created=await f.execute({ action:'create',functions:['0x1000','0x1010','0x1020'] });
  f.setLimit(0);
  const task=await f.execute({ action:'run',id:created.id });
  assert.equal(task.counts.completed,1); assert.equal(task.counts.pending,2); assert.equal(task.pauseReason,'IG5_SHARED_BUDGET_EXHAUSTED');
  const cancelled=await f.execute({ action:'cancel',id:created.id }); assert.equal(cancelled.counts.cancelled,2);
  await f.execute({ action:'run',id:created.id }); assert.equal(f.rpcs,5);
  f.session.dbRevision++;
  await assert.rejects(f.execute({ action:'run',id:created.id }),{code:'BATCH_STALE'});
});

test('cancel aborts an active item and leaves no active batch owner', async t => {
  const f=fixture(t), created=await f.execute({action:'create',functions:['0x1000','0x1010']});
  let entered;const waiting=new Promise(resolve=>{entered=resolve;});
  f.mgr.rpc=async()=>{entered();return new Promise((resolve,reject)=>f.mgr.scope.getStore().signal.addEventListener('abort',()=>reject(Object.assign(new Error('aborted'),{code:'ABORT_ERR'})),{once:true}));};
  const running=f.execute({action:'run',id:created.id});await waiting;
  await f.execute({action:'cancel',id:created.id});const task=await running;
  assert.equal(task.counts.cancelled,2);assert.equal(f.batches.active.size,0);
});
