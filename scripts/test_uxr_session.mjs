import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { uxrHost } from './fixtures/uxr_host.mjs';
import { DelegationControl } from '../source/delegation_control.js';
const agent = (id, parent) => ({ id, session: { header: { id, ...(parent ? { parentSession: parent } : {}) } } });

test('public metadata doctor reaches an orphan; normal tools stay blocked and no ledger is created', async t => {
  const f = uxrHost(t), child = agent('child', 'missing');
  const result = await f.call('ig5_doctor', { operation: 'session' }, child);
  assert.equal(result.code, 'PARENT_SESSION_UNAVAILABLE'); assert.equal(result.budget, null);
  assert.equal(result.rpcPerformed, false); assert.equal(result.budgetModified, false); assert.equal(result.faultStartedAt, null);
  assert.equal(fs.existsSync(path.join(f.root, 'projects/delegation-control/projects.json')), false);
  await assert.rejects(f.call('ig5_doctor', {}, child), { code: 'AGENT_LINEAGE_UNAVAILABLE', reason: 'PARENT_SESSION_UNAVAILABLE' });
  await assert.rejects(f.call('ig5_doctor', { operation: 'session', parentId: 'fake' }, child), { code: 'INVALID_ARGUMENT' });
});

test('host reindexing resumes the same persisted root budget; diagnosis is exempt at exhaustion', async t => {
  const f = uxrHost(t), parent = agent('parent'), child = agent('child', 'parent');
  f.agents.set(parent.id, parent);
  await f.call('ig5_profile', { collaboration: { action: 'start', max_calls: 2 } }, parent);
  await assert.rejects(f.call('ig5_open', { path: path.join(f.root, 'absent.exe') }, child));
  const ledger = path.join(f.root, 'projects/delegation-control/projects.json'), before = fs.readFileSync(ledger);
  const diag = await f.call('ig5_doctor', { operation: 'session' }, child);
  assert.deepEqual(diag.budget, { active: true, used: 1, limit: 2 }); assert.deepEqual(fs.readFileSync(ledger), before);
  const c = new DelegationControl({ root: path.join(f.root, 'projects'), getAgent: id => f.agents.get(id) });
  assert.equal(c.diagnose(child, { operation: 'session' }).budget.used, 1);
  c.charge(child, 'ig5_decompile', {});
  assert.throws(() => c.charge(parent, 'ig5_open', {}), { code: 'IG5_SHARED_BUDGET_EXHAUSTED' });
  assert.equal((await f.call('ig5_doctor', { operation: 'session' }, child)).budget.used, 2);
  await assert.rejects(f.call('ig5_profile', { collaboration: { action: 'start', max_calls: 999 } }, parent), { code: 'BUDGET_ALREADY_STARTED' });
});

test('cycle, identity conflict, corrupt ledger and missing metadata remain distinct and non-mutating', t => {
  const f = uxrHost(t), parent = agent('parent'), child = agent('child', 'parent');
  const c = new DelegationControl({ root: path.join(f.root, 'isolated'), getAgent: () => ({ id: 'wrong', session: { header: { id: 'wrong' } } }) });
  assert.equal(c.diagnose(child, { operation: 'session' }).code, 'PARENT_IDENTITY_MISMATCH');
  const loop = agent('loop', 'loop');
  assert.equal(c.diagnose(loop, { operation: 'session' }).code, 'SESSION_LINEAGE_CYCLE');
  assert.equal(c.diagnose(undefined, { operation: 'session' }).code, 'SESSION_IDENTITY_MISMATCH');
  c.budget(parent, { action: 'start', max_calls: 2 });
  fs.writeFileSync(c.store.file, '{corrupt'); const raw = fs.readFileSync(c.store.file);
  const reloaded = new DelegationControl({ root: path.join(f.root, 'isolated') });
  assert.equal(reloaded.diagnose(parent, { operation: 'session' }).code, 'DELEGATION_STORE_CORRUPT');
  assert.deepEqual(fs.readFileSync(c.store.file), raw);
  assert.throws(() => reloaded.charge(parent, 'ig5_open', {}));
});
