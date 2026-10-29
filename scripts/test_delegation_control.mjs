import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DelegationControl } from '../source/delegation_control.js';

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-delegation-test-'));
  const agents = new Map();
  const agent = (id, parent) => { const a = { id, session: { header: { id, ...(parent ? { parentSession: parent.id } : {}) } } }; agents.set(id, a); return a; };
  const parent = agent('parent'), child = agent('child', parent), sibling = agent('sibling', parent), grandchild = agent('grandchild', child);
  const control = new DelegationControl({ root, getAgent: id => agents.get(id) });
  t.after(() => { assert.equal(path.dirname(root), path.resolve(os.tmpdir())); assert(path.basename(root).startsWith('ig5-delegation-test-')); fs.rmSync(root, { recursive: true, force: true }); });
  const task = { taskId: 'task', taskRevision: 2 }, scope = { projectId: 'project', artifactId: 'artifact', sha256: 'sha', engine: 'reverse', provider: 'ghidra', attachmentId: 'attachment', dbRevision: 0 };
  const snapshot = { snapshot_id: 'snapshot', context: scope, stale: false };
  const start = a => control.start({ id: a.id, runId: 'run-' + a.id, local: true });
  const end = (a, extra = {}) => control.end({ id: a.id, runId: 'run-' + a.id, stopReason: 'completed', lastAssistantMessage: [{ type: 'text', text: 'returned snapshot' }], ...extra });
  return { root, agents, parent, child, sibling, grandchild, control, task, scope, snapshot, start, end };
}
const rejects = (fn, code) => assert.throws(fn, e => e.code === code);

test('shared parent/child/grandchild budget is persistent, cannot reset, and has atomic exhaustion', async t => {
  const f = fixture(t), c = f.control;
  c.budget(f.parent, { action: 'start', max_calls: 3 });
  await Promise.all([f.parent, f.child, f.grandchild].map(a => Promise.resolve().then(() => c.charge(a, 'ig5_profile', {}))));
  rejects(() => c.charge(f.sibling, 'ig5_open', {}), 'IG5_SHARED_BUDGET_EXHAUSTED');
  c.charge(f.child, 'ig5_profile', { collaboration: { action: 'status' } });
  assert.deepEqual(c.budget(f.child, { action: 'status' }).byAgent, { parent: 1, child: 1, grandchild: 1 });
  rejects(() => c.budget(f.parent, { action: 'start', max_calls: 100 }), 'BUDGET_ALREADY_STARTED');
  rejects(() => c.budget(f.child, { action: 'start', max_calls: 100 }), 'BUDGET_OWNER_REQUIRED');
  const reloaded = new DelegationControl({ root: f.root, getAgent: id => f.agents.get(id) });
  rejects(() => reloaded.charge(f.parent, 'ig5_bytes', {}), 'IG5_SHARED_BUDGET_EXHAUSTED');
  assert.equal(reloaded.budget(f.parent, { action: 'status' }).used, 3);
});

test('missing, cyclic and spoofed lineage fail closed for controlled state', t => {
  const f = fixture(t);
  rejects(() => f.control.budget({ id: 'x' }, { action: 'start', max_calls: 3 }), 'AGENT_LINEAGE_UNAVAILABLE');
  rejects(() => f.control.charge({ id: 'x', session: { header: { id: 'x', parentSession: 'missing' } } }, 'ig5_open', {}), 'AGENT_LINEAGE_UNAVAILABLE');
  f.parent.session.header.parentSession = f.child.id;
  rejects(() => f.control.budget(f.parent, { action: 'status' }), 'AGENT_LINEAGE_UNAVAILABLE');
});

test('post-return review rejects early, unread, foreign, wrong-run, failed and mismatched evidence', t => {
  const f = fixture(t), c = f.control;
  const { handoffId: id } = c.handoff(f.parent, f.task, f.scope);
  rejects(() => c.review(f.parent, id, f.task, f.scope, ['snapshot']), 'CHILD_RETURN_REQUIRED');
  rejects(() => c.claim(f.child, id, f.task, f.scope), 'CHILD_LIFECYCLE_UNAVAILABLE');
  f.start(f.child); c.claim(f.child, id, f.task, f.scope);
  f.start(f.sibling);
  rejects(() => c.claim(f.sibling, id, f.task, f.scope), 'HANDOFF_CHILD_REQUIRED');
  rejects(() => c.submit(f.child, id, f.task, f.scope, [f.snapshot]), 'EVIDENCE_READ_REQUIRED');
  c.read(f.child, { ...f.snapshot, stale: true });
  rejects(() => c.submit(f.child, id, f.task, f.scope, [f.snapshot]), 'EVIDENCE_READ_REQUIRED');
  c.read(f.child, f.snapshot); c.submit(f.child, id, f.task, f.scope, [f.snapshot]);
  rejects(() => c.review(f.parent, id, f.task, f.scope, ['snapshot']), 'CHILD_RETURN_REQUIRED');
  f.end(f.child, { runId: 'wrong' });
  rejects(() => c.review(f.parent, id, f.task, f.scope, ['snapshot']), 'CHILD_RETURN_REQUIRED');
  f.end(f.child, { stopReason: 'error' });
  rejects(() => c.review(f.parent, id, f.task, f.scope, ['snapshot']), 'CHILD_RETURN_REQUIRED');
});

test('observed completed output allows exact returned snapshots only; reload and revision changes invalidate ticket', t => {
  const f = fixture(t), c = f.control;
  const { handoffId: id } = c.handoff(f.parent, f.task, f.scope);
  f.start(f.child); c.claim(f.child, id, f.task, f.scope); c.read(f.child, f.snapshot);
  c.submit(f.child, id, f.task, f.scope, [f.snapshot]); f.end(f.child);
  assert.equal(c.review(f.parent, id, f.task, f.scope, ['snapshot']).delegationVerified, true);
  rejects(() => c.review(f.parent, id, f.task, f.scope, ['other']), 'RETURN_SNAPSHOT_MISMATCH');
  rejects(() => c.review(f.sibling, id, f.task, f.scope, ['snapshot']), 'HANDOFF_PARENT_REQUIRED');
  rejects(() => c.review(f.parent, id, { ...f.task, taskRevision: 3 }, f.scope, ['snapshot']), 'STALE_HANDOFF');
  rejects(() => c.review(f.parent, id, f.task, { ...f.scope, attachmentId: 'new' }, ['snapshot']), 'STALE_HANDOFF');
  const reloaded = new DelegationControl({ root: f.root, getAgent: id => f.agents.get(id) });
  rejects(() => reloaded.review(f.parent, id, f.task, f.scope, ['snapshot']), 'HANDOFF_RESTARTED');
});
