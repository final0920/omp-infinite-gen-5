import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { resumeNavigation, investigationResume } from '../source/investigation_resume.js';
import { memoryResumeFixture, assessMemoryResume, auditResumeRetrieval } from './evals/memory_resume_fixture.mjs';
import { apply } from './evals/memory_resume_guard.mjs';

test('recovery navigation names at most three owned gaps and never incorporates historical instructions', () => {
  const f = memoryResumeFixture(), before = JSON.stringify(f), nav = resumeNavigation(f);
  assert.equal(nav.gaps.length, 3); assert.equal(nav.gaps[0].kind, 'verifier-feedback');
  assert(nav.gaps.every(g => /^"[a-f0-9-]+"$/.test(g.search.memory.query)));
  assert(!JSON.stringify(nav).includes('execute again'));
  assert.equal(nav.semanticVerified, false); assert.equal(nav.executionAuthorized, false);
  assert.equal(JSON.stringify(f), before);
  f.failures = Array.from({ length: 3 }, (_, i) => ({ reportRef: { id: `92000000-0000-4000-8000-00000000000${i}` }, advice: { category: 'usage' } }));
  assert(resumeNavigation(f).gaps.some(gap => gap.kind === 'stale-evidence'));
  f.task.systemEvidence = []; f.research = null; f.failures = [];
  assert.equal(resumeNavigation(f).gaps[0].sourceId, f.task.taskId);
  f.task.systemEvidence = [{ stale: false }]; assert.equal(resumeNavigation(f).gaps.length, 0);
});

test('recovery rejects foreign identities, cross-task research and unstable snapshots', () => {
  const f = memoryResumeFixture(); f.context = { ...f.context, sha256: 'b'.repeat(64) };
  assert.throws(() => resumeNavigation(f), { code: 'INVESTIGATION_IDENTITY_MISMATCH' });
  const g = memoryResumeFixture(); g.research.taskId = 'foreign';
  assert.throws(() => resumeNavigation(g), { code: 'INVESTIGATION_IDENTITY_MISMATCH' });
  let revision = 0;
  assert.throws(() => investigationResume({ read: () => { const current = memoryResumeFixture(); current.task.taskRevision = revision++; return current; } }), { code: 'SNAPSHOT_INCONSISTENT' });
  assert.throws(() => investigationResume({ read: memoryResumeFixture, maxBytes: 4095 }), { code: 'INVALID_ARGUMENT' });
  assert(Buffer.byteLength(JSON.stringify(investigationResume({ read: memoryResumeFixture, maxBytes: 4096 }))) <= 4096);
});

test('independent recovery scoring rejects forgotten constraints, lost witnesses, repeat proposals and incorrect acceptance', () => {
  const data = memoryResumeFixture();
  const good = { accepted: false, inputDomain: 'signed-16-bit', counterexample: { actual: -6, input: -7, expected: 7 }, pathCondition: 'x < 0', sideEffects: 'unobserved', currentRevision: 3, nextAction: 'change-experiment', historicalAuthorization: false };
  assert(assessMemoryResume(good, data).pass);
  for (const patch of [{ accepted: true }, { inputDomain: 'nonnegative-only' }, { counterexample: null }, { sideEffects: 'none' }, { currentRevision: 2 }, { nextAction: 'repeat-unchanged' }, { historicalAuthorization: true }]) assert.equal(assessMemoryResume({ ...good, ...patch }, data).pass, false);
  assert.equal(auditResumeRetrieval(data, []).pass, false, 'A correct guessed answer cannot substitute for complete source reads');
});

test('actual replay guard enforces the tool boundary, exact pages, output budgets and current revalidation', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-memory-guard-'));
  assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir()));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const data = memoryResumeFixture(), dataset = path.join(root, 'dataset.json'), log = path.join(root, 'tools.jsonl');
  fs.writeFileSync(dataset, JSON.stringify(data));
  let gate, tool; const disposers = [];
  const ctx = { tools: { register(value) { tool = value; return () => {}; } }, on(_name, fn) { gate = fn; }, effect(fn) { const dispose = fn(); if (typeof dispose === 'function') disposers.push(dispose); } };
  await apply(ctx, { dataset, variant: 'brief-lcm', runRoot: root, log });
  try {
    assert.equal(gate({ name: 'shell' }, () => assert.fail('not allowed')).kind, 'deny');
    assert.throws(() => tool.execute({ action: 'read', path: 'foreign' }), /Invalid retrieval/);
    const nav = tool.execute({ action: 'resume' });
    for (const gap of nav.gaps) {
      const hit = tool.execute({ action: 'search', query: gap.search.memory.query }).hits[0];
      tool.execute({ action: 'read', ref: hit.ref });
    }
    tool.execute({ action: 'current' });
    let records = fs.readFileSync(log, 'utf8').trim().split('\n').map(JSON.parse);
    assert(auditResumeRetrieval(data, records).pass);
    records = records.filter(r => r.args?.action !== 'current'); assert.equal(auditResumeRetrieval(data, records).pass, false);
    assert.throws(() => tool.execute({ action: 'read', ref: { kind: 'event', id: '0', sha256: '0'.repeat(64) } }), { code: 'LCM_CONTENT_CHANGED' });
    for (let i = 0; i < 30; i++) gate({ name: 'ig5_memory_eval' }, () => null);
    assert.equal(gate({ name: 'ig5_memory_eval' }, () => assert.fail('budget')).kind, 'deny');
  } finally { for (const dispose of disposers.reverse()) dispose(); }
});
