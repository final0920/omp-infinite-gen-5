import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { LcmMemory, MEMORY_LIMITS, digest } from '../source/lcm_memory.js';
import { installLcmBridge } from '../source/lcm_bridge.js';

const event = (seq, text = '原始反例 0xffffffffffffffff 🧪\u0000') => ({ seq, type: 'tool/result', data: { message: { toolCallId: `call-${seq}`, content: [{ type: 'text', text }] } } });
async function fixture(t, limits) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-lcm-'));
  const opts = { root, sessionId: 'A', workspace: root, ...(limits ? { limits } : {}) };
  const stores = [];
  const open = async (overrides = {}) => { const s = await LcmMemory.open({ ...opts, ...overrides }); stores.push(s); return s; };
  t.after(() => { for (const s of stores) try { s.close(); } catch {} fs.rmSync(root, { recursive: true, force: true }); });
  return { root, opts, open, store: await open() };
}
function all(store, ref, limit = 103) {
  let text = '', offset = 0;
  do { const page = store.read(ref, { offset, limit }); text += page.text; offset = page.nextOffset; } while (offset !== null);
  assert.equal(digest(text), ref.sha256); return text;
}
test('exact JSON survives Unicode pagination, duplicate capture, reopen, and repeated summaries', async t => {
  const { store, open } = await fixture(t);
  const raw = event(0, '反例 🧪\u0000 0xffffffffffffffff '.repeat(300));
  const { ref } = await store.capture(raw);
  assert.equal(all(store, ref), JSON.stringify(raw));
  assert.equal((await store.capture(raw)).duplicate, true);
  assert.equal(store.status().count, 1);
  let parent = ref;
  for (let i = 0; i < 12; i++) parent = await store.checkpoint(`第${i}次摘要遗漏细节`, [parent]);
  const top = parent;
  for (let i = 0; i < 12; i++) { const page = store.expand(parent); assert.equal(page.directSourcesComplete, true); parent = page.refs[0]; }
  assert.deepEqual(parent, ref); assert.equal(all(store, parent), JSON.stringify(raw));
  store.close(); const reopened = await open(); assert.equal(reopened.status().summaries, 12);
  assert.equal(reopened.read(top).semanticVerified, false); assert.equal(all(reopened, ref), JSON.stringify(raw));
});
test('identity conflicts, invalid JSON and scoped foreign references fail explicitly', async t => {
  const { store, open, root } = await fixture(t);
  const { ref } = await store.capture(event(1));
  await assert.rejects(store.capture(event(1, 'changed')), { code: 'LCM_EVENT_CONFLICT' });
  await assert.rejects(store.capture(event(2, 4n)), { code: 'INVALID_IG5_OUTPUT' });
  const otherSession = await open({ sessionId: 'B' }), otherWorkspace = await open({ workspace: path.join(root, 'other') });
  for (const other of [otherSession, otherWorkspace]) assert.throws(() => other.read(ref), { code: 'LCM_REF_NOT_FOUND' });
  assert.equal(store.status().count, 1);
});
test('hashes cover raw data and summary lineage, not merely summary prose', async t => {
  const { store } = await fixture(t);
  const { ref } = await store.capture(event(0)); const summary = await store.checkpoint('导航', [ref]);
  store.db.prepare('UPDATE ig5_lcm_nodes SET refs=? WHERE id=?').run('[]', summary.id);
  assert.throws(() => store.expand(summary), { code: 'LCM_CONTENT_CHANGED' });
  await assert.rejects(store.checkpoint('导航', [ref]), { code: 'LCM_CONTENT_CHANGED' });
  store.db.prepare('UPDATE messages SET content=?').run('changed');
  assert.throws(() => store.read(ref), { code: 'LCM_CONTENT_CHANGED' });
});
test('DSH compaction retains raw events, links previous summaries and exposes missing sources', async t => {
  const { store } = await fixture(t);
  await store.capture(event(0)); await store.capture(event(1));
  const blocks = [{ type: 'text', text: '压缩一' }];
  await store.capture({ seq: 3, type: 'compaction/summary', data: { summary: blocks, shadowedSeqs: [0, 1, 2] } });
  const first = store.restore().summaries[0]; assert.equal(store.expand(first).directSourcesComplete, false);
  assert.deepEqual(JSON.parse(store.read(first).text), blocks);
  await store.capture({ seq: 4, type: 'user/message', data: { content: blocks }, surfaceOp: { op: 'replace', startSeq: 0, endSeq: 1 }, sourceEventSeqs: [3, 0, 1] });
  await store.capture({ seq: 5, type: 'compaction/summary', data: { summary: [{ type: 'text', text: '压缩二' }], shadowedSeqs: [4] } });
  const top = store.restore().summaries[0]; const expanded = store.expand(top); const child = expanded.refs.find(r => r.kind === 'summary');
  assert(expanded.refs.some(r => r.kind === 'event' && r.id === '4'));
  assert.equal(child.id, first.id); assert.equal(store.expand(child).missingSourceCount, 1);
  assert.equal(store.status().count, 5); assert.equal(store.status().hostCompactionReplaced, false);
  assert.equal((await store.capture({ seq: 6, type: 'user/message', data: { source: { kind: 'runtime-context' } } })).skipped, true);
});
test('budget refusals do not evict stored evidence; summary failure retains committed raw', async t => {
  const first = event(0, 'small'), bytes = Buffer.byteLength(JSON.stringify(first));
  const { store } = await fixture(t, { ...MEMORY_LIMITS, eventBytes: 1024, sessionBytes: bytes });
  const { ref } = await store.capture(first);
  await assert.rejects(store.capture(event(1)), { code: 'LCM_SESSION_BUDGET' });
  await assert.rejects(store.capture(event(2, 'x'.repeat(2048))), { code: 'LCM_EVENT_BUDGET' });
  assert.equal(all(store, ref), JSON.stringify(first)); assert.equal(store.status().bytes, bytes);
  const f = await fixture(t);
  const raw = { seq: 0, type: 'compaction/summary', data: { summary: '', shadowedSeqs: [] } };
  assert.equal((await f.store.capture(raw)).summaryWarning.code, 'INVALID_ARGUMENT');
  assert.equal(all(f.store, f.store.eventRef(0)), JSON.stringify(raw));
  await f.store.capture(event(1, 'later evidence survives derived-index failure'));
  assert.equal(f.store.status().count, 2); assert.equal(f.store.status().summaryFailures, 1);
});
test('search and expansion are bounded; no silent page loss or surrogate splitting', async t => {
  const { store } = await fixture(t); const refs = [];
  for (let i = 0; i < 20; i++) refs.push((await store.capture(event(i, 'counterexample abc' + i))).ref);
  assert.equal(store.search('counterexample', 3).hits.length, 3);
  assert.equal(store.search('counterexample').exhaustive, false);
  assert.throws(() => store.search('x', 17), { code: 'INVALID_ARGUMENT' });
  const summary = await store.checkpoint('🧪导航', refs);
  assert.equal(store.read(summary, { limit: 2 }).text, '🧪');
  assert.throws(() => store.read(summary, { offset: 1 }), { code: 'INVALID_ARGUMENT' });
  assert.throws(() => store.read(summary, { limit: 1 }), { code: 'INVALID_ARGUMENT' });
  const page = store.expand(summary, { limit: 16 }); assert.equal(page.nextOffset, 16);
  assert.equal(store.expand(summary, { offset: page.nextOffset }).refs.length, 4);
});
function host(root) {
  const hooks = new Map(), prompts = [];
  const ctx = { on(name, fn) { hooks.set(name, fn); return () => hooks.delete(name); } };
  const agent = { id: 'A', session: { header: { id: 'A', cwd: root }, log: [event(0, 'initial')] }, ctx: { get: () => ({ context(p) { prompts.push(p); return () => prompts.splice(prompts.indexOf(p), 1); } }) } };
  return { ctx, hooks, agent, prompts, bridge: installLcmBridge(ctx, { projectRoot: root }) };
}
test('bridge survives invalid queries, captures compaction hooks and drains final events on disposal', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-lcm-bridge-'));
  const { bridge, hooks, agent, prompts } = host(root);
  t.after(async () => { await bridge.dispose(); fs.rmSync(root, { recursive: true, force: true }); });
  assert.equal((await bridge.handle(agent, { action: 'status' })).count, 1);
  const initialNavigation = prompts[0].text();
  await assert.rejects(bridge.handle(agent, { action: 'search', query: '' }), { code: 'INVALID_ARGUMENT' });
  agent.session.log.push(event(1, 'following query failure'));
  hooks.get('session/event')(agent.session, agent.session.log.at(-1));
  let next = 0; await hooks.get('agent/pre-step')({ agent }, () => next++); assert.equal(next, 1);
  const status = await bridge.handle(agent, { action: 'status' }); assert.equal(status.count, 2); assert.equal(status.error, null);
  assert(prompts[0].text().includes('search/read/expand'));
  assert.equal(prompts[0].text(), initialNavigation, 'ordinary events must not force repeated runtime-context snapshots');
  const beforeSearch = await bridge.handle(agent, { action: 'status' });
  const searched = await bridge.handle(agent, { action: 'search', query: 'following' });
  assert.equal(searched.recovery.dataOnly, true);
  assert.equal(searched.recovery.automaticCheckpointSaved, false);
  assert.equal(searched.recovery.read[0].memory.action, 'read');
  assert.equal(searched.recovery.checkpointDraft.sources[0].sha256, searched.hits[0].ref.sha256);
  assert.match(searched.recovery.checkpointDraft.text, /Caller-unverified/);
  assert.equal((await bridge.handle(agent, { action: 'status' })).summaries, beforeSearch.summaries);
  assert.equal((await bridge.handle(agent, { action: 'search', query: 'no-such-premise' })).recovery.checkpointDraft, null);
  agent.session.log.push(event(2, 'last committed event'));
  await bridge.dispose(); assert.equal(prompts.length, 0); assert.equal(hooks.size, 0);
  const reopened = await LcmMemory.open({ root: path.join(root, 'lcm'), sessionId: 'A', workspace: root });
  try { assert.equal(reopened.status().count, 3); } finally { reopened.close(); }
});
test('bridge reports capture failure and unavailable identity without pretending complete', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-lcm-bridge-'));
  const { bridge, agent } = host(root);
  t.after(async () => { await bridge.dispose(); fs.rmSync(root, { recursive: true, force: true }); });
  assert.equal((await bridge.handle({}, { action: 'status' })).available, false);
  await bridge.activate(agent); agent.session.log.push(event(0, 'conflict'));
  const status = await bridge.handle(agent, { action: 'status' });
  assert.equal(status.captureComplete, false); assert.equal(status.error.code, 'LCM_EVENT_CONFLICT');
  assert.equal(status.count, 1);
});
test('resuming an IG5 session reinstalls navigation without an explicit memory tool call', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-lcm-resume-'));
  const { bridge, hooks, agent, prompts } = host(root);
  t.after(async () => { await bridge.dispose(); fs.rmSync(root, { recursive: true, force: true }); });
  agent.session.log.push({ seq: 1, type: 'tool/call', data: { name: 'ig5_profile', arguments: {} } });
  await hooks.get('agent/created')({ agent });
  assert.equal(prompts.length, 1); assert.match(prompts[0].text(), /history is available/);
});
test('missing host lineage and depth exhaustion preserve subsequent original events', async t => {
  const { store } = await fixture(t);
  await store.capture(event(0));
  for (let seq = 1; seq <= 67; seq++) await store.capture({ seq, type: 'compaction/summary', data: { summary: '摘要' + seq, shadowedSeqs: [seq - 1] } });
  assert.equal(store.status().count, 68); assert(store.status().summaryFailures > 0);
  const raw = { seq: 68, type: 'compaction/summary', data: { summary: '来源缺失' } };
  assert.equal((await store.capture(raw)).summaryWarning.code, 'LCM_SUMMARY_SOURCES_UNAVAILABLE');
  await store.capture(event(69)); assert.equal(store.status().count, 70);
  assert.equal(all(store, store.eventRef(68)), JSON.stringify(raw));
});
test('a changed workspace cannot continue reading the old archive through the same agent object', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-lcm-scope-'));
  const { bridge, agent } = host(root);
  t.after(async () => { await bridge.dispose(); fs.rmSync(root, { recursive: true, force: true }); });
  await bridge.activate(agent); const ref = (await bridge.handle(agent, { action: 'search', query: 'initial' })).hits[0].ref;
  agent.session.header.cwd = path.join(root, 'changed');
  await assert.rejects(bridge.handle(agent, { action: 'read', ref }), { code: 'LCM_SCOPE_REQUIRED' });
});
