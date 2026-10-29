// 2026-10-24 独立评审 R6/R7/R8 的回归测试：复现脚本 docs/review/review-20261024/reproduce_node.mjs 的断言取反。
// 全部使用临时目录与模拟 worker 进程，不启动样本、调试器或 JVM。
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { AnalysisArtifacts } from '../source/analysis_artifacts.js';
import { ProjectStore } from '../source/project_store.js';
import { WorkerManager } from '../source/worker_manager.js';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-review-fixes-'));
test.after(() => fs.rmSync(root, { recursive: true, force: true }));

test('R6: two store instances on one history directory never lose a report from the listing', async () => {
  const a = new AnalysisArtifacts(path.join(root, 'history')), b = new AnalysisArtifacts(path.join(root, 'history'));
  try {
    const first = a.save({ kind: 'fixture', action: 'first', result: {} });
    const second = b.save({ kind: 'fixture', action: 'second', result: {} });
    for (const store of [a, b]) {
      const listing = await store.list();
      assert.equal(listing.total, 2, 'both committed reports must be listed');
      assert.deepEqual(listing.items.map(item => item.id).sort(), [first.id, second.id].sort());
      assert.equal(listing.partial, false);
    }
  } finally { await a.dispose(); await b.dispose(); }
});

test('R6: a later save by the same instance is listed too (cache is rebuilt, not trusted)', async () => {
  const store = new AnalysisArtifacts(path.join(root, 'history-single'));
  try {
    const ids = [];
    for (const action of ['a', 'b', 'c']) { ids.push(store.save({ kind: 'fixture', action, result: {} }).id); await store.list(); }
    assert.deepEqual((await store.list()).items.map(item => item.id).sort(), ids.sort());
  } finally { await store.dispose(); }
});

test('R6: a verified incremental cache keeps hitting; an unseen foreign record forces exactly one rescan', async () => {
  const dir = path.join(root, 'history-verify');
  const a = new AnalysisArtifacts(dir), b = new AnalysisArtifacts(dir);
  try {
    a.save({ kind: 'fixture', action: 'a1', result: {} });
    a.save({ kind: 'fixture', action: 'a2', result: {} });
    const verified = await a.list();
    assert.equal(verified.total, 2); assert.equal(verified.cacheHit, true, 'count check passes -> still served from the cache');
    assert.equal(verified.indexBytesRead, 0, 'no metadata file is re-read when the count matches');
    assert.equal((await a.list()).cacheHit, true, 'the cache is trusted again after verification');
    b.save({ kind: 'fixture', action: 'b1', result: {} }); // a foreign writer commits after a's cache was verified
    const rescan = await a.list();
    assert.equal(rescan.total, 3, 'the stamp changed, so a rescans and sees the foreign record'); assert.equal(rescan.cacheHit, false);
    assert.equal((await a.list()).cacheHit, true);
  } finally { await a.dispose(); await b.dispose(); }
});

function lockOwner(extra = {}) {
  return { schema: 1, pid: process.pid, creationIdentity: '1', nonce: randomUUID(), hostName: os.hostname(), platform: process.platform, ...extra };
}
function storeWithLock(name, owner) {
  const store = new ProjectStore({ root: path.join(root, name) });
  fs.mkdirSync(store.lockFile);
  fs.writeFileSync(path.join(store.lockFile, 'owner.json'), JSON.stringify(owner));
  return store;
}

test('R7: a lock owned by another host is never reclaimed from local PID probing', () => {
  for (const foreign of [{ hostName: os.hostname() + '-another-host' }, { platform: process.platform === 'win32' ? 'linux' : 'win32' }]) {
    const store = storeWithLock('foreign-' + Object.keys(foreign)[0], lockOwner(foreign));
    assert.equal(store._recoverLock(), false, 'foreign owner must be treated as live');
    assert(fs.existsSync(store.lockFile), 'the foreign lock must be left intact');
  }
});

test('R7: a legacy lock without host identity is left intact and reported as unrecognized', () => {
  const { hostName, platform, ...legacy } = lockOwner();
  const store = storeWithLock('legacy', legacy);
  assert.throws(() => store._recoverLock(), error => error.code === 'STORE_BUSY' && /Unrecognized project lock/.test(error.message));
  assert(fs.existsSync(store.lockFile));
});

test('R7: new locks record host and platform, and a same-host dead owner is still recoverable', () => {
  const store = new ProjectStore({ root: path.join(root, 'fresh') });
  const owner = store._acquireLock();
  assert.equal(owner.hostName, os.hostname()); assert.equal(owner.platform, process.platform);
  const onDisk = JSON.parse(fs.readFileSync(path.join(store.lockFile, 'owner.json'), 'utf8'));
  assert.equal(onDisk.hostName, os.hostname()); assert.equal(onDisk.platform, process.platform);
  store._releaseLock(owner);
  // 本机、PID 创建标识不同 → 本机 PID 被复用 → 可回收（原有行为不变）
  const reused = storeWithLock('same-host-reused', lockOwner({ creationIdentity: 'definitely-not-this-process' }));
  assert.equal(reused._recoverLock(), true);
});

function managerWithWorker(name, respond) {
  const mgr = new WorkerManager({ projectRoot: path.join(root, name), artifactDir: root, defaultEngine: 'reverse',
    reverseProvider: 'commercial', maxSessions: 3, requestTimeoutMs: 1000, openTimeoutMs: 1000 });
  mgr.projects.open = target => ({ target, projectId: 'p', artifactId: 'a', sha256: 'a'.repeat(64) });
  mgr.projects.attachEngine = () => ({ attachmentId: 'attachment', dbRevision: 0 });
  mgr.projects.bumpRevision = () => { throw Object.assign(new Error('fixture metadata busy'), { code: 'STORE_BUSY' }); };
  const state = { killed: false };
  mgr.killSession = () => { state.killed = true; };
  mgr.spawnWorker = () => {
    const proc = new EventEmitter();
    Object.assign(proc, { pid: 424243, exitCode: null, stdout: new EventEmitter(), stderr: new EventEmitter(), stdin: new EventEmitter() });
    proc.stdin.write = line => {
      const request = JSON.parse(line);
      setImmediate(() => proc.stdout.emit('data', Buffer.from(JSON.stringify(request.method === 'open'
        ? { id: request.id, result: { databasePath: 'fixture-db' } } : { id: request.id, ...respond(request) }) + '\n')));
    };
    setImmediate(() => proc.stdout.emit('data', Buffer.from('{"ig5":"ready"}\n')));
    return proc;
  };
  return { mgr, state };
}

test('R8: a metadata failure after a partial-commit error keeps the original commit receipt', async () => {
  const { mgr, state } = managerWithWorker('mgr-error', () => ({ error: { code: 'SAVE_FAILED', message: 'fixture partial write',
    committed: true, saved: false, partial_commit: true, recoveryRequired: true, journalId: 'fixture-journal', revision: 7 } }));
  const target = path.join(root, 'fixture-a.bin');
  await mgr.open(target, false);
  let receipt;
  try { await mgr.rpc(mgr.get(target), 'patch', { ea: '0x1000', hex: '22' }); } catch (error) { receipt = error; }
  mgr.get(target)?.client?.dispose?.();
  assert.equal(state.killed, true, 'the session is still recycled');
  assert.ok(receipt, 'the call must fail');
  assert.equal(receipt.code, 'SAVE_FAILED'); assert.equal(receipt.committed, true); assert.equal(receipt.saved, false);
  assert.equal(receipt.partial_commit, true); assert.equal(receipt.recoveryRequired, true);
  assert.equal(receipt.journalId, 'fixture-journal'); assert.equal(receipt.revision, 7);
  assert.equal(receipt.metadataFailure?.code, 'STORE_BUSY', 'the metadata failure is reported alongside, not instead');
  assert.match(receipt.message, /revision metadata is unavailable/); assert.match(receipt.message, /fixture partial write/);
});

test('R8: a metadata failure after a successful worker result keeps the operation result', async () => {
  const { mgr, state } = managerWithWorker('mgr-result', () => ({ result: { ok: true, applied: true, committed: true, saved: true, revision: 9, journalId: 'ok-journal' } }));
  const target = path.join(root, 'fixture-b.bin');
  await mgr.open(target, false);
  let failure;
  try { await mgr.rpc(mgr.get(target), 'patch', { ea: '0x1000', hex: '22' }); } catch (error) { failure = error; }
  mgr.get(target)?.client?.dispose?.();
  assert.equal(state.killed, true); assert.ok(failure);
  assert.equal(failure.operationCompleted, true); assert.equal(failure.operationResult.applied, true);
  assert.equal(failure.committed, true); assert.equal(failure.journalId, 'ok-journal'); assert.equal(failure.revision, 9);
  assert.equal(failure.metadataFailure?.code, 'STORE_BUSY'); assert.match(failure.message, /could not be committed/);
});
