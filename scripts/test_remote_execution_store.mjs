// Real metadata persistence and independent-process contention. No target runs.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID, createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { test } from 'node:test';
import { RemoteExecutionStore, remoteExecutionKey } from '../source/remote_execution_store.js';

const binding = (target = path.resolve('owned-guest.exe')) => ({ guestCID: 112233, profileName: 'lab', profileSha256: 'a'.repeat(64),
  bundleSha256: 'b'.repeat(64), targetSha256: 'c'.repeat(64), targetId: 'owned-case', target, projectRoot: path.resolve('projects') });
const remote = (b, session = 'd'.repeat(64)) => ({ guestCID: b.guestCID, bundleSha256: b.bundleSha256, serverInstanceId: 'e'.repeat(32), sessionId: session });
const proof = row => ({ schema: 'ig5-guest-cleanup-v1', executionTerminal: true, guestCID: row.binding.guestCID,
  bundleSha256: row.binding.bundleSha256, serverInstanceId: row.remote.serverInstanceId, sessionId: row.remote.sessionId,
  targetSha256: row.binding.targetSha256, targetId: row.binding.targetId, allOwnedRootsExitedAndJobsClosed: true,
  nativeRoots: [{ rootId: '1'.repeat(32), pid: 1234, rootExitConfirmed: true, jobClosed: true, exitCode: 0 }] });

if (process.argv[2] === 'lease-child') {
  const store = new RemoteExecutionStore({ root: process.argv[3] });
  process.send({ ready: true });
  await new Promise(resolve => process.once('message', resolve));
  try {
    let row = store.reserve(binding(), 'child-' + process.pid);
    if (process.argv[4] === 'arm') { row = store.bind(row, remote(row.binding)); row = store.arm(row); }
    process.send({ reserved: true, row });
  } catch (error) { process.send({ reserved: false, code: error.code }); }
  process.disconnect();
} else {
  const hash = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
  async function fixture(run) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-remote-execution-'));
    try { await run(new RemoteExecutionStore({ root: dir }), dir); }
    finally {
      assert.equal(path.dirname(path.resolve(dir)), path.resolve(os.tmpdir()));
      assert(path.basename(dir).startsWith('ig5-remote-execution-'));
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
  function active(store) { const b = binding(); let row = store.reserve(b, 'agent-one'); row = store.bind(row, remote(b)); return store.arm(row); }

  test('cleanup evidence exposes stored terminal proof separately from pending custody without writes', () => fixture((store, root) => {
    let row = active(store); row = store.observeRoots(row, [{rootId:'1'.repeat(32),pid:1234}]);
    assert.equal(store.cleanupEvidence().entries.length,0);
    store.complete(row,proof(row));
    const before=hash(store.file), view=store.cleanupEvidence();
    assert.equal(view.entries.length,1);assert.equal(view.totalStoredCleanedGenerations,1);assert.equal(view.partial,false);
    const entry=view.entries[0];assert.equal(entry.status,'stored-terminal-receipt-verified');assert.equal(entry.nativeCleanupProved,true);
    assert.equal(entry.nonce,row.nonce);assert.equal(hash(entry.receiptPath),entry.receiptSha256);
    assert.equal(entry.nativeRoots[0].jobClosed,true);assert.match(view.scope,/not a new HMAC/);
    assert.equal(hash(store.file),before);
    fs.appendFileSync(entry.receiptPath,' ');
    const corrupt=store.cleanupEvidence();assert.equal(corrupt.entries[0].status,'unknown');assert.equal(corrupt.entries[0].nativeCleanupProved,false);
    assert.equal(corrupt.entries[0].nativeRoots,undefined);assert.equal(hash(store.file),before);
    assert.throws(()=>store.reserve(binding(),'agent-two'),{code:'REMOTE_LEASE_CORRUPT'});
    fs.unlinkSync(entry.receiptPath);
    assert.equal(store.cleanupEvidence().entries[0].status,'unknown');assert.equal(hash(store.file),before);
  }));

  test('cleanup evidence never promotes unarmed abandonment and is bounded to eight generations', () => fixture(store => {
    for(let i=0;i<10;i++){
      const b={...binding(path.resolve(`case-${i}.exe`)),targetSha256:createHash('sha256').update(String(i)).digest('hex')};
      const row=store.reserve(b,'agent-one');store.abandonUnarmed(row,true);
    }
    const before=hash(store.file),view=store.cleanupEvidence();
    assert.equal(view.entries.length,8);assert.equal(view.totalStoredCleanedGenerations,10);assert.equal(view.omitted,2);assert.equal(view.partial,true);
    assert(view.entries.every(e=>e.status==='unarmed-bridge-exit-only'&&e.nativeCleanupProved===false));
    assert.deepEqual(view.entries.map(e=>e.key),view.entries.map(e=>e.key).sort());assert.equal(hash(store.file),before);
  }));
  function child(root, mode = 'reserve') {
    const proc = spawn(process.execPath, [import.meta.filename, 'lease-child', root, mode], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
    let stderr = ''; proc.stderr.on('data', data => { stderr += data; });
    const ready = new Promise((resolve, reject) => { proc.once('message', resolve); proc.once('error', reject); });
    const result = new Promise((resolve, reject) => { proc.on('message', value => { if (Object.hasOwn(value, 'reserved')) resolve(value); }); proc.once('error', reject); });
    const exited = new Promise((resolve, reject) => proc.once('exit', code => code === 0 ? resolve() : reject(new Error(stderr || `child exit ${code}`))));
    return { proc, ready, result, exited };
  }

  test('armed execution survives bridge loss, store reconstruction and alias changes', async () => fixture((store, root) => {
    const row = active(store);
    store.uncertain(row, 'transport-lost');
    const reconstructed = new RemoteExecutionStore({ root });
    assert.equal(reconstructed.current(row.key).state, 'unknown');
    const alias = { ...binding(path.resolve('moved-copy.exe')), profileName: 'other-profile', profileSha256: 'f'.repeat(64) };
    assert.equal(remoteExecutionKey(alias), row.key);
    assert.throws(() => reconstructed.reserve(alias, 'another-agent'), { code: 'REMOTE_EXECUTION_RETAINED' });
  }));

  test('missing, new-session, wrong-target and incomplete cleanup never release an owner', async () => fixture(store => {
    const row = active(store); store.uncertain(row);
    const good = proof(row), before = hash(store.file);
    for (const change of [{ sessionId: 'f'.repeat(64) }, { serverInstanceId: 'f'.repeat(32) }, { guestCID: row.binding.guestCID+1 },
      { targetSha256: 'f'.repeat(64) }, { targetId: 'other' }, { bundleSha256: 'f'.repeat(64) }, { executionTerminal: false },
      { allOwnedRootsExitedAndJobsClosed: false }, { nativeRoots: [{ pid: 1234, rootExitConfirmed: false, jobClosed: true }] },
      { nativeRoots: [{ pid: 1234, rootExitConfirmed: true, jobClosed: false }] }]) {
      assert.throws(() => store.complete(row, { ...good, ...change }), { code: 'REMOTE_CLEANUP_UNCONFIRMED' });
      assert.equal(hash(store.file), before);
    }
    assert.throws(() => store.complete(row, null), { code: 'REMOTE_CLEANUP_UNCONFIRMED' });
    assert.equal(store.current(row.key).state, 'unknown');
  }));

  test('exact terminal cleanup is durable; old evidence cannot release a replacement generation', async () => fixture((store, root) => {
    const row = active(store), receipt = proof(row);
    const completed = store.complete(row, receipt);
    assert.equal(completed.state, 'cleaned');
    assert.equal(new RemoteExecutionStore({ root }).current(row.key).cleanup.sha256, completed.cleanup.sha256);
    const next = store.reserve(binding(), 'agent-two');
    assert.notEqual(next.nonce, row.nonce);
    assert.throws(() => store.complete(row, receipt), { code: 'STALE_REMOTE_LEASE' });
    const rebound = store.bind(next, remote(next.binding, 'f'.repeat(64)));
    store.arm(rebound);
    assert.throws(() => store.complete(rebound, receipt), { code: 'REMOTE_CLEANUP_UNCONFIRMED' });
    assert.equal(store.current(next.key).state, 'active');
  }));

  test('only an unarmed reservation with confirmed bridge exit can be abandoned', async () => fixture(store => {
    const first = store.reserve(binding(), 'agent-one');
    assert.throws(() => store.abandonUnarmed(first, false), { code: 'REMOTE_CLEANUP_UNCONFIRMED' });
    assert.equal(store.abandonUnarmed(first, true).cleanup.nativeDispatchAttempted, false);
    const armed = active(store);
    assert.throws(() => store.abandonUnarmed(armed, true), { code: 'REMOTE_CLEANUP_UNCONFIRMED' });
  }));

  test('a terminal transport event cannot undo a confirmed cleanup', async () => fixture(store => {
    const row = active(store); store.complete(row, proof(row));
    assert.equal(store.uncertain(row).state, 'cleaned');
  }));

  test('corrupted immutable cleanup evidence forbids a replacement execution', async () => fixture((store, root) => {
    const row = active(store), receipt = proof(row);
    const completed = store.complete(row, receipt);
    const file = path.join(root, 'remote-cleanup-receipts', completed.cleanup.sha256+'.json');
    fs.writeFileSync(file, 'different');
    assert.throws(() => store.complete(row, receipt), { code: 'REMOTE_LEASE_CORRUPT' });
    assert.throws(() => store.reserve(binding(), 'another-agent'), { code: 'REMOTE_LEASE_CORRUPT' });
  }));

  test('cleanup cannot omit or substitute a previously observed native root', async () => fixture(store => {
    let row = active(store);
    row = store.observeRoots(row, [{ rootId: '1'.repeat(32), pid: 1234 }]);
    const receipt = proof(row);
    assert.throws(() => store.complete(row, { ...receipt, nativeRoots: [] }), { code: 'REMOTE_CLEANUP_UNCONFIRMED' });
    assert.throws(() => store.complete(row, { ...receipt, nativeRoots: [{ ...receipt.nativeRoots[0], pid: 2222 }] }), { code: 'REMOTE_CLEANUP_UNCONFIRMED' });
    assert.equal(store.complete(row, receipt).state, 'cleaned');
  }));

  test('invalid legacy metadata and oversized metadata fail closed', async () => fixture((store, root) => {
    const row = active(store), data = JSON.parse(fs.readFileSync(store.file));
    delete data.remoteExecutions[row.key].nonce;
    fs.writeFileSync(store.file, JSON.stringify(data));
    assert.throws(() => new RemoteExecutionStore({ root }), { code: 'REMOTE_LEASE_CORRUPT' });
    fs.writeFileSync(store.file, Buffer.alloc(8*1024*1024+1, 32));
    assert.throws(() => new RemoteExecutionStore({ root }), { code: 'INPUT_LIMIT' });
  }));

  test('independent processes cannot both reserve the same guest target', async () => fixture(async (_store, root) => {
    const first = child(root), second = child(root);
    await Promise.all([first.ready, second.ready]); first.proc.send('go'); second.proc.send('go');
    const results = await Promise.all([first.result, second.result]);
    await Promise.all([first.exited, second.exited]);
    assert.equal(results.filter(row => row.reserved).length, 1);
    assert(['STORE_BUSY', 'REMOTE_EXECUTION_RETAINED'].includes(results.find(row => !row.reserved).code));
  }));

  test('real original host process exit does not prove guest cleanup', async () => fixture(async (_store, root) => {
    const owner = child(root, 'arm'); await owner.ready; owner.proc.send('go');
    const result = await owner.result; await owner.exited; assert(result.reserved);
    const reopened = new RemoteExecutionStore({ root });
    assert.equal(reopened.current(result.row.key).state, 'active');
    assert.throws(() => reopened.reserve(binding(), 'new-host-agent'), { code: 'REMOTE_EXECUTION_RETAINED' });
  }));
}
