// Review probes: assertions confirm defects, not product acceptance.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { AnalysisArtifacts } from '../../../source/analysis_artifacts.js';
import { ProjectStore } from '../../../source/project_store.js';
import { WorkerManager } from '../../../source/worker_manager.js';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-review-36-'));
const observations = [];

// R6: A second writer advances the directory generation without merging rows.
const a = new AnalysisArtifacts(path.join(root, 'history'));
const b = new AnalysisArtifacts(path.join(root, 'history'));
const first = a.save({ kind: 'fixture', action: 'first', result: {} });
const second = b.save({ kind: 'fixture', action: 'second', result: {} });
const listing = await b.list();
assert.equal(listing.total, 1);
assert.equal(listing.partial, false);
assert.deepEqual(listing.items.map(item => item.id), [second.id]);
assert.equal(b.get(first.id).id, first.id);
observations.push({ id: 'R6', committedReports: 2, listedTotal: listing.total,
  partial: listing.partial, omittedReportStillReadable: true });
await a.dispose(); await b.dispose();

// R7: A foreign-host lock is accepted and moved based on the local PID.
// No live lock or user data is touched; only a synthetic lock in this temp root.
const store = new ProjectStore({ root: path.join(root, 'foreign-lock') });
fs.mkdirSync(store.lockFile);
const owner = { schema: 1, pid: process.pid, creationIdentity: '1', nonce: randomUUID(),
  hostName: os.hostname() + '-another-host', platform: process.platform };
fs.writeFileSync(path.join(store.lockFile, 'owner.json'), JSON.stringify(owner));
assert.equal(store._recoverLock(), true);
assert.equal(fs.existsSync(store.lockFile), false);
observations.push({ id: 'R7', foreignHost: owner.hostName, foreignLockReclaimed: true });

// R8: Metadata failure replaces the original partial-commit receipt.
const mgr = new WorkerManager({ projectRoot: path.join(root, 'manager'), artifactDir: root,
  defaultEngine: 'reverse', reverseProvider: 'commercial', maxSessions: 3,
  requestTimeoutMs: 1000, openTimeoutMs: 1000 });
mgr.projects.open = target => ({ target, projectId: 'p', artifactId: 'a', sha256: 'a'.repeat(64) });
mgr.projects.attachEngine = () => ({ attachmentId: 'attachment', dbRevision: 0 });
mgr.projects.bumpRevision = () => { throw Object.assign(new Error('fixture metadata busy'), { code: 'STORE_BUSY' }); };
let killed = false;
mgr.killSession = () => { killed = true; };
mgr.spawnWorker = () => {
  const proc = new EventEmitter();
  Object.assign(proc, { pid: 424243, exitCode: null, stdout: new EventEmitter(), stderr: new EventEmitter(), stdin: new EventEmitter() });
  proc.stdin.write = line => {
    const request = JSON.parse(line);
    setImmediate(() => proc.stdout.emit('data', Buffer.from(JSON.stringify(request.method === 'open'
      ? { id: request.id, result: { databasePath: 'fixture-db' } }
      : { id: request.id, error: { code: 'SAVE_FAILED', message: 'fixture partial write', committed: true,
          saved: false, partial_commit: true, recoveryRequired: true, journalId: 'fixture-journal', revision: 7 } }) + '\n')));
  };
  setImmediate(() => proc.stdout.emit('data', Buffer.from('{"ig5":"ready"}\n')));
  return proc;
};
const target = path.join(root, 'fixture.bin');
await mgr.open(target, false);
let receipt;
try { await mgr.rpc(mgr.get(target), 'patch', { ea: '0x1000', hex: '22' }); }
catch (error) { receipt = error; }
assert.equal(killed, true);
assert.ok(receipt);
assert.equal(receipt.committed, undefined);
assert.equal(receipt.recoveryRequired, undefined);
assert.equal(receipt.journalId, undefined);
observations.push({ id: 'R8', message: receipt.message, sessionRecycled: killed,
  originalCommitEvidencePreserved: false, originalJournalIdPreserved: false });
mgr.get(target).client.dispose();

console.log(JSON.stringify({ nativeLaunches: 0, fixtureDirectory: root, observations }, null, 2));
