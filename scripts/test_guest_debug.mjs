// Actual host lifecycle/profile implementation with real temporary metadata.
// Transport is a deterministic stand-in; no PE or VM is executed here.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { test } from 'node:test';
import { AsyncLocalStorage } from 'node:async_hooks';
import { EventEmitter } from 'node:events';
import { createHash, randomBytes } from 'node:crypto';
import { RemoteExecutionStore } from '../source/remote_execution_store.js';
import { ProjectStore } from '../source/project_store.js';
import { guestProfileConfiguration, loadGuestProfile, publicGuestProfile, guestTarget } from '../source/guest_debug_profile.js';
import { engineId } from '../engine_runtime.js';
import { attachWorker, workerLaunch } from '../source/worker_transport.js';
import { GUEST_RECOVERY_FIELDS, validateGuestRecoveryArgs } from '../source/guest_recovery.js';

const source = fs.readFileSync(new URL('../index.js', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const classSource = source.match(/class WorkerManager \{[\s\S]*?\n\}\n/)[0];
const errors = source.slice(source.indexOf('function publicEngineError('), source.indexOf('// ── Worker 池'));
const publicEngineError = vm.runInNewContext(errors + '\npublicEngineError;');
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const WorkerManager = vm.runInNewContext(classSource + '\nWorkerManager;', {
  path, fs, createHash, process, Buffer, AsyncLocalStorage, ProjectStore, RemoteExecutionStore,
  engineId, loadGuestProfile, guestTarget, publicEngineError, attachWorker,
  setTimeout, clearTimeout, HERE: path.resolve('.'), diagAppend() {},
  terminateTree(proc) { proc.exitCode = -1; proc.emit('exit', -1); },
});
async function fixture(run) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-guest-debug-'));
  try { await run(root); }
  finally {
    assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir()));
    assert(path.basename(root).startsWith('ig5-guest-debug-')); fs.rmSync(root, { recursive: true, force: true });
  }
}
function prepare(root) {
  const key = path.join(root, 'pairing.key'), profileFile = path.join(root, 'guest.json');
  const secret = randomBytes(32); fs.writeFileSync(key, secret);
  const profile = { schema: 'ig5-vmci-guest-profile-v1', guestCID: 112233, port: 53215, guestLabel: 'Owned test guest',
    bundleSha256: 'b'.repeat(64), pairingKeyRef: { path: key, sha256: digest(secret) }, targets: [{ id: 'owned-case', sha256: 'c'.repeat(64) }] };
  fs.writeFileSync(profileFile, JSON.stringify(profile));
  const cfg = { host: { id: 'win32-x64' }, projectRoot: path.join(root, 'projects'), remoteExecutionRoot: path.join(root, 'remote'),
    guestDebugProfiles: guestProfileConfiguration({ lab: profileFile }), defaultEngine: 'reverse', defaultDebugger: 'x64dbg', maxSessions: 3 };
  return { cfg, profile, profileFile, secret, snapshot: loadGuestProfile(cfg, 'lab') };
}
function owned(mgr, snapshot, root, state = 'active') {
  const target = path.join(root, 'target.exe'), key = mgr.sessionKey(target, 'x64dbg');
  let lease = mgr.remoteStore().reserve({ guestCID: snapshot.profile.guestCID, profileName: snapshot.name, profileSha256: snapshot.sha256,
    bundleSha256: snapshot.profile.bundleSha256, targetSha256: 'c'.repeat(64), targetId: 'owned-case', target, projectRoot: mgr.cfg.projectRoot }, 'agent-one');
  lease = mgr.remoteStore().bind(lease, { guestCID: snapshot.profile.guestCID, bundleSha256: snapshot.profile.bundleSha256,
    serverInstanceId: 'e'.repeat(32), sessionId: 'f'.repeat(64) });
  if (state === 'active') lease = mgr.remoteStore().arm(lease);
  const proc = new EventEmitter(); Object.assign(proc, { pid: 12345, exitCode: null, signalCode: null });
  const session = { key, target, engine: 'x64dbg', guestProfile: snapshot, remoteLease: lease, pending: new Map(), proc, ready: true,
    sha256: 'c'.repeat(64), controlOwner: 'agent-one', runtime: { state: 'suspended', runId: '1'.repeat(32), stopSeq: 1 },
    executionLocation: { kind: 'vmci-guest', profileSha256: snapshot.sha256, ...lease.remote } };
  mgr.sessions.set(key, session); mgr.debugOwners.set(target.toLowerCase(), 'x64dbg');
  return session;
}
const proof = session => ({ schema: 'ig5-guest-cleanup-v1', executionTerminal: true, ...session.remoteLease.remote,
  targetId: 'owned-case', targetSha256: session.sha256, nativeRoots: [], allOwnedRootsExitedAndJobsClosed: true });

test('profile inspection redacts pairing path/bytes and fixes all profile bytes', () => fixture(root => {
  const { cfg, snapshot, secret, profileFile } = prepare(root), output = JSON.stringify(publicGuestProfile(snapshot));
  assert(!output.includes(secret.toString('hex'))); assert(!output.includes('pairing.key'));
  assert.equal(publicGuestProfile(snapshot).authenticatedStartupVerified, false);
  assert.equal(publicGuestProfile(snapshot).bindingSha256, digest(fs.readFileSync(profileFile)));
  fs.appendFileSync(profileFile, ' ');
  assert.throws(() => loadGuestProfile(cfg, 'lab', snapshot.sha256), /changed/);
}));
test('profile rejects unknown fields, duplicate target hashes, wrong key and unsupported host', () => fixture(root => {
  const { cfg, profile, profileFile } = prepare(root);
  for (const change of [{ guestCID: 2 }, { port: 80 }, { arbitraryPath: 'x' }, { targets: [...profile.targets, { id: 'alias', sha256: 'c'.repeat(64) }] },
    { pairingKeyRef: { ...profile.pairingKeyRef, sha256: 'd'.repeat(64) } }]) {
    fs.writeFileSync(profileFile, JSON.stringify({ ...profile, ...change }));
    assert.throws(() => loadGuestProfile(cfg, 'lab'), { code: 'INVALID_GUEST_PROFILE' });
  }
  assert.throws(() => guestProfileConfiguration({ lab: 'relative.json' }));
  assert.throws(() => loadGuestProfile({ ...cfg, host: { id: 'darwin-arm64' } }, 'lab'), /Windows x64/);
}));
test('guest worker receives profile path/digest only; local launch is unchanged and hidden', () => fixture(root => {
  const { cfg, snapshot, secret } = prepare(root);
  cfg.x64dbg = { available: true, pythonExe: 'python.exe', manifest: 'manifest.json' }; cfg.stateRoot = root;
  const remote = workerLaunch({ ...cfg, guestExecutionProfile: snapshot }, 'x64dbg', root);
  assert(remote.args.includes(path.join(root, 'adapters', 'vmci', 'adapter.py')));
  assert(remote.args.includes(snapshot.sha256)); assert(!JSON.stringify(remote).includes(secret.toString('hex')));
  assert.equal(remote.options.windowsHide, true);
  assert(workerLaunch(cfg, 'x64dbg', root).args.includes(path.join(root, 'adapters', 'x64dbg', 'adapter.py')));
}));
test('bridge kill retains guest owner and survives WorkerManager reconstruction', () => fixture(root => {
  const { cfg, snapshot } = prepare(root), mgr = new WorkerManager(cfg), session = owned(mgr, snapshot, root);
  assert.equal(mgr.killSession(session.key), false);
  assert.equal(mgr.sessions.get(session.key), session); assert.equal(mgr.remoteStore().current(session.remoteLease.key).state, 'unknown');
  assert.equal(session.controlOwner, 'agent-one'); assert.equal(session.runtime.cleanupRequired, true);
  const next = new WorkerManager(cfg); assert.equal(next.remoteExecutionStatus().length, 1);
  assert.throws(() => next.remoteStore().reserve(session.remoteLease.binding, 'agent-two'), /retained|active or unknown/);
}));
test('only exact authenticated terminal close releases guest custody', () => fixture(root => {
  const { cfg, snapshot } = prepare(root), mgr = new WorkerManager(cfg), session = owned(mgr, snapshot, root);
  const value = { authenticatedGuestResponse: true, executionLocation: session.executionLocation, guestCleanupHMACVerified: true, guestCleanup: proof(session) };
  assert.throws(() => mgr.acceptRemoteResult(session, 'dbg', value), /terminal close/);
  assert.throws(() => mgr.acceptRemoteResult(session, 'close', { ...value, guestCleanupHMACVerified: false }), /terminal close/);
  assert.throws(() => mgr.acceptRemoteResult(session, 'close', { ...value, executionLocation: { ...value.executionLocation, sessionId: '0'.repeat(64) } }), /identity/);
  assert.equal(mgr.remoteStore().current(session.remoteLease.key).state, 'active');
  mgr.acceptRemoteResult(session, 'close', value);
  assert.equal(mgr.killSession(session.key), true); assert(!mgr.sessions.has(session.key)); assert(!mgr.debugOwners.has(session.target.toLowerCase()));
}));
test('late old bridge failure never overwrites the replacement local owner', () => fixture(root => {
  const { cfg, snapshot } = prepare(root), mgr = new WorkerManager(cfg), old = owned(mgr, snapshot, root);
  mgr.remoteStore().complete(old.remoteLease, proof(old));
  const next = mgr.remoteStore().reserve(old.remoteLease.binding, 'agent-two');
  mgr.sessions.set(old.key, { key: old.key, engine: 'reverse' }); mgr.debugOwners.set(old.target.toLowerCase(), 'reverse');
  assert.equal(mgr.retainRemoteExecution(old), true);
  assert.equal(mgr.remoteStore().current(next.key).state, 'reserved'); assert.equal(mgr.debugOwners.get(old.target.toLowerCase()), 'reverse');
}));
test('unarmed abandon waits for actual bridge exit', () => fixture(root => {
  const { cfg, snapshot } = prepare(root), mgr = new WorkerManager(cfg), session = owned(mgr, snapshot, root, 'reserved');
  mgr.retainRemoteExecution(session);
  assert.equal(mgr.remoteStore().current(session.remoteLease.key).state, 'reserved');
  assert(mgr.sessions.has(session.key)); session.proc.exitCode = 0; session.proc.emit('exit', 0);
  assert.equal(mgr.remoteStore().current(session.remoteLease.key).state, 'cleaned'); assert(!mgr.sessions.has(session.key));
}));
test('guest execution destination cannot silently switch, even after bridge loss', () => fixture(async root => {
  const { cfg, snapshot } = prepare(root), mgr = new WorkerManager(cfg), session = owned(mgr, snapshot, root);
  await assert.rejects(mgr.open(session.target, false, { engine: 'x64dbg', internal: true }), /destination changed/);
  await assert.rejects(mgr.performDebug({ ...session, engine: 'reverse' }, { op: 'state', backend: 'x64dbg' }, 1000), /Every guest/);
  mgr.killSession(session.key);
  await assert.rejects(mgr.open(session.target, false, { engine: 'x64dbg', internal: true, guestProfile: snapshot }), /retained/);
}));
test('debug stop/no-task keeps remote custody until terminal close', () => fixture(async root => {
  const { cfg, snapshot } = prepare(root), mgr = new WorkerManager(cfg), session = owned(mgr, snapshot, root);
  mgr.open = async () => ({}); mgr.rpc = async () => ({ ok: true, state: 'no-task' });
  await mgr.scope.run({ agentId: 'agent-one' }, () => mgr.performDebug({ ...session, engine: 'reverse' },
    { op: 'stop', backend: 'x64dbg', guest_profile: snapshot.name, guest_binding_sha256: snapshot.sha256 }, 1000));
  assert.equal(mgr.remoteStore().current(session.remoteLease.key).state, 'active'); assert.equal(mgr.debugOwners.get(session.target.toLowerCase()), 'x64dbg');
}));

test('recovery diagnostics retain exact whitelist and never echo values or mutate input', () => {
  const original = ['target', 'engine', 'op', 'backend', 'guest_profile', 'guest_binding_sha256', 'control'];
  assert.deepEqual([...GUEST_RECOVERY_FIELDS], original);
  assert(Object.isFrozen(GUEST_RECOVERY_FIELDS));
  const minimal = { target: 'owned.exe', op: 'recover', backend: 'x64dbg', guest_profile: 'lab', guest_binding_sha256: 'a'.repeat(64) };
  const before = JSON.stringify(minimal);
  validateGuestRecoveryArgs(minimal);
  validateGuestRecoveryArgs({ ...minimal, engine: 'x64dbg', control: 'takeover' });
  assert.equal(JSON.stringify(minimal), before);
  for (const key of ['timeout', 'expected_run_id', 'expected_stop_seq', 'path', 'reg', 'value', 'record_trace', 'arbitrary']) {
    const args = { ...minimal, [key]: 'sensitive-test-value' }, bytes = JSON.stringify(args);
    assert.throws(() => validateGuestRecoveryArgs(args), error => {
      assert.equal(error.code, 'INVALID_GUEST_RECOVERY_ARGS');
      assert.match(error.message, /Omit timeout/);
      assert.match(error.message, /No cleanup was confirmed/);
      assert(!error.message.includes('sensitive-test-value'));
      return true;
    });
    assert.equal(JSON.stringify(args), bytes);
  }
  assert(source.includes('validateGuestRecoveryArgs(args);'));
});

test('missing retained execution is actionable, not remote cleanup proof', () => fixture(async root => {
  const { cfg, snapshot } = prepare(root), mgr = new WorkerManager(cfg);
  const before = mgr.remoteStore().list();
  await assert.rejects(mgr.recoverGuest(path.join(root, 'target.exe'), {
    guest_profile: snapshot.name, guest_binding_sha256: snapshot.sha256,
  }), error => {
    assert.equal(error.code, 'GUEST_RECOVERY_NOT_FOUND');
    assert.match(error.message, /does not confirm remote cleanup/);
    assert.match(error.message, /ig5_status remoteExecutions/);
    return true;
  });
  assert.deepEqual(mgr.remoteStore().list(), before);
}));
