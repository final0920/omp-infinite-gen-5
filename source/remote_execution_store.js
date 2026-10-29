import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { ProjectStore } from './project_store.js';
import { readStableFile } from './analysis_artifacts.js';

const hash = value => createHash('sha256').update(value).digest('hex');
const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value);
const opaque = value => typeof value === 'string' && /^[a-f0-9]{32}$/.test(value);
const identifier = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(value);
const integer = (value, minimum, maximum) => Number.isSafeInteger(value) && value >= minimum && value <= maximum;
const copy = value => structuredClone(value);
const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
const canonical = value => JSON.stringify(value, (_key, item) => item && typeof item === 'object' && !Array.isArray(item)
  ? Object.fromEntries(Object.keys(item).sort().map(key => [key, item[key]])) : item);

export function remoteExecutionKey(binding) {
  if (!binding || !integer(binding.guestCID, 3, 0xfffffffe) || !digest(binding.targetSha256)) fail('INVALID_GUEST_BINDING', 'Guest CID and exact target SHA-256 are required');
  // Profile aliases and local target paths must not permit duplicate execution.
  return hash(`${binding.guestCID}:${binding.targetSha256}`);
}

function validBinding(binding) {
  return binding && integer(binding.guestCID, 3, 0xfffffffe) && identifier(binding.profileName)
    && digest(binding.profileSha256) && digest(binding.bundleSha256) && digest(binding.targetSha256)
    && identifier(binding.targetId) && typeof binding.target === 'string' && binding.target.length <= 32767 && path.isAbsolute(binding.target)
    && typeof binding.projectRoot === 'string' && binding.projectRoot.length <= 32767 && path.isAbsolute(binding.projectRoot)
    && Object.keys(binding).every(key => ['guestCID', 'profileName', 'profileSha256', 'bundleSha256', 'targetSha256', 'targetId', 'target', 'projectRoot'].includes(key));
}

function validRemote(value, binding) {
  return value && value.guestCID === binding.guestCID && value.bundleSha256 === binding.bundleSha256
    && opaque(value.serverInstanceId) && digest(value.sessionId)
    && Object.keys(value).every(key => ['guestCID', 'bundleSha256', 'serverInstanceId', 'sessionId'].includes(key));
}

function recordShape(row, key) {
  return row && row.schema === 'ig5-remote-execution-lease-v1' && row.key === key && uuid(row.nonce)
    && ['reserved', 'active', 'unknown', 'cleaned'].includes(row.state) && integer(row.revision, 1, Number.MAX_SAFE_INTEGER)
    && validBinding(row.binding) && remoteExecutionKey(row.binding) === key
    && (row.remote === null || validRemote(row.remote, row.binding)) && integer(row.hostPid, 1, 0xffffffff)
    && typeof row.agentId === 'string' && row.agentId.length <= 256
    && Array.isArray(row.observedRoots) && row.observedRoots.length <= 256
    && row.observedRoots.every(root => root && opaque(root.rootId) && integer(root.pid, 1, 0xffffffff))
    && new Set(row.observedRoots.map(root => root.rootId)).size === row.observedRoots.length;
}

function validReceipt(row, receipt) {
  return row.remote && receipt && receipt.schema === 'ig5-guest-cleanup-v1' && receipt.executionTerminal === true
    && receipt.guestCID === row.binding.guestCID && receipt.bundleSha256 === row.binding.bundleSha256
    && receipt.serverInstanceId === row.remote.serverInstanceId && receipt.sessionId === row.remote.sessionId
    && receipt.targetSha256 === row.binding.targetSha256 && receipt.targetId === row.binding.targetId
    && Array.isArray(receipt.nativeRoots) && receipt.nativeRoots.length <= 256 && receipt.allOwnedRootsExitedAndJobsClosed === true
    && receipt.nativeRoots.every(root => root && opaque(root.rootId) && integer(root.pid, 1, 0xffffffff) && root.rootExitConfirmed === true && root.jobClosed === true)
    && new Set(receipt.nativeRoots.map(root => root.rootId)).size === receipt.nativeRoots.length
    && row.observedRoots.every(observed => receipt.nativeRoots.some(root => root.rootId === observed.rootId && root.pid === observed.pid));
}

/** Dedicated metadata file, reusing the existing nonce/OS-owner lock and atomic
 * ProjectStore commit. Its empty project/database tables are never opened.
 * Host/bridge death is deliberately NOT a remote execution recovery criterion.
 */
export class RemoteExecutionStore extends ProjectStore {
  _read() {
    if (!fs.existsSync(this.file)) return super._read();
    const data = JSON.parse(readStableFile(this.file, 8 * 1024 * 1024).data.toString('utf8'));
    if (data.schemaVersion !== 1 || !integer(data.revision, 0, Number.MAX_SAFE_INTEGER)
        || ['projects', 'artifacts', 'targets', 'databases', 'attachments', 'runtimes'].some(key => !data[key] || typeof data[key] !== 'object' || Array.isArray(data[key])))
      fail('REMOTE_LEASE_CORRUPT', 'Unsupported remote execution metadata schema');
    this._records(data);
    return data;
  }

  _budget(data) {
    if (Buffer.byteLength(JSON.stringify(data, null, 2), 'utf8') + 1 > 8 * 1024 * 1024)
      fail('REMOTE_LEASE_LIMIT', 'Remote execution metadata exceeds 8 MiB; no owner was evicted');
  }

  _records(data) {
    const rows = data.remoteExecutions ??= {};
    if (!rows || typeof rows !== 'object' || Array.isArray(rows) || Object.keys(rows).length > 1024)
      fail('REMOTE_LEASE_CORRUPT', 'Remote execution metadata is invalid or exceeds 1024 targets');
    for (const [key, row] of Object.entries(rows)) if (!digest(key) || !recordShape(row, key))
      fail('REMOTE_LEASE_CORRUPT', 'An unrecognized remote execution owner was retained');
    return rows;
  }

  list() { return Object.values(this._records(this._read())).map(copy); }

  _storedCleanupReceipt(row) {
    const meta = row.cleanup;
    if (meta?.kind !== 'paired-guest-terminal-receipt' || !digest(meta.sha256) || !integer(meta.bytes, 1, 128 * 1024))
      fail('REMOTE_LEASE_CORRUPT', 'Prior guest cleanup reference is invalid');
    const file = path.join(this.root, 'remote-cleanup-receipts', meta.sha256 + '.json');
    const bytes = readStableFile(file, 128 * 1024).data;
    if (bytes.length !== meta.bytes || hash(bytes) !== meta.sha256)
      fail('REMOTE_LEASE_CORRUPT', 'Prior guest cleanup evidence differs; execution remains retained');
    const receipt = JSON.parse(bytes.toString('utf8'));
    if (!validReceipt(row, receipt)) fail('REMOTE_LEASE_CORRUPT', 'Prior guest cleanup binding differs; execution remains retained');
    return { file, receipt };
  }

  // Pending custody and durable historical receipts are different views.
  // Bounded to eight current cleaned generations / 1 MiB of receipt reads.
  // This is read-only stored-evidence validation, never a fresh HMAC exchange
  // or permission to operate on a process/newer generation.
  cleanupEvidence() {
    const rows = this.list().filter(row => row.state === 'cleaned').sort((a, b) => a.key.localeCompare(b.key));
    const entries = rows.slice(0, 8).map(row => {
      const summary = { key: row.key, nonce: row.nonce, revision: row.revision, target: row.binding.target,
        targetSha256: row.binding.targetSha256, guestCID: row.binding.guestCID, profile: row.binding.profileName,
        profileSha256: row.binding.profileSha256, status: 'unknown', nativeCleanupProved: false };
      if (row.cleanup?.kind === 'unarmed-local-bridge-exited' && row.cleanup.nativeDispatchAttempted === false)
        return { ...summary, status: 'unarmed-bridge-exit-only', nativeDispatchAttempted: false };
      try {
        const { file, receipt } = this._storedCleanupReceipt(row);
        return { ...summary, status: 'stored-terminal-receipt-verified', nativeCleanupProved: true,
          receiptPath: file, receiptSha256: row.cleanup.sha256, receiptBytes: row.cleanup.bytes,
          originalRemoteSession: row.remote, nativeRoots: receipt.nativeRoots.map(r => ({ rootId: r.rootId, pid: r.pid,
            rootExitConfirmed: r.rootExitConfirmed, jobClosed: r.jobClosed })) };
      } catch { return { ...summary, reason: 'Stored receipt is missing, corrupt or does not bind the original generation' }; }
    });
    return { entries, totalStoredCleanedGenerations: rows.length, omitted: Math.max(0, rows.length - entries.length),
      partial: rows.length > entries.length, order: 'lease-key-ascending',
      scope: 'Stored receipt bytes and original binding only; not a new HMAC exchange, current process liveness, complete history or execution authority' };
  }

  current(key) {
    if (!digest(key)) fail('INVALID_REMOTE_LEASE', 'Invalid remote execution key');
    return copy(this._records(this._read())[key] ?? null);
  }

  reserve(binding, agentId) {
    if (!validBinding(binding) || typeof agentId !== 'string' || !agentId || agentId.length > 256)
      fail('INVALID_GUEST_BINDING', 'Explicit immutable guest/target identity and agent are required');
    const key = remoteExecutionKey(binding);
    return this._write(data => {
      const rows = this._records(data), prior = rows[key];
      if (prior && prior.state !== 'cleaned') fail('REMOTE_EXECUTION_RETAINED', 'This guest target has an active or unknown execution; recover its exact cleanup receipt before starting again');
      if (prior) {
        if (prior.cleanup?.kind === 'paired-guest-terminal-receipt') {
          this._storedCleanupReceipt(prior);
        } else if (prior.cleanup?.kind !== 'unarmed-local-bridge-exited' || prior.cleanup.nativeDispatchAttempted !== false)
          fail('REMOTE_LEASE_CORRUPT', 'Prior guest cleanup evidence is missing; execution remains retained');
      }
      if (!prior && Object.keys(rows).length >= 1024) fail('REMOTE_LEASE_LIMIT', 'Remote execution target limit reached; no owner was evicted');
      const revision = (prior?.revision ?? 0) + 1;
      if (!Number.isSafeInteger(revision)) fail('REMOTE_LEASE_LIMIT', 'Remote execution revision exhausted');
      const row = rows[key] = { schema: 'ig5-remote-execution-lease-v1', key, nonce: randomUUID(), revision,
        state: 'reserved', binding: copy(binding), remote: null, observedRoots: [], hostPid: process.pid, agentId,
        reservedAt: new Date().toISOString(), previousCleanup: prior?.cleanup ?? null };
      this._budget(data);
      return row;
    });
  }

  _update(handle, update) {
    if (!handle || !digest(handle.key) || !uuid(handle.nonce)) fail('INVALID_REMOTE_LEASE', 'Exact remote execution handle is required');
    return this._write(data => {
      const row = this._records(data)[handle.key];
      if (!row || row.nonce !== handle.nonce) fail('STALE_REMOTE_LEASE', 'Remote execution generation changed; old evidence cannot affect its replacement');
      update(row);
      if (!Number.isSafeInteger(row.revision + 1)) fail('REMOTE_LEASE_LIMIT', 'Remote execution revision exhausted');
      row.revision++;
      this._budget(data);
      return row;
    });
  }

  bind(handle, remote) {
    return this._update(handle, row => {
      if (row.state !== 'reserved' || row.remote || !validRemote(remote, row.binding))
        fail('REMOTE_IDENTITY_MISMATCH', 'Authenticated remote session does not match the reserved guest');
      row.remote = copy(remote);
    });
  }

  attach(handle, attachment) {
    return this._update(handle, row => {
      if (row.state !== 'reserved' || !attachment || typeof attachment.attachmentId !== 'string'
          || typeof attachment.projectId !== 'string' || attachment.artifactId !== 'artifact_' + row.binding.targetSha256)
        fail('REMOTE_ATTACHMENT_MISMATCH', 'Guest execution attachment differs from the opened artifact');
      row.attachment = { attachmentId: attachment.attachmentId, projectId: attachment.projectId, artifactId: attachment.artifactId };
    });
  }

  arm(handle) {
    return this._update(handle, row => {
      if (!row.remote || !['reserved', 'active'].includes(row.state)) fail('REMOTE_EXECUTION_RETAINED', 'Unknown or unbound guest execution cannot dispatch native operations');
      row.state = 'active';
    });
  }

  observeRoots(handle, roots) {
    return this._update(handle, row => {
      if (row.state !== 'active' || !Array.isArray(roots) || roots.length > 256
          || roots.some(root => !root || !opaque(root.rootId) || !integer(root.pid, 1, 0xffffffff)))
        fail('REMOTE_ROOT_MISMATCH', 'Native root identities require the active remote execution');
      for (const root of roots) {
        const prior = row.observedRoots.find(item => item.rootId === root.rootId);
        if (prior && prior.pid !== root.pid) fail('REMOTE_ROOT_MISMATCH', 'Native root identity changed PID');
        if (!prior) row.observedRoots.push({ rootId: root.rootId, pid: root.pid });
      }
      if (row.observedRoots.length > 256) fail('REMOTE_LEASE_LIMIT', 'Remote native root observation limit reached');
    });
  }

  uncertain(handle, reason = 'transport-lost') {
    if (!['transport-lost', 'rpc-timeout', 'shutdown', 'cleanup-unconfirmed'].includes(reason)) fail('INVALID_REMOTE_LEASE', 'Unsupported remote uncertainty reason');
    return this._update(handle, row => {
      if (row.state === 'cleaned') return;
      row.state = 'unknown'; row.reason = reason;
    });
  }

  abandonUnarmed(handle, bridgeExitConfirmed) {
    return this._update(handle, row => {
      if (row.state !== 'reserved' || bridgeExitConfirmed !== true)
        fail('REMOTE_CLEANUP_UNCONFIRMED', 'Only an unarmed reservation with confirmed local bridge exit may be abandoned');
      row.state = 'cleaned'; row.cleanup = { kind: 'unarmed-local-bridge-exited', nativeDispatchAttempted: false };
    });
  }

  complete(handle, receipt) {
    return this._update(handle, row => {
      if (!validReceipt(row, receipt))
        fail('REMOTE_CLEANUP_UNCONFIRMED', 'Cleanup must identify the original guest, target and remote session and confirm every native root/Job');
      const encoded = Buffer.from(canonical(receipt), 'utf8');
      if (encoded.length > 128 * 1024) fail('REMOTE_LEASE_LIMIT', 'Remote cleanup receipt exceeds 128 KiB');
      const digest = hash(encoded), dir = path.join(this.root, 'remote-cleanup-receipts');
      fs.mkdirSync(dir, { recursive: true });
      if (fs.lstatSync(dir).isSymbolicLink()) fail('REMOTE_LEASE_CORRUPT', 'Remote cleanup receipt directory cannot be a link');
      const file = path.join(dir, digest + '.json');
      let fd;
      try { fd = fs.openSync(file, 'wx'); fs.writeFileSync(fd, encoded); fs.fsyncSync(fd); }
      catch (error) { if (error.code !== 'EEXIST') throw error; }
      finally { if (fd !== undefined) fs.closeSync(fd); }
      const stat = fs.lstatSync(file);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size !== encoded.length || hash(readStableFile(file, 128 * 1024).data) !== digest)
        fail('REMOTE_LEASE_CORRUPT', 'Remote cleanup receipt file differs');
      row.state = 'cleaned'; row.cleanup = { kind: 'paired-guest-terminal-receipt', sha256: digest, bytes: encoded.length };
    });
  }
}
