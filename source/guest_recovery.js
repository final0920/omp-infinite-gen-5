import { spawnWorker, attachWorker } from './worker_transport.js';
import { terminateTree } from '../engine_runtime.js';

export const GUEST_RECOVERY_FIELDS = Object.freeze([
  'target', 'engine', 'op', 'backend', 'guest_profile', 'guest_binding_sha256', 'control',
]);

// Reject, never silently discard, execution/epoch parameters on a receipt query.
// Do not echo caller values (which may contain sensitive material) in diagnostics.
export function validateGuestRecoveryArgs(args) {
  if (Object.keys(args).some(key => !GUEST_RECOVERY_FIELDS.includes(key))) {
    throw Object.assign(new Error('op=recover is a cleanup-receipt query, not execution. Send only target, op=recover, backend=x64dbg, guest_profile, guest_binding_sha256; optionally engine and control=takeover. Omit timeout, expected_run_id, expected_stop_seq and all execution parameters. No cleanup was confirmed.'),
      { code: 'INVALID_GUEST_RECOVERY_ARGS' });
  }
}

// A recovery connection can query the original signed terminal receipt only.
// It never opens a target or sends a native debugger operation.
export async function recoverGuestExecution(cfg, pluginRoot, snapshot, lease, { signal } = {}) {
  if (!lease.remote) throw new Error('Original authenticated guest session is unknown; cleanup cannot be inferred');
  const session = { engine: 'x64dbg', seq: 0, pending: new Map() };
  const proc = spawnWorker({ ...cfg, guestExecutionProfile: { path: snapshot.path, sha256: snapshot.sha256 } }, 'x64dbg', pluginRoot);
  let location;
  const client = attachWorker(proc, { session, onMessage(message) {
    if (message.ig5 === 'ready') { location = message.executionLocation; return; }
    const pending = session.pending.get(message.id);
    if (!pending) return;
    session.pending.delete(message.id); clearTimeout(pending.timer); pending.removeAbort?.();
    if (message.error) pending.reject(Object.assign(new Error(message.error.message), message.error));
    else pending.resolve(message.result);
  } });
  try {
    await client.waitReady(30_000);
    if (location?.kind !== 'vmci-guest' || location.profileSha256 !== snapshot.sha256
        || location.guestCID !== lease.binding.guestCID || location.bundleSha256 !== lease.binding.bundleSha256)
      throw new Error('Recovery peer differs from the retained guest binding');
    const result = await client.request(session, 'recover', { serverInstanceId: lease.remote.serverInstanceId,
      sessionId: lease.remote.sessionId, targetId: lease.binding.targetId, targetSha256: lease.binding.targetSha256 }, { timeoutMs: 20_000, signal });
    if (result?.authenticatedGuestResponse !== true || result.guestCleanupHMACVerified !== true
        || !result.executionLocation || Object.keys(location).some(key => result.executionLocation[key] !== location[key]))
      throw new Error('Recovery did not return an authenticated original cleanup receipt');
    // Closing this empty connection is housekeeping, not proof for the old one.
    try { await client.request(session, 'close', {}, { timeoutMs: 5000 }); } catch { /* retain original proof */ }
    return result.guestCleanup;
  } finally {
    client.dispose();
    const exited = !proc.pid || proc.exitCode !== null || proc.signalCode != null;
    if (!exited) {
      const confirmed = new Promise(resolve => {
        const timer = setTimeout(() => { proc.removeListener('exit', onExit); resolve(false); }, 5000);
        const onExit = () => { clearTimeout(timer); resolve(true); };
        proc.once('exit', onExit);
      });
      terminateTree(proc);
      if (!await confirmed) throw new Error('Recovery bridge exit is unconfirmed; retained guest execution was not released');
    }
  }
}
