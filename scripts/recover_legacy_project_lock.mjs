// Explicit offline maintenance only. Never used by ProjectStore's automatic recovery.
import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const digest = bytes => createHash('sha256').update(bytes).digest('hex');
function ordinary(filename, directory) {
  const stat = fs.lstatSync(filename);
  if (stat.isSymbolicLink() || (directory ? !stat.isDirectory() : !stat.isFile())) throw new Error('Linked or unexpected path: ' + filename);
  return stat;
}
export function recoverLegacyLock({ root, expectedOwnerSha256, offlineConfirmed = false } = {}) {
  if (!root || !path.isAbsolute(root)) throw new Error('An absolute project metadata root is required');
  root = path.resolve(root);
  for (let at = root;; at = path.dirname(at)) {
    ordinary(at, true);
    if (path.dirname(at) === at) break;
  }
  const lock = path.join(root, 'projects.lock'), ownerPath = path.join(lock, 'owner.json');
  if (!fs.existsSync(lock)) return { status: 'no-lock', root, changed: false };
  const before = ordinary(lock, true);
  ordinary(ownerPath, false);
  const bytes = fs.readFileSync(ownerPath), ownerSha256 = digest(bytes), owner = JSON.parse(bytes);
  if (owner.schema !== 1 || !Number.isSafeInteger(owner.pid) || owner.pid <= 0 ||
      !/^[0-9a-f-]{36}$/.test(owner.nonce) || !(owner.creationIdentity === null || typeof owner.creationIdentity === 'string') ||
      Object.hasOwn(owner, 'hostName') || Object.hasOwn(owner, 'platform')) throw new Error('Only a recognized legacy lock with both host fields absent is supported');
  const preview = { status: 'legacy-lock', root, lock, ownerSha256, pid: owner.pid, changed: false,
    requirement: 'Stop all DSH/IG5 writers on every host using this root; prevent restart during recovery. Local PID absence cannot prove foreign-owner exit.' };
  if (!offlineConfirmed) return preview;
  if (expectedOwnerSha256 !== ownerSha256) throw new Error('Owner hash differs from the explicitly inspected lock');
  try { process.kill(owner.pid, 0); }
  catch (error) { if (error.code !== 'ESRCH') throw new Error('Owner PID status is unknown; leave the lock intact'); else return move(); }
  throw new Error('Owner PID is still live locally; leave the lock intact');

  function move() {
    const after = ordinary(lock, true);
    ordinary(ownerPath, false);
    if (before.dev !== after.dev || before.ino !== after.ino || before.birthtimeMs !== after.birthtimeMs ||
        digest(fs.readFileSync(ownerPath)) !== ownerSha256) throw new Error('Lock changed; leave it intact');
    const backup = path.join(root, `.projects-legacy-lock-${owner.nonce}-${randomUUID()}`);
    fs.renameSync(lock, backup); // same root, no deletion, original owner evidence retained
    return { ...preview, status: 'moved-offline', changed: true, backup, offlineConfirmed: true, recoveredAt: new Date().toISOString() };
  }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2), option = flag => args[args.indexOf(flag) + 1];
  try {
    console.log(JSON.stringify(recoverLegacyLock({ root: args.includes('--root') ? option('--root') : undefined,
      expectedOwnerSha256: args.includes('--expected-owner-sha256') ? option('--expected-owner-sha256') : undefined,
      offlineConfirmed: args.includes('--offline-confirmed') }), null, 2));
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
