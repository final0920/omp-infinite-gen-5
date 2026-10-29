import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { recoverLegacyLock } from './recover_legacy_project_lock.mjs';

test('offline legacy recovery preserves evidence and refuses unapproved, changed, live, and modern locks', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-lock-recovery-'));
  const lock = path.join(root, 'projects.lock'), ownerFile = path.join(lock, 'owner.json');
  try {
    assert.equal(recoverLegacyLock({ root }).status, 'no-lock');
    fs.mkdirSync(lock);
    const owner = { schema: 1, pid: 2147483647, nonce: randomUUID(), creationIdentity: null };
    const bytes = JSON.stringify(owner); fs.writeFileSync(ownerFile, bytes);
    const preview = recoverLegacyLock({ root });
    assert.equal(preview.changed, false); assert(fs.existsSync(lock));
    assert.throws(() => recoverLegacyLock({ root, offlineConfirmed: true, expectedOwnerSha256: 'bad' }), /hash/);
    fs.writeFileSync(ownerFile, JSON.stringify({ ...owner, pid: process.pid }));
    const live = recoverLegacyLock({ root });
    assert.throws(() => recoverLegacyLock({ root, offlineConfirmed: true, expectedOwnerSha256: live.ownerSha256 }), /live/);
    fs.writeFileSync(ownerFile, JSON.stringify({ ...owner, hostName: os.hostname(), platform: process.platform }));
    assert.throws(() => recoverLegacyLock({ root }), /legacy/);
    fs.writeFileSync(ownerFile, bytes);
    const moved = recoverLegacyLock({ root, offlineConfirmed: true, expectedOwnerSha256: preview.ownerSha256 });
    assert.equal(moved.changed, true); assert(!fs.existsSync(lock));
    assert.equal(fs.readFileSync(path.join(moved.backup, 'owner.json'), 'utf8'), bytes);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
