// Bounded immutable input snapshots; reading does not execute or approve work.
import path from 'node:path';
import fs from 'node:fs';
import { readStableFile, hashBytes } from './analysis_artifacts.js';
import { RECOVERY_LIMITS, recoveryError, validateRecoveryCase } from './vm_recovery_case.js';
import { planVmRecovery } from './vm_recovery_plan.js';

function absoluteFile(filename) {
  if (typeof filename !== 'string' || !path.isAbsolute(filename) || filename.includes('\0')
    || /^(\\\\|\/\/)/.test(filename) || filename.split(/[\\/]/).includes('..'))
    recoveryError('INVALID_RECOVERY_PATH', 'Use an explicit local absolute file path without parent traversal');
  return path.resolve(filename);
}
function checkAncestors(filename) {
  const parts = path.relative(path.parse(filename).root, filename).split(path.sep);
  let current = path.parse(filename).root;
  for (const part of parts.slice(0, -1)) {
    current = path.join(current, part);
    const stat = fs.lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) recoveryError('INVALID_RECOVERY_PATH', 'Linked or non-directory ancestors are not supported');
  }
}
export function loadRecoveryPlan(filename, { expectedSha256, checkCancelled = () => {} } = {}) {
  if (expectedSha256 !== undefined && (typeof expectedSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(expectedSha256)))
    recoveryError('INVALID_RECOVERY_REF', 'Case reference requires its lowercase SHA-256');
  if (typeof checkCancelled !== 'function') recoveryError('INVALID_ARGUMENT', 'Invalid internal cancellation callback');
  checkCancelled();
  const casePath = absoluteFile(filename);
  checkAncestors(casePath);
  const { data, origin } = readStableFile(casePath, RECOVERY_LIMITS.caseBytes);
  const sha256 = hashBytes(data);
  if (expectedSha256 !== undefined && sha256 !== expectedSha256)
    recoveryError('RECOVERY_CASE_CHANGED', 'Recovery case bytes differ from the supplied SHA-256; no referenced file was read');
  checkCancelled();
  let parsed;
  try { parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data)); }
  catch { recoveryError('INVALID_RECOVERY_CASE', 'Case must be UTF-8 JSON'); }
  const snapshot = validateRecoveryCase(parsed);
  for (const ref of snapshot.references) absoluteFile(ref.path);
  const checks = snapshot.references.map(ref => {
    checkCancelled();
    try {
      checkAncestors(absoluteFile(ref.path));
      const bytes = readStableFile(absoluteFile(ref.path), Math.min(RECOVERY_LIMITS.referenceBytes, ref.bytes)).data;
      const actualHash = hashBytes(bytes);
      return { id: ref.id, bytes: bytes.length, sha256: actualHash,
        status: bytes.length === ref.bytes && actualHash === ref.sha256 ? 'identity-matched' : 'identity-mismatch' };
    } catch (error) { return { id: ref.id, status: 'unavailable', code: error.code || 'REFERENCE_READ_FAILED' }; }
  });
  checkCancelled();
  const plan = { ...planVmRecovery(snapshot, checks), sourceCase: { path: origin.path, bytes: data.length, sha256 }, referenceChecks: checks };
  return { plan, snapshot };
}
export const readRecoveryPlan = (filename, options) => loadRecoveryPlan(filename, options).plan;
