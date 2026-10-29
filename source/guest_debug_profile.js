import path from 'node:path';
import { hashBytes, readStableFile } from './analysis_artifacts.js';

const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const name = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(value);
const object = value => !!value && typeof value === 'object' && !Array.isArray(value);
const exact = (value, keys) => object(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const fail = message => { throw Object.assign(new Error(message), { code: 'INVALID_GUEST_PROFILE' }); };

export function guestProfileConfiguration(value = {}) {
  if (!object(value) || Object.keys(value).length > 8) fail('guestDebugProfiles must map at most eight names to explicit profile files');
  const profiles = Object.create(null);
  for (const [key, file] of Object.entries(value)) {
    if (!name(key) || typeof file !== 'string' || !path.isAbsolute(file) || file.includes('\0')) fail('Guest profile names and absolute profile paths are required');
    profiles[key] = path.resolve(file);
  }
  return Object.freeze(profiles);
}

export function loadGuestProfile(cfg, profileName, expectedSha256) {
  if (!name(profileName) || !Object.hasOwn(cfg.guestDebugProfiles ?? {}, profileName)) fail('Unknown configured guest debug profile');
  if (expectedSha256 !== undefined && !digest(expectedSha256)) fail('guest_binding_sha256 must be the exact inspected profile digest');
  if (cfg.host?.id !== 'win32-x64') fail('Paired VMCI guest debugging currently requires the Windows x64 host runtime');
  const file = cfg.guestDebugProfiles[profileName], data = readStableFile(file, 64 * 1024).data;
  const sha256 = hashBytes(data);
  if (expectedSha256 !== undefined && sha256 !== expectedSha256) fail('Guest debug profile changed; inspect its current identity before execution');
  let profile;
  try { profile = JSON.parse(data.toString('utf8')); } catch { fail('Guest debug profile must be UTF-8 JSON'); }
  if (!exact(profile, ['schema', 'guestCID', 'port', 'guestLabel', 'bundleSha256', 'pairingKeyRef', 'targets'])
      || profile.schema !== 'ig5-vmci-guest-profile-v1' || !Number.isSafeInteger(profile.guestCID) || profile.guestCID < 3 || profile.guestCID > 0xfffffffe
      || !Number.isSafeInteger(profile.port) || profile.port < 1024 || profile.port > 0xfffffffe
      || typeof profile.guestLabel !== 'string' || !profile.guestLabel.trim() || profile.guestLabel.length > 128
      || !digest(profile.bundleSha256) || !exact(profile.pairingKeyRef, ['path', 'sha256'])
      || typeof profile.pairingKeyRef.path !== 'string' || !path.isAbsolute(profile.pairingKeyRef.path) || !digest(profile.pairingKeyRef.sha256)
      || !Array.isArray(profile.targets) || profile.targets.length < 1 || profile.targets.length > 64)
    fail('Guest profile identity, key reference or bounded target catalog is invalid');
  const ids = new Set(), hashes = new Set();
  for (const target of profile.targets) {
    if (!exact(target, ['id', 'sha256']) || !name(target.id) || !digest(target.sha256) || ids.has(target.id) || hashes.has(target.sha256))
      fail('Guest target catalog must have unique explicit IDs and SHA-256 identities');
    ids.add(target.id); hashes.add(target.sha256);
  }
  const key = readStableFile(profile.pairingKeyRef.path, 32).data;
  if (key.length !== 32 || hashBytes(key) !== profile.pairingKeyRef.sha256) fail('Guest pairing key size/digest differs');
  return { name: profileName, path: file, sha256, profile };
}

export function publicGuestProfile(snapshot) {
  return { name: snapshot.name, bindingSha256: snapshot.sha256, guestCID: snapshot.profile.guestCID,
    guestLabel: snapshot.profile.guestLabel, port: snapshot.profile.port, bundleSha256: snapshot.profile.bundleSha256,
    targets: snapshot.profile.targets, pairingKeyVerified: true, authenticatedStartupVerified: false,
    nativeTargetExecuted: false, scope: 'Prepared profile files only; actual authenticated connection and native execution are separate checks' };
}

export function guestTarget(snapshot, targetSha256) {
  const target = snapshot.profile.targets.find(row => row.sha256 === targetSha256);
  if (!target) fail('Opened artifact is not registered in the selected guest catalog');
  return target;
}
