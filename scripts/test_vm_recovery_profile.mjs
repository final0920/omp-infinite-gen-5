// Read-only host/IO seams with real report storage; no engine or target execution.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { AnalysisArtifacts } from '../source/analysis_artifacts.js';
import { runRecoveryProfile, recoveryProfileSchema } from '../source/vm_recovery_profile.js';
import { loadRecoveryPlan } from '../source/vm_recovery_io.js';
import { recoveryBinding, recoveryObservationBinding } from '../source/vm_recovery_case.js';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-recovery-profile-'));
  const artifacts = new AnalysisArtifacts(path.join(root, 'reports'));
  const value = JSON.parse(fs.readFileSync(new URL('./fixtures/vm_recovery_case.example.json', import.meta.url), 'utf8'));
  const file = path.join(root, 'case.json');
  const save = () => { const bytes = Buffer.from(JSON.stringify(value)); fs.writeFileSync(file, bytes); return { path: file, sha256: hash(bytes) }; };
  const mgr = { analysis: { artifacts }, cancellations: 0, checkCancelled() { this.cancellations++; if (this.abortAt === this.cancellations) throw Object.assign(new Error('cancelled'), { code: 'ABORT_ERR' }); } };
  const run = (ref = save(), extra = {}) => runRecoveryProfile(mgr, { recovery: { case_ref: ref }, ...extra }).recovery;
  const count = () => fs.readdirSync(path.join(artifacts.root, 'records')).length;
  t.after(async () => {
    await artifacts.dispose(); assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir()));
    assert.ok(path.basename(root).startsWith('ig5-recovery-profile-')); assert.equal(fs.lstatSync(root).isSymbolicLink(), false);
    fs.rmSync(root, { recursive: true, force: true });
  });
  return { root, artifacts, value, file, save, mgr, run, count };
}
test('profile saves an immutable full input snapshot and returns an exact report hash', t => {
  const f = fixture(t), ref = f.save(), result = f.run(ref), raw = fs.readFileSync(result.reportPath);
  assert.equal(hash(raw), result.reportSha256);
  assert.equal(result.sourceCase.sha256, ref.sha256);
  const full = f.artifacts.get(result.reportId);
  assert.equal(full.kind, 'vm-recovery-plan'); assert.deepEqual(full.result.caseSnapshot, f.value);
  assert.equal(result.integration.dshPlanningEntry, 'ig5_recovery.recovery');
  assert.equal(result.integration.automaticExecution, 'not-connected');
  assert.equal(result.completionAssessment.businessAccepted, false);
  assert.equal(result.executionAuthority, 'not-inspected');
  f.value.scope.modelRevision++; f.save();
  assert.equal(f.artifacts.get(result.reportId).result.caseSnapshot.scope.modelRevision, 0);
  assert.equal(f.count(), 1);
});
test('all incompatible profile modes are rejected before any report or side effect', t => {
  const f = fixture(t), ref = f.save();
  for (const [key, value] of Object.entries({ target: 'not-opened', engine: 'ghidra', toolset: 'full', workspace: { action: 'list' }, history: { action: 'stats' }, guest_debug: 'lab' })) {
    assert.throws(() => f.run(ref, { [key]: value }), /Use recovery separately/);
  }
  assert.equal(f.count(), 0);
});
test('missing/bad digests and unsupported parameters are rejected at the host seam', t => {
  const f = fixture(t), ref = f.save();
  for (const sha256 of [undefined, null, 'BAD', 'A'.repeat(64)]) assert.throws(() => f.run({ path: ref.path, sha256 }), /sha256 is required/);
  assert.throws(() => runRecoveryProfile(f.mgr, { recovery: { case_ref: { ...ref, passed: true } } }), /case_ref requires exactly/);
  assert.throws(() => runRecoveryProfile(f.mgr, { recovery: { case_ref: ref, execute: true } }), /recovery requires exactly/);
  assert.equal(f.count(), 0);
});
test('digest mismatch precedes UTF-8 parsing and referenced-file reads', t => {
  const f = fixture(t); fs.writeFileSync(f.file, Buffer.from([0xff]));
  assert.throws(() => f.run({ path: f.file, sha256: '0'.repeat(64) }), error => error.code === 'RECOVERY_CASE_CHANGED');
  assert.equal(f.count(), 0);
});
test('cancellation at entry, after input read and before save leaves no report', t => {
  for (const abortAt of [1, 2, 3, 4]) {
    const f = fixture(t); f.mgr.abortAt = abortAt;
    assert.throws(() => f.run(), error => error.code === 'ABORT_ERR');
    assert.equal(f.count(), 0);
  }
});
test('an unavailable artifact becomes stale work rather than a fabricated passing gate', t => {
  const f = fixture(t);
  f.value.references.push({ id: 'missing', kind: 'trace', path: path.join(f.root, 'absent.json'), bytes: 1, sha256: '0'.repeat(64) });
  const event = { id: 'observed', stage: 'admission', state: 'candidate', bindingSha256: recoveryBinding(f.value),
    inputBindingSha256: '0'.repeat(64), inputs: [], references: ['missing'], hypothesisRevision: 0, failure: null, note: 'Synthetic caller claim' };
  event.inputBindingSha256 = recoveryObservationBinding(f.value, event); f.value.events.push(event);
  const result = f.run(); assert.equal(result.referenceChecks.unavailable, 1); assert.equal(result.staleEventCount, 1);
  assert.equal(result.stages[0].workState, 'stale'); assert.equal(result.stages[0].gateAccepted, false);
  assert.equal(result.completionAssessment.exactRequestedVersionAccepted, false);
});
test('profile never invokes engine, process, approval or task mutation services', t => {
  const f = fixture(t);
  for (const name of ['get', 'spawnWorker', 'performDebug', 'run', 'close', 'remoteStore'])
    f.mgr[name] = () => { throw Error(`Unexpected service: ${name}`); };
  assert.equal(f.run().executionPerformed, false);
});
test('preview puts unverified completion and byte-only provenance before variable-length lists', t => {
  const f = fixture(t), result = f.run(), prefix = JSON.stringify({ recovery: result }).slice(0, 512);
  assert.match(prefix, /businessAccepted":false/); assert.match(prefix, /not-achieved/);
  assert.equal(result.previewComplete, false); assert.equal(result.fullReportContainsCaseSnapshotAndAllRequirements, true);
  assert.ok(result.nextActions.every(action => action.readiness === 'requires-independent-preflight'));
});
test('profile schema has nested required arrays and denies unknown fields', () => {
  assert.deepEqual(recoveryProfileSchema.oneOf, ['case_ref','observations','roles','flow','recurrences','handlers','context','declare_contract','role_compare','role_validate','program','function_check','instances','instance_check'].map(k => ({ required: [k] })));
  assert.deepEqual(recoveryProfileSchema.properties.roles.required, ['recordings','target_sha256']);
  assert.equal(recoveryProfileSchema.properties.roles.properties.offset, undefined);
  assert.deepEqual(recoveryProfileSchema.properties.case_ref.required, ['path', 'sha256']);
  assert.deepEqual(recoveryProfileSchema.properties.context.required, ['handler_refs']);
  assert.equal(recoveryProfileSchema.additionalProperties, false);
  assert.equal(recoveryProfileSchema.properties.case_ref.additionalProperties, false);
});
test('shared reader verifies the optional caller digest and retains CLI compatibility', t => {
  const f = fixture(t), ref = f.save();
  const loaded = loadRecoveryPlan(ref.path, { expectedSha256: ref.sha256 });
  assert.deepEqual(loaded.snapshot, f.value); assert.equal(loaded.plan.sourceCase.sha256, ref.sha256);
  assert.throws(() => loadRecoveryPlan(ref.path, { expectedSha256: 'bad' }), /lowercase SHA-256/);
  assert.throws(() => loadRecoveryPlan(ref.path, { checkCancelled: true }), /cancellation callback/);
});
