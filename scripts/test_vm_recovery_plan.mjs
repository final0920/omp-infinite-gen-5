import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { RECOVERY_LIMITS, RECOVERY_STAGES, recoveryBinding, recoveryDigest, recoveryObservationBinding,
  validateRecoveryCase } from '../source/vm_recovery_case.js';
import { planVmRecovery } from '../source/vm_recovery_plan.js';
import { readRecoveryPlan } from './plan_vm_recovery.mjs';

const sampleBytes = Buffer.from('Synthetic evidence; contains no target code.');
const hash = recoveryDigest('sample');
function clean(root) {
  const resolved = path.resolve(root), temp = path.resolve(os.tmpdir());
  assert.equal(path.dirname(resolved), temp);
  assert.ok(path.basename(resolved).startsWith('ig5-recovery-'));
  assert.equal(fs.lstatSync(resolved).isSymbolicLink(), false);
  fs.rmSync(resolved, { recursive: true, force: true });
}
function fixture() {
  return { schema: 'ig5-vm-recovery-case-v1', caseId: 'test', objective: { family: 'VMProtect', versionSeries: '3.8' },
    scope: { targetSha256: hash, architecture: 'x64', family: 'VMProtect', version: '3.8.1', build: 'test-build',
      producerSha256: hash, configurationSha256: hash, functionEntry: '0x140001000', functionContractSha256: hash,
      codeEpoch: 'test-epoch', modelRevision: 0 },
    references: [{ id: 'report', kind: 'checkpoint', path: path.join(os.tmpdir(), 'synthetic-report.json'), bytes: sampleBytes.length, sha256: hash }], events: [] };
}
function checks(value) { return value.references.map(ref => ({ id: ref.id, status: 'identity-matched', sha256: ref.sha256, bytes: ref.bytes })); }
function event(value, stage, state = 'partial', code = null, options = {}) {
  const entry = { id: `event${value.events.length}`, stage, state, bindingSha256: recoveryBinding(value), inputBindingSha256: hash,
    inputs: state === 'partial' || state === 'candidate' ? RECOVERY_STAGES[stage].map(prior => value.events.findLast(e => e.stage === prior)?.id).filter(Boolean) : [],
    references: ['report'], hypothesisRevision: 0, failure: code ? { code, fingerprint: hash } : null,
    note: 'Synthetic work observation', ...options };
  entry.inputBindingSha256 = recoveryObservationBinding(value, entry);
  value.events.push(entry);
  return entry;
}
const plan = value => planVmRecovery(value, checks(value));

test('empty admitted-version case requests work without claiming any gate accepted', () => {
  const result = plan(fixture());
  assert.equal(result.versionMatch, true);
  assert.equal(result.nextActions[0].stage, 'admission');
  assert.ok(result.stages.every(stage => !stage.gateAccepted));
  assert.equal(result.completionAssessment.businessAccepted, false);
  assert.equal(result.executionAuthority, 'not-inspected');
});
test('3.11 and 3.7.3 do not qualify as the 3.8 series', () => {
  for (const version of ['3.11', '3.7.3.1628', null]) {
    const value = fixture(); value.scope.version = version;
    const result = plan(value);
    assert.equal(result.lane, 'component-research-only');
    assert.equal(result.nextActions[0].action, 'obtain-requested-version-case');
    assert.equal(result.completionAssessment.exactRequestedVersionAccepted, false);
  }
});
test('all caller candidates and matched hashes still require independent verifiers', () => {
  const value = fixture();
  for (const stage of Object.keys(RECOVERY_STAGES)) event(value, stage, 'candidate');
  const result = plan(value);
  assert.ok(result.stages.every(stage => stage.workState === 'candidate' && !stage.gateAccepted));
  assert.ok(Object.values(result.completionAssessment).filter(x => typeof x === 'boolean').every(x => !x));
  assert.ok(result.nextActions.every(action => action.action === 'connect-independent-stage-verifier'));
});
test('fake passed/completed state and extra businessAccepted field are rejected', () => {
  for (const state of ['passed', 'completed', 'verified']) {
    const value = fixture(); event(value, 'admission'); value.events[0].state = state;
    assert.throws(() => plan(value), /unsupported stage or caller state/);
  }
  const value = fixture(); value.businessAccepted = true;
  assert.throws(() => plan(value), /unsupported field/);
});
test('model, epoch, goal, config, target and contract changes invalidate prior observations', () => {
  for (const mutate of [v => v.scope.modelRevision++, v => v.scope.codeEpoch = 'other', v => v.scope.targetSha256 = 'b'.repeat(64),
    v => v.scope.configurationSha256 = 'c'.repeat(64), v => v.scope.functionContractSha256 = 'd'.repeat(64), v => v.objective.versionSeries = '3.9']) {
    const value = fixture(); event(value, 'admission'); mutate(value);
    assert.equal(plan(value).stages[0].workState, 'stale');
  }
});
test('replacing bytes behind the same reference id makes old observations stale even with a matching new hash', () => {
  const value = fixture(); event(value, 'admission');
  value.references[0].sha256 = 'e'.repeat(64);
  assert.ok(plan(value).evaluatedEvents[0].invalidReasons.includes('referenced-artifacts-or-input-records-changed'));
});
test('missing and mismatching file identities prevent evidence reuse', () => {
  const value = fixture(); event(value, 'admission');
  for (const status of ['unavailable', 'identity-mismatch']) {
    const result = planVmRecovery(value, [{ id: 'report', status }]);
    assert.equal(result.stages[0].workState, 'stale');
  }
  assert.equal(planVmRecovery(value).stages[0].workState, 'stale');
});
test('superseding an upstream observation invalidates downstream observations', () => {
  const value = fixture(); event(value, 'admission'); event(value, 'capture'); event(value, 'vm_model');
  event(value, 'capture');
  const result = plan(value);
  assert.equal(result.stages.find(stage => stage.stage === 'vm_model').workState, 'stale');
  assert.equal(result.stages.find(stage => stage.stage === 'capture').workState, 'partial');
});
test('editing a prerequisite record invalidates its dependents', () => {
  const value = fixture(); event(value, 'admission'); event(value, 'capture');
  value.events[0].note = 'Changed hypothesis record';
  assert.equal(plan(value).stages.find(stage => stage.stage === 'capture').workState, 'stale');
});
test('a partial semantic observation cannot omit its prerequisite evidence', () => {
  const value = fixture(); event(value, 'isa');
  assert.ok(plan(value).evaluatedEvents[0].invalidReasons.includes('missing-prerequisite-observation:vm_model'));
});
test('VM model and complete program gaps appear as generic capability work', () => {
  const value = fixture(); for (const stage of ['admission', 'capture', 'vm_model', 'isa']) event(value, stage);
  const result = plan(value);
  assert.ok(result.nextActions.some(action => action.action === 'recover-bytecode-program' && action.implementation === 'generic-adapter-needed'));
  assert.ok(result.nextActions.some(action => action.action === 'infer-and-test-vm-roles'));
});
test('trace prefix, unknown flag, unresolved control and guard failures route to different capabilities', () => {
  for (const [stage, code, action] of [
    ['capture', 'TRACE_PREFIX_NOT_RETURNED', 'investigate-trigger-and-return'],
    ['isa', 'LIVE_UNKNOWN_FLAG', 'repair-and-verify-instruction-semantics'],
    ['program', 'UNRESOLVED_INDIRECT', 'resolve-virtual-control-transfer'],
    ['coverage', 'UNRESOLVED_GUARD', 'derive-counterexample-path'],
  ]) {
    const value = fixture(); event(value, stage, 'failed', code);
    assert.ok(plan(value).nextActions.some(item => item.action === action));
    assert.equal(plan(value).completionAssessment.businessAccepted, false);
  }
});
test('SMT unknown stays unknown and requests proof decomposition', () => {
  const value = fixture(); event(value, 'business', 'unknown', 'SMT_UNKNOWN');
  const result = plan(value);
  assert.equal(result.stages.find(stage => stage.stage === 'business').workState, 'unknown');
  assert.ok(result.nextActions.some(action => action.action === 'decompose-proof-obligation'));
});
test('repeated failure with the same bytes requests a different experiment', () => {
  const value = fixture(); event(value, 'coverage', 'failed', 'UNRESOLVED_GUARD'); event(value, 'coverage', 'failed', 'UNRESOLVED_GUARD');
  assert.equal(plan(value).evaluatedEvents.at(-1).repeatedWithoutNewInputs, 2);
  assert.ok(plan(value).nextActions.some(action => action.action === 'design-discriminating-experiment'));
});
test('changing a bare revision, fingerprint, note or artifact id is not new evidence', () => {
  const value = fixture(); event(value, 'coverage', 'failed', 'UNRESOLVED_GUARD');
  value.references.push({ ...value.references[0], id: 'renamed' });
  event(value, 'coverage', 'failed', 'UNRESOLVED_GUARD', { references: ['renamed'], hypothesisRevision: 42,
    failure: { code: 'UNRESOLVED_GUARD', fingerprint: 'a'.repeat(64) }, note: 'Another narrative' });
  assert.equal(plan(value).evaluatedEvents.at(-1).repeatedWithoutNewInputs, 2);
});
test('genuinely different input bytes start a new experiment while preserving old failure', () => {
  const value = fixture(); event(value, 'coverage', 'failed', 'UNRESOLVED_GUARD');
  value.references.push({ ...value.references[0], id: 'new-input', sha256: 'f'.repeat(64) });
  event(value, 'coverage', 'failed', 'UNRESOLVED_GUARD', { references: ['new-input'] });
  const result = plan(value);
  assert.equal(result.evaluatedEvents.length, 2);
  assert.equal(result.evaluatedEvents.at(-1).repeatedWithoutNewInputs, 1);
});
test('unconfirmed cleanup survives ordinary candidates, stale hashes and changed model epoch', () => {
  const value = fixture(); event(value, 'capture', 'unknown', 'CLEANUP_UNCONFIRMED'); event(value, 'capture', 'candidate');
  value.scope.codeEpoch = 'changed';
  const result = planVmRecovery(value);
  assert.equal(result.executionHeldFromObservations, true);
  assert.equal(result.nextActions[0].action, 'recover-original-execution-owner');
  assert.equal(result.executionAuthority, 'not-inspected');
  assert.equal(result.changesExecutionAuthority, false);
});
test('deleting a caller hold cannot grant execution authority', () => {
  const result = plan(fixture());
  assert.equal(result.executionHeldFromObservations, false);
  assert.equal(result.executionAuthority, 'not-inspected');
  assert.ok(result.nextActions.every(action => action.execution === 'proposal-only' && !action.approvalGranted));
});
test('duplicate ids/references, future inputs and cyclic/self inputs are rejected', () => {
  for (const mutate of [v => v.references.push({ ...v.references[0] }), v => v.events.push(structuredClone(v.events[0])),
    v => v.events[0].inputs.push('future'), v => v.events[0].inputs.push(v.events[0].id),
    v => v.events[0].references.push('report')]) {
    const value = fixture(); event(value, 'admission'); mutate(value); assert.throws(() => plan(value));
  }
});
test('accessors, prototype payloads, sparse arrays, nonfinite revisions and uint64 addresses are checked', () => {
  let touched = false;
  const getter = fixture(); Object.defineProperty(getter, 'caseId', { enumerable: true, get() { touched = true; return 'x'; } });
  assert.throws(() => plan(getter)); assert.equal(touched, false);
  for (const mutate of [v => Object.setPrototypeOf(v.scope, { fake: true }), v => v.events = new Array(1),
    v => v.scope.modelRevision = Infinity, v => v.scope.modelRevision = -0, v => v.scope.functionEntry = '0x10000000000000000',
    v => v.scope.functionEntry = '0x0001']) {
    const value = fixture(); mutate(value); assert.throws(() => plan(value));
  }
});
test('stage and failure keys are rejected without invoking ToPropertyKey', () => {
  let touched = false;
  const bad = { toString() { touched = true; return 'capture'; } };
  const a = fixture(); event(a, 'admission'); a.events[0].stage = bad;
  assert.throws(() => plan(a)); assert.equal(touched, false);
  const b = fixture(); event(b, 'capture', 'failed', 'MEMORY_GAP'); b.events[0].failure.code = bad;
  assert.throws(() => plan(b)); assert.equal(touched, false);
});
test('budgets reject too many events, references, total bytes and oversized notes', () => {
  for (const mutate of [v => v.events = Array.from({ length: RECOVERY_LIMITS.events + 1 }, () => ({})),
    v => v.references = Array.from({ length: RECOVERY_LIMITS.references + 1 }, () => ({})),
    v => v.references = ['a', 'b', 'c'].map(id => ({ ...v.references[0], id, bytes: RECOVERY_LIMITS.referenceBytes })),
    v => { event(v, 'admission'); v.events[0].note = 'x'.repeat(2049); }]) {
    const value = fixture(); mutate(value); assert.throws(() => validateRecoveryCase(value));
  }
});
test('invalid or duplicate internal reference checks fail closed', () => {
  const value = fixture();
  assert.throws(() => planVmRecovery(value, [checks(value)[0], checks(value)[0]]), /Invalid or duplicate/);
  assert.throws(() => planVmRecovery(value, [{ id: 'unknown', status: 'identity-matched' }]), /Invalid or duplicate/);
});
test('planner is deterministic and does not mutate caller records or frozen stage graph', () => {
  const value = fixture(); event(value, 'admission'); const before = JSON.stringify(value);
  assert.deepEqual(plan(value), plan(value)); assert.equal(JSON.stringify(value), before);
  assert.throws(() => RECOVERY_STAGES.capture.push('business'));
});
test('requirements include transitive input artifacts and keep unprobed capabilities unknown', () => {
  const result = plan(fixture()), closure = result.blockedRequirements.find(row => row.stage === 'program').inputs;
  assert.deepEqual(closure.stages, ['admission', 'capture', 'vm_model', 'isa', 'program']);
  assert.ok(closure.artifacts.some(row => row.kind === 'trace' && row.inventory === 'missing-reference'));
  assert.ok(closure.capabilities.every(row => row.availability === 'not-probed'));
  assert.ok(result.engineeringActions.every(row => row.dependsOnBusinessRecovery === false));
});
test('declared artifact kind is inventory only and cannot prove an available capability', () => {
  const value = fixture(); value.references[0].kind = 'trace';
  const result = plan(value), closure = result.blockedRequirements.find(row => row.stage === 'capture').inputs;
  assert.ok(closure.artifacts.some(row => row.kind === 'trace' && row.inventory === 'declared-reference-present' && !row.semanticVerified));
  assert.ok(closure.capabilities.every(row => row.availability === 'not-probed'));
});
test('proposed research actions remain unready until independent capability and input preflight', () => {
  const value = fixture(); for (const stage of ['admission', 'capture', 'vm_model', 'isa']) event(value, stage);
  const result = plan(value);
  assert.ok(result.nextActions.every(action => action.readiness === 'requires-independent-preflight'));
  const action = result.nextActions.find(item => item.stage === 'program');
  assert.ok(action.missingArtifactKinds.includes('trace'));
  assert.ok(action.missingArtifactKinds.includes('vm-model'));
});
test('read-only file entry verifies actual bytes and detects a same-size rewrite', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-recovery-'));
  try {
    const ref = path.join(root, 'evidence.json'), file = path.join(root, 'case.json');
    fs.writeFileSync(ref, sampleBytes);
    const value = fixture(); value.references[0].path = ref;
    // Use the actual file SHA, not the canonical object digest helper.
    value.references[0].sha256 = createHash('sha256').update(sampleBytes).digest('hex');
    event(value, 'admission'); fs.writeFileSync(file, JSON.stringify(value));
    const result = readRecoveryPlan(file);
    assert.equal(result.referenceChecks[0].status, 'identity-matched');
    assert.equal(result.stages[0].workState, 'partial');
    const before = fs.readFileSync(file);
    fs.writeFileSync(ref, Buffer.alloc(sampleBytes.length, 42));
    assert.equal(readRecoveryPlan(file).stages[0].workState, 'stale');
    assert.deepEqual(fs.readFileSync(file), before);
  } finally { clean(root); }
});
test('file entry rejects relative/traversal/network paths and invalid UTF-8 before referenced reads', () => {
  assert.throws(() => readRecoveryPlan('relative.json'), /explicit local absolute/);
  assert.throws(() => readRecoveryPlan('\\\\server\\share\\case.json'), /explicit local absolute/);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-recovery-'));
  try {
    assert.throws(() => readRecoveryPlan(root + path.sep + '..' + path.sep + 'case.json'), /explicit local absolute/);
    const file = path.join(root, 'case.json'); fs.writeFileSync(file, Buffer.from([0xff]));
    assert.throws(() => readRecoveryPlan(file), /UTF-8 JSON/);
    const value = fixture(); value.references[0].path = 'relative-reference'; fs.writeFileSync(file, JSON.stringify(value));
    assert.throws(() => readRecoveryPlan(file), /explicit local absolute/);
  } finally { clean(root); }
});
