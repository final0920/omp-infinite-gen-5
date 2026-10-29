import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import test from 'node:test';
import assert from 'node:assert/strict';
import { createAnalysisService } from '../analysis_tools.js';
import { runRecoveryProfile } from '../source/vm_recovery_profile.js';
import { buildPhaseContextCase } from './fixtures/vm_phase_context_cases.mjs';
import { vmContextEvidence } from '../source/evidence_adapters/vm_context.js';
import { phaseContextIndex } from '../source/vm_phase_context.js';
import { validateObservationRequest } from '../source/vm_observation_profile.js';
import { routeFailure } from '../source/failure_router.js';

async function fixture(t, options) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-phase-context-'));
  const cfg = { artifactDir: path.join(root, 'artifacts'), projectRoot: path.join(root, 'projects') };
  const analysis = createAnalysisService({}, cfg), mgr = { analysis, checkCancelled() {} };
  t.after(async () => { await analysis.dispose(); assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir())); assert(path.basename(root).startsWith('ig5-phase-context-')); fs.rmSync(root, { recursive: true, force: true }); });
  const built = await buildPhaseContextCase(analysis, cfg, options);
  for (const name of ['get', 'spawnWorker', 'performDebug', 'run', 'close']) mgr[name] = () => assert.fail('Offline context annotation cannot execute targets');
  const invoke = request => runRecoveryProfile(mgr, { recovery: { observations: { ...built.request, ...request } } }, cfg);
  return { ...built, cfg, analysis, mgr, invoke };
}

test('audited candidates bind exact raw fetch/body/boundary groups and distinguish prefix from initialization', async t => {
  const f = await fixture(t), view = (await f.invoke({ offset: 99, limit: 5 })).observations;
  const result = f.analysis.artifacts.get(view.reportId).result, annotation = result.phaseModel.contextAnnotation;
  assert.equal(annotation.audit.status, 'pass'); assert.equal(annotation.matchedGroups, 16); assert.equal(annotation.matchedNextFetchHeads, 8);
  assert.equal(annotation.segments.length, 16); assert.equal(annotation.prefix.endGroup, 99);
  assert.equal(view.phaseModel.contextAnnotation.segments.length, 4);
  assert.equal(view.phaseModel.contextAnnotation.totalSegments, 16); assert.equal(view.phaseModel.contextAnnotation.segmentsPreviewComplete, false);
  assert.deepEqual(result.phaseModel.groups.map(g => g.contextPhase.kind), ['unclassified-prefix', 'fetch-dispatch-candidate', 'handler-body-candidate', 'unclassified-context-gap', 'unclassified-context-gap']);
  assert(result.phaseModel.groups.every(g => g.initialization === 'unknown' && g.dispatch === 'unknown' && g.business === 'unknown'));
  assert.equal(annotation.phaseClassificationProved, false); assert.equal(f.analysis.jobs.active, null);
});

test('an audited candidate model alone cannot authorize mismatched body, fetch bytes or initial raw state', async t => {
  for (const options of [{ tamperBody: true }, { tamperDescriptor: true }, { tamperInitial: true }]) {
    const f = await fixture(t, options); const before = fs.readdirSync(f.analysis.artifacts.directory('records')).length;
    await assert.rejects(f.invoke({ limit: 1 }), { code: 'INVALID_PHASE_CONTEXT' });
    assert.equal(fs.readdirSync(f.analysis.artifacts.directory('records')).length, before);
  }
});

test('context requires opt-in and exact SHA; changed manifests and caller phases are refused', async t => {
  const f = await fixture(t);
  await assert.rejects(f.invoke({ phase_model: false }), /requires phase_model/);
  await assert.rejects(f.invoke({ phase_context_ref: { ...f.request.phase_context_ref, sha256: '0'.repeat(64) } }), { code: 'ARTIFACT_CHANGED' });
  await assert.rejects(f.invoke({ phase_context_ref: { ...f.request.phase_context_ref, phase: 'verified' } }), /Invalid observation fields/);
  const view = (await f.invoke({ offset: 100, limit: 1 })).observations;
  const original = f.analysis.observeNative;
  f.analysis.observeNative = async (...args) => { const result = await original(...args); result.phaseModel.groups[0].contextPhase.kind = 'business'; return result; };
  await assert.rejects(f.invoke({ offset: 100, limit: 1 }), { code: 'INVALID_PHASE_CONTEXT' });
  assert.equal(view.phaseModel.phaseVerified, false);
});

test('context accessors are rejected without evaluation and typed failure advice never grants execution', () => {
  let evaluated = false;
  const ref = { sha256: 'a'.repeat(64), get id() { evaluated = true; return 'untrusted'; } };
  assert.throws(() => validateObservationRequest({ recordings: [], target_sha256: 'a'.repeat(64), phase_model: true, phase_context_ref: ref }), /Invalid observation fields/);
  assert.equal(evaluated, false);
  const advice = routeFailure({ failureCode: 'INVALID_PHASE_CONTEXT' });
  assert.equal(advice.category, 'research'); assert.equal(advice.nextCheck, 'revalidate-context-and-complete-recording-manifest');
  assert.equal(advice.executionAuthorized, false);
});

test('full source manifests are required and segment endpoints outside the preview cannot be substituted', async t => {
  const f = await fixture(t);
  const packet = vmContextEvidence(f.analysis.artifacts, { scope: { sha256: f.request.target_sha256 } }, f.request.phase_context_ref).request;
  const changed = structuredClone(f.window); changed.source.reportSha256 = 'f'.repeat(64);
  assert.throws(() => phaseContextIndex(packet, [changed], f.request.target_sha256), { code: 'INVALID_PHASE_CONTEXT' });
  const original = f.analysis.observeNative;
  f.analysis.observeNative = async (...args) => { const result = await original(...args); result.phaseModel.contextAnnotation.segments[0].firstVersionId = 'f'.repeat(64); return result; };
  await assert.rejects(f.invoke({ offset: 0, limit: 1 }), { code: 'INVALID_PHASE_CONTEXT' });
});
