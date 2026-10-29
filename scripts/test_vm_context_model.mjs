import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { AnalysisArtifacts } from '../source/analysis_artifacts.js';
import { deriveVmContextModel } from '../source/vm_context_model.js';
import { contextProfileSchema, runVmContextProfile } from '../source/vm_context_profile.js';
import { recoveryProfileSchema, runRecoveryProfile } from '../source/vm_recovery_profile.js';

import { contextPage as page } from './fixtures/vm_context_cases.mjs';
const sha = digit => digit.repeat(64);

function sources() { return [page(0), page(1)]; }

test('sixteen bodies produce explicit context candidates while all proof boundaries stay false', () => {
  const result = deriveVmContextModel(sources());
  assert.equal(result.evidence.occurrences, 16); assert.equal(result.evidence.ordinaryConsistent, 10);
  assert.equal(result.evidence.partialUnknownPreserved, 6); assert.equal(result.evidence.unknownGprResults, 6);
  assert.equal(result.evidence.unknownStoreValues, 12);
  assert.deepEqual(result.roles.vipCandidates.map(row => row.name), ['rsi']);
  assert.deepEqual(result.roles.dispatchBaseCandidates.map(row => row.name), ['r11']);
  assert.deepEqual(result.roles.opcodeCarrierCandidates.map(row => row.name), ['rax']);
  assert.deepEqual(result.roles.handlerTargetCarrierCandidates.map(row => row.name), ['r8']);
  assert.equal(result.roles.vspCandidates[0].name, 'rbp');
  assert.equal(result.phases.initialization.status, 'unknown'); assert.equal(result.phases.fixup.status, 'unknown');
  assert.equal(result.phases.businessExecution.status, 'unknown'); assert.equal(result.phases.dispatchExecution.status, 'observed-candidate');
  for (const key of ['vmRoleProved','vmIsaProved','wholeVmRecovered','businessAccepted','wholeFunctionCoverageProved','wholeBinaryVerified']) assert.equal(result[key], false);
});

test('partial 0x39 and 0x5c dictionary entries retain unknown outputs and have no invented semantic labels', () => {
  const result = deriveVmContextModel(sources());
  for (const sourceValue of ['0x39','0x5c']) {
    const row = result.observedHandlerDictionary.find(entry => entry.sourceValue === sourceValue);
    assert.equal(row.status, 'partially-consistent-unknown-preserved'); assert.deepEqual(row.unknownGprs, ['r10']);
    assert.equal(row.unknownStores, 2); assert.equal(row.semanticOpcodeLabel, null); assert.equal(row.instructionSemanticsProved, false);
  }
});

test('mixed target, duplicated evidence and upgraded source claims are rejected', () => {
  for (const mutate of [
    x => x[1].handlers.targetSha256 = sha('d'),
    x => { x[1].recurrence.occurrences[0] = structuredClone(x[0].recurrence.occurrences[0]); x[1].handlers.bodies[0].sourceOccurrence = x[0].handlers.bodies[0].sourceOccurrence; x[1].selection.bodies[0].sourceOccurrence = x[0].selection.bodies[0].sourceOccurrence; },
    x => x[0].handlers.vmRoleProved = true,
    x => x[0].handlers.bodies[0].assessment.gprs[0].name = 'fake',
  ]) { const evidence = sources(); mutate(evidence); assert.throws(() => deriveVmContextModel(evidence), /Invalid VM context evidence/); }
});

test('profile binds every source by committed SHA and saves an exact CAS report', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-context-')), store = new AnalysisArtifacts(path.join(root, 'analysis-data'));
  t.after(async () => { await store.dispose(); fs.rmSync(root, { recursive: true, force: true }); });
  const handlerRefs = [];
  for (let i = 0; i < 2; i++) {
    const source = page(i, store), h = store.save({ kind: 'vm-recorded-handlers', action: 'assess', result: source.handlers }, { pretty: true });
    handlerRefs.push({ id: h.id, sha256: store.metadata(h.id).result.recordSha256 });
  }
  const mgr = { analysis: { artifacts: store }, checkCancelled() {} }, reply = runVmContextProfile(mgr, { handler_refs: handlerRefs }).context;
  assert.equal(reply.evidence.occurrences, 16); assert.equal(reply.vmRoleProved, false);
  assert.equal(fs.existsSync(reply.reportPath), true); assert.equal(store.metadata(reply.reportId).result.recordSha256, reply.reportSha256);
  const full = store.get(reply.reportId); assert.equal(full.result.sourceReports.length, 2);
  assert.equal(full.result.sourceReports.every(group => Object.values(group).every(ref => fs.existsSync(ref.path))), true);
  const audit = spawnSync(path.resolve('runtimes/ghidra/python/python.exe'), ['-I','-B','scripts/verify_vm_context_model.py',reply.reportPath,reply.reportSha256], { encoding: 'utf8' });
  assert.equal(audit.status, 0, audit.stderr); assert.equal(JSON.parse(audit.stdout).passed, true);
  assert.throws(() => runVmContextProfile(mgr, { handler_refs: [{ ...handlerRefs[0], sha256: sha('f') }] }), /SHA-256 differs/);
});

test('public context mode is exclusive and accepts no caller role or phase assertions', () => {
  assert.equal(contextProfileSchema.additionalProperties, false); assert.equal(recoveryProfileSchema.properties.context, contextProfileSchema);
  const ref = { id: '11111111-1111-4111-8111-111111111111', sha256: sha('a') };
  for (const extra of [{ vip: 'rsi' }, { phase: 'business' }, { semantics: { '0x39': 'ret' } }])
    assert.throws(() => runVmContextProfile({}, { handler_refs: [ref], ...extra }), /requires only handler_refs/);
  assert.throws(() => runRecoveryProfile({}, { recovery: { context: { handler_refs: [ref] }, handlers: {} } }, {}), /requires exactly/);
});
