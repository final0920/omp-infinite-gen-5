import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { AnalysisArtifacts } from '../source/analysis_artifacts.js';
import { contextPage } from './fixtures/vm_context_cases.mjs';
import { runVmContextProfile } from '../source/vm_context_profile.js';
import { runRecoveryProfile } from '../source/vm_recovery_profile.js';
import { validateFunctionContract } from '../source/vm_function_contract.js';

const declaration = () => ({ schema: 'ig5-function-contract-v1', targetSha256: 'a'.repeat(64), entryRva: '0x1000', normalReturn: 'native-ret',
  input: { register: 'rcx', bits: 8, minimum: '0x0', maximum: '0xff' }, outputs: { returnRegister: 'rax', memory: [{ rva: '0x3000', bytes: 8 }] },
  environment: 'single-threaded-no-external-calls', exclusions: ['external calls', 'exceptions', 'concurrency'] });
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-progress-')), store = new AnalysisArtifacts(root);
  const mgr = { analysis: { artifacts: store }, checkCancelled() {} };
  for (const key of ['get','rpc','performDebug','spawnWorker','run','close','approve']) mgr[key] = () => assert.fail('Readonly progression cannot execute');
  t.after(async () => { await store.dispose(); assert.equal(path.dirname(root), os.tmpdir()); assert(path.basename(root).startsWith('ig5-progress-')); fs.rmSync(root, { recursive: true, force: true }); });
  const invoke = (mode, args) => runRecoveryProfile(mgr, { recovery: { [mode]: args } }, {})[mode];
  const ref = view => ({ id: view.reportId, sha256: view.reportSha256 });
  const saved = (kind, action, result) => { const s = store.save({ kind, action, result }); return { id: s.id, sha256: store.metadata(s.id).result.recordSha256 }; };
  const context = (run, mutation = () => {}) => {
    const p = contextPage(0);
    for (const row of p.recurrence.occurrences) { row.firstRecordingId = run; row.lastRecordingId = run; }
    p.selection.source = { schema: 'ig5-native-observations-v1', targetSha256: 'a'.repeat(64), identity: { runId: run, threadId: 1, runtimeBase: '0x140000000' } };
    p.recurrence.source = p.selection.source;
    mutation(p);
    p.handlers.sourceRecurrence = saved('vm-flow-recurrences','validate',p.recurrence);
    const s = saved('vm-handler-windows','select',p.selection);
    p.handlers.sourceSelection = { ...s, path: path.join(store.directory('records'),s.id + '.json') };
    return ref(runVmContextProfile(mgr, { handler_refs: [saved('vm-recorded-handlers','assess',p.handlers)] }).context);
  };
  const contract = ref(invoke('declare_contract', { contract: declaration() }));
  return { mgr, store, invoke, ref, saved, context, contract };
}

test('distinct runs support relations, while inputs/instances and ordinary-switch remain unresolved', t => {
  const f = fixture(t), refs = [f.context('run-a'), f.context('run-b')];
  const view = f.invoke('role_compare',{ context_refs: refs, contract_ref: f.contract }), report = f.store.get(view.reportId).result;
  assert.equal(report.status,'cross-run-candidate-relations-only'); assert.equal(report.independence.distinctObservedRuns,2);
  assert.equal(report.independence.independentInputs,'unknown'); assert.equal(report.independence.independentVmInstances,'unknown');
  assert(report.competingExplanations.every(c => c.status === 'unresolved')); assert.equal(report.vmRoleProved,false);
  assert(report.relations.some(r => r.name === 'rsi' && r.sameObservedFetchDelta));
  const repeated = f.invoke('role_compare',{ context_refs: [refs[0],f.context('run-a')], contract_ref: f.contract });
  assert.equal(repeated.independence.distinctObservedRuns,1); assert.equal(repeated.status,'insufficient-independent-runs');
});
test('candidate changes are retained as counterobservations, never normalized by runtime base', t => {
  const f = fixture(t), first = f.context('a'), second = f.context('b', p => {
    for (const o of p.recurrence.occurrences) { const u = o.sourceAddressInputUpdates[0]; u.after = '0x' + (BigInt(u.before) + 2n).toString(16); u.deltaModulo64 = '0x2'; }
  });
  const view = f.invoke('role_compare', { context_refs: [first,second], contract_ref: f.contract });
  const result = f.store.get(view.reportId).result;
  assert.equal(result.relations.find(r => r.family === 'vipCandidates' && r.name === 'rsi').sameObservedFetchDelta,false);
  assert.equal(result.independence.addressNormalization,'none');
});
test('same bytecode address and registers in different observations never merge unknown decode memory', t => {
  const f = fixture(t), contexts = [f.context('a'),f.context('b')];
  const comparison = f.ref(f.invoke('role_compare',{ context_refs: contexts, contract_ref: f.contract }));
  const view = f.invoke('program',{ comparison_ref: comparison }), graph = f.store.get(view.reportId).result;
  assert.equal(graph.nodes.length,16); assert.equal(new Set(graph.nodes.map(n => n.id)).size,16);
  assert.equal(graph.nodes[0].identity.bytecodePositionCandidate,graph.nodes[8].identity.bytecodePositionCandidate);
  assert.equal(graph.edges.length,0); assert.equal(graph.unresolvedEdges.length,32);
  assert(graph.nodes.every(n => !n.terminalReturnProved && n.fullStateEffects.assessment.orderedStores.length));
  const checked = f.invoke('function_check',{ program_ref: f.ref(view) }), assessment = f.store.get(checked.reportId).result;
  assert.equal(assessment.finiteTesting.cases,0); assert.equal(assessment.universalProof,false); assert.equal(assessment.businessAccepted,false);
  assert.equal(assessment.domainSize,'256'); assert.equal(checked.status,'unsupported-incomplete-program-semantics');
});
test('changed candidate/graph bytes and scope upgrades cannot be laundered through fresh committed reports', t => {
  const f = fixture(t), comparison = f.ref(f.invoke('role_compare',{ context_refs: [f.context('a')], contract_ref: f.contract }));
  const c = f.store.get(comparison.id).result; c.businessAccepted = true;
  const forged = f.saved('vm-role-comparison','compare',c);
  assert.throws(() => f.invoke('program',{ comparison_ref: forged }), /differs from audited/);
  const view = f.invoke('program',{ comparison_ref: comparison }), graph = f.store.get(view.reportId).result;
  graph.nodes[0].terminalReturnProved = true;
  assert.throws(() => f.invoke('function_check',{ program_ref: f.saved('vm-observed-program','derive',graph) }), /differs from audited/);
  assert.throws(() => f.invoke('role_compare',{ context_refs: [], contract_ref: f.contract }), /1..8/);
  assert.throws(() => f.invoke('role_compare',{ context_refs: [f.context('b')], contract_ref: { ...f.contract, sha256: '0'.repeat(64) } }), /SHA differs/);
});
test('contract widths, aliases, unknown fields and accessor data are refused without executing caller code', () => {
  for (const mutate of [c => c.input.maximum = '0x100', c => c.outputs.memory.push({ rva: '0x3004', bytes: 8 }), c => c.nativeTargetExecuted = true,
    c => Object.defineProperty(c, 'schema', { get() { assert.fail('accessor executed'); }, enumerable: true })]) {
    const c = declaration(); mutate(c); assert.throws(() => validateFunctionContract(c));
  }
});
