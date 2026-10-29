import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { AnalysisArtifacts } from '../source/analysis_artifacts.js';
import { FailureRecords } from '../source/failure_record.js';
import { failureBinding } from '../source/failure_adapters.js';
import { CapabilityAcceptance, runtimeIdentity } from '../source/capability_acceptance.js';
import { DiagnosticStore } from '../source/diagnostic_store.js';
import { reference } from './evals/oracle.mjs';

const hash = x => createHash('sha256').update(x).digest('hex');
function fixture(t) {
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-persistent-'));
  const artifacts = new AnalysisArtifacts(path.join(root, 'reports'));
  t.after(async () => { await artifacts.dispose(); assert.equal(path.dirname(root), fs.realpathSync(os.tmpdir())); fs.rmSync(root, { recursive: true, force: true }); });
  const scope = { projectId: 'p', artifactId: 'a', sha256: hash('target'), engine: 'reverse', provider: 'ghidra', attachmentId: 'first', dbRevision: 1 };
  return { root, artifacts, scope };
}
test('failures persist across actual process restart; prior attachment remains historical, no cleanup inferred', t => {
  const { root, artifacts, scope } = fixture(t);
  const store = new FailureRecords({ root, artifacts });
  const input = { operation: 'ig5_ir', scope, semanticInputs: { digest: hash('same input') }, error: { code: 'MEMORY_GAP', message: 'original failure', cleanupConfirmed: false } };
  const saved = store.add(input); assert.equal(saved.indexed, true);
  const script = `import {FailureRecords} from ${JSON.stringify(new URL('../source/failure_record.js', import.meta.url).href)};import {AnalysisArtifacts} from ${JSON.stringify(new URL('../source/analysis_artifacts.js', import.meta.url).href)};const a=new AnalysisArtifacts(${JSON.stringify(path.join(root,'reports'))});const s=new FailureRecords({root:${JSON.stringify(root)},artifacts:a});console.log(JSON.stringify(s.recent(${JSON.stringify(scope)})));await a.dispose();`;
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8' });
  assert.equal(child.status, 0, child.stderr);
  const recovered = JSON.parse(child.stdout)[0];
  assert.equal(recovered.original.message, 'original failure'); assert.equal(recovered.original.cleanupConfirmed, false);
  assert.equal(recovered.reportRef.id, saved.reportRef.id);
  const reopened = new FailureRecords({ root, artifacts });
  assert.equal(reopened.add(input).advice.nextCheck, 'recover-original-execution-owner');
  assert.equal(reopened.add({...input,error:{...input.error,cleanupConfirmed:null}}).advice.needsRediagnosis,true);
  const historical = reopened.recent({ ...scope, attachmentId: 'second', dbRevision: 2 })[0];
  assert.equal(historical.historical, true); assert.equal(historical.advice.cleanupConfirmed, null);
  assert.deepEqual(historical.staleReasons, ['attachmentId-changed', 'dbRevision-changed']);
});
test('persistent failure corruption and failed index retain the original immutable report', t => {
  const { root, artifacts, scope } = fixture(t), store = new FailureRecords({ root, artifacts });
  store.store.updateInvestigationRecords = () => { throw Object.assign(new Error('busy'), { code: 'STORE_BUSY' }); };
  const saved = store.add({ operation: 'ig5_ir', scope, semanticInputs: {}, error: { code: 'STATE_CONFLICT', message: 'original' } });
  assert.equal(saved.reportSaved, true); assert.equal(saved.indexed, false); assert.equal(saved.indexError, 'STORE_BUSY');
  assert.equal(artifacts.get(saved.reportRef.id).result.original.message, 'original');
});
test('long messages and structured native receipts remain retrievable without inferring cleanup', t => {
  const { root, artifacts, scope } = fixture(t), store = new FailureRecords({ root, artifacts });
  const message='original long failure '.repeat(250);
  const error=Object.assign(new Error(message),{code:'PROJECTION_FAILED',analysisFailure:{id:randomUUID(),reportSha256:hash('source'),failedStage:'java-decode',cleanupConfirmed:false},recoveryRequired:true,committed:true,saved:false});
  const saved=store.add({operation:'ig5_ir',scope,semanticInputs:{},error});
  assert.equal(artifacts.read(saved.originalMessageRef.ref).data.toString('utf8'),message);
  const receipt=JSON.parse(artifacts.read(saved.originalReceiptRef.ref).data.toString('utf8'));
  assert.deepEqual(receipt.analysisFailure,error.analysisFailure);
  const recovered=new FailureRecords({root,artifacts}).recent(scope)[0];
  assert.equal(recovered.original.saved,false);assert.equal(recovered.original.recoveryRequired,true);
  assert.equal(recovered.advice.cleanupConfirmed,null);assert.equal(recovered.originalReceiptRef.sha256,saved.originalReceiptRef.sha256);
});
test('tool adapters cover static, data, debug and recovery, bind report content and never persist raw keys', t => {
  const { artifacts } = fixture(t), mgr = { analysis: { artifacts } };
  const a = artifacts.save({ kind: 'test', action: 'read', result: { memory: 'same bytes', runId: 'run1' } });
  const b = artifacts.save({ kind: 'test', action: 'read', result: { memory: 'same bytes', runId: 'run1' } });
  const bind = r => failureBinding('ig5_ir', { recovery: { id: r.id, sha256: artifacts.metadata(r.id).result.recordSha256 } }, mgr);
  assert.deepEqual(bind(a).semanticInputs, bind(b).semanticInputs);
  for (const operation of ['ig5_decompile', 'ig5_crypto', 'ig5_protocol', 'ig5_dbg', 'ig5_emulate', 'ig5_capture_control']) {
    const result = failureBinding(operation, { data: 'secret-test-value', action: 'fixed', run_id: 'run1', stop_seq: 3 }, mgr);
    assert(result.semanticInputs); assert(!JSON.stringify(result).includes('secret-test-value'));
    assert.notDeepEqual(result.semanticInputs, failureBinding(operation, { data: 'secret-test-value', action: 'fixed', run_id: 'run2', stop_seq: 3 }, mgr).semanticInputs);
  }
  assert.equal(failureBinding('unknown-tool', {}, mgr).semanticInputs, null);
});
test('scoped acceptance survives reload as historical; new runtime cannot inherit verified status', t => {
  const { root, artifacts, scope } = fixture(t), manifest = path.join(root, 'runtime.json'); fs.writeFileSync(manifest, '{"version":1}');
  const cfg = { reverseProvider: 'bundled', ghidra: { manifest } };
  const registry = new CapabilityAcceptance({ root, artifacts, cfg, startupId: 'boot1' });
  const dossier = { kind: 'function-dossier', provenance: scope, snapshotDigest: hash('dossier'), function: { ea: '0x140001000' },
    sections: Object.fromEntries(['decompile','cfg','callers','callees','stack'].map(k => [k, { status: 'ok' }])) };
  const ref = registry.registerDossier(dossier); assert(ref);
  const args = ['function-context', 'reverse', 'ghidra', runtimeIdentity(cfg, 'reverse'), [{ attachmentId: 'first', dbRevision: 1 }]];
  const current = registry.view(...args); assert.equal(current.status, 'verified-in-scope'); assert(current.exclusions.includes('semantic-correctness'));
  assert.equal(new CapabilityAcceptance({ root, artifacts, cfg, startupId: 'boot2' }).view(...args).status, 'historical');
  fs.writeFileSync(manifest, '{"version":2}');
  assert.equal(registry.view(...args.slice(0,3), runtimeIdentity(cfg, 'reverse'), args[4]).status, 'historical');
  fs.appendFileSync(path.join(artifacts.root, 'records', `${ref.id}.json`), ' ');
  assert.throws(() => registry.view(...args));
});
test('diagnostic roots reject directory links without creating files through the link', t => {
  const { root } = fixture(t), outside = path.join(root, 'outside'); fs.mkdirSync(outside);
  const alias = path.join(root, 'alias'); fs.symlinkSync(outside, alias, process.platform === 'win32' ? 'junction' : 'dir');
  assert.throws(() => new DiagnosticStore({ root: path.join(alias, 'state') }), { code: 'DIAGNOSTIC_STORE_INVALID' });
  assert.equal(fs.existsSync(path.join(outside, 'state')), false);
});
test('independent VM oracle respects unsigned function return domain', () => {
  assert.deepEqual(reference({ kind: 'toy-vm', values: [0,1,2], delta: 3 }), [{ returned: 4294967293, written: 0 }, { returned: 4, written: 3 }, { returned: 4294967295, written: 6 }]);
});
