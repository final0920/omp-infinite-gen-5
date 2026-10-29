// Original profile entry, bounded worker and committed evidence; no native execution.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createAnalysisService } from '../analysis_tools.js';
import { AnalysisArtifacts } from '../source/analysis_artifacts.js';
import { runRecoveryProfile } from '../source/vm_recovery_profile.js';

const [input, destination] = process.argv.slice(2);
assert(input && destination, 'Usage: accept_vm_phase_reference.mjs FIXTURES NEW_OUTPUT');
const root = path.resolve(input), output = path.resolve(destination);
assert(!fs.existsSync(output), 'Preserve prior acceptance runs');
assert(output !== root && !output.startsWith(root + path.sep), 'Keep input fixtures immutable');
const hash = data => createHash('sha256').update(data).digest('hex');
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'reference-fixtures.json')));
assert.equal(manifest.schema, 'ig5-phase-reference-fixtures-v1'); assert.equal(manifest.nativeTargetExecuted, false);
fs.mkdirSync(output, { recursive: true });
const cfg = { artifactDir: path.join(output, 'artifacts'), projectRoot: path.join(output, 'projects') };
const analysis = createAnalysisService({}, cfg), recordings = new AnalysisArtifacts(path.join(cfg.artifactDir, 'debug-traces'));
const mgr = { analysis, checkCancelled() {} }, cases = [];
for (const name of ['get', 'spawnWorker', 'performDebug', 'run', 'close']) mgr[name] = () => assert.fail('Reference acceptance cannot start native workers');
try {
  for (const entry of manifest.cases) {
    assert(/^[a-z-]+$/.test(entry.name));
    for (const [name, sha] of Object.entries(entry.files)) assert.equal(hash(fs.readFileSync(path.join(root, entry.name, name))), sha);
    const trace = fs.readFileSync(path.join(root, entry.name, 'trace.bin'));
    const stores = fs.readFileSync(path.join(root, entry.name, 'stores.json')), parsed = JSON.parse(stores);
    const summary = JSON.parse(fs.readFileSync(path.join(root, entry.name, 'summary.json')));
    const body = { ...summary, fixtureMode: 'offline-reference-no-native-execution', input: recordings.put(trace),
      storeEvents: { schema: parsed.schema, sha256: hash(stores), bytes: stores.length, input: recordings.put(stores), groups: parsed.events.length,
        completeDecodedStoreGroups: parsed.events.filter(e => e.completeDecodedStoreSet).length, actualWriteCausalityProved: false, cpuWriteFootprintProved: false } };
    const saved = recordings.save({ kind: 'debug-trace', action: 'record', result: body });
    const ref = { id: saved.id, sha256: recordings.metadata(saved.id).result.recordSha256 };
    const request = { recordings: [ref], target_sha256: summary.targetSha256 };
    const invoke = extra => runRecoveryProfile(mgr, { recovery: { observations: { ...request, ...extra } } }, cfg);
    const reports = [];
    for (const extra of [{ phase_model: true, limit: 32 }, { phase_model: true, offset: 9, limit: 1 }, { limit: 32 }]) {
      const view = (await invoke(extra)).observations, result = analysis.artifacts.get(view.reportId).result;
      if (extra.phase_model) assert.equal(result.phaseModel.phaseVerified, false);
      else assert.equal(result.phaseModel, undefined, 'Default observations remain unchanged');
      reports.push({ path: view.reportPath, sha256: view.reportSha256 });
    }
    const original = analysis.observeNative;
    const negatives = [];
    for (const [name, mutate] of [
      ['invented-initialization', r => { r.phaseModel.groups[0].initialization = 'verified'; }],
      ['changed-summary', r => { r.phaseModel.counts.codeChangeGroups++; }],
      ['invented-return', r => { r.phaseModel.groups[0].events.exit = 'verified-return'; }],
      ['changed-version', r => { r.phaseModel.groups[0].versions[0].version.binding.reportSha256 = '0'.repeat(64); }],
      ...(entry.name === 'clc' ? [['changed-store-ref', r => { r.phaseModel.groups[9].versions[0].relation.storeObservations[0].source.groupIndex = 5; }]] : []),
    ]) {
      analysis.observeNative = async (...args) => { const result = await original(...args); mutate(result); return result; };
      const before = fs.readdirSync(analysis.artifacts.directory('records')).length;
      await assert.rejects(invoke({ phase_model: true, limit: 32 }), e => ['INVALID_VM_PHASE_MODEL', 'CODE_VERSION_MISMATCH'].includes(e.code));
      assert.equal(fs.readdirSync(analysis.artifacts.directory('records')).length, before);
      negatives.push(name);
    }
    analysis.observeNative = original;
    const blobPath = path.join(recordings.directory('blobs'), hash(stores) + '.bin');
    const before = fs.readdirSync(analysis.artifacts.directory('records')).length;
    try {
      fs.appendFileSync(blobPath, ' ');
      await assert.rejects(invoke({ phase_model: true, limit: 1 }), /hash|digest/i);
      assert.equal(fs.readdirSync(analysis.artifacts.directory('records')).length, before);
    } finally { fs.writeFileSync(blobPath, stores); }
    negatives.push('corrupt-sidecar-outside-preview');
    for (const [name, sha] of Object.entries(entry.files)) assert.equal(hash(fs.readFileSync(path.join(root, entry.name, name))), sha);
    assert.equal(analysis.jobs.active, null); assert.equal(analysis.jobs.queue.length, 0);
    cases.push({ name: entry.name, recording: { ...ref, path: path.join(recordings.directory('records'), saved.id + '.json') }, reports, negatives });
  }
} finally { await recordings.dispose(); await analysis.dispose(); }
const receipt = { schema: 'ig5-phase-reference-acceptance-v1', ok: true, cases, inputFixtures: root,
  fixtureManifestSha256: hash(fs.readFileSync(path.join(root, 'reference-fixtures.json'))), sourceInputsUnchanged: true,
  cleanupConfirmed: analysis.jobs.active === null && analysis.jobs.queue.length === 0, nativeTargetExecuted: false,
  phaseClassificationProved: false, scope: 'Original profile with committed simulated recordings, worker provenance and negative cases; no native collection' };
assert(receipt.cleanupConfirmed);
fs.writeFileSync(path.join(output, 'acceptance.json'), JSON.stringify(receipt, null, 2));
console.log(JSON.stringify({ ok: true, cases: cases.length, negativeChecks: cases.reduce((n,c) => n+c.negatives.length,0), output }));
