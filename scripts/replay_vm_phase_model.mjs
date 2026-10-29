import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createAnalysisService } from '../analysis_tools.js';
import { runRecoveryProfile } from '../source/vm_recovery_profile.js';

const [outputArg, artifactsArg, id, sha256] = process.argv.slice(2);
const output = path.resolve(outputArg), artifactDir = path.resolve(artifactsArg);
assert(!fs.existsSync(output), 'Preserve previous replay outputs');
assert(/^[a-f0-9-]{36}$/.test(id) && /^[a-f0-9]{64}$/.test(sha256));
const hash = value => createHash('sha256').update(value).digest('hex');
const sourcePath = path.join(artifactDir, 'debug-traces', 'records', id + '.json');
const bytes = fs.readFileSync(sourcePath); assert.equal(hash(bytes), sha256);
const source = JSON.parse(bytes), body = source.result;
assert.equal(body.input.ref, 'sha256:' + body.sha256);
const tracePath = path.join(artifactDir, 'debug-traces', 'blobs', body.sha256 + '.bin');
assert.equal(hash(fs.readFileSync(tracePath)), body.sha256);
fs.mkdirSync(output, { recursive: true });
const cfg = { artifactDir, projectRoot: path.join(output, 'projects') }, analysis = createAnalysisService({}, cfg);
const mgr = { analysis, checkCancelled() {}, scope: { getStore: () => ({ signal: new AbortController().signal }) } };
for (const method of ['get', 'performDebug', 'spawnWorker', 'run', 'close']) mgr[method] = () => assert.fail('No native service in offline replay');
try {
  const request = { recordings: [{ id, sha256 }], target_sha256: body.targetSha256, phase_model: true, limit: 64 };
  const first = (await runRecoveryProfile(mgr, { recovery: { observations: request } }, cfg)).observations;
  const full = analysis.artifacts.get(first.reportId).result;
  const overlap = (await runRecoveryProfile(mgr, { recovery: { observations: { ...request, offset: 63, limit: 2 } } }, cfg)).observations;
  const second = analysis.artifacts.get(overlap.reportId).result;
  if (full.phaseModel.groups.length === 64) assert.deepEqual(full.phaseModel.groups[63], second.phaseModel.groups[0]);
  assert.equal(hash(fs.readFileSync(sourcePath)), sha256); assert.equal(hash(fs.readFileSync(tracePath)), body.sha256);
  const report = { schema: 'ig5-vm-phase-replay-v1', ok: true, sourceImplementation: fileURLToPath(new URL('../source/vm_phase_model.js', import.meta.url)),
    implementationDigests: Object.fromEntries(['vm_phase_model.js', 'code_epoch_map.js', 'vm_observations.js', 'vm_observation_profile.js', 'analysis_worker.js'].map(name => [name, hash(fs.readFileSync(new URL('../source/' + name, import.meta.url)))])),
    sourcePath, sourceSha256: sha256, tracePath, traceSha256: body.sha256, fullReportPath: first.reportPath, fullReportSha256: first.reportSha256,
    overlapReportPath: overlap.reportPath, overlapReportSha256: overlap.reportSha256,
    counts: full.phaseModel.counts, codeEpochs: full.phaseModel.codeEpochs, sourceInputsUnchanged: true,
    execution: { nativeTargetExecuted: false, decoderExecuted: false, modelApiCalled: false },
    phaseVerified: false, smcCoverageComplete: false, cleanupConfirmed: !analysis.jobs.active && !analysis.jobs.queue.length };
  assert(report.cleanupConfirmed); fs.writeFileSync(path.join(output, 'phase-replay.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify({ ok: true, counts: report.counts, report: path.join(output, 'phase-replay.json') }));
} finally { await analysis.dispose(); }
