import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createAnalysisService } from '../analysis_tools.js';
import { vmContextEvidence } from '../source/evidence_adapters/vm_context.js';
import { runRecoveryProfile } from '../source/vm_recovery_profile.js';

const [out, artifactsRoot, id, sha256] = process.argv.slice(2);
const output = path.resolve(out), artifactDir = path.resolve(artifactsRoot);
assert(!fs.existsSync(output), 'Preserve previous replay runs');
assert(/^[a-f0-9-]{36}$/.test(id) && /^[a-f0-9]{64}$/.test(sha256));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const cfg = { artifactDir, projectRoot: path.join(output, 'projects') };
const analysis = createAnalysisService({}, cfg);
try {
  const model = analysis.artifacts.get(id).result;
  const prepared = vmContextEvidence(analysis.artifacts, { scope: { sha256: model.targetSha256 } }, { id, sha256 }).request;
  const parent = JSON.parse(Buffer.from(prepared.parents.find(p => JSON.parse(Buffer.from(p.bytes)).kind === 'vm-handler-windows').bytes)).result;
  const recordings = parent.source.windows.map(w => ({ id: w.reportId, sha256: w.reportSha256 }));
  const frozen = [prepared.root, ...prepared.parents].map(p => ({ path: p.path, sha256: p.sha256 }));
  for (const window of parent.source.windows) {
    frozen.push({ path: path.join(artifactDir, 'debug-traces', 'records', window.reportId + '.json'), sha256: window.reportSha256 });
    frozen.push({ path: path.join(artifactDir, 'debug-traces', 'blobs', window.traceSha256 + '.bin'), sha256: window.traceSha256 });
  }
  for (const p of frozen) assert.equal(hash(fs.readFileSync(p.path)), p.sha256);
  fs.mkdirSync(output, { recursive: true });
  const mgr = { analysis, checkCancelled() {}, scope: { getStore: () => ({ signal: new AbortController().signal }) } };
  for (const name of ['get', 'spawnWorker', 'performDebug', 'run', 'close']) mgr[name] = () => assert.fail('No native execution in phase context replay');
  const request = { recordings, target_sha256: model.targetSha256, phase_model: true, phase_context_ref: { id, sha256 }, limit: 64 };
  const pages = [];
  for (const offset of [0, model.observedHandlerDictionary[0].sourceOccurrence]) {
    const view = (await runRecoveryProfile(mgr, { recovery: { observations: { ...request, offset } } }, cfg)).observations;
    const result = analysis.artifacts.get(view.reportId).result;
    pages.push({ reportPath: view.reportPath, reportSha256: view.reportSha256, offset, counts: result.phaseModel.counts,
      annotation: result.phaseModel.contextAnnotation, kinds: [...new Set(result.phaseModel.groups.map(g => g.contextPhase.kind))] });
  }
  for (const p of frozen) assert.equal(hash(fs.readFileSync(p.path)), p.sha256);
  const report = { schema: 'ig5-phase-context-replay-v1', ok: true, contextRef: { id, sha256 }, inputRefs: frozen, pages,
    sourceInputsUnchanged: true, nativeTargetExecuted: false, decoderExecuted: false, modelApiCalled: false,
    cleanupConfirmed: analysis.jobs.active === null && analysis.jobs.queue.length === 0, phaseClassificationProved: false };
  assert(report.cleanupConfirmed); fs.writeFileSync(path.join(output, 'phase-context-replay.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify({ ok: true, windows: recordings.length, segments: pages[0].annotation.segments.length,
    matchedGroups: pages[0].annotation.matchedGroups, report: path.join(output, 'phase-context-replay.json') }));
} finally { await analysis.dispose(); }
