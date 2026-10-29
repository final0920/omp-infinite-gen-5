// Synthetic format and committed-candidate fixture. No instructions are executed.
import path from 'node:path';
import { AnalysisArtifacts } from '../../source/analysis_artifacts.js';
import { analyzeVmObservations } from '../../source/vm_observations.js';
import { runVmContextProfile } from '../../source/vm_context_profile.js';
import { contextPage } from './vm_context_cases.mjs';
import { observationWindow, observationHash as hash } from './vm_observation_cases.mjs';

export async function buildPhaseContextCase(analysis, cfg, { tamperBody = false, tamperDescriptor = false, tamperInitial = false, runId, inputValue } = {}) {
  const page = contextPage(0), count = 174, base = observationWindow({ count, reads: false });
  const names = 'rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split(' ');
  const states = Array.from({ length: count + 1 }, () => Object.fromEntries(names.map(n => [n, '0x0'])));
  if(runId!==undefined)base.summary.runId=runId;
  if(inputValue!==undefined)states[0].rcx=inputValue;
  const pcs = Array.from({ length: count + 1 }, (_, n) => '0x' + (0x1000 + n).toString(16)), reads = new Map();
  for (const o of page.recurrence.occurrences) {
    const n = o.startGroup;
    states[n] = o.initialGprs; states[n + 1] = o.finalGprs;
    states[n + 2] = { ...o.finalGprs, rbp: '0x' + (BigInt(o.initialGprs.rbp) - 8n).toString(16) };
    pcs[n] = '0x2000'; pcs[n + 1] = o.target; pcs[n + 2] = '0x2000';
    reads.set(n, `mr:${o.sourceAddress}:1:${o.sourceValue}`); reads.set(n + 1, `mr:${o.initialGprs.rbp}:8:0x0`);
  }
  const rows = ['h:ig5-native-x64-v2'];
  for (let n = 0; n < count; n++) {
    rows.push('r:' + names.map(name => states[n][name]).join(':'), 'e:0x202');
    if (reads.has(n)) rows.push(reads.get(n));
    rows.push(`i:${pcs[n]}:1:90`);
  }
  rows.push('f:' + names.map(name => states[count][name]).join(':') + ':' + pcs[count] + ':0x202', '');
  base.data = Buffer.from(rows.join('\n')); Object.assign(base.summary, { entry: pcs[0], exit: pcs[count - 1], bytes: base.data.length, sha256: hash(base.data) });
  const debugStore = new AnalysisArtifacts(path.join(cfg.artifactDir, 'debug-traces'));
  let ref;
  try {
    const blob = debugStore.put(base.data), saved = debugStore.save({ kind: 'debug-trace', action: 'record', result: { ...base.summary, input: blob } });
    ref = { id: saved.id, sha256: debugStore.metadata(saved.id).result.recordSha256 };
    Object.assign(base.source, { reportId: ref.id, reportSha256: ref.sha256, locationFingerprint: hash(Buffer.from('null')) });
  } finally { await debugStore.dispose(); }
  const groups = new Map();
  const observation = analyzeVmObservations({ targetSha256: base.summary.targetSha256, windows: [base], limit: 1 }, group => groups.set(group.groupIndex, group));
  const { stopGroups, pagination, ...source } = observation;
  page.recurrence.source = source; page.selection.source = source;
  page.recurrence.descriptor = [{ runtimePc: '0x2000', bytes: tamperDescriptor ? 'cc' : '90' }];
  for (let i = 0; i < 8; i++) {
    const o = page.recurrence.occurrences[i], body = page.selection.bodies[i];
    Object.assign(o, { endGroup: o.startGroup, groupCount: 1, firstPause: o.startGroup + 1, lastPause: o.startGroup + 2,
      firstRecordingId: ref.id, lastRecordingId: ref.id, sourceBytes: 1, status: 'consistent-recorded-ordinary-state' });
    body.groups = [groups.get(o.startGroup + 1)]; body.nextFetchGroup = o.startGroup + 2;
  }
  if (tamperBody) page.selection.bodies[0].groups[0].before.gprs.rax = '0xff';
  if (tamperInitial) page.recurrence.occurrences[0].initialGprs = { ...page.recurrence.occurrences[0].initialGprs, rax: '0xff' };
  const store = analysis.artifacts;
  const r = store.save({ kind: 'vm-flow-recurrences', action: 'validate', result: page.recurrence });
  const s = store.save({ kind: 'vm-handler-windows', action: 'select', result: page.selection });
  page.handlers.sourceRecurrence = { id: r.id, sha256: store.metadata(r.id).result.recordSha256 };
  page.handlers.sourceSelection = { id: s.id, path: path.join(store.directory('records'), s.id + '.json'), sha256: store.metadata(s.id).result.recordSha256 };
  const h = store.save({ kind: 'vm-recorded-handlers', action: 'assess', result: page.handlers });
  const model = runVmContextProfile({ analysis, checkCancelled() {} }, { handler_refs: [{ id: h.id, sha256: store.metadata(h.id).result.recordSha256 }] }).context;
  return { window: base, request: { recordings: [ref], target_sha256: base.summary.targetSha256, phase_model: true,
    phase_context_ref: { id: model.reportId, sha256: model.reportSha256 } }, model, debugRef: ref };
}
