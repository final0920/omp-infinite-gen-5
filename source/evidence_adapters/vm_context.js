import path from 'node:path';
import { readStableFile, hashBytes } from '../analysis_artifacts.js';

const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
export const VM_CONTEXT_PROPERTY = 'vm-context-candidate-derivation-and-provenance';
export function exactReportRef(ref) {
  if (!ref || typeof ref !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(ref))
    || Reflect.ownKeys(ref).length !== 2 || ['id','sha256'].some(k => !Object.hasOwn(ref,k)
      || !Object.hasOwn(Object.getOwnPropertyDescriptor(ref,k),'value'))
    || typeof ref.id !== 'string' || typeof ref.sha256 !== 'string'
    || !UUID.test(ref.id) || !SHA.test(ref.sha256)) fail('INVALID_RESEARCH_REF', 'Only exact committed UUID/SHA references are supported');
  return ref;
}
export function evidenceReadBudget() { return { bytes: 0, cache: new Map() }; }
export function committedBytes(artifacts, ref, kind, action, budget = evidenceReadBudget()) {
  exactReportRef(ref);
  if (budget.cache.has(ref.id)) {
    const old = budget.cache.get(ref.id);
    if (old.sha256 !== ref.sha256 || old.record.kind !== kind || old.record.action !== action) fail('ARTIFACT_CHANGED', 'Conflicting committed identity');
    return old;
  }
  if (budget.cache.size >= 64) fail('EVIDENCE_READ_LIMIT', 'At most 64 committed reports per scoped evidence/receipt read');
  if (artifacts.metadata(ref.id).result.recordSha256 !== ref.sha256) fail('ARTIFACT_CHANGED', 'Committed metadata SHA differs');
  const filename = path.join(artifacts.directory('records'), ref.id + '.json');
  const { data } = readStableFile(filename, Math.min(4 * 1024 ** 2, 8 * 1024 ** 2 - budget.bytes));
  budget.bytes += data.length;
  if (hashBytes(data) !== ref.sha256) fail('ARTIFACT_CHANGED', 'Committed report bytes differ');
  const record = JSON.parse(data);
  if (record.schemaVersion !== 1 || record.id !== ref.id || record.kind !== kind || record.action !== action) fail('UNSUPPORTED_EVIDENCE', 'Committed kind/action/schema differs');
  const value = { id: ref.id, sha256: ref.sha256, path: filename, bytes: data, record };
  budget.cache.set(ref.id, value); return value;
}
const samePath = (a, b) => typeof a === 'string' && path.isAbsolute(a)
  && (process.platform === 'win32' ? path.resolve(a).toLowerCase() === path.resolve(b).toLowerCase() : path.resolve(a) === path.resolve(b));

/** Only the committed aggregation and its three typed immediate inputs are within assurance. */
export function vmContextEvidence(artifacts, task, ref, budget = evidenceReadBudget()) {
  const root = committedBytes(artifacts, ref, 'vm-context-model', 'derive', budget), model = root.record.result;
  if (model?.schema !== 'ig5-vm-context-model-v1' || model.targetSha256 !== task.scope.sha256
    || model.status !== 'single-run-context-candidates-phases-unknown') fail('RESEARCH_SCOPE_MISMATCH', 'VM context does not bind this target and supported schema');
  if (!Array.isArray(model.sourceReports) || !model.sourceReports.length || model.sourceReports.length > 16) fail('UNSUPPORTED_EVIDENCE', 'VM context requires 1..16 source groups');
  const parents = new Map();
  for (const group of model.sourceReports) {
    if (!group || Object.keys(group).sort().join(',') !== 'handlers,recurrence,selection') fail('UNSUPPORTED_EVIDENCE', 'Unexpected context parent group');
    for (const [key, kind, action, schema] of [
      ['handlers', 'vm-recorded-handlers', 'assess', 'ig5-recorded-handlers-v1'],
      ['recurrence', 'vm-flow-recurrences', 'validate', 'ig5-flow-recurrences-v1'],
      ['selection', 'vm-handler-windows', 'select', 'ig5-recorded-handler-windows-v1'],
    ]) {
      const source = group[key];
      if (!source || Object.keys(source).sort().join(',') !== 'id,path,sha256') fail('UNSUPPORTED_EVIDENCE', 'Unexpected typed parent reference');
      const parent = committedBytes(artifacts, { id: source.id, sha256: source.sha256 }, kind, action, budget);
      if (!samePath(source.path, parent.path) || parent.record.result?.schema !== schema || parent.record.result.targetSha256 !== task.scope.sha256) fail('ARTIFACT_CHANGED', 'Parent location, schema or target differs');
      parents.set(parent.id, parent);
    }
    const h = parents.get(group.handlers.id).record.result;
    for (const [key, field] of [['recurrence', 'sourceRecurrence'], ['selection', 'sourceSelection']]) {
      if (h[field]?.id !== group[key].id || h[field]?.sha256 !== group[key].sha256
        || key === 'selection' && !samePath(h[field]?.path, parents.get(group[key].id).path)) fail('ARTIFACT_CHANGED', 'Handler parent binding differs');
    }
  }
  const parentRefs = [...parents.values()].map(p => ({ id: p.id, sha256: p.sha256, kind: p.record.kind }));
  return { link: { kind: 'vm-context-model', assurance: 'committed-candidate-input-integrity', reportId: root.id, sha256: root.sha256,
    targetSha256: model.targetSha256, dependencyType: 'immutable-bytes', parents: parentRefs,
    supportedProperties: [VM_CONTEXT_PROPERTY],
    limitations: ['Only committed context/handlers/recurrence/selection bytes; earlier capture, decoder and CPU semantics are premises.', 'No VM-role, phase, bytecode-program or function-contract acceptance.'] },
    request: { targetSha256: model.targetSha256, root: { id: root.id, sha256: root.sha256, path: root.path, bytes: root.bytes },
      parents: [...parents.values()].map(p => ({ id: p.id, sha256: p.sha256, path: p.path, bytes: p.bytes })) } };
}
