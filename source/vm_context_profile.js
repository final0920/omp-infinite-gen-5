import path from 'node:path';
import { hashBytes, readStableFile } from './analysis_artifacts.js';
import { deriveVmContextModel } from './vm_context_model.js';

const REF = { type: 'object', properties: { id: { type: 'string' }, sha256: { type: 'string', pattern: '^[a-f0-9]{64}$' } }, required: ['id','sha256'], additionalProperties: false };
export const contextProfileSchema = { type: 'object', properties: {
  handler_refs: { type: 'array', minItems: 1, maxItems: 16, items: REF },
}, required: ['handler_refs'], additionalProperties: false };
const fail = message => { throw new Error('VM context model: ' + message); };
function exactObject(value, keys) {
  return value && typeof value === 'object' && [Object.prototype, null].includes(Object.getPrototypeOf(value))
    && Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}
function committed(store, ref, kind, action) {
  if (!exactObject(ref, ['id','sha256']) || typeof ref.id !== 'string' || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(ref.id)
    || typeof ref.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(ref.sha256)) fail('exact committed UUID/SHA required');
  if (store.metadata(ref.id).result.recordSha256 !== ref.sha256) fail('committed report SHA-256 differs');
  const reportPath = path.join(store.directory('records'), ref.id + '.json'), { data } = readStableFile(reportPath, 8 * 1024 ** 2);
  if (hashBytes(data) !== ref.sha256) fail('committed report bytes changed');
  const record = JSON.parse(data);
  if (record.id !== ref.id || record.kind !== kind || record.action !== action) fail('committed report identity differs');
  return { result: record.result, source: { id: ref.id, path: reportPath, sha256: ref.sha256 } };
}
export function runVmContextProfile(mgr, input) {
  if (!exactObject(input, ['handler_refs']) || !Array.isArray(input.handler_refs) || !input.handler_refs.length || input.handler_refs.length > 16) fail('requires only handler_refs[1..16]');
  const identities = input.handler_refs.map(ref => ref?.id + ':' + ref?.sha256);
  if (new Set(identities).size !== identities.length) fail('duplicate handler reference');
  mgr.checkCancelled(); const store = mgr.analysis.artifacts, sources = [];
  for (const handlerRef of input.handler_refs) {
    mgr.checkCancelled(); const handlerRecord = committed(store, handlerRef, 'vm-recorded-handlers', 'assess'), handlers = handlerRecord.result;
    if (handlers?.schema !== 'ig5-recorded-handlers-v1') fail('handler schema differs');
    const recurrenceRef = handlers.sourceRecurrence, selectionRef = handlers.sourceSelection;
    const recurrenceRecord = committed(store, { id: recurrenceRef?.id, sha256: recurrenceRef?.sha256 }, 'vm-flow-recurrences', 'validate');
    const selectionRecord = committed(store, { id: selectionRef?.id, sha256: selectionRef?.sha256 }, 'vm-handler-windows', 'select');
    sources.push({ handlers, recurrence: recurrenceRecord.result, selection: selectionRecord.result,
      handlerRef: { id: handlerRef.id, sha256: handlerRef.sha256 }, recurrenceRef: { id: recurrenceRef.id, sha256: recurrenceRef.sha256 },
      selectionRef: { id: selectionRef.id, path: selectionRef.path, sha256: selectionRef.sha256 },
      sourceReports: { handlers: handlerRecord.source, recurrence: recurrenceRecord.source, selection: selectionRecord.source } });
  }
  mgr.checkCancelled(); const model = deriveVmContextModel(sources);
  model.sourceReports = sources.map(source => source.sourceReports);
  const saved = store.save({ kind: 'vm-context-model', action: 'derive', result: model }, { pretty: true, maxBytes: 4 * 1024 ** 2 });
  mgr.checkCancelled(); const reportPath = path.join(store.directory('records'), saved.id + '.json'), reportSha256 = store.metadata(saved.id).result.recordSha256;
  return { context: { schema: model.schema, status: model.status, targetSha256: model.targetSha256, evidence: model.evidence,
    roles: model.roles, phases: model.phases, observedHandlerDictionary: model.observedHandlerDictionary,
    reportId: saved.id, reportPath, reportSha256, nativeTargetExecuted: false, vmRoleProved: false, vmIsaProved: false,
    wholeVmRecovered: false, businessAccepted: false, wholeFunctionCoverageProved: false,
    nextObligations: model.nextObligations, scope: model.scope } };
}
