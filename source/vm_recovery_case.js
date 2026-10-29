import { createHash } from 'node:crypto';

export const RECOVERY_LIMITS = Object.freeze({ caseBytes: 256 * 1024, events: 128, references: 64,
  referenceBytes: 8 * 1024 * 1024, totalReferenceBytes: 16 * 1024 * 1024 });
export const RECOVERY_STAGES = Object.freeze({
  admission: Object.freeze([]), capture: Object.freeze(['admission']), vm_model: Object.freeze(['capture']), isa: Object.freeze(['vm_model']),
  program: Object.freeze(['capture', 'vm_model', 'isa']), business: Object.freeze(['program']), coverage: Object.freeze(['business']),
  autonomy: Object.freeze(['coverage']), deployment: Object.freeze(['coverage', 'autonomy']),
});
export const RECOVERY_FAILURES = Object.freeze({
  PROVENANCE_UNADMITTED: ['admission', 'establish-provenance'],
  TRACE_PREFIX_NOT_RETURNED: ['capture', 'investigate-trigger-and-return'],
  MEMORY_GAP: ['capture', 'resolve-observation-gap'],
  STATE_CONFLICT: ['capture', 'locate-first-state-divergence'],
  SMC_EPOCH_MISMATCH: ['capture', 'recapture-code-epoch'],
  FETCH_UNPROVEN: ['vm_model', 'test-fetch-and-phase-hypothesis'],
  UNKNOWN_ALIAS: ['isa', 'derive-memory-alias-obligation'],
  LIVE_UNKNOWN_FLAG: ['isa', 'repair-and-verify-instruction-semantics'],
  UNSUPPORTED_SEMANTICS: ['isa', 'repair-and-verify-instruction-semantics'],
  UNRESOLVED_INDIRECT: ['program', 'resolve-virtual-control-transfer'],
  ORACLE_MISMATCH: ['business', 'locate-first-business-divergence'],
  UNRESOLVED_GUARD: ['coverage', 'derive-counterexample-path'],
  SMT_UNKNOWN: ['business', 'decompose-proof-obligation'],
  BUDGET_EXHAUSTED: ['program', 'design-bounded-summary'],
  CLEANUP_UNCONFIRMED: ['capture', 'recover-original-execution-owner'],
  DEPLOYMENT_MISMATCH: ['deployment', 'revalidate-installed-build'],
});
for (const route of Object.values(RECOVERY_FAILURES)) Object.freeze(route);
const states = new Set(['partial', 'candidate', 'failed', 'unknown']);
const kinds = new Set(['source', 'checkpoint', 'trace', 'image-manifest', 'projection', 'vm-model', 'isa', 'program', 'business', 'validation']);
const scopeKeys = ['targetSha256', 'architecture', 'family', 'version', 'build', 'producerSha256',
  'configurationSha256', 'functionEntry', 'functionContractSha256', 'codeEpoch', 'modelRevision'];
export function recoveryError(code, message) { throw Object.assign(new Error(message), { code }); }
function object(value, keys, name) {
  if (!value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value)))
    recoveryError('INVALID_RECOVERY_CASE', `${name} must be a plain object`);
  const actual = Reflect.ownKeys(value);
  if (actual.some(key => typeof key !== 'string' || !keys.includes(key)
    || !Object.getOwnPropertyDescriptor(value, key).enumerable
    || !Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), 'value')))
    recoveryError('INVALID_RECOVERY_CASE', `${name} contains an unsupported field or accessor`);
  if (keys.some(key => !Object.hasOwn(value, key))) recoveryError('INVALID_RECOVERY_CASE', `${name} is missing required fields`);
  return value;
}
function string(value, name, max = 512, nullable = false) {
  if (nullable && value === null) return;
  if (typeof value !== 'string' || !value.trim() || value.length > max || /[\u0000-\u001f]/.test(value))
    recoveryError('INVALID_RECOVERY_CASE', `${name} must be a bounded nonempty string`);
}
function integer(value, name, max) {
  if (!Number.isSafeInteger(value) || Object.is(value, -0) || value < 0 || value > max)
    recoveryError('INVALID_RECOVERY_CASE', `${name} is outside its integer budget`);
}
function digest(value, name, nullable = false) {
  if (nullable && value === null) return;
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) recoveryError('INVALID_RECOVERY_CASE', `${name} must be a lowercase SHA-256`);
}
function id(value, name) {
  if (typeof value !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/.test(value)) recoveryError('INVALID_RECOVERY_CASE', `${name} is invalid`);
}
function array(value, name, max) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > max
    || Reflect.ownKeys(value).length !== value.length + 1
    || Array.from({ length: value.length }, (_, i) => Object.getOwnPropertyDescriptor(value, String(i)))
      .some(d => !d || !Object.hasOwn(d, 'value')))
    recoveryError('INVALID_RECOVERY_CASE', `${name} must be a bounded plain dense array`);
}
function version(value, name, nullable = false) {
  if (nullable && value === null) return;
  if (typeof value !== 'string' || !/^\d{1,5}(?:\.\d{1,5}){1,3}$/.test(value)) recoveryError('INVALID_RECOVERY_CASE', `${name} must be a numeric version`);
}
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
}
export const recoveryDigest = value => createHash('sha256').update(canonical(value)).digest('hex');
/** Includes the requested goal, function contract, code epoch and model revision. */
export const recoveryBinding = value => recoveryDigest({ caseId: value.caseId, objective: value.objective, scope: value.scope });
/** Snapshot the precise referenced bytes and prior event records, not mutable ids alone. */
export function recoveryObservationBinding(value, event) {
  return recoveryDigest({ bindingSha256: event.bindingSha256,
    references: event.references.map(id => value.references.find(ref => ref.id === id)),
    inputs: event.inputs.map(id => ({ id, recordSha256: recoveryDigest(value.events.find(prior => prior.id === id)) })) });
}

/** Caller records are work observations, never verifier certificates or approval. */
export function validateRecoveryCase(input) {
  object(input, ['schema', 'caseId', 'objective', 'scope', 'references', 'events'], 'case');
  if (input.schema !== 'ig5-vm-recovery-case-v1') recoveryError('INVALID_RECOVERY_CASE', 'Unsupported recovery case schema');
  id(input.caseId, 'caseId');
  object(input.objective, ['family', 'versionSeries'], 'objective');
  string(input.objective.family, 'objective.family', 64);
  version(input.objective.versionSeries, 'objective.versionSeries');
  object(input.scope, scopeKeys, 'scope');
  const scope = input.scope;
  for (const key of ['targetSha256', 'producerSha256', 'configurationSha256', 'functionContractSha256']) digest(scope[key], `scope.${key}`, true);
  string(scope.family, 'scope.family', 64);
  if (!['x86', 'x64', 'arm64', 'unknown'].includes(scope.architecture)) recoveryError('INVALID_RECOVERY_CASE', 'Unsupported architecture');
  version(scope.version, 'scope.version', true);
  string(scope.build, 'scope.build', 64, true);
  string(scope.codeEpoch, 'scope.codeEpoch', 128, true);
  integer(scope.modelRevision, 'scope.modelRevision', 1_000_000);
  if (scope.functionEntry !== null && (typeof scope.functionEntry !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]{0,15})$/.test(scope.functionEntry)))
    recoveryError('INVALID_RECOVERY_CASE', 'functionEntry must be a canonical uint64 hex string or null');
  array(input.references, 'references', RECOVERY_LIMITS.references);
  const refs = new Map();
  let totalBytes = 0;
  for (const ref of input.references) {
    object(ref, ['id', 'kind', 'path', 'bytes', 'sha256'], 'reference');
    id(ref.id, 'reference.id');
    if (refs.has(ref.id) || !kinds.has(ref.kind)) recoveryError('INVALID_RECOVERY_CASE', 'Duplicate reference or unsupported reference kind');
    string(ref.path, 'reference.path', 2048);
    digest(ref.sha256, 'reference.sha256');
    integer(ref.bytes, 'reference.bytes', RECOVERY_LIMITS.referenceBytes);
    totalBytes += ref.bytes;
    if (totalBytes > RECOVERY_LIMITS.totalReferenceBytes) recoveryError('RECOVERY_INPUT_LIMIT', 'Total reference bytes exceed 16 MiB');
    refs.set(ref.id, ref);
  }
  array(input.events, 'events', RECOVERY_LIMITS.events);
  const events = new Map();
  for (const event of input.events) {
    object(event, ['id', 'stage', 'state', 'bindingSha256', 'inputBindingSha256', 'inputs', 'references', 'hypothesisRevision', 'failure', 'note'], 'event');
    id(event.id, 'event.id');
    if (events.has(event.id) || typeof event.stage !== 'string' || !Object.hasOwn(RECOVERY_STAGES, event.stage) || !states.has(event.state))
      recoveryError('INVALID_RECOVERY_CASE', 'Duplicate event, unsupported stage or caller state');
    digest(event.bindingSha256, 'event.bindingSha256');
    digest(event.inputBindingSha256, 'event.inputBindingSha256');
    integer(event.hypothesisRevision, 'event.hypothesisRevision', 1_000_000);
    string(event.note, 'event.note', 2048);
    array(event.inputs, 'event.inputs', 16);
    array(event.references, 'event.references', 16);
    if (new Set(event.inputs).size !== event.inputs.length || new Set(event.references).size !== event.references.length)
      recoveryError('INVALID_RECOVERY_CASE', 'Duplicate event input or reference');
    for (const key of event.inputs) {
      id(key, 'event.inputs[]');
      if (!events.has(key) || !RECOVERY_STAGES[event.stage].includes(events.get(key).stage))
        recoveryError('INVALID_RECOVERY_CASE', 'Inputs must name earlier direct prerequisite-stage events');
    }
    for (const key of event.references) { id(key, 'event.references[]'); if (!refs.has(key)) recoveryError('INVALID_RECOVERY_CASE', 'Unknown event artifact reference'); }
    if (['partial', 'candidate'].includes(event.state) && !event.references.length)
      recoveryError('INVALID_RECOVERY_CASE', 'Partial and candidate observations require artifact references');
    if (event.failure !== null) {
      object(event.failure, ['code', 'fingerprint'], 'failure');
      if (typeof event.failure.code !== 'string' || !Object.hasOwn(RECOVERY_FAILURES, event.failure.code)) recoveryError('INVALID_RECOVERY_CASE', 'Unsupported failure code');
      digest(event.failure.fingerprint, 'failure.fingerprint');
      if (RECOVERY_FAILURES[event.failure.code][0] !== event.stage || !['failed', 'unknown'].includes(event.state))
        recoveryError('INVALID_RECOVERY_CASE', 'Failure route must match its stage and failed/unknown state');
    }
    if (event.state === 'failed' && event.failure === null) recoveryError('INVALID_RECOVERY_CASE', 'Failed work observations require a failure classification');
    events.set(event.id, event);
  }
  const result = structuredClone(input);
  if (Buffer.byteLength(JSON.stringify(result)) > RECOVERY_LIMITS.caseBytes) recoveryError('RECOVERY_INPUT_LIMIT', 'Recovery case exceeds 256 KiB');
  return result;
}
