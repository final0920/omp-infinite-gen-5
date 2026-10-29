import { CONTEXT_PROPERTY, MODEL_PROPERTY, RECORDED_PROPERTY, PROVENANCE_PROPERTY } from './research_properties.js';
const entries = [
  [CONTEXT_PROPERTY,'vm-context-audit-v1','vm-context-model','vm-context-audit','verifiers/vm_context_audit.js',['VM roles','CPU semantics','function acceptance']],
  [MODEL_PROPERTY,'vm-finite-model-v1','vm-function-assessment','vm-function-verify','verifiers/vm_function_verify.js',['native input coverage','universal CPU equivalence']],
  [RECORDED_PROPERTY,'vm-recorded-function-v1','vm-function-assessment','vm-recorded-function-verify','verifiers/vm_recorded_function.js',['unexecuted native inputs','complete CPU write footprint']],
  [PROVENANCE_PROPERTY,'vm-recorded-source-v1','vm-role-validation','vm-role-validation','vm_role_validation.js',['general VM roles','unseen inputs','CPU semantics']],
].map(([propertyId,id,evidenceKind,workerKind,implementation,exclusions])=>Object.freeze({propertyId,id,version:1,evidenceKind,workerKind,implementation,
  parameterSchema:Object.freeze({type:'object',properties:{},additionalProperties:false}),scopePolicy:'exact',
  budget:Object.freeze({workerMemoryMiB:64,timeoutMs:15000,queue:4}),outputSchema:'ig5-verification-result-v2',
  applicableDomain:propertyId===CONTEXT_PROPERTY?'committed-context':propertyId===MODEL_PROPERTY?'fixed-model-integer-range':'specified-recordings',
  sharedDependencies:Object.freeze(['analysis worker lifecycle','immutable artifact storage']),closes:Object.freeze([propertyId]),exclusions:Object.freeze(exclusions)}));
export const VERIFIER_CATALOG = Object.freeze(entries);
export function registeredVerifier(propertyId) {
  const entry=entries.find(e=>e.propertyId===propertyId);
  if(!entry) throw Object.assign(new Error('Unknown fixed research property'),{code:'UNSUPPORTED_VERIFIER'});
  return entry;
}
