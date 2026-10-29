import { propertyScopeSchema } from './research_properties.js';
import { jsonToolOutput } from './json_output.js';
const sha={type:'string',pattern:'^[a-f0-9]{64}$'},uuid={type:'string',pattern:'^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$'};
const shape=properties=>({type:'object',properties,required:Object.keys(properties),additionalProperties:false});
const ref=shape({id:uuid,sha256:sha}),status={enum:['pass','fail','unknown','unsupported','error']};
const fields={
  schema:{const:'ig5-verification-result-v2'},verifierId:{type:'string'},code:{type:'object',additionalProperties:sha},runtime:{type:'object'},rulesDigest:sha,runtimeDigest:sha,
  taskId:uuid,scopeDigest:sha,taskRevision:{type:'integer',minimum:0},researchRevision:{type:'integer',minimum:0},contractDigest:sha,contractRevision:{type:'integer',minimum:0},
  obligationId:uuid,obligationDigest:sha,evidenceId:uuid,experimentId:{oneOf:[uuid,{type:'null'}]},property:{type:'string'},inputRefs:{type:'array',maxItems:112,items:ref},
  dependencyType:{const:'immutable-bytes'},status,method:{type:'string'},premises:{type:'array',items:{type:'string'}},exclusions:{type:'array',items:{type:'string'}},sharedDependencies:{type:'object'},outcome:{type:'object'},
  nativeTargetExecuted:{const:false},databaseModified:{const:false},changesExecutionAuthority:{const:false},businessAccepted:{const:false},
  propertyId:{type:'string'},result:status,contractRef:ref,obligationRef:shape({id:uuid,digest:sha}),subjectRef:ref,
  scope:{oneOf:[propertyScopeSchema,shape({targetSha256:sha,evidenceId:uuid}),{type:'null'}]},
  verifier:shape({id:{type:'string'},rulesDigest:sha,runtimeDigest:sha}),coverageRef:{type:'null'},counterexampleRef:{type:'null'},cleanupReceiptRef:{type:'null'},
  cleanup:shape({kind:{const:'owned-data-worker-exit'},confirmed:{type:'boolean'}}),
};
export const VERIFICATION_RESULT_V2_SCHEMA = {$schema:'https://json-schema.org/draft/2020-12/schema',...shape(fields)};
/** Structural gate; registry separately checks exact scopes, byte closure, identity and result authority. */
export function validateReceiptShape(input) {
  const value=jsonToolOutput(input);
  if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join()!==Object.keys(fields).sort().join()
    ||value.schema!=='ig5-verification-result-v2'||!status.enum.includes(value.status)||value.result!==value.status
    ||value.propertyId!==value.property||['nativeTargetExecuted','databaseModified','changesExecutionAuthority','businessAccepted'].some(k=>value[k]!==false))
    throw Object.assign(new Error('Unsupported typed verification receipt shape'),{code:'INVALID_VERIFICATION'});
  return value;
}
