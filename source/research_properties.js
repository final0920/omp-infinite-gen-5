import { planningDigest } from './planning_identity.js';

export const CONTEXT_PROPERTY = 'vm-context-candidate-derivation-and-provenance';
export const MODEL_PROPERTY = 'fixed-owned-model-return-and-output-memory-equivalence';
export const RECORDED_PROPERTY = 'fixed-owned-recorded-return-and-output-conformance';
export const PROVENANCE_PROPERTY = 'recorded-fetch-body-source-binding';
export const PROPERTY_IDS = Object.freeze([CONTEXT_PROPERTY, MODEL_PROPERTY, RECORDED_PROPERTY, PROVENANCE_PROPERTY]);
const SHA = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const HEX = /^0x[0-9a-f]{1,16}$/;
const reject = () => { throw Object.assign(new Error('Exact typed property scope required'), { code: 'INVALID_PROPERTY_SCOPE' }); };
const keys = (v, names) => v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).sort().join() === names.sort().join();
export function validatePropertyScope(v) {
  if (!keys(v, ['targetSha256','subjectRef','contractRef','environmentRef','domain']) || !SHA.test(v.targetSha256) || !SHA.test(v.environmentRef)) reject();
  for (const ref of [v.subjectRef,v.contractRef]) if (!keys(ref,['id','sha256']) || !UUID.test(ref.id) || !SHA.test(ref.sha256)) reject();
  const d = v.domain;
  if (d?.kind === 'integer-range') {
    if (!keys(d,['kind','bits','minimum','maximum']) || ![8,16,32,64].includes(d.bits) || !HEX.test(d.minimum) || !HEX.test(d.maximum)
      || BigInt(d.minimum)>BigInt(d.maximum) || BigInt(d.maximum)>=1n<<BigInt(d.bits)) reject();
  } else if (d?.kind === 'recorded-inputs') {
    if (!keys(d,['kind','inputs','recordingRefs']) || !Array.isArray(d.inputs) || d.inputs.length>8 || d.inputs.some(x=>!HEX.test(x))
      || new Set(d.inputs).size!==d.inputs.length || !Array.isArray(d.recordingRefs) || !d.recordingRefs.length || d.recordingRefs.length>48) reject();
    for (const r of d.recordingRefs) if (!keys(r,['id','sha256']) || !UUID.test(r.id) || !SHA.test(r.sha256)) reject();
    if(new Set(d.recordingRefs.map(r=>r.id)).size!==d.recordingRefs.length) reject();
  } else reject();
  return v;
}
// No free-text implication or environment merging. V1 supports exact scope only.
export function samePropertyScope(a,b) { return !!a && !!b && planningDigest(validatePropertyScope(a))===planningDigest(validatePropertyScope(b)); }
export const propertyScopeSchema = { type:'object', properties: {
  targetSha256:{type:'string',pattern:SHA.source}, environmentRef:{type:'string',pattern:SHA.source},
  ...Object.fromEntries(['subjectRef','contractRef'].map(k=>[k,{type:'object',properties:{id:{type:'string',pattern:UUID.source},sha256:{type:'string',pattern:SHA.source}},required:['id','sha256'],additionalProperties:false}])),
  domain:{oneOf:[{type:'object',properties:{kind:{const:'integer-range'},bits:{enum:[8,16,32,64]},minimum:{type:'string',pattern:HEX.source},maximum:{type:'string',pattern:HEX.source}},required:['kind','bits','minimum','maximum'],additionalProperties:false},
    {type:'object',properties:{kind:{const:'recorded-inputs'},inputs:{type:'array',maxItems:8,uniqueItems:true,items:{type:'string',pattern:HEX.source}},recordingRefs:{type:'array',minItems:1,maxItems:48,items:{type:'object',properties:{id:{type:'string',pattern:UUID.source},sha256:{type:'string',pattern:SHA.source}},required:['id','sha256'],additionalProperties:false}}},required:['kind','inputs','recordingRefs'],additionalProperties:false}]}
},required:['targetSha256','subjectRef','contractRef','environmentRef','domain'],additionalProperties:false};
