import { researchDigest } from './research_state.js';
import { caseTrustedScope, projectCaseSources } from './research_case_bridge.js';
import { privateResearchStore } from './research_case_index.js';
import { publicResearchStore } from './knowledge_v2.js';
import { METHOD_SPECS, METHOD_REGISTRY_VERSION } from './method_registry.js';

const fail=(code,message)=>{throw Object.assign(new Error(message),{code});};
export const methodActions=Object.freeze(['method-registry','method-applicability']);
export function validateMethodInput(input){
 const allowed=input?.action==='method-registry'?['action','id']:['action','id','method_id','generation'];
 if(!input||typeof input!=='object'||Array.isArray(input)||!methodActions.includes(input.action)||Object.keys(input).some(k=>!allowed.includes(k)))fail('INVALID_ARGUMENT','Invalid fixed method query fields');
 if(input.action==='method-applicability'&&!METHOD_SPECS.some(m=>m.id===input.method_id))fail('INVALID_ARGUMENT','Select an exact fixed method_id');
 if(input.generation!==undefined&&input.generation!=='absent'&&(typeof input.generation!=='string'||!/^[a-f0-9]{64}$/.test(input.generation)))fail('INVALID_ARGUMENT','Invalid private index generation');
}
const predicate=(value,reason,records=[])=>({value,reason,evidenceRefs:records.map(r=>({ref:r.sourceRef,projectionDigest:r.projectionDigest,sourceStatus:r.status,kind:r.kind}))});
/** Fixed structural observations only. Source code, caller prose and article text are never interpreted. */
export function methodPredicates(projection){
 const rows=projection.records, dossiers=rows.filter(r=>r.kind==='function-dossier'&&r.status==='observed');
 const conclusions=rows.filter(r=>r.kind==='task-statement'&&typeof r.sourceData.conclusion==='string'&&r.sourceData.conclusion.trim());
 const conflicts=rows.filter(r=>r.kind==='hypotheses'&&r.status==='contested');
 const sections=dossiers.flatMap(r=>Object.values(r.sourceData.sections||{}).map(s=>({s,r})));
 const incomplete=sections.filter(({s})=>s.status==='truncated');
 const calls=dossiers.flatMap(r=>{
  const section=r.sourceData.sections?.callees,data=section?.data;
  if(!['ok','truncated'].includes(section?.status)||!Array.isArray(data?.calls))return [];
  // Each group is local to ONE function snapshot. Different tasks/versions are not pooled.
  const addresses=new Set(data.calls.map(c=>c?.ea).filter(e=>typeof e==='string'&&/^0x[0-9a-f]+$/i.test(e)).map(e=>BigInt(e).toString(16)));
  return [{r,section,data,count:addresses.size}];
 });
 const multiple=calls.filter(c=>c.count>1);
 const completeCalls=calls.filter(c=>c.section.status==='ok'&&c.data.total===c.data.calls.length&&c.data.calls.every(c=>typeof c?.ea==='string'&&/^0x[0-9a-f]+$/i.test(c.ea)));
 const completeSections=sections.length>0&&sections.every(({s})=>s.status==='ok')&&dossiers.every(r=>r.sourceData.responseTruncated===false);
 return {
  'reported-result':predicate(conclusions.length?'true':'unknown','Caller conclusion supplies a readback target only; output correctness and algorithm remain unestablished',conclusions),
  'static-observation':predicate(dossiers.length?'true':'unknown','Current committed dossier integrity; no address mapping or CPU assurance',dossiers),
  'truncated-source':predicate(incomplete.length?'true':completeSections?'false':'unknown','Explicit truncation status; unsupported/error/absent sections remain unknown',incomplete.length?incomplete.map(x=>x.r):completeSections?dossiers:[]),
  'multiple-callees':predicate(multiple.length?'true':completeCalls.length&&completeCalls.length===dossiers.length?'false':'unknown','Distinct observed addresses require distinguishing observations; no algorithm or VM identity inference',(multiple.length?multiple:completeCalls).map(x=>x.r)),
  'declared-conflict':predicate(conflicts.length?'true':'unknown','Supporting and opposing links declared on a current hypothesis; semantic contradiction not adjudicated',conflicts),
  'architecture-supported':predicate('unknown','No architecture-bearing committed adapter is registered for this method'),
  'typed-expression-ir':predicate('unknown','No typed pure-expression adapter registered; decompiled text is not typed IR'),
  'pure-expression':predicate('unknown','Memory, flags, calls, widths and extensions require an explicit complete model'),
  'prototype-known':predicate('unknown','Dossier stack/call text does not establish argument ABI or prototype'),
  'instance-identity':predicate('unknown','Callee/seed/table addresses and structural similarity do not establish a VM instance'),
 };
}
/** No scoring, probability, dynamic predicates or execution. Unknown exclusions also fail closed. */
export function decideApplicability(method,predicates){
 const required=method.requiredPredicates.map(id=>predicates[id]?.value??'unknown');
 const excluded=method.excludedPredicates.map(id=>predicates[id]?.value??'unknown');
 if(excluded.includes('true'))return 'blocked';
 if(required.includes('false'))return 'inapplicable';
 if(required.includes('unknown')||excluded.includes('unknown'))return 'needs-evidence';
 return 'applicable';
}
export function captureMethodInputs(projectRoot,read,artifacts){
 const data=read(),trust=caseTrustedScope(data);
 if(!trust.ready)return {ready:false,reason:trust.reason,digest:researchDigest(data)};
 const projection=projectCaseSources(data,artifacts),privateStore=privateResearchStore(projectRoot,trust.scope),privateCapture=privateStore.current();
 const active=(privateCapture.snapshot?.entries||[]).filter(e=>e.state==='active');
 const privateCurrent=!!privateCapture.snapshot&&active.length===projection.records.length&&active.every(e=>e.metadata.reviewNotes.includes('source-stamp:'+projection.stamp)&&projection.records.some(r=>r.id===e.ref.id));
 // Rebind full bodies as well as metadata. A current pointer alone is not evidence integrity.
 if(privateCurrent)for(const entry of active)privateStore.read(entry.ref,privateCapture);
 const publicStore=publicResearchStore(projectRoot),publicCapture=publicStore.current();
 const sources=Object.fromEntries(METHOD_SPECS.flatMap(m=>m.sourceRefs).map(ref=>{
  const entry=publicCapture.snapshot?.entries.find(e=>e.ref.id===ref.id&&e.ref.sha256===ref.sha256&&e.state==='active');
  if(!entry)return [ref.id,{available:false,ref}];
  const source=publicStore.read(ref,publicCapture);
  return [ref.id,{available:source.record.metadata.sources.every(s=>s.review==='reviewed'),ref}];
 }));
 const binding={scope:trust.scope,researchRevision:data.research.researchRevision,contractRevision:data.research.contractRevision,
  contractDigest:data.research.contractDigest,privateGeneration:privateCapture.generation,publicGeneration:publicCapture.generation,
  sourceStamp:projection.stamp,registryVersion:METHOD_REGISTRY_VERSION,registryDigest:researchDigest(METHOD_SPECS)};
 return {ready:true,binding,projection,privateCurrent,sources,digest:researchDigest({binding,privateCurrent,sources,projection})};
}
/** Pure evaluation of an internal captured host snapshot; never accepts tool-supplied predicates. */
export function evaluateMethodCapture(before,method){
 if(!before.ready){
  const result={schema:'ig5-applicability-receipt-v1',methodId:method.id,methodVersion:method.version,registryVersion:METHOD_REGISTRY_VERSION,binding:null,inputDigest:before.digest,
   status:'needs-evidence',reason:before.reason,predicates:Object.fromEntries([...new Set([...method.requiredPredicates,...method.excludedPredicates,...method.informativePredicates])].map(id=>[id,predicate('unknown',before.reason)])),
   semanticVerified:false,algorithmExplained:false,executionAuthorized:false,assistEnabled:false,plannerChanged:false};
  return {...result,receiptDigest:researchDigest(result)};
 }
 const predicates=methodPredicates(before.projection),sourceReady=method.sourceRefs.every(r=>before.sources[r.id]?.available);
 const status=before.projection.diagnostics.length?'blocked':!before.privateCurrent||!sourceReady?'needs-evidence':decideApplicability(method,predicates);
 const result={schema:'ig5-applicability-receipt-v1',methodId:method.id,methodVersion:method.version,binding:before.binding,inputDigest:before.digest,
  status,reason:before.projection.diagnostics.length?'source-integrity-or-history-gap':!before.privateCurrent?'private-index-refresh-required':!sourceReady?'reviewed-source-missing-or-withdrawn':'fixed-predicates',
  predicates:Object.fromEntries([...new Set([...method.requiredPredicates,...method.excludedPredicates,...method.informativePredicates])].map(id=>[id,predicates[id]])),
  diagnostics:before.projection.diagnostics,omittedSources:before.projection.omitted,completeHistory:false,
  missingEvidenceActions:method.missingEvidenceActions.filter(a=>predicates[a.predicateId]?.value==='unknown'),experimentTemplateId:method.experimentTemplateId,verifierId:method.verifierId,
  semanticVerified:false,algorithmExplained:false,executionAuthorized:false,assistEnabled:false,plannerChanged:false};
 result.receiptDigest=researchDigest(result);
 if(Buffer.byteLength(JSON.stringify(result))>32768)fail('METHOD_RESPONSE_LIMIT','Method receipt exceeds 32 KiB');
 return result;
}
/** Host-only read closure, under the existing static target queue. No writes or tool execution. */
export function runMethodQuery({projectRoot,input,read,artifacts}){
 validateMethodInput(input);
 if(input.action==='method-registry')return {schema:'ig5-method-registry-v1',version:METHOD_REGISTRY_VERSION,digest:researchDigest(METHOD_SPECS),methods:structuredClone(METHOD_SPECS),executionAuthorized:false,assistEnabled:false};
 const before=captureMethodInputs(projectRoot,read,artifacts),method=METHOD_SPECS.find(m=>m.id===input.method_id);
 if(before.ready&&input.generation!==undefined&&input.generation!==before.binding.privateGeneration)fail('STALE_RESEARCH_GENERATION','Private index changed; query again');
 const result=evaluateMethodCapture(before,method),after=captureMethodInputs(projectRoot,read,artifacts);
 if(after.digest!==before.digest)fail('SNAPSHOT_INCONSISTENT','Method inputs changed during read');
 return result;
}
