import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { propertyCase } from './fixtures/research_property_cases.mjs';
import { MODEL_PROPERTY, RECORDED_PROPERTY, PROVENANCE_PROPERTY } from '../source/research_properties.js';
import { registeredVerifier, VERIFIER_CATALOG } from '../source/verifier_catalog.js';
import { evaluateObligations } from '../source/obligation_evaluator.js';
import { loadVerification, readVerificationReport } from '../source/verification_registry.js';
import { buildPhaseContextCase } from './fixtures/vm_phase_context_cases.mjs';
import { VERIFICATION_RESULT_V2_SCHEMA } from '../source/verification_schema.js';
import { readObservationWindows } from '../source/vm_observation_profile.js';

test('frozen JSON schema matches production; missing recording stores remain absent on reads',t=>{
  assert.deepEqual(JSON.parse(fs.readFileSync(new URL('../docs/schemas/verification-result-v2.schema.json',import.meta.url))),VERIFICATION_RESULT_V2_SCHEMA);
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'ig5-property-read-'));
  t.after(()=>{assert.equal(path.dirname(root),fs.realpathSync(os.tmpdir()));fs.rmSync(root,{recursive:true,force:true});});
  assert.throws(()=>readObservationWindows({checkCancelled(){}},{artifactDir:root},{recordings:[{id:randomUUID(),sha256:'a'.repeat(64)}],target_sha256:'a'.repeat(64)}));
  assert.deepEqual(fs.readdirSync(root),[]);
});
test('loaded verifier cannot bless modified rules; a fresh process captures the new identity',t=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'ig5-property-code-'));
  t.after(()=>{assert.equal(path.dirname(root),fs.realpathSync(os.tmpdir()));fs.rmSync(root,{recursive:true,force:true});});
  fs.cpSync(new URL('../source',import.meta.url),path.join(root,'source'),{recursive:true});fs.writeFileSync(path.join(root,'package.json'),'{"type":"module"}');
  const module=pathToFileURL(path.join(root,'source','verification_result.js')).href;
  const changed=path.join(root,'source','verifiers','vm_function_oracle.js');
  const run=spawnSync(process.execPath,['--input-type=module','-e',`import fs from 'node:fs';import assert from 'node:assert/strict';import {verifierIdentity} from ${JSON.stringify(module)};const identity=verifierIdentity(${JSON.stringify(MODEL_PROPERTY)});fs.appendFileSync(${JSON.stringify(changed)},${JSON.stringify('\n// identity change probe\n')});assert.throws(()=>verifierIdentity(${JSON.stringify(MODEL_PROPERTY)}),{code:'VERIFIER_CODE_CHANGED'});process.stdout.write(identity.rulesDigest);`],{encoding:'utf8',timeout:15000,windowsHide:true});
  assert.equal(run.status,0,run.stderr);
  const fresh=spawnSync(process.execPath,['--input-type=module','-e',`import {verifierIdentity} from ${JSON.stringify(module)};process.stdout.write(verifierIdentity(${JSON.stringify(MODEL_PROPERTY)}).rulesDigest);`],{encoding:'utf8',timeout:15000,windowsHide:true});
  assert.equal(fresh.status,0,fresh.stderr);assert.notEqual(fresh.stdout,run.stdout);
});

async function fixture(t) {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'ig5-property-'));
  const f=await propertyCase(root);
  t.after(async()=>{await f.analysis.dispose();assert.equal(path.dirname(root),fs.realpathSync(os.tmpdir()));fs.rmSync(root,{recursive:true,force:true});});
  return f;
}
test('static catalog rejects unknown properties; finite model closes only its exact structured domain',async t=>{
  const f=await fixture(t);assert.equal(VERIFIER_CATALOG.length,4);assert(Object.isFrozen(VERIFIER_CATALOG));
  assert.throws(()=>registeredVerifier('caller-script'),{code:'UNSUPPORTED_VERIFIER'});
  const model=f.propose(MODEL_PROPERTY),native=f.propose(RECORDED_PROPERTY),full=structuredClone(model.value.propertyScope);
  full.domain.bits=64;full.domain.maximum='0xffffffffffffffff';
  const expanded=f.propose(MODEL_PROPERTY,{propertyScope:full});
  assert.equal((await f.verify(model)).status,'pass');
  assert.equal((await f.verify(native)).status,'unsupported');
  assert.equal((await f.verify(expanded)).status,'unsupported');
  assert.deepEqual(f.get().research.objectStates.obligations.map(r=>r.status),['closed-in-scope','open','open']);
  const result=f.analysis.artifacts.get(f.get().research.verificationRefs[0].reportId).result;
  assert.equal(result.schema,'ig5-verification-result-v2');assert.equal(result.outcome.modelCases,256);assert.equal(result.cleanup.confirmed,true);
  assert.equal(result.scope.domain.kind,'integer-range');assert.equal(f.analysis.jobs.active,null);
  const programFile=path.join(f.analysis.artifacts.directory('records'),f.program.reportId+'.json'),originalProgram=fs.readFileSync(programFile);
  fs.appendFileSync(programFile,' ');assert.equal(f.get().evidence[0].integrity,'unverified');assert.equal(f.get().research.objectStates.obligations[0].status,'stale');fs.writeFileSync(programFile,originalProgram);
  const other=structuredClone(model.value.propertyScope);other.subjectRef.id=randomUUID();
  assert.equal((await f.verify(f.propose(MODEL_PROPERTY,{propertyScope:other}))).status,'unsupported');
});
test('unknown and errors do not erase a current pass; revisions stale all dependent obligations',async t=>{
  const f=await fixture(t),parent=f.propose(MODEL_PROPERTY),child=f.propose(MODEL_PROPERTY,{dependencies:[parent.id]});
  assert.equal((await f.verify(child)).status,'unknown');assert.equal(f.get().research.objectStates.obligations[1].status,'blocked');
  await f.verify(parent);await f.verify(child);
  const run=f.analysis.jobs.runSettled;f.analysis.jobs.runSettled=async()=>{throw Object.assign(new Error('timeout'),{code:'TIMEOUT'});};
  assert.equal((await f.verify(parent)).status,'unknown');assert(f.get().research.objectStates.obligations.every(r=>r.status==='closed-in-scope'));
  f.analysis.jobs.runSettled=run;
  const current=f.get();f.call({action:'research-update',id:f.task.taskId,research:{operation:'revise-obligation',entity_id:parent.id,value:parent.value,
    expected_task_revision:current.taskRevision,expected_research_revision:current.research.researchRevision,scope_digest:current.scopeDigest}});
  assert.equal(f.get().research.objectStates.obligations[1].status,'stale');
  f.update('set-contract',{...f.contract,inputDomain:'Changed domain'});
  assert(f.get().research.objectStates.obligations.every(r=>r.status==='superseded'||r.status==='stale'));
});
test('typed receipt tampering, old v1 and rule identities cannot acquire new property authority',async t=>{
  const f=await fixture(t),o=f.propose(MODEL_PROPERTY),receipt=await f.verify(o),original=f.analysis.artifacts.get(receipt.reportId).result;
  for(const change of [r=>r.scope.subjectRef.sha256='b'.repeat(64),r=>r.propertyId=RECORDED_PROPERTY,r=>r.cleanup.confirmed=false,r=>r.runtimeDigest='b'.repeat(64)]) {
    const r=structuredClone(original);change(r);const saved=f.analysis.artifacts.save({kind:'research-verification',action:'verify',result:r});
    assert.throws(()=>loadVerification(f.analysis.artifacts,f.task,f.get().research,{reportId:saved.id,sha256:f.analysis.artifacts.metadata(saved.id).result.recordSha256}));
  }
  const r=structuredClone(original);r.schema='ig5-verification-result-v1';
  const saved=f.analysis.artifacts.save({kind:'research-verification',action:'verify',result:r});
  const ref={reportId:saved.id,sha256:f.analysis.artifacts.metadata(saved.id).result.recordSha256};
  assert.equal(readVerificationReport(f.analysis.artifacts,f.task,f.get().research,ref).result.schema,'ig5-verification-result-v1');
  const view=f.get();f.mgr.researchState.linkVerification(f.task,f.context,{expected_task_revision:view.taskRevision,expected_research_revision:view.research.researchRevision,scope_digest:view.scopeDigest},ref,'test');
  // The real v2 still closes; legacy evidence is explicitly unverified, never upgraded.
  assert.equal(f.get().research.verification.checked.at(-1).integrity,'unverified');
});
test('valid same-scope counterexamples contest pass and block children; cycles are rejected',()=>{
  const a=randomUUID(),b=randomUUID();const state={contractRevision:0,obligations:[{id:a,value:{dependencies:[]}},{id:b,value:{dependencies:[a]}}],objectStates:{obligations:[{id:a,status:'open'},{id:b,status:'open'}]}};
  const pass={obligationId:a,integrity:'verified',status:'pass'},fail={...pass,status:'fail',counterexampleValid:true};
  assert.deepEqual(evaluateObligations(state,[pass,fail]).map(r=>r.status),['contested','blocked']);
  assert.deepEqual(evaluateObligations(state,[pass],{complete:false}).map(r=>r.status),['open','blocked']);
  state.obligations[0].value.dependencies=[b];assert.throws(()=>evaluateObligations(state,[]),{code:'RESEARCH_DEPENDENCY_CYCLE'});
});
test('raw source provenance rebinds complete recordings without claiming VM role semantics',async t=>{
  const f=await fixture(t),source=await buildPhaseContextCase(f.analysis,f.cfg,{runId:'synthetic-not-native-execution',inputValue:'0x1'});
  // The raw source fixture has its own target; start a task with that same exact identity.
  f.context.sha256='a'.repeat(64);f.context.artifactId=`artifact_${f.context.sha256}`;
  const task=f.call({action:'create',goal:'Provenance only'}),now=()=>f.call({action:'research-get',id:task.taskId});
  const mutate=(operation,value,extra={})=>{const n=now();return f.call({action:'research-update',id:task.taskId,...extra,research:{operation,expected_task_revision:n.taskRevision,expected_research_revision:n.research?.researchRevision??0,scope_digest:n.scopeDigest,...(value?{value}:{})}});};
  mutate('initialize',f.contract);
  const {bytecodeContract}=await import('./fixtures/vm_bytecode_cases.mjs');const c=bytecodeContract('a'.repeat(64));c.normalReturn='native-ret';
  const declared=await f.invoke('declare_contract',{contract:c});
  const compared=await f.invoke('role_compare',{context_refs:[f.ref(source.model)],contract_ref:f.ref(declared)});
  const validation=await f.invoke('role_validate',{comparison_ref:f.ref(compared),recording_bindings:[{context_ref:f.ref(source.model),recordings:[source.debugRef]}]});
  const linked=mutate('link-verifier-evidence',undefined,{report_ref:f.ref(validation)}).research.evidenceLinks[0];
  const o=mutate('add-obligation',{property:PROVENANCE_PROPERTY,scope:`evidence:${linked.id}`,verifier:registeredVerifier(PROVENANCE_PROPERTY).id,dependencies:[],propertyScope:linked.propertyScopes[PROVENANCE_PROPERTY]}).research.obligations.at(-1);
  const n=now(),result=await f.asyncCall({action:'research-verify',id:task.taskId,verification:{expected_task_revision:n.taskRevision,expected_research_revision:n.research.researchRevision,scope_digest:n.scopeDigest,evidence_id:linked.id,obligation_id:o.id}});
  assert.equal(result.status,'pass');assert.equal(now().research.objectStates.obligations[0].status,'closed-in-scope');
  assert.equal(f.analysis.artifacts.get(result.reportId).result.outcome.recordedResult.vmRoleProved,false);
});

test('omitted old receipts cannot hide a counterexample and produce a current closure',async t=>{
  const f=await fixture(t),o=f.propose(MODEL_PROPERTY);
  for(let i=0;i<9;i++)assert.equal((await f.verify(o)).status,'pass');
  const state=f.get().research;assert.equal(state.verification.omittedOlder,1);assert.equal(state.verification.complete,false);
  assert.equal(state.objectStates.obligations[0].status,'open');assert.equal(state.objectStates.obligations[0].assessment,'unverified');
});
