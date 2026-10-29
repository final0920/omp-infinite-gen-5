import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { registeredVerifier, VERIFIER_CATALOG } from './verifier_catalog.js';
import { validateReceiptShape } from './verification_schema.js';
import { CONTEXT_PROPERTY } from './research_properties.js';
import { hashBytes, readStableFile } from './analysis_artifacts.js';

export const VERIFIER_ID = 'vm-context-audit-v1';
export const VERIFICATION_STATUSES = Object.freeze(['pass', 'fail', 'unknown', 'unsupported', 'error']);
const commonFiles = ['verification_result.js','verification_registry.js','verifier_catalog.js','research_properties.js',
  'obligation_evaluator.js','verification_schema.js','analysis_worker.js','analysis_jobs.js','research_state.js','investigation_workflow.js','json_output.js'];
function snapshot(entry) {
  const paths=new Set(commonFiles);
  function collect(name) {
    if(paths.has(name))return;
    paths.add(name);
    const body=readStableFile(fileURLToPath(new URL(name,import.meta.url)),1024**2).data.toString('utf8');
    for(const match of body.matchAll(/(?:from\s*|import\s*\()(['"])(\.[^'"]+\.js)\1/g)) {
      const url=new URL(match[2],new URL(name,import.meta.url));
      collect(fileURLToPath(url).slice(fileURLToPath(new URL('./',import.meta.url)).length).replaceAll('\\','/'));
    }
  }
  collect(entry.implementation);collect('evidence_adapters/vm_context.js');collect('evidence_adapters/fixed_properties.js');
  return Object.fromEntries([...paths].sort().map(name=>[name,hashBytes(readStableFile(fileURLToPath(new URL(name,import.meta.url)),1024**2).data)]));
}
// All fixed identities captured before any request; hot-replaced files cannot bless the old loaded code.
const identities = new Map(VERIFIER_CATALOG.map(entry=>[entry.propertyId,snapshot(entry)]));
let cachedIdentity;
export function verifierIdentity(propertyId = CONTEXT_PROPERTY) {
  const entry=registeredVerifier(propertyId),code=identities.get(propertyId);
  for (const [name, expected] of Object.entries(code)) {
    if (hashBytes(readStableFile(fileURLToPath(new URL(name, import.meta.url)), 1024 ** 2).data) !== expected) throw Object.assign(new Error('Verifier code changed after module load; reload before verification'), { code: 'VERIFIER_CODE_CHANGED' });
  }
  if (cachedIdentity) return structuredClone({ ...cachedIdentity, verifierId:entry.id, code, rulesDigest:hashBytes(Buffer.from(JSON.stringify(code))) });
  const before = fs.statSync(process.execPath, { bigint: true }), hash = createHash('sha256');
  if (before.size > 512n * 1024n ** 2n) throw Object.assign(new Error('Verifier runtime identity exceeds fixed read budget'), { code: 'VERIFIER_RUNTIME_LIMIT' });
  const fd = fs.openSync(process.execPath, 'r'), chunk = Buffer.alloc(65536);
  try {
    let count; while ((count = fs.readSync(fd, chunk, 0, chunk.length, null))) hash.update(chunk.subarray(0, count));
    const after = fs.fstatSync(fd, { bigint: true });
    if (['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'].some(k => before[k] !== after[k])) throw new Error('Verifier runtime changed while hashing');
  } finally { fs.closeSync(fd); }
  const runtime = { version: process.version, v8: process.versions.v8, platform: process.platform, arch: process.arch, executableSha256: hash.digest('hex') };
  cachedIdentity = { verifierId: entry.id, code, runtime,
    rulesDigest: hashBytes(Buffer.from(JSON.stringify(code))), runtimeDigest: hashBytes(Buffer.from(JSON.stringify(runtime))) };
  return structuredClone(cachedIdentity);
}
export function verificationResult({ task, state, obligation, evidence, experimentId, outcome, inputRefs }) {
  if (!VERIFICATION_STATUSES.includes(outcome.status)) throw new Error('Unsupported verifier outcome');
  return { schema: 'ig5-verification-result-v2', ...verifierIdentity(), taskId: task.taskId, scopeDigest: state.scopeDigest,
    taskRevision: task.taskRevision, researchRevision: state.researchRevision, contractDigest: state.contractDigest, contractRevision: state.contractRevision,
    obligationId: obligation.id, obligationDigest: hashBytes(Buffer.from(JSON.stringify(obligation))), evidenceId: evidence.id, experimentId: experimentId || null,
    property: obligation.value.property, inputRefs, dependencyType: 'immutable-bytes', status: outcome.status,
    method: 'Independent JavaScript recomputation of committed context candidates and dictionary; byte hashes rechecked inside the bounded worker.',
    premises: ['Committed handler assessment, recurrence and selected window observations are inputs.', 'Original recording, projection decoder and CPU semantics are not re-proved.'],
    exclusions: ['VM roles', 'phase classification', 'bytecode program', 'CPU semantics', 'reachability', 'alternate-input coverage', 'whole function or business acceptance'],
    sharedDependencies: { sharedDerivationCode: false, sharedRecordedInputs: true, upstreamDecoderIndependenceProved: false,
      reference: 'scripts/verify_vm_context_model.py is independently exercised in regression; production runs the bounded JavaScript audit, not a caller script.' },
    outcome, nativeTargetExecuted: false, databaseModified: false, changesExecutionAuthority: false, businessAccepted: false };
}

/** Typed receipt retains legacy descriptive fields for readers, but exact machine bindings are authoritative. */
export function typedVerificationResult(args, loaded) {
  const {task,state,obligation,evidence,outcome}=args,propertyId=obligation.value.property;
  let entry;
  try { entry=registeredVerifier(propertyId); } catch { entry=registeredVerifier(CONTEXT_PROPERTY); }
  const legacy=verificationResult(args),identity=verifierIdentity(entry.propertyId);
  const scope=propertyId===CONTEXT_PROPERTY?{targetSha256:task.scope.sha256,evidenceId:evidence.id}:loaded.link.propertyScopes?.[propertyId] ?? null;
  return validateReceiptShape({...legacy,...identity,propertyId,result:outcome.status,
    contractRef:{id:task.taskId,sha256:state.contractDigest},
    obligationRef:{id:obligation.id,digest:legacy.obligationDigest},
    subjectRef:scope?.subjectRef ?? {id:evidence.reportId,sha256:evidence.sha256},scope,
    verifier:{id:identity.verifierId,rulesDigest:identity.rulesDigest,runtimeDigest:identity.runtimeDigest},
    premises:propertyId===CONTEXT_PROPERTY?legacy.premises:['Fixed registered subject and structured function contract','Original recorded observations; no new target execution'],
    exclusions:[...entry.exclusions],sharedDependencies:propertyId===CONTEXT_PROPERTY?legacy.sharedDependencies:
      {sharedCandidateEvaluator:true,independentFixedOracle:propertyId==='fixed-owned-model-return-and-output-memory-equivalence',sharedRecordedInputs:true,upstreamDecoderIndependenceProved:false},
    method:propertyId===CONTEXT_PROPERTY?legacy.method:'Fixed bounded data-worker recomputation of the named property only',
    coverageRef:null,counterexampleRef:null,cleanupReceiptRef:null,
    cleanup:{kind:'owned-data-worker-exit',confirmed:outcome.dataWorkerCleanupConfirmed===true},
  });
}
