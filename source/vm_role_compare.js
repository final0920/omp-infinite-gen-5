import { planningDigest } from './planning_identity.js';
import { vmContextEvidence, evidenceReadBudget, exactReportRef } from './evidence_adapters/vm_context.js';
import { auditVmContext } from './verifiers/vm_context_audit.js';
import { boundedDataArray } from './vm_function_contract.js';

const fail = message => { throw Object.assign(new Error(message), { code: 'INVALID_ROLE_COMPARISON' }); };
export function loadComparedContexts(artifacts, refs, targetSha256, checkCancelled = () => {}, budget = evidenceReadBudget()) {
  if (!Array.isArray(refs) || refs.length < 1 || refs.length > 8) fail('Choose 1..8 distinct committed contexts');
  boundedDataArray(refs,8,1);
  refs.forEach(exactReportRef);
  if (new Set(refs.map(r => r.id)).size !== refs.length) fail('Choose 1..8 distinct committed contexts');
  return refs.map(ref => {
    checkCancelled();
    const { request } = vmContextEvidence(artifacts, { scope: { sha256: targetSha256 } }, ref, budget);
    const audit = auditVmContext(request);
    if (audit.status !== 'pass') fail('Context candidate derivation audit failed: ' + audit.witness?.reason);
    const model = JSON.parse(Buffer.from(request.root.bytes)).result;
    const parents = new Map(request.parents.map(p => [p.id, JSON.parse(Buffer.from(p.bytes)).result]));
    return { ref, model, parents, audit };
  });
}

/** Compare only audited observations. Neither a caller label nor repeated UUIDs establish independent inputs. */
export function compareVmRoles(contexts, contractRef, targetSha256) {
  const runs = contexts.map(c => {
    const sources = c.model.sourceReports.map(g => c.parents.get(g.selection.id)?.source);
    const identities = sources.map(s => s?.identity).filter(Boolean);
    const keys = new Set(identities.map(i => planningDigest([i.runId, i.threadId, i.runtimeBase])));
    const complete = sources.every(s => s?.schema === 'ig5-native-observations-v1' && s.targetSha256 === targetSha256
      && typeof s.identity?.runId === 'string' && s.identity.runId.length > 0 && Number.isSafeInteger(s.identity.threadId)
      && /^0x[0-9a-f]+$/i.test(s.identity.runtimeBase));
    if (complete && keys.size !== 1) fail('One context must describe one exact run/thread/base');
    return { context: c.ref, identity: complete ? identities[0] : null, identityObserved: complete,
      inputIdentity: null, vmInstance: null, codeEpoch: null, memoryEpoch: null,
      candidateAudit: c.audit.status, unknownGprs: c.model.evidence.unknownGprResults, unknownStores: c.model.evidence.unknownStoreValues };
  });
  const families = ['vipCandidates', 'dispatchBaseCandidates', 'opcodeCarrierCandidates', 'handlerTargetCarrierCandidates', 'vspCandidates'];
  const relations = families.flatMap(family => {
    const names = [...new Set(contexts.flatMap(c => c.model.roles[family].map(r => r.name)))].sort();
    return names.map(name => {
      const observations = contexts.map((c, index) => ({ contextIndex: index, candidate: c.model.roles[family].find(r => r.name === name) ?? null }));
      const deltas = observations.map(o => o.candidate?.observedDeltaModulo64 ?? null);
      return { family, name, observations, presentInAll: observations.every(o => o.candidate !== null),
        sameObservedFetchDelta: family === 'vipCandidates' ? deltas.every(d => d !== null && d === deltas[0]) : null,
        predictionValidated: false, vmRoleProved: false };
    });
  });
  const distinctRuns = new Set(runs.filter(r => r.identityObserved).map(r => r.identity.runId)).size;
  return { schema: 'ig5-vm-role-comparison-v1', targetSha256, contractRef, sourceContexts: contexts.map(c => c.ref), runs, relations,
    contractBinding: { targetMatched: true, functionEntryVerified: false, inputDomainVerified: false, authority: 'caller-declared-scope' },
    independence: { distinctObservedRuns: distinctRuns, allRunIdentitiesObserved: runs.every(r => r.identityObserved),
      identityAssurance: 'committed-source-manifest-only', rawCaptureRevalidated: false,
      independentInputs: 'unknown', independentVmInstances: 'unknown', codeVersionComparability: 'unknown', addressNormalization: 'none' },
    status: distinctRuns >= 2 ? 'cross-run-candidate-relations-only' : 'insufficient-independent-runs',
    competingExplanations: [{ kind: 'ordinary-switch', status: 'unresolved' }, { kind: 'buffer-iteration', status: 'unresolved' }],
    obligations: ['Bind entry inputs to each exact recording', 'Bind VM-instance lifetime and observed code/memory versions',
      'Predict held-out fetch/dispatch/stack/key changes', 'Discriminate ordinary switch and buffer iteration'],
    vmRoleProved: false, businessAccepted: false, nativeTargetExecuted: false, changesExecutionAuthority: false };
}
