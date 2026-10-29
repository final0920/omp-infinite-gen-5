import { RECOVERY_LIMITS, RECOVERY_STAGES, RECOVERY_FAILURES, recoveryBinding, recoveryDigest,
  recoveryObservationBinding, recoveryError, validateRecoveryCase } from './vm_recovery_case.js';
import { routeFailure } from './failure_router.js';

const stageActions = Object.freeze({
  admission: ['establish-case-and-contract', ['producer/version/configuration provenance', 'target identity', 'independent function contract'], ['ig5_recovery', 'ig5_open']],
  capture: ['collect-phase-bound-observations', ['run/thread/address-space identity', 'phase and code epochs', 'entry/return and ordered state observations'], ['ig5_dbg', 'ig5_ir level=trace']],
  vm_model: ['infer-and-test-vm-roles', ['VIP/VSP/context/key candidates with origins', 'fetch/dispatch/exit relations', 'competing hypotheses and counterexamples'], ['ig5_ir level=discover', 'ig5_ir level=project', 'ig5_ir level=compose']],
  isa: ['derive-and-verify-handler-families', ['complete input/output and ordered memory effects', 'flags/aliases/guards/side exits', 'independent equivalence obligations'], ['ig5_ir level=project', 'ig5_ir level=compose', 'ig5_ir level=trace']],
  program: ['recover-bytecode-program', ['phase-bound bytecode with read provenance', 'virtual CFG including unresolved edges', 'calls/returns/loops and code-version dependencies'], []],
  business: ['verify-complete-function-contract', ['return and all contract side effects', 'independent oracle comparison', 'assumptions and counterexamples'], ['ig5_ir level=trace']],
  coverage: ['discharge-input-and-path-obligations', ['declared input domain', 'path partition/coverage obligations', 'independent holdout and unresolved guards'], ['ig5_ir level=trace']],
  autonomy: ['run-no-answer-key-agent-acceptance', ['original task and actual model/tool journal', 'human guidance count', 'autonomous model/plan revisions and validation'], ['ig5_profile']],
  deployment: ['validate-reproducible-deployment', ['source/installed build pins', 'cold reload and actual model acceptance', 'repeatability/performance/cleanup evidence'], ['ig5_profile', 'ig5_status']],
});
const needsImplementation = new Set(['vm_model', 'isa', 'program', 'business', 'coverage', 'autonomy']);
const requirements = Object.freeze({
  admission: { artifacts: ['source'], capabilities: ['case-contract-validation'] },
  capture: { artifacts: ['source', 'trace', 'image-manifest'], capabilities: ['approved-recorder', 'phase-and-epoch-binding'] },
  vm_model: { artifacts: ['trace', 'projection'], capabilities: ['native-dataflow', 'vm-role-inference'] },
  isa: { artifacts: ['vm-model', 'projection'], capabilities: ['state-translation', 'handler-semantics-verifier'] },
  program: { artifacts: ['vm-model', 'isa', 'trace'], capabilities: ['bytecode-decoder', 'virtual-cfg-builder'] },
  business: { artifacts: ['program', 'business'], capabilities: ['independent-function-verifier'] },
  coverage: { artifacts: ['business', 'validation'], capabilities: ['input-domain-and-path-verifier'] },
  autonomy: { artifacts: ['validation'], capabilities: ['host-goal-driver', 'configured-model', 'agent-journal-validator'] },
  deployment: { artifacts: ['validation'], capabilities: ['build-pin-verifier', 'cold-reload-validator'] },
});
function prerequisiteClosure(stage, referenceKinds) {
  const stages = new Set(), artifacts = new Set(), capabilities = new Set();
  function visit(id) {
    if (stages.has(id)) return;
    for (const dependency of RECOVERY_STAGES[id]) visit(dependency);
    stages.add(id);
    for (const kind of requirements[id].artifacts) artifacts.add(kind);
    for (const capability of requirements[id].capabilities) capabilities.add(capability);
  }
  visit(stage);
  return { stages: [...stages], artifacts: [...artifacts].map(kind => ({ kind,
    inventory: referenceKinds.has(kind) ? 'declared-reference-present' : 'missing-reference', semanticVerified: false })),
  capabilities: [...capabilities].map(id => ({ id, availability: 'not-probed' })),
  scope: 'planning-requirements-not-host-capability-verification' };
}

/** Pure, bounded work planner. Artifact identity checks are not semantic certificates. */
export function planVmRecovery(input, referenceChecks = []) {
  const value = validateRecoveryCase(input), binding = recoveryBinding(value);
  if (!Array.isArray(referenceChecks) || Object.getPrototypeOf(referenceChecks) !== Array.prototype
    || referenceChecks.length > RECOVERY_LIMITS.references || Reflect.ownKeys(referenceChecks).length !== referenceChecks.length + 1
    || Array.from({ length: referenceChecks.length }, (_, i) => Object.getOwnPropertyDescriptor(referenceChecks, String(i)))
      .some(d => !d || !Object.hasOwn(d, 'value')))
    recoveryError('INVALID_RECOVERY_CHECK', 'Reference checks exceed their bounded internal contract');
  const checkedIds = new Set();
  for (const check of referenceChecks) {
    if (!check || Object.getPrototypeOf(check) !== Object.prototype
      || Reflect.ownKeys(check).some(key => !['id', 'status', 'sha256', 'bytes', 'code'].includes(key)
        || !Object.hasOwn(Object.getOwnPropertyDescriptor(check, key), 'value'))
      || typeof check.id !== 'string' || !value.references.some(ref => ref.id === check.id) || checkedIds.has(check.id)
      || !['identity-matched', 'identity-mismatch', 'unavailable'].includes(check.status))
      recoveryError('INVALID_RECOVERY_CHECK', 'Invalid or duplicate internal reference check');
    checkedIds.add(check.id);
  }
  const checks = new Map(referenceChecks.map(check => [check.id, check]));
  const latest = new Map(value.events.map(event => [event.stage, event.id]));
  const refs = new Map(value.references.map(ref => [ref.id, ref]));
  const evaluated = new Map();
  const fingerprintCounts = new Map();
  for (const event of value.events) {
    const invalid = [];
    if (event.bindingSha256 !== binding) invalid.push('case-scope-or-objective-changed');
    if (event.inputBindingSha256 !== recoveryObservationBinding(value, event)) invalid.push('referenced-artifacts-or-input-records-changed');
    for (const ref of event.references) {
      const check = checks.get(ref), expected = refs.get(ref);
      if (check?.status !== 'identity-matched' || check.sha256 !== expected.sha256 || check.bytes !== expected.bytes)
        invalid.push(`artifact-not-revalidated:${ref}`);
    }
    for (const id of event.inputs) {
      const prior = evaluated.get(id);
      if (!prior || prior.invalidReasons.length || latest.get(prior.stage) !== id || !['partial', 'candidate'].includes(prior.callerState))
        invalid.push(`stale-or-open-input:${id}`);
    }
    if (['partial', 'candidate'].includes(event.state)) {
      for (const stage of RECOVERY_STAGES[event.stage]) {
        if (!event.inputs.some(id => evaluated.get(id)?.stage === stage)) invalid.push(`missing-prerequisite-observation:${stage}`);
      }
    }
    const contentKey = recoveryDigest({ stage: event.stage, binding: event.bindingSha256,
      references: event.references.map(id => ({ kind: refs.get(id).kind, sha256: refs.get(id).sha256, bytes: refs.get(id).bytes }))
        .sort((a, b) => a.sha256.localeCompare(b.sha256) || a.kind.localeCompare(b.kind)),
      inputs: event.inputs.map(id => evaluated.get(id).contentKey).sort() });
    let repeatedWithoutNewInputs = 0;
    if (event.failure && !invalid.length) {
      // Bare caller revisions, fingerprints, notes and new ids are not new evidence.
      const repeatKey = recoveryDigest({ code: event.failure.code, contentKey });
      repeatedWithoutNewInputs = (fingerprintCounts.get(repeatKey) || 0) + 1;
      fingerprintCounts.set(repeatKey, repeatedWithoutNewInputs);
    }
    evaluated.set(event.id, { id: event.id, stage: event.stage, callerState: event.state,
      invalidReasons: invalid, contentKey, repeatedWithoutNewInputs, semanticVerified: false });
  }
  const stages = Object.keys(RECOVERY_STAGES).map(stage => {
    const event = evaluated.get(latest.get(stage));
    return { stage, dependsOn: [...RECOVERY_STAGES[stage]], workState: !event ? 'missing'
      : event.invalidReasons.length ? 'stale' : event.callerState,
    latestEvent: event?.id || null, invalidReasons: event?.invalidReasons || [],
    assurance: 'unverified', gateAccepted: false, verifierAdapter: 'not-connected' };
  });
  const byStage = new Map(stages.map(stage => [stage.stage, stage]));
  const versionMatches = value.scope.family === value.objective.family && value.scope.version !== null
    && (value.scope.version === value.objective.versionSeries || value.scope.version.startsWith(value.objective.versionSeries + '.'));
  const actions = [];
  const referenceKinds = new Set(value.references.map(ref => ref.kind));
  const add = (stage, action, reason, priority, event = null) => {
    if (actions.some(item => item.stage === stage && item.action === action)) return;
    const prerequisites = prerequisiteClosure(stage, referenceKinds);
    actions.push({ stage, action, reason, priority, basedOn: event ? [event.id] : [],
      requiredOutputs: [...stageActions[stage][1]], toolHints: [...stageActions[stage][2]],
      prerequisites, readiness: 'requires-independent-preflight',
      missingArtifactKinds: prerequisites.artifacts.filter(item => item.inventory === 'missing-reference').map(item => item.kind),
      implementation: needsImplementation.has(stage) ? 'generic-adapter-needed' : 'existing-components-require-validation',
      execution: 'proposal-only', approvalGranted: false });
  };
  const ownerEvents = value.events.filter(event => event.failure?.code === 'CLEANUP_UNCONFIRMED');
  // A later ordinary success/candidate cannot erase an unresolved native owner.
  // This v1 has no authority/adapter to import a terminal cleanup receipt.
  const executionHeld = ownerEvents.length > 0;
  if (executionHeld) add('capture', 'recover-original-execution-owner', 'Original cleanup authority must confirm termination before another execution', 0, ownerEvents.at(-1));
  if (!versionMatches) add('admission', 'obtain-requested-version-case', 'Current case is not the requested version series; engineering results remain in the component lane', 1);
  if (['targetSha256', 'producerSha256', 'configurationSha256', 'functionContractSha256'].some(k => value.scope[k] === null)
    || value.scope.functionEntry === null || value.scope.architecture === 'unknown' || value.scope.codeEpoch === null)
    add('admission', 'establish-case-and-contract', 'Identity, protection configuration or complete-function contract is missing', 2);
  for (const stage of stages) {
    const original = value.events.find(event => event.id === stage.latestEvent);
    const event = original && evaluated.get(original.id);
    if (event && !event.invalidReasons.length && original.failure) {
      add(stage.stage, routeFailure({ failureCode: original.failure.code }, event.repeatedWithoutNewInputs).nextCheck,
        event.repeatedWithoutNewInputs >= 2 ? 'Same failure, hypothesis and inputs repeated; select a different testable hypothesis' : original.failure.code,
        original.failure.code === 'CLEANUP_UNCONFIRMED' ? 0 : 3, original);
      continue;
    }
    const depsOpen = stage.dependsOn.filter(id => !['partial', 'candidate'].includes(byStage.get(id).workState));
    if (depsOpen.length) continue;
    if (stage.workState === 'candidate') {
      add(stage.stage, 'connect-independent-stage-verifier', 'Caller candidate and matched file hashes cannot discharge this stage gate', 5, original);
    } else {
      add(stage.stage, stageActions[stage.stage][0], stage.workState === 'partial' ? 'Complete the missing obligations in this stage'
        : stage.workState === 'stale' ? 'Revalidate changed scope, artifacts or prerequisite observations' : 'No current stage observation',
      stage.stage === 'vm_model' || stage.stage === 'program' ? 3 : 4, original);
    }
  }
  actions.sort((a, b) => a.priority - b.priority || Object.keys(RECOVERY_STAGES).indexOf(a.stage) - Object.keys(RECOVERY_STAGES).indexOf(b.stage)
    || a.action.localeCompare(b.action));
  return { schema: 'ig5-vm-recovery-plan-v1', caseId: value.caseId, bindingSha256: binding,
    caseSha256: recoveryDigest(value), requestedVersionSeries: value.objective.versionSeries,
    versionMatch: versionMatches, lane: versionMatches ? 'requested-version-candidate' : 'component-research-only',
    sourceOfWorkStates: 'caller-observations', artifactChecksEstablish: 'byte-identity-only',
    stages, evaluatedEvents: [...evaluated.values()], nextActions: actions.slice(0, 4), deferredActions: actions.slice(4),
    blockedRequirements: stages.map(stage => ({ stage: stage.stage,
      missingWorkDependencies: stage.dependsOn.filter(id => !['partial', 'candidate'].includes(byStage.get(id).workState)),
      independentVerifier: 'not-connected', inputs: prerequisiteClosure(stage.stage, referenceKinds) })),
    // These are engineering checks, not the final autonomy/deployment stage gates.
    engineeringActions: [
      { action: 'run-component-regression', dependsOnBusinessRecovery: false },
      { action: 'verify-source-and-installed-pins', dependsOnBusinessRecovery: false },
      { action: 'validate-host-skill-and-goal-integration', dependsOnBusinessRecovery: false },
    ],
    integration: { dshPlanningEntry: 'not-invoked-by-pure-planner', automaticExecution: 'not-connected', stageVerifiers: 'not-connected' },
    executionHeldFromObservations: executionHeld, executionAuthority: 'not-inspected',
    executionPerformed: false, changesExecutionAuthority: false,
    completionAssessment: { status: 'not-achieved', businessAccepted: false, wholeVmRecovered: false,
      exactRequestedVersionAccepted: false, autonomousRecoveryVerified: false,
      reason: 'Stage-specific independent verifier adapters and end-to-end acceptance are not connected in framework v1' },
  };
}
