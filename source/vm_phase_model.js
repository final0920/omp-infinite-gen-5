import { createPhaseContext, phaseContextIndex, contextPhaseAt, validateContextAnnotation } from './vm_phase_context.js';
import { analyzeVmObservations } from './vm_observations.js';
import { createCodeEpochMap, observedCodeVersion, requireObservedCodeVersion } from './code_epoch_map.js';

/** Replay existing observations only. Temporal candidates do not identify VM stages. */
export function analyzeVmPhases(request) {
  const context = request.phaseContext ? createPhaseContext(request.phaseContext, request.windows, request.targetSha256) : null;
  const map = createCodeEpochMap(), visited = new Set(), page = [], offset = request.offset ?? 0, limit = request.limit ?? 32;
  let visitsComplete = true;
  const counts = { groups: 0, firstVisits: 0, revisits: 0, unindexedVisits: 0, codeChangeGroups: 0, memoryChangeGroups: 0, missingStoreGroups: 0, incompleteIntermediateGroups: 0 };
  const result = analyzeVmObservations(request, (group, { source, summary }) => {
    const versions = group.instructions.map(i => {
      const version = observedCodeVersion(request.targetSha256, group, i, source, summary);
      return { version, relation: map.observe(version) };
    });
    const contextPhase = context?.observe(group, versions);
    const address = group.before.rip, revisited = visited.has(address);
    if (visited.size < 4096 || revisited) visited.add(address); else visitsComplete = false;
    const visitTrackingComplete = visitsComplete;
    const codeChanged = versions.some(v => v.relation.changedBytes.length);
    const writes = group.memoryWrites;
    const memoryChanges = (writes.stores || []).filter(store => store.changed === true).map(store => ({ ...store,
      sourceBlobSha256: writes.sourceBlobSha256, beforeStopSeq: writes.beforeStopSeq, afterStopSeq: writes.afterStopSeq,
      codeOverlap: map.overlap(store.address, store.bytes), actualWriteCausalityProved: false }));
    map.noteStores(group, source, summary);
    counts.groups++; counts[revisited ? 'revisits' : visitsComplete ? 'firstVisits' : 'unindexedVisits']++;
    if (codeChanged) counts.codeChangeGroups++;
    if (memoryChanges.length) counts.memoryChangeGroups++;
    if (writes.status === 'not-recorded-by-this-format') counts.missingStoreGroups++;
    if (!group.intermediateStateAvailable) counts.incompleteIntermediateGroups++;
    if (group.groupIndex >= offset && page.length < limit) page.push({ groupIndex: group.groupIndex, recordingId: group.recordingId,
      pauseSequence: group.pauseSequence, observedEntry: address, observedExit: group.after.rip,
      events: { entry: 'observed-stop-group-entry', exit: 'observed-next-stop-not-function-return',
        memoryReads: group.memoryReads, memoryChanges, storeObservationStatus: writes.status,
        unknownStores: writes.stores ? writes.stores.filter(store => store.changed === null).length : null,
        unchangedByteObservations: (writes.stores || []).filter(store => store.changed === false).length,
        unchangedBytesProveNoWrite: false, fullStoreSource: { recordingId: group.recordingId, groupIndex: group.groupIndex, sha256: writes.sourceBlobSha256 || null },
        controlVisit: revisited ? 'revisited' : visitsComplete ? 'first-observed' : 'unindexed' },
      candidate: codeChanged ? 'observed-code-change' : memoryChanges.length ? 'observed-memory-change' : revisited ? 'revisited-control-location' : !visitsComplete ? 'unindexed-control-location' : 'first-observed-control-location',
      candidateAssurance: 'temporal-observation-only; ordinary loops and switches remain alternatives',
      ...(contextPhase ? { contextPhase } : {}),
      phase: 'unknown', verifiedPhase: null, initialization: 'unknown', dispatch: 'unknown', business: 'unknown',
      visitTrackingComplete, intermediateStateAvailable: group.intermediateStateAvailable, versions });
  });
  return { ...result, phaseModel: { schema: 'ig5-vm-phase-model-v1', targetSha256: request.targetSha256,
    scope: 'Observation-local code versions and temporal candidates over fully validated recordings',
    ...(context ? { contextAnnotation: context.finish() } : {}),
    counts, visitsComplete, visitCountIsLowerBound: !visitsComplete, codeEpochs: map.status(), groups: page, pagination: result.pagination,
    phaseVerified: false, smcCoverageComplete: false, writesAttributedToInstructions: false,
    unknowns: ['Initialization/dispatch/business require independent role and contract evidence', 'No observation proves bytes stayed stable between stops',
      'Equal STORE before/after does not prove no write', 'Module load, concurrent writes and unrecorded memory remain unknown', 'Coalesced instructions have no invented intermediate state'],
    executionAuthorized: false, nativeTargetExecutedByThisRequest: false, businessAccepted: false } };
}

/** Host validation binds every published version to the exact independently loaded raw-source scope. */
export function validatePhaseModel(result, windows, phaseContext = null) {
  const model = result?.phaseModel;
  const index = phaseContext ? phaseContextIndex(phaseContext, windows, result.targetSha256, false) : null;
  if (index ? model?.contextAnnotation?.schema !== 'ig5-phase-context-annotation-v1' || JSON.stringify(model.contextAnnotation.contextRef) !== JSON.stringify(index.ref)
    || model.contextAnnotation.audit?.status !== 'pass' || model.contextAnnotation.phaseClassificationProved !== false || model.contextAnnotation.vmRoleProved !== false || model.contextAnnotation.businessAccepted !== false
    : model?.contextAnnotation !== undefined) throw Object.assign(new Error('Phase context annotation scope differs'), { code: 'INVALID_PHASE_CONTEXT' });
  if (index) validateContextAnnotation(model.contextAnnotation, index, phaseContext, windows, result.targetSha256);
  if (model?.schema !== 'ig5-vm-phase-model-v1' || model.targetSha256 !== result.targetSha256 || model.phaseVerified !== false
    || model.smcCoverageComplete !== false || model.writesAttributedToInstructions !== false || model.executionAuthorized !== false
    || model.nativeTargetExecutedByThisRequest !== false || model.businessAccepted !== false || model.groups?.length !== result.stopGroups.length
    || model.counts?.groups !== result.totals.stopGroups || model.codeEpochs?.globalCodeEpochKnown !== false) throw Object.assign(new Error('Invalid phase observation boundary'), { code: 'INVALID_VM_PHASE_MODEL' });
  // Replay the complete raw input at the host boundary, including events outside
  // the returned page. This verifies worker provenance, not independent CPU semantics.
  const expected = analyzeVmPhases({ targetSha256: result.targetSha256, windows,
    maxInstructions: result.totals.instructions, offset: result.pagination.offset, limit: result.pagination.limit }).phaseModel;
  const { contextAnnotation: _annotation, ...temporal } = model;
  const expectedRows = expected.groups;
  const { groups: _rows, ...actualHeader } = temporal;
  const { groups: _expectedRows, ...expectedHeader } = expected;
  if (JSON.stringify(actualHeader) !== JSON.stringify(expectedHeader)) throw Object.assign(new Error('Phase temporal summary differs from complete raw recordings'), { code: 'INVALID_VM_PHASE_MODEL' });
  for (let n = 0; n < result.stopGroups.length; n++) {
    const group = result.stopGroups[n], row = model.groups[n];
    if (index ? JSON.stringify(row.contextPhase) !== JSON.stringify(contextPhaseAt(index, group.groupIndex)) : row.contextPhase !== undefined) throw Object.assign(new Error('Phase interval annotation differs'), { code: 'INVALID_PHASE_CONTEXT' });
    const window = windows.find(w => w.source.reportId === group.recordingId);
    if (!window || row.groupIndex !== group.groupIndex || row.recordingId !== group.recordingId || row.phase !== 'unknown' || row.verifiedPhase !== null
      || ['initialization', 'dispatch', 'business'].some(k => row[k] !== 'unknown')
      || !['observed-code-change', 'observed-memory-change', 'revisited-control-location', 'first-observed-control-location', 'unindexed-control-location'].includes(row.candidate)
      || row.events?.unchangedBytesProveNoWrite !== false || row.intermediateStateAvailable !== group.intermediateStateAvailable
      || row.events.storeObservationStatus !== group.memoryWrites.status
      || JSON.stringify(row.events.memoryReads) !== JSON.stringify(group.memoryReads) || row.versions.length !== group.instructions.length) throw Object.assign(new Error('Phase source differs'), { code: 'INVALID_VM_PHASE_MODEL' });
    for (let i = 0; i < group.instructions.length; i++) requireObservedCodeVersion(row.versions[i].version,
      observedCodeVersion(result.targetSha256, group, group.instructions[i], window.source, window.summary));
    const { contextPhase: _context, ...actualRow } = row;
    if (JSON.stringify(actualRow) !== JSON.stringify(expectedRows[n])) throw Object.assign(new Error('Phase temporal row differs from complete raw recordings'), { code: 'INVALID_VM_PHASE_MODEL' });
    const stores = (group.memoryWrites.stores || []).filter(store => store.changed === true);
    if (!Array.isArray(row.events.memoryChanges) || row.events.memoryChanges.length !== stores.length
      || row.events.unknownStores !== (group.memoryWrites.stores ? group.memoryWrites.stores.filter(store => store.changed === null).length : null)
      || row.events.unchangedByteObservations !== (group.memoryWrites.stores || []).filter(store => store.changed === false).length
      || row.versions.some(v => v.relation?.intervalStable !== 'unknown' || v.relation.cause !== 'unknown')) throw Object.assign(new Error('Phase memory/interval scope differs'), { code: 'INVALID_VM_PHASE_MODEL' });
    for (let i = 0; i < stores.length; i++) {
      const view = row.events.memoryChanges[i];
      if (Object.keys(stores[i]).some(key => view[key] !== stores[i][key]) || view.actualWriteCausalityProved !== false
        || view.sourceBlobSha256 !== group.memoryWrites.sourceBlobSha256 || view.beforeStopSeq !== group.memoryWrites.beforeStopSeq
        || view.afterStopSeq !== group.memoryWrites.afterStopSeq) throw Object.assign(new Error('Phase write observation differs from its source'), { code: 'INVALID_VM_PHASE_MODEL' });
    }
  }
  return true;
}
