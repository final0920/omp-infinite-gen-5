import { planningDigest } from './planning_identity.js';

/** Observed candidate graph. Unknown decode memory/epochs deliberately prevent cross-observation merging. */
export function buildObservedVmCfg(contexts, comparisonRef, targetSha256, contractRef, checkCancelled = () => {}) {
  const nodes = [], edges = [], unresolved = [];
  for (const context of contexts) for (const refs of context.model.sourceReports) {
    checkCancelled();
    const recurrence = context.parents.get(refs.recurrence.id), selection = context.parents.get(refs.selection.id), handlers = context.parents.get(refs.handlers.id);
    for (let i = 0; i < recurrence.occurrences.length; i++) {
      if (nodes.length >= 1024) throw Object.assign(new Error('Observed VM graph exceeds 1024 nodes'), { code: 'VM_PROGRAM_LIMIT' });
      const o = recurrence.occurrences[i], body = selection.bodies[i], assessed = handlers.bodies[i];
      const identity = { context: context.ref, selection: { id: refs.selection.id, sha256: refs.selection.sha256 },
        occurrence: o.startGroup, recordedRun: selection.source?.identity ?? null, bytecodePositionCandidate: o.sourceAddress ?? null,
        decodeRegisters: o.initialGprs, observedEntry: o.target, codeEpoch: null, memoryEpoch: null, vmInstance: null,
        unknownDecodeMemory: true };
      const id = planningDigest(identity);
      const width = o.sourceBytes;
      const observedBytes = Number.isSafeInteger(width) && width >= 1 && width <= 8 && /^0x[0-9a-f]{1,16}$/.test(o.sourceValue)
        && BigInt(o.sourceValue) < 1n << BigInt(width * 8) ? BigInt(o.sourceValue).toString(16).padStart(width * 2, '0').match(/../g).reverse().join('') : null;
      nodes.push({ id, identity, fetchedValue: o.sourceValue,
        fetchedObservation: { address: o.sourceAddress ?? null, bytes: observedBytes, width: observedBytes === null ? null : width, assurance: 'committed-recurrence-source-read' },
        semanticOpcode: null, sourceRefs: refs,
        groupRange: { fetchStart: o.startGroup, fetchEnd: o.endGroup ?? null, bodyStart: body.groups[0]?.groupIndex ?? null,
          bodyEnd: body.groups.at(-1)?.groupIndex ?? null, nextFetchGroup: body.nextFetchGroup ?? null },
        fullStateEffects: { assessment: assessed.assessment, projection: assessed.projection, sourceSelection: refs.selection,
          observedGroups: body.groups.length, unknownMemoryFootprint: true },
        unknowns: ['VM role', 'decode memory', 'code/memory epoch', 'unobserved branches', 'aliasing', 'calls/returns/exceptions'],
        terminalReturnProved: false });
    }
  }
  // Only exact recording/group adjacency is an observed successor; sorting opcode values invents edges.
  for (const node of nodes) {
    checkCancelled();
    const matches = nodes.filter(n => n.identity.context.id === node.identity.context.id
      && node.groupRange.nextFetchGroup !== null && n.identity.occurrence === node.groupRange.nextFetchGroup);
    if (matches.length === 1) edges.push({ from: node.id, to: matches[0].id, kind: 'observed-next-fetch', source: node.sourceRefs.selection });
    else unresolved.push({ from: node.id, kind: 'next-fetch-unresolved', target: null, observedNextGroup: node.groupRange.nextFetchGroup });
    unresolved.push({ from: node.id, kind: 'unobserved-alternative', target: null });
  }
  return { schema: 'ig5-observed-vm-program-v1', targetSha256, contractRef, comparisonRef, sourceContexts: contexts.map(c => c.ref),
    nodes, edges, unresolvedEdges: unresolved, stateMerging: 'disabled-unknown-decode-memory', status: 'observed-candidate-paths',
    fullFunctionCoverageProved: false, concreteBytecodeProgramRecovered: false, vmIsaProved: false, businessAccepted: false,
    nativeTargetExecuted: false, changesExecutionAuthority: false };
}
