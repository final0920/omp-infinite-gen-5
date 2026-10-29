// Conservative aggregation of hash-bound recurrence and handler observations.
// This module names candidates only. It never upgrades a single recorded run to
// a VM-role, phase, ISA, reachability, CPU, or business proof.
const GPRS = 'rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split(' ');
const MASK = (1n << 64n) - 1n;
const fail = message => { throw new Error('Invalid VM context evidence: ' + message); };
const hex = value => typeof value === 'string' && /^0x[0-9a-f]{1,16}$/.test(value);
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const delta = (before, after) => '0x' + ((BigInt(after) - BigInt(before)) & MASK).toString(16);
const signedDistance = (base, address) => {
  const d = (BigInt(address) - BigInt(base)) & MASK;
  return d > (1n << 63n) ? d - (1n << 64n) : d;
};
function increment(map, key, sample) {
  const row = map.get(key) || { count: 0, samples: [] };
  row.count++;
  if (row.samples.length < 8 && sample !== undefined) row.samples.push(sample);
  map.set(key, row);
}
function validateSource(source) {
  const { handlers, recurrence, selection } = source || {};
  if (handlers?.schema !== 'ig5-recorded-handlers-v1' || recurrence?.schema !== 'ig5-flow-recurrences-v1'
    || selection?.schema !== 'ig5-recorded-handler-windows-v1') fail('source schemas differ');
  if (handlers.targetSha256 !== recurrence.targetSha256 || handlers.targetSha256 !== selection.targetSha256
    || handlers.sourceRecurrence?.id !== source.recurrenceRef?.id || handlers.sourceRecurrence?.sha256 !== source.recurrenceRef?.sha256
    || handlers.sourceSelection?.id !== source.selectionRef?.id || handlers.sourceSelection?.path !== source.selectionRef?.path
    || handlers.sourceSelection?.sha256 !== source.selectionRef?.sha256) fail('source identity differs');
  if (!Array.isArray(handlers.bodies) || handlers.bodies.length > 8 || !Array.isArray(recurrence.occurrences)
    || recurrence.occurrences.length > 8 || !Array.isArray(selection.bodies) || selection.bodies.length > 8) fail('source budgets differ');
  if (handlers.bodies.length !== recurrence.occurrences.length || handlers.bodies.length !== selection.bodies.length) fail('body/recurrence counts differ');
  if (recurrence.distinctRecordedRuns !== 1 || recurrence.vmRoleProved !== false || recurrence.businessAccepted !== false
    || handlers.vmRoleProved !== false || handlers.businessAccepted !== false || handlers.moduleLoadEpoch !== null || handlers.memoryEpoch !== null) fail('source scope differs');
  const allowed = new Set(['consistent-recorded-ordinary-state', 'partially-consistent-unknown-preserved']);
  for (let i = 0; i < handlers.bodies.length; i++) {
    const h = handlers.bodies[i], o = recurrence.occurrences[i], s = selection.bodies[i];
    if (h.sourceOccurrence !== o.startGroup || h.sourceOccurrence !== s.sourceOccurrence || h.sourceValue !== o.sourceValue
      || h.sourceValue !== s.sourceValue || h.observedEntry !== o.target || h.observedEntry !== s.observedEntry
      || !allowed.has(h.status) || h.completeNextBoundary !== true || s.completeNextBoundary !== true
      || h.assessment?.schema !== 'ig5-recorded-handler-assessment-v1' || h.assessment.status !== h.status
      || !Array.isArray(s.groups) || !s.groups.length || !Array.isArray(h.assessment.gprs) || h.assessment.gprs.length !== 16
      || !same(h.assessment.gprs.map(row => row.name), GPRS)) fail('body binding or status differs');
  }
}
function nearbyAccesses(body) {
  const first = body.groups[0].before.gprs, last = body.groups.at(-1).after.gprs;
  const accesses = body.groups.flatMap(group => [...(Array.isArray(group.memoryReads) ? group.memoryReads : []),
    ...(Array.isArray(group.memoryWrites) ? group.memoryWrites : Array.isArray(group.memoryWrites?.stores) ? group.memoryWrites.stores : [])]);
  return GPRS.map(name => {
    if (!hex(first[name]) || !hex(last[name])) fail('unobserved body register');
    const near = accesses.filter(access => hex(access.address) && [first[name], last[name]].some(base => {
      const d = signedDistance(base, access.address); return d >= -4096n && d <= 4096n;
    }));
    const d = delta(first[name], last[name]), signed = signedDistance(first[name], last[name]);
    return { name, before: first[name], after: last[name], deltaModulo64: d, mutated: first[name] !== last[name],
      smallAlignedDelta: first[name] !== last[name] && signed >= -256n && signed <= 256n && signed % 2n === 0n,
      nearbyAccesses: near.length };
  });
}

export function deriveVmContextModel(sources) {
  if (!Array.isArray(sources) || !sources.length || sources.length > 16) fail('requires 1..16 source pages');
  sources.forEach(validateSource);
  const targetSha256 = sources[0].handlers.targetSha256;
  if (sources.some(source => source.handlers.targetSha256 !== targetSha256)) fail('mixed targets');
  const occurrenceKeys = new Set(), opcodeKeys = new Set(), fetch = new Map(), indexed = new Map(), opcode = new Map(), target = new Map();
  const stack = new Map(GPRS.map(name => [name, { name, bodies: 0, mutatedBodies: 0, smallAlignedDeltaBodies: 0, nearbyAccessBodies: 0, nearbyAccesses: 0, deltaExamples: [] }]));
  const isa = [], recordingIds = new Set();
  let ordinary = 0, partial = 0, unknownGprs = 0, unknownStores = 0, occurrenceCount = 0;
  for (const source of sources) {
    for (let i = 0; i < source.recurrence.occurrences.length; i++) {
      const occurrence = source.recurrence.occurrences[i], body = source.handlers.bodies[i], selected = source.selection.bodies[i];
      const occurrenceKey = occurrence.firstRecordingId + ':' + occurrence.startGroup;
      if (occurrenceKeys.has(occurrenceKey)) fail('duplicate occurrence'); occurrenceKeys.add(occurrenceKey);
      const opcodeKey = body.sourceValue + ':' + body.observedEntry;
      if (opcodeKeys.has(opcodeKey)) fail('duplicate opcode/entry pair'); opcodeKeys.add(opcodeKey);
      recordingIds.add(occurrence.firstRecordingId); recordingIds.add(occurrence.lastRecordingId); occurrenceCount++;
      for (const update of occurrence.sourceAddressInputUpdates || []) {
        if (!GPRS.includes(update.name) || !hex(update.before) || !hex(update.after) || !hex(update.deltaModulo64)
          || delta(update.before, update.after) !== update.deltaModulo64) fail('invalid fetch update');
        increment(fetch, update.name + ':' + update.deltaModulo64, { sourceValue: body.sourceValue, sourceAddress: occurrence.sourceAddress });
      }
      for (const read of occurrence.indexedAddressInputValues || []) for (const input of read.inputs || []) {
        if (!GPRS.includes(input.name) || !hex(input.value)) fail('invalid indexed-address input');
        increment(indexed, input.name, input.value);
      }
      for (const name of GPRS) {
        if (occurrence.finalGprs[name] === occurrence.sourceValue) increment(opcode, name, body.sourceValue);
        if (occurrence.finalGprs[name] === occurrence.target) increment(target, name, occurrence.target);
      }
      for (const row of nearbyAccesses(selected)) {
        const summary = stack.get(row.name); summary.bodies++;
        if (row.mutated) summary.mutatedBodies++;
        if (row.smallAlignedDelta) summary.smallAlignedDeltaBodies++;
        if (row.nearbyAccesses) summary.nearbyAccessBodies++;
        summary.nearbyAccesses += row.nearbyAccesses;
        if (row.mutated && summary.deltaExamples.length < 8 && !summary.deltaExamples.includes(row.deltaModulo64)) summary.deltaExamples.push(row.deltaModulo64);
      }
      const ug = body.assessment.gprs.filter(row => row.status === 'unknown-preserved').map(row => row.name);
      const us = body.assessment.orderedStores.filter(row => row.valueStatus === 'unknown-preserved').length;
      if (body.status === 'consistent-recorded-ordinary-state') ordinary++; else partial++;
      unknownGprs += ug.length; unknownStores += us;
      isa.push({ sourceValue: body.sourceValue, observedEntry: body.observedEntry, sourceOccurrence: body.sourceOccurrence,
        status: body.status, projection: body.projection, matchedFinalGprs: 16 - ug.length,
        unknownGprs: ug, orderedStores: body.assessment.orderedStores.length, unknownStores: us,
        terminalControl: body.assessment.control, semanticOpcodeLabel: null, instructionSemanticsProved: false });
    }
  }
  const candidate = (map, kind, exclude = new Set()) => [...map.entries()].map(([key, value]) => {
    const [name, observedDelta] = key.split(':');
    return { name, kind, observations: value.count, coverage: `${value.count}/${occurrenceCount}`,
      ...(observedDelta ? { observedDeltaModulo64: observedDelta } : {}), samples: value.samples, vmRoleProved: false };
  }).filter(row => row.observations === occurrenceCount && !exclude.has(row.name)).sort((a,b) => a.name.localeCompare(b.name));
  const vipCandidates = candidate(fetch, 'fetch-address-updater');
  const vipNames = new Set(vipCandidates.map(row => row.name));
  const dispatchBaseCandidates = candidate(indexed, 'indexed-dispatch-address-input', vipNames).map(row => ({ ...row,
    stableObservedValues: [...new Set(indexed.get(row.name).samples)] }));
  const opcodeCarrierCandidates = candidate(opcode, 'fetched-source-value-carrier');
  const handlerTargetCarrierCandidates = candidate(target, 'observed-handler-target-carrier');
  const vspCandidates = [...stack.values()].filter(row => row.nearbyAccessBodies > 0 && row.mutatedBodies > 0)
    .sort((a,b) => b.nearbyAccessBodies - a.nearbyAccessBodies || b.smallAlignedDeltaBodies - a.smallAlignedDeltaBodies || a.name.localeCompare(b.name))
    .map(row => ({ ...row, coverage: `${row.nearbyAccessBodies}/${occurrenceCount}`, kind: 'memory-proximate-mutable-register', vmRoleProved: false }));
  isa.sort((a,b) => a.sourceOccurrence - b.sourceOccurrence);
  return { schema: 'ig5-vm-context-model-v1', status: 'single-run-context-candidates-phases-unknown', targetSha256,
    evidence: { sourcePages: sources.length, occurrences: occurrenceCount, distinctRecordingIds: recordingIds.size,
      recordingIds: [...recordingIds].sort(), ordinaryConsistent: ordinary, partialUnknownPreserved: partial,
      unverified: 0, unknownGprResults: unknownGprs, unknownStoreValues: unknownStores },
    roles: { vipCandidates, dispatchBaseCandidates, opcodeCarrierCandidates, handlerTargetCarrierCandidates, vspCandidates,
      genericMappingProved: false, competingCandidatesRetained: true },
    phases: { initialization: { status: 'unknown', reason: 'no phase-bound entry or initialization-completion observation' },
      fixup: { status: 'unknown', reason: 'module and memory epochs are absent; writes are not classified as relocation fixups' },
      dispatchExecution: { status: 'observed-candidate', occurrenceCount, reason: 'recurrent fetch/index/target observations bounded by recorded handler bodies' },
      businessExecution: { status: 'unknown', reason: 'no function contract, independent oracle, return boundary, or alternate-input evidence' },
      phaseClassificationProved: false, moduleLoadEpoch: null, memoryEpoch: null },
    observedHandlerDictionary: isa,
    nativeTargetExecuted: false, changesExecutionAuthority: false, databaseModified: false, instructionSemanticsProved: false,
    vmRoleProved: false, vmIsaProved: false, concreteBytecodeProgramRecovered: false, wholeVmRecovered: false,
    independentInputCoverageProved: false, businessAccepted: false, wholeFunctionCoverageProved: false, wholeBinaryVerified: false,
    nextObligations: ['Bind module and memory epochs and classify initialization/fixup/dispatch boundaries',
      'Repeat the same role relations across independent inputs and VM instances',
      'Resolve saved-status consumers while preserving unknown outputs',
      'Recover bytecode control flow and validate a complete function contract with an independent oracle'],
    scope: 'Hash-bound aggregation of recorded recurrence and handler observations. Candidate names and the handler dictionary are not VM-role, phase, ISA, CPU, reachability, program, or business proofs.' };
}
