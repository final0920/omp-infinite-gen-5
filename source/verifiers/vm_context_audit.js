import { createHash } from 'node:crypto';

// Independent implementation: no imports from the context derivation, decoder or adapter.
const registers = 'rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split(' ');
const mask = (1n << 64n) - 1n;
const canonical = v => Array.isArray(v) ? v.map(canonical) : v && typeof v === 'object'
  ? Object.fromEntries(Object.keys(v).sort().map(k => [k, canonical(v[k])])) : v;
const equal = (a, b) => JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
function requireFact(value, message) { if (!value) throw new Error(message); }
const hex = v => typeof v === 'string' && /^0x[0-9a-f]{1,16}$/.test(v);
const distance = (base, value) => { const d = (BigInt(value) - BigInt(base)) & mask; return d > (1n << 63n) ? d - (1n << 64n) : d; };
function add(map, key, sample) {
  const row = map.get(key) || { count: 0, samples: [] }; row.count++;
  if (row.samples.length < 8 && sample !== undefined) row.samples.push(sample);
  map.set(key, row);
}
export function auditVmContext(request) {
  let checks = 0;
  try {
    requireFact(request && Array.isArray(request.parents) && request.parents.length <= 48, 'bounded parent list required');
    let bytes = 0;
    const records = new Map(), paths = new Map();
    for (const entry of [request.root, ...request.parents]) {
      requireFact(entry?.bytes instanceof Uint8Array && entry.bytes.length <= 4 * 1024 ** 2, 'bounded byte inputs required');
      bytes += entry.bytes.length; requireFact(bytes <= 8 * 1024 ** 2, 'aggregate byte budget exceeded');
      const buffer = Buffer.from(entry.bytes);
      requireFact(createHash('sha256').update(buffer).digest('hex') === entry.sha256, 'input SHA mismatch');
      const record = JSON.parse(buffer);
      requireFact(record.id === entry.id && record.schemaVersion === 1 && !records.has(entry.id), 'record identity/duplicate differs');
      records.set(entry.id, record); paths.set(entry.id, entry.path); checks++;
    }
    const root = records.get(request.root.id), model = root.result;
    requireFact(root.kind === 'vm-context-model' && root.action === 'derive' && model?.schema === 'ig5-vm-context-model-v1'
      && model.status === 'single-run-context-candidates-phases-unknown' && model.targetSha256 === request.targetSha256, 'model identity differs');
    requireFact(Array.isArray(model.sourceReports) && model.sourceReports.length > 0 && model.sourceReports.length <= 16, 'source group budget differs');
    const tables = { fetch: new Map(), indexed: new Map(), opcode: new Map(), target: new Map() };
    const stack = new Map(registers.map(name => [name, { name, bodies: 0, mutatedBodies: 0, smallAlignedDeltaBodies: 0, nearbyAccessBodies: 0, nearbyAccesses: 0, deltaExamples: [] }]));
    const dictionary = [], occurrences = new Set(), pairs = new Set(), recordings = new Set(), usedParents = new Set();
    let ordinary = 0, partial = 0, unknownGprs = 0, unknownStores = 0;
    for (const group of model.sourceReports) {
      requireFact(equal(Object.keys(group).sort(), ['handlers', 'recurrence', 'selection']), 'parent group differs');
      const loaded = {};
      for (const [key, kind, action, schema] of [
        ['handlers', 'vm-recorded-handlers', 'assess', 'ig5-recorded-handlers-v1'],
        ['recurrence', 'vm-flow-recurrences', 'validate', 'ig5-flow-recurrences-v1'],
        ['selection', 'vm-handler-windows', 'select', 'ig5-recorded-handler-windows-v1'],
      ]) {
        const ref = group[key], entry = request.parents.find(p => p.id === ref?.id), record = records.get(ref?.id);
        requireFact(entry && equal(Object.keys(ref).sort(), ['id', 'path', 'sha256']) && entry.sha256 === ref.sha256 && paths.get(ref.id) === ref.path
          && record.kind === kind && record.action === action && record.result?.schema === schema && record.result.targetSha256 === request.targetSha256, 'typed parent binding differs');
        usedParents.add(ref.id); loaded[key] = record.result;
      }
      const { handlers: h, recurrence: r, selection: s } = loaded;
      requireFact(h.sourceRecurrence?.id === group.recurrence.id && h.sourceRecurrence?.sha256 === group.recurrence.sha256
        && h.sourceSelection?.id === group.selection.id && h.sourceSelection?.sha256 === group.selection.sha256
        && h.sourceSelection?.path === group.selection.path, 'source references differ');
      requireFact(r.distinctRecordedRuns === 1 && r.vmRoleProved === false && r.businessAccepted === false && h.vmRoleProved === false
        && h.businessAccepted === false && h.moduleLoadEpoch === null && h.memoryEpoch === null, 'source proof scope differs');
      requireFact(Array.isArray(h.bodies) && h.bodies.length > 0 && h.bodies.length <= 8 && Array.isArray(r.occurrences)
        && Array.isArray(s.bodies) && h.bodies.length === r.occurrences.length && h.bodies.length === s.bodies.length, 'source body count differs');
      for (let i = 0; i < h.bodies.length; i++) {
        const body = h.bodies[i], occurrence = r.occurrences[i], selected = s.bodies[i];
        const assessment = body.assessment;
        requireFact(body.sourceOccurrence === occurrence.startGroup && body.sourceOccurrence === selected.sourceOccurrence
          && body.sourceValue === occurrence.sourceValue && body.sourceValue === selected.sourceValue && body.observedEntry === occurrence.target
          && body.observedEntry === selected.observedEntry && body.completeNextBoundary === true && selected.completeNextBoundary === true
          && ['consistent-recorded-ordinary-state', 'partially-consistent-unknown-preserved'].includes(body.status)
          && assessment?.schema === 'ig5-recorded-handler-assessment-v1' && assessment.status === body.status, 'body/assessment binding differs');
        const key = occurrence.firstRecordingId + ':' + occurrence.startGroup, pair = body.sourceValue + ':' + body.observedEntry;
        requireFact(!occurrences.has(key) && !pairs.has(pair), 'duplicate occurrence or source/target pair'); occurrences.add(key); pairs.add(pair);
        recordings.add(occurrence.firstRecordingId); recordings.add(occurrence.lastRecordingId);
        requireFact(Array.isArray(occurrence.sourceAddressInputUpdates) && occurrence.sourceAddressInputUpdates.length <= 16, 'fetch input budget differs');
        for (const row of occurrence.sourceAddressInputUpdates) {
          requireFact(registers.includes(row.name) && hex(row.before) && hex(row.after) && hex(row.deltaModulo64)
            && '0x' + ((BigInt(row.after) - BigInt(row.before)) & mask).toString(16) === row.deltaModulo64, 'fetch update arithmetic differs');
          add(tables.fetch, row.name + ':' + row.deltaModulo64, { sourceValue: body.sourceValue, sourceAddress: occurrence.sourceAddress });
        }
        requireFact(Array.isArray(occurrence.indexedAddressInputValues) && occurrence.indexedAddressInputValues.length <= 128, 'indexed input budget differs');
        for (const read of occurrence.indexedAddressInputValues) {
          requireFact(Array.isArray(read.inputs) && read.inputs.length <= 16, 'indexed register budget differs');
          for (const input of read.inputs) { requireFact(registers.includes(input.name) && hex(input.value), 'indexed register differs'); add(tables.indexed, input.name, input.value); }
        }
        for (const name of registers) {
          if (occurrence.finalGprs[name] === occurrence.sourceValue) add(tables.opcode, name, body.sourceValue);
          if (occurrence.finalGprs[name] === occurrence.target) add(tables.target, name, occurrence.target);
        }
        requireFact(Array.isArray(selected.groups) && selected.groups.length > 0 && selected.groups.length <= 128, 'selected group budget differs');
        const accesses = selected.groups.flatMap(g => [...(Array.isArray(g.memoryReads) ? g.memoryReads : []), ...(Array.isArray(g.memoryWrites) ? g.memoryWrites : Array.isArray(g.memoryWrites?.stores) ? g.memoryWrites.stores : [])]);
        requireFact(accesses.length <= 4096, 'memory access budget differs');
        for (const name of registers) {
          const before = selected.groups[0].before.gprs[name], after = selected.groups.at(-1).after.gprs[name];
          requireFact(hex(before) && hex(after), 'unobserved register');
          const nearby = accesses.filter(a => hex(a.address) && [before, after].some(base => { const d = distance(base, a.address); return d >= -4096n && d <= 4096n; })).length;
          const summary = stack.get(name), delta = '0x' + ((BigInt(after) - BigInt(before)) & mask).toString(16), signed = distance(before, after);
          summary.bodies++; summary.nearbyAccesses += nearby;
          if (nearby) summary.nearbyAccessBodies++;
          if (before !== after) {
            summary.mutatedBodies++;
            if (signed >= -256n && signed <= 256n && signed % 2n === 0n) summary.smallAlignedDeltaBodies++;
            if (summary.deltaExamples.length < 8 && !summary.deltaExamples.includes(delta)) summary.deltaExamples.push(delta);
          }
        }
        requireFact(Array.isArray(assessment.gprs) && equal(assessment.gprs.map(g => g.name), registers)
          && Array.isArray(assessment.orderedStores) && assessment.orderedStores.length <= 4096, 'assessment register/store budget differs');
        const unknown = assessment.gprs.filter(g => g.status === 'unknown-preserved').map(g => g.name);
        const stores = assessment.orderedStores.filter(g => g.valueStatus === 'unknown-preserved').length;
        if (body.status === 'consistent-recorded-ordinary-state') ordinary++; else partial++;
        unknownGprs += unknown.length; unknownStores += stores;
        dictionary.push({ sourceValue: body.sourceValue, observedEntry: body.observedEntry, sourceOccurrence: body.sourceOccurrence,
          status: body.status, projection: body.projection, matchedFinalGprs: 16 - unknown.length, unknownGprs: unknown,
          orderedStores: assessment.orderedStores.length, unknownStores: stores, terminalControl: assessment.control,
          semanticOpcodeLabel: null, instructionSemanticsProved: false }); checks++;
      }
    }
    requireFact(usedParents.size === request.parents.length, 'unused or missing input parent');
    const total = occurrences.size;
    const candidates = (map, kind, excluded = []) => [...map].filter(([key, value]) => value.count === total && !excluded.includes(key.split(':')[0]))
      .map(([key, value]) => { const [name, delta] = key.split(':'); return { name, kind, observations: value.count, coverage: `${value.count}/${total}`,
        ...(delta ? { observedDeltaModulo64: delta } : {}), samples: value.samples, vmRoleProved: false }; }).sort((a, b) => a.name.localeCompare(b.name));
    const vipCandidates = candidates(tables.fetch, 'fetch-address-updater');
    const dispatchBaseCandidates = candidates(tables.indexed, 'indexed-dispatch-address-input', vipCandidates.map(c => c.name))
      .map(row => ({ ...row, stableObservedValues: [...new Set(tables.indexed.get(row.name).samples)] }));
    const vspCandidates = [...stack.values()].filter(row => row.nearbyAccessBodies > 0 && row.mutatedBodies > 0)
      .sort((a, b) => b.nearbyAccessBodies - a.nearbyAccessBodies || b.smallAlignedDeltaBodies - a.smallAlignedDeltaBodies || a.name.localeCompare(b.name))
      .map(row => ({ ...row, coverage: `${row.nearbyAccessBodies}/${total}`, kind: 'memory-proximate-mutable-register', vmRoleProved: false }));
    requireFact(equal(model.evidence, { sourcePages: model.sourceReports.length, occurrences: total, distinctRecordingIds: recordings.size,
      recordingIds: [...recordings].sort(), ordinaryConsistent: ordinary, partialUnknownPreserved: partial, unverified: 0,
      unknownGprResults: unknownGprs, unknownStoreValues: unknownStores }), 'evidence counts differ');
    requireFact(equal(model.roles, { vipCandidates, dispatchBaseCandidates, opcodeCarrierCandidates: candidates(tables.opcode, 'fetched-source-value-carrier'),
      handlerTargetCarrierCandidates: candidates(tables.target, 'observed-handler-target-carrier'), vspCandidates, genericMappingProved: false, competingCandidatesRetained: true }), 'role candidate derivation differs');
    requireFact(equal(model.observedHandlerDictionary, dictionary.sort((a, b) => a.sourceOccurrence - b.sourceOccurrence)), 'dictionary derivation differs');
    const phases = model.phases;
    requireFact(phases?.initialization?.status === 'unknown' && phases.fixup?.status === 'unknown' && phases.businessExecution?.status === 'unknown'
      && phases.dispatchExecution?.status === 'observed-candidate' && phases.dispatchExecution.occurrenceCount === total
      && phases.phaseClassificationProved === false && phases.moduleLoadEpoch === null && phases.memoryEpoch === null, 'phase boundary differs');
    for (const key of ['nativeTargetExecuted', 'changesExecutionAuthority', 'databaseModified', 'instructionSemanticsProved', 'vmRoleProved', 'vmIsaProved',
      'concreteBytecodeProgramRecovered', 'wholeVmRecovered', 'independentInputCoverageProved', 'businessAccepted', 'wholeFunctionCoverageProved', 'wholeBinaryVerified']) requireFact(model[key] === false, 'scope flag upgraded: ' + key);
    return { status: 'pass', checks, coverage: { sourcePages: model.sourceReports.length, occurrences: total, bytes, unknownGprs, unknownStores }, witness: null,
      nativeTargetExecuted: false, businessAccepted: false };
  } catch (error) {
    return { status: /budget|bounded/.test(error.message) ? 'unsupported' : 'fail', checks, coverage: null, witness: { reason: String(error.message).slice(0, 512) }, nativeTargetExecuted: false, businessAccepted: false };
  }
}
