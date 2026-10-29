import { auditVmContext } from './verifiers/vm_context_audit.js';
import { planningDigest } from './planning_identity.js';
import { observedCodeVersion } from './code_epoch_map.js';

const fail = message => { throw Object.assign(new Error(message), { code: 'INVALID_PHASE_CONTEXT' }); };
const same = (a, b) => planningDigest(a) === planningDigest(b);
const integer = n => Number.isSafeInteger(n) && n >= 0 && n <= 100000;

/** The independent audit verifies candidate derivation only. Raw group rebinding is separate. */
export function phaseContextIndex(input, windows, targetSha256, audit = true) {
  if (!input || input.targetSha256 !== targetSha256) fail('Context target differs');
  const assessment = audit ? auditVmContext(input) : null;
  if (audit && assessment.status !== 'pass') fail('Context candidate derivation audit did not pass');
  const root = JSON.parse(Buffer.from(input.root.bytes)), model = root.result;
  const parents = new Map(input.parents.map(p => [p.id, JSON.parse(Buffer.from(p.bytes)).result]));
  const byGroup = new Map(), bodies = new Map(), boundaries = new Map(), cycles = [];
  const manifest = windows.map(w => ({ reportId: w.source.reportId, reportSha256: w.source.reportSha256,
    traceSha256: w.summary.sha256, locationFingerprint: w.source.locationFingerprint,
    startStopSeq: w.summary.startStopSeq, endStopSeq: w.summary.endStopSeq,
    confirmedStopGroups: w.summary.confirmedStepStops ?? w.summary.instructionCount, bytes: w.data.length,
    instructionCount: w.summary.instructionCount }));
  const total = windows.reduce((n, w) => n + (w.summary.confirmedStepStops ?? w.summary.instructionCount), 0);
  const add = (index, value) => {
    if (!integer(index) || index >= total || byGroup.has(index)) fail('Overlapping or out-of-range context intervals');
    if (byGroup.size >= 2048) fail('Context correlation exceeds 2048 group bindings');
    byGroup.set(index, value);
  };
  for (const refs of model.sourceReports) {
    const selection = parents.get(refs.selection.id), recurrence = parents.get(refs.recurrence.id);
    for (const source of [selection?.source, recurrence?.source]) {
      if (!source || source.schema !== 'ig5-native-observations-v1' || source.targetSha256 !== targetSha256 || source.totals?.stopGroups !== total
        || !Array.isArray(source.windows) || !same(source.windows.map(w => Object.fromEntries(Object.keys(manifest[0]).map(k => [k, w[k]]))), manifest)
        || source.identity?.runId !== windows[0].summary.runId || source.identity.threadId !== windows[0].summary.threadId
        || typeof source.identity.runtimeBase !== 'string' || !/^0x[0-9a-f]{1,16}$/i.test(source.identity.runtimeBase)
        || BigInt(source.identity.runtimeBase) !== BigInt(windows[0].summary.runtimeBase)) fail('The complete context recording manifest/run must match; subsets cannot reuse global group numbers');
    }
    const descriptor = recurrence.descriptor;
    if (!Array.isArray(descriptor) || !descriptor.length || descriptor.length > 128) fail('A bounded committed fetch descriptor is required');
    for (let n = 0; n < recurrence.occurrences.length; n++) {
      const occurrence = recurrence.occurrences[n], body = selection.bodies[n], ordinal = cycles.length;
      if (ordinal >= 128 || !integer(occurrence.startGroup) || !integer(occurrence.endGroup)
        || occurrence.endGroup - occurrence.startGroup + 1 !== descriptor.length || occurrence.groupCount !== descriptor.length
        || occurrence.status !== 'consistent-recorded-ordinary-state' || !body?.completeNextBoundary
        || !Array.isArray(body.groups) || !body.groups.length || body.groups.length > 128
        || body.groups[0].groupIndex !== occurrence.endGroup + 1 || body.groups.at(-1).groupIndex + 1 !== body.nextFetchGroup
        || body.groups.some((g, i) => g.groupIndex !== occurrence.endGroup + 1 + i)) fail('Context fetch/body boundaries differ');
      const cycle = { ordinal, occurrence: occurrence.startGroup, fetchStart: occurrence.startGroup, fetchEnd: occurrence.endGroup,
        bodyStart: body.groups[0].groupIndex, bodyEnd: body.groups.at(-1).groupIndex, nextFetchGroup: body.nextFetchGroup,
        sourceRecurrence: { id: refs.recurrence.id, sha256: refs.recurrence.sha256 }, sourceSelection: { id: refs.selection.id, sha256: refs.selection.sha256 } };
      cycles.push(cycle);
      for (let i = 0; i < descriptor.length; i++) add(occurrence.startGroup + i, { kind: 'fetch-dispatch-candidate', cycle, descriptor: descriptor[i], occurrence, first: i === 0, last: i === descriptor.length - 1 });
      for (const group of body.groups) { add(group.groupIndex, { kind: 'handler-body-candidate', cycle }); bodies.set(group.groupIndex, planningDigest(group)); }
      if (boundaries.has(body.nextFetchGroup) && !same(boundaries.get(body.nextFetchGroup), descriptor[0])) fail('Conflicting next fetch heads');
      boundaries.set(body.nextFetchGroup, descriptor[0]);
    }
  }
  if (!cycles.length) fail('No supported context cycles');
  return { assessment, ref: { id: input.root.id, sha256: input.root.sha256 }, byGroup, bodies, boundaries, cycles, total,
    firstSelected: Math.min(...cycles.map(c => c.fetchStart)) };
}

export function createPhaseContext(input, windows, targetSha256) {
  const index = phaseContextIndex(input, windows, targetSha256), matched = new Set(), matchedBoundaries = new Set();
  const sourceRead = new Set(), endpoints = new Map();
  return {
    observe(group, versions) {
      const entry = index.byGroup.get(group.groupIndex), head = index.boundaries.get(group.groupIndex);
      if (head && (group.instructions.length !== 1 || group.instructions[0].pc !== head.runtimePc || group.instructions[0].bytes !== head.bytes)) fail('Recorded next fetch head changed');
      if (head) matchedBoundaries.add(group.groupIndex);
      if (entry) {
        const cycle = entry.cycle;
        if (entry.kind === 'handler-body-candidate') {
          if (planningDigest(group) !== index.bodies.get(group.groupIndex)) fail('Handler body no longer matches the exact recorded group');
        } else {
          const item = group.instructions[0], o = entry.occurrence;
          if (group.instructions.length !== 1 || !group.intermediateStateAvailable || item.pc !== entry.descriptor.runtimePc || item.bytes !== entry.descriptor.bytes) fail('Fetch bytes or intermediate state differ from descriptor');
          if (entry.first && (group.recordingId !== o.firstRecordingId || group.pauseSequence.before !== o.firstPause || !same(group.before.gprs, o.initialGprs))) fail('Fetch initial identity/state differs');
          if (entry.last && (group.recordingId !== o.lastRecordingId || group.pauseSequence.after !== o.lastPause || !same(group.after.gprs, o.finalGprs) || group.after.rip !== o.target)) fail('Fetch final identity/state/target differs');
          if (group.memoryReads.some(read => read.address === o.sourceAddress && read.bytes === o.sourceBytes && BigInt('0x' + read.littleEndianHex.match(/../g).reverse().join('')) === BigInt(o.sourceValue))) sourceRead.add(cycle.ordinal);
        }
        matched.add(group.groupIndex);
        for (const [name, start, end] of [['fetch', cycle.fetchStart, cycle.fetchEnd], ['body', cycle.bodyStart, cycle.bodyEnd]]) {
          const key = cycle.ordinal + ':' + name;
          if (group.groupIndex === start) endpoints.set(key + ':first', versions[0].version.id);
          if (group.groupIndex === end) endpoints.set(key + ':last', versions.at(-1).version.id);
        }
      }
      return contextPhaseAt(index, group.groupIndex);
    },
    finish() {
      if (matched.size !== index.byGroup.size || matchedBoundaries.size !== index.boundaries.size || sourceRead.size !== index.cycles.length) fail('Not every selected context premise was rebound to the original recording');
      return { schema: 'ig5-phase-context-annotation-v1', contextRef: index.ref, audit: index.assessment,
        matchedGroups: matched.size, matchedNextFetchHeads: matchedBoundaries.size,
        segments: index.cycles.flatMap(cycle => [['fetch', cycle.fetchStart, cycle.fetchEnd], ['body', cycle.bodyStart, cycle.bodyEnd]].map(([kind, startGroup, endGroup]) => ({
          kind: kind === 'fetch' ? 'fetch-dispatch-candidate' : 'handler-body-candidate', occurrence: cycle.occurrence, startGroup, endGroup,
          firstVersionId: endpoints.get(cycle.ordinal + ':' + kind + ':first'), lastVersionId: endpoints.get(cycle.ordinal + ':' + kind + ':last'),
          sourceRecurrence: cycle.sourceRecurrence, sourceSelection: cycle.sourceSelection,
          status: 'observed-candidate', intervalStable: 'unknown' }))),
        prefix: index.firstSelected ? { startGroup: 0, endGroup: index.firstSelected - 1, status: 'unclassified-prefix-not-proved-initialization' } : null,
        phaseClassificationProved: false, vmRoleProved: false, businessAccepted: false,
        limitations: ['Candidate derivation and selected raw group bindings only; earlier decoder/CPU semantics remain premises', 'Unselected intervals are unknown, not implied handler or initialization coverage'] };
    },
  };
}

export function contextPhaseAt(index, groupIndex) {
  const entry = index.byGroup.get(groupIndex);
  return { kind: entry?.kind || (groupIndex < index.firstSelected ? 'unclassified-prefix' : 'unclassified-context-gap'),
    status: entry ? 'observed-candidate' : 'unknown', occurrence: entry?.cycle.occurrence ?? null,
    contextRef: index.ref, vmRoleProved: false, phaseVerified: false };
}

/** Reconstruct segment endpoint IDs from raw i/c lines, including endpoints outside the returned page. */
export function validateContextAnnotation(annotation, index, input, windows, targetSha256) {
  const endpoints = new Set(index.cycles.flatMap(c => [c.fetchStart, c.fetchEnd, c.bodyStart, c.bodyEnd])), versions = new Map();
  let base = 0;
  for (const window of windows) {
    let local = -1;
    const rows = Buffer.from(window.data).toString('ascii').split('\n');
    for (let line = 0; line < rows.length; line++) {
      const fields = rows[line].split(':');
      if (fields[0] === 'i') local++;
      if (!['i', 'c'].includes(fields[0]) || !endpoints.has(base + local)) continue;
      const group = { groupIndex: base + local, pauseSequence: { before: window.summary.startStopSeq + local, after: window.summary.startStopSeq + local + 1 } };
      const version = observedCodeVersion(targetSha256, group, { sourceLine: line + 1, pc: '0x' + BigInt(fields[1]).toString(16), bytes: fields[3].toLowerCase(), beforeStateAvailable: fields[0] === 'i' }, window.source, window.summary);
      const entry = versions.get(group.groupIndex) || { first: version.id };
      entry.last = version.id; versions.set(group.groupIndex, entry);
    }
    base += window.summary.confirmedStepStops ?? window.summary.instructionCount;
  }
  const segments = index.cycles.flatMap(c => [['fetch-dispatch-candidate', c.fetchStart, c.fetchEnd], ['handler-body-candidate', c.bodyStart, c.bodyEnd]].map(([kind, startGroup, endGroup]) => ({
    kind, occurrence: c.occurrence, startGroup, endGroup, firstVersionId: versions.get(startGroup)?.first, lastVersionId: versions.get(endGroup)?.last,
    sourceRecurrence: c.sourceRecurrence, sourceSelection: c.sourceSelection, status: 'observed-candidate', intervalStable: 'unknown' })));
  const prefix = index.firstSelected ? { startGroup: 0, endGroup: index.firstSelected - 1, status: 'unclassified-prefix-not-proved-initialization' } : null;
  if (!same(annotation.segments, segments) || !same(annotation.prefix, prefix) || annotation.matchedGroups !== index.byGroup.size
    || annotation.matchedNextFetchHeads !== index.boundaries.size || annotation.audit?.coverage?.occurrences !== index.cycles.length
    || annotation.audit.coverage.bytes !== [input.root, ...input.parents].reduce((n,p) => n + p.bytes.length, 0)
    || annotation.audit.nativeTargetExecuted !== false || annotation.audit.businessAccepted !== false) fail('Phase segment endpoints, source intervals or audit receipt differ');
  return true;
}
