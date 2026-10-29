import { createHash } from 'node:crypto';
import { readNativeStoreEvents } from './native_store_events.js';

const GPRS = 'rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split(' ');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = message => { throw Object.assign(new Error(message), { code: 'INVALID_VM_OBSERVATION' }); };
const limit = message => { throw Object.assign(new Error(message), { code: 'VM_OBSERVATION_LIMIT' }); };
const hex = value => typeof value === 'string' && /^0x[0-9a-f]{1,16}$/i.test(value);
const hx = value => '0x' + value.toString(16);
function number(value, label, low, high) {
  if (!Number.isSafeInteger(value) || Object.is(value, -0) || value < low || value > high) fail(label + ' is outside its integer budget');
}
function words(values, count) {
  if (values.length !== count || !values.every(hex)) fail('Invalid native snapshot width or uint64 value');
  return values.map(value => BigInt(value));
}
function snapshot(registers, flags, rip, line) {
  return { gprs: Object.fromEntries(GPRS.map((name, index) => [name, hx(registers[index])])),
    rip: hx(rip), flags: hx(flags), sourceLine: line, assurance: 'recorded-observation-not-predicted-state' };
}

/** Data-only native recording view. No decoder, instruction processing or CPU proof.
 * Read all windows for continuity; retain only the requested page of stop groups.
 */
export function analyzeVmObservations(request, visitGroup = null) {
  if (!request || typeof request.targetSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(request.targetSha256)) fail('Expected target SHA-256');
  const maximum = request.maxInstructions ?? 50000, offset = request.offset ?? 0, pageSize = request.limit ?? 32;
  number(maximum, 'maxInstructions', 1, 100000); number(offset, 'offset', 0, 100000); number(pageSize, 'limit', 1, 64);
  if (!Array.isArray(request.windows) || !request.windows.length || request.windows.length > 256) limit('Choose 1..256 recording windows');
  const pages = [], windows = [], code = new Map(), changes = [], ids = new Set();
  let totalBytes = 0, totalInstructions = 0, totalGroups = 0, totalReads = 0, changedCodeCount = 0, totalStoreBytes = 0;
  let previous = null, codeTrackingComplete = true;
  for (const window of request.windows) {
    if (!window || typeof window !== 'object') fail('Missing native observation window');
    const { source, summary } = window;
    if (!source || typeof source.reportId !== 'string' || !/^[a-f0-9-]{36}$/.test(source.reportId) || ids.has(source.reportId)
      || typeof source.reportSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(source.reportSha256) || !summary
      || summary.targetSha256 !== request.targetSha256 || summary.nativeTargetExecuted !== true
      || !['ig5.x86-recording.v1', 'ig5.x86-recording.v2'].includes(summary.format)
      || summary.finalSnapshotIncluded !== true || summary.finalSnapshotCurrent === false) fail('Recording identity or final snapshot is invalid');
    ids.add(source.reportId);
    if (!(window.data instanceof Uint8Array)) fail('Recording bytes must be a bounded byte snapshot');
    const data = Buffer.from(window.data);
    if (!data.length || data.length > 1024 * 1024) limit('Recording window exceeds 1 MiB');
    totalBytes += data.length; if (totalBytes > 16 * 1024 * 1024) limit('Recording input exceeds 16 MiB');
    if (data.at(-1) !== 10 || data.some(value => value > 127) || data.length !== summary.bytes || sha(data) !== summary.sha256)
      fail('Recording ASCII, byte count or SHA-256 differs');
    if (typeof summary.runId !== 'string' || !summary.runId.trim() || summary.runId.length > 256) fail('Missing bounded run identity');
    if (typeof summary.stopReason !== 'string' || !summary.stopReason || summary.stopReason.length > 128) fail('Missing bounded recording stop reason');
    number(summary.threadId, 'threadId', 1, 0xffffffff);
    number(summary.startStopSeq, 'startStopSeq', 1, Number.MAX_SAFE_INTEGER);
    number(summary.endStopSeq, 'endStopSeq', 1, Number.MAX_SAFE_INTEGER);
    number(summary.instructionCount, 'instructionCount', 1, 1024);
    const confirmed = summary.confirmedStepStops ?? summary.instructionCount;
    number(confirmed, 'confirmedStepStops', 1, 512);
    if (summary.endStopSeq - summary.startStopSeq !== confirmed || !hex(summary.runtimeBase)
      || !hex(summary.entry) || !hex(summary.exit) || !hex(summary.initialFlags)) fail('Recording boundaries or confirmed pause count differ');
    let storeEvents = null;
    if (window.storeEventData !== undefined || source.storeEvents !== undefined) {
      const reference = source.storeEvents;
      if (!(window.storeEventData instanceof Uint8Array) || !reference || reference.bytes !== window.storeEventData.length
        || sha(Buffer.from(window.storeEventData)) !== reference.sha256) fail('Native store-event reference differs');
      storeEvents = readNativeStoreEvents(window.storeEventData, summary, data);
      totalStoreBytes += window.storeEventData.length;
    }
    if (totalBytes + totalStoreBytes > 16 * 1024 * 1024) limit('Combined recording evidence exceeds 16 MiB');
    const rows = data.toString('ascii').slice(0, -1).split('\n');
    const header = rows.shift();
    if (header !== 'h:ig5-native-x64-' + summary.format.slice(-2)) fail('Native recording header differs from its summary version');
    let pending = null, pendingLine = null, flags = null, reads = [], previousRegs = null, group = null, final = null;
    let gs = null, groupCount = 0, instructionCount = 0, firstPc = null, lastPc = null, firstSnapshot = null;
    const finish = (after, afterFlags, afterPc, afterLine) => {
      if (!group) fail('Final observation has no preceding instruction');
      if (visitGroup || (totalGroups >= offset && pages.length < pageSize)) {
        const observed = {
        groupIndex: totalGroups, recordingId: source.reportId, phase: 'unclassified',
        pauseSequence: { before: summary.startStopSeq + groupCount - 1, after: summary.startStopSeq + groupCount,
          source: 'derived-from-recorded-window-order-and-confirmed-step-count', individuallyAttested: false },
        before: group.before, after: snapshot(after, afterFlags, afterPc, afterLine),
        instructions: group.instructions, memoryReads: group.reads,
        intermediateStateAvailable: group.instructions.length === 1,
        memoryWrites: storeEvents ? { status: 'decoded-locations-observed-across-stop', effectsNotInferredFromReads: true,
          ...storeEvents.events[groupCount - 1], storeOrder: storeEvents.storeOrder, cpuWriteFootprintProved: false,
          sourceBlobSha256: source.storeEvents.sha256 } : { status: 'not-recorded-by-this-format', effectsNotInferredFromReads: true },
        };
        if (visitGroup) visitGroup(observed, { gsBaseObservation: gs, source, summary });
        if (totalGroups >= offset && pages.length < pageSize) pages.push(observed);
      }
      totalGroups++; group = null;
    };
    const observeCode = (pc, bytes, line) => {
      const address = hx(pc), key = address + ':' + bytes;
      const prior = code.get(address);
      if (prior !== undefined && prior !== bytes) {
        changedCodeCount++;
        if (changes.length < 64) changes.push({ address, before: prior, after: bytes, recordingId: source.reportId, sourceLine: line,
          interpretation: 'observed-code-bytes-changed', cause: 'unknown-not-a-proved-SMC-write' });
      }
      if (code.has(address) || code.size < 4096) code.set(address, bytes);
      else codeTrackingComplete = false;
      return sha(Buffer.from(key, 'ascii'));
    };
    for (let index = 0; index < rows.length; index++) {
      const line = rows[index], lineNumber = index + 2;
      if (line.length > 1024 || final) fail('Oversized row or records after final snapshot');
      const fields = line.split(':'), kind = fields.shift();
      if (kind === 's' && fields.length === 2 && fields[0] === 'gs' && hex(fields[1]) && gs === null && !pending && !groupCount) gs = hx(BigInt(fields[1]));
      else if ((kind === 'r' || kind === 'd') && !pending && !reads.length) {
        if (kind === 'r') pending = words(fields, 16);
        else {
          if (header !== 'h:ig5-native-x64-v2' || !previousRegs || !hex(fields[0])) fail('Unexpected native delta snapshot');
          const mask = BigInt(fields[0]); if (mask > 0xffffn) fail('Native delta mask exceeds 16 GPRs');
          const changed = words(fields.slice(1), mask.toString(2).replace(/0/g, '').length);
          pending = [...previousRegs]; let cursor = 0;
          for (let bit = 0; bit < 16; bit++) if (mask & (1n << BigInt(bit))) pending[bit] = changed[cursor++];
        }
        pendingLine = lineNumber;
      } else if (kind === 'e' && fields.length === 1 && pending && flags === null && !reads.length && hex(fields[0])) {
        flags = BigInt(fields[0]); if (flags >= 0x100000000n) fail('Native EFLAGS exceeds 32 bits');
      } else if (kind === 'mr' && fields.length === 3 && pending && flags !== null && hex(fields[0])) {
        const size = Number(fields[1]);
        if (!/^(1|2|4|8|16|32|64)$/.test(fields[1]) || !/^0x[0-9a-f]{1,128}$/i.test(fields[2]) || reads.length >= 8) fail('Invalid native memory observation');
        const value = BigInt(fields[2]); if (value >= 1n << BigInt(size * 8)) fail('Memory value exceeds its byte width');
        const raw = value.toString(16).padStart(size * 2, '0').match(/../g).reverse().join('');
        reads.push({ address: hx(BigInt(fields[0])), bytes: size, littleEndianHex: raw, sourceLine: lineNumber,
          meaning: 'observed-memory-read-not-bytecode-or-input-classification' }); totalReads++;
      } else if (kind === 'i' && fields.length === 3 && pending && flags !== null && hex(fields[0])) {
        const size = Number(fields[1]);
        if (!/^(?:[1-9]|1[0-5])$/.test(fields[1]) || !new RegExp('^[0-9a-f]{' + (size * 2) + '}$', 'i').test(fields[2])) fail('Invalid native instruction bytes');
        const pc = BigInt(fields[0]), bytes = fields[2].toLowerCase();
        if (group) finish(pending, flags, pc, pendingLine);
        else if (!firstSnapshot) firstSnapshot = { registers: [...pending], flags, rip: pc };
        const version = observeCode(pc, bytes, lineNumber);
        group = { before: snapshot(pending, flags, pc, pendingLine), reads,
          instructions: [{ pc: hx(pc), bytes, sourceLine: lineNumber, codeObservationSha256: version, beforeStateAvailable: true }] };
        previousRegs = [...pending]; pending = null; flags = null; reads = []; pendingLine = null;
        firstPc ??= hx(pc); lastPc = hx(pc); groupCount++; instructionCount++;
      } else if (kind === 'c' && fields.length === 3 && header === 'h:ig5-native-x64-v2' && !pending && !reads.length && group
        && group.instructions.length === 1 && group.instructions[0].bytes === '0fa2' && hex(fields[0])) {
        const size = Number(fields[1]), pc = BigInt(fields[0]);
        if (!/^[1-7]$/.test(fields[1]) || pc !== BigInt(group.instructions[0].pc) + 2n
          || !new RegExp('^[0-9a-f]{' + (size * 2) + '}$').test(fields[2])) fail('Invalid coalesced continuation bytes');
        group.instructions.push({ pc: hx(pc), bytes: fields[2], sourceLine: lineNumber,
          codeObservationSha256: observeCode(pc, fields[2], lineNumber), beforeStateAvailable: false,
          continuationSemanticsValidated: false, reason: 'No intermediate GPR/flags snapshot was recorded' });
        instructionCount++; lastPc = hx(pc);
      } else if (kind === 'f' && !pending && !reads.length && group) {
        final = words(fields, 18); if (final[17] >= 0x100000000n) fail('Final EFLAGS exceeds 32 bits');
        finish(final.slice(0, 16), final[17], final[16], lineNumber);
      } else fail('Invalid native recording order at line ' + lineNumber);
      if (instructionCount > 1024 || groupCount > 512) limit('Native window exceeds its original recording-step budget');
    }
    if (!final || pending || reads.length || !firstSnapshot || instructionCount !== summary.instructionCount || groupCount !== confirmed
      || firstPc !== hx(BigInt(summary.entry)) || lastPc !== hx(BigInt(summary.exit)) || firstSnapshot.flags !== BigInt(summary.initialFlags))
      fail('Native rows differ from the recording summary or final observation');
    if (previous) {
      if (summary.runId !== previous.summary.runId || summary.threadId !== previous.summary.threadId
        || source.locationFingerprint !== previous.locationFingerprint
        || BigInt(summary.runtimeBase) !== BigInt(previous.summary.runtimeBase) || summary.startStopSeq !== previous.summary.endStopSeq
        || !['instruction-budget', 'recording-deadline', 'recording-evidence-budget'].includes(previous.summary.stopReason) || gs !== previous.gs
        || firstSnapshot.registers.some((value, index) => value !== previous.final[index])
        || firstSnapshot.rip !== previous.final[16] || firstSnapshot.flags !== previous.final[17]) fail('Cross-window run/thread/pause/GPR/flags/RIP continuity differs');
    }
    totalInstructions += instructionCount; if (totalInstructions > maximum) limit('Combined recording instruction budget exceeded');
    windows.push({ ...source, traceSha256: summary.sha256, bytes: data.length, instructionCount, confirmedStopGroups: groupCount,
      startStopSeq: summary.startStopSeq, endStopSeq: summary.endStopSeq, entry: firstPc, lastRecordedInstruction: lastPc,
      observedEndpoint: hx(final[16]), recordedStopReason: summary.stopReason,
      moduleLoadEpoch: null, memoryEpoch: null, phase: 'unclassified', gsBaseObservation: gs });
    previous = { summary, final, gs, locationFingerprint: source.locationFingerprint };
  }
  return { schema: 'ig5-native-observations-v1', targetSha256: request.targetSha256,
    nativeTargetExecutedByThisRequest: false, changesExecutionAuthority: false, liveExecutionInspected: false,
    businessAccepted: false, wholeFunctionCoverageProved: false, architectureProved: false,
    scope: 'Hash-bound recording declarations and ordered observations; no VM phase, ISA, native reachability or business proof',
    identity: { runId: previous.summary.runId, threadId: previous.summary.threadId, runtimeBase: hx(BigInt(previous.summary.runtimeBase)),
      moduleLoadEpoch: null, addressSpaceAttested: false },
    totals: { windows: windows.length, rawBytes: totalBytes,
      ...(totalStoreBytes ? { storeEventBytes: totalStoreBytes, evidenceBytes: totalBytes + totalStoreBytes } : {}),
      instructions: totalInstructions, stopGroups: totalGroups, memoryReads: totalReads },
    pagination: { offset, limit: pageSize, returned: pages.length, nextOffset: offset + pages.length < totalGroups ? offset + pages.length : null,
      entireInputValidated: true, pageIsWholeRecording: offset === 0 && pages.length === totalGroups },
    codeObservations: { trackedAddresses: code.size, trackingComplete: codeTrackingComplete, observedChanges: changedCodeCount,
      changeCountIsLowerBound: !codeTrackingComplete,
      changes, changesPreviewComplete: changedCodeCount === changes.length, globalCodeEpochKnown: false },
    windows, stopGroups: pages,
  };
}
