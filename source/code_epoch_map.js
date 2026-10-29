import { createHash } from 'node:crypto';

const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const fail = message => { throw Object.assign(new Error(message), { code: 'CODE_VERSION_MISMATCH' }); };

/** Observation-local code identities. Epoch numbers never certify unobserved intervals. */
export function observedCodeVersion(targetSha256, group, instruction, source, summary) {
  const binding = { targetSha256, runId: summary.runId, threadId: summary.threadId,
    runtimeBase: summary.runtimeBase, locationFingerprint: source.locationFingerprint,
    reportId: source.reportId, reportSha256: source.reportSha256, traceSha256: summary.sha256,
    groupIndex: group.groupIndex, beforeStopSeq: group.pauseSequence.before, afterStopSeq: group.pauseSequence.after,
    sourceLine: instruction.sourceLine, pc: instruction.pc, bytes: instruction.bytes,
    beforeStateAvailable: instruction.beforeStateAvailable };
  return { id: hash(binding), binding, contentSha256: createHash('sha256').update(Buffer.from(instruction.bytes, 'hex')).digest('hex'),
    observationOnly: true, validBetweenObservations: false, moduleLoadEpoch: null, globalMemoryEpoch: null };
}

export function requireObservedCodeVersion(actual, expected) {
  if (!actual?.binding || actual.id !== hash(actual.binding) || actual.contentSha256 !== createHash('sha256').update(Buffer.from(actual.binding.bytes, 'hex')).digest('hex')
    || actual.observationOnly !== true || actual.validBetweenObservations !== false || actual.moduleLoadEpoch !== null || actual.globalMemoryEpoch !== null
    || !expected?.binding || expected.id !== hash(expected.binding) || actual.id !== expected.id) fail('Exact observation point and code version required; cross-version or cross-stop composition is not authorized');
  return true;
}

export function createCodeEpochMap() {
  const bytes = new Map(); let epoch = 0, totalChanges = 0, trackingComplete = true;
  // At most one bounded receipt per already tracked byte. Multiple observations
  // remain ambiguous: decoder enumeration does not establish a write order.
  const pending = new Map();
  const stores = { changedObservations: 0, overlappingBytes: 0, ambiguousBytes: 0,
    reobservedBytes: 0, matchingBytes: 0, conflictingBytes: 0 };
  return {
    noteStores(group, source, summary) {
      for (const [storeIndex, store] of (group.memoryWrites.stores || []).entries()) {
        if (store.changed !== true) continue;
        stores.changedObservations++;
        const receipt = { recordingId: source.reportId, reportSha256: source.reportSha256, traceSha256: summary.sha256,
          storeBlobSha256: group.memoryWrites.sourceBlobSha256, groupIndex: group.groupIndex, storeIndex,
          beforeStopSeq: group.pauseSequence.before, afterStopSeq: group.pauseSequence.after };
        for (let offset = 0; offset < store.bytes; offset++) {
          const key = (BigInt(store.address) + BigInt(offset)).toString(16), prior = bytes.get(key);
          if (!prior) continue;
          stores.overlappingBytes++;
          const existing = pending.get(key);
          if (existing) { existing.observationCount++; stores.ambiguousBytes++; continue; }
          pending.set(key, { receipt, byteOffset: offset, before: store.beforeHex.slice(offset * 2, offset * 2 + 2),
            after: store.afterHex.slice(offset * 2, offset * 2 + 2), priorVersionId: prior.versionId, observationCount: 1 });
        }
      }
    },
    overlap(address, size) {
      let observedBytes = 0; const versions = new Set();
      for (let n = 0; n < size; n++) {
        const prior = bytes.get((BigInt(address) + BigInt(n)).toString(16));
        if (prior) { observedBytes++; if (versions.size < 4) versions.add(prior.versionId); }
      }
      return { previouslyObservedCodeBytes: observedBytes, priorVersionIds: [...versions], trackingComplete,
        implication: 'address overlap only; not proof of an instruction-caused code write' };
    },
    observe(version) {
      const { pc, bytes: raw } = version.binding, address = BigInt(pc), changed = [], storeObservations = [];
      if (address + BigInt(raw.length / 2) > 1n << 64n) fail('Code byte observation overflows uint64');
      for (let offset = 0; offset < raw.length / 2; offset++) {
        const key = (address + BigInt(offset)).toString(16), value = raw.slice(offset * 2, offset * 2 + 2), prior = bytes.get(key);
        const observed = pending.get(key);
        if (observed && prior) {
          pending.delete(key); stores.reobservedBytes++;
          const beforeMatches = observed.before === prior.value, afterMatches = observed.after === value;
          stores[beforeMatches && afterMatches ? 'matchingBytes' : 'conflictingBytes']++;
          storeObservations.push({ address: '0x' + key, source: observed.receipt, byteOffset: observed.byteOffset,
            priorCodeVersionId: observed.priorVersionId, nextCodeVersionId: version.id,
            priorCodeByte: prior.value, storeBeforeByte: observed.before, storeAfterByte: observed.after, nextCodeByte: value,
            beforeMatches, afterMatches, observationCount: observed.observationCount, ambiguous: observed.observationCount !== 1,
            scope: 'first-store-snapshot-to-next-code-observation; intervening writes and causes unknown',
            actualWriteCausalityProved: false, intervalStable: 'unknown' });
        }
        if (prior && prior.value !== value) { changed.push({ address: '0x' + key, before: prior.value, after: value, priorVersionId: prior.versionId }); totalChanges++; }
        if (prior || bytes.size < 16384) bytes.set(key, { value, versionId: version.id }); else trackingComplete = false;
      }
      if (changed.length) epoch++;
      return { observationEpoch: epoch, changedBytes: changed, storeObservations, intervalStable: 'unknown', cause: 'unknown', trackingComplete };
    },
    status() { return { trackedBytes: bytes.size, trackingComplete, observedChangedBytes: totalChanges,
      changeCountIsLowerBound: !trackingComplete, observationEpoch: epoch, globalCodeEpochKnown: false, unobservedIntervals: 'unknown',
      storeTimeline: { ...stores, pendingBytes: pending.size, trackingComplete,
        scope: 'changed snapshots overlapping already observed code only', actualWriteCausalityProved: false } }; },
  };
}
