// Synthetic bytes/observations for format tests; this module executes no target.
import { observationHash as hash, observationTarget } from './vm_observation_cases.mjs';
export function storeEventCase() {
  const regs = ['0x1122334455667788', ...Array(15).fill('0x0')]; regs[7] = '0x8000';
  const last = [...regs]; last[7] = '0x8008';
  const traceData = ['h:ig5-native-x64-v2', 'r:' + regs.join(':'), 'e:0x202', 'i:0x1000:4:48890424',
    'r:' + regs.join(':'), 'e:0x202', 'mr:0x8000:8:0x1122334455667788', 'i:0x1004:1:c3',
    'f:' + last.join(':') + ':0x1122334455667788:0x202', ''].join('\n');
  const data = Buffer.from(traceData);
  const traceSummary = { format: 'ig5.x86-recording.v2', targetSha256: observationTarget, nativeTargetExecuted: true,
    finalSnapshotIncluded: true, finalSnapshotCurrent: true, runId: '1'.repeat(32), threadId: 7,
    startStopSeq: 1, endStopSeq: 3, instructionCount: 2, confirmedStepStops: 2, runtimeBase: '0x1000', entry: '0x1000', exit: '0x1004',
    initialFlags: '0x202', stopReason: 'returned', bytes: data.length, sha256: hash(data) };
  const event = { schema: 'ig5.native-store-events.v1', runId: traceSummary.runId, threadId: 7, runtimeBase: '0x1000', startStopSeq: 1, endStopSeq: 3,
    traceSha256: hash(data), scope: 'decoded-store-locations-observed-across-native-stop', cpuWriteFootprintProved: false,
    storeOrder: 'decoder-enumeration-not-intermediate-write-order', events: [
      { groupIndex: 0, pc: '0x1000', beforeStopSeq: 1, afterStopSeq: 2, pauseIdentityMatched: true, completeDecodedStoreSet: true,
        actualWriteCausalityProved: false, stores: [{ address: '0x8000', bytes: 8, beforeHex: '0807060504030201', afterHex: '8877665544332211', changed: true, status: 'observed' }] },
      { groupIndex: 1, pc: '0x1004', beforeStopSeq: 2, afterStopSeq: 3, pauseIdentityMatched: true, completeDecodedStoreSet: true,
        actualWriteCausalityProved: false, stores: [] },
    ] };
  const storeEventData = JSON.stringify(event), storeEventSummary = { schema: event.schema, sha256: hash(Buffer.from(storeEventData)), bytes: Buffer.byteLength(storeEventData) };
  const window = { source: { reportId: '11111111-1111-1111-1111-111111111111', reportSha256: 'b'.repeat(64), locationFingerprint: 'c'.repeat(64), image: null,
    storeEvents: { sha256: storeEventSummary.sha256, bytes: storeEventSummary.bytes, groups: 2, completeDecodedStoreGroups: 2 } },
  summary: traceSummary, data, storeEventData: Buffer.from(storeEventData) };
  return { event, window, native: { recording: true, nativeStepsPerformed: 2, traceData, traceSummary, storeEventData, storeEventSummary } };
}
