import { createHash } from 'node:crypto';
const hash = value => createHash('sha256').update(value).digest('hex');
const fail = message => { throw Object.assign(new Error(message), { code: 'INVALID_VM_OBSERVATION' }); };
const hex = value => typeof value === 'string' && /^0x[0-9a-f]{1,16}$/i.test(value);
const sameHex = (a, b) => hex(a) && hex(b) && BigInt(a) === BigInt(b);

/** Bind the optional sidecar to its complete raw trace. No CPU/write proof. */
export function readNativeStoreEvents(data, summary, trace) {
  if (!(data instanceof Uint8Array) || data.length < 1 || data.length + trace.length > 1024 * 1024) fail('Combined trace/store-event input exceeds 1 MiB');
  const raw = Buffer.from(data);
  if (raw.some(value => value > 127)) fail('Native store-event JSON must be ASCII');
  const result = JSON.parse(raw.toString('ascii'));
  const fields = (value, names) => value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name));
  if (raw.toString('ascii') !== JSON.stringify(result) || !fields(result,
    ['schema', 'runId', 'threadId', 'runtimeBase', 'startStopSeq', 'endStopSeq', 'traceSha256', 'scope', 'cpuWriteFootprintProved', 'storeOrder', 'events']))
    fail('Native store-event JSON fields/encoding differ');
  if (result?.schema !== 'ig5.native-store-events.v1' || result.runId !== summary.runId || result.threadId !== summary.threadId
    || !sameHex(result.runtimeBase, summary.runtimeBase) || result.startStopSeq !== summary.startStopSeq || result.endStopSeq !== summary.endStopSeq
    || result.traceSha256 !== summary.sha256 || result.traceSha256 !== hash(Buffer.from(trace))
    || result.scope !== 'decoded-store-locations-observed-across-native-stop' || result.cpuWriteFootprintProved !== false
    || result.storeOrder !== 'decoder-enumeration-not-intermediate-write-order' || !Array.isArray(result.events)) fail('Native store-event identity/scope differs');
  const groups = Buffer.from(trace).toString('ascii').split('\n').filter(row => row.startsWith('i:'));
  if (groups.length !== (summary.confirmedStepStops ?? summary.instructionCount) || result.events.length !== groups.length
    || groups.length < 1 || groups.length > 512) fail('Native store-event count differs from confirmed groups');
  for (let index = 0; index < result.events.length; index++) {
    const event = result.events[index];
    if (!fields(event, ['groupIndex', 'pc', 'beforeStopSeq', 'afterStopSeq', 'pauseIdentityMatched', 'completeDecodedStoreSet', 'actualWriteCausalityProved', 'stores'])
      || event.groupIndex !== index || !sameHex(event.pc, groups[index].split(':')[1])
      || event.beforeStopSeq !== summary.startStopSeq + index || event.afterStopSeq !== event.beforeStopSeq + 1
      || typeof event.pauseIdentityMatched !== 'boolean' || typeof event.completeDecodedStoreSet !== 'boolean'
      || event.actualWriteCausalityProved !== false || !Array.isArray(event.stores) || event.stores.length > 32) fail('Native store-event group differs');
    let bytes = 0;
    for (const store of event.stores) {
      if (!fields(store, ['address', 'bytes', 'beforeHex', 'afterHex', 'changed', 'status']) || !hex(store.address) || !Number.isSafeInteger(store.bytes) || store.bytes < 1 || store.bytes > 256
        || BigInt(store.address) + BigInt(store.bytes) > 1n << 64n) fail('Native store-event location exceeds its budget');
      bytes += store.bytes;
      const validBytes = value => typeof value === 'string' && new RegExp('^[a-f0-9]{' + store.bytes * 2 + '}$').test(value);
      if (!validBytes(store.beforeHex) || !['observed', 'deadline', 'unavailable', 'pause-changed'].includes(store.status)
        || (store.status === 'observed' ? !validBytes(store.afterHex) || store.changed !== (store.beforeHex !== store.afterHex)
          : store.afterHex !== null || store.changed !== null)
        || (!event.pauseIdentityMatched && store.status !== 'pause-changed')) fail('Native store-event byte observation differs');
    }
    if (bytes > 256 || event.completeDecodedStoreSet !== (event.pauseIdentityMatched && event.stores.every(store => store.status === 'observed')))
      fail('Native store-event completeness differs');
  }
  return result;
}
