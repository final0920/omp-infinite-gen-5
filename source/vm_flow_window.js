import { analyzeVmObservations } from './vm_observations.js';
/** Retain a contiguous prefix starting at the exact recorded candidate stop.
 * All supplied windows are still validated, including rows beyond this prefix.
 */
export function selectVmFlowWindow(request) {
  const seed = request.seed;
  if (!seed || !Number.isSafeInteger(seed.groupIndex) || seed.groupIndex < 0 || seed.groupIndex > 100000
    || typeof seed.recordingId !== 'string' || !/^0x[0-9a-f]{1,16}$/.test(seed.pc || '')
    || !/^(?:[0-9a-f]{2}){1,15}$/.test(seed.bytes || '')) throw new Error('Invalid recorded flow seed');
  const groups = [], sites = new Set(); let stoppedFor = null;
  const observation = analyzeVmObservations({ ...request, offset: 0, limit: 1 }, (group, context) => {
    if (group.groupIndex < seed.groupIndex || stoppedFor) return;
    if (!groups.length && (group.recordingId !== seed.recordingId || group.instructions[0].pc !== seed.pc || group.instructions[0].bytes !== seed.bytes))
      throw new Error('Recorded flow seed differs from the exact source stop');
    if (groups.length === 128) { stoppedFor = 'stop-group-budget'; return; }
    const next = new Set([...sites, ...group.instructions.map(i => i.pc + ':' + i.bytes)]);
    if (next.size > 128) { stoppedFor = 'distinct-byte-site-budget'; return; }
    for (const key of next) sites.add(key);
    groups.push({ ...group, gsBaseObservation: context.gsBaseObservation });
  });
  if (!groups.length) throw new Error('Recorded flow seed is outside the supplied recording');
  const { stopGroups, pagination, ...source } = observation;
  const result = { schema: 'ig5-recorded-flow-window-v1', source, seed, groups,
    stoppedFor: stoppedFor || 'supplied-recording-end', distinctByteSites: sites.size,
    allInputWindowsValidated: true, nativeTargetExecuted: false, businessAccepted: false, vmRoleProved: false };
  if (Buffer.byteLength(JSON.stringify(result)) > 4 * 1024 ** 2) throw new Error('Recorded flow window exceeds 4 MiB');
  return result;
}
