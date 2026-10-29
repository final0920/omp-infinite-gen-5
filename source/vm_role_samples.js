import { analyzeVmObservations } from './vm_observations.js';
const key = group => group.instructions[0].pc + ':' + group.instructions[0].bytes;
const interesting = group => group.memoryReads.length || /^(c3|c2[0-9a-f]{4}|(?:4[0-9a-f])?ff[0-9a-f]+)$/.test(group.instructions[0].bytes);
/** Two full validations, bounded site table, deterministic first/last observations.
 * Selection is deliberately independent of known VM addresses or handler answers.
 */
export function selectVmRoleSamples(request) {
  const sites = new Map(); let overflow = false;
  const observation = analyzeVmObservations({ ...request, offset: 0, limit: 1 }, group => {
    if (!interesting(group)) return;
    const id = key(group); let site = sites.get(id);
    if (!site && sites.size < 4096) sites.set(id, site = { pc: group.instructions[0].pc, bytes: group.instructions[0].bytes, count: 0, smallReads: 0 });
    if (!site) { overflow = true; return; }
    site.count++; if (group.memoryReads.some(read => read.bytes <= 2)) site.smallReads++;
  });
  const chosen = [...sites].sort((a, b) => Number(!!b[1].smallReads) - Number(!!a[1].smallReads) || b[1].count - a[1].count || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)).slice(0, 128);
  const selected = new Map(chosen.map(([id, site]) => [id, { ...site, groups: [] }]));
  analyzeVmObservations({ ...request, offset: 0, limit: 1 }, (group, context) => {
    const site = selected.get(key(group)); if (!site) return;
    const sample = { ...group, gsBaseObservation: context.gsBaseObservation };
    if (site.groups.length < 8) site.groups.push(sample);
    else { site.groups.splice(4, 1); site.groups.push(sample); }
  });
  const { stopGroups, pagination, ...summary } = observation;
  const result = { schema: 'ig5-vm-role-samples-v1', observation: summary,
    sampling: { strategy: 'small-read-sites-first-then-frequency-first4-last4', trackedSites: sites.size,
      trackingComplete: !overflow, countsAreLowerBounds: overflow, selectedSites: selected.size,
      omittedTrackedSites: sites.size - selected.size, samples: [...selected.values()].reduce((n, site) => n + site.groups.length, 0),
      allInputWindowsValidated: true, samplesAreWholeRecording: false }, sites: [...selected.values()] };
  if (Buffer.byteLength(JSON.stringify(result)) > 4 * 1024 ** 2) throw Object.assign(new Error('VM role samples exceed 4 MiB'), { code: 'VM_OBSERVATION_LIMIT' });
  return result;
}
