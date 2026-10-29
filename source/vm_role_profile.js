import path from 'node:path';
import { loadObservationWindows, observationProfileSchema } from './vm_observation_profile.js';
import { LiftJobs } from './lift_jobs.js';
import { runObservedDecode } from './observed_decode_jobs.js';
import { analyzeVmAddressRoles } from './vm_address_roles.js';
export const roleProfileSchema = { ...observationProfileSchema,
  properties: Object.fromEntries(Object.entries(observationProfileSchema.properties).filter(([key]) => !['offset','limit'].includes(key))) };
export async function runVmRoleProfile(mgr, cfg, input) {
  const controller = new AbortController(), source = mgr.scope?.getStore()?.signal;
  const cancel = () => controller.abort();
  if (source?.aborted) cancel(); else source?.addEventListener('abort', cancel, { once: true });
  const timer = setTimeout(cancel, Math.min(cfg?.requestTimeoutMs || 60000, 60000));
  try { return await runRoleProfile(mgr, cfg, input, controller.signal); }
  finally { clearTimeout(timer); source?.removeEventListener('abort', cancel); }
}
async function runRoleProfile(mgr, cfg, input, signal) {
  const check = () => { mgr.checkCancelled(); if (signal.aborted) throw Object.assign(new Error('VM role analysis cancelled or deadline exhausted'), { code: 'ABORT_ERR' }); };
  check();
  if (!input || Object.hasOwn(input, 'offset') || Object.hasOwn(input, 'limit')) throw new Error('recovery.roles samples first/last observations; offset and limit belong to observations');
  const { windows } = await loadObservationWindows(mgr, cfg, input);
  const samples = await mgr.analysis.sampleVmRoles({ targetSha256: input.target_sha256, windows, maxInstructions: input.max_instructions }, signal);
  check();
  if (samples?.schema !== 'ig5-vm-role-samples-v1' || samples.observation?.targetSha256 !== input.target_sha256 || samples.sites?.length > 128
    || samples.sampling?.samples > 1024 || samples.sampling?.allInputWindowsValidated !== true) throw new Error('Invalid VM role sampling result');
  const artifacts = mgr.analysis.artifacts;
  const sampleRecord = artifacts.save({ kind: 'vm-role-samples', action: 'sample', result: samples }, { pretty: true, maxBytes: 4 * 1024 ** 2 });
  mgr.lifter ||= new LiftJobs(cfg);
  const decoded = await runObservedDecode(mgr.lifter, samples.sites, signal);
  check();
  const result = analyzeVmAddressRoles(samples, decoded.result);
  result.evidence = { sampleReport: { path: path.join(artifacts.root, 'records', sampleRecord.id + '.json'), sha256: artifacts.metadata(sampleRecord.id).result.recordSha256 },
    decoderReport: { path: decoded.reportPath, sha256: decoded.reportSha256 }, process: decoded.process };
  const record = artifacts.save({ kind: 'vm-address-roles', action: 'hypothesize', result }, { pretty: true, maxBytes: 4 * 1024 ** 2 });
  return { roles: { schema: result.schema, status: result.status, nativeTargetExecuted: false, databaseModified: false, businessAccepted: false,
    wholeBinaryVerified: false, vmModelProved: false, instructionSemanticsProved: false, changesExecutionAuthority: false,
    counts: result.counts, sampling: result.sampling, streamCandidateCount: result.streamCandidates.length, contextCandidateCount: result.contextCandidates.length,
    phases: 'unclassified', memoryEpoch: null, moduleLoadEpoch: null,
    streamCandidateSites: result.streamCandidates.slice(0, 8).map(c => ({ pc: c.pc, bytes: c.bytes, kind: c.kind, vmRoleProved: false })),
    candidatePreviewComplete: result.streamCandidates.length <= 8, nextObligations: result.nextObligations, scope: result.scope,
    reportId: record.id, reportPath: path.join(artifacts.root, 'records', record.id + '.json'), reportSha256: artifacts.metadata(record.id).result.recordSha256 } };
}
