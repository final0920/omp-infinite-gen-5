const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };

export function validateSnapshotReport(snapshot, report) {
  const result = report?.result;
  const keys = ['projectId', 'artifactId', 'sha256', 'engine', 'provider', 'attachmentId', 'dbRevision'];
  if (report?.kind !== 'function-dossier' || report.action !== 'capture' || result?.kind !== 'function-dossier' || result.schemaVersion !== 1 || result.snapshotDigest !== snapshot.digest
    || keys.some(key => report.association?.[key] !== snapshot.context[key] || result.provenance?.[key] !== snapshot.context[key] || result._ig5?.[key] !== snapshot.context[key])
    || result.function?.ea !== snapshot.function.ea
    || JSON.stringify(Object.keys(result.sections || {}).sort()) !== JSON.stringify([...snapshot.sections].sort())) {
    fail('ARTIFACT_CHANGED', 'Stored report does not match the scope and function of this system observation');
  }
  if (snapshot.function.name !== undefined && (snapshot.function.nameTruncated
    ? result.function.name?.slice(0, 256) !== snapshot.function.name : result.function.name !== snapshot.function.name)) {
    fail('ARTIFACT_CHANGED', 'Stored report function name differs from the system observation');
  }
  for (const section of Object.values(result.sections)) {
    if (!section || !['ok', 'truncated', 'unsupported', 'unavailable', 'error'].includes(section.status)) fail('ARTIFACT_CHANGED', 'Unsupported dossier section status');
  }
  return result;
}

/** Membership in the host task is mandatory; UUID/hash alone do not confer assurance. */
export function dossierEvidence(artifacts, task, snapshotId) {
  const snapshot = task.systemEvidence.find(s => s.snapshot_id === snapshotId);
  if (!snapshot) fail('INVALID_RESEARCH_REF', 'Dossier must be a system snapshot belonging to this task');
  if (artifacts.metadata(snapshot.report_id).result.recordSha256 !== snapshot.report_sha256) fail('ARTIFACT_CHANGED', 'Dossier metadata digest differs');
  const { data } = readStableFile(path.join(artifacts.directory('records'), snapshot.report_id + '.json'), 128 * 1024);
  if (hashBytes(data) !== snapshot.report_sha256) fail('ARTIFACT_CHANGED', 'Dossier bytes differ');
  const report = JSON.parse(data);
  if (report.id !== snapshot.report_id || report.schemaVersion !== 1) fail('ARTIFACT_CHANGED', 'Dossier UUID/schema differs');
  validateSnapshotReport(snapshot, report);
  return { kind: 'function-dossier', assurance: 'system-snapshot-integrity', snapshotId,
    reportId: snapshot.report_id, sha256: snapshot.report_sha256,
    context: structuredClone(snapshot.context), function: structuredClone(snapshot.function), sections: [...snapshot.sections],
    supportedProperties: ['dossier-provenance-and-structure'],
    limitations: ['No semantic, execution, VM-role or function-contract acceptance.'] };
}
import path from 'node:path';
import { readStableFile, hashBytes } from '../analysis_artifacts.js';
