import path from 'node:path';
import { randomUUID, createHash } from 'node:crypto';
import { readStableFile } from './analysis_artifacts.js';
import { DiagnosticStore } from './diagnostic_store.js';
import { fileURLToPath } from 'node:url';

const hash = value => createHash('sha256').update(value).digest('hex');
const implementationDigest = hash(['function_dossier.js', 'capability_acceptance.js'].map(name => readStableFile(fileURLToPath(new URL(name, import.meta.url)), 1024 * 1024).data).map(b => hash(b)).join(':'));
export function runtimeIdentity(cfg, engine) {
  const runtime = engine === 'reverse' && cfg.reverseProvider !== 'commercial' ? cfg.ghidra : engine === 'reverse' ? cfg.reverseRuntime : cfg[engine];
  try { return runtime?.manifest ? hash(readStableFile(runtime.manifest, 1024 * 1024).data) : null; } catch { return null; }
}

/** Internal fixed validator registry; no public path or caller-issued pass input. */
export class CapabilityAcceptance {
  constructor({ root, artifacts, cfg, startupId = randomUUID() }) {
    this.store = new DiagnosticStore({ root: path.join(root, 'capability-acceptance-v1') });
    this.artifacts = artifacts; this.cfg = cfg; this.startupId = startupId;
  }
  registerDossier(dossier) {
    const sectionNames = ['decompile', 'cfg', 'callers', 'callees', 'stack'];
    if (dossier?.kind !== 'function-dossier' || !/^[a-f0-9]{64}$/.test(dossier.snapshotDigest)
      || !dossier.provenance || !dossier.function?.ea || sectionNames.some(k => !['ok', 'truncated'].includes(dossier.sections?.[k]?.status))) return null;
    const scope = { ...dossier.provenance, functionEa: dossier.function.ea };
    const runtimeDigest = runtimeIdentity(this.cfg, scope.engine);
    const key = hash([dossier.snapshotDigest, runtimeDigest, implementationDigest, this.startupId].join(':'));
    if (this.store.readInvestigationRecords()[key]) return null;
    const result = { schema: 'ig5-capability-acceptance-v1', validator: 'dossier-sections-and-provenance-v1', operation: 'function-context',
      scope, runtimeDigest, implementationDigest, startupId: this.startupId, snapshotDigest: dossier.snapshotDigest,
      verdict: 'pass', method: 'host-validated-dossier-structure',
      properties: ['five-sections-produced', 'same-function-and-database-snapshot'],
      exclusions: ['semantic-correctness', 'function-contract', 'other-functions', 'target-execution'],
      sections: Object.fromEntries(sectionNames.map(k => [k, dossier.sections[k].status])),
      responseTruncated: dossier.responseTruncated === true };
    const report = this.artifacts.save({ kind: 'capability-acceptance', action: 'dossier', result });
    const ref = { id: report.id, sha256: this.artifacts.metadata(report.id).result.recordSha256 };
    this.store.updateInvestigationRecords(rows => {
      if (Object.keys(rows).length >= 1024) throw Object.assign(new Error('Capability acceptance index full; report retained'), { code: 'CAPABILITY_INDEX_FULL' });
      rows[key] = { schema: 'ig5-capability-acceptance-index-v1', ref, operation: result.operation,
        engine: scope.engine, provider: scope.provider, runtimeDigest, implementationDigest, startupId: this.startupId,
        scope, recordedAt: report.createdAt };
    });
    return ref;
  }
  view(operation, engine, provider, runtimeDigest, sessions = []) {
    const rows = Object.values(this.store.readInvestigationRecords());
    if (rows.length > 1024 || rows.some(r => r.schema !== 'ig5-capability-acceptance-index-v1' || !r.ref || !/^[a-f0-9]{64}$/.test(r.ref.sha256))) throw new Error('Invalid capability acceptance index');
    const candidates = rows.filter(r => r.operation === operation && r.engine === engine && r.provider === provider).sort((a, b) => b.recordedAt.localeCompare(a.recordedAt));
    const latest = candidates.find(r => r.runtimeDigest === runtimeDigest && r.implementationDigest === implementationDigest) || candidates[0];
    if (!latest) return { status: 'not-tested' };
    if (this.artifacts.metadata(latest.ref.id).result.recordSha256 !== latest.ref.sha256) throw new Error('Capability acceptance report digest changed');
    const report = this.artifacts.get(latest.ref.id), record = report.result;
    if (report.kind !== 'capability-acceptance' || record.schema !== 'ig5-capability-acceptance-v1' || record.validator !== 'dossier-sections-and-provenance-v1'
      || record.operation !== operation || record.scope.engine !== engine || record.scope.provider !== provider
      || JSON.stringify(record.scope) !== JSON.stringify(latest.scope) || record.runtimeDigest !== latest.runtimeDigest
      || record.implementationDigest !== latest.implementationDigest || record.startupId !== latest.startupId || record.verdict !== 'pass') throw new Error('Capability acceptance binding mismatch');
    const current = runtimeDigest !== null && latest.runtimeDigest === runtimeDigest && latest.implementationDigest === implementationDigest
      && latest.startupId === this.startupId && sessions.some(s => s.attachmentId === latest.scope.attachmentId && s.dbRevision === latest.scope.dbRevision);
    return { status: current ? 'verified-in-scope' : 'historical', reportRef: latest.ref, scope: record.scope,
      validator: record.validator, properties: record.properties, exclusions: record.exclusions,
      runtimeMatches: runtimeDigest !== null && latest.runtimeDigest === runtimeDigest, implementationMatches: latest.implementationDigest === implementationDigest };
  }
}
