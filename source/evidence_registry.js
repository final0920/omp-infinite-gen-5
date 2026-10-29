import { fixedPropertyEvidence } from './evidence_adapters/fixed_properties.js';
import { dossierEvidence } from './evidence_adapters/dossier.js';
import { vmContextEvidence, evidenceReadBudget } from './evidence_adapters/vm_context.js';
import { planningDigest } from './planning_identity.js';

/** Fixed allowlist. No public registration, filesystem path, or caller assurance. */
export function linkDossierEvidence(artifacts, task, snapshotId) {
  return dossierEvidence(artifacts, task, snapshotId);
}
export function inspectResearchEvidence(artifacts, task, context, state) {
  const checked = new Map(), budget = evidenceReadBudget(), semanticParents = new Map();
  return state.evidenceLinks.map(link => {
    const staleReasons = [];
    if (link.kind === 'function-dossier' && link.context.attachmentId !== context.attachmentId) staleReasons.push('attachment-changed');
    if (link.kind === 'function-dossier' && link.context.dbRevision !== context.dbRevision) staleReasons.push('database-revision-changed');
    if (link.contractRevision !== state.contractRevision) staleReasons.push('contract-changed');
    try {
      const key = link.kind + ':' + link.reportId;
      if (!checked.has(key)) {
        if (checked.size >= 16) return { id: link.id, kind: link.kind, reportId: link.reportId, sha256: link.sha256,
          integrity: 'not-read-budget', stale: staleReasons.length > 0, staleReasons };
        try {
          let value;
          if (link.kind === 'function-dossier') value = dossierEvidence(artifacts, task, link.snapshotId);
          else if(['vm-function-assessment','vm-role-validation'].includes(link.kind)) {
            const loaded=fixedPropertyEvidence(artifacts,task,{id:link.reportId,sha256:link.sha256},budget);
            value={...loaded.link,inputBytes:loaded.inputBytes,candidateInputDigest:planningDigest(loaded.link.propertyScopes)};
          }
          else {
            const loaded = vmContextEvidence(artifacts, task, { id: link.reportId, sha256: link.sha256 }, budget);
            const claim = JSON.parse(Buffer.from(loaded.request.root.bytes)).result;
            const { sourceReports, ...claimContent } = claim;
            const parentDigests = loaded.request.parents.map(parent => {
              if (!semanticParents.has(parent.id)) {
                const record = JSON.parse(Buffer.from(parent.bytes)), { sourceRecurrence, sourceSelection, ...content } = record.result;
                semanticParents.set(parent.id, planningDigest({ kind: record.kind, action: record.action, content }));
              }
              return semanticParents.get(parent.id);
            }).sort();
            value = { ...loaded.link, inputBytes: loaded.request.root.bytes.length + loaded.request.parents.reduce((sum, p) => sum + p.bytes.length, 0),
              candidateInputDigest: planningDigest({ claimContent, parentDigests }) };
          }
          checked.set(key, { value });
        }
        catch (error) { checked.set(key, { error }); }
      }
      const cached = checked.get(key);
      if (cached.error) throw cached.error;
      const verified = cached.value;
      if (verified.reportId !== link.reportId || verified.sha256 !== link.sha256) throw Object.assign(new Error('Link differs'), { code: 'ARTIFACT_CHANGED' });
      if (['vm-context-model','vm-function-assessment','vm-role-validation'].includes(link.kind) && JSON.stringify(verified.parents) !== JSON.stringify(link.parents)) throw Object.assign(new Error('VM parent closure differs'), { code: 'ARTIFACT_CHANGED' });
      if(link.propertyScopes&&planningDigest(verified.propertyScopes)!==planningDigest(link.propertyScopes))throw Object.assign(new Error('Typed scope differs'),{code:'ARTIFACT_CHANGED'});
      return { id: link.id, kind: link.kind, reportId: link.reportId, sha256: link.sha256, integrity: 'verified', stale: staleReasons.length > 0, staleReasons,
        ...(verified.inputBytes !== undefined ? { inputBytes: verified.inputBytes, candidateInputDigest: verified.candidateInputDigest } : {}) };
    } catch (error) {
      return { id: link.id, kind: link.kind, reportId: link.reportId, sha256: link.sha256, integrity: 'unverified', failureCode: error.code || 'EVIDENCE_READ_FAILED', stale: staleReasons.length > 0, staleReasons };
    }
  });
}
