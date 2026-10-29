import { createHash } from 'node:crypto';
import { makeInvestigationPlan } from './investigation_planning.js';

const identityKeys = ['projectId', 'artifactId', 'sha256', 'engine', 'provider', 'attachmentId', 'dbRevision'];
const identity = scope => Object.fromEntries(identityKeys.map(key => [key, scope[key]]));
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };

/** Bounded optimistic snapshot, under the existing static queue. No engine calls. */
export function investigationBrief({ readTask, readContext, readEvidence, readResearch = () => null, readPlanning = null, capabilities, failures = [], failureHistoryError = null, maxBytes = 12288, cursor = null }) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 4096 || maxBytes > 32768) fail('INVALID_ARGUMENT', 'brief max_bytes must be 4096..32768');
  for (let attempt = 0; attempt < 2; attempt++) {
    const scope = readContext(), task = readTask(scope), research = readResearch(task, scope);
    const planning = readPlanning ? readPlanning(task, scope, research) : null;
    const plan = planning ? makeInvestigationPlan(planning) : null;
    const snapshot = { taskRevision: task.taskRevision, researchRevision: research?.researchRevision ?? null, ...identity(scope) };
    if (plan) snapshot.planningDigest = digest(plan);
    if (research?.verification) snapshot.verificationDigest = digest(research.verification);
    const stamp = digest({ taskId: task.taskId, ...snapshot });
    const textLimit = maxBytes < 8192 ? 128 : 512;
    let offset = 0;
    if (cursor !== null) {
      if (typeof cursor !== 'string' || !/^[a-f0-9]{64}:\d{1,2}$/.test(cursor)) fail('INVALID_ARGUMENT', 'Invalid brief cursor');
      const [version, position] = cursor.split(':');
      if (version !== stamp) fail('STALE_SESSION_CONTEXT', 'Brief changed; read the first page again');
      offset = Number(position);
      if (offset > task.systemEvidence.length) fail('INVALID_ARGUMENT', 'Brief cursor is outside this task');
    }
    const brief = { schema: 'ig5-investigation-brief-v1', taskId: task.taskId, snapshot,
      question: task.goal.slice(0, textLimit), workStatus: task.status,
      acceptance: { status: research?.acceptanceStatus || 'not-assessed', contractRef: research?.contractDigest || null }, resourceStatus: research?.resourceStatus || 'unknown',
      claims: { origin: 'caller-statement', hypothesis: task.hypothesis.slice(0, textLimit), conclusion: task.conclusion.slice(0, textLimit), next_step: task.next_step.slice(0, textLimit) },
      observations: [], staleEvidence: [], unknowns: ['Caller statements and completed work status are not acceptance.', research?.verification ? 'A verifier closes only an explicitly named evidence-bound property; function and business acceptance remain unresolved.' : research ? 'Research proposals are caller statements; no verified assessment is linked.' : 'Research sidecar and acceptance verifier are not connected.'],
      recentFailures: failures.slice(0, 3).map(f => ({ operation: f.operation, failureCode: f.failureCode, failedStage: f.failedStage,
        semanticKey: f.semanticKey, original: f.original, advice: f.advice,
        reportRef: f.reportRef || null, originalMessageRef: f.originalMessageRef || null, originalReceiptRef: f.originalReceiptRef || null,
        historical: f.historical === true, staleReasons: f.staleReasons || [] })),
      failureHistoryScope: 'persistent-source-bound-history',
      failureHistoryStatus: failureHistoryError ? 'unavailable' : 'read', failureHistoryError,
      capabilities: capabilities.entries.filter(c => c.engine === scope.engine || ['read-recording', 'restore-history'].includes(c.operation))
        .map(c => ({ operation: c.operation, provider: c.provider, files: c.files, startup: c.startup, functionalEvidence: c.functionalEvidence,
          ...(c.acceptance?.reportRef ? { acceptanceRef: c.acceptance.reportRef, acceptanceScope: c.acceptance.scope, acceptedProperties: c.acceptance.properties } : {}), policy: c.policy, session: c.session })),
      nextExperiments: [], evidenceRefs: [], totalEvidence: task.systemEvidence.length, pageOffset: offset,
      omitted: [], complete: true, nextCursor: null,
      taskRef: { tool: 'ig5_workspace', target: scope.target, engine: scope.engine, workspace: { action: 'get', id: task.taskId } },
    };
    if (research) {
      brief.research = { stale: research.stale, staleReasons: research.staleReasons,
        contractDigest: research.contractDigest, contractRevision: research.contractRevision,
        hypotheses: research.hypotheses.slice(-1).map(h => ({ id: h.id, proposition: h.value.proposition.slice(0, 128) })),
        counts: { hypotheses: research.hypotheses.length, obligations: research.obligations.length, experiments: research.experiments.length, evidenceLinks: research.evidenceLinks.length },
        fullRef: { action: 'research-get', id: task.taskId } };
      brief.omitted.push({ field: 'research', reason: 'bounded-preview', fullRef: 'research.fullRef' });
      if (research.stale) brief.unknowns.push('Research context changed; review the current task and evidence before acknowledging it.');
      if (research.verification) brief.research.verification = {
        closedInScope: research.objectStates.obligations.filter(o => o.status === 'closed-in-scope').length,
        complete: research.verification.complete, omittedOlder: research.verification.omittedOlder,
      };
    }
    for (const [key, value] of Object.entries({ goal: task.goal, hypothesis: task.hypothesis, conclusion: task.conclusion, next_step: task.next_step })) {
      if (value.length > textLimit) brief.omitted.push({ field: key, reason: 'caller-text-preview', fullRef: 'taskRef' });
    }
    // Failure receipts remain available on the original thrown error; bound the preview.
    for (const f of brief.recentFailures) if (f.original.message.length > 256) {
      f.original = { ...f.original, message: f.original.message.slice(0, 256), messageTruncated: true };
      brief.omitted.push({ field: 'failure-message', reason: 'preview', fullRef: 'original-tool-error' });
    }
    const stale = task.systemEvidence.find(e => e.stale && !task.systemEvidence.some(current => !current.stale && current.function.ea === e.function.ea));
    if(failureHistoryError)brief.unknowns.push('Failure history could not be verified; an empty list does not mean there were no failures.');
    if (stale) brief.nextExperiments.push({ kind: 'refresh-stale-dossier', rationale: 'Old attachment or database revision cannot support current observations.',
      request: { tool: 'ig5_decompile', target: scope.target, engine: scope.engine, ea: stale.function.ea, style: 'dossier', task_id: task.taskId } });
    const first = task.systemEvidence.find(e => !e.stale);
    if (first) brief.nextExperiments.push({ kind: 'read-complete-evidence', rationale: 'Inspect section scope, unknowns and limitations before accepting an explanation.',
      request: { tool: 'ig5_workspace', target: scope.target, engine: scope.engine, workspace: { action: 'evidence', id: task.taskId, snapshot_id: first.snapshot_id } } });
    if (!task.systemEvidence.length) brief.unknowns.push('No system dossier evidence; select a function using existing static tools.');
    brief.historyNavigation = { reason: 'Only retrieve a named missing premise; history remains unverified data.',
      fullRef: { action: 'resume', id: task.taskId }, revalidateCurrentIdentity: true };
    if (failures[0]) brief.nextExperiments.push({ kind: 'diagnose-failure', rationale: failures[0].advice.nextCheck, executionAuthorized: false });
    if (plan) {
      brief.nextExperiments = plan.candidates.map(candidate => ({ kind: candidate.kind, rationale: candidate.rationale.slice(0, 160),
        request: candidate.request, executionAuthorized: false }));
      brief.planning = { schema: plan.schema, deferredCount: plan.deferredCount,
        fullRef: { action: 'plan', id: task.taskId } };
    }
    let omittedExperiments = 0;
    while (plan && Buffer.byteLength(JSON.stringify(brief)) > maxBytes - 1200 && brief.nextExperiments.length) { brief.nextExperiments.pop(); omittedExperiments++; }
    if (omittedExperiments) brief.omitted.push({ field: 'nextExperiments', count: omittedExperiments, reason: 'brief-preview-budget', fullRef: 'planning.fullRef' });
    let index = offset;
    // Leave space for omission/cursor metadata; never drop a row without pagination.
    for (; index < task.systemEvidence.length; index++) {
      const entry = task.systemEvidence[index];
      const ref = { snapshotId: entry.snapshot_id, reportId: entry.report_id, sha256: entry.report_sha256, function: entry.function,
        stale: entry.stale, staleReasons: entry.staleReasons, sectionStatus: 'not-read',
        request: { action: 'evidence', id: task.taskId, snapshot_id: entry.snapshot_id } };
      try {
        const report = readEvidence(entry);
        ref.sectionStatus = Object.fromEntries(Object.entries(report.sections).map(([key, value]) => [key, value.status]));
        ref.responseTruncated = report.responseTruncated === true;
        ref.analysis = report.analysis;
        ref.reportIntegrity = 'verified';
      } catch (error) {
        ref.reportIntegrity = 'unverified'; ref.failureCode = error.code || 'EVIDENCE_READ_FAILED';
      }
      // Analysis metadata may be large; full report is the authoritative source.
      delete ref.analysis;
      brief.evidenceRefs.push(ref);
      if (Buffer.byteLength(JSON.stringify(brief)) > maxBytes - 512) { brief.evidenceRefs.pop(); break; }
    }
    brief.observations = brief.evidenceRefs.filter(e => !e.stale && e.reportIntegrity === 'verified').map(e => ({ snapshotId: e.snapshotId, meaning: 'system dossier captured; inspect full report', acceptanceVerified: false }));
    brief.staleEvidence = brief.evidenceRefs.filter(e => e.stale).map(e => ({ snapshotId: e.snapshotId, reasons: e.staleReasons }));
    // Derived duplicate summaries also count against the response budget.
    while (Buffer.byteLength(JSON.stringify(brief)) > maxBytes - 512 && brief.evidenceRefs.length) {
      brief.evidenceRefs.pop(); index--;
      brief.observations = brief.evidenceRefs.filter(e => !e.stale && e.reportIntegrity === 'verified').map(e => ({ snapshotId: e.snapshotId, meaning: 'system dossier captured; inspect full report', acceptanceVerified: false }));
      brief.staleEvidence = brief.evidenceRefs.filter(e => e.stale).map(e => ({ snapshotId: e.snapshotId, reasons: e.staleReasons }));
    }
    if (index < task.systemEvidence.length) {
      if (index === offset) fail('BRIEF_BUDGET_TOO_SMALL', 'Increase brief max_bytes to fit the mandatory scope and one evidence reference');
      brief.nextCursor = `${stamp}:${index}`;
      brief.omitted.push({ field: 'evidenceRefs', remaining: task.systemEvidence.length - index, reason: 'page-budget' });
    }
    brief.complete = brief.omitted.length === 0;
    const endScope = readContext(), endTask = readTask(endScope), endResearch = readResearch(endTask, endScope);
    const endPlan = readPlanning ? makeInvestigationPlan(readPlanning(endTask, endScope, endResearch)) : null;
    if (digest(plan) !== digest(endPlan)) continue;
    if (task.taskRevision !== endTask.taskRevision || (research?.researchRevision ?? null) !== (endResearch?.researchRevision ?? null)
      || digest(research?.verification || null) !== digest(endResearch?.verification || null)
      || JSON.stringify(identity(scope)) !== JSON.stringify(identity(endScope))) continue;
    if (Buffer.byteLength(JSON.stringify(brief)) > maxBytes) fail('BRIEF_BUDGET_TOO_SMALL', 'Increase brief max_bytes to preserve mandatory context');
    return brief;
  }
  fail('SNAPSHOT_INCONSISTENT', 'Task or database context changed during both brief reads; read current context and retry');
}
