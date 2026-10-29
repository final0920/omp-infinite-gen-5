import { planningDigest } from './planning_identity.js';

const identityKeys = ['projectId', 'artifactId', 'sha256', 'engine', 'provider', 'attachmentId', 'dbRevision'];
const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(value);
const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };

/** Navigation over current task-owned identifiers only; no history text or model instructions. */
export function resumeNavigation({ context, task, research = null, failures = [] }) {
  if (!context || !task || !Array.isArray(task.systemEvidence) || task.systemEvidence.length > 64 || failures.length > 67) fail('INVALID_ARGUMENT', 'Bounded recovery state required');
  if (task.scope && identityKeys.slice(0, 5).some(k => task.scope[k] !== context[k])
    || research && (research.taskId !== task.taskId || identityKeys.slice(0, 5).some(k => research.scope[k] !== context[k]))) fail('INVESTIGATION_IDENTITY_MISMATCH', 'Recovery references must belong to this target and task');
  const gaps = [], seen = new Set();
  const add = (kind, id, currentRead, reason) => {
    if (!uuid(id) || seen.has(id)) return;
    seen.add(id);
    gaps.push({ kind, sourceId: id, reason,
      search: { tool: 'ig5_profile', memory: { action: 'search', query: `"${id}"`, limit: 3 } },
      currentRead: currentRead ? { tool: 'ig5_workspace', target: context.target, engine: context.engine, workspace: { id: task.taskId, ...currentRead } } : null });
  };
  for (const result of research?.verification?.checked || []) {
    if (result.integrity === 'verified' && ['fail', 'unknown', 'unsupported', 'error'].includes(result.status)) {
      add('verifier-feedback', result.reportId, { action: 'research-verification', verification_id: result.reportId }, 'Recover the full result, witness, conditions and limitations before proposing another experiment.');
    }
  }
  const failedInputs = new Set();
  for (const failure of failures.slice(0, 3)) {
    // Schema mistakes already explained by the brief are not missing historical premises.
    if (failure.advice?.category === 'usage' || failure.historical) continue;
    const key = failure.semanticKey || `${failure.operation}:${failure.failureCode}`;
    if (failedInputs.has(key)) continue;
    failedInputs.add(key);
    add('failure-premises', failure.reportRef?.id, null, 'Recover the original failure and owner receipt; a new session never restores execution ownership.');
  }
  for (const item of research?.obligations || []) {
    const state = research.objectStates?.obligations?.find(s => s.id === item.id);
    if (state?.status !== 'open' || state.staleContract) continue;
    const evidenceId = item.value.scope.startsWith('evidence:') ? item.value.scope.slice(9) : null;
    const link = research.evidenceLinks.find(e => e.id === evidenceId);
    add('open-obligation', link?.reportId || item.id, { action: 'research-get' }, 'Recover the missing premise and its counterexamples; caller proposals are not verified facts.');
  }
  for (const item of task.systemEvidence) if (item.stale) {
    add('stale-evidence', item.report_id, { action: 'evidence', snapshot_id: item.snapshot_id }, 'Recover the exact historical source, then recheck its mapping and current revision; old evidence remains stale.');
  }
  if (!task.systemEvidence.length && !gaps.length) add('missing-observation', task.taskId, { action: 'get' }, 'Locate prior constraints and observations only if the current brief lacks a required premise.');
  return { schema: 'ig5-investigation-resume-v1', taskId: task.taskId,
    snapshot: { taskRevision: task.taskRevision, researchRevision: research?.researchRevision ?? null,
      ...Object.fromEntries(identityKeys.map(k => [k, context[k]])) },
    gaps: gaps.slice(0, 3), totalGaps: gaps.length, omittedGaps: Math.max(0, gaps.length - 3),
    sequence: ['Read current brief', 'Search only a named missing premise', 'Read complete hash-bound events; expand summary sources recursively', 'Revalidate current identity and original resource ownership', 'Continue through original tools'],
    revalidate: ['artifact SHA', 'attachment and database revision', 'task and research revision', 'run/thread/stop or epoch if execution is involved', 'original resource owner and cleanup receipt'],
    checkpointAdvice: { origin: 'caller-unverified', fields: ['failed attempt and exact inputs', 'counterexample and path conditions', 'unresolved obligations', 'source references and scope'], automaticSave: false },
    historyScope: 'executing DSH session + workspace only; absent hits do not prove absence',
    executionAuthorized: false, semanticVerified: false, taskModified: false };
}

export function investigationResume({ read, maxBytes = 12288 }) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 4096 || maxBytes > 32768) fail('INVALID_ARGUMENT', 'resume max_bytes must be 4096..32768');
  const stamp = state => planningDigest({ context: state.context, task: state.task, research: state.research,
    failures: state.failures, failureHistoryError: state.failureHistoryError });
  for (let attempt = 0; attempt < 2; attempt++) {
    const before = read(), result = resumeNavigation(before), after = read();
    if (stamp(before) !== stamp(after)) continue;
    result.failureHistoryStatus = before.failureHistoryError ? 'unavailable' : 'bounded';
    if (Buffer.byteLength(JSON.stringify(result)) > maxBytes) fail('RESUME_BUDGET_TOO_SMALL', 'Increase resume max_bytes to preserve current scope and navigation');
    return result;
  }
  fail('SNAPSHOT_INCONSISTENT', 'Recovery state changed during both bounded reads');
}
