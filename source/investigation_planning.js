import { capabilityCatalog } from './capability_catalog.js';
import { inspectResearchEvidence } from './evidence_registry.js';
import { planExperiments } from './experiment_planner.js';
import { planningDigest, planningRequestKey } from './planning_identity.js';
import { planningImplementationDigest } from './planning_runtime.js';

const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
export function planningContext({ mgr, cfg, args, execution, context, task, research }) {
  const capabilities = capabilityCatalog(mgr, cfg, { engine: context.engine, ownQueue: true });
  const evidence = research ? inspectResearchEvidence(mgr.analysis.artifacts, task, context, research) : [];
  const keys = [...new Set(task.systemEvidence.filter(e => e.stale && !task.systemEvidence.some(c => !c.stale && c.function.ea === e.function.ea)).map(e => planningRequestKey({ tool: 'ig5_decompile', target: context.target,
    engine: context.engine, ea: e.function.ea, style: 'dossier', task_id: task.taskId }, context, planningImplementationDigest)).filter(Boolean))];
  const current = task.systemEvidence.find(e => !e.stale);
  if (current) keys.push(planningRequestKey({ tool: 'ig5_workspace', target: context.target, engine: context.engine,
    workspace: { action: 'evidence', id: task.taskId, snapshot_id: current.snapshot_id } }, context, planningImplementationDigest));
  // A task has at most 64 snapshots. Reading current evidence and refreshing stale functions cannot require >64 distinct keys.
  const selectedKeys = [...new Set(keys)].slice(0, 64);
  let failures = [], failureHistoryError = null, failureHistory = { scope: 'recent-diagnostics-only', completeHistory: false };
  try {
    const runtime = capabilities.entries.find(c => c.operation === 'function-context' && c.engine === context.engine && c.provider === context.provider)?.runtimeDigest || null;
    if (mgr.failures?.forPlanning) { failureHistory = mgr.failures.forPlanning(context, selectedKeys, runtime); failures = failureHistory.records; }
    else failures = mgr.failures?.recent(context, 3) || [];
  } catch (error) { failureHistoryError = error.code || 'FAILURE_HISTORY_UNAVAILABLE'; }
  const session = mgr.get(args.target), jobs = mgr.analysis?.jobs;
  const resources = {
    static: { state: session.closing ? 'cleanup-pending' : session.pending?.size || session.queuedOperations > 1 ? 'busy' : 'compatible' },
    data: { state: !jobs || typeof jobs.runSettled !== 'function' ? 'unknown' : jobs.active?.retained ? 'cleanup-pending'
      : jobs.closed ? 'unavailable' : jobs.active || jobs.queue.length ? 'busy' : 'compatible', timeoutMs: jobs?.timeoutMs ?? null },
  };
  let sharedBudget = { status: 'unavailable', active: false, remaining: null };
  try { sharedBudget = mgr.coordination?.planningBudget?.(execution?.agent) || sharedBudget; }
  catch (error) { sharedBudget = { status: 'unavailable', active: false, remaining: null, code: error.code || 'BUDGET_UNAVAILABLE' }; }
  const budgets = { publicToolCalls: sharedBudget.active ? Math.min(3, sharedBudget.remaining) : sharedBudget.code ? 0 : 3, inputBytes: 8 * 1024 ** 2 };
  return { context, task, research, evidence, capabilities, resources, failures, failureHistoryError, budgets, implementationDigest: planningImplementationDigest,
    history: { scope: failureHistory.scope, keysSearched: failureHistory.keysSearched ?? 0, metadataScanned: failureHistory.metadataScanned ?? 0,
      legacyRecordsPresent: failureHistory.legacyRecordsPresent ?? null, completeHistory: false }, sharedBudget };
}
export function makeInvestigationPlan(input) {
  return { ...planExperiments(input), failureHistory: input.history, sharedBudget: input.sharedBudget,
    budgetAuthority: 'Planning hint only; original dispatcher rechecks and charges all calls.' };
}
/** Bounded optimistic read; no engine calls, execution, state saves or budget transactions. */
export function investigationPlan({ read, maxBytes = 12288 }) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 4096 || maxBytes > 32768) fail('INVALID_ARGUMENT', 'plan max_bytes must be 4096..32768');
  const stamp = data => planningDigest({ context: data.context, taskRevision: data.task.taskRevision, researchRevision: data.research?.researchRevision ?? null,
    verification: data.research?.verification || null, evidence: data.evidence, capabilities: data.capabilities, resources: data.resources,
    failures: data.failures.map(f => ({ semanticKey: f.semanticKey, planningKey: f.planningKey || null, ref: f.reportRef || null, observedAt: f.observedAt })),
    failureHistoryError: data.failureHistoryError, budget: data.sharedBudget });
  for (let attempt = 0; attempt < 2; attempt++) {
    const before = read(), result = makeInvestigationPlan(before), after = read();
    if (stamp(before) !== stamp(after)) continue;
    result.fullRef = { tool: 'ig5_workspace', target: before.context.target, engine: before.context.engine, workspace: { action: 'plan', id: before.task.taskId, max_bytes: 32768 } };
    result.complete = result.omittedDeferred === 0;
    let omittedCandidates = 0;
    while (Buffer.byteLength(JSON.stringify(result)) > maxBytes && result.candidates.length) { result.candidates.pop(); omittedCandidates++; result.omittedCandidates = omittedCandidates; }
    if (omittedCandidates) result.complete = false;
    result.budget.plannedPublicToolCalls = result.candidates.reduce((sum, c) => sum + c.estimatedCost.publicToolCalls, 0);
    result.budget.plannedInputBytes = result.candidates.reduce((sum, c) => sum + c.estimatedCost.inputBytes, 0);
    if (Buffer.byteLength(JSON.stringify(result)) > maxBytes) fail('PLAN_BUDGET_TOO_SMALL', 'Increase plan max_bytes to preserve mandatory context');
    return result;
  }
  fail('SNAPSHOT_INCONSISTENT', 'Planning state changed during both bounded reads');
}
