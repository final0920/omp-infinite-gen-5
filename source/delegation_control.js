import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { ProjectStore } from './project_store.js';

const fail = (code, message) => { throw Object.assign(new Error(message), { code,
  phase: code.includes('BUDGET') ? 'shared-budget' : 'delegation-control', retryable: false,
  observedAt: new Date().toISOString(), faultStartedAt: null, diagnosticId: randomUUID(),
  recoveryActions: ['Use ig5_doctor operation=session for local metadata; retain the original shared ledger.'] }); };
const same = (a, b) => ['projectId', 'artifactId', 'sha256', 'engine', 'provider', 'attachmentId', 'dbRevision'].every(k => a?.[k] === b?.[k]);
const key = id => createHash('sha256').update(id).digest('hex');
const lineageFailure = (reason, message) => {
  throw Object.assign(new Error(message), { code: 'AGENT_LINEAGE_UNAVAILABLE', reason, phase: 'session-lineage',
    retryable: reason === 'PARENT_SESSION_UNAVAILABLE', observedAt: new Date().toISOString(),
    diagnosticId: randomUUID(), evidenceStatus: 'observed-metadata-only', faultStartedAt: null,
    recoveryActions: ['Call ig5_doctor with operation=session for local session metadata.',
      'Ask the host to restore/index the original session ancestry, then retry. Existing shared usage remains in force.'],
    automaticRecoverySupported: false });
};

function validateState(state, rootId) {
  if (state.schemaVersion !== 1 || state.rootId !== rootId || !state.tickets || typeof state.tickets !== 'object' || Array.isArray(state.tickets)
    || Object.keys(state.tickets).length > 128 || state.budget && (!Number.isSafeInteger(state.budget.limit) || !Number.isSafeInteger(state.budget.used)
      || state.budget.limit < 1 || state.budget.used < 0 || state.budget.used > state.budget.limit || !state.budget.byAgent
      || typeof state.budget.byAgent !== 'object' || Array.isArray(state.budget.byAgent)
      || Object.values(state.budget.byAgent).some(n => !Number.isSafeInteger(n) || n < 0)
      || Object.values(state.budget.byAgent).reduce((a, b) => a + b, 0) !== state.budget.used))
    fail('DELEGATION_STORE_CORRUPT', 'Invalid delegation accounting; refusing controlled dispatch');
}

/** Persistent accounting is separate from task notes and database revisions. */
export class DelegationControl {
  constructor({ root, getAgent = () => undefined }) {
    // Defer ledger opening so a corrupt ledger cannot prevent metadata-only diagnosis.
    let store;
    Object.defineProperty(this, 'store', { get: () => store ||= new ProjectStore({ root: path.join(root, 'delegation-control') }) });
    this.getAgent = getAgent;
    this.agents = new Map();
    this.runs = new Map();
    this.epoch = randomUUID();
  }
  remember(agent) { if (agent?.id && agent.session?.header?.id === agent.id) this.agents.set(agent.id, agent); }
  lineage(agent) {
    this.remember(agent);
    if (!agent?.id || agent.session?.header?.id !== agent.id) lineageFailure('SESSION_IDENTITY_MISMATCH', 'Reliable DSH session identity is required for controlled delegation');
    const ids = [], seen = new Set();
    for (let at = agent; at; ) {
      if (seen.has(at.id)) lineageFailure('SESSION_LINEAGE_CYCLE', 'Invalid cyclic DSH parent lineage');
      if (ids.length >= 32) lineageFailure('SESSION_LINEAGE_LIMIT', 'Excessive DSH parent lineage');
      seen.add(at.id); ids.push(at.id); this.remember(at);
      const parent = at.session.header.parentSession;
      if (parent === undefined || parent === null) return ids;
      if (typeof parent !== 'string' || !parent.trim()) lineageFailure('SESSION_IDENTITY_MISMATCH', 'Invalid DSH parent session identity');
      if (seen.has(parent)) lineageFailure('SESSION_LINEAGE_CYCLE', 'Invalid cyclic DSH parent lineage');
      at = this.getAgent(parent) || this.agents.get(parent);
      if (!at) lineageFailure('PARENT_SESSION_UNAVAILABLE', 'DSH parent session is unavailable; shared budget cannot be bypassed');
      if (at.id !== parent || at.session?.header?.id !== parent) lineageFailure('PARENT_IDENTITY_MISMATCH', 'DSH parent session identity conflicts with the host index');
    }
  }
  transaction(agent, fn) {
    const ids = this.lineage(agent), rootId = ids.at(-1);
    return this.store.updateInvestigationRecords(records => {
      const k = key(rootId);
      const record = records[k] ||= { schemaVersion: 1, rootId, budget: null, tickets: {} };
      validateState(record, rootId);
      return fn(record, ids);
    });
  }
  /** Exact local control-plane operation: no RPC, content, ledger writes or inferred parent ownership. */
  diagnose(agent, args = {}) {
    if (Object.keys(args).some(k => k !== 'operation') || args.operation !== 'session') fail('INVALID_ARGUMENT', 'Use operation=session alone for local session diagnosis');
    const result = { schemaVersion: 1, kind: 'session-diagnostic', diagnosticId: randomUUID(), observedAt: new Date().toISOString(),
      faultStartedAt: null, phase: 'session-lineage', evidenceStatus: 'observed-metadata-only',
      rpcPerformed: false, budgetModified: false, automaticRecoverySupported: false, budget: null };
    try {
      const ids = this.lineage(agent), rootId = ids.at(-1);
      const state = this.store.readInvestigationRecords()[key(rootId)];
      if (state) validateState(state, rootId);
      return { ...result, status: 'available', code: 'SESSION_LINEAGE_AVAILABLE', retryable: false,
        lineageDepth: ids.length, budget: state?.budget ? { active: true, used: state.budget.used, limit: state.budget.limit } : { active: false },
        recoveryActions: [] };
    } catch (error) {
      const code = error.code === 'AGENT_LINEAGE_UNAVAILABLE' ? error.reason
        : ['STORE_CORRUPT', 'STORE_SCHEMA_MISMATCH', 'DELEGATION_STORE_CORRUPT'].includes(error.code) ? 'DELEGATION_STORE_CORRUPT' : 'SESSION_METADATA_UNAVAILABLE';
      return { ...result, status: 'unavailable', code, retryable: code === 'PARENT_SESSION_UNAVAILABLE',
        recoveryActions: error.recoveryActions || ['Inspect the original host session and retained ledger; do not recreate or reset shared accounting.'] };
    }
  }
  budget(agent, input) {
    if (!input || Object.keys(input).some(k => !['action', 'max_calls'].includes(k)) || !['start', 'status'].includes(input.action)) fail('INVALID_ARGUMENT', 'collaboration action must be start or status');
    return this.transaction(agent, (state, ids) => {
      if (input.action === 'start') {
        if (ids.length !== 1) fail('BUDGET_OWNER_REQUIRED', 'Only the root agent may establish the shared IG5 budget');
        if (!Number.isSafeInteger(input.max_calls) || input.max_calls < 1 || input.max_calls > 1000) fail('INVALID_ARGUMENT', 'max_calls must be 1..1000');
        if (state.budget) fail('BUDGET_ALREADY_STARTED', 'Shared budget already exists; it cannot be reset or enlarged by another tool call');
        state.budget = { limit: input.max_calls, used: 0, byAgent: {} };
      } else if (input.max_calls !== undefined) fail('INVALID_ARGUMENT', 'status does not accept max_calls');
      return { rootId: state.rootId, active: !!state.budget, ...(state.budget || {}),
        scope: 'all IG5 tool dispatches across this DSH root and descendants', persistent: true,
        statusExempt: true, note: 'Activation/status are control-plane queries. Failed dispatched calls count; exhausted calls do not run. Non-IG5 tools, tokens and external providers are not counted.' };
    });
  }
  /** Read-only planning hint. Dispatch remains the sole authority that charges the shared budget. */
  planningBudget(agent) {
    if (!agent?.session?.header) return { status: 'unavailable', active: false, remaining: null };
    const ids = this.lineage(agent), rootId = ids.at(-1), state = this.store.readInvestigationRecords()[key(rootId)];
    if (!state) return { status: 'read', active: false, remaining: null };
    validateState(state, rootId);
    return { status: 'read', active: !!state.budget, remaining: state.budget ? state.budget.limit - state.budget.used : null };
  }
  charge(agent, name, args) {
    // Legacy fixture/service callers have no session metadata. They cannot opt
    // into controlled delegation. Real DSH descendants with missing parents fail.
    if (!agent?.session?.header) return;
    if (name === 'ig5_profile' && args.collaboration !== undefined) return;
    this.transaction(agent, state => {
      if (!state.budget) return;
      if (state.budget.used >= state.budget.limit) fail('IG5_SHARED_BUDGET_EXHAUSTED', 'Shared parent/child IG5 call budget exhausted; only collaboration status remains available');
      state.budget.used++;
      state.budget.byAgent[agent.id] = (state.budget.byAgent[agent.id] || 0) + 1;
    });
  }
  handoff(agent, task, scope) {
    return this.transaction(agent, state => {
      if (Object.keys(state.tickets).length >= 128) fail('HANDOFF_LIMIT', 'At most 128 handoffs per root session');
      const handoffId = randomUUID();
      state.tickets[handoffId] = { parentId: agent.id, taskId: task.taskId, taskRevision: task.taskRevision,
        scope, epoch: this.epoch, childId: null, reads: [], submitted: null, terminal: null, runId: null };
      return { handoffId, mode: 'tracked', coordinationModified: true,
        next: 'Child must workspace claim with handoff_id, read complete evidence, then submit snapshot_ids. Parent review with handoff_id waits for the observed completed child run.' };
    });
  }
  ticket(state, id, task, scope) {
    const ticket = state.tickets[id];
    if (!ticket) fail('HANDOFF_NOT_FOUND', 'Choose a tracked handoff from this root');
    if (ticket.epoch !== this.epoch) fail('HANDOFF_RESTARTED', 'Host reloaded; create a new handoff rather than trusting old lifecycle observations');
    if (ticket.taskId !== task.taskId || ticket.taskRevision !== task.taskRevision || !same(ticket.scope, scope)) fail('STALE_HANDOFF', 'Task, database or attachment changed; prepare a new handoff');
    return ticket;
  }
  claim(agent, id, task, scope) {
    return this.transaction(agent, (state, ids) => {
      const ticket = this.ticket(state, id, task, scope);
      if (ids[1] !== ticket.parentId || ticket.childId && ticket.childId !== agent.id) fail('HANDOFF_CHILD_REQUIRED', 'Only one actual direct DSH child of the handing-off agent may claim this packet');
      const run = this.runs.get(agent.id);
      if (!run || run.ended) fail('CHILD_LIFECYCLE_UNAVAILABLE', 'No observed active DSH subagent run; controlled acceptance is unavailable');
      ticket.childId = agent.id; ticket.runId = run.runId;
      return { handoffId: id, taskId: task.taskId, taskRevision: task.taskRevision, childId: agent.id, claimed: true, semanticAcceptanceVerified: false };
    });
  }
  read(agent, snapshot) {
    if (!agent?.session?.header) return;
    this.transaction(agent, state => {
      for (const ticket of Object.values(state.tickets)) {
        if (ticket.epoch === this.epoch && ticket.childId === agent.id && same(ticket.scope, snapshot.context) && !snapshot.stale
          && !ticket.reads.includes(snapshot.snapshot_id) && ticket.reads.length < 64) ticket.reads.push(snapshot.snapshot_id);
      }
    });
  }
  submit(agent, id, task, scope, snapshots) {
    return this.transaction(agent, state => {
      const ticket = this.ticket(state, id, task, scope);
      const run = this.runs.get(agent.id);
      if (!run || run.ended || run.runId !== ticket.runId) fail('CHILD_LIFECYCLE_UNAVAILABLE', 'Submit must occur within the same observed active child run that claimed the handoff');
      if (ticket.childId !== agent.id || !snapshots.length || snapshots.some(s => s.stale || !ticket.reads.includes(s.snapshot_id))) fail('EVIDENCE_READ_REQUIRED', 'Claiming child must actually read every current submitted system report first');
      if (ticket.submitted) fail('HANDOFF_ALREADY_SUBMITTED', 'This handoff already has a submission');
      ticket.submitted = snapshots.map(s => s.snapshot_id);
      return { handoffId: id, submitted: true, snapshot_ids: ticket.submitted, childFinished: false, semanticAcceptanceVerified: false };
    });
  }
  review(agent, id, task, scope, ids) {
    return this.transaction(agent, state => {
      const ticket = this.ticket(state, id, task, scope);
      if (ticket.parentId !== agent.id) fail('HANDOFF_PARENT_REQUIRED', 'Only the handoff owner can perform post-return review');
      if (!ticket.submitted || !ticket.terminal || ticket.terminal.stopReason !== 'completed' || !ticket.terminal.hasOutput) fail('CHILD_RETURN_REQUIRED', 'Child has not submitted evidence and finished with observed output; this is not post-return review');
      if (JSON.stringify([...ids].sort()) !== JSON.stringify([...ticket.submitted].sort())) fail('RETURN_SNAPSHOT_MISMATCH', 'Review exactly the child-submitted snapshot IDs');
      return { handoffId: id, childId: ticket.childId, childRunId: ticket.runId, delegationVerified: true,
        reviewStage: 'post-return', note: 'Observed child termination and evidence submission, not proof of model understanding or semantic correctness.' };
    });
  }
  start(info) {
    if (info?.local === true && typeof info.id === 'string' && typeof info.runId === 'string') this.runs.set(info.id, { runId: info.runId, ended: false });
  }
  end(info) {
    const run = this.runs.get(info?.id), agent = this.getAgent(info?.id) || this.agents.get(info?.id);
    if (!run || run.ended || run.runId !== info.runId || !agent) return;
    run.ended = true;
    this.transaction(agent, state => {
      for (const ticket of Object.values(state.tickets)) if (ticket.epoch === this.epoch && ticket.childId === info.id && ticket.runId === info.runId) {
        ticket.terminal = { stopReason: info.stopReason, hasOutput: Array.isArray(info.lastAssistantMessage)
          && info.lastAssistantMessage.some(b => b.type === 'text' && typeof b.text === 'string' && !!b.text.trim()) };
      }
    });
  }
}

export function installDelegationControl(ctx, cfg) {
  const getAgent = id => { try { return ctx.get('agents')?.get(id); } catch { return undefined; } };
  const control = new DelegationControl({ root: cfg.projectRoot, getAgent });
  ctx.on('agent/created', ({ agent }) => control.remember(agent));
  ctx.on('subagent/start', info => control.start(info));
  ctx.on('subagent/end', info => control.end(info));
  return control;
}
