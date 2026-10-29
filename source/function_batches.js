import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { ProjectStore } from './project_store.js';
import { normalizeHex } from './address_ref.js';
import { collectFunctionDossier } from './function_dossier.js';

const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
const same = (a,b) => ['target','projectId','artifactId','sha256','engine','provider','attachmentId','dbRevision'].every(k => a?.[k] === b?.[k]);
const snapshot = task => ({ ...structuredClone(task), counts: Object.fromEntries(['pending','running','completed','failed','cancelled','stale'].map(s => [s,task.items.filter(i => i.status === s).length])) });

/** Durable orchestration over the existing session queue; no new worker or native route. */
export class FunctionBatches {
  constructor(root) { this.store = new ProjectStore({ root: path.join(root, 'function-batches') }); this.active = new Map(); }
  update(id, fn) { return this.store.updateInvestigationRecords(records => {
    const tasks = records.tasks ||= {};
    const task = tasks[id]; if (!task || task.schemaVersion !== 1 || !Array.isArray(task.items) || task.items.length > 72) fail('BATCH_NOT_FOUND', 'Batch task is missing or invalid');
    fn(task); return snapshot(task);
  }); }
  async execute(mgr, session, args, execution) {
    const input = args.batch;
    if (!input || Object.keys(input).some(k => !['action','id','functions','max_items'].includes(k)) || !['create','status','run','cancel'].includes(input.action)) fail('INVALID_BATCH_ARGUMENT', 'Invalid batch operation');
    const provenance = mgr.evidence(session);
    if (input.action === 'create') {
      if (input.id !== undefined || input.max_items !== undefined || !Array.isArray(input.functions) || input.functions.length < 1 || input.functions.length > 72) fail('INVALID_BATCH_ARGUMENT', 'Create requires 1..72 explicit function addresses');
      const functions = input.functions.map(ea => normalizeHex(ea));
      if (new Set(functions).size !== functions.length) fail('INVALID_BATCH_ARGUMENT', 'Duplicate function addresses are not accepted');
      return this.store.updateInvestigationRecords(records => {
        const tasks = records.tasks ||= {}; if (Object.keys(tasks).length >= 64) fail('BATCH_STORAGE_LIMIT', 'At most 64 retained function batches');
        const id = randomUUID(), task = { schemaVersion: 1, id, provenance, createdAt: new Date().toISOString(), cancelled: false,
          expiresAt: Date.now() + 7 * 86400000,
          items: functions.map(ea => ({ ea, status: 'pending', attempts: 0, resultRef: null })) };
        tasks[id] = task; return snapshot(task);
      });
    }
    if (input.functions !== undefined || typeof input.id !== 'string' || !/^[a-f0-9-]{36}$/.test(input.id)) fail('INVALID_BATCH_ARGUMENT', 'Choose an existing batch UUID');
    let task = this.update(input.id, t => {
      if (['target','projectId','artifactId','sha256','engine','provider'].some(k => t.provenance[k] !== provenance[k])) fail('BATCH_IDENTITY_MISMATCH', 'Batch belongs to another target or project');
      if (!Number.isSafeInteger(t.expiresAt) || t.expiresAt <= Date.now()) { t.stale = true; for (const item of t.items) item.status = 'stale'; }
      if (!same(t.provenance, provenance)) {
        for (const item of t.items) if (['pending','running'].includes(item.status)) item.status = 'stale';
        t.stale = true;
      }
      if (input.action === 'cancel') { t.cancelled = true; for (const item of t.items) if (item.status === 'pending') item.status = 'cancelled'; }
    });
    if (task.stale) fail('BATCH_STALE', 'Batch attachment or database revision changed; create a new batch');
    if (input.action === 'cancel') this.active.get(input.id)?.abort();
    if (input.action !== 'run' || task.stale || task.cancelled) return task;
    const maximum = input.max_items ?? 8;
    if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 8) fail('INVALID_BATCH_ARGUMENT', 'max_items must be 1..8');
    if (this.active.has(input.id)) fail('BATCH_BUSY', 'This batch is already running');
    const controller = new AbortController(); this.active.set(input.id, controller);
    let dispatched = 0, processed = 0;
    const started = Date.now();
    const run = async () => {
      for (let index = 0; index < task.items.length && processed < maximum; index++) {
        task = this.update(input.id, () => {});
        const item = task.items[index];
        if (!['pending','running'].includes(item.status) || task.cancelled) continue;
        if (Date.now()-started >= 60000 || execution?.signal?.aborted || controller.signal.aborted) break;
        if (!same(mgr.evidence(session), task.provenance)) { task = this.update(input.id, t => { t.stale = true; for (const i of t.items) if (['pending','running'].includes(i.status)) i.status = 'stale'; }); break; }
        const token = `${input.id}:${index}`;
        let committed;
        try { committed = mgr.functionResults.find(task.provenance, token); }
        catch (error) { task = this.update(input.id, t => { t.items[index].status = 'failed'; t.items[index].error = error.code || 'RESULT_CORRUPT'; }); processed++; continue; }
        if (committed) { task = this.update(input.id, t => { t.items[index].status = 'completed'; t.items[index].resultRef = committed; }); processed++; continue; }
        // Outer dispatch pays for the first fresh item; every further item pays
        // the same existing shared call charge before any provider work starts.
        if (dispatched) {
          try { mgr.coordination.charge(execution?.agent, 'ig5_decompile', {}); }
          catch (error) { task = this.update(input.id, t => { t.pauseReason = error.code || 'BUDGET_UNAVAILABLE'; }); break; }
        }
        dispatched++; processed++;
        this.update(input.id, t => { t.items[index].status = 'running'; t.items[index].attempts++; delete t.pauseReason; });
        try {
          const result = await collectFunctionDossier(mgr, session, { ea: item.ea, refresh: true, result_task_id: input.id, result_idempotency_key: token });
          if (!result.savedResult) fail(result.savedResultError?.code || 'BATCH_RESULT_NOT_SAVED', 'Batch result could not be committed');
          task = this.update(input.id, t => { t.items[index].status = 'completed'; t.items[index].resultRef = result.savedResult;
            t.items[index].sectionStates = Object.fromEntries(Object.entries(result.sections).map(([k,v]) => [k,v.completeness])); });
        } catch (error) {
          task = this.update(input.id, t => { t.items[index].status = controller.signal.aborted ? 'cancelled' : execution?.signal?.aborted ? 'pending' : 'failed'; t.items[index].error = error.code || 'COLLECTION_FAILED'; });
          if (execution?.signal?.aborted || controller.signal.aborted || !mgr.alive(session)) break;
        }
      }
      return task;
    };
    try {
      const signal = AbortSignal.any([controller.signal, ...(execution?.signal ? [execution.signal] : []), AbortSignal.timeout(60000)]);
      return await mgr.scope.run({ ...mgr.scope.getStore(), signal }, run);
    } finally { this.active.delete(input.id); }
  }
}
