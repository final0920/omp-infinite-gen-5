import { createHash } from 'node:crypto';
import { jsonToolOutput } from './json_output.js';
import { routeFailure } from './failure_router.js';
import path from 'node:path';
import { DiagnosticStore } from './diagnostic_store.js';
import { readStableFile, hashBytes } from './analysis_artifacts.js';

const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const sha = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);

/** Only trusted adapters supply semanticInputs; UUIDs/messages are not evidence. */
export function failureRecord({ operation, scope = null, semanticInputs = null, inputReportHashes = [],
  hypothesisRevision = null, runtimeDigest = null, executionIdentity = null, failedStage = null, planningKey = null, error }) {
  if (typeof operation !== 'string' || !operation || operation.length > 128 || !error
    || inputReportHashes.some(x => !sha(x)) || runtimeDigest !== null && !sha(runtimeDigest) || planningKey !== null && !sha(planningKey)) throw new Error('Invalid failure binding');
  const original = { code: typeof error.code === 'string' ? error.code : 'UNCLASSIFIED_FAILURE', message: String(error.message || error).slice(0, 2000) };
  // Whitelist structured receipts, never serialize arbitrary Error/secret-bearing args.
  for (const key of ['cleanupConfirmed', 'reportSaved', 'taskLinked', 'committed', 'saved', 'stage', 'journalId', 'partial_commit', 'recoveryRequired',
    'revision', 'durableRevision', 'cleanedUp', 'state', 'stateCode', 'runId', 'stopSeq', 'cancelledBeforeExecution', 'transactionRolledBack', 'target_executed', 'guestCleanupConfirmed',
    'metadataPublished', 'metadataStage', 'metadataCleanupConfirmed']) {
    if (['string', 'boolean', 'number'].includes(typeof error[key]) || error[key] === null) original[key] = error[key];
  }
  if (error.metadataCleanupError && typeof error.metadataCleanupError === 'object') original.metadataCleanupError = {
    code: String(error.metadataCleanupError.code || 'METADATA_CLEANUP_FAILED').slice(0, 128),
    stage: String(error.metadataCleanupError.stage || 'unknown').slice(0, 64),
  };
  const binding = jsonToolOutput(canonical({ operation, scopeDigest: scope === null ? null : hash(canonical(scope)),
    inputReportHashes: [...new Set(inputReportHashes)].sort(), hypothesisRevision, runtimeDigest, executionIdentity, failureCode: original.code, failedStage }));
  const comparable = semanticInputs !== null;
  // Report hashes authenticate provenance, but often include a fresh UUID/time.
  // Duplicate identity comes from the adapter's semantic content, not that envelope.
  const { inputReportHashes: provenanceOnly, ...semanticBinding } = binding;
  const semanticKey = comparable ? hash(canonical({ ...semanticBinding, semanticInputs: jsonToolOutput(semanticInputs) })) : null;
  return { schema: 'ig5-failure-record-v1', ...binding, semanticKey, comparable, original,
    ...(planningKey ? { planningKey } : {}),
    scope: scope === null ? null : jsonToolOutput(scope),
    originalMessageTruncated: String(error.message || error).length > 2000,
    originalErrorRetainedByCaller: true, observedAt: new Date().toISOString() };
}

/** Immutable full reports and bounded persistent index; no old task schema changes. */
export class FailureRecords {
  constructor(options = 128) {
    const { limit = 128, root, artifacts } = typeof options === 'number' ? { limit: options } : options;
    this.limit = limit; this.records = []; this.artifacts = artifacts;
    if (root && artifacts) this.store = new DiagnosticStore({ root: path.join(root, 'failure-records-v1') });
  }
  persisted() {
    if (!this.store) return this.records;
    const rows = Object.values(this.store.readInvestigationRecords());
    if (rows.length > 4096 || rows.some(r => r.schema !== 'ig5-failure-index-v1' || !r.ref || !sha(r.ref.sha256)
      || r.semanticKey !== null && !sha(r.semanticKey) || !sha(r.scopeDigest || '') && r.scopeDigest !== null || typeof r.observedAt !== 'string'
      || (r.scope === null ? r.scopeDigest !== null : !r.scope || hash(canonical(r.scope)) !== r.scopeDigest)
      || !Number.isSafeInteger(r.occurrences) || r.occurrences < 1)) throw new Error('Invalid persistent failure index');
    if (rows.some(r => r.planningKey !== undefined && r.planningKey !== null && !sha(r.planningKey))) throw new Error('Invalid planning failure index');
    if (rows.some(r => r.runtimeDigest !== undefined && r.runtimeDigest !== null && !sha(r.runtimeDigest))) throw new Error('Invalid planning runtime identity');
    return rows;
  }
  add(input) {
    const record = failureRecord(input);
    const occurrences = record.comparable ? this.persisted().filter(x => x.semanticKey === record.semanticKey).length + 1 : 1;
    const result = { ...record, advice: routeFailure(record, occurrences) };
    if (this.store) {
      const receipts = {};
      for(const key of ['analysisFailure','failureEvidenceError','stdout','stderr','compatibility','exceptionType','budget','source','compatibilityWrites','limitations','executionLocation','runtimePolicyBlock']) {
        const property=Object.getOwnPropertyDescriptor(input.error,key);
        if(property&&'value' in property&&property.value!==undefined)receipts[key]=jsonToolOutput(property.value);
      }
      if(Object.keys(receipts).length) {
        const bytes=Buffer.from(JSON.stringify(receipts));
        if(bytes.length<=1024*1024)result.originalReceiptRef=this.artifacts.put(bytes);
        else result.originalReceiptArchive={status:'over-limit',bytes:bytes.length,retainedInOriginalToolError:true};
        result.originalReceiptFields=Object.keys(receipts);
      }
      if (record.originalMessageTruncated) {
        const originalBytes = Buffer.from(String(input.error.message || input.error));
        if (originalBytes.length <= 1024 * 1024) result.originalMessageRef = this.artifacts.put(originalBytes);
        else result.originalMessageArchive = { status: 'over-limit', bytes: originalBytes.length, retainedInOriginalToolError: true };
      }
      const saved = this.artifacts.save({ kind: 'investigation-failure', action: 'record', result }, { maxBytes: 65536 });
      const ref = { id: saved.id, sha256: this.artifacts.metadata(saved.id).result.recordSha256 };
      result.reportRef = ref; result.reportSaved = true; result.indexed = false;
      try {
        this.store.updateInvestigationRecords(rows => {
          if (Object.keys(rows).length >= 4096) throw Object.assign(new Error('Persistent failure index full; saved report retained'), { code: 'FAILURE_INDEX_FULL' });
          const count = result.comparable ? Object.values(rows).filter(x => x.semanticKey === result.semanticKey).length + 1 : 1;
          rows[saved.id] = { schema: 'ig5-failure-index-v1', ref, semanticKey: result.semanticKey,
            planningKey: result.planningKey || null, runtimeDigest: result.runtimeDigest, scopeDigest: result.scopeDigest, scope: result.scope, observedAt: result.observedAt, occurrences: count };
          result.advice = routeFailure(record, count);
        });
        result.indexed = true;
      } catch (error) { result.indexError = error.code || 'FAILURE_INDEX_FAILED'; }
    }
    this.records.push(result);
    if (this.records.length > this.limit) this.records.shift();
    return result;
  }
  restore(row, scope) {
      const digest = hash(canonical(scope));
      let result = row;
      if (this.store) {
        if (this.artifacts.metadata(row.ref.id).result.recordSha256 !== row.ref.sha256) throw Object.assign(new Error('Failure report changed'), { code: 'ARTIFACT_CHANGED' });
        const data = readStableFile(path.join(this.artifacts.directory('records'), row.ref.id + '.json'), 65536).data;
        if (hashBytes(data) !== row.ref.sha256) throw Object.assign(new Error('Failure bytes changed'), { code: 'ARTIFACT_CHANGED' });
        const report = JSON.parse(data);
        if (report.kind !== 'investigation-failure' || report.result.schema !== 'ig5-failure-record-v1' || report.result.scopeDigest !== row.scopeDigest
          || report.id !== row.ref.id || report.schemaVersion !== 1 || report.result.semanticKey !== row.semanticKey
          || (report.result.planningKey || null) !== (row.planningKey || null) || row.runtimeDigest !== undefined && row.runtimeDigest !== report.result.runtimeDigest) throw new Error('Failure report binding mismatch');
        result = { ...report.result, advice: routeFailure(report.result, row.occurrences), reportRef: row.ref };
      }
      return { ...result, historical: result.scopeDigest !== digest,
        staleReasons: ['attachmentId', 'dbRevision'].filter(k => result.scope?.[k] !== scope[k]).map(k => `${k}-changed`) };
  }
  scoped(scope) {
    const digest = hash(canonical(scope)), stableKeys = ['projectId', 'artifactId', 'sha256', 'engine', 'provider'];
    return this.persisted().filter(x => x.scopeDigest === digest || x.scope && stableKeys.every(k => x.scope[k] === scope[k]))
      .sort((a, b) => a.observedAt.localeCompare(b.observedAt));
  }
  recent(scope, limit = 3) { return this.scoped(scope).slice(-limit).reverse().map(row => this.restore(row, scope)); }
  /** Scan bounded metadata, then read at most one exact full receipt per requested planning key plus three recent diagnostics. */
  forPlanning(scope, keys, runtimeDigest = null) {
    if (!Array.isArray(keys) || keys.length > 64 || keys.some(k => !sha(k))) throw new Error('Bounded planning keys required');
    const rows = this.scoped(scope), wanted = new Set(keys), selected = new Map();
    for (const row of rows) if (wanted.has(row.planningKey) && (!runtimeDigest || !row.runtimeDigest || row.runtimeDigest === runtimeDigest)) selected.set(row.planningKey, row);
    const chosen = [...new Set([...rows.slice(-3).reverse(), ...selected.values()])];
    return { records: chosen.map(row => this.restore(row, scope)), keysSearched: wanted.size,
      metadataScanned: rows.length, legacyRecordsPresent: rows.some(row => row.planningKey === undefined),
      scope: 'bounded-index; exact requested keys plus recent diagnostics', completeHistory: false };
  }
}
