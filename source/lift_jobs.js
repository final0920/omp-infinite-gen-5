import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { WorkerClient } from './worker_transport.js';
import { AnalysisArtifacts, hashBytes, readStableFile } from './analysis_artifacts.js';
import { importAnalysisFailure } from './analysis_failure.js';

const root = fs.realpathSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '..'));
const outputNames = ['output.ll', 'output_no_opts.ll', 'output_diagnostics.json', 'stdout.log', 'stderr.log', 'mergen-crash.txt'];
export const LIFT_RUNTIME_PIN = '1d63bc53c0a0f49e99163768d716727a4ea02056b4617165c18db20e21b28485';
export const LIFTER_PIN = '32806e249c5fdfa64d673c8fb403d6c3dd4ad6a51b5f19c9154b8d6f236fa0c6';
const hex = value => typeof value === 'string' && /^0x[0-9a-f]{1,16}$/i.test(value);
const cancelError = () => Object.assign(new Error('Mergen lift cancelled; target was not executed'), { code: 'ABORT_ERR' });

export function validateLift(args) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) throw new Error('Lifter parameters must be an object');
  const allowed = ['target', 'ea', 'level', 'initial_flags', 'lift_inline', 'max_blocks', 'engine'];
  if (Object.keys(args).some(key => !allowed.includes(key))) throw new Error('level=lift accepts only target, ea, initial_flags, lift_inline and max_blocks; omit database/kernel/trace parameters');
  if (args.level !== 'lift' || typeof args.target !== 'string' || !path.isAbsolute(args.target) || args.target.includes('\0')) throw new Error('level=lift requires an absolute target path');
  if (!hex(args.ea) || BigInt(args.ea) === 0n) throw new Error('level=lift requires a nonzero preferred 64-bit VA in ea');
  if (!hex(args.initial_flags) || BigInt(args.initial_flags) > 0xfffn) throw new Error('level=lift requires explicit initial_flags, hexadecimal low12 modeled bits (0x0..0xfff)');
  if (args.engine !== undefined && !['reverse', 'ghidra'].includes(args.engine)) throw new Error('level=lift is independent of database engines');
  const inline = args.lift_inline ?? [], blocks = args.max_blocks ?? 512;
  if (!Array.isArray(inline) || inline.length > 16 || inline.some(value => !hex(value) || BigInt(value) === 0n) || new Set(inline.map(value => BigInt(value).toString())).size !== inline.length) throw new Error('lift_inline requires at most sixteen unique nonzero hexadecimal preferred addresses');
  if (!Number.isSafeInteger(blocks) || blocks < 1 || blocks > 4096) throw new Error('Lifter max_blocks must be 1..4096');
  return { ea: '0x' + BigInt(args.ea).toString(16), initial_flags: '0x' + BigInt(args.initial_flags).toString(16),
    lift_inline: inline.map(value => '0x' + BigInt(value).toString(16)), max_blocks: blocks };
}

/** Independent read-only requests. Capacity requires both cleanup ACK and root exit. */
export class LiftJobs {
  constructor(cfg, { spawnProcess = spawn, stopTimeoutMs = 5000 } = {}) {
    if (!Number.isSafeInteger(stopTimeoutMs) || stopTimeoutMs < 1 || stopTimeoutMs > 5000) throw new Error('Invalid lifter cleanup grace');
    this.cfg = cfg; this.spawnProcess = spawnProcess; this.stopTimeoutMs = stopTimeoutMs;
    this.closed = false; this.active = new Set();
    this.artifacts = new AnalysisArtifacts(path.join(cfg.artifactDir || cfg.projectRoot, 'lifter'));
    fs.mkdirSync(path.join(this.artifacts.root, 'jobs'), { recursive: true });
  }

  async request(params, signal, kind = 'lift') {
    if (!['lift', 'project', 'project-recorded', 'compose','discover','decode-observed','flow-semantics','bv-candidate'].includes(kind)) throw new Error('Unsupported owned analysis mode');
    if (this.closed || signal?.aborted) throw cancelError();
    if (this.active.size >= 2) throw new Error('Mergen lifter busy; maximum two owned requests');
    if (!this.cfg.ghidra?.available || this.cfg.host?.id !== 'win32-x64') throw new Error('Mergen requires the bundled Windows x64 Python runtime');
    if (kind === 'lift' && !fs.existsSync(path.join(root, 'runtimes', 'mergen', 'manifest.json'))) throw new Error('Pinned experimental Mergen runtime is unavailable');
    const nonce = randomUUID(), started = Date.now();
    const child = this.spawnProcess(this.cfg.ghidra.pythonExe,
      ['-I', '-B', path.join(root, 'worker', kind === 'lift' ? 'ig5_lift.py' : 'ig5_project.py'), '--artifacts-root', this.artifacts.root],
      { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, cwd: root,
        env: { ...Object.fromEntries(Object.entries(process.env).filter(([key]) => /^(SYSTEMROOT|WINDIR|TEMP|TMP)$/i.test(key))),
          IG5_HOME: this.cfg.home || process.env.IG5_HOME || path.join(os.homedir(), '.dsh', 'ig5') } });
    const item = { child, jobId: params.job_id, dispatched: false, cleanupConfirmed: false, exited: false, stopIssued: false };
    let settleStopped, client, grace;
    item.stopped = new Promise(resolve => { settleStopped = resolve; });
    const release = () => {
      if (item.exited && (!item.dispatched || item.cleanupConfirmed)) {
        this.active.delete(item); clearTimeout(grace); settleStopped();
        queueMicrotask(() => client?.dispose());
      }
    };
    child.once('exit', () => { item.exited = true; release(); });
    child.once('error', () => { if (!child.pid) { item.exited = true; release(); } });
    this.active.add(item);
    const session = { seq: 0, engine: 'lift', pending: new Map() };
    const forceStop = () => {
      if (item.stopIssued || item.exited) return;
      item.stopIssued = true;
      // Killing only this owned Python worker closes its non-inherited job
      // handle. Descendant exit still requires the worker's explicit ACK.
      try { child.kill(); } catch (error) { item.stopError = error; }
    };
    client = new WorkerClient(child, { terminate: forceStop, drainOnExit: true });
    item.client = client;
    const artifacts = this.artifacts;
    client.configure({ session, onMessage(message) {
      if (message.id !== 1 || message.nonce !== nonce) return;
      if (message.cleanupConfirmed === true) { item.cleanupConfirmed = true; release(); }
      const pending = session.pending.get(message.id);
      if (!pending) return;
      session.pending.delete(message.id); clearTimeout(pending.timer); pending.removeAbort?.();
      if (!item.cleanupConfirmed || message.error) {
        const error = Object.assign(new Error(!item.cleanupConfirmed ? 'Lifter child exit was not confirmed; capacity retained' : message.error.message || 'Mergen lift failed'),
          message.error?.code ? {code:message.error.code} : {});
        if (message.error && message.analysisFailure) {
          try {
            const evidence = importAnalysisFailure(artifacts,params,kind,nonce,message);
            if (evidence) {
              error.analysisFailure = evidence;
              error.message += ` [analysisFailure stage=${evidence.failedStage}; report=${evidence.reportPath}; SHA256=${evidence.reportSha256}]`;
            }
          } catch (failure) {
            error.failureEvidenceError = failure.message;
            error.message += ' [failure evidence could not be verified]';
          }
        }
        pending.reject(error);
      }
      else pending.resolve(message.result);
    } });
    const stop = () => {
      if (item.cancelIssued || item.exited) return;
      item.cancelIssued = true;
      if (!item.dispatched) { forceStop(); return; }
      try { client.write({ id: 0, method: 'cancel', params: { requestId: 1, nonce } }); }
      catch (error) { item.stopError = error; }
      grace = setTimeout(() => { forceStop(); client.fail(new Error('Lifter cancellation cleanup not acknowledged; ownership retained')); }, this.stopTimeoutMs);
    };
    item.stop = stop;
    signal?.addEventListener('abort', stop, { once: true });
    try {
      if (signal?.aborted) stop();
      await client.waitReady(Math.min(10000, this.cfg.requestTimeoutMs || 60000));
      if (signal?.aborted || this.closed) throw cancelError();
      const total = Math.min(60000, this.cfg.requestTimeoutMs || 60000);
      const remaining = total - (Date.now() - started) - this.stopTimeoutMs;
      if (remaining < 1) throw new Error('Lifter startup exhausted request budget');
      item.dispatched = true;
      const result = await client.request(session, kind, { ...params, nonce, budget_ms: Math.min(50000, remaining) },
        { timeoutMs: remaining, onTimeout: stop });
      if (signal?.aborted || this.closed) throw cancelError();
      return result;
    } finally {
      signal?.removeEventListener('abort', stop);
      // Do not detach transport on a cancellation: a late cleanup ACK is
      // still required before the slot can be released.
      if (!item.dispatched || item.cleanupConfirmed) {
        clearTimeout(grace); child.stdin?.end(); forceStop(); client.dispose();
      } else stop();
    }
  }

  async run(args, signal) {
    const selected = validateLift(args);
    if (this.closed || signal?.aborted) throw cancelError();
    const { data } = readStableFile(args.target, 64 * 1024 * 1024);
    const input = this.artifacts.put(data), jobId = randomUUID();
    const jobs = path.join(this.artifacts.root, 'jobs');
    const directory = path.join(jobs, jobId);
    if (fs.realpathSync(jobs) !== jobs || !fs.lstatSync(jobs).isDirectory()) throw new Error('Lifter jobs directory must be physical');
    fs.mkdirSync(directory);
    const result = await this.request({ job_id: jobId, sha256: input.sha256, ...selected }, signal);
    if (result?.backendPin !== LIFTER_PIN || result?.runtimeManifestPin !== LIFT_RUNTIME_PIN || result?.targetSha256 !== input.sha256 || result?.status !== 'partial' || result?.recoveryStatus !== 'unverified' || result?.databaseModified !== false || result?.nativeTargetExecuted !== false || result?.businessAccepted !== false || result?.wholeBinaryVerified !== false || result?.process?.childExitConfirmed !== true) throw new Error('Lifter returned inconsistent scope/evidence');
    const blobs = {}; let total = 0; let diagnostics, optimized;
    for (const name of outputNames) {
      const item = result.outputs?.find(value => value.name === name);
      if (!item) continue;
      if (!item.withinBudget || !Number.isSafeInteger(item.bytes) || item.bytes < 0 || item.bytes > 4 * 1024 * 1024) {
        blobs[name] = { retainedAt: path.join(directory, name), bytes: item.bytes, status: 'output-limit', imported: false }; continue;
      }
      const { data: output } = readStableFile(path.join(directory, name), 4 * 1024 * 1024);
      total += output.length;
      if (output.length !== item.bytes || total > 24 * 1024 * 1024) throw new Error('Lifter output scope/byte budget mismatch');
      blobs[name] = this.artifacts.put(output);
      if (name === 'output_diagnostics.json') diagnostics = JSON.parse(output.toString('utf8'));
      if (name === 'output.ll') optimized = output.toString('utf8');
    }
    result.target = args.target; result.input = input; result.outputs = blobs;
    result.diagnostics = diagnostics ?? null;
    const record = this.artifacts.save({ kind: 'lift', action: 'lift', result });
    const metadata = this.artifacts.metadata(record.id).result;
    const lines = optimized?.split(/\r?\n/) ?? [], previewLines = [];
    let bytes = 0;
    for (const line of lines.slice(0, 80)) {
      const cost = Buffer.byteLength(line) + 1;
      if (bytes + cost > 4096) break;
      previewLines.push(line); bytes += cost;
    }
    return { backend: 'Mergen', status: 'partial', recoveryStatus: 'unverified', nativeTargetExecuted: false,
      businessAccepted: false, wholeBinaryVerified: false, databaseModified: false,
      targetSha256: input.sha256, entry: result.entry, initialFlags: result.initialFlags,
      initialStateScope: result.initialStateScope, inputScope: result.inputScope,
      process: result.process, diagnosticsSummary: diagnosticSummary(diagnostics),
      irPreview: previewLines.join('\n'), irPreviewTruncated: previewLines.length < lines.length,
      outputRefs: blobs, limitations: result.limitations,
      reportId: record.id, reportSha256: metadata.recordSha256,
      reportPath: path.join(this.artifacts.root, 'records', record.id + '.json') };
  }

  async dispose() {
    this.closed = true;
    const owned = [...this.active];
    for (const item of owned) item.stop?.();
    let timer;
    try {
      await Promise.race([Promise.all(owned.map(item => item.stopped)), new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('Mergen cleanup unconfirmed; owned capacity retained')), this.stopTimeoutMs);
      })]);
    } finally { clearTimeout(timer); }
  }
}

function diagnosticSummary(value) {
  // The complete diagnostic JSON is always in a hash-bound blob/report.
  if (!value || typeof value !== 'object') return { available: false };
  const arrays = Object.fromEntries(Object.entries(value).filter(([, v]) => Array.isArray(v)).map(([k, v]) => [k, v.length]));
  const scalars = Object.fromEntries(Object.entries(value).filter(([, v]) => typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string' && v.length < 160));
  const entries = Array.isArray(value.diagnostics) ? value.diagnostics : [];
  const unresolved = entries.filter(entry => entry?.severity === 'warning' || entry?.severity === 'error');
  return { available: true, ...scalars, summary: value.summary ?? null, liftStats: value.lift_stats ?? null,
    unresolved: unresolved.slice(0, 8).map(entry => ({ code: entry.code ?? null, severity: entry.severity,
      address: entry.address ?? null, message: String(entry.message || '').slice(0, 256) })),
    unresolvedCount: unresolved.length, unresolvedPreviewTruncated: unresolved.length > 8,
    arrayCounts: arrays, completeDetailsInReport: true };
}
