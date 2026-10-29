import { Worker } from 'node:worker_threads';

const error = (code, message) => Object.assign(new Error(message), { code });
/** One bounded data worker per plugin instance; cancellation never kills an engine. */
export class AnalysisJobs {
  constructor({ timeoutMs = 15000, memoryMb = 64 } = {}) {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000) throw error('INVALID_INPUT', 'Invalid data worker timeout');
    if (!Number.isSafeInteger(memoryMb) || memoryMb < 16 || memoryMb > 2048) throw error('INVALID_INPUT', 'Invalid data worker memory limit');
    this.timeoutMs = timeoutMs; this.memoryMb = memoryMb; this.active = null; this.queue = []; this.closed = false;
  }
  runSettled(kind, request, signal) { return this.run(kind, request, signal, true); }
  run(kind, request, signal, waitForCleanup = false) {
    if (this.closed) return Promise.reject(error('DISPOSED', 'Analysis service has been disposed'));
    if (signal?.aborted) return Promise.reject(error('ABORT_ERR', 'Analysis cancelled'));
    if (this.queue.length >= 4) return Promise.reject(error('BUSY', 'Data analysis queue is full'));
    return new Promise((resolve, reject) => {
      const task = { kind, request, signal, resolve, reject, waitForCleanup };
      task.abort = () => {
        if (this.active === task) task.finish(error('ABORT_ERR', 'Analysis cancelled'));
        else { this.queue = this.queue.filter(item => item !== task); signal?.removeEventListener('abort', task.abort); reject(error('ABORT_ERR', 'Queued analysis cancelled')); }
      };
      signal?.addEventListener('abort', task.abort, { once: true });
      this.queue.push(task); this.pump();
    });
  }
  pump() {
    if (this.active || this.closed || !this.queue.length) return;
    const task = this.active = this.queue.shift();
    let settled = false, worker, timer;
    task.finish = (failure, value) => {
      if (settled) return; settled = true;
      clearTimeout(timer); task.signal?.removeEventListener('abort', task.abort);
      const stopped = worker ? worker.terminate() : Promise.resolve();
      task.stopped = Promise.resolve(stopped);
      const settle = () => { if (failure) task.reject(failure); else task.resolve(value); };
      if (!task.waitForCleanup) settle();
      // Start only after the old worker's memory and event loop have been released.
      const next = cleanupFailure => {
        if (cleanupFailure) {
          this.closed = true; task.retained = true;
          failure = Object.assign(error('WORKER_CLEANUP_FAILED', 'Data worker termination was not confirmed'), { cleanupConfirmed: false });
          if (task.waitForCleanup) settle();
          for (const queued of this.queue.splice(0)) { queued.signal?.removeEventListener('abort', queued.abort); queued.reject(failure); }
          return;
        }
        this.active = null; if (task.waitForCleanup) settle(); this.pump();
      };
      task.stopped.then(() => next(), next);
    };
    try {
      worker = new Worker(new URL('./analysis_worker.js', import.meta.url), { workerData: { kind: task.kind, request: task.request }, resourceLimits: { maxOldGenerationSizeMb: this.memoryMb } });
      timer = setTimeout(() => task.finish(error('TIMEOUT', 'Data analysis exceeded its execution budget')), this.timeoutMs);
      worker.once('message', message => message.ok ? task.finish(null, message.value) : task.finish(error(message.error?.code || 'ANALYSIS_FAILED', message.error?.message || 'Analysis failed')));
      worker.once('error', () => task.finish(error('ANALYSIS_FAILED', 'Data analysis worker failed; no output was committed')));
      worker.once('exit', () => task.finish(error('WORKER_EXIT', 'Data analysis worker exited before a result')));
    } catch (failure) { task.finish(failure); }
  }
  async dispose() {
    this.closed = true;
    for (const task of this.queue.splice(0)) { task.signal?.removeEventListener('abort', task.abort); task.reject(error('DISPOSED', 'Analysis service disposed')); }
    const active = this.active;
    active?.finish(error('DISPOSED', 'Analysis service disposed'));
    await active?.stopped;
  }
}
