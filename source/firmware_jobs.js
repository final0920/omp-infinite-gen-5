import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
const MAX_OUTPUT = 32 * 1024 * 1024;

/**
 * One firmware request at a time in a short-lived bundled-Python process (worker/firmware_cli.py). The process only reads the input
 * file and writes under the extraction directory it is given; it is killed on abort or when the hard deadline passes.
 */
export class FirmwareJobs {
  constructor(cfg, { spawnProcess = spawn } = {}) { this.cfg = cfg; this.spawnProcess = spawnProcess; this.active = null; this.closed = false; }

  async run(request, signal) {
    if (this.closed) fail('DISPOSED', 'Firmware service has been disposed');
    if (signal?.aborted) fail('ABORT_ERR', 'Firmware analysis cancelled');
    if (this.active) fail('BUSY', 'A firmware analysis is already running');
    const python = this.cfg.ghidra?.pythonExe;
    if (!python) fail('NO_RUNTIME', 'The bundled Python runtime is not available');
    const seconds = request.deadline_seconds ?? 300;
    this.active = new Promise((resolve, reject) => {
      const child = this.spawnProcess(python, ['-I', '-B', '-X', 'utf8', path.join(root, 'worker', 'firmware_cli.py')], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, cwd: root,
        env: Object.fromEntries(Object.entries(process.env).filter(([key]) => /^(SYSTEMROOT|WINDIR|TEMP|TMP)$/i.test(key))) });
      const chunks = []; let size = 0, settled = false, timer;
      const finish = (error, value) => { if (settled) return; settled = true; clearTimeout(timer); signal?.removeEventListener('abort', onAbort); error ? reject(error) : resolve(value); };
      const kill = () => { try { child.kill(); } catch { /* already gone */ } };
      const onAbort = () => { kill(); finish(Object.assign(new Error('Firmware analysis cancelled'), { code: 'ABORT_ERR' })); };
      signal?.addEventListener('abort', onAbort, { once: true });
      timer = setTimeout(() => { kill(); finish(Object.assign(new Error('Firmware analysis exceeded its hard deadline'), { code: 'TIMEOUT' })); }, (seconds + 20) * 1000);
      child.stdout.on('data', data => { size += data.length; if (size > MAX_OUTPUT) { kill(); finish(Object.assign(new Error('Firmware report exceeded the output limit'), { code: 'RESULT_LIMIT' })); } else chunks.push(data); });
      child.stderr.resume();
      child.once('error', () => finish(Object.assign(new Error('The firmware worker could not start'), { code: 'NO_RUNTIME' })));
      child.once('exit', () => {
        try {
          const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (parsed.ok) finish(null, parsed.report);
          else finish(Object.assign(new Error(parsed.error?.message || 'Firmware analysis failed'), { code: parsed.error?.code || 'ANALYSIS_FAILED' }));
        } catch { finish(Object.assign(new Error('The firmware worker returned no valid report'), { code: 'ANALYSIS_FAILED' })); }
      });
      child.stdin.on('error', () => {});
      child.stdin.end(JSON.stringify(request));
    }).finally(() => { this.active = null; });
    return this.active;
  }

  dispose() { this.closed = true; return Promise.resolve(); }
}
