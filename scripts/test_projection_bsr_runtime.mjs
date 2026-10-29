// Real public ig5_ir / owned SLEIGH worker. The generated PE is input data only.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const directory = process.argv[2], pluginRoot = process.argv[3] || path.dirname(scriptDir);
const mode = process.argv[4] || 'enforce';
const decoder = process.argv[5] || 'native';
assert(directory && path.isAbsolute(directory) && path.isAbsolute(pluginRoot),
  'Usage: node test_projection_bsr_runtime.mjs new-absolute-output [absolute-plugin-root] [enforce|baseline] [native|java]');
assert(['enforce', 'baseline'].includes(mode));
assert(['native', 'java'].includes(decoder));
assert.equal(fs.realpathSync(pluginRoot), path.resolve(pluginRoot));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const ref = file => { const bytes = fs.readFileSync(file); return { path: file, bytes: bytes.length, sha256: hash(bytes) }; };
const caseFile = path.join(scriptDir, 'fixtures/projection_bsr_cases.json');
const specification = JSON.parse(fs.readFileSync(caseFile));
const cases = specification.cases.map(test => ({ ...test }));
assert.equal(cases.length, 20);
assert.equal(cases.filter(test => test.accepted).length, 8);
assert.equal(new Set(cases.map(test => test.id)).size, cases.length);
const { buildPE64Fixture } = await import(pathToFileURL(path.join(pluginRoot, 'scripts/fixtures/pe64.mjs')));
const { defineIntegrationTools } = await import(pathToFileURL(path.join(pluginRoot, 'integration_tools.js')));
const { LiftJobs } = await import(pathToFileURL(path.join(pluginRoot, 'source/lift_jobs.js')));
fs.mkdirSync(directory, { recursive: false });
assert.equal(fs.realpathSync(directory), path.resolve(directory));
const image = Buffer.from(buildPE64Fixture().image);
image.fill(0x90, 0x400, 0x800);
for (const [index, test] of cases.entries()) {
  let offset = 0x1000 + index * 0x30;
  test.addresses = [];
  for (const hex of test.code) {
    assert.match(hex, /^(?:[0-9a-f]{2})+$/);
    const bytes = Buffer.from(hex, 'hex');
    assert(offset + bytes.length <= 0x1000 + (index + 1) * 0x30 && offset + bytes.length <= 0x1400);
    test.addresses.push('0x' + (0x140000000n + BigInt(offset)).toString(16));
    bytes.copy(image, 0x400 + offset - 0x1000);
    offset += bytes.length;
  }
}
const target = path.join(directory, 'bsr-fixture.exe');
fs.writeFileSync(target, image, { flag: 'wx' });
const targetRef = ref(target), python = path.join(pluginRoot, 'runtimes/ghidra/python/python.exe');
const pins = ['integration_tools.js', 'source/projection_jobs.js', 'source/lift_jobs.js', 'source/worker_transport.js',
  'worker/ig5_project.py', 'worker/projection_worker.py', 'worker/lift_process.py', 'worker/pcode_projection.py',
  'worker/projection_flags.py', 'worker/projection_bsr.py', 'scripts/fixtures/pe64.mjs', 'runtimes/manifest.json']
  .filter(name => fs.existsSync(path.join(pluginRoot, name)))
  .map(name => ({ name, ...ref(path.join(pluginRoot, name)) }));
const processes = [], rows = [];
const cfg = { artifactDir: directory, projectRoot: path.join(directory, 'projects'),
  host: { id: 'win32-x64' }, requestTimeoutMs: 60000, ghidra: { available: true, pythonExe: python } };
const jobs = new LiftJobs(cfg, { spawnProcess(executable, args, options) {
  assert.equal(executable, python);
  assert.deepEqual(args, ['-I', '-B', path.join(pluginRoot, 'worker/ig5_project.py'), '--artifacts-root', path.join(directory, 'lifter')]);
  assert.equal(options.windowsHide, true);
  assert.equal(options.cwd, pluginRoot);
  assert(Object.keys(options.env).every(key => /^(SYSTEMROOT|WINDIR|TEMP|TMP)$/i.test(key)));
  const child = spawn(executable, args, options);
  const row = { executable, args, windowsHide: options.windowsHide, pid: child.pid, stdin: '', stdout: '', stderr: '',
    exited: false, closed: false, startedAt: new Date().toISOString() };
  processes.push(row);
  const originalWrite = child.stdin.write.bind(child.stdin);
  child.stdin.write = (chunk, ...rest) => {
    row.stdin += Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk);
    assert(row.stdin.length <= 128 * 1024);
    return originalWrite(chunk, ...rest);
  };
  child.stdout.on('data', chunk => { row.stdout += chunk.toString('utf8'); assert(row.stdout.length <= 2 * 1024 * 1024); });
  child.stderr.on('data', chunk => { row.stderr += chunk.toString('utf8'); assert(row.stderr.length <= 2 * 1024 * 1024); });
  child.once('exit', (code, signal) => { row.exited = true; row.exitCode = code; row.exitSignal = signal; row.exitedAt = new Date().toISOString(); });
  row.closedPromise = new Promise(resolve => child.once('close', () => { row.closed = true; resolve(); }));
  return child;
} });
const tool = defineIntegrationTools({ lifter: jobs, current() { throw new Error('Projection must not open a database'); } }, cfg)
  .find(item => item.name === 'ig5_ir');
assert(tool);
const snapshot = () => ({ schema: 1, mode, pluginRoot, sourcePins: pins, specification: ref(caseFile),
  runner: ref(fileURLToPath(import.meta.url)), target: targetRef,
  nativeTargetExecuted: false, databaseModified: false, businessAccepted: false, wholeBinaryVerified: false,
  cases: rows, processes: processes.map(({ closedPromise, ...row }) => row), activeRequests: jobs.active.size });
const save = () => fs.writeFileSync(path.join(directory, 'runtime-results.json'), JSON.stringify(snapshot(), null, 2));
try {
  for (const test of cases) {
    const args = { target, level: 'project', ...(decoder === 'java' ? { projection_decoder: 'java' } : {}), projection_path: test.addresses, projection_registers: test.registers };
    let result, error;
    try { result = await tool.execute(args); } catch (caught) { error = caught; }
    assert.equal(processes.length, rows.length + 1);
    const process = processes.at(-1);
    let timeout;
    try { await Promise.race([process.closedPromise, new Promise((_, reject) => {
      timeout = setTimeout(() => reject(new Error('Owned BSR root did not exit and close')), 5000);
    })]); } finally { clearTimeout(timeout); }
    assert.equal(process.exited, true); assert.equal(process.closed, true);
    const requests = process.stdin.split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line));
    const frames = process.stdout.split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line));
    const dispatched = requests.filter(frame => frame.id === 1 && frame.method === 'project');
    const finalFrames = frames.filter(frame => frame.id === 1);
    assert.equal(dispatched.length, 1); assert.equal(requests.length, 1, 'Unexpected cancellation or extra worker request');
    assert.equal(finalFrames.length, 1);
    const request = dispatched[0], ack = finalFrames[0];
    assert.match(request.params.nonce, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
    assert.equal(ack.nonce, request.params.nonce, 'Cleanup ACK belongs to another request');
    assert.equal(ack.cleanupConfirmed, true); assert.equal(jobs.active.size, 0);
    assert.equal(request.params.sha256, targetRef.sha256);
    assert.deepEqual(request.params.projection_path, test.addresses);
    assert.deepEqual(request.params.projection_registers, test.registers);
    assert(Number.isInteger(request.params.budget_ms) && request.params.budget_ms > 0 && request.params.budget_ms <= 50000);
    const jobDir = path.join(directory, 'lifter/jobs', request.params.job_id);
    const childRequest = JSON.parse(fs.readFileSync(path.join(jobDir, 'request.json')));
    assert.equal(childRequest.sha256, targetRef.sha256);
    assert.deepEqual(childRequest.projection_path, test.addresses);
    assert.deepEqual(childRequest.projection_registers, test.registers);
    assert(childRequest.budget_ms > 0 && childRequest.budget_ms <= request.params.budget_ms);
    assert.equal(hash(fs.readFileSync(childRequest.target)), targetRef.sha256);
    const row = { id: test.id, args, code: test.code, expectedAccepted: test.accepted, expected: test.expected ?? null,
      reason: test.reason ?? null, operandBits: test.operandBits ?? null, rejected: !!error,
      cleanupConfirmed: true, nonceMatched: true, rootExited: true, rootClosed: true, rootPid: process.pid,
      childRequest: ref(path.join(jobDir, 'request.json')), requestedBudgetMs: request.params.budget_ms,
      actualChildBudgetMs: childRequest.budget_ms };
    if (error) {
      assert(ack.error && !ack.result);
      row.message = ack.error.message;
      assert(error.message.startsWith(ack.error.message));
      row.processResourceEvidence = 'Failure ACK exposes no child process-resource report; fixed owned-worker source pins and cleanup are recorded separately.';
    } else {
      assert(!ack.error && ack.result);
      assert.equal(result.status, 'partial'); assert.equal(result.recoveryStatus, 'unverified');
      for (const flag of ['nativeTargetExecuted', 'databaseModified', 'businessAccepted', 'wholeBinaryVerified']) assert.equal(result[flag], false);
      const processReport = result.process;
      assert.equal(processReport.childExitConfirmed, true); assert.equal(processReport.exitCode, 0);
      assert.equal(processReport.jobAssignedAtCreation, true); assert.equal(processReport.activeProcessLimit, 1);
      assert.equal(processReport.memoryLimitBytes, 2 * 1024 ** 3);
      assert.equal(result.targetSha256, targetRef.sha256);
      const reportRaw = fs.readFileSync(result.reportPath); assert(reportRaw.length <= 4 * 1024 * 1024);
      assert.equal(hash(reportRaw), result.reportSha256);
      const report = JSON.parse(reportRaw);
      assert.equal(report.input.sha256, targetRef.sha256);
      assert.deepEqual(report.result.projectionPath, test.addresses);
      assert.deepEqual(report.result.projectionRegisters, test.registers);
      assert.deepEqual(report.result.decodedPath.map(instruction => instruction.ea), test.addresses);
      assert.deepEqual(report.result.decodedPath.map(instruction => instruction.bytes), test.code);
      row.result = result;
    }
    rows.push(row); save();
    if (mode === 'baseline') {
      assert(error, test.id + ' is no longer an unsupported baseline');
      assert.match(error.message, /Internal p-code control flow/);
    } else {
      assert.equal(row.rejected, !test.accepted, test.id + ': ' + (error?.message || 'unexpectedly accepted'));
      if (!test.accepted) assert.match(error.message, test.id === 'unsupported-memory-source'
        ? /Internal p-code control flow/ : /Live BSR destination\/status-flag frame/, 'Rejected for an unrelated reason');
    }
    assert.deepEqual(ref(target), targetRef);
    console.log(JSON.stringify({ id: test.id, mode, observed: error ? 'rejected' : 'accepted' }));
  }
  for (const pin of pins) assert.deepEqual(ref(pin.path), { path: pin.path, bytes: pin.bytes, sha256: pin.sha256 }, 'Product source changed during the run');
  const verifier = spawnSync(python, ['-I', '-B', path.join(scriptDir, 'test_projection_bsr_runtime_verify.py'),
    path.join(directory, 'runtime-results.json')], { cwd: scriptDir, windowsHide: true, encoding: 'utf8', timeout: 60000, maxBuffer: 4 * 1024 * 1024 });
  fs.writeFileSync(path.join(directory, 'semantic-verifier.stdout.json'), verifier.stdout || '');
  fs.writeFileSync(path.join(directory, 'semantic-verifier.stderr.log'), verifier.stderr || '');
  assert.equal(verifier.status, 0, verifier.stderr || verifier.stdout);
  fs.writeFileSync(path.join(directory, 'verified.json'), JSON.stringify({ ...snapshot(), verification: JSON.parse(verifier.stdout),
    runtimeResultsSha256: hash(fs.readFileSync(path.join(directory, 'runtime-results.json'))) }, null, 2));
} catch (error) {
  save(); fs.writeFileSync(path.join(directory, 'failure.json'), JSON.stringify({ message: error.message, stack: error.stack }, null, 2));
  throw error;
} finally { await jobs.dispose(); await jobs.artifacts.dispose(); }
