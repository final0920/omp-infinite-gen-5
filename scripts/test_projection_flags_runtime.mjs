// Public-route tests using real bundled SLEIGH decoding. Fixture bytes are data only.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { buildPE64Fixture } from './fixtures/pe64.mjs';
import { createHash } from 'node:crypto';

const sourceRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const directory = process.argv[2];
const pluginRoot = process.argv[3] || sourceRoot;
const mode = process.argv[4] || 'enforce';
const decoder = process.argv[5] || 'native';
assert(['native', 'java'].includes(decoder));
assert(directory && path.isAbsolute(directory) && path.isAbsolute(pluginRoot),
  'Usage: node test_projection_flags_runtime.mjs new-absolute-output [absolute-plugin-root] [enforce|baseline]');
assert(['enforce', 'baseline'].includes(mode));
fs.mkdirSync(directory, { recursive: false });
assert.equal(fs.realpathSync(directory), path.resolve(directory));
const { defineIntegrationTools } = await import(pathToFileURL(path.join(pluginRoot, 'integration_tools.js')));
const { LiftJobs } = await import(pathToFileURL(path.join(pluginRoot, 'source/lift_jobs.js')));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const fixture = buildPE64Fixture(), image = Buffer.from(fixture.image);
image.fill(0x90, 0x400, 0x800);
const cases = [
  { id: 'mul-zf-undefined', code: ['4839c0', '48f7e3', '7410'], reject: true,
    reason: 'MUL makes ZF undefined; a previous CMP cannot supply the later JZ.' },
  { id: 'imul-zf-undefined', code: ['4839c0', '480fafc3', '7410'], reject: true,
    reason: 'IMUL makes ZF undefined; the previous CMP must not leak through.' },
  { id: 'add-af-unmodeled', code: ['9e', '4801d8', '9f'], reject: true,
    reason: 'ADD defines AF architecturally, but the bundled SLEIGH omits its write.' },
  { id: 'cmp-af-unmodeled', code: ['9e', '4839d8', '9f'], reject: true,
    reason: 'CMP defines AF architecturally, but the bundled SLEIGH omits its write.' },
  { id: 'test-af-undefined', code: ['9e', '4885db', '9f'], reject: true,
    reason: 'TEST makes AF undefined; earlier SAHF is not a valid replacement.' },
  { id: 'shl-two-of-undefined', code: ['4839c0', '48c1e002', '7010'], reject: true,
    reason: 'SHL count two leaves OF undefined rather than preserving CMP OF.' },
  { id: 'shr-imm-one-of-unmodeled', code: ['4839c0', '48c1e801', '7010'], reject: true,
    reason: 'Bundled SHR immediate-count macro does not model count-one OF correctly.' },
  { id: 'shr-implicit-one-of', code: ['48d1e8', '7010'] },
  { id: 'shl-implicit-one-of', code: ['48d1e0', '7010'] },
  { id: 'shl-zero-preserves-zf', code: ['4839c0', '48c1e000', '7410'] },
  { id: 'shl-cl-of-possibly-undefined', code: ['4839c0', '48d3e0', '7010'], reject: true,
    reason: 'Free CL includes masked counts greater than one, where OF is undefined.' },
  { id: 'rol-cl-preserves-zf', code: ['4839c0', '48d3c0', '7410'] },
  { id: 'rol-two-of-undefined', code: ['4839c0', '48c1c002', '7010'], reject: true,
    reason: 'ROL multi-bit OF is undefined.' },
  { id: 'rol-byte-eight-of-undefined', code: ['4839c0', 'c0c008', '7010'], reject: true,
    reason: 'Rotation modulo byte width is zero, but masked count eight still makes OF undefined.' },
  { id: 'rol-byte-thirtytwo-preserves-zf', code: ['4839c0', 'c0c020', '7410'] },
  { id: 'store-keeps-undefined-zf-live', code: ['4839c0', '48f7e3', '0f9407'], registers: ['rbx'], reject: true,
    reason: 'The SETZ memory write depends on undefined MUL ZF even if no result GPR uses it.' },
  { id: 'mul-then-redefined-flags', code: ['48f7e3', '4839d1', '7710'], registers: ['rax', 'rdx'] },
  { id: 'sahf-restores-af-after-add', code: ['9e', '4801d8', '9e', '9f'] },
  { id: 'mul-unobserved-flags', code: ['48f7e3'], registers: ['rax', 'rdx'] },
];
const target = path.join(directory, 'flags-fixture.exe');
for (const [index, test] of cases.entries()) {
  let offset = 0x1000 + index * 0x30;
  test.addresses = [];
  for (const hex of test.code) {
    const bytes = Buffer.from(hex, 'hex');
    assert(offset + bytes.length <= 0x1400);
    test.addresses.push('0x' + (0x140000000n + BigInt(offset)).toString(16));
    bytes.copy(image, 0x400 + offset - 0x1000);
    offset += bytes.length;
  }
}
fs.writeFileSync(target, image, { flag: 'wx' });
const python = path.join(pluginRoot, 'runtimes/ghidra/python/python.exe');
const processes = [], rows = [];
const cfg = { artifactDir: directory, projectRoot: path.join(directory, 'projects'),
  host: { id: 'win32-x64' }, requestTimeoutMs: 60000, ghidra: { available: true, pythonExe: python } };
const jobs = new LiftJobs(cfg, { spawnProcess(executable, args, options) {
  assert.equal(executable, python);
  assert.deepEqual(args.slice(0, 3), ['-I', '-B', path.join(pluginRoot, 'worker/ig5_project.py')]);
  assert.equal(options.windowsHide, true);
  const child = spawn(executable, args, options);
  const row = { executable, args, pid: child.pid, stdout: '', stderr: '', exited: false };
  processes.push(row);
  child.stdout.on('data', chunk => { row.stdout += chunk.toString('utf8'); assert(row.stdout.length < 2 * 1024 * 1024); });
  child.stderr.on('data', chunk => { row.stderr += chunk.toString('utf8'); assert(row.stderr.length < 2 * 1024 * 1024); });
  row.exit = new Promise(resolve => child.once('exit', (code, signal) => {
    row.exited = true; row.exitCode = code; row.exitSignal = signal; resolve();
  }));
  return child;
} });
const tools = defineIntegrationTools({ lifter: jobs, current() { throw new Error('Flags projection must not open a database'); } }, cfg);
const tool = tools.find(item => item.name === 'ig5_ir');
assert(tool);
const sourcePins = ['worker/pcode_projection.py', 'worker/projection_worker.py', 'source/projection_jobs.js', 'source/lift_jobs.js', 'worker/projection_flags.py']
  .filter(name => fs.existsSync(path.join(pluginRoot, name)))
  .map(name => ({ name, sha256: hash(fs.readFileSync(path.join(pluginRoot, name))) }));
const snapshot = () => ({ mode, decoder, pluginRoot, sourcePins, nativeTargetExecuted: false, databaseModified: false,
  target: { path: target, sha256: hash(image), bytes: image.length }, cases: rows,
  processes: processes.map(({ exit, ...row }) => row) });
const save = () => fs.writeFileSync(path.join(directory, 'runtime-results.json'), JSON.stringify(snapshot(), null, 2));
try {
  for (const test of cases) {
    const args = { target, level: 'project', ...(decoder === 'java' ? { projection_decoder: 'java' } : {}), projection_path: test.addresses,
      projection_registers: test.registers || ['rax'] };
    let result, error;
    try { result = await tool.execute(args); } catch (caught) { error = caught; }
    assert.equal(processes.length, rows.length + 1);
    const process = processes.at(-1);
    let timeout;
    try { await Promise.race([process.exit, new Promise((_, reject) => {
      timeout = setTimeout(() => reject(new Error('Owned flags root process did not exit')), 5000);
    })]); } finally { clearTimeout(timeout); }
    assert.equal(process.exited, true);
    const requests = process.stdout.split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line));
    const ack = requests.find(row => row.id === 1);
    assert(ack?.cleanupConfirmed === true && typeof ack.nonce === 'string', 'Same-request cleanup ACK missing');
    assert.equal(jobs.active.size, 0, 'Worker ownership was not released');
    const row = { id: test.id, args, code: test.code, architecturalGap: test.reject === true,
      architecturalReason: test.reason || null, rejected: !!error, cleanupConfirmed: true, rootPid: process.pid };
    if (error) row.message = error.message;
    else {
      assert.equal(result.status, 'partial'); assert.equal(result.recoveryStatus, 'unverified');
      for (const flag of ['nativeTargetExecuted', 'databaseModified', 'businessAccepted', 'wholeBinaryVerified']) assert.equal(result[flag], false);
      assert.equal(result.process.childExitConfirmed, true); assert.equal(result.process.exitCode, 0);
      assert.equal(result.process.jobAssignedAtCreation, true); assert.equal(result.process.activeProcessLimit, 1);
      assert.equal(result.process.memoryLimitBytes, 2 * 1024 ** 3);
      assert.equal(hash(fs.readFileSync(result.reportPath)), result.reportSha256);
      const report = JSON.parse(fs.readFileSync(result.reportPath));
      assert.deepEqual(report.result.projectionPath, test.addresses);
      assert.deepEqual(report.result.decodedPath.map(instruction => instruction.bytes), test.code);
      row.result = result;
    }
    rows.push(row); save();
    if (mode === 'enforce') {
      assert.equal(row.rejected, test.reject === true, `${test.id}: ${error?.message || 'unexpectedly accepted'}`);
      if (test.reject) assert.match(error.message, /flag/i, test.id + ' rejected for an unrelated reason');
    }
    assert.equal(hash(fs.readFileSync(target)), hash(image));
    console.log(JSON.stringify({ id: test.id, observed: error ? 'rejected' : 'accepted', architecturalGap: !!test.reject, mode }));
  }
  for (const pin of sourcePins) assert.equal(hash(fs.readFileSync(path.join(pluginRoot, pin.name))), pin.sha256,
    'Tested product source changed during the run: ' + pin.name);
  const verifier = spawnSync(python, ['-I', '-B', '-X', 'utf8', path.join(sourceRoot, 'scripts/test_projection_flags_runtime_verify.py'),
    path.join(directory, 'runtime-results.json')], { cwd: sourceRoot, windowsHide: true, encoding: 'utf8', timeout: 60000, maxBuffer: 4 * 1024 * 1024 });
  fs.writeFileSync(path.join(directory, 'semantic-verifier.stdout.json'), verifier.stdout || '');
  fs.writeFileSync(path.join(directory, 'semantic-verifier.stderr.log'), verifier.stderr || '');
  assert.equal(verifier.status, 0, verifier.stderr || verifier.stdout);
  const verification = JSON.parse(verifier.stdout);
  fs.writeFileSync(path.join(directory, 'verified.json'), JSON.stringify({ ...snapshot(), verification,
    runtimeResultsSha256: hash(fs.readFileSync(path.join(directory, 'runtime-results.json'))) }, null, 2));
} catch (error) {
  save(); fs.writeFileSync(path.join(directory, 'failure.json'), JSON.stringify({ message: error.message, stack: error.stack }, null, 2));
  throw error;
} finally { await jobs.dispose(); await jobs.artifacts.dispose(); }
