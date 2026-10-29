// Real public-route/native-decode tests. The PE fixture is always data, never a process.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const main = process.argv[5] || path.dirname(scriptDir);
const directory = process.argv[2], contextPath = process.argv[3];
const context0Mode = process.argv[4] || 'dead-frame';
const decoder = process.argv[6] || 'native';
assert(['native', 'java'].includes(decoder));
assert(directory && path.isAbsolute(directory) && path.isAbsolute(main),
  'Usage: node test_projection_runtime.mjs new-absolute-output [absolute-context-source] [dead-frame|reject] [absolute-plugin-root]');
assert(['dead-frame', 'reject'].includes(context0Mode));
const { buildPE64Fixture } = await import(pathToFileURL(path.join(main, 'scripts/fixtures/pe64.mjs')));
const { defineIntegrationTools } = await import(pathToFileURL(path.join(main, 'integration_tools.js')));
const { LiftJobs } = await import(pathToFileURL(path.join(main, 'source/lift_jobs.js')));
const { hashBytes } = await import(pathToFileURL(path.join(main, 'source/analysis_artifacts.js')));
fs.mkdirSync(directory, { recursive: false });
assert.equal(fs.realpathSync(directory), path.resolve(directory));
const fixture = buildPE64Fixture(), image = Buffer.from(fixture.image);
image.fill(0x90, 0x400, 0x800);
const address = rva => '0x' + (0x140000000n + BigInt(rva)).toString(16);
const put = (rva, hex) => Buffer.from(hex, 'hex').copy(image, 0x400 + rva - 0x1000);
put(0x1000, '89c8');                 // mov eax, ecx; explicitly clears high32
put(0x1020, '88d488c8');             // mov ah, dl; mov al, cl
put(0x1040, '6689188811440fb700');   // mov [rax], bx; mov [rcx], dl; movzx r8d, word [rax]
put(0x1060, '4839d87710');           // cmp rax, rbx; ja +0x10
put(0x1080, '50c3');                 // push rax; ret
put(0x1090, '480fbdc1');             // bsr rax, rcx: unsupported internal p-code branch
put(0x10a0, '0f05');                 // syscall: unsupported side effect
put(0x10b0, 'eb0e');                 // direct jmp 0x10c0
const target = path.join(directory, 'projection-fixture.exe');
fs.writeFileSync(target, image, { flag: 'wx' });
const cases = [
  { id: 'eax-zero-extends', rvas: [0x1000], registers: ['rax'] },
  { id: 'ah-al-partial-preservation', rvas: [0x1020, 0x1022], registers: ['rax'] },
  { id: 'ordered-symbolic-alias', rvas: [0x1040, 0x1043, 0x1045], registers: ['r8'] },
  { id: 'conditional-two-successors', rvas: [0x1060, 0x1063], registers: ['rax', 'rbx'] },
  { id: 'push-ret-store-retained', rvas: [0x1080, 0x1081], registers: ['rax', 'rsp'] },
  { id: 'explicit-direct-jump', rvas: [0x10b0, 0x10c0], registers: ['rax'] },
  { id: 'internal-bsr-rejected', rvas: [0x1090], registers: ['rax'],
    rejection: context0Mode === 'reject' ? /Internal p-code control flow/ : /Live BSR destination\/status-flag frame/ },
  { id: 'syscall-rejected', rvas: [0x10a0], registers: ['rax'], rejection: /Unsupported architectural register/ },
  { id: 'missing-instruction-rejected', rvas: [0x1000, 0x1003], registers: ['rax'], rejection: /Missing fallthrough path instruction/ },
  { id: 'midpath-conditional-rejected', rvas: [0x1060, 0x1063, 0x1065], registers: ['rax'], rejection: /Conditional\/indirect control only supported at path end/ },
  { id: 'undefined-initial-flags-rejected', rvas: [0x1063], registers: ['rax'], rejection: /undefined initial architectural flags/ },
];
let contextSource = null;
if (contextPath) {
  assert(path.isAbsolute(contextPath));
  const raw = fs.readFileSync(contextPath);
  assert(raw.length <= 4 * 1024 * 1024);
  const context = JSON.parse(raw);
  assert.equal(hashBytes(fs.readFileSync(context.target.path)), context.target.sha256);
  contextSource = { path: contextPath, bytes: raw.length, sha256: hashBytes(raw), target: context.target };
  for (const index of [137, 0]) {
    const handler = context.handlers.find(row => row.byteIndex === index);
    assert(handler && Array.isArray(handler.rows));
    cases.push({ id: index === 137 ? 'context137-fixed-state' : context0Mode === 'reject' ? 'context0-internal-bsr-rejected' : 'context0-fixed-state',
      target: context.target.path, rvas: handler.rows.map(row => Number(BigInt(row.observed.rva))),
      registers: 'rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15'.split(' '),
      ...(index === 0 && context0Mode === 'reject' ? { rejection: /Internal p-code control flow/ } : {}) });
  }
}
const python = path.join(main, 'runtimes/ghidra/python/python.exe');
const cfg = { artifactDir: directory, projectRoot: path.join(directory, 'projects'),
  host: { id: 'win32-x64' }, requestTimeoutMs: 60000, ghidra: { available: true, pythonExe: python } };
const processes = [];
const jobs = new LiftJobs(cfg, { spawnProcess(executable, args, options) {
  assert.equal(executable, python);
  assert.deepEqual(args.slice(0, 3), ['-I', '-B', path.join(main, 'worker/ig5_project.py')]);
  assert.equal(options.windowsHide, true);
  const child = spawn(executable, args, options);
  const row = { executable, args, windowsHide: options.windowsHide, pid: child.pid,
    stdin: '', stdout: '', stderr: '', startedAt: new Date().toISOString(), exited: false, closed: false };
  processes.push(row);
  const originalWrite = child.stdin.write.bind(child.stdin);
  child.stdin.write = (chunk, ...rest) => {
    row.stdin += Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk);
    assert(row.stdin.length <= 128 * 1024);
    return originalWrite(chunk, ...rest);
  };
  child.stdout.on('data', part => { row.stdout += part.toString('utf8'); assert(row.stdout.length <= 2 * 1024 * 1024); });
  child.stderr.on('data', part => { row.stderr += part.toString('utf8'); assert(row.stderr.length <= 2 * 1024 * 1024); });
  child.once('exit', (code, signal) => {
    row.exited = true; row.exitCode = code; row.exitSignal = signal; row.exitedAt = new Date().toISOString();
  });
  row.exit = new Promise(resolve => child.once('close', () => { row.closed = true; resolve(); }));
  return child;
} });
const tool = defineIntegrationTools({ lifter: jobs, current() { throw new Error('Projection must not open a database'); } }, cfg).find(item => item.name === 'ig5_ir');
const rows = [];
const snapshot = () => ({ schema: 1, createdAt: new Date().toISOString(),
  decoder, nativeTargetExecuted: false, databaseModified: false, businessAccepted: false, wholeBinaryVerified: false,
  target: { path: target, bytes: image.length, sha256: hashBytes(image) }, contextSource, context0Mode, pluginRoot: main,
  cases: rows, processes: processes.map(({ exit, ...rest }) => rest), activeRequests: jobs.active.size });
const save = () => fs.writeFileSync(path.join(directory, 'runtime-results.json'), JSON.stringify(snapshot(), null, 2));
try {
  for (const test of cases) {
    const args = { level: 'project', target: test.target || target, projection_path: test.rvas.map(address), projection_registers: test.registers,
      ...(decoder === 'java' ? { projection_decoder: 'java' } : {}) };
    let result, error;
    try { result = await tool.execute(args); } catch (caught) { error = caught; }
    const process = processes.at(-1);
    let timeout;
    try { await Promise.race([process.exit, new Promise((_, reject) => {
      timeout = setTimeout(() => reject(new Error('Owned root process did not exit')), 5000);
    })]); } finally { clearTimeout(timeout); }
    const frames = process.stdout.trim().split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line));
    const ack = frames.find(frame => frame.id === 1);
    const sent = process.stdin.trim().split(/\r?\n/).map(line => JSON.parse(line));
    assert.equal(sent.length, 1); assert.equal(sent[0].id, 1); assert.equal(sent[0].method, 'project');
    assert(ack && typeof ack.nonce === 'string' && ack.cleanupConfirmed === true);
    assert.equal(ack.nonce, sent[0].params.nonce);
    assert.equal(process.exited, true);
    assert.equal(process.closed, true);
    assert.equal(jobs.active.size, 0);
    if (test.rejection) {
      assert(error, test.id + ' unexpectedly accepted');
      assert.match(error.message, test.rejection);
      assert(ack.error && !ack.result);
      rows.push({ id: test.id, args, rejected: true, expected: test.rejection.source,
        message: error.message, cleanupConfirmed: true, rootPid: process.pid });
    } else {
      if (error) throw error;
      assert.equal(result.process.exitCode, 0);
      assert.equal(result.process.childExitConfirmed, true);
      assert.equal(result.process.jobAssignedAtCreation, true);
      assert.equal(result.process.activeProcessLimit, 1);
      assert.equal(result.process.memoryLimitBytes, 2 * 1024 ** 3);
      for (const flag of ['nativeTargetExecuted', 'databaseModified', 'businessAccepted', 'wholeBinaryVerified']) assert.equal(result[flag], false);
      assert.equal(result.status, 'partial');
      assert.equal(result.recoveryStatus, 'unverified');
      assert.equal(hashBytes(fs.readFileSync(result.reportPath)), result.reportSha256);
      const record = JSON.parse(fs.readFileSync(result.reportPath, 'utf8'));
      const output = jobs.artifacts.read(result.outputRef.ref, 4 * 1024 * 1024).data;
      assert.deepEqual(JSON.parse(output), record.result);
      assert.deepEqual(record.result.projectionPath, args.projection_path);
      assert.deepEqual(record.result.projectionRegisters, args.projection_registers);
      rows.push({ id: test.id, args, rejected: false, result, cleanupConfirmed: true, rootPid: process.pid });
    }
    assert.equal(hashBytes(fs.readFileSync(target)), hashBytes(image));
    if (contextSource) assert.equal(hashBytes(fs.readFileSync(contextSource.target.path)), contextSource.target.sha256);
    save();
    console.log(JSON.stringify({ id: test.id, outcome: test.rejection ? 'expected-rejection' : 'projected', cleanupConfirmed: true }));
  }
  const verifier = spawnSync(python, ['-I', '-B', '-X', 'utf8', path.join(scriptDir, 'test_projection_runtime_verify.py'), path.join(directory, 'runtime-results.json')],
    { cwd: scriptDir, windowsHide: true, encoding: 'utf8', timeout: 60000, maxBuffer: 4 * 1024 * 1024 });
  fs.writeFileSync(path.join(directory, 'semantic-verifier.stdout.json'), verifier.stdout || '');
  fs.writeFileSync(path.join(directory, 'semantic-verifier.stderr.log'), verifier.stderr || '');
  assert.equal(verifier.status, 0, verifier.stderr);
  const verification = JSON.parse(verifier.stdout);
  assert.equal(verification.status, 'passed');
  fs.writeFileSync(path.join(directory, 'verified.json'), JSON.stringify({ ...snapshot(),
    status: 'passed', semanticVerification: verification,
    runtimeReportSha256: hashBytes(fs.readFileSync(path.join(directory, 'runtime-results.json'))),
    nativeAnalysisProcesses: processes.length, successfulProjections: cases.filter(test => !test.rejection).length,
    expectedRejections: cases.filter(test => test.rejection).length }, null, 2));
  console.log(JSON.stringify({ status: 'passed', ...verification, nativeAnalysisProcesses: processes.length }));
} catch (error) {
  save();
  fs.writeFileSync(path.join(directory, 'failure.json'), JSON.stringify({ message: error.message, stack: error.stack }, null, 2));
  throw error;
} finally {
  await jobs.dispose();
  await jobs.artifacts.dispose();
}
