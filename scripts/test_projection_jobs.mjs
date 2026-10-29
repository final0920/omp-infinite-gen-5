import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID, createHash } from 'node:crypto';
import { LiftJobs, validateLift } from '../source/lift_jobs.js';
import { PROJECTION_RUNTIME_PIN, validateProjection, runProjection, checkedProjectionReferences } from '../source/projection_jobs.js';
import { defineIntegrationTools } from '../integration_tools.js';
import { WorkerClient } from '../source/worker_transport.js';
import { AnalysisArtifacts } from '../source/analysis_artifacts.js';

// Only plain data and simulated worker events are used by this suite. No
// target, decoder, Python worker, native engine or database is launched.
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-projection-jobs-'));
const target = path.join(directory, 'input-data.bin');
fs.writeFileSync(target, Buffer.from('projection transport fixture; never executed'));
const selected = { target, level: 'project', projection_path: ['0x140001000'], projection_registers: ['rax'] };
const tick = () => new Promise(resolve => setImmediate(resolve));
const request = () => ({ job_id: randomUUID(), sha256: 'a'.repeat(64), ...validateProjection(selected) });
const liftRequest = () => ({ job_id: randomUUID(), sha256: 'b'.repeat(64),
  ...validateLift({ target, level: 'lift', ea: '0x140001000', initial_flags: '0x0' }) });
const ack = (child, message, result = { accepted: true }) => child.frame({ id: 1,
  nonce: message.params.nonce, cleanupConfirmed: true, result });

function fixture(onRequest) {
  const children = [];
  const jobs = new LiftJobs({ home: path.join(directory,'policy-home'), artifactDir: path.join(directory, randomUUID()),
    host: { id: 'win32-x64' }, requestTimeoutMs: 2000,
    ghidra: { available: true, pythonExe: 'simulated-worker-never-started.exe' } }, {
    stopTimeoutMs: 50,
    spawnProcess(executable, args, options) {
      assert.equal(executable, 'simulated-worker-never-started.exe');
      assert.equal(options.windowsHide, true);
      assert.equal(options.shell, undefined);
      assert(args.includes('-I') && args.includes('-B'));
      assert(Object.keys(options.env).every(name => /^(SYSTEMROOT|WINDIR|TEMP|TMP|IG5_HOME)$/i.test(name)));
      assert.equal(options.env.IG5_HOME,path.join(directory,'policy-home'));
      const child = new EventEmitter();
      Object.assign(child, { pid: 90000 + children.length, args, sent: [], kills: 0,
        stdout: new EventEmitter(), stderr: new EventEmitter(), stdin: new EventEmitter() });
      child.frame = value => child.stdout.emit('data', Buffer.from(JSON.stringify(value) + '\n'));
      child.exit = () => { if (!child.exited) { child.exited = true; child.emit('exit', 0); } };
      child.close = () => { if (!child.closed) { child.closed = true; child.emit('close', 0); } };
      child.finish = () => { child.exit(); child.close(); };
      child.stdin.write = raw => {
        const message = JSON.parse(raw); child.sent.push(message); onRequest?.(child, message);
      };
      child.stdin.end = () => {};
      child.kill = () => { child.kills++; };
      children.push(child);
      queueMicrotask(() => child.frame({ ig5: 'ready' }));
      return child;
    },
  });
  return { jobs, children };
}

test('projection preserves exact 64-bit addresses and normalizes only address spelling', () => {
  const input = { ...selected, projection_path: ['0xABCDEF0123456789', '0xffffffffffffffff'],
    projection_registers: ['rax', 'r15'], engine: 'ghidra' };
  const before = structuredClone(input);
  const value = validateProjection(input);
  assert.deepEqual(value.projection_path, ['0xabcdef0123456789', '0xffffffffffffffff']);
  assert.deepEqual(value.projection_registers, ['rax', 'r15']);
  assert.deepEqual(input, before);
  assert.doesNotThrow(() => validateProjection({ ...selected, engine: 'reverse' }));
});

test('projection rejects missing, duplicate, out-of-range and unsupported selection before I/O', async () => {
  const invalid = [null, [], {}, { ...selected, target: 'relative.bin' },
    ...[{ target: undefined }, { target: target + '\0' }, { level: 'raw' },
      { projection_path: undefined }, { projection_path: [] }, { projection_path: ['0x0'] },
      { projection_path: ['0x1', '0x01'] }, { projection_path: ['0x10000000000000000'] },
      { projection_path: ['1'] }, { projection_path: [1] },
      { projection_path: Array.from({ length: 129 }, (_, i) => '0x' + (i + 1).toString(16)) },
      { projection_registers: undefined }, { projection_registers: [] },
      { projection_registers: ['rax', 'rax'] }, { projection_registers: ['RAX'] },
      { projection_registers: ['eax'] }, { projection_registers: ['rip'] },
      { projection_registers: ['eflags'] }, { projection_registers: [1] },
      { engine: 'x64dbg' }].map(change => ({ ...selected, ...change }))];
  let requests = 0;
  const jobs = { request() { requests++; throw new Error('unexpected worker'); } };
  for (const value of invalid) {
    assert.throws(() => validateProjection(value));
    await assert.rejects(async () => runProjection(jobs, value));
  }
  assert.equal(requests, 0);
});

test('projection rejects every cross-mode parameter instead of silently ignoring it', async () => {
  const incompatible = { ea: '0x1', name: 'main', action: 'analyze', initial_flags: '0x0',
    lift_inline: [], max_blocks: 2, max_instructions: 2, max_code_bytes: 15, optimize: false,
    abi: 'auto', offset: 0, max_slots: 1, max_bases: 1, max_scan_bytes: 1, limit: 1,
    traces: [], trace_chunk_reports: [], trace_entry: '0x1', trace_exit: '0x2',
    trace_inputs: ['rcx', 'rdx'], trace_output: 'rax', trace_runtime_base: '0x140000000',
    trace_image: {}, trace_image_only: false, trace_target_sha256: 'a'.repeat(64),
    expected_revision: 0, input_values: {}, expression: 'rax', worker: 'other.py' };
  let requests = 0;
  const jobs = { request() { requests++; throw new Error('unexpected worker'); } };
  for (const [key, value] of Object.entries(incompatible)) {
    const args = { ...selected, [key]: value };
    assert.throws(() => validateProjection(args), key);
    await assert.rejects(async () => runProjection(jobs, args), undefined, key);
  }
  assert.equal(requests, 0);
});

test('public project route uses the existing owned worker and never opens a database', async () => {
  const h = fixture((child, message) => {
    if (message.id === 1) queueMicrotask(() => child.frame({ id: 1, nonce: message.params.nonce,
      cleanupConfirmed: true, error: { code: 'FIXTURE_STOP', message: 'simulated projection reached' } }));
  });
  let databaseCalls = 0;
  const mgr = { lifter: h.jobs, get() { databaseCalls++; throw new Error('database access'); },
    rpc() { databaseCalls++; throw new Error('database access'); } };
  const tool = defineIntegrationTools(mgr, { projectRoot: directory }).find(item => item.name === 'ig5_ir');
  assert(tool.parameters.properties.level.enum.includes('project'));
  assert.equal(tool.parameters.properties.projection_path.maxItems, 128);
  assert.equal(tool.parameters.properties.projection_registers.maxItems, 16);
  await assert.rejects(async () => tool.execute(selected), /simulated projection reached/);
  assert.equal(databaseCalls, 0);
  assert.equal(h.children.length, 1);
  assert.equal(h.children[0].sent[0].method, 'project');
  assert(h.children[0].args.some(value => value.endsWith(path.join('worker', 'ig5_project.py'))));
  assert.equal(h.jobs.active.size, 1);
  h.children[0].finish(); await h.jobs.dispose();
});

test('projection-only parameters reject in all other public modes before routing', async () => {
  let calls = 0;
  const forbidden = () => { calls++; throw new Error('unexpected route'); };
  const mgr = { get: forbidden, rpc: forbidden, kernel: { run: forbidden },
    trace: { run: forbidden }, lifter: { run: forbidden } };
  const tool = defineIntegrationTools(mgr, { projectRoot: directory }).find(item => item.name === 'ig5_ir');
  for (const level of ['raw', 'high', 'kernel', 'trace', 'lift']) {
    for (const key of ['projection_path', 'projection_registers', 'projection_mode']) {
      await assert.rejects(async () => tool.execute({ target, level, [key]: selected[key] }), /project|projection/);
    }
  }
  assert.equal(calls, 0);
});

test('lift and project share two slots, fixed worker routes, and independent nonce ownership', async () => {
  const h = fixture();
  const project = h.jobs.request(request(), undefined, 'project');
  const lift = h.jobs.request(liftRequest());
  await tick();
  assert.equal(h.children.length, 2);
  assert.deepEqual(h.children.map(child => child.sent[0].method), ['project', 'lift']);
  assert(h.children[0].args.some(value => value.endsWith(path.join('worker', 'ig5_project.py'))));
  assert(h.children[1].args.some(value => value.endsWith(path.join('worker', 'ig5_lift.py'))));
  await assert.rejects(h.jobs.request(request(), undefined, 'project'), /maximum two/);
  await assert.rejects(h.jobs.request(liftRequest()), /maximum two/);
  const [first, second] = h.children;
  first.frame({ id: 1, nonce: second.sent[0].params.nonce, cleanupConfirmed: true, result: { wrong: true } });
  await tick();
  assert.equal(h.jobs.active.size, 2);
  assert.equal(first.kills, 0);
  ack(first, first.sent[0], { route: 'project' });
  assert.deepEqual(await project, { route: 'project' });
  assert.equal(h.jobs.active.size, 2, 'ACK alone must not release the root owner');
  first.finish();
  assert.equal(h.jobs.active.size, 1);
  assert.equal(second.kills, 0, 'finishing project must not kill the lift companion');
  ack(second, second.sent[0], { route: 'lift' });
  assert.deepEqual(await lift, { route: 'lift' });
  second.finish(); await h.jobs.dispose();
  assert.equal(h.jobs.active.size, 0);
});

test('project cancellation waits for its own cleanup ACK and does not affect the companion', async () => {
  const h = fixture((child, message) => {
    if (message.id === 0) queueMicrotask(() => ack(child, child.sent[0]));
  });
  const controller = new AbortController();
  const project = h.jobs.request(request(), controller.signal, 'project');
  const companion = h.jobs.request(liftRequest());
  await tick(); controller.abort();
  await assert.rejects(project, /cancelled/);
  const [first, second] = h.children;
  assert.deepEqual(first.sent[1], { id: 0, method: 'cancel',
    params: { requestId: 1, nonce: first.sent[0].params.nonce } });
  assert.equal(h.jobs.active.size, 2);
  assert.equal(second.sent.length, 1); assert.equal(second.kills, 0);
  first.finish();
  ack(second, second.sent[0]); await companion; second.finish();
  await h.jobs.dispose(); assert.equal(h.jobs.active.size, 0);
});

test('project root exit without descendant cleanup ACK retains ownership', async () => {
  const h = fixture((child, message) => { if (message.id === 1) queueMicrotask(() => child.finish()); });
  await assert.rejects(h.jobs.request(request(), undefined, 'project'), /worker exited/);
  assert.equal(h.jobs.active.size, 1);
  await assert.rejects(h.jobs.dispose(), /cleanup unconfirmed/);
  assert.equal(h.jobs.active.size, 1);
});

test('project accepts its final stdout ACK after root exit and before close', async () => {
  const h = fixture();
  let settled;
  const pending = h.jobs.request(request(), undefined, 'project');
  const observed = pending.then(value => { settled = { value }; }, error => { settled = { error }; });
  await tick();
  const child = h.children[0]; child.exit(); await tick();
  assert.equal(settled, undefined, 'root exit alone must not discard buffered stdout');
  assert.equal(h.jobs.active.size, 1);
  ack(child, child.sent[0], { drained: true }); child.close(); await observed;
  assert.deepEqual(settled, { value: { drained: true } });
  assert.equal(h.jobs.active.size, 0);
  assert.equal(child.kills, 0);
  await h.jobs.dispose();
});

test('project rejects a wrong nonce between root exit and stdout close', async () => {
  const h = fixture();
  const rejected = assert.rejects(h.jobs.request(request(), undefined, 'project'), /worker exited/);
  await tick();
  const child = h.children[0]; child.exit();
  child.frame({ id: 1, nonce: 'unrelated-owner', cleanupConfirmed: true, result: { bad: true } });
  child.close(); await rejected;
  assert.equal(h.jobs.active.size, 1);
  await assert.rejects(h.jobs.dispose(), /cleanup unconfirmed/);
});

test('stdout draining must be explicitly enabled with a Boolean option', () => {
  for (const drainOnExit of [null, 0, 1, 'true', {}, []]) {
    assert.throws(() => new WorkerClient(new EventEmitter(), { drainOnExit }), /boolean/);
  }
});

test('pre-aborted requests and unsupported internal worker kinds never spawn', async () => {
  const h = fixture();
  const controller = new AbortController(); controller.abort();
  await assert.rejects(h.jobs.request(request(), controller.signal, 'project'), /cancelled/);
  for (const kind of ['../project', 'python', '', 'trace']) {
    await assert.rejects(h.jobs.request(request(), undefined, kind));
  }
  assert.equal(h.children.length, 0);
  await h.jobs.dispose();
});

function reportFixture(change = () => {}) {
  const h = fixture();
  h.jobs.request = async (params, _signal, kind) => {
    assert.equal(kind, 'project');
    const result = { schema: 'ig5-pcode-projection-v1', backend: 'fixture data',
      targetSha256: params.sha256, runtimeManifestPin: PROJECTION_RUNTIME_PIN,
      projectionPath: params.projection_path, projectionRegisters: params.projection_registers,
      nativeTargetExecuted: false, databaseModified: false, businessAccepted: false, wholeBinaryVerified: false,
      initialRegisters:{rax:0},initialMemory:1,registers: { rax: 0 }, control: { kind: 'fallthrough',target:0 }, currentMemory: 1,
      dag: { nodes: [{ id: 0,op:'input',args:[],type:'bv',bits:64,name:'rax' }, { id: 1,op:'initial_memory',args:[],type:'memory' }],references:5,depth:1 }, stores: [],
      scope: { independentEquivalenceProof: false }, limits: { solverQueries: 0 } };
    const reply = { runtimeManifestPin: PROJECTION_RUNTIME_PIN, targetSha256: params.sha256,
      process: { childExitConfirmed: true, status: 'completed', exitCode: 0 } };
    const mutation = change(result, reply) || {};
    const bytes = Buffer.from(JSON.stringify(result));
    fs.writeFileSync(path.join(h.jobs.artifacts.root, 'jobs', params.job_id, 'stdout.log'), bytes, { flag: 'wx' });
    return { ...reply, outputBytes: bytes.length,
      outputSha256: createHash('sha256').update(bytes).digest('hex'), ...mutation };
  };
  return h;
}

test('projection stores immutable output and retains partial/unverified scope', async () => {
  const h = reportFixture(result => {
    result.dag.nodes.push(...Array.from({ length: 98 }, (_, i) => ({ id:i+2, op: 'input', type: 'bv', bits: 64, args: [], name: 'value_' + i })));
  });
  const value = await runProjection(h.jobs, selected);
  assert.equal(value.status, 'partial'); assert.equal(value.recoveryStatus, 'unverified');
  assert.equal(value.dagReferences,5);
  for (const key of ['nativeTargetExecuted', 'databaseModified', 'businessAccepted', 'wholeBinaryVerified']) {
    assert.equal(value[key], false);
  }
  const bytes = fs.readFileSync(value.reportPath);
  assert.equal(createHash('sha256').update(bytes).digest('hex'), value.reportSha256);
  const committed = JSON.parse(bytes);
  assert(JSON.stringify(committed).length > 2000, 'fixture must exceed one host reader line');
  const lines = bytes.toString('utf8').split('\n');
  assert(lines.length > 100, 'projection report must use multiple readable lines');
  assert(lines.every(line => line.length < 2000), 'each bounded fixture line must fit the host reader');
  assert.deepEqual(h.jobs.artifacts.get(value.reportId), committed);
  assert.equal(h.jobs.artifacts.metadata(value.reportId).result.recordSha256, value.reportSha256);
  assert.deepEqual(committed.result.projectionPath, selected.projection_path);
  assert.deepEqual(committed.result.projectionRegisters, selected.projection_registers);
  assert.deepEqual(committed.outputRef, value.outputRef);
  assert.equal(value.dagReferences,committed.result.dag.references);
  assert.equal(h.children.length, 0, 'report import fixture must not spawn any process');
  await h.jobs.dispose();
});

test('projection schema counts and scope survive head/tail pruning of long metadata',async()=>{
  const h=reportFixture(r=>{r.backend='long decoder metadata '.repeat(500)});
  const value=await runProjection(h.jobs,selected),committed=JSON.parse(fs.readFileSync(value.reportPath)).result;
  const text=JSON.stringify(value,null,1),head=text.slice(0,512);
  assert(text.length>10000,'fixture must exercise a pruned middle');
  for(const [key,expected]of Object.entries({reportSchema:committed.schema,nodeCount:committed.dag.nodes.length,
    dagReferences:committed.dag.references,storeCount:committed.stores.length,status:'partial',recoveryStatus:'unverified',
    nativeTargetExecuted:false,databaseModified:false,businessAccepted:false,wholeBinaryVerified:false})){
    assert.equal(value[key],expected);assert(head.includes(JSON.stringify(key)+': '+JSON.stringify(expected)),key+' lost from head');
  }
  await h.jobs.dispose();
});

test('project preview counts repeated edges and roots and rejects stale metrics before commit',async()=>{
  const repeated=r=>{r.dag.nodes.push({id:2,op:'INT_ADD',type:'bv',bits:64,args:[0,0]});r.registers.rax=2;r.dag.references=7;r.dag.depth=2;};
  const h=reportFixture(repeated);const value=await runProjection(h.jobs,selected);
  assert.equal(value.dagReferences,7);assert.equal(JSON.parse(fs.readFileSync(value.reportPath)).result.dag.references,7);await h.jobs.dispose();
  const direct=JSON.parse(fs.readFileSync(value.reportPath)).result;direct.initialMemory=-0;
  assert.throws(()=>checkedProjectionReferences(direct),/accounting scope/);
  for(const mutate of [r=>{r.dag.references=6;},r=>{r.dag.references='7';},r=>{r.dag.references=8193;},r=>{delete r.dag.references;},
    r=>{r.dag.depth=1;},r=>{r.dag.depth=129;},r=>{r.dag.nodes[2].args=[0,2];},r=>{r.currentMemory=999;},
    r=>{r.dag.nodes[2].op='state_binding';r.dag.nodes[2].args=[];r.dag.nodes[2].source=0;},
    r=>{r.dag.nodes[2]=null;},r=>{r.dag.nodes[2].args=Array(8193).fill(0);}]){
    const bad=reportFixture(r=>{repeated(r);mutate(r)});await assert.rejects(runProjection(bad.jobs,selected),/accounting scope/);
    assert.deepEqual(fs.readdirSync(path.join(bad.jobs.artifacts.root,'records')),[]);await bad.jobs.dispose();
  }
});

test('stale or inconsistent child evidence cannot create a committed projection report', async () => {
  const changes = [
    result => { result.projectionPath = ['0x140002000']; },
    result => { result.projectionRegisters = ['rbx']; },
    result => { result.targetSha256 = '0'.repeat(64); },
    result => { result.runtimeManifestPin = '0'.repeat(64); },
    result => { result.nativeTargetExecuted = true; },
    result => { result.businessAccepted = true; },
    result => { result.schema = 'other-schema'; },
    (_result, reply) => { reply.process.childExitConfirmed = false; },
    (_result, reply) => { reply.process.exitCode = 1; },
    (_result, reply) => { reply.process.status = 'limited'; },
    (_result, reply) => { reply.runtimeManifestPin = '0'.repeat(64); },
    (_result, reply) => { reply.targetSha256 = '0'.repeat(64); },
    () => ({ outputSha256: '0'.repeat(64) }),
    () => ({ outputBytes: 1 }),
    () => ({ outputBytes: 4 * 1024 * 1024 + 1 }),
  ];
  for (const change of changes) {
    const h = reportFixture(change);
    await assert.rejects(runProjection(h.jobs, selected));
    assert.deepEqual(fs.readdirSync(path.join(h.jobs.artifacts.root, 'records')), []);
    assert.equal(h.children.length, 0);
    await h.jobs.dispose();
  }
});

test('busy or cancelled projection rejects before reading the target or creating a job', async () => {
  const h = fixture();
  const missing = { ...selected, target: path.join(directory, 'does-not-exist.bin') };
  const controller = new AbortController(); controller.abort();
  await assert.rejects(runProjection(h.jobs, missing, controller.signal), /cancelled/i);
  h.jobs.active.add({}); h.jobs.active.add({});
  await assert.rejects(runProjection(h.jobs, missing), /maximum two/);
  assert.deepEqual(fs.readdirSync(path.join(h.jobs.artifacts.root, 'jobs')), []);
  assert.equal(h.children.length, 0);
  h.jobs.active.clear(); await h.jobs.dispose();
});

test('ordinary analysis reports remain compact and hash-compatible by default', async () => {
  const store = new AnalysisArtifacts(path.join(directory, randomUUID()));
  const input = { kind: 'ordinary', action: 'inspect', result: { values: [1, 2], text: '汉字' } };
  for (const options of [undefined, {}, { pretty: false }]) {
    const record = store.save(input, options);
    const bytes = fs.readFileSync(path.join(store.root, 'records', record.id + '.json'));
    assert.equal(bytes.toString('utf8'), JSON.stringify(record));
    assert(!bytes.includes(10));
    assert.equal(store.metadata(record.id).result.recordSha256, createHash('sha256').update(bytes).digest('hex'));
    assert.deepEqual(store.get(record.id), record);
  }
  await store.dispose();
});

test('analysis formatting validates options without writing a record or evaluating accessors', async () => {
  const store = new AnalysisArtifacts(path.join(directory, randomUUID()));
  const invalid = [null, [], true, 'pretty', 1, new Date(), { unknown: true },
    { pretty: 1 }, { pretty: 'true' }, { pretty: null },
    ...[0, -1, 1.5, NaN, Infinity, '1024', null, true, 8 * 1024 * 1024 + 1].map(maxBytes => ({ maxBytes })),
    { [Symbol('pretty')]: true }];
  let reads = 0;
  invalid.push(Object.defineProperty({}, 'pretty', { get() { reads++; return true; } }));
  for (const options of invalid) {
    assert.throws(() => store.save({ result: {} }, options), error => error.code === 'INVALID_INPUT');
  }
  assert.equal(reads, 0);
  assert.deepEqual(fs.readdirSync(path.join(store.root, 'records')), []);
  assert.deepEqual(fs.readdirSync(path.join(store.root, 'metadata')), []);
  await store.dispose();
});

test('formatted report limits count final UTF-8 bytes and reject before any record is staged', async () => {
  const store = new AnalysisArtifacts(path.join(directory, randomUUID()));
  const input = { kind: 'test', result: { text: '汉字', rows: [1, 2, 3] } };
  const first = store.save(input, { pretty: true });
  const bytes = fs.readFileSync(path.join(store.root, 'records', first.id + '.json'));
  assert(bytes.length > bytes.toString('utf8').length);
  const exact = store.save(input, { pretty: true, maxBytes: bytes.length });
  assert.equal(fs.statSync(path.join(store.root, 'records', exact.id + '.json')).size, bytes.length);
  const before = fs.readdirSync(path.join(store.root, 'records'));
  const metadataBefore = fs.readdirSync(path.join(store.root, 'metadata'));
  for (const maxBytes of [1, bytes.length - 1]) {
    assert.throws(() => store.save(input, { pretty: true, maxBytes }), error => error.code === 'RESULT_LIMIT');
    assert.deepEqual(fs.readdirSync(path.join(store.root, 'records')), before);
    assert.deepEqual(fs.readdirSync(path.join(store.root, 'metadata')), metadataBefore);
  }
  await store.dispose();
});

test('projection rejects formatting expansion beyond its own 4 MiB limit', async () => {
  const h = reportFixture(result => { result.formattingBudgetFixture = Array(600000).fill(0); });
  await assert.rejects(runProjection(h.jobs, selected), error => error.code === 'RESULT_LIMIT');
  assert.deepEqual(fs.readdirSync(path.join(h.jobs.artifacts.root, 'records')), []);
  assert.deepEqual(fs.readdirSync(path.join(h.jobs.artifacts.root, 'metadata')), []);
  assert.equal(h.children.length, 0);
  await h.jobs.dispose();
});
