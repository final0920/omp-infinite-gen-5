// Contract fixtures only; no Python, native decoder, sample or database runs.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { AnalysisArtifacts } from '../source/analysis_artifacts.js';
import { PROJECTION_RUNTIME_PIN, validateProjection, runProjection } from '../source/projection_jobs.js';
import { defineIntegrationTools } from '../integration_tools.js';

const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-guarded-contract-'));
const target = path.join(directory, 'data.bin');
fs.writeFileSync(target, 'data-only transport fixture');
const strict = { target, level: 'project', projection_path: ['0x140001000', '0x140001004'], projection_registers: ['rax'] };

function fixture(change = () => {}, edges = 1) {
  const jobs = { artifacts: new AnalysisArtifacts(path.join(directory, String(Math.random()))), active: new Set(), calls: [] };
  fs.mkdirSync(path.join(jobs.artifacts.root, 'jobs'));
  jobs.request = async (params, signal, kind) => {
    jobs.calls.push({ params, signal, kind });
    const result = { schema: 'ig5-pcode-guarded-projection-v1', projectionMode: 'guarded-path',
      targetSha256: params.sha256, runtimeManifestPin: PROJECTION_RUNTIME_PIN,
      projectionPath: params.projection_path, projectionRegisters: params.projection_registers,
      nativeTargetExecuted: false, databaseModified: false, businessAccepted: false, wholeBinaryVerified: false,
      pathGuard: 2, initialMemory: 0, currentMemory: 0, initialRegisters: { rax: 1 }, registers: { rax: 1 },
      control: { kind: 'fallthrough', target: 3 }, stores: [{ guard: 2,address:3,value:1,beforeMemory:0,afterMemory:0 }],
      dag: { nodes: [{ id: 0, type: 'memory', op: 'initial_memory', args: [] },
        { id: 1, type: 'bv', bits: 64, op: 'input', name: 'rax', args: [] },
        { id: 2, type: 'bv', bits: 8, op: 'const', value: '0x1', args: [] },
        { id: 3, type: 'bv', bits: 64, op: 'const', value: '0x140001004', args: [] }],references:11+8*edges,depth:1 },
      branchPoints: Array.from({ length: edges }, (_, instructionIndex) => ({ instructionIndex, condition: 2,
        prefixGuard: 2, continuedGuard: 2, continuedSuccessor: 'taken', continuedTarget: 3, sideExitIndex: instructionIndex })),
      sideExits: Array.from({ length: edges }, (_, instructionIndex) => ({ instructionIndex,
        guard: 2, target: 3, registers: { rax: 1 }, currentMemory: 0,
        continuation: 'not-analyzed', statusFlags: 'not-exported' })),
      scope: { finalStateValidity: 'Only under pathGuard', sideExitValidity: 'Only under its own guard' }, limits: {} };
    const reply = { runtimeManifestPin: PROJECTION_RUNTIME_PIN, targetSha256: params.sha256,
      process: { childExitConfirmed: true, status: 'completed', exitCode: 0 } };
    change(result, reply);
    const raw = Buffer.from(JSON.stringify(result));
    fs.writeFileSync(path.join(jobs.artifacts.root, 'jobs', params.job_id, 'stdout.log'), raw, { flag: 'wx' });
    return { ...reply, outputBytes: raw.length, outputSha256: createHash('sha256').update(raw).digest('hex') };
  };
  return jobs;
}

test('guarded mode is explicit and invalid selectors reject before target I/O', async () => {
  assert.deepEqual(validateProjection(strict), validateProjection({ ...strict, projection_mode: 'strict' }));
  assert.equal(validateProjection({ ...strict, projection_mode: 'guarded-path' }).projection_mode, 'guarded-path');
  for (const mode of [undefined, null, false, 1, {}, [], 'observed-path']) {
    const args = { ...strict, target: path.join(directory, 'missing'), projection_mode: mode };
    assert.throws(() => validateProjection(args), /projection_mode/);
    await assert.rejects(runProjection({}, args), /projection_mode/);
  }
});

test('guarded import preserves guards, schema, full reports and false business scope', async () => {
  const jobs = fixture();
  try {
    const value = await runProjection(jobs, { ...strict, projection_mode: 'guarded-path' });
    assert.equal(jobs.calls[0].params.projection_mode, 'guarded-path');
    assert.equal(jobs.calls[0].kind, 'project');
    assert.equal(value.projectionMode, 'guarded-path'); assert.equal(value.pathGuard, 2);
    assert.equal(value.sideExitCount, 1); assert.equal(value.sideExitPreviewComplete, true);
    assert.equal(value.dagReferences,19);
    assert.equal(value.status, 'partial'); assert.equal(value.recoveryStatus, 'unverified');
    assert.equal(value.businessAccepted, false); assert.equal(value.wholeBinaryVerified, false);
    const raw = fs.readFileSync(value.reportPath);
    assert.equal(createHash('sha256').update(raw).digest('hex'), value.reportSha256);
    const saved = JSON.parse(raw).result;
    assert.equal(saved.schema, 'ig5-pcode-guarded-projection-v1');
    assert.equal(saved.stores[0].guard, 2); assert.equal(saved.sideExits[0].registers.rax, 1);
  } finally { await jobs.artifacts.dispose(); }
});

test('guarded exit previews are bounded and explicitly incomplete when full report is larger', async () => {
  const jobs = fixture(undefined, 10);
  try {
    const args = { ...strict, projection_path: Array.from({ length: 11 }, (_, i) => '0x' + (0x140001000 + i).toString(16)), projection_mode: 'guarded-path' };
    const value = await runProjection(jobs, args);
    assert.equal(value.sideExitCount, 10); assert.equal(value.sideExitPreview.length, 8);
    assert.equal(value.sideExitPreviewComplete, false);
    assert.equal(JSON.parse(fs.readFileSync(value.reportPath)).result.sideExits.length, 10);
  } finally { await jobs.artifacts.dispose(); }
});

test('schema confusion and invalid guard/state references never commit a report', async () => {
  const changes = [
    r => { r.schema = 'ig5-pcode-projection-v1'; },
    r => { delete r.projectionMode; },
    r => { r.pathGuard = 1; },
    r => { r.pathGuard = 9999; },
    r => { r.branchPoints[0].condition = 1; },
    r => { r.branchPoints[0].sideExitIndex = 1; },
    r => { r.branchPoints = []; },
    r => { r.sideExits[0].currentMemory = 1; },
    r => { r.sideExits[0].statusFlags = 'fully-restored'; },
    r => { r.sideExits[0].registers = {}; },
    r => { r.sideExits[0].continuation = 'covered'; },
    r => { r.stores[0].guard = 1; },
  ];
  for (const change of changes) {
    const jobs = fixture(change);
    try {
      await assert.rejects(runProjection(jobs, { ...strict, projection_mode: 'guarded-path' }), /scope/);
      assert.deepEqual(fs.readdirSync(path.join(jobs.artifacts.root, 'records')), []);
    } finally { await jobs.artifacts.dispose(); }
  }
  const jobs = fixture();
  try { await assert.rejects(runProjection(jobs, strict), /scope/); }
  finally { await jobs.artifacts.dispose(); }
});

test('public tool schema declares mode and rejects it outside project', async () => {
  let calls = 0;
  const fail = () => { calls++; throw Error('Unexpected engine access'); };
  const tool = defineIntegrationTools({ get: fail, rpc: fail, kernel: { run: fail }, trace: { run: fail }, lifter: { run: fail } }, { projectRoot: directory }).find(x => x.name === 'ig5_ir');
  assert.deepEqual(tool.parameters.properties.projection_mode.enum, ['strict', 'guarded-path', 'opaque-effects', 'opaque-status']);
  for (const level of ['raw', 'high', 'kernel', 'trace', 'lift', 'compose']) {
    for(const projection_mode of ['guarded-path','opaque-effects','opaque-status'])
      await assert.rejects(async () => tool.execute({ target, level, projection_mode }), level==='compose' ? /level=compose accepts only target and one composition plan input/ : /projection|Projection/);
  }
  assert.equal(calls, 0);
});
