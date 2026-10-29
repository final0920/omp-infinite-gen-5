import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { AnalysisArtifacts, hashBytes } from '../source/analysis_artifacts.js';
import { joinRecordedTrace } from '../source/debug_trace_chunks.js';
import { TraceJobs } from '../source/trace_jobs.js';

test('recorded continuation validates hashes, identity, flags and RIP before recovery', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-trace-chunks-'));
  const cfg = { artifactDir: root, projectRoot: root }, store = new AnalysisArtifacts(path.join(root, 'debug-traces'));
  const target = path.join(root, 'owned-target'); fs.writeFileSync(target, 'target');
  const targetSha = hashBytes(Buffer.from('target'));
  const regs = ['0x1', ...Array(15).fill('0x0')];
  const save = (ea, start, extra = {}, initial = regs) => {
    const data = Buffer.from('h:ig5-native-x64-v1\nr:' + initial.join(':') + '\ne:0x202\ni:' + ea + ':1:90\nf:' + regs.join(':') + ':' + '0x' + (BigInt(ea) + 1n).toString(16) + ':0x202\n');
    const input = store.put(data);
    return store.save({ kind: 'debug-trace', action: 'record', result: { targetSha256: targetSha, input, sha256: input.sha256, bytes: data.length,
      instructionCount: 1, entry: ea, exit: ea, runId: 'run', threadId: 1, runtimeBase: '0x1000', startStopSeq: start, endStopSeq: start + 1,
      nativeTargetExecuted: true, finalSnapshotIncluded: true, stopReason: 'instruction-budget', ...extra } }).id;
  };
  const first = save('0x1000', 1), second = save('0x1001', 2);
  try {
    const joined = await joinRecordedTrace(cfg, [first, second], targetSha);
    await assert.rejects(joinRecordedTrace(cfg, [first, second], targetSha, 1), /instruction budget exceeded/);
    await assert.rejects(joinRecordedTrace(cfg, [first, second], targetSha, 100001), /instruction budget must/);
    assert.equal(joined.sources.length, 2); assert.equal(joined.data.toString().split('\n').filter(line => line.startsWith('f:')).length, 1);
    await assert.rejects(joinRecordedTrace(cfg, [first, first], targetSha), /distinct/);
    await assert.rejects(joinRecordedTrace(cfg, [first, save('0x1001', 2, { runId: 'other' })], targetSha), /not consecutive/);
    await assert.rejects(joinRecordedTrace(cfg, [first, save('0x1002', 2)], targetSha), /RIP continuation/);
    await assert.rejects(joinRecordedTrace(cfg, [first, save('0x1001', 2, {}, ['0x2', ...Array(15).fill('0x0')])], targetSha), /GPR/);
    await assert.rejects(joinRecordedTrace(cfg, [first, second], '0'.repeat(64)), /identity/);
    const jobs = new TraceJobs(cfg); jobs.jobs.run = async args => { assert.equal(args.traces[0].sha256, hashBytes(joined.data)); return { ok: true }; };
    try {
      const result = await jobs.run({ target, trace_chunk_reports: [first, second], trace_entry: '0x1000', trace_exit: '0x1001', trace_inputs: ['rcx', 'rdx'], trace_output: 'rax', initial_flags: '0x202' });
      assert.equal(result.joinedRecording.sources.length, 2);
      assert.equal(result.joinedRecording.nativeTargetExecutedByJoin, false);
      await assert.rejects(jobs.run({ target, trace_chunk_reports: [first], traces: [] }), /not both/);
    } finally { await jobs.dispose(); }
  } finally { await store.dispose(); }
});
