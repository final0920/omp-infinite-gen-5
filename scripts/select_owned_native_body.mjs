// Explicitly select the body AFTER a saved initial debugger stop with no
// observed JMP transition. Preserve all raw data; do not delete internal VM
// instructions or override any register/flag/input value.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { TraceJobs } from '../source/trace_jobs.js';
import { runtimeConfiguration } from '../engine_runtime.js';
const folder = path.resolve(process.argv[2] || '');
if (!process.argv[2]) throw new Error('Supply owned completed-native receipt folder');
const receipt = JSON.parse(fs.readFileSync(path.join(folder, 'receipt.json'), 'utf8'));
if (receipt.parts.at(-1).summary.stopReason !== 'until-address') throw new Error('Native body did not reach the explicit return boundary');
const filename = path.join(folder, 'joined.trace'), raw = fs.readFileSync(filename), rows = raw.toString('ascii').trimEnd().split('\n');
const frames = rows.map((row, index) => row.startsWith('r:') ? index : -1).filter(index => index >= 0);
if (frames.length < 2 || rows[frames[0]] !== rows[frames[1]]) throw new Error('Initial GPR snapshots are not identical');
const firstInstruction = rows.slice(frames[0], frames[1]).find(row => row.startsWith('i:'));
const secondInstruction = rows.slice(frames[1], frames[2]).find(row => row.startsWith('i:'));
if (firstInstruction !== secondInstruction || !firstInstruction.split(':')[3].startsWith('e9')) throw new Error('Initial opcode/address are not the same direct JMP');
const selected = Buffer.from([...rows.slice(0, frames[0]), ...rows.slice(frames[1])].join('\n') + '\n', 'ascii');
const output = path.join(folder, 'body-after-initial-stop.trace'), hash = data => createHash('sha256').update(data).digest('hex');
fs.writeFileSync(output, selected);
const selection = { source: filename, sourceSha256: hash(raw), selected: output, selectedSha256: hash(selected),
  skippedInitialSnapshots: 1, internalInstructionsRemoved: 0, inputRegistersUnchanged: true,
  scope: 'body after an initial unchanged debugger stop; no claim that the discarded observation retired an instruction or that hidden execution was absent' };
fs.writeFileSync(path.join(folder, 'body-selection.json'), JSON.stringify(selection, null, 2));
const jobs = new TraceJobs({ ...runtimeConfiguration({}), artifactDir: folder });
try {
  const args = { target: receipt.target, traces: [{ path: output, sha256: hash(selected) }], trace_entry: secondInstruction.split(':')[1],
    trace_exit: receipt.parts.at(-1).summary.exit, trace_inputs: receipt.generatedCase.inputs, trace_output: receipt.generatedCase.output,
    initial_flags: rows[frames[1] + 1].slice(2), trace_runtime_base: receipt.runtimeBase };
  const result = await jobs.run(args);
  fs.writeFileSync(path.join(folder, 'body-recovery.json'), JSON.stringify({ selection, args, result }, null, 2));
  console.log(JSON.stringify({ expression: result.recoveredExpression, coverage: result.coverage, instructions: result.paths[0].instructionCount,
    finalSnapshot: result.paths[0].finalSnapshotVerified, observed: result.paths[0].observedOutput, binding: result.paths[0].binaryBinding }));
} finally { await jobs.dispose(); }
