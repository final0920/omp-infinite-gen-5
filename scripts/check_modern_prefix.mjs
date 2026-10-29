// Offline diagnostic of captured OWN modern target prefixes; no target launch.
import fs from 'node:fs';
import path from 'node:path';
import { TraceJobs } from '../source/trace_jobs.js';
import { runtimeConfiguration } from '../engine_runtime.js';
const folder = process.argv[2];
if (!folder) throw new Error('Supply an owned native receipt folder');
const receipt = JSON.parse(fs.readFileSync(path.join(folder, 'receipt.json'), 'utf8'));
const recordings = receipt.calls.filter(call => call.result.traceSaved).map(call => call.result);
if (!recordings.length) throw new Error('No native recording to diagnose');
const jobs = new TraceJobs({ ...runtimeConfiguration({}), artifactDir: folder, projectRoot: path.join(folder, 'projects') });
const run = jobs.jobs.run.bind(jobs.jobs);
jobs.jobs.run = async args => { fs.writeFileSync(path.join(folder, 'offline-request.json'), JSON.stringify(args)); return run(args); };
try {
  const args = { target: receipt.target, level: 'trace', trace_chunk_reports: recordings.map(result => result.traceReportId),
    trace_entry: recordings[0].traceSummary.entry, trace_exit: recordings.at(-1).traceSummary.exit,
    trace_inputs: receipt.generatedCase.inputs, trace_output: receipt.generatedCase.output, initial_flags: recordings[0].traceSummary.initialFlags };
  const result = await jobs.run(args);
  fs.writeFileSync(path.join(folder, 'prefix-diagnostic.json'), JSON.stringify({ completeFunctionClaimed: false, args, result }, null, 2));
  console.log(JSON.stringify({ instructions: result.paths[0].instructionCount, observed: result.paths[0].observedOutput, expression: result.paths[0].outputExpression, coverage: result.coverage, fullFunctionProved: false }));
} catch (error) {
  fs.writeFileSync(path.join(folder, 'prefix-diagnostic.json'), JSON.stringify({ completeFunctionClaimed: false, error: error.message }, null, 2));
  throw error;
} finally { await jobs.dispose(); }
