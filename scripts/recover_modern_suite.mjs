// Revalidate a complete OWN native recording through the public readonly tool.
// The failed native receipt remains intact; no reference expression is supplied.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { apply } from '../index.js';
const folder = path.resolve(process.argv[2] || '');
assert(process.argv[2], 'Supply a completed owned native suite receipt');
const receiptPath = path.join(folder, 'receipt.json'), bytes = fs.readFileSync(receiptPath), receipt = JSON.parse(bytes);
const hash = data => createHash('sha256').update(data).digest('hex');
assert(['owned-compiled-suite-c-v1', 'owned-packed-suite-c-v1', 'owned-enigma-suite-c-v1', 'owned-enigma-suite-c-v2'].includes(receipt.generatedCase.recipe));
assert.equal(receipt.parts.at(-1).summary.stopReason, 'until-address');
assert.equal(receipt.targetUnchanged, true); assert.equal(hash(fs.readFileSync(receipt.target)), receipt.generatedCase.targetSha256);
const definitions = new Map(), effects = [];
const ctx = { tools: { register(d) { definitions.set(d.name, d); return () => definitions.delete(d.name); } }, get() {}, on() {},
  inject() { return { dispose() {} }; }, effect(callback) { const dispose = callback(); if (typeof dispose === 'function') effects.push(dispose); } };
apply(ctx, { reverse: false, toolset: 'full', artifactDir: folder, projectRoot: path.join(folder, 'projects') });
try {
  const args = { target: receipt.target, level: 'trace', trace_chunk_reports: receipt.parts.map(row => row.reportId),
    trace_entry: receipt.parts[0].summary.entry, trace_exit: receipt.parts.at(-1).summary.exit,
    trace_inputs: receipt.generatedCase.inputs, trace_output: receipt.generatedCase.output, initial_flags: receipt.parts[0].summary.initialFlags,
    max_instructions: receipt.maxInstructions ?? 50000 };
  const result = await definitions.get('ig5_ir').execute(args, { agent: { id: 'owned-modern-suite-readonly-validation' } });
  fs.writeFileSync(path.join(folder, 'revalidation.json'), JSON.stringify({ sourceReceiptSha256: hash(bytes), args, result }, null, 2));
  console.log(JSON.stringify({ ok: result.ok, coverage: result.coverage, expression: result.recoveredExpression,
    instructions: result.paths[0].instructionCount, reportId: result.reportId, reportSha256: result.reportSha256 }));
} finally { for (const dispose of effects.reverse()) await dispose(); }
