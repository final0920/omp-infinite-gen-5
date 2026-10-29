// Real bundled native SSA through the public tool. No target execution or writes.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { apply } from '../index.js';
import { buildDeobfuscationPE64Fixture } from './fixtures/deobfuscation_pe64.mjs';

const output = path.join(os.homedir(), '.dsh', 'ig5', 'artifacts', 'deobfuscation-v110', randomUUID());
fs.mkdirSync(output, { recursive: true });
const fixture = buildDeobfuscationPE64Fixture(), target = path.join(output, 'synthetic-obfuscation.exe');
fs.writeFileSync(target, fixture.image, { flag: 'wx' });
const definitions = new Map(), effects = [], events = new Map();
const ctx = {
  tools: { register(def) { definitions.set(def.name, def); return () => definitions.delete(def.name); } },
  on(name, handler) { events.set(name, handler); return () => events.delete(name); },
  get() {}, inject(names, callback) { if (names.includes('webServer')) callback({ webServer: { register() { return () => {}; } } }); return { dispose() {} }; },
  effect(fn) { const dispose = fn(); if (typeof dispose === 'function') effects.push(dispose); },
};
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const root = fs.realpathSync(new URL('..', import.meta.url));
const files = ['advanced_tools.js', 'adapters/ghidra/microcode_analysis.py', 'adapters/ghidra/deobfuscation_analysis.py', 'adapters/ghidra/deobfuscation_symbolic.py', 'scripts/fixtures/deobfuscation_pe64.mjs', 'scripts/test_deobfuscation_runtime.mjs'];
const report = { kind: 'native-deobfuscation-acceptance', sourceRoot: root, sourceHashes: Object.fromEntries(files.map(file => [file, hash(fs.readFileSync(path.join(root, file)))])), fixture: { path: target, sha256: hash(fixture.image), addresses: fixture.addresses }, targetExecuted: false, databaseModified: false, checks: [] };
const call = (name, args = {}) => definitions.get(name).execute({ target, ...args }, { agent: { id: 'deobfuscation-runtime-test' }, signal: new AbortController().signal });
const pass = (label, data = {}) => { report.checks.push({ label, ...data }); console.log('PASS', label); };
try {
  apply(ctx, { toolset: 'full', reverseProvider: 'bundled', defaultEngine: 'reverse', reverse: false,
    artifactDir: path.join(output, 'analysis'), projectRoot: path.join(output, 'projects'), requestTimeoutMs: 120000, openTimeoutMs: 180000 });
  assert.equal(definitions.size, 43);
  const opened = await call('ig5_open', { path: target, background: false });
  assert.equal(opened.engine, 'reverse'); assert.equal(opened.provider, 'ghidra');
  const before = await call('ig5_bytes', { ea: fixture.addresses.dispatcher, size: 128 });
  pass('Synthetic PE opened in bundled native provider', { engine: opened.engine, provider: opened.provider, functions: opened.n_funcs });
  const analyze = async (name, args = {}) => {
    const result = await call('ig5_microcode', { ea: fixture.addresses[name], action: 'deobfuscate', ...args });
    fs.writeFileSync(path.join(output, `${name}${args.max_steps ? '-budget' : ''}.json`), JSON.stringify(result, null, 2));
    assert.equal(result.actualStage, 'firstpass'); assert.equal(result.action, 'deobfuscate');
    assert.equal(result.idb_modified, false); assert.equal(result.deobfuscation.executed, false);
    assert.equal(result.source.artifactSHA256, report.fixture.sha256);
    return result;
  };
  const parity = await analyze('opaqueParity');
  assert.equal(parity.deobfuscation.partial, false);
  assert(parity.deobfuscation.simplifications.some(item => item.rule === 'consecutive-integer-product-is-even'));
  assert(parity.deobfuscation.branchDecisions.length > 0); assert(parity.deobfuscation.unreachableBlocks.length > 0);
  pass('Algebraic opaque predicate proves and prunes a native SSA branch', { decisions: parity.deobfuscation.branchDecisions.length, unreachable: parity.deobfuscation.unreachableBlocks });
  const dispatcher = await analyze('dispatcher');
  assert.equal(dispatcher.deobfuscation.partial, false);
  assert(dispatcher.blocks.some(block => block.instructions.some(op => op.mnemonic === 'MULTIEQUAL')));
  assert(dispatcher.deobfuscation.dispatcherRoutes.length >= 2);
  assert(new Set(dispatcher.deobfuscation.dispatcherRoutes.map(item => item.destination)).size >= 2);
  pass('Flattened dispatcher has distinct proven incoming-state routes', { routes: dispatcher.deobfuscation.dispatcherRoutes });
  const unknown = await analyze('unresolvedMemory');
  assert(unknown.deobfuscation.unresolved.some(item => item.opcode === 'LOAD'));
  pass('Unknown memory remains explicit', { unresolved: unknown.deobfuscation.unresolved.length });
  for (const name of ['linearMba', 'booleanMba']) {
    const result = await analyze(name);
    assert(result.deobfuscation.expressionSimplifications.some(item => item.width === 32 && item.replacement.opcode === 'INT_XOR'));
    pass('Native ' + name + ' recovers an exact local XOR expression', { proofs: result.deobfuscation.expressionSimplifications });
  }
  const indirect = await analyze('indirectTarget');
  // Native Ghidra may represent a tail JMP as CALLIND followed by RETURN.
  assert(indirect.deobfuscation.indirectTransfers.some(item => ['BRANCHIND', 'CALLIND'].includes(item.opcode)));
  assert(indirect.deobfuscation.indirectTransfers.some(item => item.dependencies.some(op => op.opcode === 'LOAD')));
  assert.deepEqual(indirect.deobfuscation.branchDecisions, []);
  pass('Native indirect-target slice exposes memory dependence without inventing targets');
  const budget = await analyze('dispatcher', { max_steps: 1 });
  assert.equal(budget.deobfuscation.partial, true); assert.equal(budget.deobfuscation.budget.exhausted, true);
  assert.deepEqual(budget.deobfuscation.constants, []); assert.deepEqual(budget.deobfuscation.branchDecisions, []);
  pass('Work exhaustion withholds provisional proofs');
  const after = await call('ig5_bytes', { ea: fixture.addresses.dispatcher, size: 128 });
  assert.equal(after.hex, before.hex); assert.equal(hash(fs.readFileSync(target)), report.fixture.sha256);
  const status = await call('ig5_status');
  assert(status.sessions.every(session => session.dbRevision === 0));
  pass('Input file, database bytes and revision unchanged');
  report.ok = true;
} catch (error) {
  report.ok = false; report.error = { name: error.name, message: error.message }; throw error;
} finally {
  for (const dispose of effects.reverse()) await dispose();
  report.finishedAt = new Date().toISOString();
  fs.writeFileSync(path.join(output, 'receipt.json'), JSON.stringify(report, null, 2));
  console.log('RECEIPT', path.join(output, 'receipt.json'));
}
