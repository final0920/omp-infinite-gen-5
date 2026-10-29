// Real Ghidra + public read-only tool wrappers. Loading/SSA are not devirtualization.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { apply } from '../index.js';

const root = path.resolve(import.meta.dirname, '..');
const base = process.env.IG5_CORPUS_EVIDENCE || 'C:/Users/IG5User/.dsh/ig5/artifacts/corpus-expansion-20261014';
const corpus = process.env.IG5_PROTECTION_CORPUS || path.join(base, 'corpus');
const output = path.join(base, 'native-static');
fs.mkdirSync(output, { recursive: true });
const pins = JSON.parse(fs.readFileSync(path.join(root, 'scripts/fixtures/protection_corpus.json'), 'utf8')).files;
const selected = [
  ...[0, 1, 2, 3, 4].map(level => `tigress/tigress-challenges/tigress-${level}-challenge-0`),
  'vmp-research/test1/test.vmp.exe',
  ...pins.filter(p => p.file.startsWith('vmp-lab/Challenge/') && p.file.endsWith('.exe')).map(p => p.file),
  ...pins.filter(p => p.archiveMember === 'no_protections_packed_vmp1.exe').map(p => p.file),
  ...pins.filter(p => /2026.*Windows 高级题|2025.*Windows 高级题.*solly|crackme2024service/.test(p.archiveMember || '')).map(p => p.file),
];
const hash = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
for (const relative of selected) { const pin = pins.find(p => p.file === relative); assert(pin); assert.equal(hash(path.join(corpus, relative)), pin.sha256); }
const definitions = new Map(), effects = [];
const ctx = { tools: { register(d) { definitions.set(d.name, d); return () => definitions.delete(d.name); } },
  on() { return () => {}; }, get() {},
  inject(names, callback) { if (names.includes('webServer')) callback({ webServer: { register() { return () => {}; } } }); return { dispose() {} }; },
  effect(callback) { const dispose = callback(); if (typeof dispose === 'function') effects.push(dispose); },
};
const call = (name, args) => definitions.get(name).execute(args, { agent: { id: 'expanded-native-static-test' }, signal: new AbortController().signal });
const receipt = { pluginRoot: root, sourceHashes: Object.fromEntries(['worker/trace_analysis.py', 'adapters/ghidra/deobfuscation_analysis.py', 'scripts/fixtures/protection_corpus.json'].map(f => [f, hash(path.join(root, f))])),
  nativeTargetExecuted: false, businessLogicRecovered: false, rows: [], limits: ['At most 128 discovered functions; selected main or largest listed function is not proof of VM entry.', 'Static import and local SSA analysis do not prove protected business logic.'] };
const save = () => fs.writeFileSync(path.join(output, 'receipt.json'), JSON.stringify(receipt, null, 2));
apply(ctx, { toolset: 'full', reverse: false, reverseProvider: 'bundled', artifactDir: path.join(output, 'analysis'), projectRoot: path.join(output, 'projects'), requestTimeoutMs: 90000, openTimeoutMs: 120000 });
assert.equal(definitions.size, 43);
try {
  for (const relative of selected) {
    const pin = pins.find(p => p.file === relative), target = path.join(corpus, relative);
    const row = { file: relative, sha256: pin.sha256, archiveMember: pin.archiveMember, nativeTargetExecuted: false, businessLogicRecovered: false };
    receipt.rows.push(row); save(); console.log('ANALYZE ' + relative);
    const started = performance.now(); let opened = false;
    try {
      const result = await call('ig5_open', { path: target, background: false, analysis_profile: 'interactive', analysis_timeout: 20 });
      opened = true; assert.equal(result.provider, 'ghidra');
      row.opened = { provider: result.provider, functions: result.n_funcs, partial: result.partial, analysis: result.analysis };
      const list = await call('ig5_funcs', { target, limit: 128 });
      const funcs = list.funcs || list.functions || list.items || [];
      const chosen = funcs.find(f => f.name === 'main') || [...funcs].sort((a, b) => (b.size || 0) - (a.size || 0))[0];
      if (!chosen) throw new Error('No discovered function in bounded listing');
      row.functionSelection = { discoveredInPage: funcs.length, policy: 'main, else largest of first 128 discovered functions', chosen };
      const ea = chosen.ea || chosen.address || chosen.start;
      const analysis = await call('ig5_microcode', { target, ea, action: 'deobfuscate', max_steps: 25000, timeout: 25 });
      assert.equal(analysis.idb_modified, false); assert.equal(analysis.deobfuscation.executed, false);
      assert.equal(analysis.source.artifactSHA256, pin.sha256);
      const d = analysis.deobfuscation;
      if (d.controlFlowIncomplete) { assert.deepEqual(d.branchDecisions, []); assert.deepEqual(d.unreachableBlocks, []); }
      row.ssa = { ea, blocks: analysis.total_blocks, returnedInstructions: analysis.returned_instructions, partial: d.partial,
        controlFlowIncomplete: d.controlFlowIncomplete, unresolved: d.unresolved.length, localExpressionProofs: d.expressionSimplifications?.length || 0,
        branchProofs: d.branchDecisions.length, exhausted: d.budget.exhausted, evidenceTruncated: d.evidenceTruncated };
      fs.writeFileSync(path.join(output, pin.sha256 + '-ssa.json'), JSON.stringify(analysis, null, 2));
      row.status = d.partial || d.controlFlowIncomplete ? 'static-partial' : 'selected-ssa-complete';
      const status = await call('ig5_status', { target }); assert(status.sessions.every(s => s.dbRevision === 0));
      assert.equal(hash(target), pin.sha256);
    } catch (error) { row.status = 'failed'; row.error = error.message; }
    finally {
      if (opened) try { await call('ig5_close', { target }); } catch (error) { row.closeError = error.message; }
      row.elapsedMs = Math.round(performance.now() - started); save(); console.log(JSON.stringify(row));
    }
  }
} finally { for (const dispose of effects.reverse()) await dispose(); save(); }
