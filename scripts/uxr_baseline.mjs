// UXR-00: local metadata and deterministic fixtures only. Never starts an engine.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { apply } from '../index.js';
import { DelegationControl } from '../source/delegation_control.js';
import { collectFunctionDossier } from '../source/function_dossier.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const output = path.resolve(process.argv[2] || path.join(root, 'docs/uxr/baseline'));
fs.mkdirSync(output, { recursive: true });
const sha = data => createHash('sha256').update(data).digest('hex');
const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();
const files = [...new Set(git('ls-files', '--cached', '--others', '--exclude-standard').split('\n'))]
  .filter(name => /^(index\.js|client\.js|analysis_tools\.js|package\.json|AGENTS\.md|source\/|adapters\/ghidra\/worker\.py|scripts\/test_(delegation_control|function_dossier|address_ref|public_tool_catalog)\.mjs)/.test(name));
const baseline = { observedAt: new Date().toISOString(), head: git('rev-parse', 'HEAD'), status: git('status', '--short'),
  node: { executable: process.execPath, version: process.version },
  python: execFileSync('powershell', ['-NoProfile', '-Command', '(Get-Command python).Source'], { encoding: 'utf8' }).trim(),
  bundledPython: path.join(root, 'runtimes/ghidra/python/python.exe'),
  files: files.map(name => { const data = fs.readFileSync(path.join(root, name)); return { path: name, bytes: data.length, sha256: sha(data) }; }) };
fs.writeFileSync(path.join(output, 'workspace.json'), JSON.stringify(baseline, null, 2));
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-uxr-baseline-'));
const disposers = [], tools = new Map(), events = new Map();
const ctx = {
  tools: { register(def) { tools.set(def.name, def); return () => tools.delete(def.name); } },
  get(name) { return name === 'tools' ? this.tools : undefined; },
  on(name, fn) { const list = events.get(name) || []; list.push(fn); events.set(name, list); return () => {}; },
  inject(names, fn) { const remove = names.every(n => ctx.get(n)) ? fn(ctx) : undefined; const dispose = async () => { if (typeof remove === 'function') await remove(); }; disposers.push(dispose); return { dispose }; },
  effect(fn) { const remove = fn(); if (typeof remove === 'function') disposers.push(remove); },
};
try {
  apply(ctx, { artifactDir: path.join(scratch, 'artifacts'), projectRoot: path.join(scratch, 'projects'), stateRoot: path.join(scratch, 'state'), toolset: 'full', memory: false });
  assert.equal(tools.size, 41);
  fs.writeFileSync(path.join(output, 'tools.json'), JSON.stringify({ evidence: 'actual source registration in fixture host; not live DSH',
    core: ['doctor','open','status','funcs','strings','decompile','close','profile'].map(n => 'ig5_' + n),
    tools: [...tools.values()].map(d => ({ name: d.name, description: d.description, parameters: d.parameters })) }, null, 2));
  const control = new DelegationControl({ root: path.join(scratch, 'coordination') });
  let error;
  try { control.charge({ id: 'child', session: { header: { id: 'child', parentSession: 'missing' } } }, 'ig5_decompile', {}); }
  catch (e) { error = { code: e.code, message: e.message }; }
  assert.equal(error?.code, 'AGENT_LINEAGE_UNAVAILABLE');
  const session = { target: 'fixture', projectId: 'p', artifactId: 'a', sha256: 'a'.repeat(64), engine: 'ghidra', provider: 'ghidra', attachmentId: 'attach', dbRevision: 1,
    cache: new Map(), capabilities: ['decompile','cfg','calls','stack'], info: { analysisProfile: 'interactive', partial: false, analysisComplete: true } };
  let rpcCount = 0;
  const code = '/* 中文 */\n' + 'int f() { return 42; }\n'.repeat(3500);
  const mgr = { cfg: {}, checkCancelled() {}, get() { return session; }, alive() { return true; }, evidence() {
    return Object.fromEntries(['target','projectId','artifactId','sha256','engine','provider','attachmentId','dbRevision'].map(k => [k, session[k]]));
  }, async rpc(_s, method, args) { rpcCount++; return method === 'decompile' ? { ea: '0x1000', name: 'f', size: 64, code, lines: 3501 }
    : method === 'calls' ? { ea: '0x1000', direction: args.direction, total: 40, calls: Array.from({ length: args.limit }, (_, i) => ({ ea: '0x' + (8192+i).toString(16), name: 'callee' + i })) }
      : method === 'cfg' ? { ea: '0x1000', total_blocks: 0, total_edges: 0, blocks: [], edges: [] } : { ea: '0x1000', members: [], total_members: 0 }; } };
  const args = { ea: '0x1000', dossier_max_bytes: 14000 };
  const first = await collectFunctionDossier(mgr, session, args), firstCount = rpcCount;
  const second = await collectFunctionDossier(mgr, session, args);
  assert.equal(second.cache.hit, true); assert.equal(rpcCount, firstCount); assert(first.responseTruncated);
  const changed = await collectFunctionDossier(mgr, session, { ...args, dossier_max_bytes: 64000 });
  assert.equal(changed.cache.hit, false);
  fs.writeFileSync(path.join(output, 'fixtures.json'), JSON.stringify({ evidence: 'mock provider; no native or historical incident validation', missingParent: error,
    repeat: { firstHit: first.cache.hit, secondHit: second.cache.hit, firstRPCs: firstCount, repeatAdditionalRPCs: rpcCount-firstCount-5, changedBudgetHit: changed.cache.hit },
    large: { providerCodeBytes: Buffer.byteLength(code), responseBytes: Buffer.byteLength(JSON.stringify(first)), responseTruncated: first.responseTruncated, section: first.sections.decompile },
    partialCalls: first.sections.callees, originalSample: 'unknown; historical requests and matching SHA not supplied' }, null, 2));
  console.log(JSON.stringify({ output, tools: tools.size, missingParent: error, firstRPCs: firstCount, repeatHit: second.cache.hit, responseBytes: Buffer.byteLength(JSON.stringify(first)), providerCodeBytes: Buffer.byteLength(code) }));
} finally {
  for (const dispose of disposers.reverse()) await dispose();
  assert.equal(path.dirname(scratch), path.resolve(os.tmpdir())); assert(path.basename(scratch).startsWith('ig5-uxr-baseline-'));
  fs.rmSync(scratch, { recursive: true, force: true });
}
