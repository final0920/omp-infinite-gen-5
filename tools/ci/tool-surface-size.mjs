// Model-visible tool-surface budget. Registers the real definitions against a
// throwaway context, then measures name + description + parameters the way the
// host serializes them. Tokens are estimated as UTF-8 JSON characters / 4 (a
// conservative cross-tokenizer approximation, not a claim about any one model).
// No engine, sample, network or user project is touched.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { apply } from '../../index.js';
import { CORE_TOOL_NAMES } from '../../workflow.js';
import { ALL_TOOLS } from '../../scripts/fixtures/tool_classification.mjs';

const CORE_BUDGET = 4000;
const TOOL_BUDGET = 4000;

const scratch = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-tool-surface-'));
const definitions = new Map();
const ctx = {
  tools: { register(definition) { definitions.set(definition.name, definition); return () => definitions.delete(definition.name); } },
  on() { return () => {}; },
  get(name) { return name === 'approval' ? { request: async () => 'allowed-once' } : undefined; },
  inject(names, callback) { if (names.includes('webServer')) callback({ webServer: { register() { return () => {}; } } }); return { dispose() {} }; },
  effect(body) { const dispose = body(); if (typeof dispose === 'function') return { dispose }; },
};

const measure = name => {
  const definition = definitions.get(name);
  const characters = JSON.stringify({ name: definition.name, description: definition.description, parameters: definition.parameters }).length;
  return { name, characters, tokens: Math.ceil(characters / 4) };
};

let failure;
try {
  apply(ctx, { artifactDir: path.join(scratch, 'artifacts'), projectRoot: path.join(scratch, 'projects'),
    toolset: 'full', reverseProvider: 'bundled', defaultEngine: 'reverse', backgroundOpen: false });
  const registered = [...definitions.keys()].sort();
  const classified = [...ALL_TOOLS].sort();
  if (registered.join() !== classified.join()) {
    throw new Error(`registered tools differ from the reviewed classification fixture: missing=${classified.filter(n => !definitions.has(n)).join(',') || '-'} extra=${registered.filter(n => !classified.includes(n)).join(',') || '-'}`);
  }
  const rows = registered.map(measure);
  const core = CORE_TOOL_NAMES.map(measure);
  const coreTotal = core.reduce((sum, row) => sum + row.tokens, 0);
  // The portable package advertises the tool count in its manifest and INSTALL.txt.
  // Keep both numeric claims tied to the actually registered surface.
  const packageScript = fs.readFileSync(path.resolve(import.meta.dirname, '../../scripts/package_portable.ps1'), 'utf8');
  for (const [label, pattern] of [
    ['manifest publicToolCount', /publicToolCount = (\d+)/],
    ['INSTALL.txt tool count', /(\d+) public tools include/],
  ]) {
    const declared = Number((packageScript.match(pattern) || [])[1]);
    if (declared !== rows.length) throw new Error(`scripts/package_portable.ps1 ${label} is ${declared || 'missing'}, registered tools are ${rows.length}`);
  }
  const profile = definitions.get('ig5_profile');
  if ('workspace' in profile.parameters.properties || 'recovery' in profile.parameters.properties) {
    throw new Error('ig5_profile must not re-expose workspace/recovery parameters after the P2 split');
  }
  for (const name of ['ig5_workspace', 'ig5_recovery']) {
    if (!definitions.has(name)) throw new Error(name + ' must be registered');
  }
  for (const [name, argument, expected] of [
    ['ig5_profile', { workspace: { action: 'list' } }, 'Use ig5_workspace'],
    ['ig5_profile', { recovery: { observations: {} } }, 'Use ig5_recovery'],
  ]) {
    let message = '';
    try { await definitions.get(name).execute(argument, {}); }
    catch (error) { message = String(error.message); }
    if (!message.includes(expected)) throw new Error(`${name} must reject the split parameter with "${expected}", got "${message}"`);
  }
  for (const row of [...rows].sort((a, b) => b.tokens - a.tokens)) {
    console.log(String(row.tokens).padStart(5), String(row.characters).padStart(6), row.name);
  }
  console.log(`core ${CORE_TOOL_NAMES.length} tools: ${coreTotal} tokens (${core.map(row => row.name + '=' + row.tokens).join(', ')})`);
  const over = rows.filter(row => row.tokens > TOOL_BUDGET);
  if (coreTotal > CORE_BUDGET) throw new Error(`Core tool surface is ${coreTotal} tokens, over the ${CORE_BUDGET} budget`);
  if (over.length) throw new Error(`tool surface over the ${TOOL_BUDGET}-token per-tool budget: ${over.map(row => `${row.name}=${row.tokens}`).join(', ')}`);
  console.log(`PASS tool surface: full ${rows.length} tools, core ${coreTotal}/${CORE_BUDGET} tokens, largest ${rows.reduce((a, b) => a.tokens >= b.tokens ? a : b).name}`);
} catch (error) {
  failure = error;
  console.error('FAIL', error.message);
} finally {
  try {
    const relative = path.relative(fs.realpathSync(os.tmpdir()), fs.realpathSync(scratch));
    if (relative.startsWith('ig5-tool-surface-') && !relative.includes(path.sep)) fs.rmSync(scratch, { recursive: true, force: true });
  } catch {}
}
if (failure) process.exitCode = 1;
