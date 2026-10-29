import assert from 'node:assert/strict';
import test from 'node:test';
import { defineAdvancedTools } from '../advanced_tools.js';

const fixture = (engine = 'reverse', reverseProvider = 'bundled') => {
  const selected = { engine }, calls = [];
  const mgr = { sessions: new Map([['one', selected]]), alive: value => value === selected,
    get: () => selected, rpc(...args) { calls.push(args); return { action: args[2].action, idb_modified: false }; } };
  return { tool: defineAdvancedTools(mgr, { reverseProvider, requestTimeoutMs: 321 }, () => '')
    .find(tool => tool.name === 'ig5_microcode'), calls, selected };
};

test('deobfuscate extends the existing read-only public schema with bounded evidence', () => {
  const { tool } = fixture();
  assert.deepEqual(tool.parameters.properties.action.enum, ['inspect', 'optimize', 'deobfuscate']);
  assert.equal(tool.parameters.properties.max_steps.type, 'integer');
  assert.equal(tool.parameters.properties.max_steps.maximum, 250000);
  assert.equal(tool.parameters.properties.max_evidence.maximum, 512);
  assert.equal(tool.parameters.additionalProperties, false);
});

test('bundled and explicit Ghidra route identical deobfuscation arguments through session RPC', () => {
  for (const engine of ['reverse', 'ghidra']) {
    const { tool, calls, selected } = fixture(engine);
    const args = { action: 'deobfuscate', ea: '0xffff800012345678', max_steps: 4000 };
    assert.equal(tool.execute(args).idb_modified, false);
    assert.deepEqual(calls, [[selected, 'microcode', args, 321]]);
  }
});

test('commercial or unsupported provider fails explicitly before worker RPC', () => {
  for (const [engine, provider] of [['reverse', 'commercial'], [undefined, 'commercial'], ['x64dbg', 'bundled']]) {
    const { tool, calls } = fixture(engine, provider);
    assert.throws(() => tool.execute({ target: 'opened', action: 'deobfuscate' }), /requires the bundled/);
    assert.equal(calls.length, 0);
  }
});
