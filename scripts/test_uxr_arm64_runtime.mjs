// Real static Ghidra acceptance; generated owned sample, no ARM64 execution.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { uxrHost } from './fixtures/uxr_host.mjs';
import { buildUXRArm64 } from './fixtures/uxr_arm64.mjs';

test('actual ARM64 ELF xrefs and all 72 persisted batch captures with shared charging', { timeout: 600000 }, async t => {
  const f = uxrHost(t), target = path.join(f.root, 'owned-arm64.elf'), fixture = buildUXRArm64();
  fs.writeFileSync(target, fixture.image);
  const agent = { id: 'uxr-arm64-root', session: { header: { id: 'uxr-arm64-root' } } };
  f.agents.set(agent.id, agent);
  const call = (name, args = {}) => f.call(name, { target, engine: 'ghidra', ...args }, agent);
  const budget = () => f.call('ig5_profile', { collaboration: { action: 'status' } }, agent);
  await f.call('ig5_profile', { collaboration: { action: 'start', max_calls: 200 } }, agent);
  await call('ig5_open', { path: target, background: false });
  const refs = await call('ig5_xrefs', { ea: fixture.functions[1] });
  assert(refs.hits.some(row => row.isCall === true && row.other === fixture.functions[0]));
  const converted = await call('ig5_profile', { address: { value: fixture.functions[0], space: 'elf_vaddr', to_space: 'file_offset' } });
  assert.equal(converted.value, '0x1000');
  const created = await call('ig5_decompile', { operation: 'batch', batch: { action: 'create', functions: fixture.functions } });
  const before = (await budget()).collaboration.used;
  let batch;
  for (let i = 0; i < 9; i++) {
    batch = await call('ig5_decompile', { operation: 'batch', batch: { action: 'run', id: created.id, max_items: 8 } });
    assert.equal(batch.counts.completed, (i + 1) * 8);
    console.log(`ARM64 batch ${batch.counts.completed}/72 saved`);
  }
  assert.equal((await budget()).collaboration.used - before, 72);
  assert.equal(batch.counts.failed, 0);
  assert.equal(new Set(batch.items.map(item => item.resultRef.id)).size, 72);
  for (const index of [0, 71]) {
    const page = await call('ig5_decompile', { operation: 'read', result_ref: batch.items[index].resultRef, section: 'decompile', page_max_bytes: 4000 });
    assert.equal(typeof page.data, 'string'); assert(page.data.length > 0);
  }
  const again = await call('ig5_decompile', { operation: 'batch', batch: { action: 'run', id: created.id, max_items: 8 } });
  assert.deepEqual(again.items.map(item => item.attempts), batch.items.map(item => item.attempts));
  await call('ig5_close');
});
