import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { uxrHost } from './fixtures/uxr_host.mjs';
import { buildUXRLargeArm64 } from './fixtures/uxr_large_arm64.mjs';

test('actual ARM64 large function reassembles all saved UTF-8 pages', { timeout: 180000 }, async t => {
  const f = uxrHost(t), fixture = buildUXRLargeArm64(), target = path.join(f.root, 'large-arm64.elf');
  fs.writeFileSync(target, fixture.image);
  const call = (name, args = {}) => f.call(name, { engine: 'ghidra', target, ...args }, { id: 'large-runtime' });
  await call('ig5_open', { path: target, background: false });
  const dossier = await call('ig5_decompile', { ea: fixture.ea, style: 'dossier', dossier_max_bytes: 4000 });
  assert(dossier.savedResult);
  let cursor, digest, pages = 0, offset = 0;
  const chunks = [];
  do {
    const page = await call('ig5_decompile', { operation: 'read', result_ref: dossier.savedResult, section: 'decompile', page_max_bytes: 4000, ...(cursor ? { cursor } : {}) });
    assert.equal(page.offset, offset); offset = page.nextOffset;
    assert(Buffer.byteLength(JSON.stringify(page)) <= 4000);
    chunks.push(page.data); digest = page.contentSha256; cursor = page.nextCursor; pages++;
  } while (cursor);
  const code = chunks.join('');
  assert(pages > 1); assert(Buffer.byteLength(code) > 4000);
  assert.equal(createHash('sha256').update(code).digest('hex'), digest);
  console.log(JSON.stringify({ pages, bytes: Buffer.byteLength(code), digest }));
  await call('ig5_close');
});
