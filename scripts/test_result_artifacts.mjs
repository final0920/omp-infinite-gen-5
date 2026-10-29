import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ResultArtifacts, RESULT_LIMITS } from '../source/result_artifacts.js';
import { hashBytes } from '../source/analysis_artifacts.js';
import { collectFunctionDossier } from '../source/function_dossier.js';

const provenance = { target: 'fixture', projectId: 'p', artifactId: 'a', sha256: 'a'.repeat(64), engine: 'ghidra', provider: 'ghidra', attachmentId: 'attach', dbRevision: 1 };
function fixture(t, options) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-uxr-result-'));
  const store = new ResultArtifacts(root, options);
  t.after(() => { assert.equal(path.dirname(root), path.resolve(os.tmpdir())); assert(path.basename(root).startsWith('ig5-uxr-result-')); fs.rmSync(root, { recursive: true, force: true }); });
  const sections = { decompile: { status: 'ok', data: { ea: '0x1000', code: '中😀文\\\"\n'.repeat(12000) }, provider: { completeness: 'complete' } },
    cfg: { status: 'ok', data: { blocks: Array.from({ length: 200 }, (_, i) => ({ id: i, text: '块'.repeat(60) })), edges: [], total_blocks: 200 } } };
  return { root, store, sections, save: (sectionsOverride = sections) => store.save({ provenance, query: { ea: '0x1000' }, sections: sectionsOverride }) };
}
function pages(store, ref, section, format) {
  const result = []; let cursor;
  do {
    const page = store.read(ref, provenance, { section, format, cursor, page_max_bytes: 4000 });
    assert(Buffer.byteLength(JSON.stringify(page)) <= 4000);
    assert.equal(page.offset, result.at(-1)?.nextOffset || 0);
    result.push(page); cursor = page.nextCursor ?? undefined;
    assert(result.length < 500);
  } while (cursor);
  return result;
}

test('UTF-8 pages and stable records reassemble exactly, including escaped text and final page', t => {
  const f = fixture(t), ref = f.save();
  const text = pages(f.store, ref, 'decompile');
  assert.equal(text.map(p => p.data).join(''), f.sections.decompile.data.code);
  assert.equal(hashBytes(Buffer.from(text.map(p => p.data).join(''))), text[0].contentSha256);
  assert.equal(text.at(-1).completeness.response, 'complete');
  const records = pages(f.store, ref, 'cfg'), joined = records.flatMap(p => p.data);
  assert.equal(joined.filter(r => r.index !== undefined).length, 200);
  assert.equal(hashBytes(Buffer.from(JSON.stringify(joined))), records[0].contentSha256);
  const json = pages(f.store, ref, 'cfg', 'json-text').map(p => p.data).join('');
  assert.deepEqual(JSON.parse(json), f.sections.cfg);
  const reloaded = new ResultArtifacts(f.root);
  assert.deepEqual(reloaded.read(ref, provenance, { section: 'decompile', cursor: text[0].nextCursor, page_max_bytes: 4000 }), text[1]);
});

test('cursor tampering, section/target/ref switching, missing commit, digest corruption and stale revisions reject', t => {
  const f = fixture(t), ref = f.save(), page = f.store.read(ref, provenance, { section: 'decompile', page_max_bytes: 4000 });
  assert.throws(() => f.store.read(ref, provenance, { section: 'decompile', cursor: page.nextCursor + 'x' }), { code: 'RESULT_CURSOR_INVALID' });
  assert.throws(() => f.store.read(ref, provenance, { section: 'cfg', cursor: page.nextCursor }), { code: 'RESULT_CURSOR_INVALID' });
  for (const key of Object.keys(provenance)) assert.throws(() => f.store.read(ref, { ...provenance, [key]: key === 'dbRevision' ? 2 : 'other' }, { section: 'cfg' }), { code: 'RESULT_STALE' });
  assert.throws(() => f.store.read({ ...ref, id: '../path' }, provenance, { section: 'cfg' }), { code: 'RESULT_REF_INVALID' });
  assert.throws(() => f.store.read({ ...ref, sha256: '0'.repeat(64) }, provenance, { section: 'cfg' }), { code: 'RESULT_DIGEST_MISMATCH' });
  fs.appendFileSync(path.join(f.root, 'data/records', ref.id + '.json'), ' ');
  assert.throws(() => f.store.read(ref, provenance, { section: 'cfg' }), { code: 'RESULT_CORRUPT' });
  fs.unlinkSync(path.join(f.root, 'data/metadata', ref.id + '.json'));
  assert.throws(() => f.store.read(ref, provenance, { section: 'cfg' }), { code: 'RESULT_COMMIT_MISSING' });
});

test('item, task and disk limits include abandoned stages; expired owned files clean without touching foreign paths', t => {
  let now = Date.now(); const f = fixture(t, { now: () => now });
  assert.throws(() => f.save({ decompile: { data: { code: 'x'.repeat(RESULT_LIMITS.itemBytes) } } }), { code: 'RESULT_ITEM_LIMIT' });
  const large = { decompile: { status: 'ok', data: { code: 'a'.repeat(900000) } } };
  for (let i = 0; i < 9; i++) f.save(large);
  assert.throws(() => f.save(large), { code: 'RESULT_STORAGE_LIMIT' });
  const ref = f.save({});
  now += RESULT_LIMITS.retentionMs + 1;
  assert.throws(() => f.store.read(ref, provenance, { section: 'cfg' }), { code: 'RESULT_EXPIRED' });
  f.save({});
  assert.equal(fs.existsSync(path.join(f.root, 'data/records', ref.id + '.json')), false);
  const abandoned = path.join(f.root, 'data/records', 'abandoned.partial');
  const fd = fs.openSync(abandoned, 'wx'); fs.ftruncateSync(fd, RESULT_LIMITS.totalBytes); fs.closeSync(fd);
  assert.throws(() => f.save({}), { code: 'RESULT_STORAGE_LIMIT' });
});

test('oversized stable record has a bounded JSON-text recovery path; empty sections finish in one page', t => {
  const f = fixture(t), sections = { cfg: { status: 'ok', data: { blocks: [{ text: '超'.repeat(40000) }] } }, stack: { status: 'unsupported' } }, ref = f.save(sections);
  assert.throws(() => pages(f.store, ref, 'cfg'), { code: 'RESULT_RECORD_TOO_LARGE' });
  assert.deepEqual(JSON.parse(pages(f.store, ref, 'cfg', 'json-text').map(p => p.data).join('')), sections.cfg);
  assert.equal(pages(f.store, ref, 'stack').length, 1);
});

test('dossier preserves legacy fields, saves before display trimming, and discloses source partial independently', async t => {
  const f = fixture(t), session = { ...provenance, cache: new Map(), capabilities: ['decompile', 'cfg', 'calls', 'stack'], info: {} };
  let rpcs = 0;
  const mgr = { functionResults: f.store, alive: () => true, checkCancelled() {}, get: () => session, evidence: () => provenance,
    async rpc(_s, method) { rpcs++; return { ea: '0x1000', name: 'f', ...(method === 'decompile' ? { code: f.sections.decompile.data.code, complete: true }
      : method === 'calls' ? { total: 200, calls: [{ ea: '0x2000' }] } : method === 'cfg' ? f.sections.cfg.data : { members: [] }) }; } };
  const result = await collectFunctionDossier(mgr, session, { ea: '0x1000', dossier_max_bytes: 4000 });
  assert(result.savedResult); assert(Buffer.byteLength(JSON.stringify(result)) <= 4000);
  assert.equal(result.sections.decompile.completeness.provider, 'complete'); assert.equal(result.sections.decompile.completeness.response, 'partial');
  assert.equal(result.sections.callees.completeness.provider, 'partial'); assert.equal(result.sections.callees.completeness.stored, 'complete');
  assert.equal(pages(f.store, result.savedResult, 'decompile').map(p => p.data).join(''), f.sections.decompile.data.code);
  assert.equal((await collectFunctionDossier(mgr, session, { ea: '0x1000', dossier_max_bytes: 4000 })).cache.hit, true); assert.equal(rpcs, 5);
  assert.equal((await collectFunctionDossier(mgr, session, { ea: '0x1000', dossier_max_bytes: 8000 })).cache.reason, 'view_budget_changed');
  assert.equal((await collectFunctionDossier(mgr, session, { ea: '0x1000', refresh: true })).cache.reason, 'explicit_refresh');
  session.info.analysisComplete = false;
  assert.equal((await collectFunctionDossier(mgr, session, { ea: '0x1000' })).cache.reason, 'analysis_state_changed');
});

test('incomplete publication never returns a ref; hardlinked commits and linked roots reject', t => {
  const f=fixture(t), original=f.store.artifacts.save.bind(f.store.artifacts);
  f.store.artifacts.save=()=>{throw Object.assign(new Error('disk interruption'),{code:'ENOSPC'});};
  assert.throws(()=>f.save(),{code:'ENOSPC'});assert.equal(f.store.find(provenance,'missing'),null);
  f.store.artifacts.save=original;const ref=f.save();
  const record=path.join(f.root,'data/records',ref.id+'.json');fs.linkSync(record,path.join(f.root,'foreign-hardlink'));
  assert.throws(()=>f.store.read(ref,provenance,{section:'cfg'}),{code:'RESULT_CORRUPT'});
  const alias=path.join(f.root,'alias');fs.symlinkSync(path.join(f.root,'data'),alias,'junction');
  assert.throws(()=>new ResultArtifacts(path.join(alias,'child')),{code:'RESULT_PATH_INVALID'});
});
