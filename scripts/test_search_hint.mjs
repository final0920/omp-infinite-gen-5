// search 无方法卡命中、但已导入来源文档命中时,应提示改用 documents;其他情况不加 hint。
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runKnowledge } from '../source/knowledge_catalog.js';
import { documentIdentity } from '../source/knowledge_documents.js';
import { knowledgeHash } from '../source/knowledge_io.js';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-hint-'));
try {
  const body = 'Zorkmid obfuscation notes: a source document body used only by this test.';
  const sourceUrl = 'https://example.com/zorkmid';
  const contentSha256 = knowledgeHash(body);
  const doc = { schema: 'ig5-source-document-v1', id: documentIdentity(sourceUrl, contentSha256), title: 'Zorkmid notes', author: 'test',
    sourceUrl, publishedAt: null, retrievedAt: '2026-10-24T00:00:00Z', contentSha256, license: 'test-only', rightsStatus: 'local-reference-only',
    methodIds: [], reviewNotes: ['fixture'], body };
  fs.mkdirSync(path.join(root, 'knowledge-v1'), { recursive: true });
  fs.writeFileSync(path.join(root, 'knowledge-v1', 'catalog.json'), JSON.stringify({ schema: 'ig5-knowledge-catalog-v1', cards: [], documents: [doc] }));
  const cfg = { projectRoot: root };

  const s = runKnowledge(cfg, { action: 'search', query: 'zorkmid' });
  assert.equal(s.total, 0);
  assert.equal(s.hint?.code, 'TRY_DOCUMENTS');
  assert.equal(s.hint.documentMatches, 1);

  const d = runKnowledge(cfg, { action: 'documents', query: 'zorkmid' });
  assert.equal(d.total, 1);
  assert.equal(d.hint, undefined);

  const none = runKnowledge(cfg, { action: 'search', query: 'qqqqnomatchqqqq' });
  assert.equal(none.total, 0);
  assert.equal(none.hint, undefined);

  const hit = runKnowledge(cfg, { action: 'search', query: 'msynth' });
  assert.ok(hit.total >= 1);
  assert.equal(hit.hint, undefined);
  console.log('test_search_hint: PASS');
} finally { fs.rmSync(root, { recursive: true, force: true }); }
