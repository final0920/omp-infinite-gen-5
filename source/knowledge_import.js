// Maintenance-only, explicit local import. This module is not loaded by the host.
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { KNOWLEDGE_LIMITS, validateKnowledgeCatalog } from './knowledge_catalog.js';
import { DOCUMENT_LIMITS, documentIdentity, validateKnowledgeDocument } from './knowledge_documents.js';
import { assertKnowledgePath, readKnowledgeBytes, decodeKnowledgeText, knowledgeHash, knowledgeFail as fail } from './knowledge_io.js';

const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
export function prepareKnowledgeImport({ manifestPath, inputRoot }) {
  if (typeof manifestPath !== 'string' || !path.isAbsolute(manifestPath) || typeof inputRoot !== 'string' || !path.isAbsolute(inputRoot)) fail('INVALID_IMPORT_ARGUMENT', 'Manifest and input root must be explicit absolute paths');
  assertKnowledgePath(inputRoot);
  if (!fs.statSync(inputRoot).isDirectory()) fail('INVALID_IMPORT_ARGUMENT', 'Input root must be a directory');
  const bytes = readKnowledgeBytes(manifestPath, 65536);
  let manifest; try { manifest = JSON.parse(decodeKnowledgeText(bytes)); } catch { fail('INVALID_IMPORT_MANIFEST', 'Import manifest must be UTF-8 JSON'); }
  if (!plain(manifest) || Object.keys(manifest).sort().join(',') !== 'documents,schema' || manifest.schema !== 'ig5-research-import-v1'
    || !Array.isArray(manifest.documents) || !manifest.documents.length || manifest.documents.length > DOCUMENT_LIMITS.documents) fail('INVALID_IMPORT_MANIFEST', 'Invalid bounded import manifest');
  const root = path.resolve(inputRoot), records = [];
  const fields = ['path','title','author','sourceUrl','publishedAt','retrievedAt','expectedSha256','license','rightsStatus','methodIds','reviewNotes'];
  for (const item of manifest.documents) {
    if (!plain(item) || Object.keys(item).some(k => !fields.includes(k)) || fields.some(k => !(k in item)) || typeof item.path !== 'string'
      || !/\.(md|txt)$/i.test(item.path) || item.path.includes('\\') || item.path.startsWith('/') || item.path.includes(':')
      || item.path.split('/').some(p => !p || p === '.' || p === '..') || !/^[a-f0-9]{64}$/.test(item.expectedSha256)) fail('INVALID_IMPORT_MANIFEST', 'Use a relative Markdown/text path and exact SHA-256');
    const full = path.resolve(root, item.path);
    if (!full.startsWith(root + path.sep)) fail('INVALID_IMPORT_MANIFEST', 'Import path escapes its input root');
    const bodyBytes = readKnowledgeBytes(full, DOCUMENT_LIMITS.bodyBytes);
    if (knowledgeHash(bodyBytes) !== item.expectedSha256) fail('IMPORT_CONTENT_MISMATCH', 'Research input bytes do not match the reviewed manifest');
    const { path: _path, expectedSha256, ...metadata } = item;
    const document = validateKnowledgeDocument({ schema: 'ig5-source-document-v1', id: documentIdentity(item.sourceUrl, expectedSha256),
      ...metadata, contentSha256: expectedSha256, body: decodeKnowledgeText(bodyBytes) });
    records.push(document);
  }
  if (new Set(records.map(d => d.id)).size !== records.length) fail('INVALID_IMPORT_MANIFEST', 'Duplicate source/content identity in import batch');
  return { manifestSha256: knowledgeHash(bytes), documents: records };
}

// Cooperating writers serialize with an exclusive lock. Abandoned locks are never guessed stale.
export function publishKnowledgeImport({ projectRoot, prepared, expectedCatalogSha256 = 'absent', dryRun = false }) {
  if (typeof projectRoot !== 'string' || !path.isAbsolute(projectRoot) || expectedCatalogSha256 !== 'absent' && !/^[a-f0-9]{64}$/.test(expectedCatalogSha256)
    || !plain(prepared) || !/^[a-f0-9]{64}$/.test(prepared.manifestSha256) || !Array.isArray(prepared.documents) || !prepared.documents.length
    || prepared.documents.length > DOCUMENT_LIMITS.documents || typeof dryRun !== 'boolean') fail('INVALID_IMPORT_ARGUMENT', 'Invalid publication arguments');
  const documents = prepared.documents.map(validateKnowledgeDocument), dir = path.join(path.resolve(projectRoot), 'knowledge-v1'), file = path.join(dir, 'catalog.json');
  assertKnowledgePath(dir);
  const build = () => {
    const old = readKnowledgeBytes(file, KNOWLEDGE_LIMITS.fileBytes, true), previousSha256 = old ? knowledgeHash(old) : 'absent';
    if (previousSha256 !== expectedCatalogSha256) fail('STALE_KNOWLEDGE_CATALOG', 'Catalog changed; inspect its current digest before importing');
    let catalog;
    try { catalog = old ? validateKnowledgeCatalog(JSON.parse(decodeKnowledgeText(old))) : { schema: 'ig5-knowledge-catalog-v1', cards: [], documents: [] }; }
    catch (error) { if (error.code) throw error; fail('INVALID_KNOWLEDGE_FILE', 'Existing catalog is not valid UTF-8 JSON'); }
    const added = [], reused = [];
    for (const document of documents) {
      const existing = catalog.documents.find(d => d.id === document.id);
      // Preserve the first committed metadata/ref for identical source and bytes.
      if (existing) { reused.push(existing.id); continue; }
      catalog.documents.push(document); added.push(document.id);
    }
    catalog = validateKnowledgeCatalog(catalog);
    const output = Buffer.from(JSON.stringify(catalog, null, 2) + '\n');
    if (output.length > KNOWLEDGE_LIMITS.fileBytes) fail('KNOWLEDGE_IMPORT_BUDGET', 'Catalog exceeds its byte budget');
    return { old, output, previousSha256, added, reused, documentCount: catalog.documents.length };
  };
  const receipt = state => ({ schema: 'ig5-research-import-receipt-v1', manifestSha256: prepared.manifestSha256,
    previousCatalogSha256: state.previousSha256, catalogSha256: state.added.length ? knowledgeHash(state.output) : state.previousSha256,
    added: state.added, reused: state.reused, documentCount: state.documentCount, dryRun, catalogSaved: false, cleanupConfirmed: true });
  if (dryRun) return receipt(build());
  fs.mkdirSync(dir, { recursive: true }); assertKnowledgePath(dir);
  const lockFile = path.join(dir, 'import.lock'), owner = randomUUID();
  let lock;
  try { lock = fs.openSync(lockFile, 'wx'); } catch (error) { if (error.code === 'EEXIST') fail('KNOWLEDGE_IMPORT_BUSY', 'Research import lock exists; leave it intact'); throw error; }
  let stage = null, result = null, primary = null;
  try {
    fs.writeFileSync(lock, JSON.stringify({ owner, pid: process.pid })); fs.fsyncSync(lock);
    const state = build(); result = receipt(state);
    if (!state.added.length) return result;
    // Save previous bytes before replacement. Unknown history entries are never overwritten.
    if (state.old) {
      const history = path.join(dir, 'history'); assertKnowledgePath(history); fs.mkdirSync(history, { recursive: true }); assertKnowledgePath(history);
      const backup = path.join(history, state.previousSha256 + '.json');
      const prior = readKnowledgeBytes(backup, KNOWLEDGE_LIMITS.fileBytes, true);
      if (prior && knowledgeHash(prior) !== state.previousSha256) fail('KNOWLEDGE_HISTORY_CONFLICT', 'Existing catalog backup digest does not match');
      if (!prior) { const fd = fs.openSync(backup, 'wx'); try { fs.writeFileSync(fd, state.old); fs.fsyncSync(fd); } finally { fs.closeSync(fd); } }
    }
    stage = path.join(dir, `.catalog-${owner}.stage`);
    const fd = fs.openSync(stage, 'wx'); try { fs.writeFileSync(fd, state.output); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    const current = readKnowledgeBytes(file, KNOWLEDGE_LIMITS.fileBytes, true);
    if ((current ? knowledgeHash(current) : 'absent') !== state.previousSha256) fail('STALE_KNOWLEDGE_CATALOG', 'Catalog changed during publication');
    assertKnowledgePath(dir);
    fs.renameSync(stage, file); stage = null; result.catalogSaved = true;
    return result;
  } catch (error) { primary = error; Object.assign(error, { catalogSaved: result?.catalogSaved || false }); throw error; }
  finally {
    try {
      if (stage) { const info = fs.lstatSync(stage); if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1) fail('KNOWLEDGE_CLEANUP_UNCONFIRMED', 'Import stage identity changed'); fs.unlinkSync(stage); }
      const info = fs.lstatSync(lockFile), own = fs.fstatSync(lock);
      const bytes = readKnowledgeBytes(lockFile, 512);
      if (info.dev !== own.dev || info.ino !== own.ino || JSON.parse(decodeKnowledgeText(bytes)).owner !== owner) fail('KNOWLEDGE_CLEANUP_UNCONFIRMED', 'Import lock ownership changed');
      fs.closeSync(lock); lock = null; fs.unlinkSync(lockFile);
    } catch (error) {
      if (lock !== null) fs.closeSync(lock);
      if (primary) Object.assign(primary, { cleanupConfirmed: false, cleanupError: error.code || 'KNOWLEDGE_CLEANUP_UNCONFIRMED' });
      else { Object.assign(error, { catalogSaved: result?.catalogSaved || false, catalogSha256: result?.catalogSha256, cleanupConfirmed: false }); throw error; }
    }
  }
}
