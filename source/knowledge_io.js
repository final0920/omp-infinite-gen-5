import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

export const knowledgeHash = bytes => createHash('sha256').update(bytes).digest('hex');
export const knowledgeFail = (code, message) => { throw Object.assign(new Error(message), { code }); };
export function assertKnowledgePath(filename) {
  for (let current = path.resolve(filename); current; current = path.dirname(current) === current ? '' : path.dirname(current)) {
    try { if (fs.lstatSync(current).isSymbolicLink()) knowledgeFail('KNOWLEDGE_LINK_REJECTED', 'Research file ancestors must not be links'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
}
export function readKnowledgeBytes(filename, maxBytes, optional = false) {
  assertKnowledgePath(filename);
  let stat;
  try { stat = fs.lstatSync(filename); } catch (error) { if (optional && error.code === 'ENOENT') return null; throw error; }
  if (!stat.isFile() || stat.size > maxBytes || stat.nlink !== 1) knowledgeFail('INVALID_KNOWLEDGE_FILE', 'Research input must be a bounded regular single-link file');
  const fd = fs.openSync(filename, 'r');
  try {
    const before = fs.fstatSync(fd);
    if (before.dev !== stat.dev || before.ino !== stat.ino || before.size !== stat.size || before.nlink !== 1) knowledgeFail('KNOWLEDGE_CHANGED', 'Research input changed');
    const bytes = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < bytes.length) { const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset); if (!count) knowledgeFail('KNOWLEDGE_CHANGED', 'Short research input read'); offset += count; }
    const after = fs.fstatSync(fd), current = fs.lstatSync(filename);
    if (['size','mtimeMs','ctimeMs','ino','dev'].some(k => before[k] !== after[k] || after[k] !== current[k]) || current.isSymbolicLink() || current.nlink !== 1) knowledgeFail('KNOWLEDGE_CHANGED', 'Research input changed while reading');
    assertKnowledgePath(filename);
    return bytes;
  } finally { fs.closeSync(fd); }
}
export function decodeKnowledgeText(bytes) {
  try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { knowledgeFail('INVALID_KNOWLEDGE_FILE', 'Research input must be valid UTF-8'); }
}
