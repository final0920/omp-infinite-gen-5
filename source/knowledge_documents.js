import { knowledgeHash, knowledgeFail as fail } from './knowledge_io.js';

export const DOCUMENT_LIMITS = Object.freeze({ documents: 32, bodyBytes: 65536 });
const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype && Object.values(Object.getOwnPropertyDescriptors(v)).every(d => 'value' in d);
const text = (v, max) => typeof v === 'string' && v.trim().length > 0 && v.length <= max && !v.includes('\0');
export function safeResearchUrl(value) {
  if (!text(value, 1024)) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password && !url.hash && !url.port
      && /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/i.test(url.hostname) && !url.hostname.endsWith('.local');
  } catch { return false; }
}
export const documentIdentity = (sourceUrl, contentSha256) => 'doc-' + knowledgeHash(sourceUrl + '\0' + contentSha256).slice(0, 48);
export function validateKnowledgeDocument(document) {
  const fields = ['schema','id','title','author','sourceUrl','publishedAt','retrievedAt','contentSha256','license','rightsStatus','methodIds','reviewNotes','body'];
  if (!plain(document) || Object.keys(document).some(k => !fields.includes(k)) || fields.some(k => !(k in document))
    || document.schema !== 'ig5-source-document-v1' || !text(document.title, 160) || !text(document.author, 160)
    || !safeResearchUrl(document.sourceUrl) || !text(document.license, 256)
    || !['local-reference-only','redistribution-permitted'].includes(document.rightsStatus)
    || !text(document.body, DOCUMENT_LIMITS.bodyBytes) || Buffer.byteLength(document.body) > DOCUMENT_LIMITS.bodyBytes
    || typeof document.contentSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(document.contentSha256)
    || document.contentSha256 !== knowledgeHash(document.body)
    || document.id !== documentIdentity(document.sourceUrl, document.contentSha256)
    || !Array.isArray(document.methodIds) || document.methodIds.length > 16 || new Set(document.methodIds).size !== document.methodIds.length
    || document.methodIds.some(id => typeof id !== 'string' || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(id))
    || !Array.isArray(document.reviewNotes) || document.reviewNotes.length < 1 || document.reviewNotes.length > 8 || document.reviewNotes.some(note => !text(note, 512))
    || !text(document.retrievedAt, 30) || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(document.retrievedAt) || !Number.isFinite(Date.parse(document.retrievedAt))
    || document.publishedAt !== null && (!text(document.publishedAt, 30) || !/^\d{4}-\d{2}-\d{2}$/.test(document.publishedAt) || !Number.isFinite(Date.parse(document.publishedAt))))
    fail('INVALID_KNOWLEDGE_DOCUMENT', 'Invalid bounded source document or content digest');
  return JSON.parse(JSON.stringify(document));
}
