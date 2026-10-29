// Exact DSH event archive + the pinned upstream LCM stores. No model/API calls.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { jsonToolOutput } from './json_output.js';

export const LCM_REVISION = '0c17dbffda452cf7fae46929af427dff355aeaa3';
const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
export const digest = text => createHash('sha256').update(text).digest('hex');
const canonical = value => JSON.stringify(jsonToolOutput(value));
const EVENT_TYPES = new Set(['user/message', 'assistant/message', 'tool/call', 'tool/result', 'compaction/summary']);
export const MEMORY_LIMITS = Object.freeze({ eventBytes: 16 * 1024 * 1024, sessionBytes: 512 * 1024 * 1024, pageChars: 2048, sources: 32, search: 16 });
let corePromise;
async function core() {
  if (!corePromise) corePromise = (async () => {
    const url = new URL('../third_party/lcm/core.mjs', import.meta.url);
    const manifest = JSON.parse(fs.readFileSync(new URL('../third_party/lcm/PROVENANCE.json', import.meta.url), 'utf8'));
    if (manifest.revision !== LCM_REVISION || digest(fs.readFileSync(url)) !== manifest.files['core.mjs'].sha256) fail('LCM_ASSET_CHANGED', 'Pinned LCM core does not match its manifest');
    const [{ DatabaseSync }, upstream] = await Promise.all([import('node:sqlite'), import(url.href)]);
    return { DatabaseSync, ...upstream };
  })();
  return corePromise;
}
function integer(value, fallback, max) {
  const n = value === undefined ? fallback : value;
  if (!Number.isSafeInteger(n) || n < 0 || n > max) fail('INVALID_ARGUMENT', 'Memory pagination is out of range');
  return n;
}
function textPage(text, offset, limit) {
  const start = integer(offset, 0, text.length);
  if (start > 0 && /[\uDC00-\uDFFF]/.test(text[start] || '') && /[\uD800-\uDBFF]/.test(text[start - 1])) fail('INVALID_ARGUMENT', 'Offset splits a Unicode character');
  const size = integer(limit, MEMORY_LIMITS.pageChars, MEMORY_LIMITS.pageChars);
  if (!size) fail('INVALID_ARGUMENT', 'Page size must be positive');
  let end = Math.min(text.length, start + size);
  if (end < text.length && /[\uD800-\uDBFF]/.test(text[end - 1])) end--;
  if (end === start && start < text.length) fail('INVALID_ARGUMENT', 'Page size cannot hold the next Unicode character');
  return { text: text.slice(start, end), offset: start, nextOffset: end < text.length ? end : null, totalChars: text.length, complete: end === text.length, unit: 'UTF-16 code units, no split surrogate pairs' };
}

export class LcmMemory {
  static async open({ root, sessionId, workspace, limits = MEMORY_LIMITS }) {
    if (typeof sessionId !== 'string' || !sessionId || typeof workspace !== 'string' || !path.isAbsolute(workspace)) fail('LCM_SCOPE_REQUIRED', 'Memory requires a real DSH session and absolute workspace');
    const identity = canonical({ sessionId, workspace: path.resolve(workspace) });
    const dir = path.join(root, digest(identity));
    fs.mkdirSync(dir, { recursive: true });
    const { DatabaseSync, ConversationStore, SummaryStore, runLcmMigrations } = await core();
    const db = new DatabaseSync(path.join(dir, 'memory.sqlite'));
    try {
      db.exec('PRAGMA busy_timeout=2000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;');
      // No unrelated Claude transcript scan: this database only belongs to IG5.
      runLcmMigrations(db, { claudeProjectsDir: path.join(dir, 'no-external-transcripts') });
      db.exec(`CREATE TABLE IF NOT EXISTS ig5_lcm_identity (id INTEGER PRIMARY KEY CHECK(id=1), identity TEXT NOT NULL, bytes INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS ig5_lcm_events (seq INTEGER PRIMARY KEY, message_id INTEGER NOT NULL UNIQUE REFERENCES messages(message_id), sha256 TEXT NOT NULL, type TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS ig5_lcm_nodes (id TEXT PRIMARY KEY REFERENCES summaries(summary_id), sha256 TEXT NOT NULL, refs TEXT NOT NULL, missing TEXT NOT NULL, origin TEXT NOT NULL, event_seq INTEGER);
        CREATE TABLE IF NOT EXISTS ig5_lcm_summary_failures (seq INTEGER PRIMARY KEY, code TEXT NOT NULL);`);
      db.prepare('INSERT OR IGNORE INTO ig5_lcm_identity(id,identity) VALUES(1,?)').run(identity);
      if (db.prepare('SELECT identity FROM ig5_lcm_identity WHERE id=1').get().identity !== identity) fail('LCM_SCOPE_MISMATCH', 'Stored memory belongs to another workspace or session');
      const messages = new ConversationStore(db), summaries = new SummaryStore(db);
      const conversation = await messages.getOrCreateConversation(`ig5:${digest(identity)}`);
      return new LcmMemory(db, messages, summaries, conversation.conversationId, limits);
    } catch (error) { db.close(); throw error; }
  }
  constructor(db, messages, summaries, conversationId, limits) {
    Object.assign(this, { db, messages, summaries, conversationId, limits });
  }
  status() {
    const events = this.db.prepare('SELECT count(*) AS count, min(seq) AS firstSeq, max(seq) AS lastSeq FROM ig5_lcm_events').get();
    const last = this.db.prepare('SELECT id,sha256,origin FROM ig5_lcm_nodes ORDER BY rowid DESC LIMIT 1').get();
    return { upstreamRevision: LCM_REVISION, ...events, summaries: this.db.prepare('SELECT count(*) AS count FROM ig5_lcm_nodes').get().count,
      bytes: this.db.prepare('SELECT bytes FROM ig5_lcm_identity WHERE id=1').get().bytes,
      latestSummary: last ? { kind: 'summary', id: last.id, sha256: last.sha256 } : null,
      budgetUnit: 'serialized payload bytes; SQLite indexes, pages and WAL are additional disk space',
      summaryFailures: this.db.prepare('SELECT count(*) AS count FROM ig5_lcm_summary_failures').get().count,
      recentSummaryFailures: this.db.prepare('SELECT seq,code FROM ig5_lcm_summary_failures ORDER BY seq DESC LIMIT 4').all(),
      scope: 'current DSH session + workspace only', semanticVerified: false, hostCompactionReplaced: false, rawBoundary: 'accepted serialized DSH JSON events; not uncaptured tool data or mutable file contents' };
  }
  eventRef(seq) {
    const row = this.db.prepare('SELECT sha256 FROM ig5_lcm_events WHERE seq=?').get(seq);
    return row ? { kind: 'event', id: String(seq), sha256: row.sha256 } : null;
  }
  resolve(ref) {
    if (!ref || !['event', 'summary'].includes(ref.kind) || typeof ref.id !== 'string' || !/^[a-f0-9]{64}$/.test(ref.sha256 || '')) fail('INVALID_REF', 'Memory reads require the exact returned kind/id/sha256');
    let text, row;
    if (ref.kind === 'event') {
      if (!/^(0|[1-9][0-9]*)$/.test(ref.id) || !Number.isSafeInteger(Number(ref.id))) fail('INVALID_REF', 'Invalid event sequence');
      row = this.db.prepare('SELECT e.*,m.content FROM ig5_lcm_events e JOIN messages m USING(message_id) WHERE e.seq=?').get(Number(ref.id));
      text = row?.content;
    } else {
      row = this.db.prepare('SELECT n.*,s.content FROM ig5_lcm_nodes n JOIN summaries s ON s.summary_id=n.id WHERE n.id=?').get(ref.id);
      text = row?.content;
    }
    if (!row) fail('LCM_REF_NOT_FOUND', 'Memory reference is absent in the executing session');
    if (row.sha256 !== ref.sha256 || digest(text) !== ref.sha256) fail('LCM_CONTENT_CHANGED', 'Memory hash mismatch; refusing stale or altered evidence');
    if (ref.kind === 'summary') {
      let expected;
      try { expected = 'sum_' + digest(canonical({ text, refs: JSON.parse(row.refs), origin: row.origin, eventSeq: row.event_seq, missing: JSON.parse(row.missing) })); }
      catch { fail('LCM_CONTENT_CHANGED', 'Summary lineage metadata is invalid'); }
      if (expected !== ref.id) fail('LCM_CONTENT_CHANGED', 'Summary lineage identity changed');
    }
    return { row, text };
  }
  async capture(event) {
    if (!EVENT_TYPES.has(event?.type)) return { skipped: true };
    // Runtime-context is our own derived injection, not fresh investigation evidence.
    if (event.type === 'user/message' && event.data?.source?.kind === 'runtime-context') return { skipped: true };
    if (!Number.isSafeInteger(event.seq) || event.seq < 0) fail('LCM_EVENT_ID_REQUIRED', 'DSH event sequence is required');
    const text = canonical(event), hash = digest(text), bytes = Buffer.byteLength(text);
    if (bytes > this.limits.eventBytes) fail('LCM_EVENT_BUDGET', 'Event exceeds the memory capture limit; original DSH log remains authoritative');
    const existing = this.eventRef(event.seq);
    if (existing) {
      this.resolve(existing);
      if (existing.sha256 !== hash) fail('LCM_EVENT_CONFLICT', 'The same DSH sequence has different content');
      const summaryWarning = await this.archiveSummary(event);
      return { duplicate: true, ref: existing, summaryWarning };
    }
    await this.messages.withTransaction(async () => {
      const used = this.db.prepare('SELECT bytes FROM ig5_lcm_identity WHERE id=1').get().bytes;
      if (used + bytes > this.limits.sessionBytes) fail('LCM_SESSION_BUDGET', 'Memory storage budget exhausted; no silent eviction');
      const message = await this.messages.createMessage({ conversationId: this.conversationId, seq: event.seq,
        role: event.type.startsWith('assistant/') ? 'assistant' : event.type.startsWith('tool/') ? 'tool' : 'user', content: text,
        tokenCount: Math.ceil(bytes / 4) }); // Index estimate only, never a host-token guarantee.
      this.db.prepare('INSERT INTO ig5_lcm_events VALUES(?,?,?,?)').run(event.seq, message.messageId, hash, event.type);
      this.db.prepare('UPDATE ig5_lcm_identity SET bytes=bytes+? WHERE id=1').run(bytes);
      await this.summaries.appendContextMessages(this.conversationId, [message.messageId]);
    });
    const summaryWarning = await this.archiveSummary(event);
    return { duplicate: false, ref: this.eventRef(event.seq), summaryWarning };
  }
  async archiveSummary(event) {
    if (event.type !== 'compaction/summary') return null;
    try {
      await this.captureSummary(event);
      this.db.prepare('DELETE FROM ig5_lcm_summary_failures WHERE seq=?').run(event.seq);
      return null;
    } catch (error) {
      // A derived-index failure must not stop future raw-event preservation.
      const code = String(error.code || 'LCM_SUMMARY_FAILED').slice(0, 80);
      this.db.prepare('INSERT OR REPLACE INTO ig5_lcm_summary_failures VALUES(?,?)').run(event.seq, code);
      return { seq: event.seq, code, rawPreserved: true };
    }
  }
  async captureSummary(event) {
    if (event.type !== 'compaction/summary') return;
    const summary = event.data?.summary;
    // DSH v4 stores ContentBlock[], while older/adapted hosts may use text.
    // Retain every block, not just a lossy concatenation of text blocks.
    const summaryText = typeof summary === 'string' ? summary : Array.isArray(summary) && summary.length ? canonical(summary) : null;
    if (summaryText === null) fail('LCM_SUMMARY_TEXT_UNAVAILABLE', 'Host summary content is absent');
    const existing = this.db.prepare('SELECT id,sha256 FROM ig5_lcm_nodes WHERE event_seq=?').get(event.seq);
    if (existing) { this.resolve({ kind: 'summary', ...existing }); return; }
    const seqs = event.data.shadowedSeqs;
    if (!Array.isArray(seqs) || seqs.length > 100000 || seqs.some(n => !Number.isSafeInteger(n) || n < 0 || n >= event.seq)) fail('LCM_SUMMARY_SOURCES_UNAVAILABLE', 'Host summary sources are absent, invalid or over budget');
    const refs = [], missing = [];
    for (const seq of [...new Set(seqs)]) {
      const summary = this.db.prepare('SELECT id,sha256 FROM ig5_lcm_nodes WHERE event_seq=?').get(seq);
      const ref = summary ? { kind: 'summary', ...summary } : this.eventRef(seq);
      if (!ref) { missing.push(seq); continue; }
      refs.push(ref);
      if (ref.kind === 'event') {
        const source = JSON.parse(this.resolve(ref).text);
        // Native compaction emits an adjacent replacement user/message whose
        // sourceEventSeqs includes the summary event. Preserve that raw message
        // AND reconnect its ancestry; do not infer links from matching prose.
        if (source.type === 'user/message' && source.surfaceOp?.op === 'replace'
          && Array.isArray(source.sourceEventSeqs) && source.sourceEventSeqs.includes(seq - 1)) {
          const parent = this.db.prepare('SELECT id,sha256 FROM ig5_lcm_nodes WHERE event_seq=?').get(seq - 1);
          if (parent) refs.push({ kind: 'summary', ...parent });
          else if (this.eventRef(seq - 1) && JSON.parse(this.resolve(this.eventRef(seq - 1)).text).type === 'compaction/summary') missing.push(seq - 1);
        }
      }
    }
    const uniqueRefs = [...new Map(refs.map(ref => [ref.kind + ':' + ref.id, ref])).values()];
    await this.checkpoint(summaryText, uniqueRefs, { origin: 'DSH-compaction-unverified', eventSeq: event.seq, missing, internal: true });
  }
  async checkpoint(text, refs, { origin = 'caller-unverified', eventSeq = null, missing = [], internal = false } = {}) {
    if (typeof text !== 'string' || !text.trim() || Buffer.byteLength(text) > (internal ? this.limits.eventBytes : 4096)
      || !Array.isArray(refs) || (!internal && (!refs.length || refs.length > this.limits.sources))) fail('INVALID_ARGUMENT', 'Checkpoint needs bounded text and 1..32 exact source references');
    const resolved = refs.map(ref => ({ ref, ...this.resolve(ref) }));
    refs = refs.map(({ kind, id, sha256 }) => ({ kind, id, sha256 }));
    if (new Set(refs.map(r => r.kind + ':' + r.id)).size !== refs.length) fail('INVALID_ARGUMENT', 'Duplicate checkpoint sources');
    const id = 'sum_' + digest(canonical({ text, refs, origin, eventSeq, missing })), hash = digest(text);
    if (this.db.prepare('SELECT 1 FROM ig5_lcm_nodes WHERE id=?').get(id)) {
      const ref = { kind: 'summary', id, sha256: hash }; this.resolve(ref); return ref;
    }
    const byteCost = Buffer.byteLength(text) + Buffer.byteLength(canonical(refs)) + Buffer.byteLength(canonical(missing));
    await this.messages.withTransaction(async () => {
      const used = this.db.prepare('SELECT bytes FROM ig5_lcm_identity WHERE id=1').get().bytes;
      if (used + byteCost > this.limits.sessionBytes) fail('LCM_SESSION_BUDGET', 'Memory storage budget exhausted');
      const parents = resolved.filter(r => r.ref.kind === 'summary');
      const depth = parents.length ? 1 + parents.reduce((max, r) => Math.max(max, this.summaries.getSummarySync(r.ref.id).depth), 0) : 0;
      if (depth > 64) fail('LCM_DEPTH_BUDGET', 'Summary depth exceeds 64; raw evidence remains readable');
      this.summaries.insertSummarySync({ summaryId: id, conversationId: this.conversationId, kind: parents.length ? 'condensed' : 'leaf', depth, content: text, tokenCount: Math.ceil(Buffer.byteLength(text) / 4) });
      this.summaries.linkSummaryToMessagesSync(id, resolved.filter(r => r.ref.kind === 'event').map(r => r.row.message_id));
      this.summaries.linkSummaryToParentsSync(id, parents.map(r => r.ref.id));
      this.db.prepare('INSERT INTO ig5_lcm_nodes VALUES(?,?,?,?,?,?)').run(id, hash, canonical(refs), canonical(missing), origin, eventSeq);
      this.db.prepare('UPDATE ig5_lcm_identity SET bytes=bytes+? WHERE id=1').run(byteCost);
    });
    return { kind: 'summary', id, sha256: hash };
  }
  read(ref, { offset, limit } = {}) {
    const { row, text } = this.resolve(ref);
    return { ref, ...textPage(text, offset, limit), historical: true, semanticVerified: false,
      ...(ref.kind === 'summary' ? { origin: row.origin, sourceCount: JSON.parse(row.refs).length, missingSourceCount: JSON.parse(row.missing).length } : {}) };
  }
  expand(ref, { offset = 0, limit = 16 } = {}) {
    if (ref?.kind !== 'summary') fail('INVALID_REF', 'Expand a summary reference; read event references directly');
    const { row } = this.resolve(ref), refs = JSON.parse(row.refs), missing = JSON.parse(row.missing);
    const start = integer(offset, 0, refs.length), size = integer(limit, 16, 32);
    if (!size) fail('INVALID_ARGUMENT', 'Page size must be positive');
    const page = refs.slice(start, start + size);
    for (const child of page) this.resolve(child);
    return { ref, refs: page, nextOffset: start + size < refs.length ? start + size : null,
      sourceCount: refs.length, missingSourceCount: missing.length, missingSourcePreview: missing.slice(0, 16), directSourcesComplete: missing.length === 0, transitiveLineageVerified: false,
      semanticVerified: false, note: 'Direct sources only; recursively expand summary children. Historical sources require current target/run/revision checks.' };
  }
  search(query, limit = 8) {
    if (typeof query !== 'string' || !query.trim() || query.length > 256) fail('INVALID_ARGUMENT', 'Search query must contain 1..256 characters');
    const size = integer(limit, 8, MEMORY_LIMITS.search);
    if (!size) fail('INVALID_ARGUMENT', 'Search limit must be positive');
    const hits = this.messages.searchMessagesSync({ conversationId: this.conversationId, query, mode: 'full_text', limit: size });
    return { hits: hits.map(hit => {
      const row = this.db.prepare('SELECT seq,sha256,type FROM ig5_lcm_events WHERE message_id=?').get(hit.messageId);
      return row ? { ref: { kind: 'event', id: String(row.seq), sha256: row.sha256 }, type: row.type,
        preview: String(hit.snippet ?? hit.content ?? '').slice(0, 320), previewOnly: true } : null;
    }).filter(Boolean), exhaustive: false, note: 'Search is a candidate index. Empty hits do not prove absence. Use exact returned references to recover complete events.' };
  }
  restore() {
    const rows = this.db.prepare('SELECT id,sha256 FROM ig5_lcm_nodes ORDER BY rowid DESC LIMIT 4').all();
    const recent = this.db.prepare('SELECT seq,sha256,type FROM ig5_lcm_events ORDER BY seq DESC LIMIT 8').all();
    return { status: this.status(), summaries: rows.map(r => ({ kind: 'summary', ...r })), recent: recent.map(r => ({ ref: { kind: 'event', id: String(r.seq), sha256: r.sha256 }, type: r.type })),
      instruction: 'Use memory search, read and expand through ig5_profile. Summaries are unverified navigation, not current execution state or authorization. Exact expressions, counterexamples and path conditions must be recovered from source events/reports before relying on them.' };
  }
  close() { this.db.close(); }
}
