import fs from 'node:fs';
import path from 'node:path';
import { createHmac, randomBytes } from 'node:crypto';
import { AnalysisArtifacts, hashBytes } from './analysis_artifacts.js';
import { ProjectStore } from './project_store.js';
import { jsonToolOutput } from './json_output.js';

const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
export const RESULT_LIMITS = Object.freeze({ itemBytes: 1024 * 1024, taskBytes: 8 * 1024 * 1024,
  totalBytes: 64 * 1024 * 1024, records: 256, retentionMs: 7 * 86400000 });
const identityKeys = ['target','projectId','artifactId','sha256','engine','provider','attachmentId','dbRevision'];
const sameIdentity = (a, b) => identityKeys.every(k => a?.[k] === b?.[k]);
const encode = value => Buffer.from(JSON.stringify(jsonToolOutput(value)), 'utf8');
function guarded(directory) {
  for (let current = path.resolve(directory); ; current = path.dirname(current)) {
    if (fs.existsSync(current)) {
      const stat = fs.lstatSync(current);
      if (stat.isSymbolicLink() || !stat.isDirectory()) fail('RESULT_PATH_INVALID', 'Result storage cannot contain linked directories');
    }
    if (path.dirname(current) === current) return;
  }
}
function representation(raw, section, format) {
  if (format === 'json-text') return JSON.stringify(raw);
  if (section === 'decompile') return raw.data?.code ?? '';
  const rows = [];
  // Records carry their original key/index so empty arrays and scalar context survive reassembly.
  for (const [field, value] of Object.entries(raw)) {
    if (field !== 'data' || !value || typeof value !== 'object') rows.push({ field, value });
    else for (const [key, item] of Object.entries(value)) {
      if (Array.isArray(item)) {
        rows.push({ field: `data.${key}`, length: item.length });
        item.forEach((value, index) => rows.push({ field: `data.${key}`, index, value }));
      } else rows.push({ field: `data.${key}`, value: item });
    }
  }
  return rows;
}

/** Separate bounded namespace. Report data and commit metadata reuse AnalysisArtifacts integrity checks. */
export class ResultArtifacts {
  constructor(root, { now = () => Date.now() } = {}) {
    this.root = path.resolve(root); guarded(this.root);
    this.now = now;
    this.artifacts = new AnalysisArtifacts(path.join(this.root, 'data'));
    this.index = new ProjectStore({ root: path.join(this.root, 'index') });
  }
  transaction(fn) {
    guarded(this.root);
    return this.index.updateInvestigationRecords(records => {
      const state = records.results ||= { schemaVersion: 1, secret: randomBytes(32).toString('hex'), entries: {} };
      if (state.schemaVersion !== 1 || !/^[a-f0-9]{64}$/.test(state.secret) || !state.entries || typeof state.entries !== 'object'
        || Array.isArray(state.entries) || Object.keys(state.entries).length > RESULT_LIMITS.records)
        fail('RESULT_INDEX_CORRUPT', 'Invalid result storage index');
      return fn(state);
    });
  }
  diskBytes() {
    let total = 0, count = 0;
    for (const part of ['records', 'metadata', 'archived-metadata', 'blobs']) {
      const directory = this.artifacts.directory(part);
      for (const name of fs.readdirSync(directory)) {
        if (++count > 2048) fail('RESULT_STORAGE_LIMIT', 'Result storage file inventory exceeds its limit');
        const stat = fs.lstatSync(path.join(directory, name));
        if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) fail('RESULT_PATH_INVALID', 'Unexpected linked or special result file');
        total += stat.size;
      }
    }
    return total;
  }
  cleanup(state) {
    for (const [id, entry] of Object.entries(state.entries)) {
      if (!Number.isSafeInteger(entry.expiresAt) || !Number.isSafeInteger(entry.bytes) || entry.bytes < 0 || !/^[a-f0-9-]{36}$/.test(id))
        fail('RESULT_INDEX_CORRUPT', 'Invalid committed result entry');
      if (entry.expiresAt > this.now()) continue;
      // Exact owned filenames only; never recurse or remove a caller-selected path.
      for (const part of ['metadata', 'records']) {
        const filename = path.join(this.artifacts.directory(part), `${id}.json`);
        try {
          const stat = fs.lstatSync(filename);
          if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) fail('RESULT_PATH_INVALID', 'Expired result file was replaced by a link');
          fs.unlinkSync(filename);
        } catch (e) { if (e.code !== 'ENOENT') throw e; }
      }
      // Retain a small expiry tombstone until the next successful publication.
      delete state.entries[id];
    }
  }
  committed(id, entry) {
    for (const part of ['records','metadata']) {
      const stat = fs.lstatSync(path.join(this.artifacts.directory(part), id + '.json'));
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) fail('RESULT_CORRUPT', 'Linked result commits are not accepted');
    }
    if (this.artifacts.metadata(id).result.recordSha256 !== entry.sha256) fail('RESULT_CORRUPT', 'Result commit digest changed');
    return this.artifacts.get(id);
  }
  find(provenance, idempotencyKey) {
    return this.transaction(state => {
      const token = hashBytes(encode({ provenance, idempotencyKey }));
      const match = Object.entries(state.entries).find(([, e]) => e.idempotencyToken === token && e.expiresAt > this.now());
      if (!match) return null;
      const [id, entry] = match;
      const report = this.committed(id, entry);
      if (!sameIdentity(report.result?.provenance, provenance)) fail('RESULT_STALE', 'Batch result identity changed');
      return { id, sha256: entry.sha256, expiresAt: new Date(entry.expiresAt).toISOString() };
    });
  }
  save({ provenance, query, sections, taskId = null, idempotencyKey = null }) {
    const content = jsonToolOutput({ provenance, query, sections });
    const contentBytes = encode(content).length;
    if (contentBytes + 16384 > RESULT_LIMITS.itemBytes) fail('RESULT_ITEM_LIMIT', 'Provider result exceeds the 1 MiB saved-result limit; no complete reference was published');
    return this.transaction(state => {
      this.cleanup(state);
      const taskKey = hashBytes(encode({ provenance, taskId }));
      const taskBytes = Object.values(state.entries).filter(e => e.taskKey === taskKey).reduce((n, e) => n + e.bytes, 0);
      if (Object.keys(state.entries).length >= RESULT_LIMITS.records || this.diskBytes() + contentBytes + 16384 > RESULT_LIMITS.totalBytes
        || taskBytes + contentBytes + 16384 > RESULT_LIMITS.taskBytes) fail('RESULT_STORAGE_LIMIT', 'Saved-result storage quota exhausted');
      const record = this.artifacts.save({ kind: 'function-result', action: 'collect', result: content }, { maxBytes: RESULT_LIMITS.itemBytes });
      const metadata = this.artifacts.metadata(record.id);
      const entry = { sha256: metadata.result.recordSha256, bytes: metadata.bytes + fs.statSync(path.join(this.artifacts.directory('records'), record.id + '.json')).size,
        taskKey, expiresAt: this.now() + RESULT_LIMITS.retentionMs,
        ...(idempotencyKey ? { idempotencyToken: hashBytes(encode({ provenance, idempotencyKey })) } : {}) };
      state.entries[record.id] = entry;
      return { id: record.id, sha256: entry.sha256, expiresAt: new Date(entry.expiresAt).toISOString() };
    });
  }
  read(ref, provenance, args) {
    if (!ref || Object.keys(ref).some(k => !['id','sha256','expiresAt'].includes(k)) || !/^[a-f0-9-]{36}$/.test(ref.id) || !/^[a-f0-9]{64}$/.test(ref.sha256))
      fail('RESULT_REF_INVALID', 'Expected a saved result UUID and SHA-256');
    const section = args.section, format = args.format || (section === 'decompile' ? 'text' : 'records');
    if (!['decompile','cfg','callers','callees','stack'].includes(section) || !['text','records','json-text'].includes(format)
      || format === 'text' && section !== 'decompile' || format === 'records' && section === 'decompile') fail('RESULT_READ_INVALID', 'Invalid section or format');
    const maximum = args.page_max_bytes ?? 8000;
    if (!Number.isSafeInteger(maximum) || maximum < 4000 || maximum > 64000) fail('RESULT_READ_INVALID', 'page_max_bytes must be 4000..64000');
    return this.transaction(state => {
      const entry = state.entries[ref.id];
      if (!entry) fail('RESULT_NOT_FOUND', 'Saved result is unavailable or expired');
      if (entry.expiresAt <= this.now()) fail('RESULT_EXPIRED', 'Saved result has expired');
      if (entry.sha256 !== ref.sha256) fail('RESULT_DIGEST_MISMATCH', 'Saved result reference does not match its commit');
      let report;
      try {
        report = this.committed(ref.id, entry);
      }
      catch (error) { fail(error.code === 'ENOENT' ? 'RESULT_COMMIT_MISSING' : 'RESULT_CORRUPT', 'Saved result commit is missing or failed integrity validation'); }
      if (report.kind !== 'function-result' || !sameIdentity(report.result?.provenance, provenance)) fail('RESULT_STALE', 'Saved result belongs to a different target, attachment or database revision');
      const raw = report.result.sections[section];
      if (!raw) fail('RESULT_SECTION_MISSING', 'Saved result has no requested section');
      const data = representation(raw, section, format), isText = typeof data === 'string';
      const serialized = isText ? Buffer.from(data, 'utf8') : encode(data), contentSha256 = hashBytes(serialized);
      const binding = { v: 1, id: ref.id, sha256: ref.sha256, section, format, contentSha256 };
      const sign = value => createHmac('sha256', state.secret).update(value).digest('base64url');
      const cursor = offset => { const body = encode({ ...binding, offset }).toString('base64url'); return body + '.' + sign(body); };
      let offset = 0;
      if (args.cursor !== undefined) {
        if (typeof args.cursor !== 'string' || args.cursor.length > 2048) fail('RESULT_CURSOR_INVALID', 'Invalid result cursor');
        const [body, signature, extra] = args.cursor.split('.');
        if (extra !== undefined || signature !== sign(body || '')) fail('RESULT_CURSOR_INVALID', 'Result cursor authentication failed');
        let decoded; try { decoded = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')); } catch { fail('RESULT_CURSOR_INVALID', 'Malformed result cursor'); }
        if (Object.entries(binding).some(([k,v]) => decoded[k] !== v) || !Number.isSafeInteger(decoded.offset) || decoded.offset < 0) fail('RESULT_CURSOR_INVALID', 'Result cursor belongs to another result, section or format');
        offset = decoded.offset;
      }
      const length = isText ? serialized.length : data.length;
      if (offset > length || isText && offset < length && (serialized[offset] & 0xc0) === 0x80) fail('RESULT_CURSOR_INVALID', 'Cursor is outside a stable content boundary');
      const makePage = end => {
        const chunk = isText ? serialized.subarray(offset, end).toString('utf8') : data.slice(offset, end);
        return { kind: 'function-result-page', schemaVersion: 1, resultRef: { id: ref.id, sha256: ref.sha256 }, provenance, _ig5: provenance,
          section, format, status: raw.status, completeness: { provider: raw.status === 'ok' ? raw.provider?.completeness || 'unknown' : raw.status === 'unsupported' ? 'unsupported' : 'error', stored: 'complete', response: end < length ? 'partial' : 'complete' },
          contentSha256, totalBytes: serialized.length, offset, nextOffset: end, totalUnits: length,
          returnedBytes: isText ? end-offset : encode(chunk).length, data: chunk, nextCursor: end < length ? cursor(end) : null };
      };
      let low = offset, high = length;
      while (low < high) {
        const mid = Math.ceil((low + high)/2);
        if (encode(makePage(mid)).length <= maximum) low = mid; else high = mid-1;
      }
      if (isText) while (low > offset && low < length && (serialized[low] & 0xc0) === 0x80) low--;
      if (low === offset && offset !== length) fail('RESULT_RECORD_TOO_LARGE', 'A stable record exceeds the page budget; increase page_max_bytes or use format=json-text');
      const page = makePage(low);
      if (encode(page).length > maximum) fail('RESULT_PAGE_LIMIT', 'Result page metadata exceeds the byte budget');
      return page;
    });
  }
}
