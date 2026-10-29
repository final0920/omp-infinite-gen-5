import { createHash } from 'node:crypto';
import { readStableFile } from './analysis_artifacts.js';

// Bounded, read-only correlation between one saved capture exchange and a local sample file.
// It never executes, opens an engine, starts a listener or sends traffic. String matches are
// presence-in-bytes evidence only; they do not show that the sample uses an endpoint at runtime.
const SAMPLE_LIMIT = 32 * 1024 * 1024;
const NEEDLE_LIMIT = 64;
const MATCH_PER_NEEDLE = 4;
const MATCH_LIMIT = 256;
const MIN_LITERAL = 4;
const VALUE_HEADERS = ['user-agent', 'referer', 'origin', 'accept', 'content-type'];
// Exported spellings of the network APIs already classified in worker/behavior_rules.py.
// A/W variants exist only for the ANSI/wide families; the test suite checks every normalized
// name against that taxonomy so this list cannot silently drift.
export const NETWORK_API = [
  ['winhttpopen', []], ['winhttpopenrequest', []], ['winhttpconnect', []], ['winhttpsendrequest', []],  ['winhttpreceiveresponse', []], ['winhttpquerydataavailable', []], ['winhttpreaddata', []], ['winhttpwritedata', []],
  ['internetopen', ['A', 'W']], ['internetopenurl', ['A', 'W']], ['internetconnect', ['A', 'W']],
  ['httpopenrequest', ['A', 'W']], ['httpsendrequest', ['A', 'W']], ['internetreadfile', []], ['internetwritefile', []],
  ['urldownloadtofile', ['A', 'W']], ['urldownloadtocachefile', ['A', 'W']],
  ['wsastartup', []], ['wsasocket', ['A', 'W']], ['wsaconnect', []], ['wsasend', []], ['wsarecv', []],
  ['getaddrinfo', []], ['gethostbyname', []], ['inet_addr', []],
  ['curl_easy_perform', []], ['curl_easy_setopt', []], ['ssl_read', []], ['ssl_write', []],
  ['gnutls_record_recv', []], ['gnutls_record_send', []],
  ['socket', []], ['connect', []], ['send', []], ['recv', []],
];
const AMBIGUOUS = new Set(['socket', 'connect', 'send', 'recv']);

const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const printable = value => typeof value === 'string' && value.length > 0 && /^[\x20-\x7e]+$/.test(value);

function headerValue(headers, name) {
  const entry = Object.entries(headers || {}).find(([key]) => key.toLowerCase() === name);
  if (!entry) return '';
  const text = Array.isArray(entry[1]) ? entry[1].join(', ') : String(entry[1]);
  return printable(text) ? text.slice(0, 512) : '';
}

/** ASCII-only lowercase; Buffer.toString('latin1').toLowerCase() can change byte length. */
function lowerAscii(bytes) {
  const out = Buffer.allocUnsafe(bytes.length);
  for (let index = 0; index < bytes.length; index += 1) {
    const value = bytes[index];
    out[index] = value >= 65 && value <= 90 ? value + 32 : value;
  }
  return out;
}
const isWordByte = value => (value >= 48 && value <= 57) || (value >= 65 && value <= 90) || (value >= 97 && value <= 122) || value === 95;
function boundaryAt(buffer, offset, length) {
  const before = offset === 0 ? 0 : buffer[offset - 1];
  const after = offset + length >= buffer.length ? 0 : buffer[offset + length];
  return !isWordByte(before) && !isWordByte(after);
}
function utf16le(text) {
  const bytes = Buffer.allocUnsafe(text.length * 2);
  for (let index = 0; index < text.length; index += 1) { bytes[index * 2] = text.charCodeAt(index) & 0xff; bytes[index * 2 + 1] = 0; }
  return bytes;
}
function occurrences(haystack, needle, boundary, remaining) {
  const offsets = [];
  let at = 0;
  while (offsets.length < remaining) {
    const found = haystack.indexOf(needle, at);
    if (found < 0) break;
    if (!boundary || boundaryAt(haystack, found, needle.length)) { offsets.push(found); at = found + 1; }
    else at = found + 1;
  }
  return offsets;
}

/** Literal search in ASCII and UTF-16LE, plus ASCII case-insensitive. Offsets are file offsets. */
function findLiteral(sample, lowered, needle, { boundary = false, remaining = MATCH_PER_NEEDLE } = {}) {
  const exact = Buffer.from(needle, 'latin1'), wide = utf16le(needle);
  // Probe one omitted match so a per-needle cap is reported as truncation too.
  const probeLimit = remaining + 1;
  const rows = [];
  const seen = new Set();
  const add = (offset, encoding, caseInsensitive) => {
    const key = `${offset}:${encoding}:${caseInsensitive}`;
    if (seen.has(key) || rows.length >= probeLimit) return;
    seen.add(key); rows.push({ offset, encoding, caseInsensitive });
  };
  for (const offset of occurrences(sample, exact, boundary, probeLimit)) add(offset, 'ascii', false);
  if (rows.length < probeLimit) for (const offset of occurrences(sample, wide, boundary, probeLimit - rows.length)) add(offset, 'utf16le', false);
  const lowerNeedle = Buffer.from(needle.toLowerCase(), 'latin1');
  if (rows.length < probeLimit && lowerNeedle.some(value => value >= 97 && value <= 122)) {
    for (const offset of occurrences(lowered, lowerNeedle, boundary, probeLimit - rows.length)) add(offset, 'ascii', true);
  }
  return { matches: rows.slice(0, remaining), truncated: rows.length > remaining };
}

function argumentsOf(args) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) fail('CORRELATE_INVALID_INPUT', 'Correlation requires a capture id and a sample object');
  if (args.sample === null || typeof args.sample !== 'object' || Array.isArray(args.sample)) fail('CORRELATE_INVALID_INPUT', 'sample must be an object with path and optional sha256');
  const extra = Object.keys(args.sample).filter(key => !['path', 'sha256'].includes(key));
  if (extra.length) fail('CORRELATE_INVALID_INPUT', 'sample accepts only path and sha256');
  const path = args.sample.path;
  if (typeof path !== 'string' || !path || path.includes('\0') || path.length > 4096) fail('CORRELATE_INVALID_INPUT', 'sample.path must be a non-empty path of at most 4096 characters');
  const expected = args.sample.sha256;
  if (expected !== undefined && (typeof expected !== 'string' || !/^[a-f0-9]{64}$/.test(expected))) fail('CORRELATE_INVALID_INPUT', 'sample.sha256 must be a lowercase SHA-256');
  return { id: args.id, session_id: args.session_id, path, expected };
}

function sampleFile({ path, expected }) {
  let read;
  try { read = readStableFile(path, SAMPLE_LIMIT); }
  catch (error) {
    if (error.code === 'INPUT_LIMIT') fail('CORRELATE_SAMPLE_LIMIT', `sample exceeds the ${SAMPLE_LIMIT}-byte correlation budget`);
    throw error;
  }
  const bytes = read.data, digest = sha256(bytes);
  if (expected && expected !== digest) fail('CORRELATE_SAMPLE_MISMATCH', 'sample.sha256 does not match the file on disk; the sample may have changed');
  return { path: read.origin.path, sha256: digest, bytes };
}

function capturedNeedles(value, url) {
  const needles = [];
  const push = (kind, label, text, extra = {}) => {
    if (!printable(text) || text.length < MIN_LITERAL || text.length > 2048) return;
    if (needles.some(row => row.kind === kind && row.text === text)) return;
    if (needles.length >= NEEDLE_LIMIT) return;
    needles.push({ kind, label, text, ...extra });
  };
  push('endpoint-origin', 'origin', url.origin);
  push('endpoint-host', 'host', url.hostname);
  if (url.port && !((url.protocol === 'http:' && url.port === '80') || (url.protocol === 'https:' && url.port === '443'))) push('endpoint-host', 'host:port', url.host);
  if (value.protocol !== 'connect' && !value.encrypted) push('endpoint-path', 'path', url.pathname);
  for (const name of VALUE_HEADERS) push('request-header-value', name, headerValue(value.request?.headers, name));
  return needles;
}

function apiNeedles() {
  const rows = [];
  for (const [name, variants] of NETWORK_API) for (const variant of [name, ...variants.map(suffix => name + suffix.toLowerCase())]) {
    rows.push({ kind: 'communication-api-literal', label: name, text: variant, ambiguous: AMBIGUOUS.has(name), boundary: true });
  }
  return rows;
}

function bodyView(side) {
  if (!side || !side.body) return null;
  return { bodySha256: side.body.sha256 || null, capturedBytes: side.body.bytes, observedBytes: side.bodyBytes, truncated: side.truncated === true,
    ...(side.statusCode !== undefined ? { statusCode: side.statusCode } : {}) };
}

/**
 * Correlate one saved exchange with a local sample file.
 * Exact body identity is E1 (the captured bytes equal the file bytes); literal endpoint/API
 * presence is E0 (a lead, not proof the sample uses it). Query values are never read.
 */
export function correlateCaptureTraffic(service, args) {
  const input = argumentsOf(args);
  const record = service.record(input.id, input.session_id), value = record.result;
  const sample = sampleFile(input);
  let url;
  try { url = new URL(value.url); } catch { fail('CAPTURE_STORE_CHANGED', 'Saved capture record has no parseable URL'); }
  const lowered = lowerAscii(sample.bytes);
  const links = [], unmatched = [];
  let truncatedMatches = false, scannedNeedles = 0;

  const addIdentity = (direction, side) => {
    const view = bodyView(side);
    if (!view || !view.bodySha256 || !view.capturedBytes) return;
    if (value.tunnel === true || value.encrypted === true) return;
    if (view.bodySha256 !== sample.sha256 || view.capturedBytes !== sample.bytes.length) return;
    links.push({ kind: 'body-bytes-identity', direction, evidenceLevel: 'E1', bodySha256: view.bodySha256, bytes: view.capturedBytes,
      captureComplete: value.complete === true && !view.truncated,
      detail: view.truncated
        ? 'The stored captured bytes are exactly this file; the capture itself was truncated after these bytes.'
        : 'The captured body bytes are exactly this sample file. This does not show that the client executed or loaded it.' });
  };
  addIdentity('request', value.request);
  addIdentity('response', value.response);

  const endpointNeedles = capturedNeedles(value, url), needles = [...endpointNeedles, ...apiNeedles()];
  for (const needle of needles) {
    const remaining = MATCH_LIMIT - links.reduce((total, row) => total + (row.matches?.length || 0), 0);
    if (remaining <= 0) { truncatedMatches = true; break; }
    scannedNeedles += 1;
    const { matches, truncated } = findLiteral(sample.bytes, lowered, needle.text, { boundary: needle.boundary === true, remaining: Math.min(MATCH_PER_NEEDLE, remaining) });
    truncatedMatches ||= truncated;
    if (matches.length) links.push({ kind: needle.kind, label: needle.label, needle: needle.text, evidenceLevel: 'E0',
      ambiguous: needle.ambiguous === true, matches,
      detail: 'The literal appears in the sample bytes. It may be a string, an import name or unrelated data; presence does not show that the sample uses it at runtime.' });
    else if (needle.kind !== 'communication-api-literal') unmatched.push({ kind: needle.kind, label: needle.label, needle: needle.text,
      detail: 'Not found as a literal. The sample may build it dynamically, store it encoded or not use it; absence is not proof.' });
  }

  return {
    schema: 'ig5.trafficCorrespondence.v1', action: 'correlate', mode: 'read-only',
    executed: false, networkRequests: 0,
    capture: { id: record.id, session_id: value.session_id, method: value.method, origin: url.origin, host: url.hostname,
      path: value.protocol === 'connect' || value.encrypted ? null : url.pathname, queryValuesExcluded: true,
      statusCode: value.response?.statusCode ?? null, protocol: value.protocol, complete: value.complete === true,
      truncated: value.request?.truncated === true || value.response?.truncated === true,
      encrypted: value.encrypted === true, tunnel: value.tunnel === true, websocket: value.protocol === 'websocket',
      request: bodyView(value.request), response: bodyView(value.response) },
    sample: { path: sample.path, sha256: sample.sha256, bytes: sample.bytes.length },
    evidence: { identityLevel: 'E1', literalLevel: 'E0',
      note: 'E1 means the captured body bytes equal this file. E0 means the literal occurs in the sample bytes; it does not show the sample uses that endpoint, header or API, and absence does not show it does not.' },
    links, unmatched,
    coverage: { scannedBytes: sample.bytes.length, sampleLimitBytes: SAMPLE_LIMIT, needlesEvaluated: scannedNeedles,
      endpointNeedles: endpointNeedles.length, literalMatchLimit: MATCH_LIMIT, matchesTruncated: truncatedMatches },
    note: 'Read-only correlation of saved capture metadata and a local file. No engine was opened, no listener started and no request sent. Unobserved server code and runtime use of an endpoint remain unknown.',
  };
}
