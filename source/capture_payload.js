import fs from 'node:fs';
import path from 'node:path';
import { inspectDeliveredPayload } from './delivered_payload.js';
import { hashBytes, readStableFile } from './analysis_artifacts.js';

const BODY_LIMIT = 1048576;
const directories = new WeakMap();
const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
const equalIdentity = (a, b) => a.dev === b.dev && a.ino === b.ino;

function regularDirectory(filename) {
  const stat = fs.lstatSync(filename, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail('PAYLOAD_UNSAFE_PATH', 'Payload storage requires a regular, non-linked directory');
  return stat;
}
function regularFile(filename) {
  const stat = fs.lstatSync(filename, { bigint: true });
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n) fail('PAYLOAD_UNSAFE_PATH', 'Payload destination must be a regular file with exactly one link');
  return stat;
}
function directoryFor(service) {
  const root = path.resolve(service.cfg.artifactDir), filename = path.join(root, 'capture-payloads');
  const rootIdentity = regularDirectory(root);
  const previous = directories.get(service);
  if (previous && (previous.root !== root || !equalIdentity(previous.rootIdentity, rootIdentity))) fail('PAYLOAD_STORE_CHANGED', 'Payload storage root was replaced');
  if (!previous) {
    try { fs.mkdirSync(filename, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
  }
  const identity = regularDirectory(filename);
  if (previous && !equalIdentity(previous.identity, identity)) fail('PAYLOAD_STORE_CHANGED', 'Payload output directory was replaced');
  const current = previous || { root, filename, rootIdentity, identity };
  directories.set(service, current);
  return current;
}
function assertDirectory(directory) {
  if (!equalIdentity(directory.rootIdentity, regularDirectory(directory.root)) || !equalIdentity(directory.identity, regularDirectory(directory.filename))) fail('PAYLOAD_STORE_CHANGED', 'Payload storage directory changed during materialization');
}
function header(headers, name) {
  const entry = Object.entries(headers || {}).find(([key]) => key.toLowerCase() === name);
  return entry ? (Array.isArray(entry[1]) ? entry[1].join(',') : String(entry[1])) : '';
}
function contentType(headers) {
  const value = header(headers, 'content-type').split(';', 1)[0].trim().toLowerCase();
  return value.length <= 127 && /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(value) ? value : '';
}
function contentEncoding(headers) {
  const value = header(headers, 'content-encoding').trim().toLowerCase();
  if (!value) return { display: '', encoded: false };
  const tokens = value.split(',').map(token => token.trim());
  return { display: value.length <= 128 && tokens.every(token => /^[a-z0-9._-]+$/.test(token)) ? tokens.join(', ') : 'unknown', encoded: tokens.some(token => token !== 'identity') };
}
function sourcePayload(service, args = {}) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) fail('PAYLOAD_INVALID_INPUT', 'Payload selection requires a capture id and optional body direction');
  if (['path', 'output_path', 'destination', 'filename'].some(key => Object.hasOwn(args, key))) fail('PAYLOAD_INVALID_INPUT', 'Payload output paths and filenames are derived only from the captured SHA-256');
  const record = service.record(args.id, args.session_id), value = record.result;
  const exported = service.export(args), direction = exported.direction, selected = value[direction];
  const meta = service.artifacts.metadata(record.id);
  const sourceReportSha256 = hashBytes(Buffer.from(JSON.stringify(record)));
  if (sourceReportSha256 !== meta.result.recordSha256) fail('PAYLOAD_SOURCE_CHANGED', 'Capture report metadata changed during payload selection');
  const bytes = service.artifacts.read(exported.input.ref, BODY_LIMIT).data, sha256 = hashBytes(bytes);
  if (sha256 !== selected.body.sha256 || selected.body.bytes !== bytes.length || exported.body.sha256 !== sha256) fail('PAYLOAD_SOURCE_CHANGED', 'Capture body metadata does not match its content-addressed bytes');
  const encoding = contentEncoding(selected.headers), type = contentType(selected.headers);
  const reasons = [];
  if (!exported.complete || selected.truncated || value.complete !== true || selected.bodyBytes !== bytes.length) reasons.push('INCOMPLETE_CAPTURE');
  if (!bytes.length) reasons.push('EMPTY_PAYLOAD');
  if (encoding.encoded) reasons.push('HTTP_CONTENT_ENCODING_REQUIRES_EXPLICIT_DECODE');
  if (direction === 'response' && (selected.statusCode === 206 || header(selected.headers, 'content-range'))) reasons.push('PARTIAL_HTTP_RESOURCE');
  if (value.websocketHandshake) reasons.push('WEBSOCKET_HANDSHAKE_HAS_NO_DELIVERED_MESSAGE');
  if (value.protocol === 'websocket') {
    const frame = value.websocket || {};
    const frameDirection = frame.direction === 'client_to_server' ? 'request' : frame.direction === 'server_to_client' ? 'response' : null;
    if (direction !== frameDirection) reasons.push('WEBSOCKET_DIRECTION_MISMATCH');
    if (frame.fin !== true || ![1, 2].includes(frame.opcode) || frame.partial === true) reasons.push('WEBSOCKET_FRAGMENT_OR_CONTROL_FRAME');
    if (frame.compressed !== false || frame.rsv2 === true || frame.rsv3 === true || frame.payloadEncoding === 'compressed-undecoded') reasons.push('WEBSOCKET_ENCODING_REQUIRES_EXPLICIT_DECODE');
  }
  let origin = null;
  try { origin = new URL(value.url).origin; } catch { /* preserve source digest without an invented endpoint */ }
  const provenance = {
    kind: 'captured-delivered-payload', captureId: record.id, sessionId: value.session_id, direction,
    sourceReportSha256, sourceMetadataSha256: meta.digest, sourceBodyRef: exported.input.ref,
    sourceUrlSha256: hashBytes(Buffer.from(String(value.url))), sourceOrigin: origin,
    protocol: value.protocol, exchangeId: value.exchangeId || null, parentExchangeId: value.parentExchangeId || null,
    capturedAt: value.startedAt, sha256, byteCount: bytes.length, observedBytes: selected.bodyBytes,
    complete: exported.complete === true && selected.bodyBytes === bytes.length, truncated: selected.truncated === true,
    representation: exported.representation,
  };
  const classification = inspectDeliveredPayload(bytes, { contentType: type, contentEncoding: encoding.display,
    complete: provenance.complete, truncated: provenance.truncated, ...(value.protocol === 'websocket' ? { websocket: value.websocket } : {}) });
  return { bytes, exported, classification, provenance, reasons };
}
function view(source) {
  return { capture_id: source.provenance.captureId, session_id: source.provenance.sessionId, direction: source.provenance.direction,
    sha256: source.provenance.sha256, byteCount: source.bytes.length, complete: source.provenance.complete,
    truncated: source.provenance.truncated, input: source.exported.input, provenance: source.provenance,
    classification: source.classification, canMaterialize: source.reasons.length === 0, blockedReasons: source.reasons, executed: false };
}

/** Bounded read-only classification; it never downloads, decompresses, opens an engine or executes bytes. */
export function inspectCapturePayload(service, args) { return view(sourcePayload(service, args)); }

function verifyDestination(filename, sha256, length) {
  const before = regularFile(filename);
  const value = readStableFile(filename, BODY_LIMIT).data;
  const after = regularFile(filename);
  if (!equalIdentity(before, after) || value.length !== length || hashBytes(value) !== sha256) fail('PAYLOAD_FILE_CHANGED', 'Existing payload does not match its immutable SHA-256 path; it was not overwritten');
}
function persist(directory, bytes, sha256) {
  assertDirectory(directory);
  const filename = path.join(directory.filename, `${sha256}.bin`);
  let fd, owned, failure, created = false;
  try {
    fd = fs.openSync(filename, 'wx', 0o600); created = true;
    owned = fs.fstatSync(fd, { bigint: true });
    if (!owned.isFile() || owned.nlink !== 1n) fail('PAYLOAD_UNSAFE_PATH', 'New payload file has an unexpected identity');
    let offset = 0;
    while (offset < bytes.length) {
      const written = fs.writeSync(fd, bytes, offset, bytes.length - offset);
      if (written <= 0) fail('PAYLOAD_WRITE_FAILED', 'Payload write made no progress');
      offset += written;
    }
    fs.fsyncSync(fd);
    if (!equalIdentity(owned, regularFile(filename))) fail('PAYLOAD_FILE_CHANGED', 'Payload destination changed while it was written');
  } catch (error) {
    if (created || error.code !== 'EEXIST') failure = error;
  } finally { if (fd !== undefined) fs.closeSync(fd); }
  if (failure) {
    // A failed exclusive write may leave a partial file at the hash path. Only
    // remove the regular single-link file whose opened identity we own. An
    // existing, substituted, linked or moved destination is never cleaned up.
    let removed = false;
    if (created && owned) {
      try {
        assertDirectory(directory);
        if (equalIdentity(owned, regularFile(filename))) { fs.unlinkSync(filename); removed = true; }
      } catch { /* Report retention rather than deleting an uncertain path. */ }
    }
    throw Object.assign(failure, { stage: 'file', partialFileRetained: created && !removed,
      ...(created && !removed ? { path: filename } : {}) });
  }
  assertDirectory(directory);
  verifyDestination(filename, sha256, bytes.length);
  return { filename, reused: !created };
}
function analysisHint(classification) {
  const format = classification.candidates?.[0]?.format || 'unknown';
  if (['pe', 'elf'].includes(format)) return { formatHint: format, nextTool: 'ig5_open', requiresExplicitCall: true,
    note: 'Header evidence is only a format candidate. Open the returned path explicitly for static loader validation; no program has been executed.' };
  if (['gzip', 'zlib'].includes(format)) return { formatHint: format, nextTool: 'ig5_crypto', requiresExplicitCall: true,
    note: 'Use an explicit bounded decompression recipe and inspect its resulting producer reference before further analysis.' };
  return { formatHint: format, nextTool: 'ig5_protocol', requiresExplicitCall: true,
    note: 'Inspect the returned bytes/reference or review recognized text as data. Unknown bytes remain a .bin file; no executable format or behavior is inferred from MIME alone.' };
}

/** Save only complete, decoded transport payload bytes under an immutable SHA-256 filename. */
export function materializeCapturePayload(service, args) {
  const source = sourcePayload(service, args);
  if (source.reasons.length) fail('PAYLOAD_NOT_MATERIALIZABLE', `Payload cannot be materialized: ${source.reasons.join(', ')}`);
  const directory = directoryFor(service), file = persist(directory, source.bytes, source.provenance.sha256);
  const hint = analysisHint(source.classification);
  const { result_id: _sourceProducer, ...bodyRef } = source.exported.body;
  let report;
  try {
    report = service.artifacts.save({ kind: 'delivered-payload', action: 'materialize',
      input: { ...bodyRef, origin: { kind: 'capture-payload', ...source.provenance } },
      output: bodyRef,
      result: { path: file.filename, sha256: source.provenance.sha256, byteCount: source.bytes.length,
        provenance: source.provenance, classification: source.classification, analysisHint: hint, executed: false } });
  } catch (error) {
    throw Object.assign(new Error('Payload bytes were saved, but the provenance report could not be committed; no engine was started'),
      { code: 'PAYLOAD_REPORT_FAILED', stage: 'report', fileSaved: true, path: file.filename, sha256: source.provenance.sha256, cause: error });
  }
  const metadata = service.artifacts.metadata(report.id);
  return { path: file.filename, sha256: source.provenance.sha256, byteCount: source.bytes.length, reused: file.reused,
    result_id: report.id, reportSha256: metadata.result.recordSha256,
    input: { ref: source.exported.input.ref, result_id: report.id }, provenance: source.provenance,
    classification: source.classification, analysisHint: hint, executed: false };
}
