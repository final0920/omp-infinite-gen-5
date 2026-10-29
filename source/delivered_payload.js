// Pure byte triage only. No filesystem, network, decompression, code evaluation,
// native loading, or claimed recovery of undisclosed server-side source code.
export const DELIVERED_PAYLOAD_LIMITS = Object.freeze({ inputBytes: 8 * 1024 * 1024, headerBytes: 256 * 1024,
  textBytes: 256 * 1024, hintCharacters: 65536, jsonDepth: 32, jsonTokens: 8192, previewCharacters: 32 });

const fail = message => { throw Object.assign(new TypeError(message), { code: 'DELIVERED_PAYLOAD_INPUT' }); };
function field(object, name) {
  const property = Object.getOwnPropertyDescriptor(object, name);
  if (property && !('value' in property)) fail('Payload metadata must not contain accessors');
  return property?.value;
}
function plain(value) { return value && typeof value === 'object' && [Object.prototype, null].includes(Object.getPrototypeOf(value)); }
function bool(object, name) { const value = field(object, name); if (value !== undefined && typeof value !== 'boolean') fail(`${name} must be boolean`); return value; }
const MIME = new Set(['application/json', 'text/json', 'application/javascript', 'text/javascript', 'application/ecmascript',
  'text/html', 'text/plain', 'application/wasm', 'application/octet-stream', 'application/zip', 'application/gzip',
  'application/x-gzip', 'application/x-dosexec', 'application/vnd.microsoft.portable-executable', 'application/x-executable']);
const ENCODINGS = new Set(['identity', 'gzip', 'x-gzip', 'deflate', 'br', 'zstd', 'compress']);
function mediaHints(options) {
  const contentType = field(options, 'contentType'), contentEncoding = field(options, 'contentEncoding');
  for (const value of [contentType, contentEncoding]) if (value !== undefined && value !== null && typeof value !== 'string') fail('Content metadata must be a string');
  const type = (contentType || '').slice(0, 256).split(';')[0].trim().toLowerCase();
  const encoding = (contentEncoding || '').slice(0, 256).split(',').map(item => item.trim().toLowerCase()).filter(Boolean);
  return { contentTypeHint: MIME.has(type) ? type : null, contentTypeRecognized: MIME.has(type),
    contentEncodingHint: encoding.slice(0, 8).map(value => ENCODINGS.has(value) ? value : 'unknown'),
    metadataTruncated: (contentType?.length || 0) > 256 || (contentEncoding?.length || 0) > 256 || encoding.length > 8,
    trusted: false };
}

function jsonBudget(text) {
  let depth = 0, maximumDepth = 0, tokens = 0, quoted = false, escaped = false, primitive = false;
  for (let at = 0; at < text.length; at++) {
    const char = text[at];
    if (quoted) { if (escaped) escaped = false; else if (char === '\\') escaped = true; else if (char === '"') quoted = false; continue; }
    if (char === '"') { quoted = true; primitive = false; tokens++; }
    else if (char === '{' || char === '[') { depth++; maximumDepth = Math.max(maximumDepth, depth); tokens++; primitive = false; }
    else if (char === '}' || char === ']') { depth--; primitive = false; }
    else if (char === ',' || char === ':') { tokens++; primitive = false; }
    else if (!/\s/u.test(char) && !primitive) { primitive = true; tokens++; }
    if (maximumDepth > DELIVERED_PAYLOAD_LIMITS.jsonDepth) return { allowed: false, reason: 'json-depth-budget', tokens, maximumDepth };
    if (tokens > DELIVERED_PAYLOAD_LIMITS.jsonTokens) return { allowed: false, reason: 'json-token-budget', tokens, maximumDepth };
  }
  return { allowed: true, tokens, maximumDepth };
}

function jsonShape(value) {
  const type = item => item === null ? 'null' : Array.isArray(item) ? 'array' : typeof item;
  const counts = { object: 0, array: 0, string: 0, number: 0, boolean: 0, null: 0 };
  let nodes = 0, unsafeNumbers = 0;
  const work = [value];
  while (work.length) {
    const item = work.pop(), kind = type(item); counts[kind]++; nodes++;
    if (kind === 'object') for (const child of Object.values(item)) work.push(child);
    else if (kind === 'array') for (const child of item) work.push(child);
    else if (kind === 'number' && (!Number.isFinite(item) || Number.isInteger(item) && !Number.isSafeInteger(item))) unsafeNumbers++;
  }
  return { topLevel: type(value), topLevelMembers: value && typeof value === 'object' ? Object.keys(value).length : null,
    nodes, valueTypes: counts, unsafeNumberRepresentations: unsafeNumbers,
    valuesIncluded: false, keyNamesIncluded: false, duplicateKeysChecked: false };
}

/** Classifies only supplied bytes and explicit capture metadata, without executing payloads. */
export function inspectDeliveredPayload(input, options = {}) {
  if (!Buffer.isBuffer(input) && !(input instanceof Uint8Array)) fail('Payload must be Buffer or Uint8Array bytes');
  if (input.byteLength > DELIVERED_PAYLOAD_LIMITS.inputBytes) fail('Payload exceeds the 8 MiB inspection budget');
  if (!plain(options)) fail('Payload metadata must be a plain object');
  const bytes = Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  const complete = bool(options, 'complete'), truncated = bool(options, 'truncated');
  const websocket = field(options, 'websocket');
  if (websocket !== undefined && websocket !== null && !plain(websocket)) fail('websocket metadata must be a plain object');
  const ws = websocket || null;
  const wsCompressed = ws ? bool(ws, 'compressed') === true || field(ws, 'payloadEncoding') === 'compressed-undecoded' : false;
  const wsPartial = ws ? bool(ws, 'partial') === true || bool(ws, 'fin') !== true || field(ws, 'opcode') === 0 : false;
  const opcode = ws ? field(ws, 'opcode') : null;
  if (opcode !== null && opcode !== undefined && (!Number.isInteger(opcode) || opcode < 0 || opcode > 15)) fail('WebSocket opcode must be 0..15');
  const wsControl = ws && [8, 9, 10].includes(opcode);
  const media = mediaHints(options), evidence = [], candidates = [], nextActions = [];
  const header = bytes.subarray(0, DELIVERED_PAYLOAD_LIMITS.headerBytes);
  const sourcePartial = truncated === true || complete === false || wsPartial;
  const source = { complete: complete === true && !sourcePartial, truncated: truncated === true,
    completeness: sourcePartial ? 'partial' : complete === true ? 'complete' : 'unknown',
    websocket: ws ? { opcode: opcode ?? null, compressed: wsCompressed, partial: wsPartial, controlFrame: Boolean(wsControl), reassembled: false } : null };
  const result = {
    kind: 'delivered-payload-inspection', bytes: bytes.length, source, media,
    encoding: { encoded: false, requiresExplicitDecode: false, reason: null },
    evidence, candidates, text: { inspected: false, utf8: null, json: null },
    preview: { kind: 'omitted', reason: 'Payload text, JSON values and key names are omitted to avoid disclosure.' },
    nextActions,
    limitations: ['Only supplied bytes are inspected; response MIME and encoding labels are untrusted hints.',
      'Binary signatures and header checks do not prove a valid, complete or executable file.',
      'Delivered client bytes do not reveal undisclosed server implementation or prove the full application logic.',
      'No payload is executed, loaded, decompressed or sent; no network or filesystem access occurs.',
      'Text/code observations are heuristics; no syntax or behavior validation is performed for scripts.',
      'Unknown or opaque bytes do not establish encryption; no encryption claim is made from entropy.'],
    budget: { ...DELIVERED_PAYLOAD_LIMITS, inspectedHeaderBytes: header.length, textBudgetExceeded: bytes.length > DELIVERED_PAYLOAD_LIMITS.textBytes,
      headerBudgetExceeded: bytes.length > header.length, jsonBudgetExceeded: false },
  };
  const add = (format, confidence, validation, details = {}) => candidates.push({ format, confidence, validation, ...details });
  const ev = (code, details = {}) => evidence.push({ code, ...details });
  const magic = (...values) => header.length >= values.length && values.every((value, index) => header[index] === value);
  const preview = count => { result.preview = { kind: 'header-hex', hex: header.subarray(0, Math.min(count, 16)).toString('hex'), byteCount: Math.min(count, header.length, 16) }; };
  if (source.completeness !== 'complete') nextActions.push('Preserve partial/unknown capture completeness; obtain missing bytes before claiming a complete delivered artifact.');
  if (!bytes.length) { add('empty', 'high', 'byte-length-only'); ev('EMPTY_PAYLOAD'); return result; }
  if (wsControl) {
    ev('WEBSOCKET_CONTROL_FRAME'); add('websocket-control', 'high', 'capture-metadata-only');
    result.limitations.push('A WebSocket control frame is not an application message.'); return result;
  }

  // Container hints remain hints: no checksum, stream or archive extraction is attempted.
  if (magic(0x1f, 0x8b)) {
    preview(10); add('gzip', 'medium', 'header-only');
    ev('GZIP_SIGNATURE', { fixedHeaderPresent: header.length >= 10,
      deflateMethod: header.length >= 3 ? header[2] === 8 : null,
      reservedFlagsClear: header.length >= 4 ? (header[3] & 0xe0) === 0 : null });
    result.encoding = { encoded: true, requiresExplicitDecode: true, reason: 'gzip-signature' };
  } else if (header.length >= 2 && (header[0] & 15) === 8 && (header[0] >> 4) <= 7 && ((header[0] << 8) + header[1]) % 31 === 0) {
    preview(2); add('zlib', 'low', 'header-only');
    ev('ZLIB_HEADER_CHECK', { presetDictionary: Boolean(header[1] & 32), dictionaryIdPresent: !(header[1] & 32) || header.length >= 6 });
    result.encoding = { encoded: true, requiresExplicitDecode: true, reason: 'zlib-header-hint' };
  } else if (magic(0x50, 0x4b, 3, 4) || magic(0x50, 0x4b, 5, 6)) {
    preview(4); add('zip', 'medium', 'header-only');
    const local = header[2] === 3, minimum = local ? 30 : 22;
    ev('ZIP_SIGNATURE', { headerKind: local ? 'local-file' : 'end-of-central-directory', fixedHeaderPresent: header.length >= minimum });
    if (local && header.length >= 30) ev('ZIP_LOCAL_HEADER_FIELDS', { compressionMethod: header.readUInt16LE(8), encryptedFlag: Boolean(header.readUInt16LE(6) & 1),
      variableHeaderPresent: 30 + header.readUInt16LE(26) + header.readUInt16LE(28) <= header.length });
    result.encoding = { encoded: true, requiresExplicitDecode: true, reason: 'archive-requires-explicit-extraction' };
  }
  if (wsCompressed) {
    ev('WEBSOCKET_COMPRESSION_UNDECODED');
    result.encoding = { encoded: true, requiresExplicitDecode: true, reason: 'websocket-compressed-payload' };
    result.limitations.push('WebSocket compression may require connection context and prior frames; no standalone deflate equivalence is assumed.');
  }
  const encodedHint = media.contentEncodingHint.some(value => value !== 'identity');
  if (encodedHint) {
    ev('CONTENT_ENCODING_HINT_REQUIRES_REVIEW');
    if (!result.encoding.encoded) result.encoding = { encoded: true, requiresExplicitDecode: true, reason: 'unverified-content-encoding-hint' };
  }

  // Inspect raw executable headers even if a MIME label disagrees, but never inspect
  // compressed WebSocket fragments as if they were decoded application bytes.
  if (!wsCompressed && !['gzip-signature', 'zlib-header-hint', 'archive-requires-explicit-extraction'].includes(result.encoding.reason)) {
    if (magic(0x4d, 0x5a)) {
      preview(2); ev('DOS_MZ_SIGNATURE');
      if (header.length < 64) { add('pe', 'low', 'incomplete-header'); ev('PE_DOS_HEADER_INCOMPLETE'); }
      else {
        const peOffset = header.readUInt32LE(0x3c); ev('PE_HEADER_POINTER', { offset: peOffset });
        if (peOffset < 64) { add('dos-or-malformed-pe', 'low', 'malformed-header'); ev('PE_HEADER_POINTER_BEFORE_DOS_HEADER'); }
        else if (peOffset + 24 > header.length) {
          add('pe', 'low', 'unverified-header');
          ev(peOffset + 24 > bytes.length ? 'PE_HEADER_POINTER_OUTSIDE_CAPTURE' : 'PE_HEADER_POINTER_OUTSIDE_BUDGET');
        } else if (header.readUInt32LE(peOffset) !== 0x00004550) { add('dos-or-malformed-pe', 'low', 'signature-mismatch'); ev('PE_SIGNATURE_MISMATCH'); }
        else {
          const sections = header.readUInt16LE(peOffset + 6), optionalBytes = header.readUInt16LE(peOffset + 20);
          const optionalMagic = optionalBytes >= 2 && peOffset + 26 <= header.length ? header.readUInt16LE(peOffset + 24) : null;
          const structural = sections > 0 && sections <= 96 && [0x10b, 0x20b].includes(optionalMagic)
            && optionalBytes >= (optionalMagic === 0x20b ? 112 : 96)
            && peOffset + 24 + optionalBytes + sections * 40 <= header.length;
          add('pe', structural ? 'high' : 'medium', 'header-only');
          ev('PE_COFF_HEADER', { machine: header.readUInt16LE(peOffset + 4), sections, optionalHeaderBytes: optionalBytes,
            optionalMagic, boundedHeaderShapeConsistent: structural });
          result.limitations.push('PE section contents, imports, signatures, relocations and loadability are not validated.');
        }
      }
    } else if (magic(0x7f, 0x45, 0x4c, 0x46)) {
      preview(7); add('elf', 'medium', 'header-only');
      if (header.length < 16) ev('ELF_IDENT_INCOMPLETE');
      else {
        const bits = header[4] === 1 ? 32 : header[4] === 2 ? 64 : null;
        const endian = header[5] === 1 ? 'little' : header[5] === 2 ? 'big' : null;
        const expected = bits === 32 ? 52 : bits === 64 ? 64 : null;
        ev('ELF_IDENT', { bits, endian, identVersion: header[6], fixedHeaderPresent: expected !== null && header.length >= expected });
        if (expected && endian && header.length >= expected) {
          const read16 = offset => endian === 'little' ? header.readUInt16LE(offset) : header.readUInt16BE(offset);
          ev('ELF_HEADER_FIELDS', { machine: read16(18), headerBytes: read16(bits === 32 ? 40 : 52),
            boundedHeaderShapeConsistent: header[6] === 1 && read16(bits === 32 ? 40 : 52) === expected });
        }
        result.limitations.push('ELF program/section tables and loadability are not validated.');
      }
    } else if (magic(0, 0x61, 0x73, 0x6d)) {
      preview(8); add('wasm', 'medium', 'header-only');
      ev('WASM_HEADER', { version: header.length >= 8 ? header.readUInt32LE(4) : null,
        supportedVersionPrefix: header.length >= 8 && header.readUInt32LE(4) === 1 });
      result.limitations.push('WASM sections, instructions and module validity are not validated or instantiated.');
    }
  }
  if (result.encoding.requiresExplicitDecode) {
    nextActions.push('Select the actual encoding from byte evidence and capture context, explicitly decode/extract with a bounded decoder, preserve the original bytes, then inspect the result.');
    result.text = { inspected: false, utf8: null, json: null, reason: 'encoded-or-encoding-uncertain' };
  } else if (candidates.length) {
    result.text = { inspected: false, utf8: null, json: null, reason: 'binary-header-candidate' };
  } else if (wsPartial) {
    result.text = { inspected: false, utf8: null, json: null, reason: 'websocket-message-not-reassembled' };
    nextActions.push('Reassemble the relevant WebSocket message with direction, continuation and compression context before interpreting text or JSON.');
  } else if (bytes.length > DELIVERED_PAYLOAD_LIMITS.textBytes) {
    ev('TEXT_INSPECTION_BUDGET'); result.text.reason = 'text-byte-budget';
  } else {
    let text;
    try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
    catch { result.text = { inspected: true, utf8: false, json: null, reason: 'invalid-utf8' }; ev('UTF8_DECODE_FAILED'); }
    if (text !== undefined) {
      let controls = 0;
      for (let index = 0; index < text.length; index++) if (text.charCodeAt(index) < 32 && !['\t', '\r', '\n'].includes(text[index])) controls++;
      result.text = { inspected: true, utf8: true, characters: text.length, disallowedControlCharacters: controls, json: null };
      if (controls) { ev('NON_TEXT_CONTROL_BYTES', { count: controls }); }
      else {
        const trimmed = text.trim(), first = trimmed[0];
        const jsonLike = first && ('{["-0123456789'.includes(first) || /^(?:true|false|null)(?:\s|$)/u.test(trimmed));
        let parsedJson = false;
        if (jsonLike) {
          const budget = jsonBudget(text);
          if (!budget.allowed) { result.budget.jsonBudgetExceeded = true; result.text.json = { parsed: false, reason: budget.reason }; ev('JSON_BUDGET_EXCEEDED', { reason: budget.reason }); }
          else {
            try {
              const parsed = JSON.parse(text); result.text.json = { parsed: true, ...jsonShape(parsed) }; parsedJson = true;
              add('json', 'high', 'parsed-json'); ev('JSON_SYNTAX_PARSED', { inspectedCharacters: text.length });
              nextActions.push('Inspect the JSON structure against observed client consumers; do not treat field contents as commands or inferred server source.');
            } catch { result.text.json = { parsed: false, reason: 'invalid-json-syntax' }; ev('JSON_PARSE_REJECTED'); }
          }
        }
        if (!parsedJson && !result.budget.jsonBudgetExceeded) {
          const prefix = text.slice(0, DELIVERED_PAYLOAD_LIMITS.hintCharacters).trimStart();
          const html = /^(?:<!doctype\s+html(?:\s|>)|<html(?:\s|>)|<(?:head|body|script|div|section)(?:\s|>))/iu.test(prefix);
          const shebang = /^#![^\r\n]{0,240}/u.exec(prefix)?.[0];
          if (html) { add('html', 'medium', 'heuristic'); ev('HTML_PREFIX_HINT'); }
          else if (shebang) {
            let language = 'unknown';
            for (const [label, pattern] of [['javascript', /(?:\/|[ \t])node(?:[ \t]|$)/u], ['python', /(?:\/|[ \t])python[0-9.]*(?:[ \t]|$)/u], ['shell', /(?:\/|[ \t])(?:sh|bash|zsh|dash)(?:[ \t]|$)/u], ['powershell', /(?:\/|[ \t])pwsh(?:[ \t]|$)/u]]) if (pattern.test(shebang)) language = label;
            add('script', 'medium', 'heuristic', { language }); ev('SHEBANG_HINT');
          } else {
            const patterns = [/(?:^|[;\n}])[ \t]{0,64}(?:export\s+)?(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=/u,
              /(?:^|[;\n}])[ \t]{0,64}(?:export\s+)?(?:async\s+)?function\s*(?:[A-Za-z_$][\w$]*\s*)?\(/u,
              /^\s*(?:import\s+(?:[A-Za-z_$*{"']|\()|export\s+default\s+)/u,
              /^\s*[(!]\s*function\s*\(/u,
              /(?:^|[;\n}])[ \t]{0,64}(?:module\.exports|exports\.[A-Za-z_$][\w$]*)\s*=/u];
            const hits = patterns.reduce((count, pattern) => count + Number(pattern.test(prefix)), 0);
            if (hits) { add('javascript', 'low', 'heuristic'); ev('JAVASCRIPT_LEXICAL_HINTS', { patternFamilies: hits }); }
          }
        }
        if (!candidates.length) add('text', 'low', 'utf8-only');
        if (candidates.some(candidate => ['html', 'javascript', 'script'].includes(candidate.format))) nextActions.push('Review delivered text statically as untrusted data; follow observed calls/data use without evaluating the script or assuming hidden server code is included.');
      }
    }
  }
  if (!candidates.length) add('unknown', 'low', 'insufficient-evidence');
  if (candidates.some(candidate => ['pe', 'elf', 'wasm'].includes(candidate.format))) nextActions.push('Preserve exact bytes and provenance, validate the complete format, then open an explicitly materialized artifact in the appropriate static analysis backend; do not execute it.');
  if (candidates.some(candidate => candidate.format === 'unknown')) nextActions.push('Correlate framing and client-side consumers, or use bounded protocol/crypto analysis; opacity alone does not identify encryption or recover logic.');
  return result;
}
