import { hashBytes } from './analysis_artifacts.js';

const fail = message => { throw Object.assign(new Error(message), { code: 'CAPTURE_TRACE_INVALID' }); };
const keys = (value, allowed, name) => {
  if (!value || typeof value !== 'object' || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail(`${name} must be a plain object`);
  if (Reflect.ownKeys(value).some(key => typeof key !== 'string' || !allowed.includes(key) || !Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), 'value'))) fail(`${name} contains unsupported properties or accessors`);
};
function selector(value, fallback) {
  if (value === undefined) return { source: fallback };
  keys(value, ['source', 'offset', 'size'], 'symbol selector');
  if (value.source === fallback && value.offset === undefined && value.size === undefined) return { source: fallback };
  if (value.source !== 'body-field' || !Number.isSafeInteger(value.offset) || Object.is(value.offset, -0) || value.offset < 0 || value.offset > 1048575 || !Number.isSafeInteger(value.size) || value.size < 1 || value.size > 8)
    fail('body-field symbols require explicit offset >= 0 and size 1..8; bytes are kept in wire order');
  return { source: 'body-field', offset: value.offset, size: value.size };
}
function header(headers, key) {
  const found = Object.entries(headers || {}).find(([name]) => name.toLowerCase() === key);
  return found ? String(found[1]).trim().toLowerCase() : '';
}

/** Build observed traces from caller-selected application sessions, never from guessed TCP boundaries. */
export function buildCaptureStateTrace(service, args) {
  keys(args, ['action', 'traces', 'holdout', 'symbols'], 'capture trace request');
  const symbols = args.symbols ?? {};
  keys(symbols, ['request', 'response'], 'symbols');
  const requestSelector = selector(symbols.request, 'http-route');
  const responseSelector = selector(symbols.response, 'http-status');
  const usedIds = new Set(), traceIds = new Set(), provenance = [];
  let recordCount = 0, observedBytes = 0;
  const manifest = { schemaVersion: 'ig5.protocol-traces.v1', traces: [] };
  function traces(values, partition) {
    if (!Array.isArray(values) || values.length > 32 || partition === 'traces' && !values.length) fail('traces requires 1..32 explicit conversations; holdout supports at most 32');
    return values.map(trace => {
      keys(trace, ['id', 'session_id', 'start', 'complete', 'ids'], 'trace');
      if (typeof trace.id !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(trace.id) || traceIds.has(trace.id)) fail('Trace IDs must be unique short labels');
      traceIds.add(trace.id);
      if (!['session-start', 'unknown'].includes(trace.start) || typeof trace.complete !== 'boolean') fail('Each conversation must declare start and complete; capture sessions are not application sessions');
      if (typeof trace.session_id !== 'string' || !Array.isArray(trace.ids) || !trace.ids.length || trace.ids.length > 128) fail('Each trace requires session_id and 1..128 ordered capture ids');
      const events = [], records = [];
      let lastEnd = -Infinity, origin;
      for (const id of trace.ids) {
        if (++recordCount > 256) fail('Capture trace selection exceeds 256 total exchanges');
        if (usedIds.has(id)) fail('An exchange cannot appear twice or be shared between training and holdout');
        usedIds.add(id);
        const record = service.record(id, trace.session_id), value = record.result;
        if (value.encrypted || value.tunnel || value.websocketHandshake || !['http', 'https'].includes(value.protocol)) fail('State traces currently require complete plaintext HTTP exchanges; decode other protocols into explicit directional traces');
        if (!value.complete || value.error || value.request?.truncated || value.response?.truncated) fail('Incomplete exchanges cannot be treated as contiguous protocol events');
        const url = new URL(value.url), start = Date.parse(value.startedAt), end = Date.parse(value.endedAt);
        if (url.username || url.password || !Number.isFinite(start) || !Number.isFinite(end) || end < start || start < lastEnd) fail('Ordered exchanges must have valid, non-overlapping time ranges');
        if (origin !== undefined && url.origin !== origin) fail('A trace must select one exact origin; separate cross-origin conversations');
        origin = url.origin; lastEnd = end;
        const sourceReportSha256 = service.artifacts.metadata(record.id).result.recordSha256;
        if (hashBytes(Buffer.from(JSON.stringify(record))) !== sourceReportSha256) fail('Capture source changed during trace construction');
        const row = { captureId: record.id, sessionId: value.session_id, sourceReportSha256,
          urlSha256: hashBytes(Buffer.from(value.url)), originSha256: hashBytes(Buffer.from(url.origin)), startedAt: value.startedAt, endedAt: value.endedAt };
        for (const [side, direction, selected] of [['request', 'client_to_server', requestSelector], ['response', 'server_to_client', responseSelector]]) {
          const item = value[side];
          if (!item?.body || item.bodyBytes !== item.body.bytes) fail('Capture body completeness or length evidence does not match');
          observedBytes += item.body.bytes;
          if (observedBytes > 8 * 1024 * 1024) fail('Selected capture bodies exceed the 8 MiB verification budget');
          const bytes = service.artifacts.read(item.body.ref, 1048576).data;
          if (bytes.length !== item.body.bytes || hashBytes(bytes) !== item.body.sha256) fail('Capture body reference does not match');
          let symbol;
          if (selected.source === 'body-field') {
            const encoding = header(item.headers, 'content-encoding');
            if (encoding && encoding.split(',').some(token => token.trim() !== 'identity')) fail('Decode content-encoding before selecting a body event field');
            if (side === 'response' && (item.statusCode === 206 || header(item.headers, 'content-range'))) fail('A partial HTTP resource cannot supply a complete message field');
            if (selected.offset + selected.size > bytes.length) fail('The selected event field lies outside the complete captured body');
            symbol = 'field:' + bytes.subarray(selected.offset, selected.offset + selected.size).toString('hex');
          } else if (selected.source === 'http-route') {
            if (!/^[A-Z]{1,16}$/.test(value.method)) fail('Unsupported HTTP method symbol');
            symbol = value.method + ':route:' + hashBytes(Buffer.from(url.pathname)).slice(0, 32);
          } else {
            if (!Number.isInteger(item.statusCode) || item.statusCode < 100 || item.statusCode > 599) fail('HTTP response status is unavailable');
            symbol = 'status:' + item.statusCode;
          }
          events.push({ direction, symbol, complete: true, sourceId: record.id + ':' + side,
            evidence: { captureId: record.id, sha256: sourceReportSha256, bodyRef: item.body.ref, bodySha256: item.body.sha256 } });
        }
        records.push(row); provenance.push({ partition, traceId: trace.id, ...row });
      }
      return { id: trace.id, sourceId: 'trace:' + hashBytes(Buffer.from(JSON.stringify(records))), start: trace.start, complete: trace.complete, events };
    });
  }
  manifest.traces = traces(args.traces, 'traces');
  const heldout = traces(args.holdout ?? [], 'holdout');
  if (args.holdout !== undefined) manifest.holdout = heldout;
  const data = Buffer.from(JSON.stringify(manifest));
  if (data.length > 1024 * 1024) fail('State trace manifest exceeds 1 MiB');
  const output = service.artifacts.put(data);
  const result = { schemaVersion: manifest.schemaVersion, counts: { traces: manifest.traces.length, holdout: heldout.length, exchanges: recordCount, events: recordCount * 2, verifiedBodyBytes: observedBytes },
    selectors: { request: requestSelector, response: responseSelector }, provenance,
    sessionBoundaries: 'caller-declared; not inferred from proxy or TCP sessions',
    abstraction: 'observed-directional-events; route hashes or caller-selected byte fields do not prove protocol semantics',
    networkSent: false, targetExecuted: false };
  const report = service.artifacts.save({ kind: 'capture-traces', action: 'state_trace', output, result });
  return { result_id: report.id, reportSha256: service.artifacts.metadata(report.id).result.recordSha256,
    input: { ref: output.ref, result_id: report.id }, counts: result.counts, selectors: result.selectors,
    sessionBoundaries: result.sessionBoundaries, abstraction: result.abstraction, networkSent: false, targetExecuted: false,
    next: 'Use input unchanged with ig5_protocol action=state_infer. A capture session may contain many independent application conversations; their boundaries remain caller declarations.' };
}
