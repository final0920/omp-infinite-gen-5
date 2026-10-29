import { createCaptureService } from './source/capture_service.js';
import { inspectCapturePayload, materializeCapturePayload } from './source/capture_payload.js';
import { buildCaptureStateTrace } from './source/capture_state_trace.js';
import { correlateCaptureTraffic } from './source/traffic_correlate.js';

export function defineCaptureTools(ctx, mgr, cfg, render) {
  mgr.capture ??= createCaptureService(mgr, cfg);
  const output = { schema: { type: 'object', additionalProperties: true },
    render: render || ((_args, value) => [{ type: 'text', text: JSON.stringify(value) }]) };
  const identity = { id: { type: 'string', description: 'Persistent capture report UUID returned by list/get' },
    session_id: { type: 'string', description: 'Capture session UUID; required for replay and recommended for stop/get/export' } };
  const trace = { type: 'object', properties: { id: { type: 'string', maxLength: 64 }, session_id: identity.session_id,
    start: { type: 'string', enum: ['session-start', 'unknown'], description: 'Explicit application conversation boundary; never inferred from proxy session' },
    complete: { type: 'boolean', description: 'Caller declares the conversation observation complete; does not prove protocol termination' },
    ids: { type: 'array', minItems: 1, maxItems: 128, items: identity.id } }, required: ['id', 'session_id', 'start', 'complete', 'ids'], additionalProperties: false };
  const symbol = fallback => ({ type: 'object', properties: { source: { type: 'string', enum: [fallback, 'body-field'] },
    offset: { type: 'integer', minimum: 0, maximum: 1048575 }, size: { type: 'integer', minimum: 1, maximum: 8 } }, required: ['source'], additionalProperties: false });
  return [
    { name: 'ig5_capture', description: 'Read independent proxy history and saved HTTP/HTTPS/WS/WSS evidence; never start a listener or send requests. get redacts common headers/query values; bodies are untrusted. export returns exact captured bytes as SHA refs. inspect_payload classifies bounded headers/text; materialize saves complete unencoded bytes under a fixed SHA path without executing/opening an engine. correlate compares one saved exchange with a local sample file: exact captured-body identity (E1) and literal host/path/header-value/network-API presence in the sample bytes (E0 leads, not proof of use), read-only and bounded to 32 MiB. state_trace builds an authenticated trace manifest from caller-selected ordered complete HTTP exchanges, with explicit application-session boundaries, direction, source hashes and separate holdout. Default event symbols are request method/path hash and response status; optional body-field selects 1..8 bytes. Pass returned input unchanged to ig5_protocol state_infer/state_validate. review makes passive observations, not exploit verification. Unseen server code and protocol semantics are not inferred. Use approved ig5_capture_control for start/stop/replay.',
      parameters: { type: 'object', properties: { action: { type: 'string', enum: ['status', 'list', 'get', 'export', 'review', 'inspect_payload', 'materialize', 'state_trace', 'correlate'] }, ...identity,
        sample: { type: 'object', properties: { path: { type: 'string', maxLength: 4096, description: 'Local sample file to compare; read-only, never executed or opened in an engine' },
          sha256: { type: 'string', description: 'Optional expected lowercase SHA-256; a mismatch fails instead of correlating a changed file' } }, required: ['path'], additionalProperties: false,
          description: 'correlate: local sample file (up to 32 MiB) compared with the selected exchange' },
        traces: { type: 'array', minItems: 1, maxItems: 32, items: trace, description: 'state_trace: caller-selected ordered non-overlapping HTTP application conversations' },
        holdout: { type: 'array', maxItems: 32, items: trace, description: 'Separate held-out conversations, with no repeated capture records' },
        symbols: { type: 'object', properties: { request: symbol('http-route'), response: symbol('http-status') }, additionalProperties: false, description: 'Default request method/path hash and response status symbols; optional body-field selects exact 1..8 bytes in wire order' },
        offset: { type: 'integer', minimum: 0, maximum: 1000000 }, limit: { type: 'integer', minimum: 1, maximum: 100 },
        body: { type: 'string', enum: ['request', 'response'], description: 'Body direction to export, inspect or materialize; default response for HTTP or captured direction for a WebSocket frame' } }, required: ['action'], additionalProperties: false }, output,
      execute(args = {}) {
        if (args.action === 'status') return mgr.capture.status();
        if (args.action === 'list') return mgr.capture.list(args);
        if (args.action === 'get') return mgr.capture.get(args.id, args);
        if (args.action === 'export') return mgr.capture.export(args);
        if (args.action === 'review') return mgr.capture.review(args);
        if (args.action === 'inspect_payload') return inspectCapturePayload(mgr.capture, args);
        if (args.action === 'materialize') return materializeCapturePayload(mgr.capture, args);
        if (args.action === 'state_trace') return buildCaptureStateTrace(mgr.capture, args);
        if (args.action === 'correlate') return correlateCaptureTraffic(mgr.capture, args);
        throw Object.assign(new Error('Capture action must be status, list, get, export, review, inspect_payload, materialize, state_trace or correlate'), { code: 'CAPTURE_INVALID_INPUT' });
      } },
    { name: 'ig5_capture_control', description: 'APPROVAL REQUIRED. Control IG5 independent local HTTP/HTTPS and WS/WSS proxy or replay one complete HTTP request. start binds only 127.0.0.1 with explicit origin scope; configure your client to use the returned port. tls=true enables HTTPS interception with a local CA the client must explicitly trust; default CONNECT remains encrypted. stop closes owned connections. replay requires saved id and active session_id, sends once to the original scoped origin with optional bounded request edits and never follows redirects. WebSocket frames/handshakes cannot be replayed. Remote side effects cannot be undone; failure/cancellation can leave outcomeUnknown. No Burp is required.',
      parameters: { type: 'object', properties: { action: { type: 'string', enum: ['start', 'stop', 'replay'] }, ...identity,
        port: { type: 'integer', minimum: 0, maximum: 65535, description: 'Loopback port; 0 chooses an unused port' },
        scope: { type: 'array', minItems: 1, maxItems: 32, items: { type: 'string', maxLength: 2048 }, description: 'Exact HTTP/HTTPS origins, e.g. http://127.0.0.1:3000; no wildcard or URL path. WS/WSS use the matching HTTP/HTTPS handshake origin.' },
        tls: { type: 'boolean', description: 'Explicit HTTPS interception; does not automatically change system/browser certificate trust' },
        request: { type: 'object', description: 'Optional approved replay edits. Path remains on the original origin, headers merge by name, body replaces captured bytes. Host/framing headers are normalized.', properties: {
          method: { type: 'string', maxLength: 32 }, path: { type: 'string', maxLength: 8192 },
          headers: { type: 'object', additionalProperties: { type: 'string', maxLength: 8192 } },
          body: { type: 'object', properties: { encoding: { type: 'string', enum: ['hex', 'base64'] }, data: { type: 'string', maxLength: 2097152 } }, required: ['encoding', 'data'], additionalProperties: false },
        }, additionalProperties: false } }, required: ['action'], additionalProperties: false }, output,
      execute: (args, execution) => mgr.capture.control(args, execution) },
  ];
}
