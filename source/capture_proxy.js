import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import { randomUUID } from 'node:crypto';

const MAX_BODY = 1024 * 1024;
const HOP_HEADERS = new Set(['connection', 'proxy-connection', 'proxy-authenticate', 'proxy-authorization', 'keep-alive', 'te', 'trailer', 'transfer-encoding', 'upgrade']);
const error = (code, message) => Object.assign(new Error(message), { code });
const integer = (value, min, max, name) => {
  if (!Number.isInteger(value) || value < min || value > max) throw error('CAPTURE_CONFIG', `${name} 必须是 ${min}–${max} 的整数`);
  return value;
};

/** Canonical origins only: no paths, credentials, fragments, or hidden URL normalization. */
export function normalizeCaptureScope(scope) {
  if (!Array.isArray(scope) || scope.length < 1 || scope.length > 128) throw error('CAPTURE_SCOPE', '抓包范围需要 1–128 个 HTTP/HTTPS origin');
  return [...new Set(scope.map(value => {
    if (typeof value !== 'string' || value.length > 2048 || /[\\\s?#]/u.test(value)) throw error('CAPTURE_SCOPE', '抓包范围 origin 无效');
    let url;
    try { url = new URL(value); } catch { throw error('CAPTURE_SCOPE', '抓包范围 origin 无效'); }
    if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw error('CAPTURE_SCOPE', '抓包范围只能包含协议、主机和端口');
    return url.origin;
  }))];
}

function headersForForward(headers) {
  const excluded = new Set(HOP_HEADERS);
  for (const token of String(headers.connection || '').split(',')) excluded.add(token.trim().toLowerCase());
  return Object.fromEntries(Object.entries(headers).filter(([name]) => !excluded.has(name.toLowerCase())));
}

function snapshot(limit) {
  let parts = [], size = 0, bytes = 0;
  return {
    add(chunk) {
      bytes += chunk.length;
      if (size < limit) {
        const part = Buffer.from(chunk.subarray(0, limit - size));
        parts.push(part); size += part.length;
      }
    },
    finish() {
      const body = Buffer.concat(parts, size); parts = [];
      return { body, bodyBytes: bytes, capturedBytes: size, truncated: bytes > size };
    },
  };
}

// Streaming frame decoder: buffers only the header and the bounded payload preview.
// Fragmentation and compression stay explicit; this does not infer application messages.
class WebSocketFrames {
  constructor({ limit, client, onFrame, onInvalid }) {
    Object.assign(this, { limit, client, onFrame, onInvalid });
    this.header = Buffer.alloc(14); this.headerBytes = 0; this.headerNeeded = 2;
    this.frame = null; this.disabled = false; this.fragmentCompressed = false; this.fragmentOpcode = null;
  }
  push(chunk) {
    if (this.disabled) return;
    let at = 0;
    while (at < chunk.length) {
      if (!this.frame) {
        const take = Math.min(this.headerNeeded - this.headerBytes, chunk.length - at);
        chunk.copy(this.header, this.headerBytes, at, at + take); this.headerBytes += take; at += take;
        if (this.headerBytes < this.headerNeeded) continue;
        if (this.headerNeeded === 2) {
          this.headerNeeded = 2 + ((this.header[1] & 127) === 126 ? 2 : (this.header[1] & 127) === 127 ? 8 : 0) + ((this.header[1] & 128) ? 4 : 0);
          if (this.headerBytes < this.headerNeeded) continue;
        }
        const marker = this.header[1] & 127, masked = Boolean(this.header[1] & 128);
        const length = marker === 127 ? this.header.readBigUInt64BE(2) : BigInt(marker === 126 ? this.header.readUInt16BE(2) : marker);
        const opcode = this.header[0] & 15, fin = Boolean(this.header[0] & 128), compressed = Boolean(this.header[0] & 64);
        if (length > BigInt(Number.MAX_SAFE_INTEGER) || masked !== this.client || ![0, 1, 2, 8, 9, 10].includes(opcode) || (opcode >= 8 && (!fin || length > 125n))) {
          this.disabled = true; this.onInvalid(); return;
        }
        if (opcode === 0 && (this.fragmentOpcode === null || compressed)
          || (opcode === 1 || opcode === 2) && this.fragmentOpcode !== null
          || opcode >= 8 && compressed) {
          this.disabled = true; this.onInvalid(); return;
        }
        const continuationCompressed = opcode === 0 && this.fragmentCompressed;
        if ((opcode === 1 || opcode === 2) && !fin) { this.fragmentOpcode = opcode; this.fragmentCompressed = compressed; }
        if (opcode === 0 && fin) { this.fragmentOpcode = null; this.fragmentCompressed = false; }
        this.frame = { opcode, fin, compressed: compressed || continuationCompressed, masked, payloadBytes: Number(length), consumed: 0,
          rsv2: Boolean(this.header[0] & 32), rsv3: Boolean(this.header[0] & 16),
          mask: masked ? Buffer.from(this.header.subarray(this.headerNeeded - 4, this.headerNeeded)) : null, preview: snapshot(this.limit) };
      }
      const frame = this.frame, take = Math.min(frame.payloadBytes - frame.consumed, chunk.length - at);
      if (take) {
        let bytes = chunk.subarray(at, at + take);
        // Only the retained prefix needs unmasking; avoid copying large discarded payload tails.
        const retain = Math.max(0, Math.min(take, this.limit - frame.consumed));
        if (frame.mask && retain) {
          const decoded = Buffer.from(bytes.subarray(0, retain));
          for (let i = 0; i < decoded.length; i++) decoded[i] ^= frame.mask[(frame.consumed + i) % 4];
          frame.preview.add(decoded);
          if (retain < take) frame.preview.add(bytes.subarray(retain));
        } else frame.preview.add(bytes);
        frame.consumed += take; at += take;
      }
      if (frame.consumed === frame.payloadBytes) {
        const { preview, mask: _mask, consumed: _consumed, ...metadata } = frame;
        this.onFrame({ ...metadata, ...preview.finish() });
        this.frame = null; this.headerBytes = 0; this.headerNeeded = 2;
      }
    }
  }
  get partial() { return Boolean(this.frame || this.headerBytes || this.disabled || this.fragmentOpcode !== null); }
}

/** Independent local forward proxy. Captures bytes without modifying system proxy settings. */
export class CaptureProxy {
  #options;
  #server = null;
  #innerServer = null;
  #sockets = new Set();
  #connections = new Set();
  #active = new Set();
  #pending = new Set();
  #scope = new Set();
  #generation = null;
  #port = null;
  #running = false;
  #stopping = null;
  #tls = false;
  #count = 0;
  #rejected = 0;
  #sinkErrors = 0;
  #lastError = null;
  #droppedFrames = 0;

  constructor({ onExchange, allowHosts, maxBodyBytes = MAX_BODY, timeoutMs = 30000, maxConnections = 64, certificateAuthority, upstreamCa } = {}) {
    if (typeof onExchange !== 'function') throw error('CAPTURE_CONFIG', 'onExchange 必须是函数');
    if (allowHosts !== undefined && (!Array.isArray(allowHosts) || allowHosts.some(host => typeof host !== 'string' || !host || host.length > 253))) throw error('CAPTURE_CONFIG', 'allowHosts 无效');
    this.#options = {
      onExchange, certificateAuthority, upstreamCa,
      allowHosts: allowHosts ? new Set(allowHosts.map(host => host.toLowerCase())) : null,
      maxBodyBytes: integer(maxBodyBytes, 0, MAX_BODY, 'maxBodyBytes'),
      timeoutMs: integer(timeoutMs, 100, 300000, 'timeoutMs'),
      maxConnections: integer(maxConnections, 1, 128, 'maxConnections'),
    };
  }

  status() {
    return {
      running: this.#running, host: '127.0.0.1', port: this.#port, captureId: this.#generation,
      scope: [...this.#scope], tlsInterceptEnabled: this.#tls,
      httpsMode: this.#tls ? 'mitm' : 'opaque-connect',
      activeConnections: this.#connections.size, activeExchanges: this.#active.size,
      pendingExchanges: this.#pending.size, capturedExchanges: this.#count,
      rejected: this.#rejected, sinkErrors: this.#sinkErrors, lastError: this.#lastError,
      droppedWebSocketFrames: this.#droppedFrames,
      maxBodyBytes: this.#options.maxBodyBytes, timeoutMs: this.#options.timeoutMs,
      maxConnections: this.#options.maxConnections,
      limitations: ['websocket-frames-not-reassembled', 'websocket-compression-not-decoded', 'http2-client-unsupported', 'no-system-proxy-change', 'body-snapshot-bounded'],
    };
  }

  async start({ port = 0, scope, tls: intercept = false } = {}) {
    if (this.#server || this.#stopping) throw error('CAPTURE_STATE', '抓包代理已启动或正在停止');
    const origins = normalizeCaptureScope(scope);
    integer(port, 0, 65535, 'port');
    if (typeof intercept !== 'boolean') throw error('CAPTURE_CONFIG', 'tls 必须是布尔值');
    if (intercept && typeof this.#options.certificateAuthority?.issue !== 'function') throw error('CAPTURE_TLS_CA', 'HTTPS 解密需要本地抓包 CA');
    for (const origin of origins) if (!this.#hostAllowed(new URL(origin).hostname)) throw error('CAPTURE_SCOPE', '抓包范围超出 allowHosts');
    this.#scope = new Set(origins);
    this.#tls = intercept;
    this.#generation = randomUUID();
    this.#count = 0; this.#rejected = 0; this.#sinkErrors = 0; this.#lastError = null; this.#droppedFrames = 0;
    const server = http.createServer({ maxHeaderSize: 32768 }, (req, res) => this.#handleHttp(req, res));
    server.requestTimeout = this.#options.timeoutMs;
    server.headersTimeout = Math.min(this.#options.timeoutMs, 15000);
    server.keepAliveTimeout = 5000;
    server.maxRequestsPerSocket = 100;
    server.on('connection', socket => {
      if (this.#connections.size >= this.#options.maxConnections) { this.#rejected++; socket.destroy(); return; }
      this.#connections.add(socket); this.#trackSocket(socket);
      socket.once('close', () => this.#connections.delete(socket));
      socket.setTimeout(this.#options.timeoutMs, () => socket.destroy());
    });
    server.on('connect', (req, socket, head) => { this.#handleConnect(req, socket, head).catch(() => socket.destroy()); });
    server.on('upgrade', (req, socket, head) => this.#handleUpgrade(req, socket, head));
    server.on('clientError', (_cause, socket) => this.#denySocket(socket, 400, 'Malformed HTTP request'));
    server.on('error', () => { this.#lastError = 'CAPTURE_LISTENER'; });
    this.#server = server;
    try {
      await new Promise((resolve, reject) => {
        const failed = () => { server.removeListener('listening', ready); reject(error('CAPTURE_LISTENER', '本地抓包端口监听失败')); };
        const ready = () => { server.removeListener('error', failed); resolve(); };
        server.once('error', failed); server.once('listening', ready);
        server.listen({ host: '127.0.0.1', port, exclusive: true });
      });
      this.#port = server.address().port; this.#running = true;
      return this.status();
    } catch (cause) { this.#server = null; server.close(); throw cause; }
  }

  #hostAllowed(host) { return !this.#options.allowHosts || this.#options.allowHosts.has(host.toLowerCase()); }

  #trackSocket(socket) {
    this.#sockets.add(socket);
    socket.on('error', () => {});
    socket.once('close', () => this.#sockets.delete(socket));
    return socket;
  }

  #denySocket(socket, status, message) {
    this.#rejected++;
    if (!socket.destroyed) socket.end(`HTTP/1.1 ${status} ${message}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
  }

  #denyHttp(res, status, message) {
    this.#rejected++;
    res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8', connection: 'close' });
    res.end(message);
  }

  #admit() {
    return this.#running && this.#active.size < this.#options.maxConnections * 2 && this.#pending.size < this.#options.maxConnections;
  }

  #record(exchange) {
    this.#count++;
    let pending;
    pending = Promise.resolve().then(() => this.#options.onExchange(exchange)).catch(() => {
      this.#sinkErrors++; this.#lastError = 'CAPTURE_SINK';
    }).finally(() => this.#pending.delete(pending));
    this.#pending.add(pending);
  }

  #target(req, boundOrigin) {
    if (typeof req.url !== 'string' || req.url.length > 16384 || /[\\\s]/u.test(req.url)) throw error('CAPTURE_URL', '请求地址无效');
    let url;
    try {
      if (boundOrigin && req.url.startsWith('/') && !req.url.startsWith('//')) url = new URL(req.url, boundOrigin);
      else url = new URL(req.url);
    } catch { throw error('CAPTURE_URL', '代理请求需要完整 HTTP 地址'); }
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash) throw error('CAPTURE_URL', '请求地址无效');
    if (!boundOrigin && url.protocol !== 'http:') throw error('CAPTURE_URL', 'HTTPS 必须使用 CONNECT');
    if (boundOrigin && url.origin !== boundOrigin) throw error('CAPTURE_SCOPE', 'TLS 隧道请求越过绑定 origin');
    if (!this.#scope.has(url.origin) || !this.#hostAllowed(url.hostname)) throw error('CAPTURE_SCOPE', '请求不在本次抓包范围内');
    let hostOrigin;
    try { hostOrigin = new URL(`${url.protocol}//${req.headers.host}`).origin; } catch { throw error('CAPTURE_SCOPE', 'Host 无效'); }
    if (hostOrigin !== url.origin) throw error('CAPTURE_SCOPE', 'Host 与请求 origin 不一致');
    return url;
  }

  #handleHttp(req, res, boundOrigin = null) {
    if (!this.#admit()) { this.#denyHttp(res, 503, '抓包代理暂不可用或已达到并发上限'); return; }
    let url;
    try { url = this.#target(req, boundOrigin); }
    catch (cause) { this.#denyHttp(res, cause.code === 'CAPTURE_SCOPE' ? 403 : 400, cause.message); return; }
    const requestBody = snapshot(this.#options.maxBodyBytes), responseBody = snapshot(this.#options.maxBodyBytes);
    const exchange = {
      id: randomUUID(), captureId: this.#generation, protocol: boundOrigin ? 'https' : 'http',
      method: req.method, url: url.href, startedAt: new Date().toISOString(),
      encrypted: false, tlsDecrypted: Boolean(boundOrigin), tunnel: false,
      request: { headers: { ...req.headers }, rawHeaders: [...req.rawHeaders] },
      response: { statusCode: null, headers: {}, rawHeaders: [] },
      provenance: { provider: 'ig5-native-proxy', bodyEncoding: 'bytes', proxyOrigin: url.origin },
    };
    let finished = false, upstream, upstreamResponse, requestComplete = false, responseComplete = false;
    const timer = setTimeout(() => abort('CAPTURE_TIMEOUT', '请求超过抓包时限', 504), this.#options.timeoutMs);
    const finish = (code, message) => {
      if (finished) return;
      finished = true; clearTimeout(timer); this.#active.delete(abort);
      exchange.endedAt = new Date().toISOString();
      exchange.request = { ...exchange.request, ...requestBody.finish(), trailers: { ...req.trailers }, rawTrailers: [...req.rawTrailers], complete: requestComplete };
      exchange.response = { ...exchange.response, ...responseBody.finish(), trailers: { ...upstreamResponse?.trailers }, rawTrailers: [...(upstreamResponse?.rawTrailers || [])], complete: responseComplete };
      exchange.complete = requestComplete && responseComplete && !code;
      if (code) exchange.error = { code, message };
      this.#record(exchange);
    };
    const abort = (code = 'CAPTURE_STOPPED', message = '抓包会话已停止', status = 502) => {
      finish(code, message);
      upstream?.destroy(); upstreamResponse?.destroy();
      if (!res.headersSent && !res.destroyed) { res.writeHead(status, { connection: 'close' }); res.end(message); }
      else if (!res.writableEnded) res.destroy();
    };
    this.#active.add(abort);
    req.on('data', chunk => { if (!finished) requestBody.add(chunk); });
    req.once('end', () => {
      requestComplete = true;
      // This listener runs before pipe's end handler, so trailers precede upstream.end().
      if (upstream && !upstream.destroyed && !upstream.writableEnded && Object.keys(req.trailers).length) {
        try { upstream.addTrailers(req.trailers); }
        catch { abort('CAPTURE_REQUEST_TRAILERS', '客户端请求 trailer 无效'); }
      }
    });
    req.once('aborted', () => abort('CAPTURE_CLIENT_ABORT', '客户端请求中断'));
    req.once('error', () => abort('CAPTURE_CLIENT_ERROR', '客户端请求失败'));
    res.once('close', () => { if (!res.writableFinished) abort('CAPTURE_CLIENT_ABORT', '客户端连接关闭'); });
    try {
      const headers = headersForForward(req.headers);
      headers.host = url.host;
      // Node decodes inbound chunk framing. Explicitly reframe it, including GET
      // bodies, and retain announced trailers rather than silently discarding them.
      if (req.headers['transfer-encoding'] || req.headers.trailer) {
        delete headers['content-length']; headers['transfer-encoding'] = 'chunked';
        if (req.headers.trailer) headers.trailer = req.headers.trailer;
      }
      // Never weaken upstream TLS validation, even when a local client trusts the capture CA.
      upstream = (url.protocol === 'https:' ? https : http).request(url, {
        method: req.method, headers, agent: false, rejectUnauthorized: true,
        ...(this.#options.upstreamCa ? { ca: this.#options.upstreamCa } : {}),
      }, response => {
        if (finished) { response.destroy(); return; }
        upstreamResponse = response;
        exchange.response.statusCode = response.statusCode;
        exchange.response.headers = { ...response.headers }; exchange.response.rawHeaders = [...response.rawHeaders];
        const responseHeaders = headersForForward(response.headers);
        if (response.headers.trailer) {
          delete responseHeaders['content-length']; responseHeaders['transfer-encoding'] = 'chunked';
          responseHeaders.trailer = response.headers.trailer;
        }
        try { res.writeHead(response.statusCode, responseHeaders); }
        catch { abort('CAPTURE_RESPONSE_HEADERS', '上游响应头无效'); return; }
        response.on('data', chunk => { if (!finished) responseBody.add(chunk); });
        response.once('end', () => {
          try {
            if (Object.keys(response.trailers).length) res.addTrailers(response.trailers);
            responseComplete = true; finish();
          } catch { abort('CAPTURE_RESPONSE_TRAILERS', '上游响应 trailer 无效'); }
        });
        response.once('aborted', () => abort('CAPTURE_UPSTREAM_ABORT', '上游响应中断'));
        response.once('error', () => abort('CAPTURE_UPSTREAM_ERROR', '上游响应失败'));
        response.pipe(res);
      });
      upstream.on('socket', socket => this.#trackSocket(socket));
      upstream.once('error', () => abort('CAPTURE_UPSTREAM_ERROR', '上游连接失败或 TLS 验证失败'));
      req.pipe(upstream);
    } catch { abort('CAPTURE_UPSTREAM_ERROR', '上游请求创建失败'); }
  }

  #handleUpgrade(req, socket, head, boundOrigin = null) {
    if (!this.#admit()) { this.#denySocket(socket, 503, 'Capture unavailable'); return; }
    if (String(req.headers.upgrade).toLowerCase() !== 'websocket') { this.#denySocket(socket, 501, 'Unsupported upgrade'); return; }
    let url;
    try {
      // Proxy clients may use ws:// in the absolute request target. Scopes remain HTTP origins.
      if (req.url.startsWith('ws:')) req.url = 'http:' + req.url.slice(3);
      else if (req.url.startsWith('wss:')) req.url = 'https:' + req.url.slice(4);
      url = this.#target(req, boundOrigin);
    } catch { this.#denySocket(socket, 403, 'Outside capture scope'); return; }
    socket.pause();
    const exchange = {
      id: randomUUID(), captureId: this.#generation, protocol: boundOrigin ? 'https' : 'http',
      method: req.method, url: url.href, startedAt: new Date().toISOString(),
      encrypted: false, tlsDecrypted: Boolean(boundOrigin), tunnel: false, websocketHandshake: true,
      request: { headers: { ...req.headers }, rawHeaders: [...req.rawHeaders] },
      response: { statusCode: null, headers: {}, rawHeaders: [] },
      provenance: { provider: 'ig5-native-proxy', bodyEncoding: 'bytes', proxyOrigin: url.origin },
    };
    let upstream, remote, finished = false, upgraded = false, frameCount = 0, dropped = 0, malformed = false;
    const empty = () => ({ body: Buffer.alloc(0), bodyBytes: 0, capturedBytes: 0, truncated: false, complete: true });
    const responseBody = snapshot(this.#options.maxBodyBytes);
    const finish = (code, message) => {
      if (finished) return;
      finished = true; clearTimeout(timer); this.#active.delete(abort);
      exchange.endedAt = new Date().toISOString(); exchange.complete = !code;
      exchange.request = { ...exchange.request, ...empty() };
      exchange.response = { ...exchange.response, ...responseBody.finish(), complete: !code };
      exchange.websocket = { upgraded, frameCount, droppedFrames: dropped, partial: malformed || clientFrames.partial || serverFrames.partial || Boolean(code) };
      if (code) exchange.error = { code, message };
      this.#record(exchange);
    };
    const abort = (code = 'CAPTURE_STOPPED', message = '抓包会话已停止') => {
      finish(code, message); upstream?.destroy(); remote?.destroy(); socket.destroy();
    };
    const onFrame = direction => frame => {
      frameCount++;
      if (frameCount > 1000 || this.#pending.size >= this.#options.maxConnections) { dropped++; this.#droppedFrames++; return; }
      const { body, bodyBytes, capturedBytes, truncated, ...metadata } = frame;
      const payload = { ...empty(), body, bodyBytes, capturedBytes, truncated };
      this.#record({
        id: randomUUID(), captureId: this.#generation, parentExchangeId: exchange.id,
        protocol: 'websocket', method: 'WEBSOCKET', url: url.href, startedAt: new Date().toISOString(), endedAt: new Date().toISOString(),
        encrypted: false, tlsDecrypted: Boolean(boundOrigin), tunnel: false, complete: true,
        request: { headers: {}, rawHeaders: [], ...(direction === 'client_to_server' ? payload : empty()) },
        response: { statusCode: 101, headers: {}, rawHeaders: [], ...(direction === 'server_to_client' ? payload : empty()) },
        websocket: { direction, ...metadata, payloadEncoding: metadata.compressed ? 'compressed-undecoded' : 'bytes', extensions: exchange.response.headers['sec-websocket-extensions'] || null, reassembled: false },
        provenance: { provider: 'ig5-native-proxy', bodyEncoding: 'websocket-frame-payload', proxyOrigin: url.origin },
      });
    };
    const clientFrames = new WebSocketFrames({ limit: this.#options.maxBodyBytes, client: true, onFrame: onFrame('client_to_server'), onInvalid: () => { malformed = true; } });
    const serverFrames = new WebSocketFrames({ limit: this.#options.maxBodyBytes, client: false, onFrame: onFrame('server_to_client'), onInvalid: () => { malformed = true; } });
    const timer = setTimeout(() => abort('CAPTURE_TIMEOUT', 'WebSocket 超过抓包时限'), this.#options.timeoutMs);
    this.#active.add(abort);
    socket.once('error', () => abort('CAPTURE_CLIENT_ERROR', 'WebSocket 客户端连接失败'));
    socket.once('close', () => { finish(); upstream?.destroy(); remote?.destroy(); });
    try {
      upstream = (url.protocol === 'https:' ? https : http).request(url, {
        method: req.method, agent: false, rejectUnauthorized: true,
        headers: { ...headersForForward(req.headers), host: url.host, connection: 'Upgrade', upgrade: 'websocket' },
        ...(this.#options.upstreamCa ? { ca: this.#options.upstreamCa } : {}),
      });
      upstream.on('socket', upstreamSocket => this.#trackSocket(upstreamSocket));
      upstream.once('error', () => abort('CAPTURE_UPSTREAM_ERROR', 'WebSocket 上游连接或 TLS 验证失败'));
      upstream.once('upgrade', (response, upstreamSocket, upstreamHead) => {
        if (finished) { upstreamSocket.destroy(); return; }
        if (response.statusCode !== 101 || String(response.headers.upgrade).toLowerCase() !== 'websocket') {
          upstreamSocket.destroy(); abort('CAPTURE_UPGRADE_INVALID', '上游未接受 WebSocket 升级'); return;
        }
        upgraded = true; remote = this.#trackSocket(upstreamSocket);
        exchange.response.statusCode = response.statusCode;
        exchange.response.headers = { ...response.headers }; exchange.response.rawHeaders = [...response.rawHeaders];
        const headerLines = [];
        for (let i = 0; i < response.rawHeaders.length; i += 2) headerLines.push(`${response.rawHeaders[i]}: ${response.rawHeaders[i + 1]}`);
        socket.write(`HTTP/1.1 ${response.statusCode} ${response.statusMessage}\r\n${headerLines.join('\r\n')}\r\n\r\n`);
        if (head.length) { clientFrames.push(head); remote.write(head); }
        if (upstreamHead.length) { serverFrames.push(upstreamHead); socket.write(upstreamHead); }
        socket.on('data', bytes => { if (!finished) clientFrames.push(bytes); });
        remote.on('data', bytes => { if (!finished) serverFrames.push(bytes); });
        remote.once('error', () => abort('CAPTURE_UPSTREAM_ERROR', 'WebSocket 上游连接失败'));
        remote.once('end', () => finish());
        remote.once('close', () => { finish(); socket.destroy(); });
        socket.pipe(remote); remote.pipe(socket); socket.resume();
      });
      upstream.once('response', response => {
        exchange.response.statusCode = response.statusCode;
        exchange.response.headers = { ...response.headers }; exchange.response.rawHeaders = [...response.rawHeaders];
        // Preserve the non-upgrade response with connection-close framing and decoded body bytes.
        const filtered = headersForForward(response.headers); delete filtered['content-length'];
        const lines = Object.entries(filtered).flatMap(([key, value]) => (Array.isArray(value) ? value : [value]).map(item => `${key}: ${item}`));
        socket.write(`HTTP/1.1 ${response.statusCode} ${response.statusMessage}\r\n${lines.join('\r\n')}\r\nConnection: close\r\n\r\n`);
        response.on('data', bytes => responseBody.add(bytes));
        response.once('end', () => finish());
        response.once('error', () => abort('CAPTURE_UPSTREAM_ERROR', 'WebSocket 握手响应失败'));
        response.pipe(socket); socket.resume();
      });
      upstream.end();
    } catch { abort('CAPTURE_UPSTREAM_ERROR', 'WebSocket 上游请求创建失败'); }
  }

  async #handleConnect(req, socket, head) {
    if (!this.#admit()) { this.#denySocket(socket, 503, 'Capture unavailable'); return; }
    let url;
    try {
      if (!/^([a-zA-Z0-9.-]+|\[[a-fA-F0-9:]+\]):[0-9]{1,5}$/u.test(req.url)) throw new Error();
      url = new URL(`https://${req.url}`);
      if (!this.#scope.has(url.origin) || !this.#hostAllowed(url.hostname)) throw new Error();
    } catch { this.#denySocket(socket, 403, 'Outside capture scope'); return; }
    const exchange = {
      id: randomUUID(), captureId: this.#generation, protocol: 'connect', method: 'CONNECT', url: url.origin,
      startedAt: new Date().toISOString(), encrypted: true, tunnel: !this.#tls, tlsIntercepted: this.#tls,
      request: { headers: { ...req.headers }, rawHeaders: [...req.rawHeaders] },
      response: { statusCode: null, headers: {}, rawHeaders: [] },
      provenance: { provider: 'ig5-native-proxy', bodyEncoding: 'opaque-tls', proxyOrigin: url.origin },
    };
    let upstream, finished = false, connected = false, sentBytes = 0, receivedBytes = 0;
    const timer = setTimeout(() => abort('CAPTURE_TIMEOUT', 'CONNECT 超过抓包时限'), this.#options.timeoutMs);
    const finish = (code, message) => {
      if (finished) return;
      finished = true; clearTimeout(timer); this.#active.delete(abort);
      exchange.endedAt = new Date().toISOString(); exchange.complete = connected && !code;
      exchange.request = { ...exchange.request, body: Buffer.alloc(0), bodyBytes: sentBytes, capturedBytes: 0, truncated: sentBytes > 0, complete: exchange.complete };
      exchange.response = { ...exchange.response, body: Buffer.alloc(0), bodyBytes: receivedBytes, capturedBytes: 0, truncated: receivedBytes > 0, complete: exchange.complete };
      if (code) exchange.error = { code, message };
      this.#record(exchange);
    };
    const abort = (code = 'CAPTURE_STOPPED', message = '抓包会话已停止') => {
      finish(code, message); upstream?.destroy(); socket.destroy();
    };
    this.#active.add(abort);
    socket.once('error', () => abort('CAPTURE_CLIENT_ERROR', 'CONNECT 客户端连接失败'));
    socket.once('close', () => { finish(); upstream?.destroy(); });
    if (this.#tls) {
      try {
        const certificate = await this.#options.certificateAuthority.issue(url.hostname.replace(/^\[|\]$/gu, ''));
        if (!this.#running || finished || socket.destroyed) { abort(); return; }
        const tlsServer = tls.createServer({ key: certificate.key, cert: certificate.cert, ALPNProtocols: ['http/1.1'], handshakeTimeout: Math.min(this.#options.timeoutMs, 15000) }, secure => {
          this.#trackSocket(secure);
          if (!this.#innerServer) {
            this.#innerServer = http.createServer({ maxHeaderSize: 32768 });
            this.#innerServer.requestTimeout = this.#options.timeoutMs;
            this.#innerServer.headersTimeout = Math.min(this.#options.timeoutMs, 15000);
            this.#innerServer.keepAliveTimeout = 5000;
            this.#innerServer.on('request', (innerReq, innerRes) => this.#handleHttp(innerReq, innerRes, innerReq.socket.ig5CaptureOrigin));
            this.#innerServer.on('upgrade', (innerReq, innerSocket, innerHead) => this.#handleUpgrade(innerReq, innerSocket, innerHead, innerReq.socket.ig5CaptureOrigin));
            this.#innerServer.on('connect', (_innerReq, innerSocket) => this.#denySocket(innerSocket, 403, 'Nested CONNECT is not permitted'));
            this.#innerServer.on('clientError', (_cause, innerSocket) => this.#denySocket(innerSocket, 400, 'Malformed HTTP request'));
          }
          secure.ig5CaptureOrigin = url.origin;
          this.#innerServer.emit('connection', secure);
        });
        tlsServer.on('tlsClientError', () => abort('CAPTURE_TLS_CLIENT', '客户端未信任抓包 CA 或 TLS 握手失败'));
        tlsServer.on('error', () => abort('CAPTURE_TLS_SERVER', '抓包 TLS 服务失败'));
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        connected = true; exchange.response.statusCode = 200;
        if (head.length) socket.unshift(head);
        tlsServer.emit('connection', socket);
      } catch { abort('CAPTURE_TLS_CA', '无法签发本地抓包证书'); }
      return;
    }
    upstream = this.#trackSocket(net.connect({ host: url.hostname.replace(/^\[|\]$/gu, ''), port: Number(url.port || 443) }));
    upstream.once('connect', () => {
      if (finished) { upstream.destroy(); return; }
      connected = true; exchange.response.statusCode = 200;
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      sentBytes += head.length;
      if (head.length) upstream.write(head);
      socket.on('data', chunk => { sentBytes += chunk.length; });
      upstream.on('data', chunk => { receivedBytes += chunk.length; });
      socket.pipe(upstream); upstream.pipe(socket);
    });
    upstream.once('error', () => abort('CAPTURE_UPSTREAM_ERROR', 'CONNECT 上游连接失败'));
    upstream.once('end', () => finish());
    upstream.once('close', () => { finish(); socket.destroy(); });
  }

  async stop() {
    if (this.#stopping) return this.#stopping;
    this.#running = false;
    this.#stopping = (async () => {
      for (const abort of [...this.#active]) abort();
      for (const socket of [...this.#sockets]) socket.destroy();
      if (this.#server) await new Promise(resolve => this.#server.close(() => resolve()));
      this.#server = null; this.#innerServer = null;
      // The sink is application-owned; its failure cannot keep a listener alive indefinitely.
      let timer;
      await Promise.race([
        Promise.allSettled([...this.#pending]),
        new Promise(resolve => { timer = setTimeout(resolve, Math.min(this.#options.timeoutMs, 10000)); }),
      ]);
      clearTimeout(timer);
      return this.status();
    })();
    try { return await this.#stopping; } finally { this.#stopping = null; }
  }
}
