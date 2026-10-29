import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { CaptureProxy, normalizeCaptureScope } from '../source/capture_proxy.js';
import { createCaptureCA } from '../source/capture_ca.js';

const listen = server => new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
const close = server => new Promise(resolve => { server.closeAllConnections?.(); server.close(() => resolve()); });
const until = async predicate => {
  const end = Date.now() + 2500;
  while (!predicate()) { if (Date.now() > end) throw new Error('capture wait expired'); await new Promise(resolve => setTimeout(resolve, 5)); }
};
function forward(proxy, url, { method = 'GET', body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: proxy.host, port: proxy.port, path: url, method, headers: { host: new URL(url).host, ...headers } }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.once('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      res.once('error', reject);
    });
    req.once('error', reject); req.end(body);
  });
}
function tlsRequest(proxy, origin, ca, rawRequest) {
  return new Promise((resolve, reject) => {
    const target = new URL(origin);
    const connect = http.request({ hostname: proxy.host, port: proxy.port, method: 'CONNECT', path: target.host, headers: { host: target.host } });
    connect.once('error', reject);
    connect.once('connect', (response, socket, head) => {
      if (response.statusCode !== 200) { socket.destroy(); reject(new Error(`CONNECT ${response.statusCode}`)); return; }
      if (head.length) socket.unshift(head);
      const secure = tls.connect({ socket, ca, checkServerIdentity: (_host, cert) => tls.checkServerIdentity(target.hostname, cert) }, () => secure.write(rawRequest));
      const chunks = [];
      secure.on('data', chunk => chunks.push(chunk));
      secure.once('end', () => resolve(Buffer.concat(chunks).toString('latin1')));
      secure.once('error', reject);
    });
    connect.end();
  });
}
function authorities(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-capture-proxy-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return { capture: createCaptureCA(path.join(directory, 'capture')), upstream: createCaptureCA(path.join(directory, 'upstream')) };
}

test('scope validation rejects broad/non-origin inputs and has explicit body bounds', () => {
  for (const invalid of [[], ['https://a/path'], ['http://user:pass@a'], ['file:///tmp'], ['http://a/?x=1'], ['http://a/#'], ['http://a\\b'], ['http://a\n']]) {
    assert.throws(() => normalizeCaptureScope(invalid));
  }
  assert.deepEqual(normalizeCaptureScope(['HTTP://EXAMPLE.COM:80', 'http://example.com/']), ['http://example.com']);
  assert.throws(() => new CaptureProxy({ onExchange() {}, maxBodyBytes: 1048577 }));
});

test('real HTTP proxy streams binary both ways while snapshots are independently bounded', async t => {
  const captured = [], sent = Buffer.from(Array.from({ length: 16384 }, (_, i) => i % 256));
  let received;
  const origin = http.createServer((req, res) => {
    const parts = []; req.on('data', bytes => parts.push(bytes));
    req.on('end', () => { received = Buffer.concat(parts); res.writeHead(201, { 'content-type': 'application/octet-stream', 'set-cookie': ['a=1', 'b=2'] }); res.end(sent); });
  });
  const port = await listen(origin);
  const proxy = new CaptureProxy({ onExchange: item => captured.push(item), maxBodyBytes: 1024 });
  t.after(async () => { await proxy.stop(); await close(origin); });
  const address = await proxy.start({ scope: [`http://127.0.0.1:${port}`] });
  const response = await forward(address, `http://127.0.0.1:${port}/binary?q=1`, { method: 'POST', body: sent, headers: { 'proxy-authorization': 'not-forwarded', 'x-fixture': 'ok' } });
  assert.equal(response.status, 201); assert.deepEqual(response.body, sent); assert.deepEqual(received, sent);
  await until(() => captured.length === 1);
  assert.equal(captured[0].complete, true); assert.equal(captured[0].request.bodyBytes, sent.length);
  assert.equal(captured[0].response.bodyBytes, sent.length);
  assert.deepEqual(captured[0].request.body, sent.subarray(0, 1024));
  assert.deepEqual(captured[0].response.body, sent.subarray(0, 1024));
  assert.equal(captured[0].request.truncated, true); assert.equal(captured[0].response.truncated, true);
  assert.deepEqual(captured[0].response.headers['set-cookie'], ['a=1', 'b=2']);
  assert.equal(proxy.status().host, '127.0.0.1');
});

test('out-of-scope traffic and Host mismatch never reach origin; no redirects followed', async t => {
  let hits = 0;
  const captured = [];
  const origin = http.createServer((_req, res) => { hits++; res.writeHead(302, { location: 'http://outside.example/' }); res.end(); });
  const port = await listen(origin), proxy = new CaptureProxy({ onExchange: item => captured.push(item) });
  t.after(async () => { await proxy.stop(); await close(origin); });
  const address = await proxy.start({ scope: [`http://127.0.0.1:${port}`] });
  assert.equal((await forward(address, 'http://outside.example/')).status, 403);
  assert.equal((await forward(address, `http://127.0.0.1:${port}/`, { headers: { host: 'outside.example' } })).status, 403);
  assert.equal(hits, 0);
  assert.equal((await forward(address, `http://127.0.0.1:${port}/`)).status, 302);
  assert.equal(hits, 1);
});

test('HTTP timeout records incomplete evidence and releases its own upstream', async t => {
  const captured = [], origin = http.createServer(() => {});
  const port = await listen(origin), proxy = new CaptureProxy({ onExchange: item => captured.push(item), timeoutMs: 150 });
  t.after(async () => { await proxy.stop(); await close(origin); });
  const address = await proxy.start({ scope: [`http://127.0.0.1:${port}`] });
  const response = await forward(address, `http://127.0.0.1:${port}/`).catch(error => ({ error }));
  await until(() => captured.length === 1);
  assert.equal(captured[0].complete, false);
  assert.ok(['CAPTURE_TIMEOUT', 'CAPTURE_CLIENT_ABORT'].includes(captured[0].error.code));
  assert.ok(response.status === 504 || response.error);
  assert.equal(proxy.status().activeExchanges, 0);
});

test('CONNECT tunnels real TLS and records only opaque byte counts without plaintext claims', async t => {
  const ca = authorities(t), captured = [];
  const origin = https.createServer(ca.upstream.issue('127.0.0.1'), (_req, res) => res.end('opaque payload'));
  const port = await listen(origin), proxy = new CaptureProxy({ onExchange: item => captured.push(item) });
  t.after(async () => { await proxy.stop(); await close(origin); });
  const target = `https://127.0.0.1:${port}`;
  const address = await proxy.start({ scope: [target] });
  const response = await tlsRequest(address, target, ca.upstream.certificate, `GET / HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`);
  assert.match(response, /opaque payload/);
  await until(() => captured.length === 1);
  assert.equal(captured[0].encrypted, true); assert.equal(captured[0].tunnel, true);
  assert.equal(captured[0].request.capturedBytes, 0); assert.equal(captured[0].response.capturedBytes, 0);
  assert.ok(captured[0].request.bodyBytes > 0); assert.ok(captured[0].response.bodyBytes > 0);
});

test('opt-in MITM captures HTTPS plaintext with trusted upstream and enforces bound Host', async t => {
  const ca = authorities(t), captured = []; let hits = 0;
  const origin = https.createServer(ca.upstream.issue('127.0.0.1'), (_req, res) => { hits++; res.end('decrypted fixture'); });
  const port = await listen(origin);
  const proxy = new CaptureProxy({ onExchange: item => captured.push(item), certificateAuthority: ca.capture, upstreamCa: ca.upstream.certificate });
  t.after(async () => { await proxy.stop(); await close(origin); });
  const target = `https://127.0.0.1:${port}`;
  const address = await proxy.start({ scope: [target, 'https://outside.example'], tls: true });
  const response = await tlsRequest(address, target, ca.capture.certificate, `GET /sensitive HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`);
  assert.match(response, /decrypted fixture/);
  await until(() => captured.some(item => item.protocol === 'https'));
  const item = captured.find(item => item.protocol === 'https');
  assert.equal(item.tlsDecrypted, true); assert.equal(item.complete, true); assert.equal(item.response.body.toString(), 'decrypted fixture');
  assert.equal(hits, 1);
  const forbidden = await tlsRequest(address, target, ca.capture.certificate, 'GET https://outside.example/ HTTP/1.1\r\nHost: outside.example\r\nConnection: close\r\n\r\n');
  assert.match(forbidden, /^HTTP\/1.1 403/); assert.equal(hits, 1);
});

test('MITM refuses untrusted upstream TLS rather than downgrading validation', async t => {
  const ca = authorities(t), captured = []; let hits = 0;
  const origin = https.createServer(ca.upstream.issue('127.0.0.1'), (_req, res) => { hits++; res.end('should not reach'); });
  const port = await listen(origin);
  const proxy = new CaptureProxy({ onExchange: item => captured.push(item), certificateAuthority: ca.capture });
  t.after(async () => { await proxy.stop(); await close(origin); });
  const target = `https://127.0.0.1:${port}`, address = await proxy.start({ scope: [target], tls: true });
  const response = await tlsRequest(address, target, ca.capture.certificate, `GET / HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`);
  assert.match(response, /^HTTP\/1.1 502/); assert.equal(hits, 0);
  await until(() => captured.some(item => item.protocol === 'https'));
  assert.equal(captured.find(item => item.protocol === 'https').error.code, 'CAPTURE_UPSTREAM_ERROR');
});

test('stop aborts in-flight capture, drains callback, and leaves unrelated server available', async t => {
  const captured = [], origin = http.createServer((req, res) => { if (req.url === '/ok') res.end('still alive'); });
  const port = await listen(origin), proxy = new CaptureProxy({ onExchange: async item => { await new Promise(resolve => setTimeout(resolve, 15)); captured.push(item); } });
  t.after(async () => { await proxy.stop(); await close(origin); });
  const address = await proxy.start({ scope: [`http://127.0.0.1:${port}`] });
  const inflight = forward(address, `http://127.0.0.1:${port}/hang`).catch(() => null);
  await until(() => proxy.status().activeExchanges === 1);
  const status = await proxy.stop(); await inflight;
  assert.equal(status.running, false); assert.equal(status.pendingExchanges, 0);
  assert.equal(captured.length, 1); assert.equal(captured[0].error.code, 'CAPTURE_STOPPED');
  const alive = await new Promise((resolve, reject) => http.get(`http://127.0.0.1:${port}/ok`, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); }).on('error', reject));
  assert.equal(alive, 200);
  await proxy.stop();
});

test('upgrade rejects explicitly and repeated stop is safe', async t => {
  const proxy = new CaptureProxy({ onExchange() {} });
  t.after(() => proxy.stop());
  const address = await proxy.start({ scope: ['http://127.0.0.1:12345'] });
  const response = await new Promise((resolve, reject) => {
    const socket = net.connect(address.port, address.host, () => socket.write('GET http://127.0.0.1:12345/ HTTP/1.1\r\nHost: 127.0.0.1:12345\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n'));
    const chunks = []; socket.on('data', bytes => chunks.push(bytes)); socket.on('end', () => { socket.destroy(); resolve(Buffer.concat(chunks).toString()); }); socket.on('error', reject);
  });
  assert.match(response, /^HTTP\/1.1 501/);
  await Promise.all([proxy.stop(), proxy.stop()]);
});

function frame(payload, { masked = false, opcode = 2, fin = true, compressed = false } = {}) {
  const long = payload.length >= 126, header = Buffer.alloc(2 + (long ? 2 : 0) + (masked ? 4 : 0));
  header[0] = opcode | (fin ? 128 : 0) | (compressed ? 64 : 0);
  header[1] = (long ? 126 : payload.length) | (masked ? 128 : 0);
  if (long) header.writeUInt16BE(payload.length, 2);
  const data = Buffer.from(payload);
  if (masked) { const mask = Buffer.from([0x42, 0x19, 0x55, 0x01]); mask.copy(header, header.length - 4); for (let i = 0; i < data.length; i++) data[i] ^= mask[i % 4]; }
  return Buffer.concat([header, data]);
}

function wsOrigin(server, expectedBytes, reply) {
  server.on('upgrade', (req, socket, head) => {
    const digest = createHash('sha1').update(req.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: ${digest}\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n`);
    let bytes = head.length;
    socket.on('error', () => {});
    socket.on('data', chunk => { bytes += chunk.length; if (bytes >= expectedBytes) socket.end(reply); });
  });
}

function wsTransfer(address, origin, payload, ca) {
  const target = new URL(origin);
  return new Promise((resolve, reject) => {
    const use = socket => {
      let headers = Buffer.alloc(0), established = false; const body = [];
      socket.on('error', reject);
      socket.on('data', chunk => {
        if (established) { body.push(chunk); return; }
        headers = Buffer.concat([headers, chunk]); const end = headers.indexOf('\r\n\r\n');
        if (end < 0) return;
        if (!headers.subarray(0, end).toString().startsWith('HTTP/1.1 101')) { reject(new Error(headers.toString())); socket.destroy(); return; }
        established = true; body.push(headers.subarray(end + 4));
        // Split mask, extended length and payload boundaries independently.
        socket.write(payload.subarray(0, 1));
        setImmediate(() => { socket.write(payload.subarray(1, 3)); setImmediate(() => socket.write(payload.subarray(3))); });
      });
      socket.once('end', () => { socket.destroy(); resolve(Buffer.concat(body)); });
      const requestTarget = ca ? '/ws' : `${origin}/ws`;
      socket.write(`GET ${requestTarget} HTTP/1.1\r\nHost: ${target.host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: MDEyMzQ1Njc4OWFiY2RlZg==\r\n\r\n`);
    };
    if (!ca) { const socket = net.connect(address.port, address.host, () => use(socket)); socket.on('error', reject); return; }
    const connect = http.request({ hostname: address.host, port: address.port, method: 'CONNECT', path: target.host, headers: { host: target.host } });
    connect.on('error', reject);
    connect.on('connect', (response, socket, head) => {
      if (response.statusCode !== 200) { socket.destroy(); reject(new Error(`CONNECT ${response.statusCode}`)); return; }
      if (head.length) socket.unshift(head);
      const secure = tls.connect({ socket, ca, checkServerIdentity: (_host, cert) => tls.checkServerIdentity(target.hostname, cert) }, () => use(secure));
      secure.on('error', reject);
    });
    connect.end();
  });
}

for (const tlsEnabled of [false, true]) {
  test(`${tlsEnabled ? 'WSS' : 'WS'} forwards exact frames and captures binary/unmask/compression/fragment metadata`, async t => {
    const ca = authorities(t), captured = [], first = Buffer.from([0, 255, 33, 128, 0, 15]);
    const last = Buffer.from(Array.from({ length: 600 }, (_, index) => index % 256));
    const payload = Buffer.concat([frame(first, { masked: true, fin: false, compressed: true }), frame(last, { masked: true, opcode: 0 })]);
    const reply = Buffer.concat([frame(Buffer.from([0, 250, 0, 19])), frame(Buffer.alloc(0), { opcode: 8 })]);
    const origin = tlsEnabled ? https.createServer(ca.upstream.issue('127.0.0.1')) : http.createServer();
    wsOrigin(origin, payload.length, reply);
    const port = await listen(origin), target = `${tlsEnabled ? 'https' : 'http'}://127.0.0.1:${port}`;
    const proxy = new CaptureProxy({ onExchange: item => captured.push(item), maxBodyBytes: 4, certificateAuthority: ca.capture, upstreamCa: ca.upstream.certificate });
    t.after(async () => { await proxy.stop(); await close(origin); });
    const address = await proxy.start({ scope: [target], tls: tlsEnabled });
    assert.deepEqual(await wsTransfer(address, target, payload, tlsEnabled ? ca.capture.certificate : null), reply);
    await until(() => captured.filter(item => item.protocol === 'websocket').length === 4);
    const frames = captured.filter(item => item.protocol === 'websocket');
    assert.deepEqual(frames[0].request.body, first.subarray(0, 4));
    assert.equal(frames[0].websocket.fin, false); assert.equal(frames[0].request.truncated, true);
    assert.equal(frames[1].websocket.opcode, 0); assert.equal(frames[1].websocket.compressed, true);
    assert.equal(frames[1].request.bodyBytes, last.length); assert.deepEqual(frames[1].request.body, last.subarray(0, 4));
    assert.equal(frames[2].websocket.direction, 'server_to_client'); assert.deepEqual(frames[2].response.body, Buffer.from([0, 250, 0, 19]));
    assert.equal(frames[3].websocket.opcode, 8); assert.equal(frames[3].response.bodyBytes, 0);
    assert.equal(frames[0].tlsDecrypted, tlsEnabled); assert.equal(frames[0].websocket.reassembled, false);
  });
}

test('WebSocket frame flood is bounded and loss is reported in handshake metadata', async t => {
  const captured = [], payload = frame(Buffer.from('x'), { masked: true });
  const reply = Buffer.concat(Array.from({ length: 1200 }, () => frame(Buffer.alloc(0), { opcode: 9 })));
  const origin = http.createServer(); wsOrigin(origin, payload.length, reply);
  const port = await listen(origin), target = `http://127.0.0.1:${port}`;
  const proxy = new CaptureProxy({ onExchange: item => captured.push(item), maxConnections: 4 });
  t.after(async () => { await proxy.stop(); await close(origin); });
  const address = await proxy.start({ scope: [target] });
  assert.deepEqual(await wsTransfer(address, target, payload), reply);
  await until(() => captured.some(item => item.websocketHandshake));
  const handshake = captured.find(item => item.websocketHandshake);
  assert.equal(handshake.websocket.frameCount, 1201);
  assert.ok(handshake.websocket.droppedFrames >= 201);
  assert.ok(captured.filter(item => item.protocol === 'websocket').length <= 1000);
  assert.equal(proxy.status().droppedWebSocketFrames, handshake.websocket.droppedFrames);
});

test('malformed WebSocket length disables capture parsing without inventing payloads', async t => {
  const captured = [], payload = Buffer.from([0x82, 0xff, 0x80, 0, 0, 0, 0, 0, 0, 0, 0x42, 0x19, 0x55, 1]);
  const reply = frame(Buffer.alloc(0), { opcode: 8 }), origin = http.createServer();
  wsOrigin(origin, payload.length, reply);
  const port = await listen(origin), target = `http://127.0.0.1:${port}`;
  const proxy = new CaptureProxy({ onExchange: item => captured.push(item) });
  t.after(async () => { await proxy.stop(); await close(origin); });
  const address = await proxy.start({ scope: [target] });
  assert.deepEqual(await wsTransfer(address, target, payload), reply);
  await until(() => captured.some(item => item.websocketHandshake));
  assert.equal(captured.find(item => item.websocketHandshake).websocket.partial, true);
  assert.equal(captured.filter(item => item.protocol === 'websocket' && item.websocket.direction === 'client_to_server').length, 0);
});

test('failed persistence is counted and does not tear down forwarding or leak callbacks', async t => {
  const origin = http.createServer((_req, res) => res.end('ok')), port = await listen(origin);
  const proxy = new CaptureProxy({ onExchange() { throw new Error('fixture persistence failure'); } });
  t.after(async () => { await proxy.stop(); await close(origin); });
  const target = `http://127.0.0.1:${port}`, address = await proxy.start({ scope: [target] });
  assert.equal((await forward(address, target + '/')).body.toString(), 'ok');
  await until(() => proxy.status().sinkErrors === 1);
  assert.equal(proxy.status().pendingExchanges, 0);
  const oldId = proxy.status().captureId;
  await proxy.stop();
  const restarted = await proxy.start({ scope: [target] });
  assert.notEqual(restarted.captureId, oldId);
  assert.equal(restarted.sinkErrors, 0);
  assert.equal((await forward(restarted, target + '/again')).status, 200);
});

test('chunked request and response trailers reach both peers and captured evidence unchanged', async t => {
  const captured = [], requestBody = Buffer.from([0, 17, 255, 4]);
  let receivedRequest;
  const origin = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      receivedRequest = { body: Buffer.concat(chunks), trailers: req.trailers, declared: req.headers.trailer };
      res.writeHead(200, { 'content-type': 'application/octet-stream', 'transfer-encoding': 'chunked', trailer: 'X-Response-Digest' });
      res.write(requestBody); res.addTrailers({ 'X-Response-Digest': 'fixture-response' }); res.end();
    });
  });
  const port = await listen(origin), target = `http://127.0.0.1:${port}`;
  const proxy = new CaptureProxy({ onExchange: item => captured.push(item) });
  t.after(async () => { await proxy.stop(); await close(origin); });
  const address = await proxy.start({ scope: [target] });
  const receivedResponse = await new Promise((resolve, reject) => {
    // GET is deliberate: Node does not select chunked framing automatically for GET.
    const req = http.request({ host: address.host, port: address.port, path: target + '/trailers', method: 'GET',
      headers: { host: `127.0.0.1:${port}`, 'transfer-encoding': 'chunked', trailer: 'X-Request-Digest' } }, res => {
      const chunks = []; res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ body: Buffer.concat(chunks), trailers: res.trailers, declared: res.headers.trailer }));
      res.on('error', reject);
    });
    req.on('error', reject); req.write(requestBody); req.addTrailers({ 'X-Request-Digest': 'fixture-request' }); req.end();
  });
  assert.deepEqual(receivedRequest.body, requestBody);
  assert.equal(receivedRequest.trailers['x-request-digest'], 'fixture-request');
  assert.equal(receivedRequest.declared, 'X-Request-Digest');
  assert.deepEqual(receivedResponse.body, requestBody);
  assert.equal(receivedResponse.trailers['x-response-digest'], 'fixture-response');
  assert.equal(receivedResponse.declared, 'X-Response-Digest');
  await until(() => captured.length === 1);
  assert.equal(captured[0].request.trailers['x-request-digest'], 'fixture-request');
  assert.equal(captured[0].response.trailers['x-response-digest'], 'fixture-response');
  assert.equal(captured[0].complete, true);
});


for (const [name, reply, partial, expectedFrames] of [
  ['unfinished uncompressed message', frame(Buffer.from('A'), {fin:false}), true, 1],
  ['new data during fragment', Buffer.concat([frame(Buffer.from('A'), {fin:false}),frame(Buffer.from('B'))]), true, 1],
  ['continuation without start', frame(Buffer.from('B'), {opcode:0}), true, 0],
  ['ping preserves fragment and next message is allowed', Buffer.concat([frame(Buffer.from('A'), {fin:false}),frame(Buffer.alloc(0), {opcode:9}),frame(Buffer.from('B'), {opcode:0}),frame(Buffer.from('C'))]), false, 4],
]) test('WebSocket message state: '+name, async t => {
  const captured=[], payload=frame(Buffer.alloc(0), {masked:true,opcode:9}),origin=http.createServer();
  wsOrigin(origin,payload.length,reply);const port=await listen(origin),url=`http://127.0.0.1:${port}`;
  const proxy=new CaptureProxy({onExchange:e=>captured.push(e)});
  t.after(async()=>{await proxy.stop();await close(origin);});
  const address=await proxy.start({scope:[url]});await wsTransfer(address,url,payload);
  await until(()=>captured.some(e=>e.websocketHandshake));
  assert.equal(captured.find(e=>e.websocketHandshake).websocket.partial,partial);
  assert.equal(captured.filter(e=>e.protocol==='websocket'&&e.websocket.direction==='server_to_client').length,expectedFrames);
});
