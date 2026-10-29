import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';

// Renderer fixture: checks read/draft boundaries and asynchronous selection ownership.
// This does not replace a browser or a native proxy integration test.
let activeHarness, api;
let request = () => { throw new Error('Unexpected HTTP request'); };
const same = (a, b) => a && b && a.length === b.length && a.every((v, i) => Object.is(v, b[i]));
const react = {
  createElement: (type, props, ...children) => ({ type, props: props || {}, children: children.flat(Infinity).filter(v => v !== null && v !== undefined && v !== false) }),
  useState(initial) {
    const h = activeHarness, i = h.cursor++;
    if (!(i in h.cells)) h.cells[i] = typeof initial === 'function' ? initial() : initial;
    return [h.cells[i], value => { h.cells[i] = typeof value === 'function' ? value(h.cells[i]) : value; }];
  },
  useRef(initial) { const h = activeHarness, i = h.cursor++; return h.cells[i] ||= { current: initial }; },
  useEffect(fn, deps) {
    const h = activeHarness, i = h.cursor++, old = h.effects[i];
    if (!old || !same(old.deps, deps)) h.pending.push(() => { old?.cleanup?.(); h.effects[i] = { deps, cleanup: fn() }; });
  },
};
vm.runInNewContext(fs.readFileSync(new URL('../client.js', import.meta.url), 'utf8'), {
  window: { __ModuleLoader__: { load: value => { api = value.factory(name => { assert.equal(name, 'react'); return react; }); } } },
  console, URL, URLSearchParams, fetch: (...args) => request(...args), setTimeout, clearTimeout,
}, { filename: 'client.js' });
const ui = api.__test;
function harness(component = ui.CaptureView, props = {}) {
  return {
    cells: [], effects: [], pending: [], cursor: 0, tree: null,
    render() { this.cursor = 0; activeHarness = this; this.tree = component(props); activeHarness = null; this.pending.splice(0).forEach(fn => fn()); return this.tree; },
    unmount() { this.effects.forEach(effect => effect?.cleanup?.()); },
  };
}
function nodes(node, predicate) { return node && typeof node === 'object' ? (predicate(node) ? [node] : []).concat((node.children || []).flatMap(child => nodes(child, predicate))) : []; }
function text(node) { return typeof node === 'string' || typeof node === 'number' ? String(node) : (node?.children || []).map(text).join(''); }
function button(h, label) { const found = nodes(h.tree, node => node.type === 'button' && text(node) === label)[0]; assert.ok(found, `Missing button ${label}`); return found; }
function input(h, label) { const found = nodes(h.tree, node => node.props['aria-label'] === label)[0]; assert.ok(found, `Missing input ${label}`); return found; }
const response = data => ({ ok: true, status: 200, json: async () => ({ data }) });
const settle = async () => { for (let i = 0; i < 12; i++) await Promise.resolve(); };
function deferred() { let resolve; const promise = new Promise(yes => { resolve = yes; }); return { promise, resolve }; }
const status = { running: true, host: '127.0.0.1', port: 8123, session_id: 'session-1', scope: ['http://localhost:3000'], stored: 2, dropped: 0 };
const row = (id, extra = {}) => ({ id, session_id: 'session-1', method: 'GET', url: `http://localhost:3000/${id}`, statusCode: 200, complete: true, ...extra });
const list = (items, extra = {}) => ({ items, offset: 0, limit: 20, session_id: 'session-1', total: items.length, hasMore: false, ...extra });
const detail = (id, extra = {}) => ({ ...row(id), request: { headers: { host: 'localhost:3000' }, body: { ref: 'sha256:req', bytes: 2, previewText: '{}' } }, response: { statusCode: 200, headers: {}, body: { ref: 'sha256:res', bytes: 2, previewText: 'ok' } }, ...extra });
async function mounted(handler, props) {
  const calls = [];
  request = (url, options) => { const query = new URL(url, 'http://localhost').searchParams; calls.push({ query, options }); return Promise.resolve(handler(query, options)); };
  const h = harness(ui.CaptureView, props); h.render(); await settle(); h.render(); return { h, calls };
}
async function history(h) { button(h, '读取最新记录').props.onClick(); h.render(); await settle(); h.render(); }
async function select(h, id) { button(h, `GET http://localhost:3000/${id}`).props.onClick(); h.render(); await settle(); h.render(); }
function draftArgs(h) { const draft = input(h, '待发送流量工具草稿').props.value; return JSON.parse(draft.slice(draft.indexOf('{'))); }

test('mount reads only local status, with no static identity or traffic polling', async () => {
  const { h, calls } = await mounted(query => { assert.equal(query.get('type'), 'capture_status'); return response(status); });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].query.get('engine'), null); assert.equal(calls[0].query.get('expected_snapshot'), null);
  assert.equal(calls[0].options, undefined); assert.match(text(h.tree), /127.0.0.1:8123/);
  h.render(); await settle(); assert.equal(calls.length, 1); h.unmount();
});

test('HTTP history is explicitly read in bounded pages and detail is selected independently', async () => {
  const { h, calls } = await mounted(query => {
    if (query.get('type') === 'capture_status') return response(status);
    assert.equal(query.get('session_id'), 'session-1');
    if (query.get('type') === 'capture_detail') return response(detail(query.get('id')));
    assert.equal(query.get('limit'), '20');
    return response(list([row(query.get('offset') === '20' ? 'next' : 'first')], { hasMore: query.get('offset') === '0', total: 21 }));
  });
  await history(h); await select(h, 'first');
  assert.equal(calls[2].query.get('type'), 'capture_detail'); assert.equal(calls[2].query.get('id'), 'first');
  button(h, '下一页流量').props.onClick(); h.render(); await settle(); h.render();
  assert.match(text(h.tree), /偏移 20/); assert.doesNotMatch(text(h.tree), /生成重放审批草稿/);
  assert.equal(calls[3].query.get('offset'), '20'); assert.equal(button(h, '下一页流量').props.disabled, true);
  button(h, '上一页流量').props.onClick(); await settle(); h.render(); assert.equal(calls[4].query.get('offset'), '0');
  assert.ok(calls.every(call => call.options === undefined)); h.unmount();
});

test('late detail for an old selection cannot paint a newer selection', async () => {
  const old = deferred();
  const { h } = await mounted(query => query.get('type') === 'capture_status' ? response(status) : query.get('type') === 'capture_history' ? response(list([row('old'), row('new')])) : query.get('id') === 'old' ? old.promise : response(detail('new')));
  await history(h); button(h, 'GET http://localhost:3000/old').props.onClick(); h.render(); await select(h, 'new');
  old.resolve(response(detail('old'))); await settle(); h.render();
  button(h, '生成重放审批草稿').props.onClick(); h.render(); assert.equal(draftArgs(h).id, 'new'); h.unmount();
});

test('refreshing status invalidates in-flight history and all previous detail drafts', async () => {
  const pending = deferred(); let statusReads = 0;
  const { h } = await mounted(query => query.get('type') === 'capture_status' ? response({ ...status, session_id: ++statusReads === 1 ? 'session-1' : 'session-2' }) : pending.promise);
  button(h, '读取最新记录').props.onClick(); h.render();
  button(h, '刷新捕获状态').props.onClick(); h.render(); await settle(); h.render();
  pending.resolve(response(list([row('stale')]))); await settle(); h.render();
  assert.doesNotMatch(text(h.tree), /localhost:3000\/stale/); assert.match(text(h.tree), /session-2/); h.unmount();
});

test('cross-session records and oversized pages are rejected before rendering', async () => {
  for (const invalid of [list([row('wrong', { session_id: 'session-2' })]), list([row('wrong')], { session_id: 'session-2' }), list(Array.from({ length: 21 }, (_, i) => row(`item-${i}`)))]) {
    const { h } = await mounted(query => response(query.get('type') === 'capture_status' ? status : invalid));
    await history(h); assert.match(text(h.tree), /流量会话已变化或数据格式无效/); assert.doesNotMatch(text(h.tree), /localhost:3000\/(?:wrong|item)/); h.unmount();
  }
});

test('detail identity mismatches and read errors remain explicit failures', async () => {
  const { h } = await mounted(query => response(query.get('type') === 'capture_status' ? status : query.get('type') === 'capture_history' ? list([row('first')]) : detail('wrong')));
  await history(h); await select(h, 'first'); assert.match(text(h.tree), /流量详情身份已变化/); assert.doesNotMatch(text(h.tree), /生成重放审批草稿/); h.unmount();
  const failed = await mounted(() => ({ ok: false, status: 503 })); assert.match(text(failed.h.tree), /HTTP 503/); failed.h.unmount();
});

test('start requires an explicit scope and only inserts a user-editable composer draft', async () => {
  const inserted = [], insertion = { revision: 5, start: 4, end: 4 };
  const { h, calls } = await mounted(() => response(status), { inputActions: {
    captureInsertion: () => insertion,
    insertText: (...args) => { inserted.push(args); return true; }, persistDraft: () => inserted.push('persist'), submit: () => assert.fail('must never submit'),
  } });
  button(h, '生成启动审批草稿').props.onClick(); h.render(); assert.match(text(h.tree), /请填写明确的/);
  input(h, '捕获目标范围').props.onChange({ target: { value: 'http://localhost:3000,https://localhost:4443' } }); h.render();
  button(h, '生成启动审批草稿').props.onClick(); h.render();
  assert.deepEqual(draftArgs(h), { port: 0, scope: ['http://localhost:3000', 'https://localhost:4443'], action: 'start' });
  input(h, '待发送流量工具草稿').props.onChange({ target: { value: input(h, '待发送流量工具草稿').props.value + '\n请先核对监听范围。' } }); h.render();
  button(h, '插入会话草稿（待发送）').props.onClick(); h.render();
  assert.equal(inserted[0][1], insertion); assert.match(inserted[0][0], /ig5_capture_control/); assert.match(inserted[0][0], /请先核对监听范围/);
  assert.equal(inserted[1], 'persist'); assert.match(text(h.tree), /尚未发送或执行/); assert.equal(calls.length, 1); h.unmount();
});

test('composer absence or stale insertion keeps a copyable draft without persistence', async () => {
  for (const props of [{}, { inputActions: { captureInsertion: () => ({}), insertText: () => false, persistDraft: () => assert.fail('must not persist rejected insertion') } }]) {
    const { h, calls } = await mounted(() => response(status), props);
    button(h, '生成停止审批草稿').props.onClick(); h.render(); button(h, '插入会话草稿（待发送）').props.onClick(); h.render();
    assert.equal(draftArgs(h).action, 'stop'); assert.match(text(h.tree), /复制草稿|复制下方草稿/); assert.equal(calls.length, 1); h.unmount();
  }
});

test('HTTPS decryption stays explicit in drafts and displays actual CA evidence only when enabled', async () => {
  const { h, calls } = await mounted(() => response({ ...status, tlsInterceptEnabled: true, certificate: { certificatePath: 'C:/capture/capture-ca.pem', fingerprint256: '11:22' } }));
  assert.match(text(h.tree), /HTTPS 解密已启用/); assert.match(text(h.tree), /C:\/capture\/capture-ca.pem/); assert.match(text(h.tree), /11:22/);
  input(h, '捕获目标范围').props.onChange({ target: { value: 'https://localhost:4443/path' } }); h.render();
  button(h, '生成启动审批草稿').props.onClick(); h.render(); assert.match(text(h.tree), /仅协议、主机和端口/);
  input(h, '捕获目标范围').props.onChange({ target: { value: 'https://localhost:4443' } }); h.render();
  input(h, '启用 HTTPS 解密').props.onChange({ target: { checked: true } }); h.render();
  button(h, '生成启动审批草稿').props.onClick(); h.render(); assert.equal(draftArgs(h).tls, true);
  assert.equal(calls.length, 1); h.unmount();
});

test('replay and export drafts retain captured identity and do not perform HTTP writes', async () => {
  const { h, calls } = await mounted(query => response(query.get('type') === 'capture_status' ? status : query.get('type') === 'capture_history' ? list([row('selected')]) : detail('selected')));
  await history(h); await select(h, 'selected');
  button(h, '生成重放审批草稿').props.onClick(); h.render(); assert.deepEqual(draftArgs(h), { id: 'selected', session_id: 'session-1', action: 'replay' });
  button(h, '生成响应正文导出草稿').props.onClick(); h.render();
  assert.deepEqual(draftArgs(h), { id: 'selected', session_id: 'session-1', body: 'response', action: 'export' });
  assert.match(input(h, '待发送流量工具草稿').props.value, /调用 ig5_capture，/); assert.equal(calls.length, 3); h.unmount();
});

test('CONNECT records clearly expose encrypted metadata and no replay or body export controls', async () => {
  const { h } = await mounted(query => response(query.get('type') === 'capture_status' ? status : query.get('type') === 'capture_history' ? list([row('tls', { encrypted: true })]) : detail('tls', { encrypted: true })));
  await history(h); await select(h, 'tls'); assert.match(text(h.tree), /没有解密后的 HTTP/); assert.doesNotMatch(text(h.tree), /生成重放审批草稿|正文导出草稿/); h.unmount();
});

test('WebSocket payloads retain frame direction and compression caveats without HTTP replay', async () => {
  const frame = { protocol: 'websocket', websocket: { direction: 'client_to_server', opcode: 2, fin: false, compressed: true, reassembled: false } };
  const { h, calls } = await mounted(query => response(query.get('type') === 'capture_status' ? status : query.get('type') === 'capture_history' ? list([row('ws', frame)]) : detail('ws', frame)));
  await history(h); await select(h, 'ws'); assert.match(text(h.tree), /客户端 → 服务端/); assert.match(text(h.tree), /opcode 2/); assert.match(text(h.tree), /FIN=false/);
  assert.match(text(h.tree), /尚未解压或重组/); assert.match(text(h.tree), /不代表完整应用消息/); assert.doesNotMatch(text(h.tree), /生成重放审批草稿|生成被动检查草稿/);
  button(h, '生成请求正文导出草稿').props.onClick(); h.render(); assert.equal(draftArgs(h).body, 'request'); assert.equal(calls.length, 3); h.unmount();
});

test('delivered script analysis and sample saving create identity-bound drafts without execution or requests', async () => {
  const inserted = [], insertion = { revision: 7, start: 3, end: 3 };
  const script = 'globalThis.compromised = true; fetch("https://unexpected.invalid");';
  const sample = detail('script', { response: { statusCode: 200, headers: { 'content-type': 'application/javascript' }, body: { ref: 'sha256:script', bytes: script.length, previewText: script } } });
  const { h, calls } = await mounted(query => response(query.get('type') === 'capture_status' ? status : query.get('type') === 'capture_history' ? list([row('script')]) : sample), { inputActions: {
    captureInsertion: () => insertion, insertText: (...args) => { inserted.push(args); return true; }, submit: () => assert.fail('must not submit or execute delivered code'),
  } });
  await history(h); await select(h, 'script');
  assert.match(text(h.tree), /不能据此看到未返回的服务器内部代码/); assert.match(text(h.tree), /按格式、架构与引擎实际支持/);
  button(h, '分析下发载荷').props.onClick(); h.render();
  assert.deepEqual(draftArgs(h), { id: 'script', session_id: 'session-1', body: 'response', action: 'inspect_payload' });
  button(h, '保存为逆向样本').props.onClick(); h.render();
  assert.deepEqual(draftArgs(h), { id: 'script', session_id: 'session-1', body: 'response', action: 'materialize' });
  const draft = input(h, '待发送流量工具草稿').props.value;
  assert.match(draft, /调用 ig5_capture，/); assert.doesNotMatch(draft, /compromised|fetch|ig5_open|ig5_dbg/);
  button(h, '插入会话草稿（待发送）').props.onClick(); h.render();
  assert.equal(inserted.length, 1); assert.equal(inserted[0][1], insertion); assert.equal(calls.length, 3);
  assert.match(text(h.tree), /尚未发送或执行/); h.unmount();
});

test('compressed and partial responses explain decoding and keep incomplete binaries out of materialize drafts', async () => {
  for (const change of [
    { complete: false },
    { response: { ...detail('partial').response, truncated: true } },
    { response: { ...detail('partial').response, statusCode: 206 } },
    { response: { ...detail('partial').response, headers: { 'content-range': 'bytes 0-1/100' } } },
  ]) {
    const { h, calls } = await mounted(query => response(query.get('type') === 'capture_status' ? status : query.get('type') === 'capture_history' ? list([row('partial')]) : detail('partial', change)));
    await history(h); await select(h, 'partial'); assert.match(text(h.tree), /载荷尚不完整/);
    assert.equal(button(h, '分析下发载荷').props.disabled, false); assert.equal(button(h, '保存为逆向样本').props.disabled, true);
    button(h, '保存为逆向样本').props.onClick(); h.render(); assert.match(text(h.tree), /先补齐资源或重组分片/);
    assert.equal(nodes(h.tree, node => node.props['aria-label'] === '待发送流量工具草稿').length, 0); assert.equal(calls.length, 3); h.unmount();
  }
  const { h, calls } = await mounted(query => response(query.get('type') === 'capture_status' ? status : query.get('type') === 'capture_history' ? list([row('gzip')]) : detail('gzip', { response: { ...detail('gzip').response, headers: { 'content-encoding': 'gzip' } } })));
  await history(h); await select(h, 'gzip'); assert.match(text(h.tree), /Content-Encoding：gzip/); assert.match(text(h.tree), /先在预算内解码/);
  assert.equal(button(h, '保存为逆向样本').props.disabled, true);
  button(h, '保存为逆向样本').props.onClick(); h.render(); assert.match(text(h.tree), /先解码或重组/);
  button(h, '分析下发载荷').props.onClick(); h.render(); assert.equal(draftArgs(h).action, 'inspect_payload'); assert.equal(calls.length, 3); h.unmount();
});

test('payload handoff distinguishes server frames from client uploads and incomplete WebSocket fragments', async () => {
  for (const [direction, fin, opcode, compressed, canInspect, canSave] of [
    ['client_to_server', true, 2, false, false, false], ['server_to_client', false, 2, false, true, false],
    ['server_to_client', true, 2, false, true, true], ['server_to_client', true, 2, true, true, false],
    ['server_to_client', true, 0, false, true, false], ['server_to_client', true, 9, false, true, false],
  ]) {
    const frame = { protocol: 'websocket', websocket: { direction, opcode, fin, compressed, reassembled: false } };
    const { h, calls } = await mounted(query => response(query.get('type') === 'capture_status' ? status : query.get('type') === 'capture_history' ? list([row('frame', frame)]) : detail('frame', frame)));
    await history(h); await select(h, 'frame');
    assert.equal(button(h, '分析下发载荷').props.disabled, !canInspect); assert.equal(button(h, '保存为逆向样本').props.disabled, !canSave);
    if (canInspect) { button(h, '分析下发载荷').props.onClick(); h.render(); assert.equal(draftArgs(h).body, 'response'); }
    assert.equal(calls.length, 3); h.unmount();
  }
});

test('changing selected capture clears a materialize draft before reading the next response', async () => {
  const pending = deferred();
  const { h } = await mounted(query => query.get('type') === 'capture_status' ? response(status) : query.get('type') === 'capture_history' ? response(list([row('old'), row('next')])) : query.get('id') === 'old' ? response(detail('old')) : pending.promise);
  await history(h); await select(h, 'old'); button(h, '保存为逆向样本').props.onClick(); h.render(); assert.equal(draftArgs(h).id, 'old');
  button(h, 'GET http://localhost:3000/next').props.onClick(); h.render();
  assert.equal(nodes(h.tree, node => node.props['aria-label'] === '待发送流量工具草稿').length, 0);
  pending.resolve(response(detail('next'))); await settle(); h.render(); button(h, '保存为逆向样本').props.onClick(); h.render(); assert.equal(draftArgs(h).id, 'next'); h.unmount();
});

test('body preview stays bounded literal text with explicit capture and preview truncation', () => {
  const source = '<img src=x onerror=alert(1)>'.repeat(3000);
  const h = harness(ui.CaptureMessage, { label: '响应', message: { headers: { injected: '<script>steal()</script>' }, body: { bytes: 99999, ref: 'sha256:body', previewText: source, truncated: true } } });
  h.render(); const pre = nodes(h.tree, node => node.type === 'pre');
  assert.equal(pre[1].children[0], source.slice(0, 64000));
  assert.ok(nodes(h.tree, () => true).every(node => node.props.dangerouslySetInnerHTML === undefined));
  assert.equal(nodes(h.tree, node => node.type === 'img' || node.type === 'script').length, 0);
  assert.match(text(h.tree), /正文捕获已截断/); assert.match(text(h.tree), /当前预览已截断/);
});

test('unmount invalidates pending status and detail responses', async () => {
  const pending = deferred(); const { h } = await mounted(() => pending.promise);
  h.unmount(); const before = JSON.stringify(h.cells); pending.resolve(response(status)); await settle();
  assert.equal(JSON.stringify(h.cells), before);
});
