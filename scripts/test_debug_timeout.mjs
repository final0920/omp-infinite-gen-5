import test from 'node:test';
import assert from 'node:assert/strict';
import { debugTimeout } from '../source/debug_timeout.js';
test('explicit continuation wait has bounded RPC cleanup margin', () => {
  assert.deepEqual(debugTimeout({ op: 'cont', backend: 'x64dbg', timeout: 120 }, { requestTimeoutMs: 180000 }), { seconds: 120, rpcTimeoutMs: 135000 });
  assert.deepEqual(debugTimeout({ op: 'trace', record_trace: true }, { requestTimeoutMs: 180000 }), { seconds: 45, rpcTimeoutMs: 75000 });
  assert.equal(debugTimeout({ op: 'cont' }, { requestTimeoutMs: 180000 }).seconds, 30);
  assert.throws(() => debugTimeout({ op: 'cont', backend: 'x64dbg', timeout: 120 }, { requestTimeoutMs: 120000 }), /shorter/);
});
test('long waits do not widen tracing, other engines or invalid numeric inputs', () => {
  for (const args of [{ op: 'trace', timeout: 61 }, { op: 'cont', backend: 'win32', timeout: 61 }, { op: 'start', backend: 'x64dbg', timeout: 61 }, { op: 'cont', backend: 'x64dbg', timeout: 121 }])
    assert.throws(() => debugTimeout(args, { requestTimeoutMs: 180000 }), /at most/);
  for (const timeout of [NaN, Infinity, true, '30', 0, -1]) assert.throws(() => debugTimeout({ op: 'cont', timeout }, { requestTimeoutMs: 180000 }), /timeout/);
});
