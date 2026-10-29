// Actual host doctor method, synthetic transport; no process or target starts.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const source = fs.readFileSync(new URL('../index.js', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const method = source.match(/  async doctor\(engine =[\s\S]*?\n  }\n/)?.[0];
assert(method);
async function invoke(result) {
  let metadataStarts = 0, kills = 0;
  const sandbox = { engineId: value => value, doctorWorker: async () => result, terminateTree: child => child?.kill() };
  const value = vm.runInNewContext('({' + method + '})', sandbox);
  value.cfg = {}; value.spawnWorker = () => { metadataStarts++; return { kill() { kills++; } }; }; value.rpcError = error => error;
  try { return { result: await value.doctor('x64dbg'), metadataStarts, kills }; }
  catch (error) { return { error: error.message, metadataStarts, kills }; }
}
test('host retains blocked launch evidence instead of replacing it with a generic startup error', async () => {
  const out = await invoke({ ok: false, engine: 'x64dbg', filesReady: true, launchVerified: false, targetExecuted: false,
    launchReadiness: { 64: { state: 'blocked-by-application-control', nativeLaunchAttempted: false, block: { winError: 4551 } } } });
  assert.equal(out.result.ok, false); assert.equal(out.result.nativeTargetExecuted, false); assert.equal(out.result.startupVerified, false);
  assert.equal(out.result.launchReadiness[64].block.winError, 4551); assert.equal(out.metadataStarts, 1); assert.equal(out.kills, 1);
});
test('unknown cache state also prevents a positive execution readiness claim', async () => {
  const out = await invoke({ ok: false, engine: 'x64dbg', launchVerified: false, targetExecuted: false,
    launchReadiness: { 64: { state: 'unknown-policy-state', nativeLaunchAttempted: false } } });
  assert.equal(out.result.ok, false); assert.equal(out.result.scope, 'metadata-and-recorded-launch-blocks-only'); assert.equal(out.kills, 1);
});
test('other malformed/unsuccessful startup responses retain the original rejection', async () => {
  const out = await invoke({ ok: false }); assert.match(out.error, /did not confirm/); assert.equal(out.kills, 1);
});
test('file-only readiness remains explicitly unprobed and cannot become startup proof', async () => {
  const out = await invoke({ ok: true, engine: 'x64dbg', launchVerified: false, targetExecuted: false, launchReadiness: { 64: { state: 'not-probed', nativeLaunchAttempted: false } } });
  assert.equal(out.result.launchVerified, false); assert.equal(out.result.launchReadiness[64].state, 'not-probed'); assert.equal(out.kills, 1);
  assert.equal(out.result.startupVerified, false); assert.equal(out.result.runtimeReady, false);
});
