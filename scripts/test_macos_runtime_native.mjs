#!/usr/bin/env node
// Optional real macOS arm64 smoke. Synthetic unit tests cannot prove JVM/engine startup.
// Supply an explicitly provisioned runtime and an authorized local binary sample.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { runtimeConfiguration, terminateTree } from '../engine_runtime.js';
import { attachWorker, spawnWorker } from '../source/worker_transport.js';

async function main([root, sample, filter]) {
  if (process.platform !== 'darwin' || process.arch !== 'arm64' || !root || !sample) {
    throw new Error('Usage (macOS arm64): node scripts/test_macos_runtime_native.mjs <runtime-root> <sample-file> [function-filter]');
  }
  const target = fs.realpathSync(sample);
  assert.ok(fs.statSync(target).isFile(), 'sample must be a file');
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-mac-native-smoke-'));
  const owner = fs.statSync(temporary);
  // Optional real check of the macOS default under an isolated HOME; never writes to the user's Library.
  const checkDefaultProjectRoot = process.env.IG5_MAC_NATIVE_DEFAULT_PROJECT_ROOT === '1';
  const originalHome = process.env.HOME;
  if (checkDefaultProjectRoot) process.env.HOME = temporary;
  let child, client;
  try {
    const cfg = runtimeConfiguration({ runtimeRoot: root, ...(checkDefaultProjectRoot ? {} : { projectRoot: temporary }) });
    if (checkDefaultProjectRoot) assert.equal(cfg.projectRoot,
      path.join(temporary, 'Library', 'Application Support', 'DeepSeek Harness', 'IG5', 'projects'));
    assert.equal(cfg.host.id, 'darwin-arm64');
    assert.equal(cfg.ghidra.available, true, cfg.ghidra.reason);
    assert.equal(cfg.ghidra.integrityVerified, false, 'startup validation does not rehash the entire runtime');
    assert.equal(cfg.x64dbg.available, false, 'x64dbg must remain unavailable on macOS');
    assert.equal(cfg.reverseProvider, 'bundled', 'default Reverse should use this Ghidra runtime');
    for (const route of ['ghidra', 'reverse']) {
      child = spawnWorker(cfg, route, path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..'));
      const session = { seq: 0, pending: new Map(), engine: route };
      client = attachWorker(child, { session, onMessage(message) {
        if (message.ig5 === 'progress' || message.ig5 === 'ready') return;
        const pending = session.pending.get(message.id);
        if (!pending) return; // ready/progress messages do not settle an RPC
        clearTimeout(pending.timer);
        pending.removeAbort?.();
        session.pending.delete(message.id);
        message.error ? pending.reject(new Error(message.error.message)) : pending.resolve(message.result);
      } });
      await client.waitReady(90000);
      const request = (method, params = {}) => client.request(session, method, params, { timeoutMs: method === 'open' ? 180000 : 90000 });
      const doctor = await request('doctor');
      assert.equal(doctor.ok, true);
      assert.equal(doctor.version, '12.1.4');
      assert.equal(doctor.python.startsWith('3.12.'), true);
      assert.equal(doctor.jpype, '1.5.2');
      assert.ok(doctor.unsupported.includes('dbg') && doctor.unsupported.includes('emulate'));
      const opened = await request('open', { path: target, auto: true, analysis_timeout: 60 });
      assert.equal(opened.open, true);
      assert.equal(opened.partial, false, 'sample analysis did not finish in the time budget');
      const funcs = await request('funcs', { filter: filter || '', limit: 30, user_only: true });
      assert.ok(funcs.funcs.length, `no non-thunk functions matched ${JSON.stringify(filter || '')}`);
      const selected = funcs.funcs[0];
      const decompiled = await request('decompile', { ea: selected.ea });
      assert.ok(decompiled.code.trim(), 'no decompiled function body');
      assert.equal(decompiled.ea, selected.ea);
      await request('close');
      child.stdin.end();
      await once(child, 'close');
      assert.equal(child.exitCode, 0, client.stderrTail);
      console.log(JSON.stringify({ nativeVerified: true, route, engine: doctor.engine, version: doctor.version,
        host: cfg.host.id, sample: target, function: selected.name, ea: selected.ea,
        codePreview: decompiled.code.trim().slice(0, 300), validation: cfg.ghidra.validation,
        projectRoot: cfg.projectRoot, defaultProjectRootUsed: checkDefaultProjectRoot,
        integrityVerified: cfg.ghidra.integrityVerified }));
      client.dispose();
      client = null;
      child = null;
    }
  } finally {
    if (child && child.exitCode === null && !child.signalCode) terminateTree(child);
    client?.dispose();
    if (checkDefaultProjectRoot) {
      if (originalHome === undefined) delete process.env.HOME;
      else process.env.HOME = originalHome;
    }
    // Delete only this invocation's just-created, same-inode scratch project.
    try {
      const now = fs.lstatSync(temporary);
      if (now.isDirectory() && now.dev === owner.dev && now.ino === owner.ino
        && path.dirname(fs.realpathSync(temporary)) === fs.realpathSync(os.tmpdir())) {
        fs.rmSync(temporary, { recursive: true });
      }
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
}

main(process.argv.slice(2)).catch(error => { console.error(error); process.exitCode = 1; });
