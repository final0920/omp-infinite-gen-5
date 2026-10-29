// Worker processes must not inherit host secrets. Pure checks: no worker, sample or network starts.
import assert from 'node:assert/strict';
import test from 'node:test';
import { workerEnvironment, workerLaunch } from '../source/worker_transport.js';

const fake = {
  PATH: 'C:\\Windows', SystemRoot: 'C:\\Windows', TEMP: 'C:\\tmp', LC_ALL: 'C', IG5_HOME: 'C:\\ig5',
  DEEPSEEK_API_KEY: 'sk-secret', ANTHROPIC_API_KEY: 'sk-secret', GITHUB_TOKEN: 'ghp_secret', AWS_SECRET_ACCESS_KEY: 'secret',
  HTTP_PROXY: 'http://user:pass@proxy',
};

test('secrets are dropped, startup essentials are kept (case-insensitive names)', () => {
  const env = workerEnvironment(fake);
  for (const name of ['PATH', 'SystemRoot', 'TEMP', 'LC_ALL', 'IG5_HOME']) assert.equal(env[name], fake[name], name);
  for (const name of ['DEEPSEEK_API_KEY', 'ANTHROPIC_API_KEY', 'GITHUB_TOKEN', 'AWS_SECRET_ACCESS_KEY', 'HTTP_PROXY']) assert.equal(env[name], undefined, name);
});

test('explicit passthrough allows named variables only', () => {
  const env = workerEnvironment(fake, ['http_proxy']);
  assert.equal(env.HTTP_PROXY, fake.HTTP_PROXY); assert.equal(env.GITHUB_TOKEN, undefined);
  assert.throws(() => workerEnvironment(fake, 'HTTP_PROXY'), /array/); assert.throws(() => workerEnvironment(fake, ['']), /array/);
});

test('the real launch path applies the allowlist and still sets the Python encoding flags', () => {
  const saved = { ...process.env };
  Object.assign(process.env, { DEEPSEEK_API_KEY: 'sk-launch-secret', GITHUB_TOKEN: 'ghp_launch' });
  try {
    const cfg = { reverseProvider: 'bundled', reverseAvailable: true, home: 'C:\\h', projectRoot: 'C:\\p', host: { platform: 'win32' },
      ghidra: { available: true, pythonExe: 'C:\\py\\python.exe', ghidraHome: 'C:\\g', javaHome: 'C:\\j' } };
    const { options } = workerLaunch(cfg, 'ghidra', 'C:\\plugin');
    assert.equal(options.env.DEEPSEEK_API_KEY, undefined); assert.equal(options.env.GITHUB_TOKEN, undefined);
    assert.equal(options.env.PYTHONUTF8, '1'); assert.equal(options.env.IG5_JAVA_HOME, 'C:\\j');
    assert.ok(options.env.PATH || options.env.Path, 'PATH must survive');
    const wider = workerLaunch({ ...cfg, workerEnvPassthrough: ['GITHUB_TOKEN'] }, 'ghidra', 'C:\\plugin').options.env;
    assert.equal(wider.GITHUB_TOKEN, 'ghp_launch'); assert.equal(wider.DEEPSEEK_API_KEY, undefined);
  } finally {
    for (const name of Object.keys(process.env)) if (!(name in saved)) delete process.env[name];
    Object.assign(process.env, saved);
  }
});
