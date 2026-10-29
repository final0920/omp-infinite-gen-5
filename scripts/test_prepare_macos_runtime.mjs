// Self-contained synthetic Mach-O fixtures: no Ghidra/JDK/Python download or execution.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { prepareMacosRuntime } from './prepare_macos_runtime.mjs';
import { readRuntime } from '../engine_runtime.js';
import { hostPlatform } from '../source/host_platform.js';

const scratch = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-prepare-macos-'));
const owner = fs.statSync(scratch);
const script = fileURLToPath(new URL('./prepare_macos_runtime.mjs', import.meta.url));
const packageVersion = JSON.parse(fs.readFileSync(fileURLToPath(new URL('../package.json', import.meta.url)), 'utf8')).version;
const host = hostPlatform({ platform: 'darwin', arch: 'arm64', env: {} });
const pass = title => console.log('PASS', title);
const keys = ['ghidra', 'python', 'jdk'];
function put(root, relative, body = 'fixture\n', executable = false) {
  const file = path.join(root, relative);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, body);
  if (executable) fs.chmodSync(file, 0o755);
  return file;
}
function mach(filetype = 2, cpu = 0x0100000c) {
  const result = Buffer.alloc(64);
  result.writeUInt32LE(0xfeedfacf, 0); result.writeUInt32LE(cpu, 4);
  result.writeUInt32LE(filetype, 12); return result;
}
function fixture(name, nativeLocation = 'os') {
  const root = path.join(scratch, name);
  const inputs = Object.fromEntries(keys.map(key => [key, path.join(root, key)]));
  const gh = inputs.ghidra, py = inputs.python, jdk = inputs.jdk;
  put(gh, 'Ghidra/application.properties', 'application.version=12.1.4\napplication.java.min=21\n');
  put(gh, 'LICENSE'); put(gh, 'bom.json'); put(gh, 'licenses/THIRD_PARTY.txt');
  for (const name of ['Ghidra/Framework/Utility/lib/Utility.jar', 'Ghidra/Features/Base/lib/Base.jar',
    'Ghidra/Features/PyGhidra/lib/PyGhidra.jar', 'Ghidra/Processors/x86/data/languages/x86-64.sla']) put(gh, name);
  for (const name of ['decompile', 'sleigh']) {
    put(gh, `Ghidra/Features/Decompiler/${nativeLocation}/mac_arm_64/${name}`, mach(), true);
  }
  put(py, 'bin/python3.12', mach(), true); put(py, 'lib/libpython3.12.dylib', mach(6));
  const standard = 'lib/python3.12';
  for (const name of ['os.py', 'site.py', 'encodings/__init__.py']) put(py, `${standard}/${name}`);
  const modules = standard + '/site-packages/';
  put(py, modules + '_jpype.cpython-312-darwin.so', mach(8));
  for (const name of ['pyghidra/__init__.py', 'pyghidra/launcher.py', 'jpype/__init__.py',
    'packaging/__init__.py', 'org.jpype.jar']) put(py, modules + name);
  for (const name of ['pyghidra-12.1.4.dist-info/LICENSE', 'jpype1-1.5.2.dist-info/LICENSE',
    'packaging-26.dist-info/LICENSE']) put(py, modules + name);
  put(py, 'LICENSE.txt');
  put(jdk, 'release', 'JAVA_VERSION="21.0.12.1"\nOS_ARCH="aarch64"\nOS_NAME="Darwin"\n');
  put(jdk, 'bin/java', mach(), true);
  put(jdk, 'lib/server/libjvm.dylib', mach(6)); put(jdk, 'lib/libjli.dylib', mach(6));
  put(jdk, 'lib/modules'); put(jdk, 'jmods/java.base.jmod'); put(jdk, 'legal/LICENSE');
  return inputs;
}
const outputOf = name => path.join(scratch, name);
const listStages = name => fs.readdirSync(scratch).filter(item => item.startsWith(`.${name}.staging-`));
const fake = { verifyDependencies({ stage, runtime }) {
  assert.equal(runtime.available, true); assert.equal(runtime.integrityVerified, false);
  assert.equal(path.dirname(stage), scratch);
} };
const expectFailure = (inputs, outputName, message, hooks = fake) => {
  const destination = outputOf(outputName);
  assert.throws(() => prepareMacosRuntime({ ...inputs, output: destination }, hooks), message);
  assert.equal(fs.existsSync(destination), false, 'no partial output may be published');
  assert.deepEqual(listStages(outputName), [], 'owned staging directory must be removed on failure');
};
try {
  const inputs = fixture('provisioned', 'build/os');
  fs.symlinkSync('LICENSE', path.join(inputs.ghidra, 'LICENSE.alias'));
  fs.symlinkSync('licenses', path.join(inputs.ghidra, 'licenses.alias'));
  // Source must be read-only to this operation: record all structural and content attributes.
  const unchanged = ['ghidra/LICENSE', 'ghidra/Ghidra/Features/Decompiler/build/os/mac_arm_64/decompile',
    'python/bin/python3.12', 'python/lib/libpython3.12.dylib', 'jdk/bin/java'].map(name => {
    const full = path.join(path.dirname(inputs.ghidra), name), stat = fs.statSync(full);
    return [full, stat.size, stat.mode, stat.mtimeMs, createHash('sha256').update(fs.readFileSync(full)).digest('hex')];
  });
  const output = outputOf('darwin-arm64');
  const result = prepareMacosRuntime({ ...inputs, output }, fake);
  assert.equal(result.output, output); assert.ok(result.filesVerified > 20); assert.equal(result.linksVerified, 2);
  assert.equal(fs.readlinkSync(path.join(output, 'ghidra/ghidra/LICENSE.alias')), 'LICENSE');
  assert.equal(fs.readlinkSync(path.join(output, 'ghidra/ghidra/licenses.alias')), 'licenses');
  // Windows does not expose POSIX executable bits through stat/chmod. Keep the
  // assertion active on POSIX hosts, including the real darwin-arm64 pack host.
  if (process.platform !== 'win32') {
    for (const name of ['ghidra/python/bin/python3.12', 'ghidra/jdk/Contents/Home/bin/java',
      'ghidra/ghidra/Ghidra/Features/Decompiler/os/mac_arm_64/decompile',
      'ghidra/ghidra/Ghidra/Features/Decompiler/os/mac_arm_64/sleigh']) {
      assert.ok((fs.statSync(path.join(output, name)).mode & 0o111) !== 0, `executable bit: ${name}`);
    }
  }
  const inventory = JSON.parse(fs.readFileSync(result.inventory, 'utf8'));
  assert.deepEqual([inventory.schemaVersion, inventory.platform, inventory.pluginVersion, inventory.engines],
    [1, 'darwin-arm64', packageVersion, ['ghidra']]);
  assert.deepEqual(inventory.links, [
    { path: 'ghidra/ghidra/LICENSE.alias', target: 'LICENSE' },
    { path: 'ghidra/ghidra/licenses.alias', target: 'licenses' },
  ]);
  for (const file of inventory.files) {
    const data = fs.readFileSync(path.join(output, file.path));
    assert.equal(file.bytes, data.length, file.path);
    assert.equal(file.sha256, createHash('sha256').update(data).digest('hex'), file.path);
  }
  assert.ok(inventory.files.some(row => row.path === 'ghidra/ghidra/LICENSE.alias'));
  assert.ok(inventory.files.some(row => row.path.endsWith('/os/mac_arm_64/sleigh')));
  assert.ok(!inventory.files.some(row => row.path === 'manifest.json'));
  const admitted = readRuntime(output, 'ghidra', undefined, { host, source: 'config' });
  assert.equal(admitted.available, true, admitted.reason);
  assert.equal(admitted.integrityVerified, false, 'loader cannot claim to hash entire runtime on startup');
  for (const [file, size, mode, mtime, sha] of unchanged) {
    const stat = fs.statSync(file);
    assert.equal(stat.size, size); assert.equal(stat.mode, mode); assert.equal(stat.mtimeMs, mtime);
    assert.equal(createHash('sha256').update(fs.readFileSync(file)).digest('hex'), sha);
  }
  pass('offline copied trees, licenses, contained file/directory symlinks, native promotion, SHA inventory and readRuntime admission');
  const direct = fixture('already-os-native');
  const directResult = prepareMacosRuntime({ ...direct, output: outputOf('direct-native-pack') }, fake);
  assert.equal(readRuntime(directResult.output, 'ghidra', undefined, { host }).available, true);
  pass('already canonical os/mac_arm_64 layout assembles without build/os');
  const standalone = fixture('standalone-python-license');
  const originalLicense = path.join(standalone.python, 'LICENSE.txt');
  const sourceLicense = put(standalone.python, 'lib/python3.12/LICENSE.txt', 'Standalone Python license\n');
  fs.unlinkSync(originalLicense);
  const standaloneResult = prepareMacosRuntime({ ...standalone, output: outputOf('standalone-license-pack') }, fake);
  assert.equal(fs.readFileSync(path.join(standaloneResult.output, 'ghidra/python/LICENSE.txt'), 'utf8'),
    fs.readFileSync(sourceLicense, 'utf8'));
  assert.equal(fs.readFileSync(path.join(standaloneResult.output, 'ghidra/python/lib/python3.12/LICENSE.txt'), 'utf8'),
    fs.readFileSync(sourceLicense, 'utf8'));
  assert.equal(fs.existsSync(originalLicense), false, 'input Python prefix must remain untouched');
  pass('python-build-standalone stdlib LICENSE is copied to required prefix root without changing source');

  assert.throws(() => prepareMacosRuntime({ ...inputs, output }, fake), /NEW directory|overwrite/);
  assert.ok(fs.existsSync(path.join(output, 'ghidra/runtime.json')));
  expectFailure(inputs, 'probe-fails', /dependency probe rejected/, { verifyDependencies() { throw new Error('dependency probe rejected'); } });
  expectFailure(inputs, 'probe-mutates-pack', /probe altered staged runtime contents/, { verifyDependencies({ stage }) {
    fs.writeFileSync(path.join(stage, 'ghidra/python/LICENSE.txt'), 'unexpected change');
  } });
  const absent = fixture('missing-dependency');
  fs.unlinkSync(path.join(absent.python, 'lib/python3.12/site-packages/packaging/__init__.py'));
  expectFailure(absent, 'missing-dep-output', /Python dependency packaging\/__init__\.py/);
  pass('failed dependencies and existing destination never publish or destroy a pack');

  const wrongArch = fixture('x86-source');
  put(wrongArch.python, 'bin/python3.12', mach(2, 0x01000007), true);
  expectFailure(wrongArch, 'wrong-arch-pack', /pythonExe.*Mach-O|expected thin macOS/i);
  const wrongGhidra = fixture('wrong-version-source');
  put(wrongGhidra.ghidra, 'Ghidra/application.properties', 'application.version=12.3\napplication.java.min=21\n');
  expectFailure(wrongGhidra, 'wrong-ghidra-pack', /version does not match/);
  const wrongJdk = fixture('wrong-jdk-source');
  put(wrongJdk.jdk, 'release', 'JAVA_VERSION="17"\nOS_ARCH="x86_64"\nOS_NAME="Darwin"\n');
  expectFailure(wrongJdk, 'wrong-jdk-pack', /JDK 21/);
  const tooNewJdk = fixture('jdk22-source');
  put(tooNewJdk.jdk, 'release', 'JAVA_VERSION="22.0.1"\nOS_ARCH="arm64"\nOS_NAME="Darwin"\n');
  expectFailure(tooNewJdk, 'jdk22-pack', /JDK 21/);
  pass('synthetic x86_64 Python, incompatible Ghidra and JDK versions other than 21 are rejected');

  const external = put(scratch, 'outside.txt', 'not in tree');
  const escaping = fixture('escaping-source');
  fs.symlinkSync(external, path.join(escaping.python, 'bad-link'));
  expectFailure(escaping, 'absolute-link-output', /Absolute symlink/);
  fs.unlinkSync(path.join(escaping.python, 'bad-link'));
  fs.symlinkSync(path.relative(escaping.python, external), path.join(escaping.python, 'bad-link'));
  expectFailure(escaping, 'relative-link-output', /Symlink escapes/);
  fs.unlinkSync(path.join(escaping.python, 'bad-link'));
  fs.symlinkSync('not-created', path.join(escaping.python, 'bad-link'));
  expectFailure(escaping, 'broken-link-output', /Broken or cyclic symlink/);
  const nested = path.join(escaping.python, 'lib/python3.12/site-packages');
  fs.symlinkSync('..', path.join(nested, 'self-parent'));
  const parentLink = path.join(scratch, 'parent-alias');
  fs.symlinkSync(scratch, parentLink);
  const aliasInputs = Object.fromEntries(keys.map(key => [key, path.join(parentLink, 'provisioned', key)]));
  assert.equal(prepareMacosRuntime({ ...aliasInputs, output: outputOf('alias-inputs-pack') }, fake).filesVerified,
    result.filesVerified, 'canonical input alias must behave like the physical source');
  assert.throws(() => prepareMacosRuntime({ ...inputs, output: path.join(parentLink, 'new') }, fake),
    /symlink aliases/);
  assert.throws(() => prepareMacosRuntime({ ...inputs, output: path.join(inputs.ghidra, 'new') }, fake),
    /overlaps --ghidra/);
  assert.throws(() => prepareMacosRuntime({ ...inputs, python: inputs.ghidra, output: outputOf('overlap') }, fake),
    /overlaps/);
  pass('absolute, relative escaping, broken links, symlinked parents and overlapping trees fail closed');

  const cli = options => spawnSync(process.execPath, [script, ...options], { encoding: 'utf8', env: { ...process.env, PATH: '' } });
  const missing = cli(['--ghidra', inputs.ghidra, '--python', inputs.python, '--jdk', inputs.jdk]);
  assert.equal(missing.status, 1); assert.match(missing.stderr, /--output|Usage/);
  const badOption = cli(['--ghidra', inputs.ghidra, '--python', inputs.python,
    '--jdk', inputs.jdk, '--output', output]);
  assert.equal(badOption.status, 1); assert.match(badOption.stderr, /NEW directory|overwrite/);
  assert.ok(fs.existsSync(result.inventory));
  pass('CLI requires explicit new output and cannot overwrite successful bundle');
} finally {
  const current = fs.lstatSync(scratch);
  if (current.isDirectory() && current.dev === owner.dev && current.ino === owner.ino
      && fs.realpathSync(scratch).startsWith(fs.realpathSync(os.tmpdir()) + path.sep)) fs.rmSync(scratch, { recursive: true });
}
