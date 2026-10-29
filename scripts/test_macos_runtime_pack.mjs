// Synthetic Mach-O fixtures check runtime admission only; no native binary is executed.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { hostPlatform } from '../source/host_platform.js';

const source = fileURLToPath(new URL('..', import.meta.url));
const scratch = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-macos-pack-'));
const relocated = path.join(scratch, '中文 macOS 插件');
const bundledRoot = path.join(relocated, 'runtimes/darwin-arm64');
const bundledPack = path.join(bundledRoot, 'ghidra');
const externalPack = path.join(scratch, '显式 外部 Ghidra');
const pass = label => console.log('PASS', label);
const raw = {
  schemaVersion: 1, engine: 'ghidra', platform: 'darwin-arm64', version: '12.1.4',
  pythonVersion: '3.12', pythonExe: 'python/bin/python3',
  pythonLibrary: 'python/lib/libpython3.12.dylib', pythonStdlib: 'python/lib/python3.12',
  pythonModules: 'python/lib/python3.12/site-packages',
  jpypeLibrary: 'python/lib/python3.12/site-packages/_jpype.cpython-312-darwin.so',
  javaHome: 'jdk/Contents/Home', ghidraHome: 'ghidra',
};
const decompile = 'ghidra/Ghidra/Features/Decompiler/os/mac_arm_64/decompile';
const sleigh = 'ghidra/Ghidra/Features/Decompiler/os/mac_arm_64/sleigh';
function write(file, body = 'structural fixture\n', executable = false) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, body);
  if (executable) fs.chmodSync(file, 0o755);
}
function machO({ cpu = 0x0100000c, filetype = 2, magic = 0xfeedfacf } = {}) {
  const header = Buffer.alloc(512);
  header.writeUInt32LE(magic, 0); header.writeUInt32LE(cpu, 4);
  header.writeUInt32LE(0, 8); header.writeUInt32LE(filetype, 12);
  return header;
}
function fixture(pack) {
  write(path.join(pack, 'runtime.json'), JSON.stringify(raw));
  for (const relative of [raw.pythonExe, 'jdk/Contents/Home/bin/java', decompile, sleigh])
    write(path.join(pack, relative), machO(), true);
  for (const relative of [raw.pythonLibrary, 'jdk/Contents/Home/lib/server/libjvm.dylib',
    'jdk/Contents/Home/lib/libjli.dylib']) write(path.join(pack, relative), machO({ filetype: 6 }));
  write(path.join(pack, raw.jpypeLibrary), machO({ filetype: 8 }));
  for (const relative of ['os.py', 'site.py', 'encodings/__init__.py'])
    write(path.join(pack, raw.pythonStdlib, relative));
  for (const relative of ['pyghidra/__init__.py', 'pyghidra/launcher.py', 'jpype/__init__.py',
    'packaging/__init__.py', 'org.jpype.jar']) write(path.join(pack, raw.pythonModules, relative));
  for (const relative of ['jdk/Contents/Home/lib/modules', 'jdk/Contents/Home/jmods/java.base.jmod',
    'jdk/Contents/Home/legal/LICENSE', 'python/LICENSE.txt', 'ghidra/LICENSE', 'ghidra/bom.json',
    'ghidra/licenses/LICENSE', 'ghidra/Ghidra/Framework/Utility/lib/Utility.jar',
    'ghidra/Ghidra/Features/Base/lib/Base.jar', 'ghidra/Ghidra/Features/PyGhidra/lib/PyGhidra.jar',
    'ghidra/Ghidra/Processors/x86/data/languages/x86-64.sla']) write(path.join(pack, relative));
  write(path.join(pack, 'jdk/Contents/Home/release'), 'JAVA_VERSION="21.0.12.1"\nOS_ARCH="aarch64"\nOS_NAME="Darwin"\n');
  write(path.join(pack, 'ghidra/Ghidra/application.properties'), 'application.version=12.1.4\napplication.java.min=21\n');
}
function inventory() {
  const files = [];
  function visit(directory) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const file = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(file);
      else if (entry.isFile() && file !== path.join(bundledRoot, 'manifest.json')) {
        const bytes = fs.readFileSync(file);
        files.push({ path: path.relative(bundledRoot, file).replaceAll('\\', '/'), bytes: bytes.length,
          sha256: createHash('sha256').update(bytes).digest('hex') });
      }
    }
  }
  visit(bundledRoot);
  write(path.join(bundledRoot, 'manifest.json'), JSON.stringify({ schemaVersion: 1,
    pluginVersion: '1.0.0', platform: 'darwin-arm64', engines: ['ghidra'], files }));
}
function replaceFile(file, bytes, check) {
  const saved = fs.readFileSync(file);
  try { write(file, bytes); check(); }
  finally { write(file, saved); }
}
function withoutFile(file, check) {
  const saved = file + '.saved';
  fs.renameSync(file, saved);
  try { check(); }
  finally { fs.renameSync(saved, file); }
}

fixture(bundledPack); fixture(externalPack); inventory();
write(path.join(relocated, 'package.json'), '{"type":"module"}');
write(path.join(relocated, 'engine_runtime.js'), fs.readFileSync(path.join(source, 'engine_runtime.js')));
write(path.join(relocated, 'source/host_platform.js'), fs.readFileSync(path.join(source, 'source/host_platform.js')));
const moved = await import(pathToFileURL(path.join(relocated, 'engine_runtime.js')).href);
const host = hostPlatform({ platform: 'darwin', arch: 'arm64', env: {} });
const envKeys = ['IG5_RUNTIME_ROOT', 'IG5_GHIDRA_RUNTIME', 'IG5_X64DBG_RUNTIME', 'IG5_HOME'];
const previous = Object.fromEntries(envKeys.map(key => [key, process.env[key]]));
for (const key of envKeys) delete process.env[key];
const bundled = () => moved.runtimeConfiguration({ home: path.join(scratch, '空 HOME') }, { host });
const external = () => moved.runtimeConfiguration({ runtimeRoot: path.join(scratch, '不存在的 root'),
  ghidraRuntime: externalPack }, { host });
function unavailable(configuration, expected, label) {
  assert.equal(configuration.ghidra.available, false, `${label}: ${configuration.ghidra.reason}`);
  assert.match(configuration.ghidra.reason, expected, label);
  assert.equal(configuration.x64dbg.available, false, 'x64dbg is Windows-only');
}
try {
  assert.equal(host.id, 'darwin-arm64'); assert.equal(host.supported, true);
  const local = bundled();
  assert.equal(local.runtimeRoot, bundledRoot);
  assert.equal(local.ghidra.available, true, local.ghidra.reason);
  assert.equal(local.ghidra.root, bundledPack);
  assert.equal(local.ghidra.source, 'bundled');
  assert.equal(local.ghidra.validation, 'structure-and-mach-o-headers');
  assert.equal(local.ghidra.integrityVerified, false, 'startup is structural, not an inventory hash audit');
  assert.equal(local.x64dbg.available, false);
  assert.match(local.x64dbg.reason, /requires a Windows/);
  pass('relocated Chinese-path Darwin bundle accepts complete Python/JDK/Ghidra and inventory');

  const override = external();
  assert.equal(override.ghidra.available, true, override.ghidra.reason);
  assert.equal(override.ghidra.source, 'config'); assert.equal(override.ghidra.root, externalPack);
  assert.equal(override.ghidra.validation, 'structure-and-mach-o-headers');
  unavailable(moved.runtimeConfiguration({ runtimeRoot: path.join(scratch, '不存在的 root') }, { host }),
    /Configured .* runtime\.json is missing/, 'missing explicit root');
  const linux = hostPlatform({ platform: 'linux', arch: 'arm64', env: {}, glibcVersion: '2.35' });
  unavailable(moved.runtimeConfiguration({ ghidraRuntime: externalPack }, { host: linux }),
    /darwin-arm64.*linux-arm64/, 'cross-platform override');
  pass('standalone external override works; missing root and cross-platform pack never fall back');

  const native = relative => path.join(externalPack, relative);
  replaceFile(native(raw.pythonExe), machO({ cpu: 0x01000007 }), () =>
    unavailable(external(), /pythonExe.*(?:Mach-O|arm64|ARM64|architecture)/i, 'x86_64 Python'));
  const fat = Buffer.alloc(512); fat.writeUInt32BE(0xcafebabe, 0); fat.writeUInt32BE(1, 4);
  replaceFile(native(raw.pythonLibrary), fat, () =>
    unavailable(external(), /Python shared library.*(?:Mach-O|FAT|fat|universal)/i, 'FAT Python'));
  replaceFile(native('jdk/Contents/Home/lib/server/libjvm.dylib'), machO({ magic: 0xfeedface }), () =>
    unavailable(external(), /JDK JVM.*(?:Mach-O|64)/i, '32-bit JVM'));
  replaceFile(native(decompile), machO({ filetype: 1 }), () =>
    unavailable(external(), /native decompiler.*(?:Mach-O|filetype|file type)/i, 'non-executable decompiler'));
  pass('Mach-O headers reject x86_64, FAT/universal, 32-bit and invalid native file types');

  const runtimeJson = native('runtime.json');
  replaceFile(runtimeJson, JSON.stringify({ ...raw, pythonVersion: '3.11' }), () =>
    unavailable(external(), /Python.*(?:ABI|3\.12)/i, 'unsupported Python ABI'));
  const staleJpype = 'python/lib/python3.12/site-packages/_jpype.cpython-311-darwin.so';
  write(native(staleJpype), machO({ filetype: 8 }));
  replaceFile(runtimeJson, JSON.stringify({ ...raw, jpypeLibrary: staleJpype }), () =>
    unavailable(external(), /JPype.*(?:ABI|3\.12|cpython-312)/i, 'incompatible JPype ABI'));
  replaceFile(native('jdk/Contents/Home/release'), 'JAVA_VERSION="21.0.12.1"\nOS_ARCH="x86_64"\nOS_NAME="Darwin"\n', () =>
    unavailable(external(), /JDK.*(?:architecture|incompatible)/i, 'x86_64 JDK'));
  pass('Python 3.12, CPython JPype suffix and ARM64 JDK metadata are enforced');

  for (const [relative, label] of [[decompile, /native decompiler/i], [sleigh, /sleigh/i]]) {
    withoutFile(native(relative), () => unavailable(external(), label, `missing ${relative}`));
  }
  pass('both native Ghidra decompile and sleigh executables are required');

  replaceFile(runtimeJson, JSON.stringify({ ...raw, pythonModules: '../../outside' }), () =>
    unavailable(external(), /contained relative path/, 'manifest traversal'));
  const linked = native(raw.pythonLibrary), outside = path.join(scratch, 'outside.dylib');
  write(outside, machO({ filetype: 6 }));
  withoutFile(linked, () => {
    fs.symlinkSync(outside, linked);
    try { unavailable(external(), /Python shared library.*(?:link|escapes)/i, 'escaping native symlink'); }
    finally { fs.unlinkSync(linked); }
  });
  const inventoryJson = path.join(bundledRoot, 'manifest.json');
  const validInventory = JSON.parse(fs.readFileSync(inventoryJson, 'utf8'));
  replaceFile(inventoryJson, JSON.stringify({ ...validInventory, files: [...validInventory.files,
    { path: '../escape', bytes: 1, sha256: '0'.repeat(64) }] }), () =>
    unavailable(bundled(), /inventory|file entry|relative|escape/i, 'inventory traversal'));
  replaceFile(inventoryJson, JSON.stringify({ ...validInventory, platform: 'linux-arm64' }), () =>
    unavailable(bundled(), /inventory/i, 'wrong bundled platform'));
  replaceFile(inventoryJson, JSON.stringify({ ...validInventory, files: validInventory.files.filter(entry =>
    entry.path !== `ghidra/${sleigh}`) }), () =>
    unavailable(bundled(), /sleigh.*inventory/i, 'unlisted required sleigh'));
  withoutFile(bundledPack, () => {
    fs.symlinkSync(externalPack, bundledPack, 'dir');
    try { unavailable(bundled(), /Bundled runtime directory escapes the plugin/i, 'linked bundled pack'); }
    finally { fs.unlinkSync(bundledPack); }
  });
  pass('manifest/inventory traversal, missing inventory entries and symlink escapes are rejected');

  const read = fs.readFileSync;
  fs.readFileSync = function(file, ...args) {
    assert.doesNotMatch(String(file), /(?:\.dylib|\.so|\.jar|\.jmod|\.sla|[/\\](?:java|python3|decompile|sleigh|modules))$/i,
      'admission must read only bounded native headers, never whole binaries');
    return read.call(this, file, ...args);
  };
  try { assert.equal(bundled().ghidra.available, true); assert.equal(external().ghidra.available, true); }
  finally { fs.readFileSync = read; }
  pass('startup validation is bounded to structural metadata and Mach-O headers');
  console.log('macOS ARM64 runtime pack structural tests passed; no native binary executed. Artifacts:', scratch);
} finally {
  for (const key of envKeys) previous[key] === undefined ? delete process.env[key] : process.env[key] = previous[key];
}
