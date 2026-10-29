#!/usr/bin/env node
// Assemble an offline macOS ARM64 Ghidra pack from three EXPLICIT, provisioned trees.
// No installer, downloader, global Python, PATH change, or input-tree write is involved.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { hostPlatform } from '../source/host_platform.js';
import { readRuntime } from '../engine_runtime.js';

const host = hostPlatform({ platform: 'darwin', arch: 'arm64', env: {} });
const here = path.dirname(fileURLToPath(import.meta.url));
const version = JSON.parse(fs.readFileSync(path.join(here, '..', 'package.json'), 'utf8')).version;
const nativeDirectory = 'Ghidra/Features/Decompiler/os/mac_arm_64';
const buildDirectory = 'Ghidra/Features/Decompiler/build/os/mac_arm_64';
const jpypeName = '_jpype.cpython-312-darwin.so';
const inside = (root, candidate) => candidate === root || (!path.relative(root, candidate).startsWith('..' + path.sep)
  && path.relative(root, candidate) !== '..' && !path.isAbsolute(path.relative(root, candidate)));
const exists = file => { try { fs.lstatSync(file); return true; } catch (error) { if (error.code === 'ENOENT') return false; throw error; } };

function directory(value, label) {
  if (typeof value !== 'string' || !value) throw new Error(`Explicit --${label} directory is required`);
  const resolved = path.resolve(value);
  if (!fs.statSync(resolved).isDirectory()) throw new Error(`--${label} is not a directory: ${resolved}`);
  // Canonicalize explicit input aliases (macOS /tmp -> /private/tmp is common)
  // BEFORE comparing roots or checking each contained symlink's physical target.
  return fs.realpathSync(resolved);
}

function requireFile(file, label) {
  if (!fs.statSync(file).isFile() || fs.statSync(file).size === 0) throw new Error(`${label} is missing or empty: ${file}`);
}

function validateLink(root, link) {
  const text = fs.readlinkSync(link);
  if (path.isAbsolute(text)) throw new Error(`Absolute symlink cannot be relocated: ${link} -> ${text}`);
  const logical = path.resolve(path.dirname(link), text);
  if (!inside(root, logical)) throw new Error(`Symlink escapes its copied tree: ${link} -> ${text}`);
  let physical;
  try { physical = fs.realpathSync(link); }
  catch (error) { throw new Error(`Broken or cyclic symlink: ${link} -> ${text}: ${error.message}`); }
  if (!inside(root, physical)) throw new Error(`Symlink escapes its copied tree: ${link} -> ${text}`);
  const stat = fs.statSync(link);
  if (!stat.isFile() && !stat.isDirectory()) throw new Error(`Unsupported symlink target: ${link}`);
  return { text, stat };
}

// Do not recurse into links (including directory links); each link must resolve
// within its OWN input tree, not merely somewhere in the eventual bundle.
function walk(root, visit) {
  function descend(dir) {
    for (const name of fs.readdirSync(dir).sort()) {
      const file = path.join(dir, name), stat = fs.lstatSync(file);
      if (stat.isSymbolicLink()) visit(file, stat, validateLink(root, file));
      else if (stat.isDirectory()) { visit(file, stat); descend(file); }
      else if (stat.isFile()) visit(file, stat);
      else throw new Error(`Unsupported special file in runtime tree: ${file}`);
    }
  }
  descend(root);
}

function copyTree(input, destination) {
  fs.mkdirSync(destination, { recursive: true });
  walk(input, (source, stat, link) => {
    const target = path.join(destination, path.relative(input, source));
    if (link) fs.symlinkSync(link.text, target);
    else if (stat.isDirectory()) fs.mkdirSync(target);
    else {
      fs.copyFileSync(source, target, fs.constants.COPYFILE_EXCL);
      fs.chmodSync(target, stat.mode & 0o777);
    }
  });
}

function sha256(file) {
  const hash = createHash('sha256'), buffer = Buffer.allocUnsafe(1024 * 1024);
  const fd = fs.openSync(file, 'r');
  try {
    let read;
    while ((read = fs.readSync(fd, buffer, 0, buffer.length, null)) > 0) hash.update(buffer.subarray(0, read));
  } finally { fs.closeSync(fd); }
  return hash.digest('hex');
}

function inventory(stage) {
  const files = [], links = [];
  walk(stage, (file, stat, link) => {
    const name = path.relative(stage, file).split(path.sep).join('/');
    if (name === 'manifest.json') return;
    if (link) {
      links.push({ path: name, target: link.text });
      if (!link.stat.isFile()) return;
    } else if (!stat.isFile()) return;
    const size = fs.statSync(file).size;
    files.push({ path: name, bytes: size, sha256: sha256(file) });
  });
  return { files, links };
}

function checkTreeBoundaries(stage) {
  for (const part of ['ghidra', 'python', 'jdk/Contents/Home']) {
    walk(path.join(stage, 'ghidra', part), () => {});
  }
}

function promoteNatives(ghidra) {
  const canonical = path.join(ghidra, nativeDirectory);
  const alternate = path.join(ghidra, buildDirectory);
  const names = ['decompile', 'sleigh'];
  if (names.every(name => exists(path.join(canonical, name)))) return;
  if (names.some(name => exists(path.join(canonical, name)))) throw new Error('Incomplete native os/mac_arm_64 directory; refusing to mix native builds');
  for (const name of names) requireFile(path.join(alternate, name), `Ghidra build/os/mac_arm_64/${name}`);
  fs.mkdirSync(canonical, { recursive: true });
  for (const name of names) {
    const input = path.join(alternate, name), output = path.join(canonical, name);
    fs.copyFileSync(input, output, fs.constants.COPYFILE_EXCL);
    fs.chmodSync(output, fs.statSync(input).mode & 0o777);
  }
}

function ensurePythonLicense(stage) {
  const python = path.join(stage, 'ghidra/python');
  const rootLicense = path.join(python, 'LICENSE.txt');
  if (exists(rootLicense)) return;
  // python-build-standalone keeps this license in the standard-library tree;
  // the existing runtime loader expects a copy at the Python prefix root.
  const standardLicense = path.join(python, 'lib/python3.12/LICENSE.txt');
  requireFile(standardLicense, 'Python 3.12 license (prefix or standard library)');
  fs.copyFileSync(standardLicense, rootLicense, fs.constants.COPYFILE_EXCL);
  fs.chmodSync(rootLicense, fs.statSync(standardLicense).mode & 0o777);
}

function checkLicenses(stage) {
  const gh = path.join(stage, 'ghidra');
  for (const [name, label] of [
    ['ghidra/ghidra/LICENSE', 'Ghidra license'], ['ghidra/ghidra/bom.json', 'Ghidra component inventory'],
    ['ghidra/python/LICENSE.txt', 'Python license'], ['ghidra/jdk/Contents/Home/release', 'JDK release'],
  ]) requireFile(path.join(stage, name), label);
  const release = fs.readFileSync(path.join(gh, 'jdk/Contents/Home/release'), 'utf8');
  if (!/^JAVA_VERSION="21(?:\.[^"\r\n]*)?"$/m.test(release)) throw new Error('Expected explicitly supplied JDK 21 HOME');
  for (const [name, label] of [['ghidra/licenses', 'Ghidra third-party licenses'],
    ['jdk/Contents/Home/legal', 'JDK licenses']]) {
    const dir = path.join(gh, name);
    if (!fs.statSync(dir).isDirectory() || !fs.readdirSync(dir).length) throw new Error(`${label} directory is missing or empty: ${dir}`);
  }
}

function run(command, args, env, label) {
  const result = spawnSync(command, args, { cwd: path.dirname(command), env, encoding: 'utf8', timeout: 60000,
    maxBuffer: 1024 * 1024, windowsHide: true });
  if (result.error || result.status !== 0) {
    throw new Error(`${label} failed: ${result.error?.message || `exit ${result.status}; ${String(result.stderr || result.stdout).trim().slice(0, 600)}`}`);
  }
}

function verifyDependencies({ stage }) {
  if (process.platform !== 'darwin' || process.arch !== 'arm64') {
    throw new Error('Native dependency verification requires a darwin-arm64 host (fixtures may inject a test-only verifier)');
  }
  const base = path.join(stage, 'ghidra');
  const python = path.join(base, 'python');
  const java = path.join(base, 'jdk/Contents/Home');
  const site = path.join(python, 'lib/python3.12/site-packages');
  const jvm = path.join(java, 'lib/server/libjvm.dylib');
  const jar = path.join(site, 'org.jpype.jar');
  const probeHome = fs.mkdtempSync(path.join(stage, '.dependency-probe-'));
  const owner = fs.statSync(probeHome);
  try {
    const environment = { ...process.env, PATH: '', PYTHONPATH: '', PYTHONHOME: '', PYTHONNOUSERSITE: '1',
      PYTHONDONTWRITEBYTECODE: '1', JAVA_HOME: java, HOME: probeHome, TMPDIR: probeHome,
      XDG_CACHE_HOME: probeHome, XDG_CONFIG_HOME: probeHome,
      JAVA_TOOL_OPTIONS: '', _JAVA_OPTIONS: '', JDK_JAVA_OPTIONS: '', DYLD_LIBRARY_PATH: '', DYLD_INSERT_LIBRARIES: '' };
    run(path.join(java, 'bin/java'), [`-Duser.home=${probeHome}`, '-version'], environment, 'Bundled JDK 21');
    // -I ignores user/site environment, -B prevents bytecode writes. Explicit
    // paths and source checks prevent a successful import from borrowing a global
    // Python/JVM or wheel. This is an isolated dependency probe, not a full doctor.
    const probe = `import os,sys,pyghidra,jpype,packaging\n` +
      `root,site,jvm,jar,home=sys.argv[1:]\n` +
      `assert sys.version_info[:2]==(3,12) and os.path.realpath(sys.prefix)==os.path.realpath(root)\n` +
      `assert all(os.path.commonpath((os.path.realpath(m.__file__),os.path.realpath(site)))==os.path.realpath(site) for m in (pyghidra,jpype,packaging))\n` +
      `jpype.startJVM(jvm, '-Duser.home='+home, classpath=[jar], convertStrings=False)\n` +
      `assert jpype.JClass('org.jpype.JPypeContext') is not None\n`;
    run(path.join(python, 'bin/python3.12'), ['-I', '-B', '-c', probe, python, site, jvm, jar, probeHome], environment,
      'Isolated Python/PyGhidra/JPype/JDK probe');
  } finally {
    if (exists(probeHome)) {
      const now = fs.lstatSync(probeHome);
      if (now.isDirectory() && now.dev === owner.dev && now.ino === owner.ino) fs.rmSync(probeHome, { recursive: true });
    }
  }
}

/** Create a NEW output directory. verifyDependencies is injectable only by direct
 * module consumers constructing synthetic fixtures; no CLI bypass is provided. */
export function prepareMacosRuntime({ ghidra, python, jdk, output }, { verifyDependencies: verifier = verifyDependencies } = {}) {
  const source = { ghidra: directory(ghidra, 'ghidra'), python: directory(python, 'python'), jdk: directory(jdk, 'jdk') };
  if (typeof output !== 'string' || !output) throw new Error('Explicit --output directory is required; no default output or installation');
  const destination = path.resolve(output), parent = path.dirname(destination);
  if (destination === parent) throw new Error('--output must name a new directory, not a filesystem root');
  if (exists(destination)) throw new Error(`--output must be a NEW directory; refusing to overwrite: ${destination}`);
  if (!fs.statSync(parent).isDirectory() || fs.realpathSync(parent) !== parent) {
    throw new Error(`--output parent must be an existing physical directory without symlink aliases: ${parent}`);
  }
  for (const [label, input] of Object.entries(source)) {
    if (inside(input, destination) || inside(destination, input)) throw new Error(`--output overlaps --${label}: ${destination}`);
    for (const [other, peer] of Object.entries(source)) {
      if (label !== other && (inside(input, peer) || inside(peer, input))) throw new Error(`--${label} overlaps --${other}`);
    }
  }
  const site = path.join(source.python, 'lib/python3.12/site-packages');
  for (const [file, label] of [[path.join(source.python, 'bin/python3.12'), 'Python 3.12 executable'],
    [path.join(source.python, 'lib/libpython3.12.dylib'), 'Python 3.12 shared library'],
    [path.join(site, jpypeName), 'JPype arm64 extension'], [path.join(site, 'org.jpype.jar'), 'JPype jar'],
    [path.join(source.jdk, 'bin/java'), 'JDK executable'],
    [path.join(source.ghidra, 'Ghidra/application.properties'), 'Ghidra metadata']]) requireFile(file, label);
  // Preflight all links before making even a staging directory; repeat after
  // copying because roots may be changed by another process during assembly.
  for (const input of Object.values(source)) walk(input, () => {});
  const stage = fs.mkdtempSync(path.join(parent, `.${path.basename(destination)}.staging-`));
  const owned = fs.statSync(stage);
  try {
    const pack = path.join(stage, 'ghidra');
    copyTree(source.ghidra, path.join(pack, 'ghidra'));
    copyTree(source.python, path.join(pack, 'python'));
    copyTree(source.jdk, path.join(pack, 'jdk/Contents/Home'));
    promoteNatives(path.join(pack, 'ghidra'));
    checkTreeBoundaries(stage);
    ensurePythonLicense(stage);
    checkLicenses(stage);
    const manifest = {
      schemaVersion: 1, engine: 'ghidra', platform: 'darwin-arm64', version: '12.1.4', pythonVersion: '3.12',
      pythonExe: 'python/bin/python3.12', pythonLibrary: 'python/lib/libpython3.12.dylib',
      pythonStdlib: 'python/lib/python3.12', pythonModules: 'python/lib/python3.12/site-packages',
      jpypeLibrary: `python/lib/python3.12/site-packages/${jpypeName}`,
      javaHome: 'jdk/Contents/Home', ghidraHome: 'ghidra',
      licenses: ['ghidra/LICENSE', 'ghidra/bom.json', 'ghidra/licenses', 'jdk/Contents/Home/legal', 'python/LICENSE.txt'],
    };
    fs.writeFileSync(path.join(pack, 'runtime.json'), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx' });
    const admission = readRuntime(stage, 'ghidra', undefined, { host, source: 'config' });
    if (!admission.available) throw new Error(`Staged readRuntime(darwin-arm64) rejected pack: ${admission.reason}`);
    if (admission.integrityVerified !== false) throw new Error('Runtime loader must not claim full inventory integrity at startup');
    const content = inventory(stage);
    verifier({ stage, runtime: admission });
    checkTreeBoundaries(stage);
    if (JSON.stringify(inventory(stage)) !== JSON.stringify(content)) throw new Error('Dependency probe altered staged runtime contents');
    const bundle = { schemaVersion: 1, pluginVersion: version, platform: 'darwin-arm64', engines: ['ghidra'],
      files: content.files, links: content.links };
    fs.writeFileSync(path.join(stage, 'manifest.json'), JSON.stringify(bundle, null, 2) + '\n', { flag: 'wx' });
    checkTreeBoundaries(stage);
    if (JSON.stringify(inventory(stage)) !== JSON.stringify(content)) throw new Error('Staged file SHA-256/size/link inventory changed before commit');
    if (exists(destination)) throw new Error(`--output appeared during assembly; refusing overwrite: ${destination}`);
    fs.renameSync(stage, destination); // Atomic publication on the same output-parent filesystem.
    return { output: destination, filesVerified: content.files.length, linksVerified: content.links.length,
      runtime: path.join(destination, 'ghidra/runtime.json'), inventory: path.join(destination, 'manifest.json') };
  } finally {
    // Only clean up our own still-present stage, never a replaced directory.
    if (exists(stage)) {
      const current = fs.lstatSync(stage);
      if (current.isDirectory() && current.dev === owned.dev && current.ino === owned.ino) fs.rmSync(stage, { recursive: true });
    }
  }
}

function args(argv) {
  if (argv.length !== 8) throw new Error('Usage: node scripts/prepare_macos_runtime.mjs --ghidra <dir> --python <prefix> --jdk <home> --output <NEW directory>');
  const result = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i].replace(/^--/, '');
    if (!argv[i].startsWith('--') || !['ghidra', 'python', 'jdk', 'output'].includes(key) || key in result
        || !argv[i + 1] || argv[i + 1].startsWith('--')) throw new Error('Invalid or duplicate CLI option; --ghidra, --python, --jdk and --output are all required');
    result[key] = argv[i + 1];
  }
  if (Object.keys(result).length !== 4) throw new Error('All four explicit directory options are required');
  return result;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { console.log(JSON.stringify(prepareMacosRuntime(args(process.argv.slice(2))))); }
  catch (error) { console.error(`macOS runtime assembly failed: ${error.message}`); process.exitCode = 1; }
}
