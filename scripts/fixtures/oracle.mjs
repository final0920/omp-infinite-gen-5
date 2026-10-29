// Independent reference implementations shipped with the bundled Ghidra, used only by tests:
//   AXMLPrinter2  - decodes Android binary XML to text (UTF-16 string pools only; it crashes on UTF-8 pools)
//   dexlib2       - the smali project's DEX reader, driven by a tiny Java program compiled here with the bundled JDK
// Nothing here is part of the product. When the JDK or the jars are missing the helpers return null so a test can skip loudly.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..', '..');
const ghidraRoot = path.join(root, 'runtimes', 'ghidra');
const exe = name => (process.platform === 'win32' ? `${name}.exe` : name);

function locate() {
  if (!fs.existsSync(ghidraRoot)) return null;
  const jdk = fs.readdirSync(ghidraRoot).find(name => name.startsWith('jdk')), ghidra = fs.readdirSync(ghidraRoot).find(name => /^ghidra_.*PUBLIC$/.test(name));
  if (!jdk || !ghidra) return null;
  const lib = path.join(ghidraRoot, ghidra, 'Ghidra', 'Features', 'FileFormats', 'lib');
  const guava = path.join(ghidraRoot, ghidra, 'Ghidra', 'Framework', 'Generic', 'lib', 'guava-32.1.3-jre.jar');
  const found = { java: path.join(ghidraRoot, jdk, 'bin', exe('java')), javac: path.join(ghidraRoot, jdk, 'bin', exe('javac')),
    axml: path.join(lib, 'AXMLPrinter2.jar'), classpath: ['dexlib2-2.5.2.jar', 'util-2.5.2.jar'].map(name => path.join(lib, name)).concat(guava) };
  return [found.java, found.javac, found.axml, ...found.classpath].every(file => fs.existsSync(file)) ? found : null;
}
export const tools = locate();
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-oracle-'));
process.on('exit', () => fs.rmSync(scratch, { recursive: true, force: true }));
let counter = 0;
const temp = (suffix, bytes) => { const file = path.join(scratch, `${++counter}${suffix}`); if (bytes) fs.writeFileSync(file, bytes); return file; };

/** AXMLPrinter2 text for a UTF-16-pool binary XML, or throws with its stderr. */
export function axmlToText(bytes) {
  // The JVM would otherwise print with the platform code page (GBK on a Chinese Windows) and garble non-ASCII text.
  const run = spawnSync(tools.java, ['-Dfile.encoding=UTF-8', '-Dstdout.encoding=UTF-8', '-jar', tools.axml, temp('.axml', bytes)], { encoding: 'utf8', timeout: 30000 });
  if (run.status !== 0 || /Exception/.test(run.stderr || '')) throw new Error('AXMLPrinter2 failed: ' + (run.stderr || '').split('\n')[0]);
  return run.stdout;
}

/** Elements as [depth, tag, [[attribute, value], ...]] parsed from AXMLPrinter2's one-attribute-per-line output. */
export function parsePrinted(text) {
  const rows = [];
  let depth = -1, current = null;
  for (const line of text.split(/\r?\n/)) {
    const open = /^\t*<([^\s/?>][^\s>]*)$/.exec(line), attr = /^\t+([^\s=<>]+)="(.*)"$/.exec(line);
    if (open) { depth++; current = [depth, open[1], []]; rows.push(current); }
    else if (attr && current) { if (!attr[1].startsWith('xmlns')) current[2].push([attr[1], attr[2]]); }   // namespace declarations are not attributes
    else if (/^\t*<\/[^>]+>$/.test(line)) depth--;
    else if (/^\t*>$/.test(line)) current = null;
  }
  return rows;
}

let compiled = null;
/** Compile (once) and run the dexlib2 dump program; returns its stdout lines. */
export function dexDump(bytes, compileOnly = false) {
  if (!compiled) {
    const source = temp('-src', null), out = path.join(scratch, 'classes');
    fs.mkdirSync(source); fs.mkdirSync(out);
    fs.copyFileSync(path.join(import.meta.dirname, 'oracle', 'DexDump.java'), path.join(source, 'DexDump.java'));
    const separator = path.delimiter, build = spawnSync(tools.javac, ['-cp', tools.classpath.join(separator), '-d', out, path.join(source, 'DexDump.java')], { encoding: 'utf8', timeout: 120000 });
    if (build.status !== 0) throw new Error('javac failed: ' + (build.stderr || '').slice(0, 400));
    compiled = out;
  }
  if (compileOnly) return [];
  const run = spawnSync(tools.java, ['-cp', [compiled, ...tools.classpath].join(path.delimiter), 'DexDump', temp('.dex', bytes)], { encoding: 'utf8', timeout: 300000, maxBuffer: 2 * 1024 ** 3 });      // a large real DEX prints a million lines
  if (run.status !== 0) throw new Error('dexlib2 rejected the file: ' + (run.stderr || '').split('\n').slice(0, 2).join(' | '));
  return run.stdout.split(/\r?\n/).filter(Boolean);
}

let opcodes = null;
/** Every opcode dexlib2 defines, as Map(value -> { name, units }); units is the reference instruction width in 16-bit code units (variable-length payloads report their fixed header size). */
export function opcodeTable() {
  if (!opcodes) {
    dexDump(Buffer.alloc(0x70), true);     // makes sure the program is compiled
    const run = spawnSync(tools.java, ['-cp', [compiled, ...tools.classpath].join(path.delimiter), 'DexDump', '--opcodes'], { encoding: 'utf8', timeout: 60000 });
    if (run.status !== 0) throw new Error('opcode listing failed: ' + (run.stderr || '').slice(0, 200));
    opcodes = new Map(run.stdout.split(/\r?\n/).filter(Boolean).map(line => { const [, value, name, units] = line.split(' '); return [Number(value), { name, units: Number(units) / 2 }]; }));      // Format.size is in bytes
  }
  return opcodes;
}

const hex16 = text => Buffer.from(text, 'utf16le').swap16().toString('hex');
/** The same line format DexDump.java prints, produced from our own reader (compare with dexDump()). */
export function dexLines(dex) {
  const out = [];
  for (const c of dex.classDefs()) {
    out.push(`CLASS ${c.type} ${c.access} ${c.superclass}`);
    for (const m of dex.methodsOf(c)) {
      out.push(`METHOD ${m.ref.text} ${m.access} ${m.codeOffset !== 0}`);
      if (!m.codeOffset) continue;
      for (const s of dex.scanCode(m.codeOffset, { trace: true }).sequence) {
        out.push(`OP ${s.op} ${s.units}`);
        if (!s.reference) continue;
        const [kind, index] = s.reference;
        out.push(kind === 'invoke' ? `INVOKE ${dex.methodRef(index).text}` : kind === 'string' ? `STRING ${hex16(dex.string(index))}` : kind === 'field' ? `FIELD ${dex.fieldRef(index).text}` : `TYPE ${dex.type(index)}`);
      }
    }
  }
  return out;
}
