// 语法检查（npm run ci 的第一步）：所有项目 JS/MJS/CJS 文件做 node --check；
// 设置环境变量 IG5_PYTHON 指向宿主使用的 Python 时，同时检查所有 .py 文件能否解析（不写 .pyc）。
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readdirSync, statSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SKIP = new Set(['node_modules', 'runtimes', 'third_party', '.downloads', 'scratch', '.git', '__pycache__', 'labs']);

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name)) continue;
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) yield* walk(full);
    else yield full;
  }
}

const files = [...walk(root)];
const js = files.filter((f) => /\.(m?js|cjs)$/.test(f));
const py = files.filter((f) => f.endsWith('.py'));
const bad = [];
for (const f of js) {
  const r = spawnSync(process.execPath, ['--check', f], { encoding: 'utf8', windowsHide: true });
  if (r.status !== 0) bad.push({ file: relative(root, f), error: (r.stderr || '').split(/\r?\n/).slice(0, 4).join(' | ') });
}
console.log(`JS 语法：检查 ${js.length} 个，失败 ${bad.length}`);

let pyBad = [];
const python = process.env.IG5_PYTHON;
if (python && py.length) {
  const tmp = mkdtempSync(join(tmpdir(), 'ig5-syntax-'));
  const list = join(tmp, 'files.txt');
  const checker = join(tmp, 'check.py');
  writeFileSync(list, py.join('\n'), 'utf8');
  writeFileSync(checker, [
    'import ast, json, sys',
    'bad = []',
    "for p in open(sys.argv[1], encoding='utf-8').read().splitlines():",
    '    try:',
    "        ast.parse(open(p, 'rb').read(), p)",
    '    except Exception as e:',
    '        bad.append({"file": p, "error": str(e)[:200]})',
    'print(json.dumps(bad, ensure_ascii=False))',
  ].join('\n'), 'utf8');
  const r = spawnSync(python, ['-I', checker, list], { encoding: 'utf8', windowsHide: true });
  rmSync(tmp, { recursive: true, force: true });
  if (r.status !== 0) { console.log(`Python：无法运行 ${python}：${(r.stderr || r.error || '').toString().slice(0, 200)}`); pyBad = [{ file: '(python)', error: 'cannot run' }]; }
  else { pyBad = JSON.parse(r.stdout || '[]'); console.log(`Python 语法：检查 ${py.length} 个，失败 ${pyBad.length}`); }
} else {
  console.log(`Python 语法：跳过（未设置 IG5_PYTHON），共 ${py.length} 个 .py 文件未检查`);
}

for (const b of [...bad, ...pyBad]) console.log(`  FAIL ${b.file}: ${b.error}`);
process.exit(bad.length + pyBad.length === 0 ? 0 : 1);
