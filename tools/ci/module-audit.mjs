// 模块分层与人工审查台账（npm run ci 的一部分）。
// 1) 每个 source/ 模块必须归属 module-map.json 里的某一层；2) 检查层间禁止依赖；
// 3) 计算"敏感根"的传递闭包（审批/执行/采集/存储相关代码），逐文件登记 SHA-256 与人工审查签字。
// 用法：node tools/ci/module-audit.mjs [--update] [--strict] [--sign <文件|all> --by <姓名>] [--report]
//   默认：校验分层与台账结构；台账里"未审查/已过期"只报告，不使审计失败。
//   --strict：存在未审查或过期的关键文件时以非 0 退出（发布前使用）。
//   --update：把闭包中新增文件加入台账、移除已不在闭包的文件（保留已有签字）。
//   --sign：为文件记录当前 SHA-256 作为"人工已审查"的版本，必须配 --by。仅在真人读过代码后使用。
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..', '..');
const map = JSON.parse(readFileSync(join(here, 'module-map.json'), 'utf8'));
const ledgerPath = join(root, 'docs', 'review', 'ledger.json');

const args = process.argv.slice(2);
const flag = (n) => args.includes(n);
const opt = (n) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };

const rel = (p) => relative(root, p).split(sep).join('/');
const files = [];
const walk = (d) => {
  for (const n of readdirSync(d)) {
    const p = join(d, n);
    if (statSync(p).isDirectory()) walk(p); else if (/\.m?js$/.test(n)) files.push(rel(p));
  }
};
walk(join(root, 'source'));
for (const n of readdirSync(root)) if (/\.js$/.test(n) && statSync(join(root, n)).isFile()) files.push(n);

const layers = map.layers.map((l) => ({ ...l, re: new RegExp(l.pattern) }));
const layerOf = (f) => layers.find((l) => l.re.test(f))?.name;
const sha = (f) => createHash('sha256').update(readFileSync(join(root, f))).digest('hex');

const present = new Set(files);
const graph = new Map();
const importRe = /(?:from|import\()\s*['"](\.[^'"]+)['"]/g;
for (const f of files) {
  const deps = new Set();
  for (const m of readFileSync(join(root, f), 'utf8').matchAll(importRe)) {
    let t = rel(resolve(root, dirname(f), m[1]));
    if (!present.has(t) && present.has(`${t}.js`)) t += '.js';
    if (present.has(t)) deps.add(t);
  }
  graph.set(f, [...deps]);
}

let failed = false;
const fail = (msg) => { failed = true; console.log(`FAIL  ${msg}`); };

// 1) 分类
const unclassified = files.filter((f) => !layerOf(f));
if (unclassified.length) fail(`${unclassified.length} 个模块未归属任何层（请在 tools/ci/module-map.json 登记）：${unclassified.slice(0, 8).join(', ')}`);
const byLayer = {};
for (const f of files) { const l = layerOf(f); if (l) byLayer[l] = (byLayer[l] || 0) + 1; }
console.log(`模块 ${files.length} 个：${Object.entries(byLayer).map(([k, v]) => `${k} ${v}`).join('，')}`);

// 2) 层间依赖
const forbid = new Set(map.layerRules.forbid.map(([a, b]) => `${a}>${b}`));
const violations = [];
for (const [f, deps] of graph) for (const d of deps) if (forbid.has(`${layerOf(f)}>${layerOf(d)}`)) violations.push(`${f} (${layerOf(f)}) -> ${d} (${layerOf(d)})`);
if (violations.length) { fail(`${violations.length} 条违反分层规则的依赖`); violations.slice(0, 15).forEach((v) => console.log(`        ${v}`)); }
else console.log('层间依赖：无违规');

// 3) 敏感闭包与台账
const roots = files.filter((f) => new RegExp(map.sensitiveRoots).test(f));
const closure = new Set();
const visit = (n) => { if (closure.has(n)) return; closure.add(n); (graph.get(n) || []).forEach(visit); };
roots.forEach(visit);
for (const f of map.sensitiveFiles || []) {
  if (!existsSync(join(root, f))) fail(`sensitiveFiles 中的文件不存在：${f}`);
  else closure.add(f);
}
const closureList = [...closure].sort();

const ledger = existsSync(ledgerPath) ? JSON.parse(readFileSync(ledgerPath, 'utf8')) : { note: '', entries: [] };
const entryOf = new Map(ledger.entries.map((e) => [e.file, e]));
const save = () => { mkdirSync(dirname(ledgerPath), { recursive: true }); writeFileSync(ledgerPath, `${JSON.stringify(ledger, null, 2)}\n`, 'utf8'); };
ledger.note = '安全关键代码审查台账。reviewedSha256 与当前 sha256 一致才算"有效审查"；文件变更后自动变为"已过期"。真人亲审与用户明确授权的代理复审必须分别标注；代理复审须记录实际执行者、授权来源、范围和证据，不得冒称真人亲审。未经用户明确授权不得代签。';

if (flag('--update')) {
  ledger.entries = closureList.map((f) => entryOf.get(f) || { file: f, reviewedBy: null, reviewedAt: null, reviewedSha256: null });
  save();
  console.log(`台账已更新：${ledger.entries.length} 项`);
}
if (flag('--sign')) {
  const target = opt('--sign'); const by = opt('--by');
  if (!by) { console.log('FAIL  --sign 需要 --by <姓名>'); process.exit(2); }
  const list = target === 'all' ? closureList : [target];
  for (const f of list) {
    const e = ledger.entries.find((x) => x.file === f);
    if (!e) { console.log(`FAIL  ${f} 不在台账内（先 --update）`); process.exit(2); }
    e.reviewedBy = by; e.reviewedAt = new Date().toISOString().slice(0, 10); e.reviewedSha256 = sha(f);
  }
  save();
  console.log(`已签字 ${list.length} 项，审查人：${by}`);
}

const missing = closureList.filter((f) => !entryOf.has(f) && !flag('--update') && !flag('--sign'));
const extra = ledger.entries.filter((e) => !closure.has(e.file)).map((e) => e.file);
if (!flag('--update') && !flag('--sign')) {
  if (missing.length) fail(`${missing.length} 个关键文件不在台账内（运行 node tools/ci/module-audit.mjs --update）：${missing.slice(0, 6).join(', ')}`);
  if (extra.length) fail(`台账里有 ${extra.length} 个文件已不在敏感闭包内（运行 --update 清理）`);
}

const state = (e) => (!e.reviewedSha256 ? 'unreviewed' : e.reviewedSha256 === sha(e.file) ? 'reviewed' : 'stale');
const live = ledger.entries.filter((e) => closure.has(e.file) && existsSync(join(root, e.file)));
const counts = { reviewed: 0, stale: 0, unreviewed: 0 };
let lines = 0;
for (const e of live) counts[state(e)] += 1;
for (const f of closureList) lines += readFileSync(join(root, f), 'utf8').split('\n').length;
const delegated = live.filter(e => state(e) === 'reviewed' && e.reviewKind === 'user-authorized-agent-review').length;
console.log(`敏感闭包：${roots.length} 个根 → ${closureList.length} 个关键文件，约 ${lines} 行；审查有效 ${counts.reviewed}（其中用户授权代理复审 ${delegated}），已过期 ${counts.stale}，未审查 ${counts.unreviewed}`);
if (flag('--strict') && (counts.stale || counts.unreviewed)) fail('存在未审查或过期的关键文件（--strict）');

if (flag('--report')) {
  const out = ['# 模块分层与审查地图（自动生成）', '', '由 `node tools/ci/module-audit.mjs --report` 生成，不要手改。', ''];
  for (const l of map.layers) {
    out.push(`## ${l.name}（${l.trust}）`, '', l.desc, '');
    for (const f of files.filter((x) => layerOf(x) === l.name).sort()) out.push(`- \`${f}\`${closure.has(f) ? ' **[关键]**' : ''}`);
    out.push('');
  }
  writeFileSync(join(root, 'docs', 'MODULE_MAP.md'), `${out.join('\n')}\n`, 'utf8');
  console.log('已写入 docs/MODULE_MAP.md');
}
process.exit(failed ? 1 : 0);
