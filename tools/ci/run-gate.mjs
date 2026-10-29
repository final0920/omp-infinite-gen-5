// 门禁测试入口（npm test）。
// 按 gate.json 顺序逐项运行，报告 pass / fail / timeout / missing；任何一项不是 pass 就以非 0 退出。
// 用法：node tools/ci/run-gate.mjs [名称...] [--json 输出路径]
// 说明：这里只放纯 Node、不依赖真实引擎和客体虚拟机的测试；需要真实环境的验收单独运行，不在此处。
// 选项：--tier core|all（默认 core；extended 层的测试可能依赖本机 runtime）、--jobs N（并行数，默认 4）。
import { spawn } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..', '..');
const gate = JSON.parse(readFileSync(join(here, 'gate.json'), 'utf8'));

const args = process.argv.slice(2);
let jsonOut = null;
let tier = 'core';
let jobs = 4;
const only = [];
for (let i = 0; i < args.length; i += 1) {
  if (args[i] === '--json') { jsonOut = args[i + 1]; i += 1; }
  else if (args[i] === '--tier') { tier = args[i + 1]; i += 1; }
  else if (args[i] === '--jobs') { jobs = Math.max(1, Number(args[i + 1]) || 1); i += 1; }
  else only.push(args[i]);
}

const selected = gate.tests.filter((t) => {
  if (only.length) return only.includes(t.name);
  return tier === 'all' || (t.tier ?? 'core') === 'core';
});

function runOne(t) {
  const file = join(root, t.file);
  if (!existsSync(file)) {
    console.log(`MISSING  ${t.name}  (${t.file})`);
    return Promise.resolve({ name: t.name, status: 'missing', seconds: 0, detail: `找不到 ${t.file}` });
  }
  return new Promise((done) => {
    const started = Date.now();
    const timeoutSec = t.timeoutSec ?? gate.defaultTimeoutSec ?? 120;
    const child = spawn(process.execPath, [file], { cwd: root, windowsHide: true });
    let out = '';
    const keep = (d) => { out = (out + d.toString()).slice(-16384); };
    child.stdout.on('data', keep);
    child.stderr.on('data', keep);
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; child.kill(); }, timeoutSec * 1000);
    const finish = (code, spawnError) => {
      clearTimeout(timer);
      const seconds = Math.round((Date.now() - started) / 100) / 10;
      let status = 'pass';
      if (timedOut) status = 'timeout';
      else if (spawnError || code !== 0) status = 'fail';
      const tail = out.trim().split(/\r?\n/).slice(-15).join('\n');
      console.log(`${status.toUpperCase().padEnd(8)} ${t.name}  ${seconds}s`);
      if (status !== 'pass') console.log(tail.split('\n').map((l) => `    | ${l}`).join('\n'));
      done({ name: t.name, area: t.area, status, seconds, exit: code, env: t.env, tail: status === 'pass' ? '' : tail });
    };
    child.on('error', (e) => finish(null, e));
    child.on('close', (code) => finish(code, null));
  });
}

const slots = new Array(selected.length);
let next = 0;
await Promise.all(Array.from({ length: Math.min(jobs, selected.length) }, async () => {
  while (next < selected.length) {
    const i = next; next += 1;
    slots[i] = await runOne(selected[i]);
  }
}));
const results = slots.filter(Boolean);

const count = (s) => results.filter((x) => x.status === s).length;
const summary = { total: results.length, pass: count('pass'), fail: count('fail'), timeout: count('timeout'), missing: count('missing') };
console.log(`\n门禁结果：${summary.pass}/${summary.total} 通过，失败 ${summary.fail}，超时 ${summary.timeout}，缺失 ${summary.missing}`);
if (jsonOut) writeFileSync(jsonOut, JSON.stringify({ at: new Date().toISOString(), summary, results }, null, 2), 'utf8');
process.exit(summary.pass === summary.total && summary.total > 0 ? 0 : 1);
