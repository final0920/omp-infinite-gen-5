// 单样本脚本登记检查（npm run ci 的一部分）：
// 名字里带 handler<数字> / context<数字> 的脚本必须登记在 sample-specific.json，登记的文件必须存在，
// 且不得出现在默认门禁里（门禁只放通用的纯 Node 测试，不放绑定某个样本的证明）。
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..', '..');
const manifest = JSON.parse(readFileSync(join(here, 'sample-specific.json'), 'utf8'));
const gate = JSON.parse(readFileSync(join(here, 'gate.json'), 'utf8'));
const registered = new Set(manifest.files);
const pattern = new RegExp(manifest.pattern);
let failed = false;
const fail = message => { failed = true; console.log(`FAIL  ${message}`); };

const found = readdirSync(join(root, 'scripts')).filter(name => pattern.test(name)).map(name => `scripts/${name}`);
const unregistered = found.filter(file => !registered.has(file));
if (unregistered.length) fail(`${unregistered.length} 个单样本脚本未登记（tools/ci/sample-specific.json）：${unregistered.join(', ')}`);
const missing = manifest.files.filter(file => !existsSync(join(root, file)));
if (missing.length) fail(`登记的单样本脚本不存在：${missing.join(', ')}`);
const inGate = gate.tests.filter(test => registered.has(test.file)).map(test => test.name);
if (inGate.length) fail(`单样本脚本不得进入默认门禁：${inGate.join(', ')}`);
console.log(`单样本脚本：已登记 ${registered.size} 个，扫描到 ${found.length} 个${failed ? '' : '，登记完整'}`);
process.exit(failed ? 1 : 0);
