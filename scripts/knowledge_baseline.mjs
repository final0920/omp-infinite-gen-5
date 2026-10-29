import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';

// Freeze current working files (including untracked source), without resetting Git.
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const output = path.resolve(process.argv[2] || '');
if (!process.argv[2] || fs.existsSync(output)) throw new Error('Provide a new baseline receipt path');
const files = execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], { cwd: root, maxBuffer: 8 * 1024 ** 2 }).toString().split('\0').filter(Boolean);
const records = [...new Set(files)].sort().filter(p => !/^(runtimes|third_party|\.downloads|scratch)\//.test(p)).map(p => {
  const full = path.join(root, p);
  if (!fs.existsSync(full)) return { path: p, missing: true };
  const stat = fs.lstatSync(full);
  if (!stat.isFile() || stat.isSymbolicLink()) return { path: p, regularFile: false };
  const bytes = fs.readFileSync(full);
  return { path: p, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') };
});
const receipt = { schema: 'ig5-knowledge-baseline-v1', capturedAt: new Date().toISOString(), root,
  head: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root }).toString().trim(),
  status: execFileSync('git', ['status', '--short'], { cwd: root }).toString(), files: records,
  excluded: ['runtimes', 'third_party', '.downloads', 'scratch'], installedOrRuntimeChanged: false };
fs.writeFileSync(output, JSON.stringify(receipt, null, 2), { flag: 'wx' });
console.log(JSON.stringify({ path: output, files: records.length }));
