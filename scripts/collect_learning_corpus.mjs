// Downloads DATA only; never starts samples or upstream scripts.
// Official 52pojie downloads are deliberately sequential (site policy).
import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';

const manifestPath = process.argv[2];
const output = path.resolve(process.argv[3] || '');
if (!manifestPath || !process.argv[3]) throw new Error('Usage: node scripts/collect_learning_corpus.mjs MANIFEST OUTPUT');
const manifest = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
if (!Array.isArray(manifest.files) || manifest.files.length > 1000) throw new Error('Invalid corpus manifest');
const source = path.resolve(import.meta.dirname, '..');
if (output === source || output.startsWith(source + path.sep)) throw new Error('Keep external corpus outside the plugin');
await fs.mkdir(output, { recursive: true });
if ((await fs.lstat(output)).isSymbolicLink()) throw new Error('Linked output root refused');
let total = 0;
const rows = [];
for (const file of manifest.files.filter(row => !row.derivedFrom)) {
  if (!/^[a-z0-9_-]+\//i.test(file.file) || file.file.includes('\\') || file.file.split('/').some(p => !p || p === '.' || p === '..' || p.includes(':'))) throw new Error('Invalid relative corpus path');
  const url = new URL(file.url);
  if (url.protocol !== 'https:' || !['raw.githubusercontent.com', 'down.52pojie.cn'].includes(url.hostname)) throw new Error('Unexpected download origin');
  if (url.hostname === 'raw.githubusercontent.com' && !/^\/[^/]+\/[^/]+\/[0-9a-f]{40}\//.test(url.pathname)) throw new Error('GitHub downloads require a pinned commit');
  if (!file.sha256 && !/^[0-9a-f]{40}$/.test(file.gitBlob || '')) throw new Error('An independent SHA256 or pinned Git blob is required');
  const destination = path.join(output, ...file.file.split('/'));
  let directory = output;
  for (const component of file.file.split('/').slice(0, -1)) {
    directory = path.join(directory, component);
    await fs.mkdir(directory, { recursive: true });
    if ((await fs.lstat(directory)).isSymbolicLink()) throw new Error('Linked corpus directory refused');
  }
  let data;
  try {
    const info = await fs.lstat(destination);
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size > 64 * 1024 * 1024) throw new Error('Unsafe existing corpus file');
    data = await fs.readFile(destination);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    const response = await fetch(url, { signal: AbortSignal.timeout(120000), redirect: 'error' });
    if (!response.ok) throw new Error('Download HTTP ' + response.status + ': ' + file.file);
    const parts = []; let bytes = 0;
    for await (const part of response.body) {
      bytes += part.length;
      if (bytes > 64 * 1024 * 1024) throw new Error('Download exceeded file budget');
      parts.push(part);
    }
    data = Buffer.concat(parts);
  }
  total += data.length;
  if (total > 256 * 1024 * 1024) throw new Error('Corpus exceeded combined download budget');
  const sha256 = createHash('sha256').update(data).digest('hex');
  const gitBlob = createHash('sha1').update('blob ' + data.length + '\0').update(data).digest('hex');
  if (file.bytes !== data.length || (file.sha256 && file.sha256 !== sha256) || (file.gitBlob && file.gitBlob !== gitBlob)) throw new Error('Corpus pin mismatch: ' + file.file);
  try { await fs.access(destination); }
  catch {
    const stage = destination + '.' + randomUUID() + '.part';
    await fs.writeFile(stage, data, { flag: 'wx' });
    await fs.rename(stage, destination);
  }
  rows.push({ ...file, sha256 });
  if (rows.length % 10 === 0) console.log(JSON.stringify({ collected: rows.length, bytes: total }));
}
await fs.writeFile(path.join(output, 'download-manifest.json'), JSON.stringify({ ...manifest, files: rows, totalBytes: total }, null, 2));
console.log(JSON.stringify({ collected: rows.length, bytes: total, nativeTargetExecuted: false }));
