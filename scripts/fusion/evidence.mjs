import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = message => { throw new Error(message); };
export function localPath(root, relative) {
  if (typeof relative !== 'string' || !relative || relative.includes('\\') || relative.split('/').some(p => !p || p === '.' || p === '..') || path.isAbsolute(relative) || relative.includes(':')) fail('Invalid relative evidence path');
  const result = path.resolve(root, relative);
  if (!result.startsWith(path.resolve(root) + path.sep)) fail('Evidence outside root');
  return result;
}
export async function readEvidence(root, relative) {
  const file = localPath(root, relative);
  for (let current = file; ; current = path.dirname(current)) {
    const stat = await fs.lstat(current);
    if (stat.isSymbolicLink()) fail('Linked evidence rejected');
    if (current === path.parse(current).root) break;
  }
  const handle = await fs.open(file, 'r');
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.nlink !== 1) fail('Evidence must be a plain single-link file');
    const bytes = await handle.readFile();
    const after = await handle.stat();
    const current = await fs.lstat(file);
    if (before.dev !== current.dev || before.ino !== current.ino || current.isSymbolicLink() || current.nlink !== 1 || before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) fail('Evidence changed during read');
    return { bytes, path: relative, size: bytes.length, sha256: sha256(bytes), mtime: after.mtime.toISOString() };
  } finally { await handle.close(); }
}
export async function inventory(root, names) {
  const records = [];
  async function walk(relative = '') {
    for (const entry of (await fs.readdir(path.join(root, relative), { withFileTypes: true })).sort((a,b) => a.name.localeCompare(b.name))) {
      const name = relative ? relative + '/' + entry.name : entry.name;
      if (entry.isDirectory()) await walk(name);
      else if (entry.isFile()) names.push(name);
      else records.push({ path: name, status: 'unsupported-file-type' });
    }
  }
  if (!names) { names = []; await walk(); }
  for (const name of [...new Set(names)].sort()) {
    const { bytes, ...record } = await readEvidence(root, name);
    records.push(record);
  }
  return { root: path.resolve(root), files: records, digest: sha256(JSON.stringify(records)), scope: 'per-file-stable-reads-not-filesystem-snapshot' };
}
export async function auditCases(bundle, root) {
  if (bundle.schema !== 'ig5-private-decision-cases-v1' || bundle.partition !== 'development' || bundle.publicExportAllowed !== false || !Array.isArray(bundle.cases) || bundle.cases.length < 12 || bundle.cases.length > 128) fail('Invalid private development bundle');
  const ids = new Set();
  const cache = new Map();
  const receipts = [];
  for (const item of bundle.cases) {
    if (!item.caseId || ids.has(item.caseId) || item.projectId !== bundle.projectId || !/^[a-f0-9]{64}$/.test(item.artifactSha256) || !['reported','contested'].includes(item.status) || item.timeline !== 'retrospective-order-unverified') fail('Invalid case identity/status/timeline');
    ids.add(item.caseId);
    for (const key of ['question','visibleInput','observations','historicalAction','locatedResult','laterCorrection','unknowns','redaction','expectedDecision']) if (typeof item[key] !== 'string' || !item[key].trim() || item[key].length > 4000) fail('Missing case field: ' + key);
    if (!Array.isArray(item.hypotheses) || item.hypotheses.length < 2 || item.hypotheses.some(h => typeof h !== 'string' || !h.trim()) || !Array.isArray(item.sourceRefs) || !item.sourceRefs.length) fail('Missing competing hypotheses or sources');
    const sources = [];
    for (const ref of item.sourceRefs) {
      if (!cache.has(ref.path)) cache.set(ref.path, await readEvidence(root, ref.path));
      const source = cache.get(ref.path);
      const lines = source.bytes.toString('utf8').split(/\r?\n/);
      if (source.sha256 !== ref.sha256 || !Number.isSafeInteger(ref.startLine) || !Number.isSafeInteger(ref.endLine) || ref.startLine < 1 || ref.endLine < ref.startLine || ref.endLine > lines.length) fail('Source identity/range mismatch');
      const selected = lines.slice(ref.startLine - 1, ref.endLine).join('\n');
      if (sha256(selected) !== ref.rangeSha256) fail('Source range mismatch');
      sources.push({ ...ref, integrity: 'matched', supportsClaim: 'human-reviewed-not-machine-proved' });
    }
    receipts.push({ caseId: item.caseId, sources, status: item.status, semanticVerified: false });
  }
  return { schema: 'ig5-case-integrity-audit-v1', bundleSha256: sha256(JSON.stringify(bundle)), caseCount: receipts.length, receipts, publicExportAllowed: false, semanticVerified: false };
}

async function main() {
  const [operation, sourceRoot, evidenceRoot, output] = process.argv.slice(2);
  if (![sourceRoot,evidenceRoot,output].every(p => p && path.isAbsolute(p))) fail('Use explicit absolute paths');
  // New output directory only; never merge into a previous receipt or into either input tree.
  for (const root of [sourceRoot,evidenceRoot]) {
    const real = await fs.realpath(root);
    const parent = await fs.realpath(path.dirname(output));
    const resolved = path.join(parent, path.basename(output));
    if (resolved.toLowerCase() === real.toLowerCase() || resolved.toLowerCase().startsWith(real.toLowerCase() + path.sep)) fail('Output must be outside inputs');
  }
  if (operation !== 'snapshot') fail('Supported operation: snapshot SOURCE_ROOT EVIDENCE_ROOT NEW_OUTPUT');
  await fs.mkdir(output);
  const names = execFileSync('git', ['ls-files','-co','--exclude-standard','-z'], { cwd: sourceRoot }).toString('utf8').split('\0').filter(Boolean);
  const source = await inventory(sourceRoot, names);
  const evidence = await inventory(evidenceRoot);
  const result = { schema: 'ig5-fusion-baseline-v1', observedAt: new Date().toISOString(), source, evidence,
    head: execFileSync('git', ['rev-parse','HEAD'], { cwd: sourceRoot }).toString().trim(),
    gitStatus: execFileSync('git', ['-c','core.quotepath=false','status','--porcelain=v1','--untracked-files=all'], { cwd: sourceRoot }).toString(),
    ignoredSourceFilesIncluded: false, sourceBytesArchived: true, evidenceBytesCopied: false };
  for (const file of source.files) {
    const current = await readEvidence(sourceRoot, file.path);
    if (current.sha256 !== file.sha256) fail('Source changed before archive');
    const destination = localPath(path.join(output,'source'), file.path);
    await fs.mkdir(path.dirname(destination), { recursive: true });
    await fs.writeFile(destination, current.bytes, { flag: 'wx' });
  }
  await fs.writeFile(path.join(output, 'baseline.json'), JSON.stringify(result,null,2), { flag: 'wx' });
  console.log(JSON.stringify({sourceFiles:source.files.length,evidenceFiles:evidence.files.length,output}));
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch(error => { console.error(error.message); process.exitCode = 1; });
