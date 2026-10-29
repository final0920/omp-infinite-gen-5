// Build the pinned upstream storage implementation without installing host hooks.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const upstream = path.resolve(process.argv[2] || path.join(root, '../_research/lcm-full-20261021'));
const revision = '0c17dbffda452cf7fae46929af427dff355aeaa3';
const git = (...args) => execFileSync('git', ['-C', upstream, ...args], { encoding: 'utf8' }).trim();
if (git('rev-parse', 'HEAD') !== revision || git('status', '--porcelain', '--untracked-files=no')) throw new Error('LCM source must match the clean pinned revision');
if (git('rev-parse', '--is-shallow-repository') !== 'false') throw new Error('Full upstream history required for this integration review');
const output = path.join(root, 'third_party/lcm');
fs.mkdirSync(output, { recursive: true });
const deps = path.join(root, 'scratch/lcm-build/node_modules');
const { build } = await import(pathToFileURL(path.join(deps, 'esbuild/lib/main.js')));
const entries = { ConversationStore: 'src/store/conversation-store.ts', SummaryStore: 'src/store/summary-store.ts', runLcmMigrations: 'src/db/migration.ts' };
const result = await build({
  absWorkingDir: root,
  stdin: { contents: Object.entries(entries).map(([name, file]) => `export { ${name} } from ${JSON.stringify(path.join(upstream, file).replaceAll('\\', '/'))};`).join('\n'), resolveDir: upstream, sourcefile: 'ig5-lcm-entry.ts' },
  outfile: path.join(output, 'core.mjs'), bundle: true, platform: 'node', format: 'esm', target: 'node22',
  nodePaths: [deps], metafile: true, legalComments: 'eof',
  banner: { js: '// Pinned lossless-claude/lcm storage core. See PROVENANCE.json and LICENSE.\nimport { createRequire as __ig5CreateRequire } from "node:module"; const require = __ig5CreateRequire(import.meta.url);' },
});
const hash = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
execFileSync('git', ['-C', upstream, 'archive', '--format=zip', `--output=${path.join(output, 'upstream-source.zip')}`, revision]);
fs.copyFileSync(path.join(upstream, 'LICENSE'), path.join(output, 'LICENSE'));
for (const dep of ['safe-regex', 'regexp-tree', 'js-yaml', 'argparse']) {
  const dir = path.join(deps, dep);
  fs.copyFileSync(path.join(dir, 'LICENSE'), path.join(output, `${dep}.LICENSE`));
}
const inputs = Object.keys(result.metafile.inputs).filter(p => fs.existsSync(path.resolve(root, p))).map(p => {
  const absolute = path.resolve(root, p);
  return { path: absolute.startsWith(upstream + path.sep) ? path.relative(upstream, absolute).replaceAll('\\', '/') : `dependency/${path.relative(deps, absolute).replaceAll('\\', '/')}`, sha256: hash(absolute) };
});
for (const file of ['package.json', 'package-lock.json']) fs.copyFileSync(path.join(deps, '..', file), path.join(output, 'build-' + file));
fs.writeFileSync(path.join(output, 'PROVENANCE.json'), JSON.stringify({
  repository: 'https://github.com/lossless-claude/lcm', revision, version: '0.16.0', fullHistoryVerified: true,
  license: 'MIT', integration: 'Unmodified ConversationStore, SummaryStore and migrations; IG5 provides exact event capture, scope, budgets, and DSH bridge. Upstream hooks, daemon, scrubber and model providers are not executed.',
  build: { dependencies: Object.fromEntries(['esbuild','safe-regex','regexp-tree','js-yaml','argparse'].map(name => [name, JSON.parse(fs.readFileSync(path.join(deps,name,'package.json'),'utf8')).version])), entries, command: 'node scripts/build_lcm_vendor.mjs <clean-full-upstream-checkout>' },
  files: Object.fromEntries(['core.mjs', 'upstream-source.zip', 'build-package.json', 'build-package-lock.json', 'LICENSE', 'safe-regex.LICENSE', 'regexp-tree.LICENSE', 'js-yaml.LICENSE', 'argparse.LICENSE'].map(p => [p, { sha256: hash(path.join(output, p)), bytes: fs.statSync(path.join(output, p)).size }])), inputs,
}, null, 2) + '\n');
console.log(JSON.stringify({ revision, inputs: inputs.length, bundleBytes: fs.statSync(path.join(output, 'core.mjs')).size, sourceArchiveBytes: fs.statSync(path.join(output, 'upstream-source.zip')).size }));
