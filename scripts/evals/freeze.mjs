import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { root, loadCases } from './registry.mjs';
import { fileURLToPath } from 'node:url';
const hash = b => createHash('sha256').update(b).digest('hex');
export function frozenTargets(filename, cases = loadCases()) {
  const value = JSON.parse(fs.readFileSync(filename, 'utf8'));
  if (value.schema !== 'ig5-eval-target-freeze-v1' || value.sourceSha256 !== hash(fs.readFileSync(path.join(root, 'fixture.c')))
    || !value.compilerVersion || value.targets.length !== cases.filter(c => c.category !== 'data').length) throw new Error('Invalid target freeze');
  const seen = new Set();
  for (const row of value.targets) {
    const c = cases.find(c => c.caseId === row.caseId);
    if (!c || seen.has(row.caseId) || c.input.sha256 !== row.specSha256 || !path.isAbsolute(row.path)
      || hash(fs.readFileSync(row.path)) !== row.sha256 || hash(fs.readFileSync(row.mapPath)) !== row.mapSha256) throw new Error('Frozen target identity mismatch');
    seen.add(row.caseId);
  }
  return value;
}
if (process.argv[2] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const value = frozenTargets(path.resolve(process.argv[2]));
  fs.writeFileSync(path.join(root, 'assets', 'targets.freeze.json'), JSON.stringify(value, null, 2) + '\n');
  for(const c of loadCases()) {
    const target=value.targets.find(t=>t.caseId===c.caseId);
    c.reference.sha256=hash(fs.readFileSync(path.join(root,'oracle.mjs')));
    if(target)c.target={path:target.path,sha256:target.sha256,mapSha256:target.mapSha256,sourceSha256:value.sourceSha256,compilerVersion:value.compilerVersion};
    c.status=target?'compiled-target-frozen-not-model-run':'data-input-frozen-not-model-run';
    fs.writeFileSync(path.join(root,'cases',c.caseId+'.json'),JSON.stringify(c,null,2)+'\n');
  }
  console.log(JSON.stringify({ frozenTargets: value.targets.length, compiler: value.compilerVersion }));
}
