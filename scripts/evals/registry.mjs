import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

export const root = path.dirname(fileURLToPath(import.meta.url));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
export function loadCases() {
  const cases = fs.readdirSync(path.join(root, 'cases')).filter(n => n.endsWith('.json')).sort().map(name => {
    const value = JSON.parse(fs.readFileSync(path.join(root, 'cases', name), 'utf8'));
    if (value.schema !== 'ig5-eval-case-v1' || !value.caseId || !['development', 'holdout'].includes(value.partition)
      || !['static', 'dynamic', 'data', 'vm'].includes(value.category) || !value.question || !value.acceptance.length
      || !value.allowedOperations.length || !value.cleanup.length || !value.reference.evaluatorOnly
      || !Number.isSafeInteger(value.budget.toolCalls) || value.budget.toolCalls < 1) throw new Error('Invalid eval case: ' + name);
    if (!Number.isSafeInteger(value.budget.elapsedMs) || value.budget.elapsedMs < 1 || !Number.isSafeInteger(value.budget.inlineBytes) || value.budget.inlineBytes < 1
      || value.reference.path !== 'oracle.mjs' || value.reference.sha256 && value.reference.sha256 !== sha(fs.readFileSync(path.join(root,'oracle.mjs')))) throw new Error('Invalid eval budget/reference: '+name);
    const fixture = path.resolve(root, value.input.path);
    if (path.dirname(fixture) !== path.join(root, 'assets') || sha(fs.readFileSync(fixture)) !== value.input.sha256) throw new Error('Eval input identity mismatch: ' + name);
    return value;
  });
  if(new Set(cases.map(c=>c.caseId)).size!==cases.length)throw new Error('Duplicate preregistered case ID');
  return cases;
}

/** Every preregistered case remains in the denominator, including blocked/missing runs. */
export function summarize(cases, runs) {
  const ids = new Set(cases.map(c => c.caseId)), seen = new Set();
  for (const run of runs) {
    const key = `${run.caseId}:${run.variant}:${run.repetition}`;
    if (!ids.has(run.caseId) || seen.has(key) || !['baseline', 'brief', 'failure-routing', 'brief-lcm'].includes(run.variant)
      || !Number.isSafeInteger(run.repetition) || run.repetition < 1 || !['completed', 'failed', 'blocked'].includes(run.status)
      || typeof run.claimedAccepted !== 'boolean' || !['pass', 'fail', 'unknown'].includes(run.independentVerdict)
      || !['exposed', 'isolated', 'unavailable'].includes(run.answerExposure)
      || !Number.isSafeInteger(run.toolCalls) || run.toolCalls < 0
      || !Number.isFinite(run.elapsedMs) || run.elapsedMs < 0) throw new Error('Invalid/duplicate eval run');
    const c = cases.find(c => c.caseId === run.caseId);
    if (run.inputSha256 !== c.input.sha256 || run.budgetDigest !== sha(JSON.stringify(c.budget))) throw new Error('Run identity or frozen budget mismatch');
    if (!run.model || !run.promptSha256 || !run.cacheCondition) throw new Error('Missing controlled comparison conditions');
    seen.add(key);
  }
  const accepted = r => {
    const budget = cases.find(c => c.caseId === r.caseId).budget;
    return r.status === 'completed' && r.claimedAccepted && r.independentVerdict === 'pass'
      && r.toolCalls <= budget.toolCalls && r.elapsedMs <= budget.elapsedMs
      && Number.isSafeInteger(r.inlineBytes) && r.inlineBytes >= 0 && r.inlineBytes <= budget.inlineBytes
      && r.cleanupConfirmed === true;
  };
  const registered = cases.length;
  return { schema: 'ig5-eval-summary-v1', registeredCases: registered, observedRuns: runs.length,
    unrunCases: cases.filter(c => !runs.some(r => r.caseId === c.caseId)).map(c => c.caseId),
    blockedRuns: runs.filter(r => r.status === 'blocked').length,
    acceptedRuns: runs.filter(accepted).length,
    falseAccepts: runs.filter(r => r.claimedAccepted && r.independentVerdict === 'fail').length,
    acceptanceUnverified: runs.filter(r => r.claimedAccepted && r.independentVerdict === 'pass' && !accepted(r)).length,
    acceptanceUnknown: runs.filter(r => r.claimedAccepted && r.independentVerdict === 'unknown').length,
    blindRuns: runs.filter(r => r.answerExposure === 'isolated' && r.modelReached === true && r.blindBoundaryLoaded === true).length,
    perVariant: Object.fromEntries(['baseline','brief','failure-routing','brief-lcm'].map(variant=>{
      const observed=runs.filter(r=>r.variant===variant);
      return [variant,{registeredCases:registered,observedRuns:observed.length, accepted:observed.filter(accepted).length,
        unrunCases:cases.filter(c=>!observed.some(r=>r.caseId===c.caseId)).map(c=>c.caseId),
        blocked:observed.filter(r=>r.status==='blocked').length,
        falseAccepts:observed.filter(r=>r.claimedAccepted&&r.independentVerdict==='fail').length}];
    })),
    conclusion: runs.length ? 'Inspect variants and controlled conditions before comparing effectiveness.' : 'Preregistered only; no task effectiveness measured.' };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const cases = loadCases();
  const runs = process.argv[2] ? JSON.parse(fs.readFileSync(process.argv[2], 'utf8')) : [];
  console.log(JSON.stringify(summarize(cases, runs), null, 2));
}
