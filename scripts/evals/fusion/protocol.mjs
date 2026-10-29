import { createHash } from 'node:crypto';

export const groups = Object.freeze(['A','B','C','D','E']);
const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const hashText = value => createHash('sha256').update(value).digest('hex');
const requireValue = (value, message) => { if (!value) throw new Error(message); };
const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const integer = value => Number.isSafeInteger(value) && value >= 0;
const channels = ['file','terminal','network','retrieval','host-cache','history','recovery-agent'];

// Preparation-side contract only. No model invocation, filesystem or network access.
export function freezeProtocol(input) {
  requireValue(input.schema === 'ig5-fusion-eval-input-v1', 'Invalid schema');
  for (const key of ['model','route','parameters','context','toolVersion','corpusGeneration','promptSha256','budget','thresholds']) requireValue(input[key] !== undefined && input[key] !== null, 'Missing control: '+key);
  for (const key of ['model','route','context','toolVersion','corpusGeneration']) requireValue(typeof input[key] === 'string' && input[key].length > 0, 'Invalid control: '+key);
  requireValue(digest(input.promptSha256), 'Invalid prompt digest');
  requireValue(input.parameters && typeof input.parameters === 'object', 'Missing model parameters');
  for (const key of ['toolCalls','tokens','elapsedMs','returnedBytes']) requireValue(integer(input.budget[key]) && input.budget[key] > 0, 'Invalid total budget');
  requireValue(input.thresholds.falseAccepts === 0 && input.thresholds.boundaryViolations === 0 && input.thresholds.nonInferiorityPercentagePoints === 5 && input.thresholds.offOverheadPercent === 10, 'Frozen hard gates changed');
  requireValue(Array.isArray(input.tasks) && input.tasks.length > 0 && input.tasks.length <= 1000, 'Invalid tasks');
  const ids = new Set(), familyPartitions = new Map(), identities = new Set();
  for (const task of input.tasks) {
    requireValue(typeof task.id === 'string' && task.id && !ids.has(task.id) && typeof task.family === 'string' && task.family && digest(task.inputSha256) && digest(task.judgeSha256) && ['development','holdout'].includes(task.partition), 'Invalid task');
    requireValue(!identities.has(task.inputSha256), 'Duplicate source input');
    requireValue(!familyPartitions.has(task.family) || familyPartitions.get(task.family) === task.partition, 'Family leaks across partitions');
    requireValue(task.project !== 'VS1.5' || task.partition === 'development', 'VS1.5 cannot be holdout');
    ids.add(task.id); identities.add(task.inputSha256); familyPartitions.set(task.family,task.partition);
  }
  const controls = Object.fromEntries(['model','route','parameters','context','toolVersion','corpusGeneration','promptSha256','budget','thresholds'].map(k=>[k,input[k]]));
  const manifest = JSON.parse(JSON.stringify({schema:'ig5-fusion-eval-frozen-v1',groups,repetitions:3,controls,tasks:input.tasks, familyAssignment:'declared-not-independently-proved', answerBoundary:'exposed', assistAllowed:false}));
  return { manifest, sha256:hash(manifest) };
}

// Independently exported raw-event receipt. A caller-provided pass flag is never used.
// The receipt is integrity binding, not an authenticated independent oracle.
export function judgeDecisionEvents(task, events, expectedDecision) {
  requireValue(Array.isArray(events) && events.length > 0 && events.length <= 256, 'Missing/bounded raw events');
  const decisions = events.filter(e=>e.type === 'decision');
  const final = decisions.at(-1);
  const supported = final && Array.isArray(final.sourceRefs) && final.sourceRefs.length > 0 && final.sourceRefs.every(digest);
  const verdict = !supported ? 'unknown' : final.value === expectedDecision ? 'pass' : 'fail';
  return {schema:'ig5-fusion-decision-judge-v1',taskId:task.id,inputSha256:task.inputSha256,judgeSha256:task.judgeSha256,eventsSha256:hash(events),verdict,
    claimedAccepted:events.some(e=>e.type==='accept' && e.value===true), scope:'workflow-decision-only-not-algorithm-equivalence'};
}

export function summarizeRuns(frozen, runs, trustedJudges = {}) {
  requireValue(hash(frozen.manifest) === frozen.sha256, 'Frozen manifest changed');
  requireValue(Array.isArray(runs), 'Invalid runs');
  const {manifest} = frozen, seen = new Set(), perGroup = Object.fromEntries(groups.map(g=>[g,{observed:0,passed:0,falseAccepts:0,budgetViolations:0,unverified:0,missing:manifest.tasks.length*3}]));
  for (const run of runs) {
    const task = manifest.tasks.find(t=>t.id===run.taskId), key = `${run.taskId}:${run.group}:${run.repetition}`;
    requireValue(task && groups.includes(run.group) && [1,2,3].includes(run.repetition) && !seen.has(key), 'Invalid/duplicate run'); seen.add(key);
    requireValue(run.protocolSha256 === frozen.sha256 && hash(run.controls) === hash(manifest.controls), 'Comparison controls differ');
    requireValue(['completed','failed','blocked'].includes(run.status), 'Invalid run status');
    requireValue(Array.isArray(run.events) && run.judge && run.judge.eventsSha256 === hash(run.events) && run.judge.taskId === task.id && run.judge.inputSha256 === task.inputSha256 && run.judge.judgeSha256 === task.judgeSha256 && ['pass','fail','unknown'].includes(run.judge.verdict) && typeof run.judge.claimedAccepted === 'boolean', 'Missing judge/source log binding');
    // The trusted expectation is supplied by the preparation/evaluator role, never by a run.
    const expected=trustedJudges[task.id];
    if(expected !== undefined) requireValue(typeof expected === 'string' && hashText(expected) === task.judgeSha256, 'Trusted judge identity mismatch');
    const assessed=expected === undefined ? {verdict:'unknown',claimedAccepted:run.events.some(e=>e.type==='accept' && e.value===true)} : judgeDecisionEvents(task,run.events,expected);
    if(expected !== undefined) requireValue(hash(assessed) === hash(run.judge), 'Caller verdict disagrees with independent decision replay');
    const stats=perGroup[run.group]; stats.observed++;stats.missing--;
    for (const k of ['toolCalls','tokens','elapsedMs','returnedBytes']) requireValue(integer(run.cost?.[k]), 'Missing total cost');
    // Costs include search and source reads, without a separate free retrieval allowance.
    const exceeded=Object.keys(manifest.controls.budget).some(k=>run.cost[k] > manifest.controls.budget[k]);
    if(exceeded)stats.budgetViolations++;
    if(assessed.claimedAccepted && assessed.verdict==='fail')stats.falseAccepts++;
    if(run.status==='completed' && assessed.verdict==='pass' && !exceeded && run.cleanupConfirmed===true)stats.passed++;
    else stats.unverified++;
  }
  return {schema:'ig5-fusion-eval-summary-v1',protocolSha256:frozen.sha256,perGroup,blindRuns:0,assistAllowed:false,
    answerBoundary:'exposed',missingBoundaryChannels:channels, conclusion:'Auxiliary workflow receipts only; no isolated model benefit or algorithm acceptance established.'};
}
