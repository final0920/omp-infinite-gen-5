import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

const directory = path.resolve(process.argv[2]);
const load = file => JSON.parse(fs.readFileSync(path.join(directory, file), 'utf8'));
const hash = value => createHash('sha256').update(value).digest('hex');
const canonical = value => JSON.stringify(value && typeof value === 'object' ? Array.isArray(value) ? value.map(v => JSON.parse(canonical(v)))
  : Object.fromEntries(Object.keys(value).sort().map(k => [k, JSON.parse(canonical(value[k]))])) : value);
const plan = load('model-plan.json'), replay = load('deterministic.json'), data = load('dataset.json');
assert.equal(hash(fs.readFileSync(path.join(directory, 'dataset.json'))), plan.datasetSha256);
for (const [file, expected] of Object.entries(replay.implementations)) assert.equal(hash(fs.readFileSync(path.join(directory, 'implementation', file))), expected);
assert.equal(replay.implementations['scripts/evals/memory_resume_model.mjs'], plan.driverSha256);
assert.equal(replay.implementations['scripts/evals/memory_resume_guard.mjs'], plan.guardSha256);
const raw = data.events.map(e => JSON.stringify(e)).join('\n');
const constraint = data.events.find(e => e.data?.constraints).data.constraints;
const witness = data.events.find(e => e.data?.observed?.counterexample).data.observed;
const needed = data.events.filter(e => data.evaluationContract?.requiredReports ? data.evaluationContract.requiredReports.includes(e.data?.reportId) : e.data?.reportId);
const certificates = [];
for (const run of load('model-runs.json')) {
  const prefix = `${run.variant}-${run.repetition}/`;
  const events = load(prefix + 'events.json');
  const logBytes = fs.readFileSync(path.join(directory, prefix, 'tool-log.jsonl'));
  const log = logBytes.toString('utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
  const calls = new Map(events.filter(e => e.type === 'tool/call').map(e => [e.data.callId, e.data]));
  const actual = [];
  for (const event of events.filter(e => e.type === 'tool/result')) {
    const message = event.data.message, call = calls.get(message.toolCallId || message.source?.callId);
    if (call?.name !== 'ig5_memory_eval' || message.isError) continue;
    try { actual.push({ args: JSON.parse(call.arguments), result: JSON.parse(message.content.filter(b => b.type === 'text').map(b => b.text).join('')) }); } catch {}
  }
  // Only receipts also present in raw SDK tool events count as recovered evidence.
  const receipts = log.filter(r => r.phase === 'result').filter(row => {
    const index = actual.findIndex(value => canonical(value) === canonical({ args: row.args, result: row.result }));
    if (index < 0) return false; actual.splice(index, 1); return true;
  });
  const complete = (pages, expected) => {
    let offset = 0, text = ''; const seen = new Set();
    while (!seen.has(offset)) {
      seen.add(offset); const page = pages.find(p => (p.args.offset ?? 0) === offset)?.result;
      if (!page || typeof page.text !== 'string') return false;
      text += page.text; if (page.nextOffset === null) return text === expected;
      if (!Number.isSafeInteger(page.nextOffset) || page.nextOffset <= offset) return false;
      offset = page.nextOffset;
    }
    return false;
  };
  const rawComplete = complete(receipts.filter(r => r.args.action === 'log'), raw);
  const missingEvents = needed.filter(e => !rawComplete && !complete(receipts.filter(r => r.args.action === 'read'
    && r.args.ref?.kind === 'event' && r.args.ref.id === String(e.seq) && r.args.ref.sha256 === hash(JSON.stringify(e))), JSON.stringify(e))).map(e => e.seq);
  const currentRead = receipts.some(r => r.args.action === 'current' && canonical(r.result) === canonical(data.current));
  let answer = null;
  try {
    const message = events.filter(e => e.type === 'assistant/message').at(-1)?.data.message;
    const text = message.content.filter(b => b.type === 'text').map(b => b.text).join('\n').replace(/^```(?:json)?\s*/, '').replace(/\s*```$/, '').trim();
    answer = JSON.parse(text);
  } catch {}
  const valid = answer && typeof answer === 'object' && !Array.isArray(answer);
  const forgottenConstraint = !valid || answer.inputDomain !== constraint.inputDomain || answer.sideEffects !== constraint.sideEffects;
  const lostCounterexample = !valid || ['input', 'expected', 'actual'].some(k => answer.counterexample?.[k] !== witness.counterexample[k]) || answer.pathCondition !== witness.pathCondition;
  const wrongConclusion = !valid || answer.accepted !== false || answer.historicalAuthorization !== false || answer.currentRevision !== data.current.dbRevision;
  const repeatedExecutionProposal = valid && answer.nextAction === 'repeat-unchanged';
  const dispatches = log.filter(r => r.phase === 'dispatch'), returnedBytes = log.filter(r => r.phase === 'result').reduce((n, r) => n + Buffer.byteLength(JSON.stringify(r.result)), 0);
  const budgetOk = dispatches.length <= plan.budget.toolCalls && returnedBytes <= plan.budget.inlineBytes && run.elapsedMs <= plan.budget.elapsedMs;
  const boundary = log.some(r => r.boundary === 'only-ig5_memory_eval');
  const pass = !!valid && !forgottenConstraint && !lostCounterexample && !wrongConclusion && answer.nextAction === 'change-experiment'
    && !missingEvents.length && currentRead && budgetOk && boundary && run.cleanupConfirmed;
  const usage = events.filter(e => e.type === 'assistant/message').map(e => e.data.usage);
  const tokens = usage.length && usage.every(u => u && Number.isFinite(u.inputTokens) && Number.isFinite(u.outputTokens)) ? {
    uncachedInput: usage.reduce((n, u) => n + u.inputTokens, 0), cacheRead: usage.reduce((n, u) => n + (u.cacheReadTokens || 0), 0), output: usage.reduce((n, u) => n + u.outputTokens, 0) } : null;
  const duplicateReads = receipts.length - new Set(receipts.map(r => canonical(r.args))).size;
  certificates.push({ variant: run.variant, repetition: run.repetition, pass, forgottenConstraint, lostCounterexample, wrongConclusion,
    repeatedExecutionProposal: !!repeatedExecutionProposal, falseAccept: valid && answer.accepted === true, missingEvents, currentRead, budgetOk,
    calls: dispatches.length, returnedBytes, tokens, duplicateReads, elapsedMs: run.elapsedMs,
    verdictMatchesDriver: pass === (run.independentVerdict === 'pass'),
    driverAccountingMatches: dispatches.length === run.toolCalls && returnedBytes === run.inlineBytes && (!tokens || canonical(tokens) === canonical(run.modelTokens)),
    sdkEventsSha256: hash(fs.readFileSync(path.join(directory, prefix, 'events.json'))), guardLogSha256: hash(logBytes) });
}
const report = { schema: 'ig5-memory-resume-audit-v1', datasetSha256: plan.datasetSha256, testedDriverSha256: plan.driverSha256,
  auditorSha256: hash(fs.readFileSync(new URL(import.meta.url))), expectedTrials: 9, observedTrials: certificates.length,
  complete: certificates.length === 9, consistent: certificates.every(c => c.verdictMatchesDriver && c.driverAccountingMatches), certificates,
  limits: 'Independent replay of frozen source observations and raw SDK receipts; one synthetic task and simulated compaction. Elapsed time and child cleanup are retained driver receipts, not independent OS attestations.' };
fs.writeFileSync(path.join(directory, 'independent-audit.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify({ complete: report.complete, consistent: report.consistent, trials: certificates.length, passed: certificates.filter(c => c.pass).length }));
if (!report.consistent) process.exitCode = 1;
