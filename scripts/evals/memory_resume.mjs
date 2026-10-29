import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { LcmMemory, digest } from '../../source/lcm_memory.js';
import { memoryResumeFixture, assessMemoryResume } from './memory_resume_fixture.mjs';

const output = path.resolve(process.argv[2]);
assert(!fs.existsSync(output), 'Use a new output directory; never replace a prior trial');
fs.mkdirSync(output, { recursive: true });
const data = memoryResumeFixture(), raw = data.events.map(e => JSON.stringify(e)).join('\n');
const dataset = path.join(output, 'dataset.json');
fs.writeFileSync(dataset, JSON.stringify(data, null, 2));
const implementations = {};
for (const relative of ['source/lcm_memory.js', 'source/lcm_bridge.js', 'source/investigation_resume.js', 'scripts/evals/memory_resume.mjs', 'scripts/evals/memory_resume_fixture.mjs', 'scripts/evals/memory_resume_guard.mjs', 'scripts/evals/memory_resume_model.mjs']) {
  const content = fs.readFileSync(new URL('../../' + relative, import.meta.url));
  implementations[relative] = digest(content);
  const destination = path.join(output, 'implementation', relative); fs.mkdirSync(path.dirname(destination), { recursive: true }); fs.writeFileSync(destination, content);
}
const results = [];
for (const variant of ['raw-log', 'lcm', 'brief-lcm']) for (let repetition = 1; repetition <= 3; repetition++) {
  const runRoot = path.join(output, `${variant}-deterministic-${repetition}`), options = { root: runRoot, sessionId: 'replay', workspace: output };
  let store = await LcmMemory.open(options);
  for (const event of data.events) await store.capture(event);
  store.close(); store = await LcmMemory.open(options);
  const calls = [], texts = []; let returnedBytes = 0; const started = performance.now();
  const record = (args, result) => { calls.push(args); returnedBytes += Buffer.byteLength(JSON.stringify(result)); return result; };
  try {
    record({ action: variant === 'brief-lcm' ? 'brief' : 'task' }, variant === 'brief-lcm' ? data.brief : { taskId: data.task.taskId, goal: data.task.goal });
    if (variant === 'raw-log') {
      for (let offset = 0; offset < raw.length; offset += 2048) texts.push(record({ action: 'log', offset }, { text: raw.slice(offset, offset + 2048) }).text);
    } else {
      const queries = variant === 'brief-lcm'
        ? record({ action: 'resume' }, data.navigation).gaps.map(gap => gap.search.memory.query)
        : ['SEMANTIC_COUNTEREXAMPLE', 'return-equivalence', 'matched-listed-inputs'];
      for (const query of queries) {
        const hit = record({ action: 'search', query }, store.search(query, 3)).hits[0]; assert(hit, query);
        let offset = 0, text = '';
        do { const page = record({ action: 'read', ref: hit.ref, offset }, store.read(hit.ref, { offset })); text += page.text; offset = page.nextOffset; } while (offset !== null);
        assert.equal(digest(text), hit.ref.sha256); texts.push(text);
      }
    }
    const current = record({ action: 'current' }, data.current);
    const recovered = variant === 'raw-log' ? texts.join('').split('\n').map(JSON.parse) : texts.map(JSON.parse);
    const constraint = recovered.find(e => e.data?.constraints)?.data.constraints;
    const counterexample = recovered.find(e => e.data?.observed?.counterexample)?.data.observed;
    const answer = { accepted: false, inputDomain: constraint?.inputDomain, counterexample: counterexample?.counterexample,
      pathCondition: counterexample?.pathCondition, sideEffects: current.sideEffects, currentRevision: current.dbRevision,
      nextAction: 'change-experiment', historicalAuthorization: constraint?.historicalAuthorization };
    const assessment = assessMemoryResume(answer, data, calls); assert(assessment.pass);
    results.push({ variant, repetition, assessment, toolCalls: calls.length, returnedBytes, elapsedMs: performance.now() - started, withinBudget: calls.length <= 20 && returnedBytes <= 65536, archiveReopened: true });
  } finally { store.close(); }
}
const report = { schema: 'ig5-memory-resume-replay-v1', datasetSha256: digest(fs.readFileSync(dataset)), implementations,
  budget: { toolCalls: 20, returnedBytes: 65536, elapsedMs: 120000 }, repetitions: 3, results,
  modelEffectivenessAssessed: false,
  limitations: ['Synthetic fixed investigation with an intentionally lossy compaction marker; not actual model compaction.', 'Deterministic readers and known keyword queries only test information recovery and accounting; no model task-success claim.', 'Same frozen inputs and limits; archive creation/indexing costs excluded from retrieval and must not be described as free.', 'No target execution or execution permission restoration.'] };
fs.writeFileSync(path.join(output, 'deterministic.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify({ deterministic: results.map(r => ({ variant: r.variant, repetition: r.repetition, calls: r.toolCalls, bytes: r.returnedBytes, pass: r.assessment.pass })) }));
if (process.argv.includes('--models')) {
  const { runMemoryResumeModels } = await import('./memory_resume_model.mjs');
  await runMemoryResumeModels(output, dataset);
}
