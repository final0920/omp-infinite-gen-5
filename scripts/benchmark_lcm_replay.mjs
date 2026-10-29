// Deterministic retrieval experiment, NOT a language-model accuracy benchmark.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import assert from 'node:assert/strict';
import { LcmMemory, digest, LCM_REVISION } from '../source/lcm_memory.js';

const output = path.resolve(process.argv[2] || fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-lcm-replay-')));
fs.mkdirSync(output, { recursive: true });
const opts = { root: path.join(output, 'store'), sessionId: 'deterministic-replay-v1', workspace: output };
assert(!fs.existsSync(opts.root), 'Use a fresh output directory to avoid timing an existing index');
const events = [], queries = [];
let seq = 0, previous = null;
const t0 = performance.now(); let store = await LcmMemory.open(opts); const openMs = performance.now() - t0;
const captureStart = performance.now();
for (let batch = 0; batch < 16; batch++) {
  const sourceSeqs = previous === null ? [] : [previous];
  for (let n = 0; n < 64; n++) {
    const key = `guardcase${batch.toString().padStart(2,'0')}${n.toString().padStart(2,'0')}`;
    const data = { key, targetSha256: digest('fixture'), run: batch, dbRevision: n, address: '0xfffffffffffffff0',
      exactCondition: `x == 0x${digest(key).slice(0,16)} && carry == 0`, conclusion: 'unknown', counterexample: digest(key + ':counterexample'),
      unrelatedTrace: '01: LOAD64 r0,[r1]; alias unresolved. '.repeat(60) };
    const event = { seq: seq++, type: 'tool/result', data };
    events.push(event); sourceSeqs.push(event.seq); await store.capture(event);
    if (n === 3 || n === 47) queries.push({ key, expected: data.exactCondition });
  }
  const summary = { seq: seq++, type: 'compaction/summary', data: { summary: `Completed batch ${batch}; hypotheses remain unverified. Exact guards deliberately omitted in this synthetic fixture.`, shadowedSeqs: sourceSeqs } };
  events.push(summary); await store.capture(summary); previous = summary.seq;
}
const captureMs = performance.now() - captureStart;
const raw = events.map(e => JSON.stringify(e)).join('\n') + '\n';
fs.writeFileSync(path.join(output, 'corpus.jsonl'), raw);
store.close(); const re0 = performance.now(); store = await LcmMemory.open(opts); const reopenMs = performance.now() - re0;
const visited = new Set(), leaves = new Set();
function visit(ref) {
  const key = ref.kind + ':' + ref.id; if (visited.has(key)) return; visited.add(key);
  if (ref.kind === 'event') { leaves.add(ref.id); return; }
  let offset = 0;
  do { const page = store.expand(ref, { offset, limit: 32 }); assert.equal(page.directSourcesComplete, true); page.refs.forEach(visit); offset = page.nextOffset; } while (offset !== null);
}
visit(store.restore().summaries[0]); assert.equal(leaves.size, 1024);
let recovered = 0, returnedBytes = 0, readCalls = 0;
const retrievalStart = performance.now();
for (const query of queries) {
  const results = store.search(query.key, 4); returnedBytes += Buffer.byteLength(JSON.stringify(results));
  const ref = results.hits[0]?.ref; assert(ref, query.key);
  let text = '', offset = 0;
  do { const page = store.read(ref, { offset }); text += page.text; returnedBytes += Buffer.byteLength(JSON.stringify(page)); readCalls++; offset = page.nextOffset; } while (offset !== null);
  assert.equal(digest(text), ref.sha256);
  if (JSON.parse(text).data.exactCondition === query.expected) recovered++;
}
const retrievalMs = performance.now() - retrievalStart;
const scanStart = performance.now(); let scanRecovered = 0;
// DSH already has raw logs: measure a simple existing-log alternative honestly.
for (const query of queries) {
  const row = raw.split('\n').find(line => line.includes(`"key":"${query.key}"`));
  if (row && JSON.parse(row).data.exactCondition === query.expected) scanRecovered++;
}
const scanMs = performance.now() - scanStart;
const finalSummary = events.at(-1).data.summary;
const status = store.status(); store.db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); store.close();
function bytes(dir) { return fs.readdirSync(dir, { withFileTypes: true }).reduce((n,d) => n + (d.isDirectory() ? bytes(path.join(dir,d.name)) : fs.statSync(path.join(dir,d.name)).size), 0); }
const report = { schema: 'ig5-lcm-deterministic-replay-v1', timestamp: new Date().toISOString(), upstreamRevision: LCM_REVISION,
  implementation: Object.fromEntries(['source/lcm_memory.js', 'source/lcm_bridge.js', 'scripts/benchmark_lcm_replay.mjs', 'third_party/lcm/core.mjs'].map(file => [file, digest(fs.readFileSync(new URL('../' + file, import.meta.url)))])),
  environment: { node: process.version, platform: process.platform, arch: process.arch }, corpus: { events: events.length, rawEvidenceEvents: 1024, compactions: 16, queries: queries.length, bytes: Buffer.byteLength(raw), sha256: digest(raw) },
  results: { summaryOnlyExactFactsPresent: queries.filter(q => finalSummary.includes(q.expected)).length, lcmExactRecovered: recovered, existingRawLogScanRecovered: scanRecovered, recursivelyReachableEvidence: leaves.size, readCalls, retrievalReturnedBytes: returnedBytes, logicalStoredBytes: status.bytes, physicalStorageBytes: bytes(opts.root) },
  timingsMs: { open: openMs, capture: captureMs, reopen: reopenMs, indexedQueriesAndReads: retrievalMs, simpleRawLogScans: scanMs },
  limitations: ['Synthetic summaries intentionally omit the query facts; 0 vs 32 is information availability, not measured model accuracy.', 'DSH raw logs can also recover 32/32. LCM provides structured scoped navigation, lineage and bounded reads; superiority over an optimized native log index is not proved.', 'One local run, warm filesystem cache; no tokenizer/model calls, real reverse target, money savings or task success measurement.'] };
assert.equal(recovered, queries.length); assert.equal(scanRecovered, queries.length);
fs.writeFileSync(path.join(output, 'report.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify({ report: path.join(output, 'report.json'), ...report.results, timingsMs: report.timingsMs }));
