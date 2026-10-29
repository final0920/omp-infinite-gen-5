import assert from 'node:assert/strict';
import { test } from 'node:test';
import { analyzeProtocolState, PROTOCOL_STATE_LIMITS } from '../source/protocol_state.js';
import { jsonToolOutput } from '../source/json_output.js';

const event = (symbol, direction = 'client_to_server', more = {}) => ({ symbol, direction, ...more });
const trace = (id, symbols, more = {}) => ({ id, start: 'session-start', complete: true, events: symbols.map(item => typeof item === 'string' ? event(item) : item), ...more });
const request = (manifest, state_model = {}) => ({ action: 'state_infer', data: Buffer.from(JSON.stringify({ version: 1, ...manifest })).toString('hex'), encoding: 'hex', state_model });
const infer = (traces, holdout = [], opts = {}) => analyzeProtocolState(request({ traces, holdout }, opts)).state;
const invalid = (fn, code = 'INVALID_PROTOCOL_STATE') => assert.throws(fn, error => error.code === code);

test('explicit directional observations produce deterministic prefix states with trace/source provenance', () => {
  const source = '11111111-1111-1111-1111-111111111111:request:' + 'a'.repeat(64);
  const rows = [trace('first', [event('HELLO', 'client_to_server', { sourceId: source }), event('OK', 'server_to_client')], { sourceId: 'capture-source', session_id: 'app-session-A' }), trace('second', ['HELLO', 'BYE'])];
  const result = infer(rows);
  assert.equal(result.observedModel.states.length, 4); assert.equal(result.observedModel.deterministic, true);
  assert.equal(result.observedModel.states[0].transitions.length, 1);
  assert.equal(result.observedModel.states[0].transitions[0].observations.length, 2);
  assert.equal(result.coverage.observedEvents, 4); assert.equal(result.training[0].events[0].sourceId, source);
  assert.equal(result.training[0].session_id, 'app-session-A');
  assert.deepEqual(jsonToolOutput(result), result);
  assert.deepEqual(infer(rows), result); // Exact observations and insertion order produce stable digests.
});

test('holdout is never inserted and reports accepted/rejected/unknown with bounded counterexamples', () => {
  const train = [trace('a', ['A', event('B', 'server_to_client')])];
  const base = infer(train);
  const checked = infer(train, [trace('match', ['A', event('B', 'server_to_client')]), trace('wrong', ['A', 'B']), trace('partial', ['A'], { complete: false }), trace('unbounded', ['A'], { start: 'unknown' }), trace('termination', ['A'])]);
  assert.equal(checked.modelDigest, base.modelDigest);
  assert.deepEqual(checked.holdout.traces.map(row => row.status), ['accepted', 'rejected', 'unknown', 'unknown', 'rejected']);
  assert.equal(checked.holdout.traces[1].counterexample.eventIndex, 1);
  assert.equal(checked.holdout.traces[1].counterexample.direction, 'client_to_server');
  assert.equal(checked.holdout.traces[4].counterexample.kind, 'end-of-trace');
  assert.equal(checked.holdout.traces[0].independence.independent, null);
  assert.equal(checked.holdout.traces[0].independence.duplicateBehavior, true);
  assert.equal(checked.holdout.independentCollectionProven, false);
});

test('incomplete events cut training at the gap and do not bridge later events', () => {
  const result = infer([trace('gap', ['A', event('missing', 'server_to_client', { complete: false }), 'must-not-connect'])], [trace('new-tail', ['A', 'X']), trace('partial-end', ['A'])]);
  assert.equal(result.observedModel.states.length, 2);
  assert.equal(result.coverage.observedEvents, 1); assert.equal(result.coverage.excludedEvents, 2);
  assert(!JSON.stringify(result.observedModel).includes('must-not-connect'));
  assert(result.holdout.traces.every(row => row.status === 'unknown'));
  assert.equal(result.observedModel.states[1].accepting, false);
});

test('unknown application starts are retained as excluded evidence and cannot create root paths', () => {
  const result = infer([trace('midstream', ['A', 'B'], { start: 'unknown' })], [trace('probe', ['A'])]);
  assert.equal(result.coverage.includedTraces, 0); assert.equal(result.observedModel.states.length, 1);
  assert.equal(result.holdout.traces[0].status, 'unknown');
  invalid(() => infer([{ id: 'implicit', complete: true, events: [] }]));
});

test('partial frontiers persist beyond matching edges, while observed complete paths still accept', () => {
  const training = [trace('partial-A', ['A'], { complete: false }), trace('complete-AXYZ', ['A', 'X', 'Y', 'Z'])];
  const holdout = [trace('one-known-edge', ['A', 'X', 'Q']), trace('two-known-edges', ['A', 'X', 'Y', 'Q']), trace('unobserved-end', ['A', 'X']), trace('observed-end', ['A', 'X', 'Y', 'Z'])];
  const result = infer(training, holdout, { merge: 'future-equivalent', merge_depth: 1 });
  for (const replay of [result.holdout, result.mergedHoldout]) {
    assert.deepEqual(replay.traces.map(row => row.status), ['unknown', 'unknown', 'unknown', 'accepted']);
    assert(replay.traces.slice(0, 3).every(row => row.reason === 'unobserved-partial-frontier'));
  }
  assert.equal(result.holdout.traces[3].reason, 'observed-complete-path');
  assert.equal(result.mergedHoldout.traces[3].reason, 'fits-merged-hypothesis');
});

test('future-equivalence merges are separate hypotheses with competing targets retained', () => {
  const train = [trace('branch-a', ['A', 'X', 'Y']), trace('branch-b', ['B', 'X', 'Z'])];
  const result = infer(train, [trace('novel-combination', ['A', 'X', 'Z'])], { merge: 'future-equivalent', merge_depth: 1 });
  assert.equal(result.holdout.traces[0].status, 'rejected');
  assert.equal(result.mergedHoldout.traces[0].status, 'accepted');
  assert.equal(result.mergedHoldout.traces[0].reason, 'fits-merged-hypothesis');
  assert.equal(result.mergedHoldout.traces[0].nondeterministic, true);
  assert.equal(result.mergedHypothesis.hypothesis, true);
  assert.equal(result.mergedHypothesis.deterministic, false);
  assert(result.mergedHypothesis.nondeterministicTransitions > 0);
  assert(result.mergedHypothesis.states.some(state => state.transitions.some(edge => edge.targets.length > 1)));
  assert.equal(result.mergedHoldout.traces[0].independence.independent, null);
  assert.equal(result.modelDigest, infer(train).modelDigest);
});

test('training overlaps include identifiers, application sessions and source evidence', () => {
  const training = [trace('original', ['A'], { session_id: 'session1', sourceId: 'source1' }), trace('second', [event('B', 'client_to_server', { evidence: { captureId: 'capture-1', sha256: 'a'.repeat(64) } })])];
  const checked = infer(training, [trace('original', ['X']), trace('new-session', ['Y'], { session_id: 'session1' }), trace('new-data', [event('C', 'client_to_server', { evidence: { captureId: 'capture-1' } })]), trace('no-observed-overlap', ['Q'])]);
  assert.deepEqual(checked.holdout.traces.map(row => row.independence.independent), [false, false, false, null]);
  assert.equal(checked.holdout.overlapDetected, 3);
});

test('identical content and behavior with distinct acquisition IDs is not provenance overlap', () => {
  const data = 'a'.repeat(64);
  const source = id => trace(id, [event('A', 'client_to_server', { sourceId: `${id}:request`, evidence: { captureId: id, bodySha256: data, bodyRef: `sha256:${data}` } })]);
  const result = infer([source('capture-a')], [source('capture-b')]);
  const checked = result.holdout.traces[0];
  assert.equal(checked.status, 'accepted');
  assert.equal(checked.independence.independent, null);
  assert.equal(checked.independence.status, 'no-overlap-observed');
  assert.equal(checked.independence.duplicateBehavior, true);
  assert.equal(checked.independence.repeatedContent, true);
  assert.equal(result.holdout.overlapDetected, 0);
});

test('saved-model replay reconstructs exact model and rejects digest or producer tampering', () => {
  const state = infer([trace('a', ['A', 'B'])], [], { merge: 'future-equivalent' });
  const base = request({ traces: [trace('held', ['A', 'B'])] }, { result_id: 'saved-report' });
  base.action = 'state_validate';
  base.prior = { training: state.training, options: state.options, observedDigest: state.modelDigest, mergedDigest: state.mergedDigest, resultId: 'saved-report' };
  const value = analyzeProtocolState(base).state;
  assert.equal(value.holdout.accepted, 1); assert.equal(value.sourceResultId, 'saved-report');
  assert.equal(value.observedModel, undefined);
  invalid(() => analyzeProtocolState({ ...base, prior: { ...base.prior, observedDigest: 'b'.repeat(64) } }));
  invalid(() => analyzeProtocolState({ ...base, state_model: { ...base.state_model, merge: 'none' } }));
});

test('explicit byte, trace, event, state and work budgets fail without partial model claims', () => {
  invalid(() => infer([trace('a', []), trace('b', [])], [], { max_traces: 1 }), 'PROTOCOL_STATE_LIMIT');
  invalid(() => infer([trace('a', ['A', 'B'])], [], { max_events: 1 }), 'PROTOCOL_STATE_LIMIT');
  invalid(() => infer([trace('a', ['A', 'B'])], [], { max_states: 2 }), 'PROTOCOL_STATE_LIMIT');
  invalid(() => infer([trace('a', Array.from({ length: 101 }, (_, index) => String(index)))], [], { max_work: 100 }), 'PROTOCOL_STATE_LIMIT');
  invalid(() => analyzeProtocolState({ action: 'state_infer', encoding: 'hex', data: '00'.repeat(PROTOCOL_STATE_LIMITS.inputBytes + 1) }), 'PROTOCOL_STATE_LIMIT');
  invalid(() => infer([trace('a', [])], [], { max_states: -0 }));
});

test('malformed JSON, UTF8, nesting, field types and untrusted extra metadata fail closed', () => {
  for (const bytes of [Buffer.from('{'), Buffer.from([0xff]), Buffer.from('\ufeff{"version":1,"traces":[]}')]) invalid(() => analyzeProtocolState({ action: 'state_infer', encoding: 'hex', data: bytes.toString('hex') }));
  invalid(() => analyzeProtocolState({ action: 'state_infer', encoding: 'hex', data: Buffer.from('['.repeat(17) + ']'.repeat(17)).toString('hex') }), 'PROTOCOL_STATE_LIMIT');
  invalid(() => infer([trace('a', [], { complete: 'true' })]));
  invalid(() => infer([trace('a', [event('A', 'unknown')])]));
  invalid(() => infer([trace('a', [event('A', 'client_to_server', { evidence: { rawBody: 'do-not-echo' } })])]));
  invalid(() => infer([trace('a', [])], [], { unbounded: true }));
  invalid(() => infer([trace('same', []), trace('same', [])]));
  invalid(() => infer([trace('a', ['A'.repeat(129)])]));
  for (const json of ['{"version":1,"version":1,"traces":[]}', '{"version":1,"traces":[],"tr\\u0061ces":[]}']) invalid(() => analyzeProtocolState({ action: 'state_infer', encoding: 'hex', data: Buffer.from(json).toString('hex') }));
});

test('schemaVersion manifests and Unicode labels are supported without executing symbol text', () => {
  const payload = 'globalThis.ig5StateExecuted=true';
  const value = analyzeProtocolState({ action: 'state_infer', encoding: 'hex', data: Buffer.from(JSON.stringify({ schemaVersion: 'ig5.protocol-traces.v1', traces: [trace('会话', [payload, '响应🙂'])] })).toString('hex') });
  assert.equal(globalThis.ig5StateExecuted, undefined);
  assert.equal(value.state.coverage.observedEvents, 2);
  assert.deepEqual(jsonToolOutput(value), value);
});
