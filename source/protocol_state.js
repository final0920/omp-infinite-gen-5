import { createHash } from 'node:crypto';

// Observation models are finite evidence summaries, never recovered server internals.
export const PROTOCOL_STATE_LIMITS = Object.freeze({ inputBytes: 1048576, traces: 256, events: 8192, states: 4096, work: 2000000, jsonDepth: 16, jsonTokens: 131072 });
const DIRECTIONS = ['client_to_server', 'server_to_client'];
const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
const invalid = message => fail('INVALID_PROTOCOL_STATE', message);
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
function object(value, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid(`${name} must be an object`);
  if (Object.values(Object.getOwnPropertyDescriptors(value)).some(item => item.get || item.set)) invalid(`${name} must not contain accessors`);
  return value;
}
function keys(value, allowed, name) { object(value, name); if (Object.keys(value).some(key => !allowed.includes(key))) invalid(`${name} has an unsupported field`); }
function integer(value, minimum, maximum, name) {
  if (!Number.isSafeInteger(value) || Object.is(value, -0) || value < minimum || value > maximum) invalid(`${name} is outside its integer budget`);
  return value;
}
function label(value, name, maximum = 256) {
  if (typeof value !== 'string' || !value.length || value.length > maximum || /[\x00-\x1f\x7f]/.test(value) || /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/u.test(value)) invalid(`${name} must be a bounded printable label`);
  return value;
}
function options(value = {}) {
  keys(value, ['result_id', 'model', 'merge', 'merge_depth', 'max_traces', 'max_events', 'max_states', 'max_work'], 'state_model');
  if (value.merge !== undefined && !['none', 'future-equivalent'].includes(value.merge)) invalid('Unknown state merge method');
  if (value.model !== undefined && !['prefix-tree', 'merged-hypothesis'].includes(value.model)) invalid('Unknown state model selection');
  if (value.result_id !== undefined) label(value.result_id, 'result_id');
  return { merge: value.merge ?? 'none', merge_depth: integer(value.merge_depth ?? 2, 1, 3, 'merge_depth'),
    max_traces: integer(value.max_traces ?? 64, 1, PROTOCOL_STATE_LIMITS.traces, 'max_traces'),
    max_events: integer(value.max_events ?? 4096, 1, PROTOCOL_STATE_LIMITS.events, 'max_events'),
    max_states: integer(value.max_states ?? 2048, 2, PROTOCOL_STATE_LIMITS.states, 'max_states'),
    max_work: integer(value.max_work ?? 1000000, 100, PROTOCOL_STATE_LIMITS.work, 'max_work') };
}
class Budget {
  constructor(limits) { this.limits = limits; this.work = 0; }
  use(count = 1) { this.work += count; if (this.work > this.limits.max_work) fail('PROTOCOL_STATE_LIMIT', 'State analysis work budget reached; no model was committed'); }
}

function parseManifest(data, encoding) {
  if (encoding !== 'hex' || typeof data !== 'string') invalid('State input requires explicit hex-encoded JSON bytes');
  if (data.length > PROTOCOL_STATE_LIMITS.inputBytes * 2) fail('PROTOCOL_STATE_LIMIT', 'State trace manifest exceeds 1 MiB');
  if (data.length % 2 || !/^[a-f0-9]*$/i.test(data)) invalid('State input requires complete hex-encoded bytes');
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(Buffer.from(data, 'hex')); } catch { invalid('State manifest must be strict UTF-8'); }
  // Reject nesting and lexical budgets before JSON.parse can allocate a deep object.
  let quoted = false, escape = false, depth = 0, tokens = 0, stringStart = 0;
  const stack = [];
  for (let index = 0; index < text.length; index++) {
    const c = text[index];
    if (quoted) {
      if (escape) escape = false;
      else if (c === '\\') escape = true;
      else if (c === '"') {
        quoted = false;
        const frame = stack.at(-1);
        if (frame?.kind === '{' && frame.expectKey) {
          let key; try { key = JSON.parse(text.slice(stringStart, index + 1)); } catch { invalid('State manifest is not valid JSON'); }
          if (frame.keys.has(key)) invalid('State manifest contains a duplicate object key');
          frame.keys.add(key);
        }
      }
      continue;
    }
    if (c === '"') { quoted = true; stringStart = index; tokens++; }
    else if (c === '{' || c === '[') { depth++; tokens++; stack.push({ kind: c, expectKey: c === '{', keys: new Set() }); if (depth > PROTOCOL_STATE_LIMITS.jsonDepth) fail('PROTOCOL_STATE_LIMIT', 'State manifest nesting budget reached'); }
    else if (c === '}' || c === ']') { depth--; stack.pop(); }
    else if (c === ',' || c === ':') { tokens++; const frame = stack.at(-1); if (frame?.kind === '{') frame.expectKey = c === ','; }
    if (tokens > PROTOCOL_STATE_LIMITS.jsonTokens) fail('PROTOCOL_STATE_LIMIT', 'State manifest token budget reached');
  }
  let value; try { value = JSON.parse(text); } catch { invalid('State manifest is not valid JSON'); }
  keys(value, ['version', 'schemaVersion', 'traces', 'holdout'], 'manifest');
  if (value.version !== 1 && value.schemaVersion !== 'ig5.protocol-traces.v1' || value.version !== undefined && value.version !== 1 || value.schemaVersion !== undefined && value.schemaVersion !== 'ig5.protocol-traces.v1') invalid('State trace manifest version is unsupported');
  return value;
}
function evidence(value) {
  keys(value, ['captureId', 'sha256', 'ref', 'result_id', 'bodyRef', 'bodySha256', 'requestSha256', 'responseSha256', 'sourceIds'], 'event evidence');
  const copy = {};
  for (const [key, item] of Object.entries(value)) {
    if (key === 'sourceIds') {
      if (!Array.isArray(item) || item.length > 16) invalid('Evidence sourceIds must be a bounded array');
      copy[key] = item.map(id => label(id, 'evidence source ID'));
    } else {
      copy[key] = label(item, 'evidence identifier');
      if (/sha256/i.test(key) && !/^[a-f0-9]{64}$/.test(item)) invalid('Evidence digest must be lowercase SHA-256');
      if (['ref', 'bodyRef'].includes(key) && !/^sha256:[a-f0-9]{64}$/.test(item)) invalid('Evidence reference must be a SHA-256 ref');
    }
  }
  return copy;
}
function traces(value, limits, counter, name) {
  if (!Array.isArray(value)) invalid(`${name} must be an array`);
  counter.traces += value.length;
  if (counter.traces > limits.max_traces) fail('PROTOCOL_STATE_LIMIT', 'State trace count budget reached');
  const ids = new Set();
  return value.map(trace => {
    keys(trace, ['id', 'session_id', 'sourceId', 'start', 'complete', 'events'], 'trace');
    const id = label(trace.id, 'trace ID', 128);
    if (ids.has(id)) invalid('Trace IDs must be unique within each partition'); ids.add(id);
    if (!['session-start', 'unknown'].includes(trace.start)) invalid('Each trace requires an explicit application-session start declaration');
    if (typeof trace.complete !== 'boolean') invalid('Each trace requires explicit completeness');
    if (!Array.isArray(trace.events)) invalid('Trace events must be an array');
    counter.events += trace.events.length;
    if (counter.events > limits.max_events) fail('PROTOCOL_STATE_LIMIT', 'State event count budget reached');
    const result = { id, start: trace.start, complete: trace.complete };
    for (const key of ['sourceId', 'session_id']) if (trace[key] !== undefined) result[key] = label(trace[key], key);
    result.events = trace.events.map(event => {
      keys(event, ['direction', 'symbol', 'sourceId', 'complete', 'evidence'], 'event');
      if (!DIRECTIONS.includes(event.direction)) invalid('Event direction must be explicit client_to_server or server_to_client');
      if (event.complete !== undefined && typeof event.complete !== 'boolean') invalid('Event completeness must be boolean');
      const item = { direction: event.direction, symbol: label(event.symbol, 'event symbol', 128), complete: event.complete ?? true };
      if (event.sourceId !== undefined) item.sourceId = label(event.sourceId, 'event source ID');
      if (event.evidence !== undefined) item.evidence = evidence(event.evidence);
      return item;
    });
    return result;
  });
}
const token = event => JSON.stringify([event.direction, event.symbol]);
function buildModel(training, limits, budget) {
  const nodes = [{ id: 'p0', accepting: false, openEnd: false, terminalTraceIds: [], transitions: [], _edges: new Map() }];
  let includedTraces = 0, observedEvents = 0, excludedEvents = 0;
  const excluded = [];
  for (const trace of training) {
    budget.use();
    if (trace.start !== 'session-start') { excluded.push({ traceId: trace.id, reason: 'unknown-session-start', excludedEvents: trace.events.length }); excludedEvents += trace.events.length; continue; }
    includedTraces++; let node = nodes[0], complete = trace.complete;
    for (let i = 0; i < trace.events.length; i++) {
      budget.use(); const event = trace.events[i];
      if (!event.complete) { complete = false; excludedEvents += trace.events.length - i; excluded.push({ traceId: trace.id, reason: 'incomplete-event-and-following-events', eventIndex: i, excludedEvents: trace.events.length - i }); break; }
      const key = token(event); let edge = node._edges.get(key);
      if (!edge) {
        if (nodes.length >= limits.max_states) fail('PROTOCOL_STATE_LIMIT', 'Observed prefix tree exceeds state budget; no model was committed');
        const child = { id: `p${nodes.length}`, accepting: false, openEnd: false, terminalTraceIds: [], transitions: [], _edges: new Map() };
        nodes.push(child); edge = { direction: event.direction, symbol: event.symbol, targets: [child.id], observations: [] }; node._edges.set(key, edge); node.transitions.push(edge);
      }
      edge.observations.push({ traceId: trace.id, eventIndex: i }); node = nodes[Number(edge.targets[0].slice(1))]; observedEvents++;
    }
    if (complete) { node.accepting = true; node.terminalTraceIds.push(trace.id); } else node.openEnd = true;
  }
  for (const node of nodes) { delete node._edges; node.transitions.sort((a, b) => token(a) < token(b) ? -1 : token(a) > token(b) ? 1 : 0); }
  if (!includedTraces) nodes[0].openEnd = true;
  return { model: { schemaVersion: 'ig5.observed-state-model.v1', kind: 'prefix-tree', startState: 'p0', deterministic: true, states: nodes },
    coverage: { trainingTraces: training.length, includedTraces, excludedTraces: training.length - includedTraces, observedEvents, excludedEvents, excluded } };
}

function mergeModel(model, depth, budget) {
  const byId = new Map(model.states.map(state => [state.id, state]));
  // Intern depth-limited future signatures. Integer child classes avoid exponentially
  // repeated signature strings. Terminal and partial endpoints are never conflated.
  let classes = new Map(model.states.map(state => [state.id, `${Number(state.accepting)}:${Number(state.openEnd)}`]));
  for (let round = 0; round < depth; round++) {
    const signatures = new Map(), next = new Map();
    for (const state of model.states) {
      budget.use(1 + state.transitions.length);
      const signature = JSON.stringify([state.accepting, state.openEnd, state.transitions.map(edge => [token(edge), classes.get(edge.targets[0])])]);
      if (!signatures.has(signature)) signatures.set(signature, signatures.size);
      next.set(state.id, signatures.get(signature));
    }
    classes = next;
  }
  const groups = new Map(), stateMap = {};
  for (const state of model.states) {
    budget.use(); const key = classes.get(state.id);
    if (!groups.has(key)) groups.set(key, { id: `m${groups.size}`, accepting: state.accepting, openEnd: state.openEnd, terminalTraceIds: [], members: [], transitions: [], _edges: new Map() });
    const merged = groups.get(key); merged.members.push(state.id); merged.terminalTraceIds.push(...state.terminalTraceIds); stateMap[state.id] = merged.id;
  }
  let conflicts = 0;
  for (const group of groups.values()) {
    for (const member of group.members) for (const edge of byId.get(member).transitions) {
      budget.use(1 + edge.observations.length); const key = token(edge);
      let merged = group._edges.get(key);
      if (!merged) { merged = { direction: edge.direction, symbol: edge.symbol, targets: [], observations: [] }; group._edges.set(key, merged); group.transitions.push(merged); }
      const target = stateMap[edge.targets[0]];
      if (!merged.targets.includes(target)) merged.targets.push(target);
      merged.observations.push(...edge.observations);
    }
    for (const edge of group.transitions) if (edge.targets.length > 1) conflicts++;
    delete group._edges;
  }
  return { schemaVersion: 'ig5.observed-state-model.v1', kind: 'merged-hypothesis', method: 'bounded-future-equivalence', mergeDepth: depth,
    hypothesis: true, startState: stateMap[model.startState], deterministic: conflicts === 0, nondeterministicTransitions: conflicts,
    mergedStates: model.states.length - groups.size, states: [...groups.values()], stateMap,
    limitation: 'Equal observed futures up to the chosen depth are a merge hypothesis; unseen futures and hidden server state remain unknown. All competing targets are retained.' };
}
function fingerprint(trace) { return digest(trace.events.map(event => [event.direction, event.symbol, event.complete])); }
function sourceTokens(trace) {
  const result = new Set();
  for (const key of ['sourceId', 'session_id']) if (trace[key]) result.add(`${key}:${trace[key]}`);
  for (const event of trace.events) {
    if (event.sourceId) result.add(`sourceId:${event.sourceId}`);
    for (const [key, value] of Object.entries(event.evidence || {})) {
      if (key === 'sourceIds') for (const id of value) result.add(`sourceId:${id}`);
      else if (['captureId', 'result_id'].includes(key)) result.add(`${key}:${value}`);
    }
  }
  return result;
}
function independence(training, trace, budget) {
  const reasons = new Set(), sources = sourceTokens(trace), sequence = fingerprint(trace);
  const content = row => new Set(row.events.flatMap(event => Object.entries(event.evidence || {}).filter(([key]) => /sha256/i.test(key) || ['ref', 'bodyRef'].includes(key)).map(([key, value]) => `${key}:${value}`)));
  const holdoutContent = content(trace);
  let duplicateBehavior = false, repeatedContent = false;
  for (const train of training) {
    budget.use(1 + train.events.length);
    if (train.id === trace.id) reasons.add('trace-id-overlap');
    if (fingerprint(train) === sequence) duplicateBehavior = true;
    for (const source of sourceTokens(train)) { budget.use(); if (sources.has(source)) reasons.add('source-evidence-overlap'); }
    for (const item of content(train)) { budget.use(); if (holdoutContent.has(item)) repeatedContent = true; }
  }
  return { independent: reasons.size ? false : null, status: reasons.size ? 'overlap-detected' : 'no-overlap-observed', reasons: [...reasons],
    duplicateBehavior, repeatedContent,
    note: 'Repeated symbols or content hashes do not prove reused observations. Duplicate behavior adds no new behavior coverage. Distinct IDs or absence of detected overlap do not prove independent collection or session separation.' };
}
function replay(model, trace, budget) {
  const byId = new Map(model.states.map(state => [state.id, state]));
  const visitedStates = new Set([model.startState]), visitedEdges = new Set();
  const base = { traceId: trace.id, ...(trace.sourceId ? { sourceId: trace.sourceId } : {}), complete: trace.complete, start: trace.start };
  const finish = (status, reason, eventIndex, active, extra = {}) => ({ ...base, status, reason, consumedEvents: eventIndex,
    reachedStates: [...active].slice(0, 32), reachedStatesTruncated: active.size > 32, coverage: { states: visitedStates.size, transitions: visitedEdges.size }, ...extra });
  let active = new Set([model.startState]), ambiguous = false, openPath = false, encounteredOpenFrontier = false;
  if (trace.start !== 'session-start') return finish('unknown', 'unknown-session-start', 0, active);
  for (let index = 0; index < trace.events.length; index++) {
    const event = trace.events[index];
    if (!event.complete) return finish('unknown', 'incomplete-event', index, active);
    const key = token(event), next = new Set();
    let openMissing = false;
    for (const id of active) {
      budget.use(); const state = byId.get(id); let found = false;
      // A partial observation leaves every longer suffix unresolved. Matching an
      // edge learned from another trace does not close that earlier frontier.
      encounteredOpenFrontier ||= state.openEnd;
      for (let i = 0; i < state.transitions.length; i++) {
        budget.use(); const edge = state.transitions[i];
        if (token(edge) !== key) continue;
        found = true; visitedEdges.add(`${id}:${i}`);
        for (const target of edge.targets) { budget.use(); next.add(target); visitedStates.add(target); }
      }
      if (!found && state.openEnd) openMissing = true;
    }
    openPath ||= openMissing;
    if (!next.size) return finish(!trace.complete || openPath || encounteredOpenFrontier ? 'unknown' : 'rejected', openPath || encounteredOpenFrontier ? 'unobserved-partial-frontier' : 'transition-not-observed', index, active,
      { counterexample: { eventIndex: index, direction: event.direction, symbol: event.symbol, ...(event.sourceId ? { sourceId: event.sourceId } : {}) }, rejectionScope: 'observation-model-only' });
    ambiguous ||= next.size > 1; active = next;
  }
  if (!trace.complete) return finish('unknown', 'trace-end-not-declared-complete', trace.events.length, active);
  const terminal = [...active].filter(id => byId.get(id).accepting).length;
  if (openPath || terminal && terminal !== active.size) return finish('unknown', 'ambiguous-or-partially-observed-futures', trace.events.length, active, { nondeterministic: ambiguous });
  if (terminal) return finish('accepted', model.kind === 'merged-hypothesis' ? 'fits-merged-hypothesis' : 'observed-complete-path', trace.events.length, active, { nondeterministic: ambiguous });
  if (encounteredOpenFrontier || [...active].some(id => byId.get(id).openEnd)) return finish('unknown', 'unobserved-partial-frontier', trace.events.length, active);
  return finish('rejected', 'complete-termination-not-observed', trace.events.length, active, { rejectionScope: 'observation-model-only', counterexample: { eventIndex: trace.events.length, kind: 'end-of-trace' } });
}
function validate(model, training, holdout, budget) {
  const rows = holdout.map(trace => ({ ...replay(model, trace, budget), independence: independence(training, trace, budget) }));
  return { model: model.kind, total: rows.length, accepted: rows.filter(row => row.status === 'accepted').length, rejected: rows.filter(row => row.status === 'rejected').length,
    unknown: rows.filter(row => row.status === 'unknown').length, overlapDetected: rows.filter(row => row.independence.independent === false).length,
    duplicateBehavior: rows.filter(row => row.independence.duplicateBehavior).length,
    independentCollectionProven: false, traces: rows };
}
const LIMITATIONS = [
  'States summarize supplied directional symbol histories, not semantic or hidden server states. Positive observations cannot prove protocol completeness or absence of other valid behavior.',
  'Application-session starts and completeness are caller declarations; TCP connections, HTTP requests and timing do not establish application-session boundaries.',
  'Accepted means a complete path fits this observation model. Rejected means outside this model, not invalid behavior of a real server. Partial, missing-boundary and unresolved competing paths remain unknown.',
  'Symbols and evidence IDs are caller labels. Their meaning and source authenticity are not inferred or independently verified. Holdout observations are never used to build or merge the model.',
];

export function analyzeProtocolState(request) {
  object(request, 'request');
  if (!['state_infer', 'state_validate'].includes(request.action)) invalid('Unsupported protocol state action');
  const supplied = request.state_model ?? {}, limits = options(supplied), manifest = parseManifest(request.data, request.encoding);
  const counter = { traces: 0, events: 0 }, budget = new Budget(limits);
  let training, holdout, buildLimits = limits;
  if (request.action === 'state_infer') {
    if (supplied.result_id !== undefined || supplied.model !== undefined) invalid('Inference does not consume a prior model');
    training = traces(manifest.traces, limits, counter, 'traces'); holdout = traces(manifest.holdout ?? [], limits, counter, 'holdout');
    if (!training.length) invalid('State inference needs at least one explicit training trace');
  } else {
    if (manifest.holdout !== undefined) invalid('Validation uses manifest.traces only; holdout is not a second validation partition');
    if (supplied.merge !== undefined || supplied.merge_depth !== undefined) invalid('Validation cannot change the saved merge hypothesis');
    keys(request.prior, ['training', 'options', 'observedDigest', 'mergedDigest', 'resultId'], 'saved inference');
    const priorOptions = options(request.prior.options);
    buildLimits = { ...priorOptions, max_states: limits.max_states };
    training = traces(request.prior.training, limits, counter, 'saved training'); holdout = traces(manifest.traces, limits, counter, 'validation traces');
  }
  const { model, coverage } = buildModel(training, buildLimits, budget);
  const merged = buildLimits.merge === 'future-equivalent' ? mergeModel(model, buildLimits.merge_depth, budget) : null;
  const observedDigest = digest(model), mergedDigest = merged ? digest(merged) : null;
  if (request.action === 'state_validate' && (observedDigest !== request.prior.observedDigest || mergedDigest !== request.prior.mergedDigest)) invalid('Saved state model reconstruction did not match its evidence digest');
  const selected = supplied.model === 'merged-hypothesis' ? merged : model;
  if (!selected) invalid('The saved inference has no merged hypothesis');
  const holdoutResult = validate(selected, training, holdout, budget);
  const state = { status: 'bounded-observation-model', method: request.action === 'state_validate' && selected.kind === 'merged-hypothesis' ? 'bounded-future-equivalence-replay' : 'deterministic-prefix-tree', coverage,
    holdout: holdoutResult, ambiguity: { stateSemanticsUnknown: true, closedWorld: false, mergeHypothesis: !!merged, nondeterministicTransitions: merged?.nondeterministicTransitions ?? 0 },
    modelDigest: observedDigest, mergedDigest, limits, budget: { work: budget.work, traceCount: counter.traces, eventCount: counter.events }, limitations: LIMITATIONS };
  if (request.action === 'state_infer') {
    if (merged) state.mergedHoldout = validate(merged, training, holdout, budget);
    Object.assign(state, { options: limits, observedModel: model, mergedHypothesis: merged, training });
    state.budget.work = budget.work;
  }
  else Object.assign(state, { sourceResultId: request.prior.resultId, selectedModel: selected.kind, selectedModelStateCount: selected.states.length });
  return { schemaVersion: 'ig5.protocol-state.v1', action: request.action, state };
}
