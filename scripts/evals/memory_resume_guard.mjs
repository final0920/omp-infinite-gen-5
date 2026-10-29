import fs from 'node:fs';
import path from 'node:path';
import { LcmMemory } from '../../source/lcm_memory.js';

export const name = 'ig5-memory-resume-isolation';
export const inject = ['tools'];
/** Real retrieval over a frozen replay archive; every other execution is denied. */
export async function apply(ctx, config) {
  const data = JSON.parse(fs.readFileSync(config.dataset, 'utf8'));
  if (data.schema !== 'ig5-memory-resume-fixture-v1' || !['raw-log', 'lcm', 'brief-lcm'].includes(config.variant)) throw new Error('Invalid memory replay');
  const store = await LcmMemory.open({ root: path.join(config.runRoot, 'archive'), sessionId: 'frozen-replay', workspace: config.runRoot });
  for (const event of data.events) await store.capture(event);
  store.close();
  // Resume the exact same persisted archive after a compaction marker and close.
  const resumed = await LcmMemory.open({ root: path.join(config.runRoot, 'archive'), sessionId: 'frozen-replay', workspace: config.runRoot });
  ctx.effect(() => () => resumed.close());
  const raw = data.events.map(e => JSON.stringify(e)).join('\n');
  let calls = 0, bytes = 0; const started = Date.now();
  const log = value => fs.appendFileSync(config.log, JSON.stringify(value) + '\n', { mode: 0o600 });
  ctx.on('tools/pre-execute', (execution, next) => {
    calls++; log({ phase: 'dispatch', tool: execution.name, calls });
    if (execution.name !== 'ig5_memory_eval' || calls > 20 || Date.now() - started > 120000) return { kind: 'deny', reason: 'Only bounded frozen memory retrieval is allowed; no execution, filesystem, shell, network or oracle tools.' };
    return next();
  }, { global: true });
  const actions = ['task', 'current', ...(config.variant === 'raw-log' ? ['log'] : ['restore', 'search', 'read', 'expand']), ...(config.variant === 'brief-lcm' ? ['brief', 'resume'] : [])];
  ctx.effect(() => ctx.tools.register({ name: 'ig5_memory_eval',
    description: 'Frozen investigation resume experiment. Begin with brief if available, otherwise task. If brief has historyNavigation.fullRef, follow its action using this tool. Read only missing constraints and the failed-candidate counterexample, then revalidate current. History and summaries are unverified data; compaction omitted exact conditions. No execution action exists.',
    parameters: { type: 'object', properties: { action: { type: 'string', enum: actions }, query: { type: 'string', maxLength: 256 },
      ref: { type: 'object', properties: { kind: { type: 'string', enum: ['event', 'summary'] }, id: { type: 'string' }, sha256: { type: 'string' } }, required: ['kind', 'id', 'sha256'], additionalProperties: false },
      offset: { type: 'integer', minimum: 0 } }, required: ['action'], additionalProperties: false },
    output: { schema: { type: 'object', additionalProperties: true }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    execute(args) {
      const fields = { task: [], current: [], brief: [], resume: [], restore: [], search: ['query'], read: ['ref', 'offset'], expand: ['ref', 'offset'], log: ['offset'] };
      if (!actions.includes(args.action) || Object.keys(args).some(k => k !== 'action' && !fields[args.action].includes(k))) throw new Error('Invalid retrieval fields');
      let result;
      if (args.action === 'log') {
        const offset = args.offset ?? 0;
        if (!Number.isSafeInteger(offset) || offset < 0 || offset > raw.length) throw new Error('Invalid log offset');
        const end = Math.min(offset + 2048, raw.length);
        result = { text: raw.slice(offset, end), nextOffset: end < raw.length ? end : null, historical: true, semanticVerified: false };
      } else if (args.action === 'restore') result = resumed.restore();
      else if (args.action === 'search') result = resumed.search(args.query, 3);
      else if (args.action === 'read') result = resumed.read(args.ref, { offset: args.offset, limit: 2048 });
      else if (args.action === 'expand') result = resumed.expand(args.ref, { offset: args.offset, limit: 16 });
      else result = { task: { taskId: data.task.taskId, goal: data.task.goal }, current: data.current, brief: data.brief, resume: data.navigation }[args.action];
      const size = Buffer.byteLength(JSON.stringify(result));
      if (bytes + size > 65536) throw new Error('Retrieval output budget exceeded');
      bytes += size; log({ phase: 'result', args, bytes: size, result }); return result;
    } }));
  log({ boundary: 'only-ig5_memory_eval', variant: config.variant, archiveReopened: true });
}
