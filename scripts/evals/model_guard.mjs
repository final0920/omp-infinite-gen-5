import fs from 'node:fs';

export const name = 'ig5-eval-isolation';
export const inject = ['tools'];
/** Test-only capability boundary. Models get JSON evidence, never paths/commands. */
export function apply(ctx, config) {
  const data = JSON.parse(fs.readFileSync(config.dataset, 'utf8'));
  if (data.schema !== 'ig5-eval-pilot-evidence-v1' || !['baseline', 'brief'].includes(config.variant)) throw new Error('Invalid replay dataset');
  let calls = 0, outputBytes = 0;
  const started = Date.now();
  const log = value => fs.appendFileSync(config.log, JSON.stringify({ at: Date.now(), ...value }) + '\n', { mode: 0o600 });
  ctx.on('tools/pre-execute', (execution, next) => {
    calls++;
    log({ phase: 'dispatch', tool: execution.name, calls });
    if (execution.name !== 'ig5_eval' || calls > 20 || Date.now() - started > 120000) {
      log({ phase: 'denied', tool: execution.name, denied: true, calls });
      return { kind: 'deny', reason: 'Evaluation permits only bounded immutable evidence retrieval; no filesystem, shell, network, subagent or oracle access.' };
    }
    return next();
  }, { global: true });
  ctx.effect(() => ctx.tools.register({ name: 'ig5_eval', description: 'Read frozen real investigation evidence. Begin with brief if available, otherwise task. Historical observations retain original scope. current_dossier retrieves current evidence; this is a replay, not new native computation.',
    parameters: { type: 'object', properties: { action: { type: 'string', enum: config.variant === 'brief'
      ? ['brief','task','historical','current_dossier','catalog'] : ['task','historical','current_dossier','catalog'] } }, required: ['action'], additionalProperties: false },
    output: { schema: { type: 'object', additionalProperties: true }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    execute(args) {
      if (Object.keys(args).join(',') !== 'action') throw new Error('Only a fixed action is allowed');
      const allowed = { task: data.task, historical: data.historical, current_dossier: data.current, catalog: data.catalog, ...(config.variant === 'brief' ? { brief: data.brief } : {}) };
      if (!Object.hasOwn(allowed, args.action)) throw new Error('Unsupported evaluation action');
      const result = structuredClone(allowed[args.action]);
      const bytes = Buffer.byteLength(JSON.stringify(result));
      if (outputBytes + bytes > 65536) throw new Error('Frozen output budget exhausted');
      outputBytes += bytes;
      log({ phase: 'result', tool: 'ig5_eval', action: args.action, calls, bytes, outputBytes });
      return result;
    } }));
  log({ boundary: 'only-ig5_eval', oracleAccessible: false, variant: config.variant });
}
