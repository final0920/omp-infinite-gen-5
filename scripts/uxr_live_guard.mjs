import fs from 'node:fs';

export const name = 'ig5-uxr-live-static-guard';
export const inject = ['tools'];
export function apply(ctx, config) {
  let calls = 0;
  const started = Date.now();
  const log = data => fs.appendFileSync(config.log, JSON.stringify(data) + '\n');
  const allowed = new Set(['ig5_doctor', 'ig5_open', 'ig5_decompile', 'ig5_close']);
  ctx.on('tools/pre-execute', (execution, next) => {
    const args = execution.arguments || {};
    calls++;
    const valid = allowed.has(execution.name) && calls <= 20 && Date.now() - started < 300000
      && (execution.name !== 'ig5_doctor' || Object.keys(args).join(',') === 'operation' && args.operation === 'session')
      && (execution.name === 'ig5_doctor' || args.target === config.target || execution.name === 'ig5_open' && args.path === config.target)
      && (args.path === undefined || args.path === config.target)
      && (args.engine === undefined || args.engine === 'ghidra')
      && (execution.name !== 'ig5_decompile' || args.operation === 'read' || args.operation === undefined && args.ea === config.ea && args.style === 'dossier');
    log({ phase: 'dispatch', tool: execution.name, args, allowed: valid, callId: execution.callId });
    if (!valid) return { kind: 'deny', reason: 'This acceptance run permits only session diagnosis and static capture/read/close of the one owned fixture.' };
    return next();
  }, { global: true });
  ctx.on('tools/post-execute', (execution, result, next) => {
    if (allowed.has(execution.name)) log({ phase: 'result', tool: execution.name, args: execution.arguments, result });
    return next();
  }, { global: true });
  log({ phase: 'boundary', tools: [...allowed], target: config.target, targetExecuted: false });
}
