import fs from 'node:fs';
export const name = 'ig5-review-smoke-guard';
export function apply(ctx, config) {
  let calls = 0;
  const started = Date.now();
  const log = row => fs.appendFileSync(config.log, JSON.stringify(row) + '\n');
  const tools = new Set(['ig5_open', 'ig5_funcs', 'ig5_decompile', 'ig5_dbg', 'ig5_close']);
  const ops = new Set(['load', 'start', 'regs', 'step', 'stop']);
  ctx.on('tools/pre-execute', (execution, next) => {
    const a = execution.arguments || {};
    const allowed = ++calls <= 20 && Date.now() - started < 300000 && tools.has(execution.name)
      && (a.target === config.target || execution.name === 'ig5_open' && a.path === config.target)
      && (a.path === undefined || a.path === config.target) && (a.engine === undefined || a.engine === 'ghidra')
      && (execution.name !== 'ig5_dbg' || a.backend === 'x64dbg' && ops.has(a.op) && a.guest_profile === undefined)
      && (execution.name !== 'ig5_decompile' || a.ea === '0x140001000');
    log({phase:'dispatch',tool:execution.name,args:a,allowed});
    return allowed ? next() : {kind:'deny',reason:'Outside the explicitly authorized owned-fixture smoke scope'};
  }, {global:true});
  ctx.on('approval/request', (request, next) => {
    // Answer the existing approval service for the exact target and bounded debug operations authorized by bai.
    // The standard approval service still records its asked/decided pair in the real session.
    if (request.toolName !== 'ig5_dbg' || !request.reason?.includes(config.target)) return next();
    const allowed = [...ops].some(op => new RegExp(`(?:^|\\n)op: ${op}(?:\\n|$)`).test(request.reason)) && Date.now()-started < 300000;
    log({phase:'authorization',tool:request.toolName,callId:request.callId,authorizedBy:'bai',outcome:allowed?'allowed-once':'rejected'});
    return allowed ? 'allowed-once' : 'rejected';
  }, {global:true});
  ctx.on('tools/post-execute', (execution,result,next) => {
    log({phase:'result',tool:execution.name,args:execution.arguments,result}); return next();
  }, {global:true});
}
