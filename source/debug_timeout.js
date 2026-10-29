/** Bound interactive native continuation separately from trace/solver budgets. */
export function debugTimeout(args, cfg) {
  const continues = ['cont', 'apitrace'].includes(args.op) && args.backend === 'x64dbg';
  const maximum = continues ? 120 : 60;
  const seconds = args.timeout ?? (args.record_trace || args.op === 'apitrace' ? 45 : ['start', 'cont'].includes(args.op) ? 30 : 15);
  if (typeof seconds !== 'number' || !Number.isFinite(seconds) || seconds <= 0 || seconds > maximum) throw new Error(`Debugger timeout must be positive and at most ${maximum} seconds; only explicit x64dbg cont/apitrace supports 120`);
  if (seconds * 1000 + 5000 > cfg.requestTimeoutMs) throw new Error('Configured debugger RPC deadline is shorter than the requested wait plus cleanup; reduce timeout or raise requestTimeoutMs');
  return { seconds, rpcTimeoutMs: Math.min(cfg.requestTimeoutMs, Math.max(75000, seconds * 1000 + 15000)) };
}
