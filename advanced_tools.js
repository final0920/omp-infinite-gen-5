import { compareSemanticsAsync } from './semantic_diff_async.js';
import { captureCffStateSource, admitCffStateSource } from './source/cff_state_workflow.js';

export function defineAdvancedTools(mgr, cfg, render) {
  const targetProperty = { type: 'string', description: 'Opened target path; omit only when one active target is selected' };
  const ea = { type: 'string', description: 'Address, for example 0x140001000' };
  const name = { type: 'string', description: 'Exact function or type name' };
  function session(args) {
    const engine = mgr.scope?.getStore()?.engine;
    const live = [...mgr.sessions.values()].filter((value) => mgr.alive(value) && value.engine !== 'x64dbg' && (!engine || !value.engine || value.engine === engine));
    if (!args.target && live.length !== 1) throw new Error('Specify target when there are zero or multiple active sessions');
    const selected = args.target ? mgr.get(args.target) : live[0];
    if (!mgr.alive(selected)) throw new Error('Target is not open; call ig5_open first');
    return selected;
  }
  function rpcTool(name, method, description, properties, required = []) {
    return {
      name, description,
      parameters: { type: 'object', properties: { target: targetProperty, ...properties }, required, additionalProperties: false },
      output: { schema: { type: 'object', additionalProperties: true }, render },
      execute(args = {}, execution) {
        const selected = session(args);
        if (name === 'ig5_microcode' && args.action === 'deobfuscate' && selected.engine !== 'ghidra' && !(selected.engine === 'reverse' && cfg.reverseProvider !== 'commercial')) {
          throw new Error('deobfuscate requires the bundled Reverse or Ghidra provider');
        }
        if (name === 'ig5_microcode' && args.task_id !== undefined) {
          if(typeof args.task_id!=='string'||args.task_id.length>64||args.action!=='deobfuscate')throw new Error('task_id capture requires an exact current task and action=deobfuscate');
          if(!execution?.agent?.id)throw Object.assign(new Error('Source capture requires actual executing agent'),{code:'AGENT_SCOPE_REQUIRED'});
          const before=admitCffStateSource(mgr,cfg,selected,args,execution),{task_id,...params}=args;
          return Promise.resolve(mgr.rpc(selected,method,params,cfg.requestTimeoutMs)).then(result=>captureCffStateSource(mgr,cfg,selected,args,result,execution,before));
        }
        return mgr.rpc(selected, method, args, cfg.requestTimeoutMs);
      },
    };
  }
  return [
    rpcTool('ig5_stack', 'stack', 'Read assembly-level stack frame members, stack offsets, arguments, saved registers and return-address regions without depending on decompilation.',
      { ea, name, limit: { type: 'number', description: 'Maximum frame fields, default 200' } }),
    rpcTool('ig5_switches', 'switches', 'Recover recognized switch/jump-table metadata, case-value groups, target addresses and default branches. Can enumerate a function or inspect an exact jump address. Read-only.',
      { ea, name, exact: { type: 'boolean' }, limit: { type: 'number' }, max_cases: { type: 'number' } }),
    rpcTool('ig5_switch_repair', 'switch_repair', 'Preview or rebuild a switch table from existing metadata or an explicit direct table definition. apply=true changes the analysis database and branch xrefs. Approval-gated; verify every target before applying.',
      { ea, action: { type: 'string', enum: ['rebuild', 'define'] }, apply: { type: 'boolean' },
        table: ea, ncases: { type: 'number' }, element_size: { type: 'number', enum: [1, 2, 4, 8] },
        lowcase: { type: 'number' }, default: ea, relative: { type: 'boolean' }, signed: { type: 'boolean' },
        elbase: ea, shift: { type: 'number' }, create_instructions: { type: 'boolean' } }, ['ea']),
    rpcTool('ig5_vtables', 'vtables', 'Inspect MSVC and Itanium virtual tables, RTTI class names and inheritance evidence. Returns virtual slots and a reviewable structure declaration. Given a table EA and byte offset, resolve that explicit virtual slot; register provenance is not inferred.',
      { ea, abi: { type: 'string', enum: ['auto', 'msvc', 'itanium'] }, offset: { type: 'number' },
        max_slots: { type: 'number' }, limit: { type: 'number' }, max_scan_bytes: { type: 'number' }, max_bases: { type: 'number' } }),
    rpcTool('ig5_microcode', 'microcode', 'Inspect native IR/CFG or optimize temporary IR. action=deobfuscate on bundled Reverse/Ghidra performs bounded SSA constants, opaque-predicate proofs, branch and dispatcher evidence, exact local bitwise/linear MBA expression identities, and backward dependency slices for indirect targets. expressionSimplifications prove only local typed expressions; indirectTransfers do not resolve targets or VM handlers. Memory/calls/indirect control remain unresolved. Returns a read-only overlay without rewriting or executing the target. Ghidra actualStage/maturity mapping is explicit; no universal devirtualization or proprietary-stage equivalence claim.',
      { ea, name, action: { type: 'string', enum: ['inspect', 'optimize', 'deobfuscate'] }, maturity: { type: 'string', enum: ['generated', 'preoptimized', 'locopt', 'calls', 'glbopt1', 'glbopt2', 'glbopt3', 'lvars'], description: 'Legacy compatibility label. Ghidra maps to firstpass, normalize or decompile. Deobfuscate defaults to generated/firstpass native SSA; inspect defaults to glbopt3/decompile. Inspect actualStage; stages are not proprietary equivalents.' },
        max_blocks: { type: 'number' }, max_instructions: { type: 'number' },
        max_steps: { type: 'integer', minimum: 1, maximum: 250000, description: 'Deobfuscation work budget, default 100000; unfinished proofs are withheld.' },
        max_evidence: { type: 'integer', minimum: 1, maximum: 512, description: 'Maximum entries per deobfuscation evidence category, default 128.' },
        rules: { type: 'array', items: { type: 'string', enum: ['xor-self', 'sub-self'] } },
        task_id: {type:'string',description:'Explicit deobfuscate only: save a full immutable typed native SSA source in this current research task; returns sourceRef for workspace cff-state. No caller IR accepted.'} }),
    {
      name: 'ig5_bindiff',
      description: 'Compare two opened binary versions by normalized instructions, CFG neighborhoods, constants and call degree. Return scored function matches and changed basic blocks with ambiguity/truncation evidence. Heuristic patch candidates, not a claim of vulnerability or semantic equivalence. Read-only.',
      parameters: { type: 'object', properties: { left: targetProperty, right: targetProperty,
        filter: { type: 'string' }, user_only: { type: 'boolean' }, limit_functions: { type: 'number', description: 'Max functions per side, default 500, max 2000' },
        threshold: { type: 'number' }, limit: { type: 'number', description: 'Maximum returned matches and changes, default 100' } },
      required: ['left', 'right'], additionalProperties: false },
      output: { schema: { type: 'object', additionalProperties: true }, render },
      async execute(args) {
        if (!args?.left || !args?.right) throw new Error('left and right opened targets are required');
        if (mgr.sessionKey(args.left) === mgr.sessionKey(args.right)) throw new Error('Open two different target paths for a version comparison');
        const params = { limit: args.limit_functions || 500, filter: args.filter || '', user_only: args.user_only !== false };
        const [left, right] = await Promise.all([
          mgr.rpc(session({ target: args.left }), 'semantics', params, cfg.requestTimeoutMs),
          mgr.rpc(session({ target: args.right }), 'semantics', params, cfg.requestTimeoutMs),
        ]);
        return { left: args.left, right: args.right, ...await compareSemanticsAsync(left, right, args, mgr.scope?.getStore()?.signal) };
      },
    },
    rpcTool('ig5_emulate', 'emulate', 'Isolated x86/x64 or ARM64 function CPU emulation from a provider-supplied MemoryImage. Supported target architectures depend on the active provider and host runtime. Provide integer arguments, registers and memory buffers; capture return values and memory. No native process or OS/import emulation. Approval-gated; bounded time/instruction/memory budgets. mode=decode_strings (x86-64): finds routines that look like string/config decoders (a loop, byte-level arithmetic, memory writes, many callers), resolves the constants passed at each call site, emulates every call and returns the text the decoder wrote, each re-run once to confirm it reproduces (level E1: consistent with emulation, not proof of run-time behavior). Decoders that call imports or the OS are reported as unsupported, never as empty. Pass ea or name to force one decoder.',
      { mode: { type: 'string', enum: ['function', 'decode_strings'], description: 'function (default): emulate one function. decode_strings: scan for decoders and decode their call sites.' },
        min_calls: { type: 'number', description: 'decode_strings: minimum call sites for a decoder candidate, default 3' },
        max_decoders: { type: 'number', description: 'decode_strings: decoders to try, best score first, default 16' },
        max_runs: { type: 'number', description: 'decode_strings: total emulated calls, default 200' },
        max_runs_per_decoder: { type: 'number', description: 'decode_strings: default 64' },
        time_budget_ms: { type: 'number', description: 'decode_strings: wall-clock budget, default 30000' },
        max_strings: { type: 'number', description: 'decode_strings: strings returned, default 500' },
        min_text: { type: 'number', description: 'decode_strings: shortest text kept, default 4' },
        max_size: { type: 'number', description: 'decode_strings: largest function considered a decoder, bytes, default 600' },
        ea, name, abi: { type: 'string', enum: ['win64', 'sysv64', 'cdecl', 'stdcall', 'aapcs64'] },
        args: { type: 'array', items: { type: 'string' }, description: 'Integer arguments encoded as decimal or hex strings' },
        registers: { type: 'object', additionalProperties: { type: 'string' } },
        memory: { type: 'array', items: { type: 'object', properties: { ea, hex: { type: 'string' } }, required: ['ea', 'hex'], additionalProperties: false } },
        capture: { type: 'array', items: { type: 'object', properties: { ea, size: { type: 'number' } }, required: ['ea'], additionalProperties: false } },
        max_instructions: { type: 'number' }, timeout_ms: { type: 'number' } }),
  ];
}
