import { createHash } from 'node:crypto';
import { checkedProjectionReferences } from './projection_jobs.js';
const fail = text => { throw new Error('Invalid fetch/control dependency: ' + text); };
const GPRS='rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split(' ').sort().join(',');
const canon = value => JSON.stringify(value, (_key, item) => item && typeof item === 'object' && !Array.isArray(item)
  ? Object.fromEntries(Object.keys(item).sort().map(k => [k,item[k]])) : item);
function inspect(core) {
  if (core?.schema !== 'ig5-pcode-opaque-status-projection-v1' || core.projectionMode !== 'opaque-status'
    || ['nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'].some(k => core[k] !== false)
    || !Array.isArray(core.projectionPath) || !core.projectionPath.length || core.projectionPath.length > 128
    || !Array.isArray(core.decodedPath) || core.decodedPath.length !== core.projectionPath.length
    || !/^[a-f0-9]{64}$/.test(core.targetSha256||'')
    || Object.keys(core.initialRegisters || {}).sort().join(',') !== GPRS || Object.keys(core.registers || {}).sort().join(',') !== GPRS) fail('full state or scope');
  checkedProjectionReferences(core);
  const nodes = core.dag.nodes, signatures = [], previews = [], previewTruncated = [];
  for (const node of nodes) {
    const { id, args, ...meaning } = node;
    signatures.push(createHash('sha256').update(canon({ ...meaning, args: args.map(i => signatures[i]) })).digest('hex'));
    let text, truncated=args.some(i=>previewTruncated[i]);
    if(node.op==='input'||node.op==='initial_memory')text=node.name;
    else if(node.op==='const')text=node.value;
    else{
      text=node.op+(node.bits?':'+node.bits:'')+'(';
      for(let i=0;i<args.length;i++){
        text+=(i?',':'')+previews[args[i]];
        if(text.length>2037){truncated=true;break;}
      }
      text+=')';
    }
    if(text.length>2048){text=text.slice(0,2037)+'[truncated]';truncated=true;}
    previews.push(text);previewTruncated.push(truncated);
  }
  const ancestors = root => {
    if (!Number.isSafeInteger(root) || root < 0 || root >= nodes.length) fail('missing root');
    const seen = new Set(), todo = [root];
    while (todo.length) { const id = todo.pop(); if (seen.has(id)) continue; seen.add(id); todo.push(...nodes[id].args); }
    return seen;
  };
  // Topological bounded strings avoid exponential expansion of shared DAGs.
  return { nodes, signatures, ancestors, format:id=>previews[id], previewTruncated };
}
/** A structural dependency certificate for two independently decoded views of
 * the same initial instruction. It is not semantic nonconstancy or a CPU proof.
 * Full state/memory/STORE reports stay intact; no reports are state-composed.
 */
export function classifyFetchFlow(prefix, full) {
  const p = inspect(prefix), f = inspect(full);
  if (prefix.projectionPath.length !== 1 || prefix.targetSha256 !== full.targetSha256
    || prefix.projectionPath[0] !== full.projectionPath[0]
    || canon(prefix.decodedPath[0]) !== canon(full.decodedPath[0]) || prefix.stores.length !== 0) fail('first-instruction byte/pcode/source binding');
  if (!['indirect','return'].includes(full.control.kind) || !Number.isSafeInteger(full.control.target)) fail('non-indirect terminal control');
  const prefixLoads = p.nodes.filter(n => n.op === 'load_le' && [1,2].includes(n.size));
  if (prefixLoads.length !== 1) fail('source narrow load is not unique');
  const sourceLoad = prefixLoads[0], sourceSignature = p.signatures[sourceLoad.id];
  const matched = f.nodes.filter(n => n.op === 'load_le' && f.signatures[n.id] === sourceSignature).map(n => n.id);
  const targetNodes = f.ancestors(full.control.target), activeSeeds = matched.filter(id => targetNodes.has(id));
  const indexedReads = f.nodes.filter(n => n.op === 'load_le' && !matched.includes(n.id) && targetNodes.has(n.id)
    && activeSeeds.some(id => f.ancestors(n.args[1]).has(id))).map(n => ({ node: n.id, bytes: n.size,
      addressNode: n.args[1], memoryNode: n.args[0], sourceLoadNodes: activeSeeds.filter(id => f.ancestors(n.args[1]).has(id)),
      addressExpression: f.format(n.args[1]), addressExpressionPreviewTruncated:f.previewTruncated[n.args[1]] }));
  const initialInputs = [...targetNodes].map(id => f.nodes[id]).filter(n => n.op === 'input').map(n => n.name);
  const opaqueIds=new Set((full.nondeterministicInputs||[]).map(n=>n.node));
  const opaqueNodes = [...targetNodes].filter(id => opaqueIds.has(id));
  return { schema: 'ig5-fetch-control-dependency-v1', status: indexedReads.length ? 'source-indexed-load-reaches-indirect-target'
    : activeSeeds.length ? 'source-reaches-target-without-indexed-load' : 'source-absent-from-target-expression',
    targetSha256: full.targetSha256, sourceInstruction: prefix.projectionPath[0], terminalInstruction: full.control.source,
    sourceLoad: { prefixNode: sourceLoad.id, bytes: sourceLoad.size, signature: sourceSignature,
      addressExpression: p.format(sourceLoad.args[1]), addressExpressionPreviewTruncated:p.previewTruncated[sourceLoad.args[1]], matchedFullNodes: matched, activeTargetNodes: activeSeeds },
    indexedReads, target: { kind: full.control.kind, node: full.control.target, expression: f.format(full.control.target),
      expressionPreviewTruncated:f.previewTruncated[full.control.target], initialInputs, opaqueNodes, expressionNodes: targetNodes.size },
    preserved: { all16InitialGprs: true, all16FinalGprs: true, initialMemory: full.initialMemory, finalMemory: full.currentMemory,
      orderedStores: full.stores.length, rawPcodeOperations: full.statistics.pcodeOperations,
      fullOriginalReportRequired: true, independentlyProvedStoreCompleteness: false },
    instructionCount: full.projectionPath.length, semanticNonconstancyProved: false, sourceValuesReplacedByObservations: false,
    stateReportsComposed: false, nativeTargetExecuted: false, databaseModified: false, vmRoleProved: false,
    instructionSemanticsProved: false, businessAccepted: false, wholeBinaryVerified: false,
    ordinaryProgramAmbiguity: 'ordinary indexed jump tables and return trampolines can have the same dependency graph',
    nextObligations: ['Verify the complete local state equations and actual recorded state', 'Check stability across source bytes, inputs and memory/module epochs',
      'Separate dispatch from ordinary tables/calls/returns before assigning VM roles', 'Recover and independently validate VM ISA, program, complete business and path coverage'],
    scope: 'Byte/pcode-bound structural SSA dependency, preserving complete state and all ordered stores; no independent CPU or VM proof' };
}
