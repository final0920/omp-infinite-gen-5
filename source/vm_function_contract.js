import { planningDigest } from './planning_identity.js';

const fail = message => { throw Object.assign(new Error(message), { code: 'INVALID_FUNCTION_CONTRACT' }); };
export function exactData(value, keys) {
  if (!value || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== keys.length || keys.some(k => !Object.hasOwn(value, k)
      || !Object.hasOwn(Object.getOwnPropertyDescriptor(value, k), 'value'))) fail('Exact data fields required: ' + keys.join(', '));
}
export function boundedDataArray(value, maximum, minimum = 0) {
  if(!Array.isArray(value)||Object.getPrototypeOf(value)!==Array.prototype||value.length<minimum||value.length>maximum
    ||Reflect.ownKeys(value).length!==value.length+1
    ||Array.from({length:value.length},(_,i)=>Object.getOwnPropertyDescriptor(value,String(i))).some(d=>!d||!Object.hasOwn(d,'value')))
    fail('A bounded dense data array without accessors is required');
  return value;
}
export function validateFunctionContract(value) {
  exactData(value, ['schema', 'targetSha256', 'entryRva', 'normalReturn', 'input', 'outputs', 'environment', 'exclusions']);
  if (value.schema !== 'ig5-function-contract-v1' || typeof value.targetSha256!=='string'||!/^[a-f0-9]{64}$/.test(value.targetSha256)
    || typeof value.entryRva!=='string'||!/^0x[0-9a-f]{1,16}$/.test(value.entryRva) || !['native-ret','bytecode-halt'].includes(value.normalReturn)) fail('Unsupported contract identity/boundary');
  exactData(value.input, ['register', 'bits', 'minimum', 'maximum']);
  if (value.input.register !== 'rcx' || ![8,16,32,64].includes(value.input.bits)
    || ![value.input.minimum, value.input.maximum].every(v => typeof v === 'string' && /^0x[0-9a-f]{1,16}$/.test(v))) fail('Bounded unsigned RCX domain required');
  const lo = BigInt(value.input.minimum), hi = BigInt(value.input.maximum);
  if (lo > hi || hi >= 1n << BigInt(value.input.bits)) fail('Input range exceeds width');
  exactData(value.outputs, ['returnRegister', 'memory']);
  boundedDataArray(value.outputs.memory,16);
  if (value.outputs.returnRegister !== 'rax') fail('Return RAX and at most 16 memory regions required');
  const intervals = [];
  for (const region of value.outputs.memory) {
    exactData(region, ['rva', 'bytes']);
    if (typeof region.rva!=='string'||!/^0x[0-9a-f]{1,16}$/.test(region.rva) || !Number.isSafeInteger(region.bytes) || region.bytes < 1 || region.bytes > 256) fail('Invalid output memory region');
    const start = BigInt(region.rva), end = start + BigInt(region.bytes);
    if (end > 1n << 64n || intervals.some(([a,b]) => start < b && a < end)) fail('Overlapping or overflowing output regions');
    intervals.push([start,end]);
  }
  boundedDataArray(value.exclusions,16);
  if (value.environment !== 'single-threaded-no-external-calls'
    || value.exclusions.some(s => typeof s !== 'string' || s.length > 256)) fail('Explicit bounded environment/exclusions required');
  // Persist plain JSON only, after exact data validation; no execution of caller expressions.
  return JSON.parse(JSON.stringify(value));
}

/** A fail-closed prerequisite assessment, not a finite-test or universal-proof receipt. */
export function assessFunctionContract(contract, program, programRef) {
  validateFunctionContract(contract);
  if (program.schema !== 'ig5-observed-vm-program-v1' || program.targetSha256 !== contract.targetSha256) fail('Program/contract target differs');
  const domainSize = BigInt(contract.input.maximum) - BigInt(contract.input.minimum) + 1n;
  const obligations = [
    { property: 'entry-and-normal-return', status: program.nodes.length && program.nodes.every(n => n.terminalReturnProved) ? 'unsupported' : 'open' },
    { property: 'all-reachable-control-paths', status: program.unresolvedEdges.length ? 'open' : 'unsupported' },
    { property: 'complete-register-and-memory-semantics', status: 'open' },
    { property: 'memory-layout-alias-and-write-footprint', status: 'open' },
    { property: 'independent-oracle-return-and-memory-effects', status: 'open' },
    { property: 'input-domain-coverage', status: 'open' },
    { property: 'external-calls-exceptions-and-concurrency', status: 'excluded-by-contract' },
  ];
  return { schema: 'ig5-function-contract-assessment-v1', targetSha256: contract.targetSha256,
    contractDigest: planningDigest(contract), programRef, domainSize: domainSize.toString(), obligations,
    status: 'unsupported-incomplete-program-semantics', finiteTesting: { status: 'not-run', cases: 0 },
    exhaustiveFiniteDomain: false, randomizedDifferential: false, universalProof: false, businessAccepted: false,
    nativeTargetExecuted: false, changesExecutionAuthority: false,
    reason: 'Observed candidate graphs do not supply executable full function semantics or an independent oracle. No verifier is silently substituted.' };
}
