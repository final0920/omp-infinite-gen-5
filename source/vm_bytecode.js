import { createHash } from 'node:crypto';
import { planningDigest } from './planning_identity.js';

const MASK = (1n << 64n) - 1n;
export const bytecodeHash = data => createHash('sha256').update(data).digest('hex');
const fail = (message, code = 'INVALID_VM_PROGRAM') => { throw Object.assign(new Error(message), { code }); };
const widths = new Map([[0,1],[1,1],[2,1],[3,1],[4,1],[5,2],[6,2],[7,2],[8,2]]);
const names = ['return-output','add-seven','xor-55','store-accumulator','load-accumulator','branch-even','jump','add-immediate','xor-immediate'];

export function decodeBytecode(code, pc, key = 0, decoder = 'plain') {
  if (!(code instanceof Uint8Array) || code.length < 1 || code.length > 65536 || !Number.isSafeInteger(pc) || pc < 0
    || !Number.isSafeInteger(key) || key < 0 || key > 255 || !['plain','xor-key-v1'].includes(decoder)) fail('Invalid decode state');
  if (pc >= code.length) return { status: 'unresolved', reason: 'target-outside-image', pc, key };
  const opcode = code[pc] ^ (decoder === 'plain' ? 0 : key), width = widths.get(opcode);
  if (width === undefined || pc + width > code.length) return { status: 'unresolved', reason: 'unsupported-or-truncated-opcode', pc, key };
  const operand = width === 2 ? code[pc + 1] : null, next = pc + width;
  const nextKey = decoder === 'plain' ? 0 : (key + opcode + 1) & 255;
  const successors = opcode === 0 ? [] : opcode === 6 ? [operand] : opcode === 5 ? [...new Set([operand,next])] : [next];
  return { status: 'decoded', pc, key, opcode, kind: names[opcode], width, operand, next, nextKey, successors,
    rawBytes: Buffer.from(code.subarray(pc,pc + width)).toString('hex'),
    stateEffects: { accumulator: [1,2,4,7,8].includes(opcode) ? names[opcode] : 'preserved',
      memory: [0,3].includes(opcode) ? 'write-eight-little-endian-bytes-at-output' : opcode === 4 ? 'read-eight-little-endian-bytes-at-output' : 'preserved',
      control: opcode === 0 ? 'explicit-model-return' : opcode === 5 ? 'accumulator-parity-branch' : 'explicit-successor', decoderKey: nextKey,
      otherVirtualState: 'none-in-this-fixed-machine', nativeCpuEffectsVerified: false } };
}

export function buildBytecodeGraph({ codeHex, decoder = 'plain', initialKey = 0, sourceSha256, stateLimit = 1024 }) {
  if (typeof codeHex !== 'string' || !/^(?:[a-f0-9]{2})+$/.test(codeHex) || codeHex.length > 131072
    || !/^[a-f0-9]{64}$/.test(sourceSha256) || !Number.isSafeInteger(stateLimit) || stateLimit < 1 || stateLimit > 1024) fail('Invalid bounded image');
  const code = Buffer.from(codeHex,'hex'), codeVersion = bytecodeHash(code), pending = [{pc:0,key:initialKey}], seen = new Map(), edges = [], unresolvedEdges = [];
  const identity = (pc,key) => ({ instance: planningDigest(['fixed-machine-image',sourceSha256]), bytecodePosition: pc,
    codeVersion, memoryVersion: codeVersion, decodeState: { key, decoder }, decodeMemory: 'immutable-image' });
  const idAt = (pc,key) => planningDigest(identity(pc,key));
  for (let at = 0; at < pending.length; at++) {
    const {pc,key} = pending[at], id = idAt(pc,key); if (seen.has(id)) continue;
    if (seen.size >= stateLimit) { unresolvedEdges.push({ from: null, to: null, pc, key, reason: 'state-budget-exhausted' }); continue; }
    const decoded = decodeBytecode(code,pc,key,decoder);
    if (decoded.status !== 'decoded') { unresolvedEdges.push({ from: id, to: null, pc,key,reason:decoded.reason }); continue; }
    seen.set(id,{ id, identity: identity(pc,key), decoded, source: { sha256: sourceSha256, byteOffset: pc, bytes: decoded.rawBytes }, unknowns: [] });
    for (const target of decoded.successors) {
      if (target >= code.length) unresolvedEdges.push({ from:id,to:null,pc:target,key:decoded.nextKey,reason:'target-outside-image' });
      else { edges.push({ from:id,to:idAt(target,decoded.nextKey),kind:decoded.opcode === 5 ? 'conditional' : 'direct' }); pending.push({pc:target,key:decoded.nextKey}); }
    }
  }
  // State limits and invalid decoding cannot leave apparently resolved dangling edges.
  const retained = edges.filter(e => {
    if (seen.has(e.to)) return true;
    unresolvedEdges.push({ from:e.from,to:null,reason:'successor-not-decoded',candidateId:e.to }); return false;
  });
  return { nodes:[...seen.values()],edges:retained,unresolvedEdges,stateLimit,codeVersion,
    merging: 'same-immutable-image-and-exact-decode-state-only', complete: unresolvedEdges.length === 0 };
}

/** Fixed virtual state only: no calls, native execution, arbitrary expressions, or zero-filled unknown loads. */
export function executeBytecode(program, input, { stepLimit = 1024 } = {}) {
  if (typeof input !== 'bigint' || input < 0n || input > MASK || !Number.isSafeInteger(stepLimit) || stepLimit < 1 || stepLimit > 1024) fail('Invalid execution input/budget');
  const code = Buffer.from(program.codeHex,'hex'), memory = new Map(), writes = [], path = [];
  let acc = input, pc = 0, key = program.initialKey, returned = false;
  const store = () => { for(let i=0;i<8;i++)memory.set(i,Number((acc >> BigInt(i*8)) & 255n)); writes.push({ offset:0,bytes:8,value:'0x'+acc.toString(16) }); };
  store(); // The fixed machine has an explicit input-to-output initialization store.
  for (let step = 0; step < stepLimit; step++) {
    const d = decodeBytecode(code,pc,key,program.decoder);
    if (d.status !== 'decoded') fail(d.reason,'UNRESOLVED_VM_PROGRAM');
    path.push({ pc,key,opcode:d.opcode }); let next = d.next;
    switch(d.opcode) {
      case 0: store(); returned = true; break;
      case 1: acc = (acc + 7n) & MASK; break;
      case 2: acc ^= 0x55n; break;
      case 3: store(); break;
      case 4: { let v=0n; for(let i=7;i>=0;i--) { if(!memory.has(i))fail('Unknown memory read','UNRESOLVED_VM_PROGRAM');v=(v<<8n)|BigInt(memory.get(i)); } acc=v; break; }
      case 5: if((acc & 1n) === 0n)next=d.operand; break;
      case 6: next=d.operand; break;
      case 7: acc=(acc+BigInt(d.operand))&MASK; break;
      case 8: acc^=BigInt(d.operand); break;
      default: fail('Unsupported state effect');
    }
    key=d.nextKey;pc=next;if(returned)break;
  }
  if (!returned) fail('Execution step budget exhausted','VM_PROGRAM_LIMIT');
  return { returnValue:'0x'+acc.toString(16), memoryHex:Buffer.from(Array.from({length:8},(_,i)=>memory.get(i))).toString('hex'),
    orderedStores:writes,path,normalReturn:true,externalCalls:0,unmodeledEffects:false };
}

// Fixed, source-bound owned references. Arbitrary images cannot select their semantics.
export function deriveExecutableProgram(imageBytes, contract) {
  const bytes = Buffer.from(imageBytes), targetSha256 = bytecodeHash(bytes);
  let referenceId, codeHex, sourceKind, entry;
  if(targetSha256 === '71d1ceaedaebeb572c63c33485405fa7612beab047aff0c00f96044bd92223f0') {
    referenceId='owned-phase-vm64-add7-xor55-v1';codeHex=bytes.subarray(0xf00,0xf03).toString('hex');sourceKind='registered-owned-pe64';entry='0x1000';
    if(codeHex !== '010200' || contract.normalReturn !== 'native-ret')fail('Owned image/return boundary differs');
  } else if(targetSha256 === 'd9bf31e34c5e95307f88fcc7ce544101bd61e566c284a4622afc9700f29da61c') {
    referenceId='owned-native-branch-memory-v1';codeHex=bytes.subarray(0xf00,0xf0c).toString('hex');sourceKind='registered-owned-pe64';entry='0x1000';
    if(codeHex !== '07070305090855060b010400' || contract.normalReturn !== 'native-ret')fail('Owned branch image/return boundary differs');
  } else if(targetSha256 === '6e71d6e35ce1939e6a44825918979e3188cd5c83f3d9d3afafa7d136b979224e') {
    referenceId='owned-branch-memory-bytecode-v1';codeHex=bytes.toString('hex');sourceKind='fixed-bytecode-image';entry='0x0';
    if(contract.normalReturn !== 'bytecode-halt')fail('Bytecode return boundary differs');
  } else fail('No source-bound fixed decoder/reference for this image','UNSUPPORTED_VM_PROGRAM');
  if(contract.targetSha256 !== targetSha256 || contract.entryRva !== entry || contract.outputs.returnRegister !== 'rax'
    || JSON.stringify(contract.outputs.memory) !== JSON.stringify([{rva:'0x3000',bytes:8}])) fail('Contract/image entry or full output layout differs');
  const model = { codeHex,decoder:'plain',initialKey:0 }, graph=buildBytecodeGraph({...model,sourceSha256:targetSha256});
  return { schema:'ig5-executable-vm-program-v1',targetSha256,referenceId,sourceKind,sourceImageHex:bytes.toString('hex'),
    model,graph,entryRva:entry,outputLayout:{rva:'0x3000',bytes:8,aliasing:'single-exact-output-region'},
    semanticScope:'fixed-owned-virtual-machine; native CPU translation remains a source-bound premise',
    codeMemoryAssumption:'immutable-within-this-model',nativeTargetExecuted:false,businessAccepted:false,changesExecutionAuthority:false,
    wholeVmRecovered:false,wholeBinaryVerified:false };
}
