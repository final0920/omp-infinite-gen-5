import { createHash } from 'node:crypto';
import { deriveExecutableProgram, executeBytecode } from '../vm_bytecode.js';
import { validateFunctionContract } from '../vm_function_contract.js';
import { fixedFunctionOracle } from './vm_function_oracle.js';
import { planningDigest } from '../planning_identity.js';
import { verifyRecordedFunction } from './vm_recorded_function.js';

/** Exhaustive finite model-domain verification, or explicitly partial finite tests. Never a universal native CPU proof. */
export function verifyFiniteFunction({program,contract,sampleInputs=[],recordedRuns=[]}) {
  validateFunctionContract(contract);
  const fresh=deriveExecutableProgram(Buffer.from(program.sourceImageHex,'hex'),contract);
  if(planningDigest(program)!==planningDigest(fresh))throw Object.assign(new Error('Executable program/source differs'),{code:'INVALID_VM_PROGRAM'});
  const lo=BigInt(contract.input.minimum),hi=BigInt(contract.input.maximum),size=hi-lo+1n,exhaustive=size<=4096n;
  if(!Array.isArray(sampleInputs)||sampleInputs.length>64||sampleInputs.some(x=>typeof x!=='string'||!/^0x[0-9a-f]{1,16}$/.test(x)
    ||BigInt(x)<lo||BigInt(x)>hi))throw new Error('Invalid bounded in-domain samples');
  const inputs=exhaustive?Array.from({length:Number(size)},(_,i)=>lo+BigInt(i)):[...new Set([lo,hi,...sampleInputs.map(BigInt)])];
  const coverage=new Set(),transcript=createHash('sha256');let witness=null,completed=0;
  for(const input of inputs) {
    const actual=executeBytecode(program.model,input),expected=fixedFunctionOracle(contract.targetSha256,input);
    if(!expected)throw new Error('No fixed independent reference');completed++;
    for(let i=0;i<actual.path.length;i++) { const p=actual.path[i],n=actual.path[i+1];coverage.add(`${p.pc}:${p.key}->${n?n.pc+':'+n.key:'return'}`); }
    const compared={returnValue:actual.returnValue,memoryHex:actual.memoryHex,normalReturn:actual.normalReturn};
    transcript.update(JSON.stringify([input.toString(),compared,expected])+'\n');
    if(planningDigest(compared)!==planningDigest(expected)){witness={input:'0x'+input.toString(16),actual:compared,expected};break;}
  }
  const recordedFunctionEvidence=verifyRecordedFunction(program,contract,recordedRuns);
  const pass=witness===null&&recordedFunctionEvidence.status!=='fail';
  const nodeById=new Map(program.graph.nodes.map(n=>[n.id,n]));
  const modelEdges=program.graph.edges.map(e=>{const a=nodeById.get(e.from).identity,b=nodeById.get(e.to).identity;return `${a.bytecodePosition}:${a.decodeState.key}->${b.bytecodePosition}:${b.decodeState.key}`;});
  const uncoveredModelEdges=modelEdges.filter(e=>!coverage.has(e));
  return {schema:'ig5-finite-function-verification-v1',targetSha256:contract.targetSha256,contractDigest:planningDigest(contract),
    status:pass?(exhaustive?'pass':'partial'):'fail',property:'fixed-owned-model-return-and-output-memory-equivalence',
    scope:{kind:'virtual-model',inputBits:contract.input.bits,minimum:contract.input.minimum,maximum:contract.input.maximum,sourceKind:program.sourceKind},
    finiteTesting:{status:pass?'pass':'fail',cases:completed,plannedCases:inputs.length,transcriptSha256:transcript.digest('hex')},
    inputDomainSize:size.toString(),exhaustiveFiniteDomain:pass&&exhaustive,modelContractAccepted:pass&&exhaustive,
    coverage:{observedModelEdges:[...coverage].sort(),uncoveredModelEdges,allModelEdgesCovered:uncoveredModelEdges.length===0,
      unresolvedDecodeEdges:program.graph.unresolvedEdges.length},witness,recordedFunctionEvidence,
    randomizedDifferential:false,universalProof:false,nativeCpuEquivalenceProved:false,nativeInputCoverageProved:false,
    nativeTargetExecuted:false,businessAccepted:false,wholeVmRecovered:false,wholeBinaryVerified:false,changesExecutionAuthority:false,
    limitations:['Fixed registered source only','No new native execution','Model-wide finite equivalence is not a native CPU or full-width universal proof',
      'Calls, exceptions and concurrency excluded by the explicit contract']};
}
