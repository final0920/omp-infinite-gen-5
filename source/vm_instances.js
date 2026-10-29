import {planningDigest} from './planning_identity.js';
import {hashBytes} from './analysis_artifacts.js';
import {exactData,boundedDataArray} from './vm_function_contract.js';
export const VM_INSTANCE_VERSION='20261024-vm-instances-1';
const fail=message=>{throw Object.assign(new Error(message),{code:'INVALID_VM_PROGRAM'});};
const sha=s=>typeof s==='string'&&/^[a-f0-9]{64}$/.test(s),integer=(n,max)=>Number.isSafeInteger(n)&&n>=0&&!Object.is(n,-0)&&n<=max;
const hex=(v,bits)=>typeof v==='string'&&/^0x[0-9a-f]{1,16}$/.test(v)&&BigInt(v)<1n<<BigInt(bits);
const unknownKeys=['codeSha256','runId','memoryEpoch'];
export function validateVmInstance(input){
 exactData(input,['schema','codeSha256','bytecodeHex','table','decode','runId','memoryEpoch','roles','contract']);
 if(input.schema!=='ig5-small-vm-instance-v1'||input.codeSha256!==null&&!sha(input.codeSha256)||typeof input.bytecodeHex!=='string'||!/^(?:[a-f0-9]{2})+$/.test(input.bytecodeHex)||input.bytecodeHex.length>8192)fail('Bounded explicit small VM source required');
 for(const k of ['runId','memoryEpoch'])if(input[k]!==null&&(typeof input[k]!=='string'||!input[k]||input[k].length>128))fail('Invalid or unknown run/memory epoch');
 if(input.table!==null){boundedDataArray(input.table,256);if(input.table.length!==256||input.table.some(x=>x!==null&&(!integer(x,5))))fail('Table must be 256 nullable explicit opcode mappings');}
 if(input.decode!==null){exactData(input.decode,['seed','bits','rotate','subtract']);const d=input.decode;if(!integer(d.seed,255)||![8,16,32,64].includes(d.bits)||!integer(d.rotate,d.bits-1)||!['acc-minus-operand','operand-minus-acc'].includes(d.subtract))fail('Invalid explicit decoder parameters');}
 if(input.roles!==null){exactData(input.roles,['vip','accumulator','result']);if(Object.values(input.roles).some(v=>typeof v!=='string'||!/^[a-z][a-z0-9]{0,15}$/.test(v))||new Set(Object.values(input.roles)).size!==3)fail('Roles must be three distinct declared slots');}
 exactData(input.contract,['minimum','maximum','initialResults','normalReturn']);const c=input.contract,bits=input.decode?.bits??64;boundedDataArray(c.initialResults,4);
 if(!hex(c.minimum,bits)||!hex(c.maximum,bits)||BigInt(c.minimum)>BigInt(c.maximum)||BigInt(c.maximum)-BigInt(c.minimum)>255n||!c.initialResults.length||c.initialResults.some(v=>!hex(v,bits))||new Set(c.initialResults).size!==c.initialResults.length||c.normalReturn!=='explicit-halt')fail('At most 256 input values, four distinct initial results and explicit HALT required');
 return JSON.parse(JSON.stringify(input));
}
export function vmInstanceIdentity(input){
 const m=validateVmInstance(input),missing=[...unknownKeys.filter(k=>m[k]===null),...['table','decode','roles'].filter(k=>m[k]===null)];
 const fields={codeSha256:m.codeSha256,bytecodeSha256:hashBytes(Buffer.from(m.bytecodeHex,'hex')),tableSha256:m.table===null?null:planningDigest(m.table),decode:m.decode,runId:m.runId,memoryEpoch:m.memoryEpoch,roles:m.roles};
 return {fields,complete:missing.length===0,missing,id:missing.length?null:planningDigest(fields),assurance:'declared-small-VM-model; not native instance identification'};
}
/** This machine is an explicit model, never inferred native/ARM64 semantics. HALT preserves result. */
export function executeSmallVm(input,x,initialResult){
 const m=validateVmInstance(input);if(!m.decode||!m.table||!m.roles)return {status:'unknown',reason:'incomplete-model'};
 const {bits,rotate,subtract}=m.decode,mask=(1n<<BigInt(bits))-1n,code=Buffer.from(m.bytecodeHex,'hex');if(!hex(x,bits)||!hex(initialResult,bits))fail('Input/state width differs');
 let pc=0,key=m.decode.seed,acc=BigInt(x),result=BigInt(initialResult);const path=[];
 for(let step=0;step<256;step++){
  if(pc>=code.length)return {status:'unknown',reason:'missing-explicit-halt',path};
  const at=pc,raw=code[pc++],index=raw^key,op=m.table[index];key=(key+1)&255;if(op===null)return {status:'unknown',reason:'unknown-table-entry',path};path.push({pc:at,keyBefore:(key+255)&255,index,opcode:op});
  if(op===0)return {status:'halt',returnValue:'0x'+result.toString(16),accumulator:'0x'+acc.toString(16),path,steps:step+1};
  if(op===1){acc=BigInt(x);continue;}if(op===5){result=acc;continue;}
  if(pc>=code.length)return {status:'unknown',reason:'truncated-operand',path};const operand=BigInt(code[pc++]);
  if(op===2)acc=(acc+operand)&mask;
  else if(op===3){const n=BigInt(rotate);acc=n===0n?acc:((acc<<n)|(acc>>(BigInt(bits)-n)))&mask;}
  else if(op===4)acc=(subtract==='acc-minus-operand'?acc-operand:operand-acc)&mask;
 }
 return {status:'unknown',reason:'step-limit',path};
}
// Separate transition implementation: no decoder/evaluator calls, no candidate-supplied oracle.
function oracle(m,input,initial){
 if(!m.decode||!m.table||!m.roles)return {status:'unknown',reason:'incomplete-model'};
 const bytes=Buffer.from(m.bytecodeHex,'hex'),mod=2n**BigInt(m.decode.bits);let pos=0,seed=m.decode.seed,value=BigInt(input),answer=BigInt(initial);
 for(let n=0;n<256;n++){
  if(pos>=bytes.length)return {status:'unknown'};const operation=m.table[bytes[pos]^seed];pos++;seed=(seed+1)%256;
  if(operation===null)return {status:'unknown'};if(operation===0)return {status:'halt',returnValue:'0x'+answer.toString(16),accumulator:'0x'+value.toString(16)};
  if(operation===1){value=BigInt(input);continue;}if(operation===5){answer=value;continue;}if(pos>=bytes.length)return {status:'unknown'};const immediate=BigInt(bytes[pos++]);
  if(operation===2)value=(value+immediate)%mod;
  if(operation===3){const split=2n**BigInt(m.decode.bits-m.decode.rotate);value=((value%split)*(mod/split)+value/split)%mod;}
  if(operation===4)value=((m.decode.subtract==='acc-minus-operand'?value-immediate:immediate-value)%mod+mod)%mod;
 }return {status:'unknown'};
}
export function compareVmInstances(models){
 boundedDataArray(models,8);if(!models.length)fail('At least one instance');const rows=models.map(validateVmInstance),identities=rows.map(vmInstanceIdentity),pairs=[];
 for(let a=0;a<rows.length;a++)for(let b=a+1;b<rows.length;b++){const x=identities[a],y=identities[b],differences=Object.keys(x.fields).filter(k=>planningDigest(x.fields[k])!==planningDigest(y.fields[k]));pairs.push({a,b,status:!x.complete||!y.complete?'unknown':differences.length?'distinct':'same-declared-identity',differences,mergeAllowed:x.complete&&y.complete&&!differences.length,nativeMergeAllowed:false});}
 return {schema:'ig5-vm-instance-comparison-v1',version:VM_INSTANCE_VERSION,identities,pairs,roleAssurance:'caller-declared; changed mapping retained, no VIP/VSP proof',wholeVmRecovered:false,architectureSupport:'explicit virtual model only; ARM64 native semantics not established',businessAccepted:false,nativeTargetExecuted:false,assistEnabled:false};
}
export function checkVmInstances(models){
 let planned=0;for(const m of models){validateVmInstance(m);planned+=Number(BigInt(m.contract.maximum)-BigInt(m.contract.minimum)+1n)*m.contract.initialResults.length;}if(planned>1024)fail('At most 1024 total finite input/state pairs');let work=0;
 const comparison=compareVmInstances(models),checks=models.map((input,index)=>{
  const m=validateVmInstance(input),cases=[];let mismatch=null,unknown=0;
  for(let x=BigInt(m.contract.minimum);x<=BigInt(m.contract.maximum);x++)for(const initial of m.contract.initialResults){const arg='0x'+x.toString(16);if(work+512>32768)fail('Combined transition budget exhausted');const actual=executeSmallVm(m,arg,initial),expected=oracle(m,arg,initial);work+=2*(actual.path?.length??256);if(actual.status!=='halt'||expected.status!=='halt')unknown++;
   const a={status:actual.status,returnValue:actual.returnValue??null,accumulator:actual.accumulator??null},e={status:expected.status,returnValue:expected.returnValue??null,accumulator:expected.accumulator??null};if(planningDigest(a)!==planningDigest(e))mismatch={input:arg,initialResult:initial,actual:a,expected:e};cases.push({input:arg,initialResult:initial,...a});}
  return {index,status:mismatch?'fail':unknown?'unknown':'pass-in-finite-model',cases:cases.length,unknown,mismatch,transcriptDigest:planningDigest(cases),transcript:cases,initialResultSensitivity:new Set(cases.filter(c=>c.input===m.contract.minimum).map(c=>c.returnValue)).size>1,nativeEquivalenceProved:false};
 });return {...comparison,schema:'ig5-small-vm-check-v1',checks,allModelsChecked:checks.every(c=>c.status==='pass-in-finite-model'),finiteModelOnly:true};
}
