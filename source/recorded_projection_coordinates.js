// Internal coordinates selected from committed native evidence. Public tools
// accept neither this object nor raw p-code. It never relocates ordinary data.
import {hashBytes} from './analysis_artifacts.js';
import {mapVmFlowBytes} from './vm_flow_mapping.js';
const fail=m=>{throw Error('Recorded projection coordinates: '+m);};
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const uint=x=>typeof x==='string'&&/^0x[0-9a-f]{1,16}$/.test(x);
const sha=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const uuid=x=>typeof x==='string'&&/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(x);
const integer=(x,max=Number.MAX_SAFE_INTEGER)=>Number.isSafeInteger(x)&&!Object.is(x,-0)&&x>=0&&x<=max;
function fields(x,keys){if(!x||typeof x!=='object'||![Object.prototype,null].includes(Object.getPrototypeOf(x))||Reflect.ownKeys(x).length!==keys.length||keys.some(k=>!Object.hasOwn(x,k))||Reflect.ownKeys(x).some(k=>!keys.includes(k)||!Object.hasOwn(Object.getOwnPropertyDescriptor(x,k),'value')))fail('invalid object scope');}
function ref(x){fields(x,['id','sha256']);if(!uuid(x.id)||!sha(x.sha256))fail('invalid committed reference');}
export function validateRecordedCoordinateInput(input,data){
 fields(input,['schema','targetSha256','preferredBase','runtimeBase','source','rows']);
 if(input.schema!=='ig5-recorded-runtime-code-input-v1'||!sha(input.targetSha256)||!uint(input.preferredBase)||!uint(input.runtimeBase))fail('input identity');
 const s=input.source;fields(s,['recurrencesRef','selectionRef','runId','threadId','windows']);ref(s.recurrencesRef);ref(s.selectionRef);
 if(typeof s.runId!=='string'||!/^[a-zA-Z0-9_-]{1,128}$/.test(s.runId)||!integer(s.threadId,0xffffffff)||s.threadId<1||!Array.isArray(s.windows)||s.windows.length<1||s.windows.length>128)fail('source identity');
 const windows=new Set();for(const w of s.windows){fields(w,['reportId','reportSha256','traceSha256']);if(!uuid(w.reportId)||!sha(w.reportSha256)||!sha(w.traceSha256)||windows.has(w.reportId))fail('source window binding');windows.add(w.reportId);}
 if(!Array.isArray(input.rows)||input.rows.length<1||input.rows.length>128)fail('128 site budget');
 const pcs=new Set(),preferreds=new Set(),used=new Set();let prior;
 for(const r of input.rows){fields(r,['groupIndex','recordingId','preferred','runtimePc','fileOffset','bytes','pauseBefore','pauseAfter']);
  if(!integer(r.groupIndex,100000)||!windows.has(r.recordingId)||!uint(r.preferred)||!uint(r.runtimePc)||BigInt(r.preferred)===0n||BigInt(r.runtimePc)===0n||!integer(r.fileOffset,64*1024**2)||typeof r.bytes!=='string'||!/^(?:[a-f0-9]{2}){1,15}$/.test(r.bytes)||!integer(r.pauseBefore)||!integer(r.pauseAfter)||r.pauseAfter!==r.pauseBefore+1||r.pauseBefore===r.pauseAfter)fail('row boundary/identity');
  if(BigInt(r.runtimePc)-BigInt(input.runtimeBase)!==BigInt(r.preferred)-BigInt(input.preferredBase)||BigInt(r.preferred)<BigInt(input.preferredBase)||BigInt(r.runtimePc)<BigInt(input.runtimeBase)||BigInt(r.runtimePc)+BigInt(r.bytes.length/2)>((1n<<64n)-1n)||pcs.has(r.runtimePc)||preferreds.has(r.preferred))fail('coordinate mapping');
  if(prior&&(r.groupIndex!==prior.groupIndex+1||r.pauseBefore!==prior.pauseAfter))fail('non-contiguous recorded body');
  pcs.add(r.runtimePc);preferreds.add(r.preferred);used.add(r.recordingId);prior=r;
 }
 if(used.size!==windows.size)fail('unrelated source window');
 const raw=Buffer.from(JSON.stringify(input),'utf8');if(raw.length>65536)fail('64 KiB coordinate snapshot budget');
 if(data!==undefined){if(!Buffer.isBuffer(data)||hashBytes(data)!==input.targetSha256)fail('original target SHA differs');
  const mapped=mapVmFlowBytes(data,input.runtimeBase,input.rows.map(r=>({groupIndex:r.groupIndex,recordingId:r.recordingId,intermediateStateAvailable:true,instructions:[{pc:r.runtimePc,bytes:r.bytes}]})));
  if(mapped.preferredBase!==input.preferredBase||mapped.mapping.some((r,i)=>Object.keys(r).some(k=>r[k]!==input.rows[i][k])))fail('original executable file byte mapping differs');
 }
 return raw;
}
export function makeRecordedCoordinateInput({targetSha256,mapping,body,source,recurrencesRef,selectionRef}){
 if(mapping?.originalOpcodeBytesMatched!==true||mapping.mapping.length!==body.groups.length)fail('complete byte mapping required');
 const used=new Set(body.groups.map(g=>g.recordingId));
 const input={schema:'ig5-recorded-runtime-code-input-v1',targetSha256,preferredBase:mapping.preferredBase,runtimeBase:mapping.runtimeBase,
  source:{recurrencesRef:{id:recurrencesRef.id,sha256:recurrencesRef.sha256},selectionRef:{id:selectionRef.id,sha256:selectionRef.sha256},runId:source.identity.runId,threadId:source.identity.threadId,
   windows:source.windows.filter(w=>used.has(w.reportId)).map(({reportId,reportSha256,traceSha256})=>({reportId,reportSha256,traceSha256}))},
  rows:mapping.mapping.map((r,i)=>{const g=body.groups[i];if(g.intermediateStateAvailable!==true||g.instructions.length!==1||g.before.rip!==r.runtimePc||g.instructions[0].pc!==r.runtimePc||g.instructions[0].bytes!==r.bytes||g.groupIndex!==r.groupIndex||g.recordingId!==r.recordingId)fail('original group mapping differs');return{...r,pauseBefore:g.pauseSequence.before,pauseAfter:g.pauseSequence.after};})};
 validateRecordedCoordinateInput(input);return input;
}
export function validateRecordedCoordinateBinding(core,input){
 const raw=validateRecordedCoordinateInput(input),b=core?.recordedCoordinates;
 if(b?.schema!=='ig5-recorded-runtime-code-binding-v1'||b.inputSha256!==hashBytes(raw)||!same(b.input,input)||b.ordinaryDataRelocated!==false||b.globalCodeEpochProved!==false||core.targetSha256!==input.targetSha256)fail('result byte-coordinate provenance');
 if(!same(core.originalPreferredPath,input.rows.map(r=>r.preferred))||!same(core.projectionPath,input.rows.map(r=>r.runtimePc))||core.projectionDecoder!=='java'||core.projectionMode!=='opaque-status'||!Array.isArray(core.decodedPath)||core.decodedPath.length!==input.rows.length)fail('result coordinate scope');
 for(const [i,r]of input.rows.entries()){const d=core.decodedPath[i];if(d.ea!==r.runtimePc||d.bytes!==r.bytes||d.decoded?.ea!==r.runtimePc||d.decoded?.size!==r.bytes.length/2)fail('decoded runtime byte boundary');}
 return b;
}
export function needsRecordedRuntimeCoordinates(decoded){
 return decoded.at(-1)?.controlFlow===false||decoded.some(d=>d.operands?.some(o=>o.kind==='register'&&['rip','eip','ip'].includes(o.name)||o.kind==='memory'&&[o.base,o.index].some(r=>r&&['rip','eip','ip'].includes(r.name))));
}
