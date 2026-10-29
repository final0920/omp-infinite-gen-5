import fs from'node:fs';import path from'node:path';import{randomUUID}from'node:crypto';
import{readStableFile,hashBytes}from'./analysis_artifacts.js';
export const DISCOVERY_PIN='65bf673f1c4304cc2c09076e3b96e368da9e0df72aa0badeba0c2a5cae392934';
const RUNTIME_PIN='8fc4ae42f775f0139aa5f184c912db71f77e68d661c14564ab6f4820d434abea',MASK=(1n<<64n)-1n;
const hex=x=>typeof x==='string'&&/^0x[0-9a-f]{1,16}$/i.test(x)&&BigInt(x)>0n;
const canonical=x=>JSON.stringify(x,(_k,v)=>v&&typeof v==='object'&&!Array.isArray(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])):v);
const fail=()=>{throw Error('Discovery returned inconsistent candidate/provenance scope');};
const system=new Set('syscall sysenter sysexit sysret sysretq int int1 int3 into iret iretd iretq hlt ud0 ud1 ud2 xabort xbegin xend rsm vmcall vmmcall vmlaunch vmresume encls enclu'.split(' '));
export function validateDiscovery(args){
 if(!args||typeof args!=='object'||Array.isArray(args)||Object.keys(args).some(k=>!['target','level','ea','max_instructions','follow_direct_calls','engine'].includes(k)))throw Error('level=discover accepts only target,ea and optional max_instructions/follow_direct_calls');
 if(args.level!=='discover'||typeof args.target!=='string'||!path.isAbsolute(args.target)||args.target.includes('\0')||!hex(args.ea))throw Error('Discovery requires an absolute target and nonzero preferred uint64 ea');
 if(args.engine!==undefined&&!['reverse','ghidra'].includes(args.engine))throw Error('Discovery is independent of database engines');
 const maximum=Object.hasOwn(args,'max_instructions')?args.max_instructions:128;if(!Number.isSafeInteger(maximum)||maximum<1||maximum>128)throw Error('Discovery max_instructions must be1..128');
 const follow=Object.hasOwn(args,'follow_direct_calls')?args.follow_direct_calls:false;if(typeof follow!=='boolean')throw Error('follow_direct_calls must be Boolean');return{ea:'0x'+BigInt(args.ea).toString(16),max_instructions:maximum,follow_direct_calls:follow};
}
function byteControl(row){
 const b=Buffer.from(row.bytes,'hex'),ea=BigInt(row.ea),next=(ea+BigInt(b.length))&MASK,m=row.text.trim().split(/\s+/)[0].toLowerCase(),h=x=>'0x'+x.toString(16);
 if(system.has(m))return{kind:'system',successors:[]};
 if(row.controlFlow){
  if(b[0]===0xe9&&b.length===5||b[0]===0xeb&&b.length===2){if(m!=='jmp'||!row.branch)fail();return{kind:'direct-jump',successors:[h((next+BigInt(b.length===5?b.readInt32LE(1):b.readInt8(1)))&MASK)]};}
  if(m.startsWith('ret'))return{kind:'return',successors:[]};
  if(['call','lcall'].includes(m)){if(m==='call'&&b[0]===0xe8&&b.length===5)return{kind:'call',successors:[h((next+BigInt(b.readInt32LE(1)))&MASK)],returnAddress:h(next)};return{kind:'call',successors:[]};}
  if(m!=='jmp'&&row.branch){let target;
   if(b.length===2&&(b[0]>=0x70&&b[0]<=0x7f||b[0]>=0xe0&&b[0]<=0xe3))target=(next+BigInt(b.readInt8(1)))&MASK;
   else if(b.length===6&&b[0]===0x0f&&b[1]>=0x80&&b[1]<=0x8f)target=(next+BigInt(b.readInt32LE(2)))&MASK;
   return{kind:'conditional',successors:target===undefined?[]:[h(target),h(next)]};}
  return{kind:'unresolved-control',successors:[]};
 }
 if(row.branch||['jmp','ljmp','call','lcall'].includes(m)||m.startsWith('ret'))fail();
 return{kind:'fallthrough',successors:[h(next)]};
}
/** Independent file-byte mapping/shape checks; not a second instruction decoder. */
export function validateDiscoveryResult(c,selected,data,sha){
 if(!c||c.schema!=='ig5-path-discovery-v1'||c.status!=='partial'||c.recoveryStatus!=='unverified'||c.targetSha256!==sha||c.runtimeManifestPin!==RUNTIME_PIN||c.decoderManifestPin!==DISCOVERY_PIN||c.decoder!=='pinned-triton-disassembly-only'||c.entry!==selected.ea||c.maxInstructions!==selected.max_instructions||c.followDirectCalls!==selected.follow_direct_calls||c.candidateOnly!==true||['pathSemanticsValidated','nativeReachabilityProved','nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'].some(k=>c[k]!==false))fail();
 if(!Array.isArray(c.instructions)||!c.instructions.length||c.instructions.length>selected.max_instructions||!Array.isArray(c.candidatePath)||canonical(c.candidatePath)!==canonical(c.instructions.map(r=>r.ea))||new Set(c.candidatePath).size!==c.candidatePath.length)fail();
 const u16=o=>{if(!Number.isSafeInteger(o)||o<0||o+2>data.length)fail();return data.readUInt16LE(o);},u32=o=>{if(!Number.isSafeInteger(o)||o<0||o+4>data.length)fail();return data.readUInt32LE(o);};
 if(data.length<64||data.toString('ascii',0,2)!=='MZ')fail();const pe=u32(0x3c),optional=pe+24,count=u16(pe+6),optSize=u16(pe+20);
 if(pe+24>data.length||data.toString('hex',pe,pe+4)!=='50450000'||u16(pe+4)!==0x8664||optSize<112||u16(optional)!==0x20b||count<1||count>4096||optional+optSize+count*40>data.length)fail();
 const base=data.readBigUInt64LE(optional+24),regions=[];
 for(let i=0;i<count;i++){let s=optional+optSize+i*40,start=base+BigInt(u32(s+12)),size=u32(s+16),offset=u32(s+20),execute=!!(u32(s+36)&0x20000000);if(offset+size>data.length||start+BigInt(size)>1n<<64n)fail();regions.push({start,size,offset,execute});}
 const mapped=(address,size=1)=>regions.filter(r=>address>=r.start&&address+BigInt(size)<=r.start+BigInt(r.size));
 let next=selected.ea;const intervals=[];
 for(const [i,row]of c.instructions.entries()){
  if(!row||!hex(row.ea)||row.ea!=='0x'+BigInt(row.ea).toString(16)||row.ea!==next||typeof row.bytes!=='string'||!/^([0-9a-f]{2}){1,15}$/.test(row.bytes)||!Number.isSafeInteger(row.size)||row.size!==row.bytes.length/2||typeof row.text!=='string'||!row.text.trim()||row.text.length>2048||typeof row.controlFlow!=='boolean'||typeof row.branch!=='boolean')fail();
  const address=BigInt(row.ea),regionsAt=mapped(address,row.size);if(regionsAt.length!==1||!regionsAt[0].execute||intervals.some(([a,n])=>address<a+BigInt(n)&&a<address+BigInt(row.size)))fail();
  const r=regionsAt[0],off=r.offset+Number(address-r.start);if(data.subarray(off,off+row.size).toString('hex')!==row.bytes||canonical(byteControl(row))!==canonical(row.control))fail();intervals.push([address,row.size]);
  if(i<c.instructions.length-1&&!['fallthrough','direct-jump'].includes(row.control.kind)&&!(selected.follow_direct_calls&&row.control.kind==='call'&&row.control.successors.length))fail();next=row.control.successors[0];
 }
 const last=c.instructions.at(-1),s=c.stop;if(!s||typeof s!=='object'||Array.isArray(s))fail();
 if(!['fallthrough','direct-jump'].includes(last.control.kind)&&!(selected.follow_direct_calls&&last.control.kind==='call'&&last.control.successors.length)){if(s.reason!==last.control.kind||s.next!==null)fail();}
 else{
  if(s.next!==next||typeof next!=='string'||!/^0x[0-9a-f]{1,16}$/.test(next))fail();const n=BigInt(next);
  if(s.reason==='instruction-budget'){if(c.instructions.length!==selected.max_instructions)fail();}
  else if(s.reason==='cycle'){if(!c.candidatePath.includes(next)||c.instructions.length===selected.max_instructions)fail();}
  else if(s.reason==='overlap'){
   if(s.nextSize!==undefined){if(!Number.isSafeInteger(s.nextSize)||s.nextSize<1||s.nextSize>15||!intervals.some(([a,l])=>n<a+BigInt(l)&&a<n+BigInt(s.nextSize)))fail();}
   else if(!intervals.some(([a,l])=>a<n&&n<a+BigInt(l)))fail();
  }else if(s.reason==='unmapped-or-nonexecutable'){let r=mapped(n);if(r.length===1&&r[0].execute)fail();}
  else fail();
 }
 if(Object.keys(s).some(k=>!['reason','next',...(s.reason==='overlap'?['nextSize']:[])].includes(k)))fail();
 return c;
}
export async function runDiscovery(jobs,args,signal){
 const selected=validateDiscovery(args);if(jobs.closed||signal?.aborted)throw Error('Discovery cancelled');if(jobs.active.size>=2)throw Error('Analysis busy; maximum two owned requests');
 const{data}=readStableFile(args.target,64*1024**2),input=jobs.artifacts.put(data),jobId=randomUUID(),parent=path.join(jobs.artifacts.root,'jobs');
 if(fs.realpathSync(parent)!==parent||!fs.lstatSync(parent).isDirectory())throw Error('Discovery jobs directory must be physical');const directory=path.join(parent,jobId);fs.mkdirSync(directory);
 const reply=await jobs.request({job_id:jobId,sha256:input.sha256,...selected},signal,'discover'),p=reply?.process;
 if(reply?.runtimeManifestPin!==RUNTIME_PIN||reply?.targetSha256!==input.sha256||p?.status!=='completed'||p.exitCode!==0||p.limitReason!==null||p.childExitConfirmed!==true||p.jobAssignedAtCreation!==true||p.activeProcessLimit!==1||p.memoryLimitBytes!==2*1024**3||!Number.isSafeInteger(p.pid)||p.pid<1||!Number.isSafeInteger(p.elapsedMs)||p.elapsedMs<0||!Number.isSafeInteger(reply.sharedBudgetMs)||reply.sharedBudgetMs<1||reply.sharedBudgetMs>50000||!Number.isSafeInteger(reply.processBudgetMs)||reply.processBudgetMs<1||reply.processBudgetMs>reply.sharedBudgetMs||p.elapsedMs>reply.processBudgetMs+100||reply.processStages!==undefined||!Number.isSafeInteger(reply.outputBytes)||reply.outputBytes<1||reply.outputBytes>4*1024**2)fail();
 const{data:output}=readStableFile(path.join(directory,'stdout.log'),4*1024**2);if(output.length!==reply.outputBytes||hashBytes(output)!==reply.outputSha256)fail();
 const result=validateDiscoveryResult(JSON.parse(output.toString('utf8')),selected,data,input.sha256),outputRef=jobs.artifacts.put(output);
 const record=jobs.artifacts.save({kind:'path-discovery',action:'discover',target:args.target,input,outputRef,process:p,result},{pretty:true,maxBytes:4*1024**2});
 return{reportSchema:result.schema,status:'partial',recoveryStatus:'unverified',candidateOnly:true,pathSemanticsValidated:false,instructionCount:result.instructions.length,stop:result.stop,nativeTargetExecuted:false,databaseModified:false,businessAccepted:false,wholeBinaryVerified:false,entry:result.entry,candidatePath:result.candidatePath,decoder:result.decoder,decoderManifestPin:DISCOVERY_PIN,process:p,
  followDirectCalls:result.followDirectCalls,processBudgetMs:reply.processBudgetMs,sharedBudgetMs:reply.sharedBudgetMs,validation:{originalBytesAndControlMetadataChecked:true,independentInstructionDecoder:false,nextStep:'Submit candidatePath to explicit Java project; preserve all semantic/flags refusals.'},reportPath:path.join(jobs.artifacts.root,'records',record.id+'.json'),reportSha256:jobs.artifacts.metadata(record.id).result.recordSha256};
}
