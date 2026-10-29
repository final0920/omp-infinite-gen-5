import { analyzeVmObservations } from '../vm_observations.js';
import { executeBytecode, decodeBytecode } from '../vm_bytecode.js';
import { planningDigest } from '../planning_identity.js';

/** Fixed owned source only. Rechecks original instruction bytes, entry, return, recorded STORE bytes and fetch predictions.
 * This is finite recorded evidence, not a complete native CPU semantic proof. */
export function verifyRecordedFunction(program,contract,recordedRuns) {
  if(!Array.isArray(recordedRuns)||recordedRuns.length>8)throw new Error('At most eight original runs');
  if(recordedRuns.length&&program.sourceKind!=='registered-owned-pe64')throw new Error('Native recordings require the registered owned PE');
  const image=Buffer.from(program.sourceImageHex,'hex'),runs=[];
  for(const {windows} of recordedRuns) {
    const groups=[];const observed=analyzeVmObservations({targetSha256:contract.targetSha256,windows,limit:1},g=>groups.push(g));
    const first=groups[0],last=groups.at(-1),base=BigInt(windows[0].summary.runtimeBase),output=base+0x3000n;
    const input=BigInt(first.before.gprs.rcx),expected=executeBytecode(program.model,input),errors=[],fetches=[],stores=[];
    const code=Buffer.from(program.model.codeHex,'hex'),expectedReads=[];
    for(const step of expected.path){const decoded=decodeBytecode(code,step.pc,step.key,program.model.decoder);
      for(let byte=0;byte<decoded.width;byte++)expectedReads.push({at:step.pc+byte,byte:code[step.pc+byte],jumpOperand:byte===1&&step.opcode===6});}
    let outputState=null,loadCount=0;
    if(first.before.rip!=='0x'+(base+BigInt(contract.entryRva)).toString(16))errors.push('entry-mismatch');
    for(let n=0;n<groups.length;n++) {
      const g=groups[n];
      if(g.instructions.length!==1){errors.push('missing-intermediate-state');continue;}
      const ins=g.instructions[0],rva=BigInt(ins.pc)-base;
      if(rva<0x1000n||rva>=0x1400n||image.subarray(0x400+Number(rva-0x1000n),0x400+Number(rva-0x1000n)+ins.bytes.length/2).toString('hex')!==ins.bytes)errors.push('executed-code-version-mismatch');
      if(g.memoryWrites.status!=='decoded-locations-observed-across-stop'||!g.memoryWrites.completeDecodedStoreSet)errors.push('store-observation-incomplete');
      for(const store of g.memoryWrites.stores??[]) {
        stores.push({...store,groupIndex:g.groupIndex});
        if(BigInt(store.address)!==output||store.bytes!==8||store.status!=='observed'||typeof store.afterHex!=='string')errors.push('unexpected-or-unknown-output-store');
        if(outputState!==null&&store.beforeHex!==outputState)errors.push('recorded-output-memory-state-conflict');
        outputState=store.afterHex;
      }
      if(ins.bytes==='498b01') {
        loadCount++;const read=g.memoryReads.find(r=>BigInt(r.address)===output&&r.bytes===8);
        if(!read||read.littleEndianHex!==outputState||!outputState||BigInt(g.after.gprs.rax)!==BigInt('0x'+outputState.match(/../g).reverse().join('')))
          errors.push('cross-handler-output-load-mismatch');
      }
      if(ins.bytes==='410fb612') {
        const address=BigInt(g.before.gprs.r10),at=address-base-0x3100n,read=g.memoryReads.find(r=>BigInt(r.address)===address&&r.bytes===1);
        const predicted=expectedReads[fetches.length];
        if(at<0n||at>=BigInt(code.length)||!predicted||at!==BigInt(predicted.at)||!read||read.littleEndianHex!==code.subarray(Number(at),Number(at)+1).toString('hex')
          ||BigInt(g.after.gprs.rdx)!==BigInt('0x'+read.littleEndianHex))errors.push('fetch-prediction-mismatch');
        const update=groups[n+1];
        if(predicted?.jumpOperand) {
          if(!update||update.instructions[0]?.bytes!=='4d8d1413'||!read||BigInt(update.after.gprs.r10)!==base+0x3100n+BigInt('0x'+read.littleEndianHex))errors.push('fetch-updater-mismatch');
        } else if(!update||update.instructions[0]?.bytes!=='49ffc2'||BigInt(update.after.gprs.r10)!==address+1n)errors.push('fetch-updater-mismatch');
        fetches.push({address:'0x'+address.toString(16),sourceByte:read?.littleEndianHex??null,groupIndex:g.groupIndex});
      }
    }
    if(windows.at(-1).summary.stopReason!=='returned'||last.instructions[0]?.bytes!=='c3'
      ||last.before.gprs.rsp!==first.before.gprs.rsp||BigInt(last.after.gprs.rsp)!==BigInt(first.before.gprs.rsp)+8n)errors.push('normal-return-not-observed');
    const returnRead=last.memoryReads.find(r=>r.address===last.before.gprs.rsp&&r.bytes===8);
    if(!returnRead||BigInt('0x'+returnRead.littleEndianHex.match(/../g).reverse().join(''))!==BigInt(last.after.rip))errors.push('return-target-observation-mismatch');
    if(stores.length!==expected.orderedStores.length||stores[0]?.afterHex!==Buffer.from(Array.from({length:8},(_,i)=>Number((input>>BigInt(i*8))&255n))).toString('hex'))errors.push('input-initialization-store-mismatch');
    for(let i=0;i<stores.length;i++)if(!expected.orderedStores[i]||stores[i].afterHex!==Buffer.from(Array.from({length:8},(_,j)=>Number((BigInt(expected.orderedStores[i].value)>>BigInt(j*8))&255n))).toString('hex'))errors.push('ordered-output-store-mismatch');
    if(loadCount!==expected.path.filter(step=>step.opcode===4).length)errors.push('output-load-coverage-mismatch');
    if(last.after.gprs.rax!==expected.returnValue||stores.at(-1)?.afterHex!==expected.memoryHex)errors.push('return-or-output-memory-mismatch');
    if(fetches.map(f=>f.sourceByte).join('')!==expectedReads.map(r=>r.byte.toString(16).padStart(2,'0')).join(''))errors.push('bytecode-fetch-coverage-mismatch');
    const inDomain=input>=BigInt(contract.input.minimum)&&input<=BigInt(contract.input.maximum),location=windows[0].executionLocation;
    runs.push({identity:observed.identity,input:'0x'+input.toString(16),inDomain,status:errors.length?'fail':'pass',errors:[...new Set(errors)],
      recordingRefs:windows.map(w=>({id:w.source.reportId,sha256:w.source.reportSha256})),groups:groups.length,fetches,
      outputMemoryHex:stores.at(-1)?.afterHex??null,returnValue:last.after.gprs.rax,
      executionInstance:location?.serverInstanceId&&location?.sessionId?planningDigest([location,observed.identity.runId,observed.identity.threadId]):null,
      fixedSourceVmInvocation:planningDigest([contract.targetSha256,location??null,observed.identity.runId,observed.identity.threadId,windows[0].summary.runtimeBase,first.pauseSequence.before]),
      vmInstanceAssurance:'single-invocation fixed-owned-source premise; not generic VM-instance discovery',
      codeVersionScope:'every recorded executed instruction matched exact registered image bytes',codeStableBetweenObservations:false});
  }
  return {status:runs.length?(runs.every(r=>r.status==='pass')?'pass':'fail'):'not-supplied',runs,
    independence:{distinctRuns:new Set(runs.map(r=>r.identity.runId)).size,distinctInputs:new Set(runs.map(r=>r.input)).size,
      inDomainDistinctInputs:new Set(runs.filter(r=>r.inDomain&&r.status==='pass').map(r=>r.input)).size,
      distinctFixedSourceVmInvocations:new Set(runs.map(r=>r.fixedSourceVmInvocation)).size},
    freshNativeExecution:false,nativeCpuEquivalenceProved:false,cpuWriteFootprintProved:false,
    scope:'registered owned source, original captured function paths; out-of-domain inputs retained separately'};
}
