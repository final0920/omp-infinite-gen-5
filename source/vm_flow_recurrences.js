import { analyzeVmObservations } from './vm_observations.js';
import { prepareRecordedFlow, replayRecordedFlow } from './recorded_flow_eval.js';
import { flowPairSelection,observeFlowSource } from './flow_pair_sampling.js';
const fail=m=>{throw new Error('Invalid recorded flow recurrence: '+m);};
const hex=v=>'0x'+v.toString(16),unique=a=>[...new Set(a)];
/** Match a complete byte/PC descriptor across all original recording groups.
 * A project path has unique PCs, so only one occurrence can be pending. Every
 * input is still parsed after capture limits, mismatches or selected samples.
 */
export function analyzeFlowRecurrences(request){
  const {flow,full,prefix}=request,prepared=prepareRecordedFlow(prefix,full),descriptor=flow?.mapping?.mapping;
  const selection=flowPairSelection(request.sampleStrategy,request.pairOffset),diverse=selection.strategy==='distinct-source-targets';
  if(!Array.isArray(descriptor)||descriptor.length<1||descriptor.length>128||descriptor.length!==full.projectionPath.length
    ||new Set(descriptor.map(d=>d.runtimePc)).size!==descriptor.length||flow.targetSha256!==request.targetSha256
    ||full.targetSha256!==request.targetSha256||flow.sourceLoad?.signature!==prepared.dependency.sourceLoad.signature
    ||descriptor.some((d,i)=>typeof d.runtimePc!=='string'||!/^0x[0-9a-f]{1,16}$/.test(d.runtimePc)
      ||d.preferred!==full.projectionPath[i]||d.bytes!==full.decodedPath[i].bytes)
    ||typeof flow.mapping.runtimeBase!=='string'||!/^0x[0-9a-f]{1,16}$/.test(flow.mapping.runtimeBase)
    ||typeof flow.mapping.preferredBase!=='string'||!/^0x[0-9a-f]{1,16}$/.test(flow.mapping.preferredBase)
    ||flow.seed?.pc!==descriptor[0].runtimePc||flow.seed?.bytes!==descriptor[0].bytes
    ||descriptor.some(d=>BigInt(d.runtimePc)-BigInt(flow.mapping.runtimeBase)!==BigInt(d.preferred)-BigInt(flow.mapping.preferredBase)))fail('descriptor/source binding');
  let active=null,starts=0,complete=0,mismatches=0,coalescedSources=0,changedSourceBytes=0,oversized=0;
  const first=[],last=[],diversePaths=[],inventory=new Map(),mismatchExamples=[],changedExamples=[],unobservedExamples=[];
  let unobservedPairs=0,unindexedPairs=0;
  const finish=item=>{
    complete++;const occurrence={ordinal:complete,startGroup:item.startGroup,endGroup:item.endGroup,groupCount:descriptor.length,
      firstRecordingId:item.firstRecordingId,lastRecordingId:item.lastRecordingId,firstPause:item.firstPause,lastPause:item.lastPause,
      snapshotCaptureComplete:!item.captureExhausted,groups:item.groups};
    if(item.captureExhausted)oversized++;
    if(!diverse){if(complete<=4)first.push(occurrence);last.push(occurrence);if(last.length>4)last.shift();return;}
    if(item.sourceObservation.status!=='observed'){
      unobservedPairs++;if(unobservedExamples.length<8)unobservedExamples.push({startGroup:item.startGroup,recordingId:item.firstRecordingId,reason:item.sourceObservation.reason});return;
    }
    const observed=item.sourceObservation,key=observed.value+':'+item.target;
    let pair=inventory.get(key);
    if(!pair){
      if(inventory.size>=256){unindexedPairs++;return;}
      pair={ordinal:inventory.size,observedValue:observed.value,target:item.target,completePaths:0,
        firstOccurrence:{startGroup:item.startGroup,endGroup:item.endGroup,recordingId:item.firstRecordingId,pause:item.firstPause,sourceRead:observed}};inventory.set(key,pair);
      if(pair.ordinal>=selection.pairOffset&&pair.ordinal<selection.pairOffset+8)diversePaths.push({...occurrence,observedPairOrdinal:pair.ordinal});
    }
    pair.completePaths++;
  };
  const capture=(item,g)=>{
    item.position++;item.endGroup=g.groupIndex;item.lastRecordingId=g.recordingId;item.lastPause=g.pauseSequence.after;item.target=g.after.rip;
    if(!item.captureExhausted){item.bytes+=Buffer.byteLength(JSON.stringify(g));
      if(item.bytes>256*1024){item.groups=[];item.captureExhausted=true;}else item.groups.push(g);}
    if(item.position===descriptor.length){finish(item);active=null;}
  };
  const source=analyzeVmObservations({targetSha256:request.targetSha256,windows:request.windows,maxInstructions:request.maxInstructions,offset:0,limit:1},g=>{
    const one=g.intermediateStateAvailable===true&&g.instructions.length===1,head=g.instructions[0];
    for(const [index,i] of g.instructions.entries())if(i.pc===descriptor[0].runtimePc){
      if(i.bytes!==descriptor[0].bytes){changedSourceBytes++;if(changedExamples.length<8)changedExamples.push({groupIndex:g.groupIndex,recordingId:g.recordingId,pc:i.pc,expectedBytes:descriptor[0].bytes,observedBytes:i.bytes});}
      else{starts++;if(!one||index!==0)coalescedSources++;}
    }
    if(active){
      const d=descriptor[active.position];
      if(one&&head.pc===d.runtimePc&&head.bytes===d.bytes){capture(active,g);return;}
      mismatches++;if(mismatchExamples.length<8)mismatchExamples.push({startGroup:active.startGroup,capturedGroups:active.position,
        failedGroup:g.groupIndex,expected:d,observed:g.instructions,reason:one?'byte-or-control-path-differs':'intermediate-state-unavailable'});
      active=null;
    }
    if(one&&head.pc===descriptor[0].runtimePc&&head.bytes===descriptor[0].bytes){
      active={startGroup:g.groupIndex,position:0,bytes:0,captureExhausted:false,groups:[],firstRecordingId:g.recordingId,firstPause:g.pauseSequence.before,
        ...(diverse?{sourceObservation:observeFlowSource(prepared,g)}:{})};capture(active,g);
    }
  });
  if(source.identity.runtimeBase!==flow.mapping.runtimeBase)fail('recorded runtime base differs');
  const selected=(diverse?diversePaths:[...new Map([...first,...last].map(o=>[o.startGroup,o])).values()]).sort((a,b)=>a.startGroup-b.startGroup);
  const occurrences=selected.map(({groups,...item})=>{
    if(!item.snapshotCaptureComplete)return{...item,status:'unverified',reason:'256 KiB selected occurrence snapshot budget exhausted'};
    try{return{...item,...replayRecordedFlow(prepared,groups)};}
    catch(error){return{...item,status:'unverified',reason:String(error.message).slice(0,512)};}
  });
  const good=occurrences.filter(o=>o.status==='consistent-recorded-ordinary-state'),updates=prepared.sourceAddressInputs.map(name=>{
    const values=good.flatMap(o=>o.sourceAddressInputUpdates.filter(r=>r.name===name));
    return{name,observations:values.length,observedDeltasModulo64:unique(values.map(r=>r.deltaModulo64)),observedBeforeValues:unique(values.map(r=>r.before)),
      role:'unassigned',universalUpdateProved:false};
  });
  const tableInputs=prepared.indexedAddressInputs.map(r=>({node:r.node,inputs:r.inputs.filter(n=>!prepared.sourceAddressInputs.includes(n)).map(name=>({name,
    observedValues:unique(good.flatMap(o=>o.indexedAddressInputValues.filter(t=>t.node===r.node).flatMap(t=>t.inputs.filter(v=>v.name===name).map(v=>v.value)))),role:'unassigned',constantAcrossVmInstancesProved:false}))}));
  const pairs=new Map();for(const o of good){const key=o.sourceValue+':'+o.target;const p=pairs.get(key)||{sourceValue:o.sourceValue,target:o.target,selectedOccurrences:0};p.selectedOccurrences++;pairs.set(key,p);}
  const {stopGroups,pagination,...recordedSource}=source;
  const result={schema:'ig5-flow-recurrences-v1',targetSha256:request.targetSha256,source:recordedSource,descriptor,
    counts:{sourceByteEvents:starts,completeDescriptorPaths:complete,pathMismatches:mismatches,coalescedSourceEvents:coalescedSources,
      changedBytesAtSourcePc:changedSourceBytes,completePathsExceedingSnapshotBudget:oversized,selectedCompletePaths:occurrences.length,selectedOrdinaryConsistent:good.length,
      selectedOrdinaryUnverified:occurrences.length-good.length},
    sampling:{strategy:'first4-last4-complete-descriptor-paths',maximumSelected:8,maximumGroupsPerPath:128,maximumSelectedLogicalGroups:1024,
      maximumCapturedBytesPerPath:256*1024,selectedLogicalGroups:occurrences.reduce((s,o)=>s+o.groupCount,0),maximumReplayMemoryVisitsPerPath:4096,
      selectionIsWholeCompletePathSet:complete===occurrences.length,allInputWindowsValidated:true,allDescriptorPathsCompared:true},
    occurrences,sourceAddressInputUpdates:updates,indexedAddressNonSourceInputs:tableInputs,selectedSourceTargetPairs:[...pairs.values()],
    mismatchExamples,mismatchExamplesComplete:mismatches===mismatchExamples.length,changedSourceByteExamples:changedExamples,changedSourceByteExamplesComplete:changedSourceBytes===changedExamples.length,
    partialCapturedPaths:active?[{startGroup:active.startGroup,capturedGroups:active.position,requiredGroups:descriptor.length,reason:'supplied-recording-end'}]:[],
    selectedOrdinaryStateConsistent:occurrences.length>0&&good.length===occurrences.length,entireRecordingOrdinaryStateVerified:false,
    nativeTargetExecuted:false,changesExecutionAuthority:false,databaseModified:false,instructionSemanticsProved:false,vmRoleProved:false,businessAccepted:false,wholeFunctionCoverageProved:false,
    wholeVmRecovered:false,nativeReachabilityProved:false,distinctRecordedRuns:1,distinctVmInstancesProved:false,independentInputCoverageProved:false,
    moduleLoadEpoch:null,memoryEpoch:null,codeDataCoherenceProved:false,independentCpuStoreFootprintProved:false,
    ordinaryProgramAmbiguity:'Ordinary indexed tables, buffer parsers and return trampolines can recur with identical observations',
    nextObligations:['Separate repeated source/pointer/table candidates from ordinary program behavior','Establish distinct VM context/instances and memory/module epochs',
      'Recover VM ISA and concrete bytecode program under explicit function contracts','Validate complete business across independent inputs and alternate paths'],
    intermediateGprSemanticsVerified:false,
    scope:'Entire recording structurally revalidated and descriptor bytes compared; first4/last4 complete paths checked for ordinary IR final GPR/target and ordered decoded STORE consistency using finite observed RAM. No missing RAM fill or intermediate-GPR/CPU/flags/store-completeness, cross-instance, VM-role or business proof'};
  if(diverse){
    result.sampling.strategy='first-per-observed-source-target-pair-page';result.sampling.pairOffset=selection.pairOffset;
    result.observedSourceTargetInventory={schema:'ig5-observed-source-target-inventory-v1',maximumTrackedPairs:256,pairs:[...inventory.values()],
      trackingComplete:unindexedPairs===0&&unobservedPairs===0,countsAreLowerBounds:unindexedPairs>0||unobservedPairs>0,unindexedCompletePaths:unindexedPairs,sourceReadUnobservedCompletePaths:unobservedPairs,
      unobservedExamples,selectedPairOrdinals:occurrences.map(o=>o.observedPairOrdinal),
      nextPairOffset:selection.pairOffset+8<inventory.size?selection.pairOffset+8:null,
      allCompletePathsAccountedFor:true,inventoryIsOrdinaryStateReplay:false,sourceValuesAreOpcodeLabels:false,vmRoleProved:false,businessAccepted:false,
      scope:'Pure initial-GPR source address matched to exact recorded narrow RAM read plus observed terminal RIP; all descriptor matches inventoried up to 256 pairs. Only selected paths receive complete ordinary-state replay'};
    result.scope='All original inputs and descriptor matches revalidated; first complete occurrence for each observed source/target pair in the selected eight-pair page receives bounded ordinary full-state consistency checks. Inventory is observational, not opcode/VM/phase/CPU/business classification; unknown reads and inventory omissions remain explicit';
  }
  if(Buffer.byteLength(JSON.stringify(result))>4*1024**2)fail('4 MiB recurrence report budget');
  return result;
}
