import { analyzeVmObservations } from './vm_observations.js';
/** Whole-input scan, retaining only bodies following selected, already
 * revalidated fetch occurrences. A following exact head closes a body even
 * when the following fetch itself is only a recorded suffix. */
export function selectRecordedHandlerBodies(request){
  const {recurrence}=request,head=recurrence?.descriptor?.[0],items=recurrence?.occurrences;
  if(!head||!Array.isArray(items)||items.length>8||items.some(o=>!Number.isSafeInteger(o.endGroup)||o.endGroup<0)
    ||new Set(items.map(o=>o.endGroup)).size!==items.length)throw Error('Invalid recorded handler source');
  const selected=new Map(items.map(o=>[o.endGroup,o])),bodies=[];let active=null;
  const close=(boundary,reason)=>{
    active.nextFetchGroup=boundary?.groupIndex??null;active.completeNextBoundary=!!boundary;
    active.selectionStatus=active.reason||reason?'unverified':'observed-boundary';
    if(reason&&!active.reason)active.reason=reason;
    if(!active.groupCount){active.selectionStatus='unverified';active.reason='empty observed body';}
    bodies.push(active);active=null;
  };
  const observation=analyzeVmObservations({...request,offset:0,limit:1},g=>{
    if(active){
      const event=g.instructions.find(i=>i.pc===head.runtimePc);
      if(event){
        if(g.intermediateStateAvailable===true&&g.instructions.length===1&&event.bytes===head.bytes)close(g);
        else close(null,'changed or coalesced next fetch head');
      }else{
        active.groupCount++;
        if(!active.reason){
          if(active.groupCount===1&&g.instructions[0].pc!==active.observedEntry)active.reason='recorded dispatch target does not enter this body';
          else if(g.intermediateStateAvailable!==true||g.instructions.length!==1)active.reason='missing intermediate body state';
          else if(active.groupCount>128)active.reason='128 body-group budget';
          else if(active.capturedBytes+Buffer.byteLength(JSON.stringify(g))>262144)active.reason='256 KiB body snapshot budget';
          if(active.reason)active.groups=[];
          else{active.capturedBytes+=Buffer.byteLength(JSON.stringify(g));active.groups.push(g);}
        }
      }
    }
    const o=selected.get(g.groupIndex);
    if(o){
      if(active)close(null,'overlapping selected source boundaries');
      active={sourceOccurrence:o.startGroup,sourceValue:o.sourceValue??null,observedEntry:o.target??null,sourceStatus:o.status,
        groupCount:0,capturedBytes:0,groups:[],...(o.status==='consistent-recorded-ordinary-state'?{}:{reason:'source ordinary state is not verified'})};
    }
  });
  if(active)close(null,'supplied recording ends before the next fetch');
  if(bodies.length!==items.length)throw Error('Recorded handler source boundaries absent');
  const{stopGroups,pagination,...source}=observation;
  return{schema:'ig5-recorded-handler-windows-v1',targetSha256:request.targetSha256,source,bodies,allInputWindowsValidated:true,
    maximumBodies:8,maximumGroupsPerBody:128,maximumCapturedBytesPerBody:262144,nativeTargetExecuted:false,businessAccepted:false,vmRoleProved:false};
}
