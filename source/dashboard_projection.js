// Logged conversation activity only. This projection never owns processes,
// approves execution, or releases an analysis/debug lease.
export function ig5DashDefinition() {
  const anySchema={parse:value=>value};
  const validId=id=>typeof id==='string'&&id.length>0&&id.length<=256;
  return {
    key:'ig5dash',stateVersion:2,stateSchema:anySchema,
    init:()=>({running:null,tool:null,calls:0,errors:0,last:null,lastSummary:null,pending:{}}),
    apply(state,event) {
      if(!event||typeof event!=='object')return state;
      const d=event.data;
      if(event.type==='tool/call') {
        if(typeof d?.name!=='string'||!d.name.startsWith('ig5_')||!validId(d.callId)||Object.hasOwn(state.pending,d.callId))return state;
        const pending={...state.pending,[d.callId]:d.name},ids=Object.keys(pending);
        while(ids.length>32)delete pending[ids.shift()];
        return {...state,running:d.name,tool:d.name,calls:state.calls+1,pending};
      }
      if(event.type==='tool/result') {
        const msg=d?.message??{},cid=msg.toolCallId??msg.callId??d?.toolCallId??d?.callId;
        // DSH uses message.toolCallId. Missing/foreign/duplicate results cannot
        // settle a pending call by guessing a name. Compaction can replay old
        // results; each observed pending id is settled at most once.
        if(!validId(cid)||!Object.hasOwn(state.pending,cid))return state;
        const name=state.pending[cid];
        if(typeof msg.name==='string'&&msg.name&&msg.name!==name)return state;
        const pending={...state.pending};delete pending[cid];
        const summary=(Array.isArray(msg.content)?msg.content:[]).find(b=>b&&b.type==='text'&&typeof b.text==='string')?.text.slice(0,120)??null;
        return {...state,running:Object.values(pending).at(-1)??null,last:name,
          errors:state.errors+(msg.isError?1:0),lastSummary:summary,pending};
      }
      return state;
    },
    wire:{viewSchema:anySchema,view:state=>state},
  };
}
