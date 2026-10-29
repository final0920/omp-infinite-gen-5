/** Bounded read-only projection. Receipts supplied here must already have their bytes and identities checked. */
export function evaluateObligations(state, checked, {complete=true}={}) {
  if(state.obligations.length>64 || checked.length>8) throw new Error('Obligation projection budget exceeded');
  const rows=new Map(state.obligations.map(o=>[o.id,o])), result=new Map(), visiting=new Set();
  function visit(id) {
    if(result.has(id)) return result.get(id);
    if(visiting.has(id)) throw Object.assign(new Error('Cyclic obligation dependency'),{code:'RESEARCH_DEPENDENCY_CYCLE'});
    const o=rows.get(id); if(!o) return {id,status:'blocked'};
    visiting.add(id);
    const base=state.objectStates.obligations.find(r=>r.id===id), proofs=checked.filter(p=>p.obligationId===id), valid=proofs.filter(p=>p.integrity==='verified');
    const deps=o.value.dependencies.map(visit), dependenciesSatisfied=deps.every(d=>d.status==='closed-in-scope');
    const pass=valid.find(p=>p.status==='pass'), counterexample=valid.find(p=>p.status==='fail' && p.counterexampleValid===true);
    let status=base.status;
    if(status!=='superseded') {
      if(base.staleContract) status='stale';
      else if(counterexample) status='contested';
      else if(!pass&&proofs.some(p=>p.integrity==='stale')) status='stale';
      else if(!dependenciesSatisfied) status=deps.some(d=>d.status==='stale'||d.status==='superseded')?'stale':'blocked';
      else if(pass) status=complete?'closed-in-scope':'open';
      else status='open';
    }
    const projected={...base,status,dependenciesSatisfied,...(!complete?{assessment:'unverified',reason:'receipt-read-budget-incomplete'}:{}),...(pass&&status==='closed-in-scope'?{verificationRef:{reportId:pass.reportId,sha256:pass.sha256},property:pass.property}:{}),
      ...(proofs.length?{verificationStatus:counterexample?'fail':pass?'pass':proofs.at(-1).status}:{})};
    visiting.delete(id);result.set(id,projected);return projected;
  }
  return state.obligations.map(o=>visit(o.id));
}
