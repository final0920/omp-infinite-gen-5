/** Rebuildable view of this task's committed sidecar only; never an authenticity authority. */
export function evidenceDependencies(state, evidenceId) {
  const dependencies = [];
  for (const h of state.hypotheses) if ([...h.value.supporting, ...h.value.opposing].includes(evidenceId)) dependencies.push({ kind: 'hypothesis', id: h.id });
  for (const e of state.experiments) if (e.value.inputs.includes(evidenceId)) dependencies.push({ kind: 'experiment', id: e.id });
  for (const proof of state.verification?.checked || []) if (proof.evidenceId === evidenceId) dependencies.push({ kind: 'verification', id: proof.reportId, obligationId: proof.obligationId });
  const pending=[...dependencies.filter(d=>d.obligationId).map(d=>d.obligationId)],seen=new Set(pending);
  while(pending.length){const parent=pending.shift();for(const o of state.obligations)if(o.value.dependencies.includes(parent)&&!seen.has(o.id)){seen.add(o.id);pending.push(o.id);dependencies.push({kind:'obligation',id:o.id,dependency:parent});}}
  const completeWithinTask = !(state.verificationRefs?.length) || state.verification?.complete === true;
  return { schema: 'ig5-evidence-dependencies-v1', taskId: state.taskId, researchRevision: state.researchRevision,
    evidenceId, dependencies, completeWithinTask, globalStatus: 'partial',
    note: 'Only this committed research state was indexed. Empty results do not establish absence of dependencies in other tasks or reports.' };
}
