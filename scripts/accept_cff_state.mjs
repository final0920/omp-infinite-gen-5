import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';import {pathToFileURL} from 'node:url';
const option=k=>{const i=process.argv.indexOf(k);assert(i>=0&&process.argv[i+1],k+' required');return path.resolve(process.argv[i+1]);};
const pluginRoot=option('--plugin-root'),out=option('--evidence');assert(!out.toLowerCase().startsWith(pluginRoot.toLowerCase()+path.sep));fs.mkdirSync(out,{recursive:false});
const load=f=>import(pathToFileURL(path.join(pluginRoot,f)).href),{bitvectorHost}=await load('scripts/fixtures/bitvector_host.mjs'),{capturedStateReport}=await load('scripts/fixtures/cff_state_cases.mjs'),{captureCffStateSource,admitCffStateSource}=await load('source/cff_state_workflow.js');
const f=bitvectorHost(out,pluginRoot);f.session=f.mgr.get();f.session.target=f.context.target;f.mgr.sessions=new Map([[f.context.target,f.session]]);const rows=[];
try{
 for(const options of [{},{loop:true},{unknown:true},{sideEffectInDispatcher:true},{ordinarySwitch:true}]){
  const args={action:'deobfuscate',task_id:f.task.taskId},before=admitCffStateSource(f.mgr,f.cfg,f.session,args,f.execution),original=capturedStateReport(f,pluginRoot,options),saved=captureCffStateSource(f.mgr,f.cfg,f.session,args,original,f.execution,before);
  const task=f.notes.get(f.context,f.task.taskId),answer=await f.call({action:'cff-state',source_ref:saved.sourceRef});assert.deepEqual(task,f.notes.get(f.context,f.task.taskId));assert.equal(answer.cffProved,false);assert.equal(answer.summary.cleanupConfirmed,true);assert.equal(f.jobs.active,null);assert.equal(f.lifter.active.size,0);assert.equal((await f.call({action:'cff-read',report_ref:answer.reportRef})).validity,'current');
  if(!Object.keys(options).length)assert.equal(answer.summary.verifiedRoutes,3);if(options.sideEffectInDispatcher||options.ordinarySwitch)assert.equal(answer.summary.stateRoutes,0);
  fs.writeFileSync(path.join(out,'view-'+rows.length+'.html'),f.mgr.analysis.artifacts.read(answer.viewRef.ref,1024**2).data);rows.push({options,answer});
 }
 const task=f.notes.get(f.context,f.task.taskId),state=f.research.get(task,f.context);f.research.mutate(task,f.context,{operation:'set-contract',expected_task_revision:task.taskRevision,expected_research_revision:state.researchRevision,scope_digest:state.scopeDigest,value:{...f.declared,question:'changed contract'}},'owner');assert.equal((await f.call({action:'cff-read',report_ref:rows[0].answer.reportRef})).validity,'stale');
 const receipt={schema:'ig5-cff-state-acceptance-v1',rows,actualPurePythonOracle:true,actualSettledJSWorker:true,staleHistoryPreserved:true,source:'Owned synthetic SSA; no native Ghidra, protected target or model execution',native:false,assist:false};fs.writeFileSync(path.join(out,'acceptance.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify({cases:rows.length,actualPurePythonOracle:true,actualSettledJSWorker:true,native:false,assist:false}));
}finally{await f.dispose();}
