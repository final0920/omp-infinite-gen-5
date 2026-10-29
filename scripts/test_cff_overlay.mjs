import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import os from 'node:os';import path from 'node:path';
import {buildCffOverlay,bindCffCondition} from '../source/cff_overlay.js';
import {renderCffComparison,validateCffInput} from '../source/cff_workflow.js';
import {bitvectorHost} from './fixtures/bitvector_host.mjs';
import {CFG_CASES,graph,dossier,captureCff} from './fixtures/cff_cases.mjs';
const source={id:'11111111-1111-4111-8111-111111111111',sha256:'a'.repeat(64)};
for(const c of CFG_CASES)test(c.id+' retains alternatives, effects, original graph and unknown semantics',()=>{
 const d=dossier({},c.graph),before=structuredClone(d),r=buildCffOverlay(d,source);
 assert.deepEqual(d,before);assert.deepEqual(r.originalGraph,c.graph);assert.equal(r.providerGraphComplete,true);assert.equal(r.cffProved,false);assert.equal(r.wholeFunctionRecovered,false);
 assert.equal(r.dispatcherCandidates[0].topologyCompatibleWithDispatcher,c.compatible);assert(r.dispatcherCandidates.every(c=>c.classification==='unknown'&&c.alternatives.includes('ordinary-switch')));
 assert.equal(r.retainedEffects.stateWritesRemoved,0);assert.equal(r.stateDependencies.selectedVariable,null);assert.equal(r.overlay.originalEdges.length,c.graph.edges.length);
 for(const e of r.overlay.localRelations){assert.equal(e.scope,'reported-CFG-topology-only');assert.equal(e.status,'verified-in-scope');for(let i=1;i<e.path.length;i++)assert(c.graph.edges.some(x=>x.from===e.path[i-1]&&x.to===e.path[i]));assert.equal(e.conditionFeasibility,'unknown');}
 assert(r.overlay.unknownExits.some(x=>x.kind==='provider-unmodelled-control-and-exceptions'));
});
test('partial, unattested provider and inconsistent counts never claim complete topology',()=>{
 for(const mutate of [d=>d.responseTruncated=true,d=>d.sections.cfg.status='truncated',d=>d.sections.cfg.completeness.provider='unknown',d=>d.sections.cfg.data.total_blocks++,d=>delete d.sections.cfg.data.blocks[0].succs]){
  const d=dossier({},CFG_CASES[0].graph);mutate(d);const r=buildCffOverlay(d,source);assert.equal(r.providerGraphComplete,false);assert(r.overlay.localRelations.every(e=>e.status==='candidate'));assert(r.overlay.unknownExits.some(x=>x.kind==='partial-or-unattested-cfg'));
 }
});
test('missing endpoint and contradictory adjacency retained as unknown',()=>{
 const g=graph([[0,1],[0,9]], [0,1]);g.blocks[0].succs=[1];const r=buildCffOverlay(dossier({},g),source);
 assert.equal(r.providerGraphComplete,false);assert.equal(r.overlay.originalEdges[1].status,'unknown');assert(r.overlay.unknownExits.some(x=>x.kind==='adjacency-disagreement'));
});
test('duplicate blocks/edges, overlap, malformed addresses and over-limit graphs reject',()=>{
 for(const mutate of [g=>g.blocks.push(g.blocks[0]),g=>g.edges.push(g.edges[0]),g=>g.blocks[1].start=g.blocks[0].start,g=>g.blocks[0].end='0x0',g=>g.blocks.push(...Array(129).fill(g.blocks[0]))]){
  const g=structuredClone(CFG_CASES[0].graph);mutate(g);assert.throws(()=>buildCffOverlay(dossier({},g),source),{code:'UNSUPPORTED_CFF_CFG'});
 }
});
test('scriptless comparison escapes provider data and keeps both original and overlay',()=>{
 const r=buildCffOverlay(dossier({},CFG_CASES[0].graph),source);r.dispatcherCandidates[0].annotation='<script>alert(1)</script>';
 const html=renderCffComparison(r);assert(!html.includes('<script>'));assert(html.includes('&lt;script&gt;'));assert(html.includes('default-src'));assert.equal((html.match(/<svg /g)||[]).length,2);assert(html.includes('全函数恢复：false'));
});
test('unknown external fields, executable parameters and malformed refs rejected before target lookup',()=>{
 for(const extra of [{scope:{}},{graph:{}},{state_variable:'rax'},{execute:true},{budget:1000},{verification_ref:{id:'x',sha256:'x'}}])assert.throws(()=>validateCffInput({action:'cff-overlay',id:'task',snapshot_id:'s',...extra}));
});
function fixture(t){const root=fs.mkdtempSync(path.join(os.tmpdir(),'ig5-cff-')),f=bitvectorHost(root,path.resolve(import.meta.dirname,'..'));t.after(async()=>{await f.dispose();assert.equal(path.dirname(root),fs.realpathSync(os.tmpdir()));fs.rmSync(root,{recursive:true,force:true});});return f;}
test('host overlay/report/view integrity, unchanged task and no native/solver dispatch',async t=>{
 const f=fixture(t),{captured}=captureCff(f);f.lifter.request=()=>{throw Error('No native request allowed');};
 const before=f.notes.get(f.context,f.task.taskId),r=await f.call({action:'cff-overlay',snapshot_id:captured.snapshotId});
 assert.equal(r.summary.verifiedConditions,0);assert.equal(r.assistEnabled,false);assert.deepEqual(f.notes.get(f.context,f.task.taskId),before);
 assert.equal((await f.call({action:'cff-read',report_ref:r.reportRef})).validity,'current');
 assert((await f.mgr.analysis.artifacts.list({target:f.context.target,engine:'ghidra'})).items.some(row=>row.id===r.reportRef.id));
 const savedAssociation=f.mgr.analysis.artifacts.get(r.reportRef.id).association;assert.equal(savedAssociation.target,f.context.target);assert.equal(savedAssociation.engine,'ghidra');
 assert(!(await f.mgr.analysis.artifacts.list({target:f.context.target+'.other'})).items.some(row=>row.id===r.reportRef.id));
 const bytes=f.mgr.analysis.artifacts.read(r.viewRef.ref,1024*1024).data;assert(bytes.toString().includes('原始 CFG'));
 f.context.dbRevision++;await assert.rejects(f.call({action:'cff-overlay',snapshot_id:captured.snapshotId}));
});
test('unlinked dossier, arbitrary proof and cancelled operations cannot create overlay',async t=>{
 const f=fixture(t),{captured}=captureCff(f);
 await assert.rejects(f.call({action:'cff-overlay',snapshot_id:'not-linked'}),{code:'CFF_SOURCE_REQUIRED'});
 await assert.rejects(f.call({action:'cff-overlay',snapshot_id:captured.snapshotId,verification_ref:source}));
 const a=new AbortController();a.abort();f.execution.signal=a.signal;await assert.rejects(f.call({action:'cff-overlay',snapshot_id:captured.snapshotId}),{code:'ABORT_ERR'});
});
test('changed original dossier bytes fail closed on generation and invalidate history',async t=>{
 const f=fixture(t),{captured}=captureCff(f),r=await f.call({action:'cff-overlay',snapshot_id:captured.snapshotId});
 const file=path.join(f.mgr.analysis.artifacts.directory('records'),captured.reportId+'.json');fs.appendFileSync(file,' ');
 await assert.rejects(f.call({action:'cff-overlay',snapshot_id:captured.snapshotId}),{code:'ARTIFACT_CHANGED'});
 assert.equal((await f.call({action:'cff-read',report_ref:r.reportRef})).validity,'stale');
});
test('committed report from another task cannot be read in the current task',async t=>{
 const f=fixture(t),{captured}=captureCff(f),r=await f.call({action:'cff-overlay',snapshot_id:captured.snapshotId}),old=f.mgr.analysis.artifacts.get(r.reportRef.id);
 const forged=f.mgr.analysis.artifacts.save({...old,id:undefined,association:{...old.association,taskId:'other-task'}},{maxBytes:1024*1024});
 await assert.rejects(f.call({action:'cff-read',report_ref:{id:forged.id,sha256:f.mgr.analysis.artifacts.metadata(forged.id).result.recordSha256}}),{code:'RESEARCH_SCOPE_MISMATCH'});
});
test('contract ABA retains history as stale instead of current proof',async t=>{
 const f=fixture(t),{captured}=captureCff(f),r=await f.call({action:'cff-overlay',snapshot_id:captured.snapshotId});
 for(const value of [{...f.declared,question:'temporary'},f.declared]){
  const task=f.notes.get(f.context,f.task.taskId),state=f.research.get(task,f.context);
  f.research.mutate(task,f.context,{operation:'set-contract',expected_task_revision:task.taskRevision,expected_research_revision:state.researchRevision,scope_digest:state.scopeDigest,value},'owner');
 }
 const history=await f.call({action:'cff-read',report_ref:r.reportRef});assert.equal(history.validity,'stale');assert.equal(history.reason,'STALE_CFF_OVERLAY');
});
test('local predicate rejects declared assumptions, non-pass, wrong root, wrong block and missing CFG edge',()=>{
 const make=()=>({overlay:buildCffOverlay(dossier({},CFG_CASES[0].graph),source),projection:{projectionPath:['0x1000'],control:{kind:'conditional',source:'0x1000',conditionRule:'nonzero-is-taken',condition:1,taken:2,fallthrough:3},dag:{nodes:[{},{},{op:'const',value:'0x1010'},{op:'const',value:'0x1020'}]}},contract:{premiseOrigin:'unconditional-true',sourceRoot:1,sourceRef:source,variables:[{name:'ssa_0',sourceName:'rax'}]},verification:{status:'pass',replay:{equivalentInIR:true},candidate:{nodes:[{id:0,op:'const',value:'0x0'}],root:0}}});
 const good=make(),r=bindCffCondition(good.overlay,good.projection,good.contract,good.verification,source);assert.equal(r.to,2);assert.equal(r.scope,'selected-pure-BV-terminal-condition-only');assert.equal(good.overlay.overlay.originalEdges.length,5);
 for(const mutate of [f=>f.contract.premiseOrigin='caller-declared-structured-assumption',f=>f.verification.status='unknown',f=>f.projection.control.condition=0,f=>f.projection.projectionPath=['0x1001'],f=>f.projection.dag.nodes[3].value='0x1030']){const f=make();mutate(f);assert.throws(()=>bindCffCondition(f.overlay,f.projection,f.contract,f.verification,source),{code:'UNSUPPORTED_CFF_CFG'});}
});
