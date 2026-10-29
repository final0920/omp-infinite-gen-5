import test from 'node:test';import assert from 'node:assert/strict';
import {validateBitvectorAST,validateBVContract,extractProjectionExpression,truePremise} from '../source/bitvector_contract.js';
import {evaluateBitvector,replayBitvectorAssessment} from '../source/bitvector_replay.js';
import {AnalysisJobs} from '../source/analysis_jobs.js';
import {validateCandidateInput} from '../source/candidate_workflow.js';
import {variable,constant,identity,addZero,declaration,assessment,projectionCase} from './fixtures/bitvector_cases.mjs';
const variables=declaration().variables;
test('bounded source and candidate contract rejects foreign SSA, implicit widths, script fields and unsupported dependencies',()=>{
 for(const ast of [{...identity(),verified:true},{nodes:[{...variable(),name:'foreign'}],root:0},{nodes:[{...variable(),bits:16}],root:0},{nodes:[{id:0,op:'eval',bits:8,args:[]}],root:0},{nodes:[{id:0,op:'LOAD',bits:8,args:[]}],root:0}])assert.throws(()=>validateBitvectorAST(ast,variables));
 for(const field of ['execute','path','verifier','timeoutMs'])assert.throws(()=>validateCandidateInput({action:'candidate-prepare',source_ref:{id:'12345678-1234-1234-1234-123456789abc',sha256:'a'.repeat(64)},root_node:0,[field]:true}));
 assert.throws(()=>validateBitvectorAST({nodes:[variable(),{id:1,op:'const',bits:16,args:[],value:'0x0'},{id:2,op:'add',bits:16,args:[0,1]}],root:2},variables));
});
test('rejects overflow literals, negative zero, cycles, depth/size excess and hidden dead nodes',()=>{
 for(const value of ['0x100','-1','0Xff','0x00','process.exit()'])assert.throws(()=>validateBitvectorAST(constant(8,value),variables));
 assert.throws(()=>validateBitvectorAST({nodes:[{...variable(),id:-0}],root:0},variables));assert.throws(()=>validateBitvectorAST({nodes:[{...variable(),args:[0]}],root:0},variables));
 const nodes=[variable()];for(let i=1;i<33;i++)nodes.push({id:i,op:'not',bits:8,args:[i-1]});assert.throws(()=>validateBitvectorAST({nodes,root:32},variables));
 assert.throws(()=>validateBitvectorAST({nodes:[variable(),{id:1,op:'const',bits:8,args:[],value:'0x0'}],root:0},variables));
});
test('SSA roots preserve input identity and refuse memory, unknown/flags inputs and CALL/PHI cuts',()=>{
 const p=projectionCase('a'.repeat(64));assert.equal(extractProjectionExpression(p,3).variables[0].name,'ssa_0');
 for(const op of ['LOAD','CALL','PHI','unmodeled','load_le']){const c=structuredClone(p);c.dag.nodes[3].op=op;assert.throws(()=>extractProjectionExpression(c,3));}
 for(const name of ['rax_injected','unknown_flags','rax;eval']){const c=structuredClone(p);c.dag.nodes[0].name=name;c.initialRegisters[name]=0;assert.throws(()=>extractProjectionExpression(c,3));}
});
test('full-width arithmetic, signed extension, explicit truncation and full shift operands have independent semantics',()=>{
 const x=declaration(addZero(64)).variables;assert.equal(evaluateBitvector(addZero(64),x,{ssa_0:0xffffffffffffffffn}),0xffffffffffffffffn);
 const shifted={nodes:[variable(),{id:1,op:'const',bits:8,args:[],value:'0x8'},{id:2,op:'shl',bits:8,args:[0,1]}],root:2};assert.equal(evaluateBitvector(shifted,variables,{ssa_0:255n}),0n);
 const signed={nodes:[variable(),{id:1,op:'sext',bits:16,args:[0]}],root:1};assert.equal(evaluateBitvector(signed,variables,{ssa_0:128n}),0xff80n);
 const truncate={nodes:[variable(),{id:1,op:'extract',bits:4,args:[0],offset:4}],root:1};assert.equal(evaluateBitvector(truncate,variables,{ssa_0:0xabn}),10n);
});
test('SAT premise and UNSAT difference yields only scoped IR pass; no native/whole-function promotion',()=>{
 const c=declaration(),candidate=identity(),r=replayBitvectorAssessment({contract:c,candidate,assessment:assessment(c,candidate)});
 assert.equal(r.status,'pass');assert.equal(r.equivalentInIR,true);assert.equal(r.businessAccepted,false);assert.equal(r.nativeTargetExecuted,false);
});
test('SAT wrong candidate needs a valid independently replayed counterexample',()=>{
 const c=declaration(),candidate=constant(),a=assessment(c,candidate,{differenceStatus:'sat'}),r=replayBitvectorAssessment({contract:c,candidate,assessment:a});assert.equal(r.status,'fail');assert.equal(r.counterexampleValid,true);
 a.counterexample.v0='0x0';assert.throws(()=>replayBitvectorAssessment({contract:c,candidate,assessment:a}));
});
test('unsatisfiable/unknown premises and solver unknown never pass, including forged candidate verified metadata',()=>{
 const c=declaration(),candidate=identity();for(const status of ['unsat','unknown','unverified']){const r=replayBitvectorAssessment({contract:c,candidate,assessment:assessment(c,candidate,{premiseStatus:status})});assert.notEqual(r.status,'pass');}
 assert.equal(replayBitvectorAssessment({contract:c,candidate,assessment:assessment(c,candidate,{differenceStatus:'unknown'})}).status,'unknown');
 assert.throws(()=>replayBitvectorAssessment({contract:c,candidate:{...candidate,verified:true},assessment:assessment(c,candidate)}));
});
test('unsat premise is rejected even when an unrelated difference claim says UNSAT; false SAT premise witness refused',()=>{
 const c=declaration(addZero(),constant(1,'0x0')),candidate=identity();assert.throws(()=>replayBitvectorAssessment({contract:c,candidate,assessment:assessment(c,candidate)}));
 const a=assessment(c,candidate,{premiseStatus:'unsat'});assert.equal(replayBitvectorAssessment({contract:c,candidate,assessment:a}).status,'unsupported');
});
test('witness type/width/name, candidate digest and premise digest are bound exactly',()=>{
 const c=declaration(),candidate=identity(),a=assessment(c,candidate);
 for(const patch of [{candidateDigest:'a'.repeat(64)},{premiseDigest:'b'.repeat(64)},{premiseWitness:{v0:'0x100',f07_dummy:'0x0'}},{premiseWitness:{v0:'0x1',f07_dummy:'0x2'}},{premiseWitness:{v0:'0x1',f07_dummy:'0x0',extra:'0x0'}}])assert.throws(()=>replayBitvectorAssessment({contract:c,candidate,assessment:{...a,...patch}}));
});
test('8-bit full finite-domain oracle checks wraparound rather than samples',()=>{
 for(let n=0;n<256;n++){assert.equal(evaluateBitvector(addZero(),variables,{ssa_0:BigInt(n)}),BigInt(n));}
 const sum={nodes:[variable(),{id:1,op:'const',bits:8,args:[],value:'0x1'},{id:2,op:'add',bits:8,args:[0,1]}],root:2};
 for(let n=0;n<256;n++)assert.equal(evaluateBitvector(sum,variables,{ssa_0:BigInt(n)}),BigInt((n+1)%256));
});
test('settled independent data replay uses original worker pool and cancellation does not publish a pass',async()=>{
 const jobs=new AnalysisJobs(),c=declaration(),candidate=identity();try{
  const r=await jobs.runSettled('bv-candidate-replay',{contract:c,candidate,assessment:assessment(c,candidate)});assert.equal(r.status,'pass');assert.equal(jobs.active,null);
  const controller=new AbortController();controller.abort();await assert.rejects(jobs.runSettled('bv-candidate-replay',{},controller.signal));assert.equal(jobs.active,null);
 }finally{await jobs.dispose();}
});
