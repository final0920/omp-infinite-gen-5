import { validateBVContract,validateBitvectorAST } from './bitvector_contract.js';
const fail=message=>{throw Object.assign(new Error(message),{code:'INVALID_BITVECTOR_WITNESS'});};
/** Independent BigInt interpreter; shares no implementation with the Python SMT encoder or future candidate providers. */
export function evaluateBitvector(ast,variables,assignment){
 validateBitvectorAST(ast,variables);const values=[];
 for(const n of ast.nodes){
  const a=n.args.map(i=>values[i]),width=BigInt(n.bits),mask=(1n<<width)-1n;
  const signed=(v,b)=>v>=(1n<<BigInt(b-1))?v-(1n<<BigInt(b)):v;
  let v;
  switch(n.op){
   case 'const':v=BigInt(n.value);break;
   case 'var':if(typeof assignment[n.name]!=='bigint')fail('Missing SSA assignment');v=assignment[n.name];break;
   case 'add':v=a[0]+a[1];break;case 'sub':v=a[0]-a[1];break;case 'mul':v=a[0]*a[1];break;
   case 'and':v=a[0]&a[1];break;case 'or':v=a[0]|a[1];break;case 'xor':v=a[0]^a[1];break;
   case 'not':v=~a[0];break;case 'neg':v=-a[0];break;
   case 'shl':v=a[1]>=width?0n:a[0]<<a[1];break;case 'lshr':v=a[1]>=width?0n:a[0]>>a[1];break;
   case 'ashr':v=a[1]>=width?(signed(a[0],n.bits)<0n?mask:0n):signed(a[0],n.bits)>>a[1];break;
   case 'eq':v=a[0]===a[1]?1n:0n;break;case 'ult':v=a[0]<a[1]?1n:0n;break;
   case 'slt':v=signed(a[0],ast.nodes[n.args[0]].bits)<signed(a[1],ast.nodes[n.args[1]].bits)?1n:0n;break;
   case 'zext':v=a[0];break;case 'sext':v=signed(a[0],ast.nodes[n.args[0]].bits);break;
   case 'extract':v=a[0]>>BigInt(n.offset);break;
   case 'concat':v=0n;for(let i=0;i<a.length;i++)v=(v<<BigInt(ast.nodes[n.args[i]].bits))|a[i];break;
   case 'ite':v=a[0]===1n?a[1]:a[2];break;
   default:fail('Unsupported interpreter operator');
  }
  values.push(v&mask);
 }
 return values[ast.root];
}
export function replayBitvectorAssessment({contract,candidate,assessment}){
 validateBVContract(contract);const checked=validateBitvectorAST(candidate,contract.variables);
 if(checked.bits!==contract.original.nodes[contract.original.root].bits||assessment.schema!=='ig5-bitvector-solver-v1'||assessment.originalDigest!==contract.originalDigest||assessment.candidateDigest!==checked.digest||assessment.premiseDigest!==contract.premiseDigest)fail('Assessment subject differs');
 const result={schema:'ig5-bitvector-replay-v1',status:'unknown',equivalentInIR:false,premiseSatisfiable:false,counterexampleValid:false,counterexample:null,
  nativeTargetExecuted:false,databaseModified:false,businessAccepted:false,wholeBinaryVerified:false};
 const queries=assessment.queries;if(!Array.isArray(queries)||queries.length>2)fail('At most two solver queries');
 if(queries.length&&queries[0].status!==assessment.premiseStatus)fail('Premise query status differs');
 if(assessment.premiseStatus!=='sat')return {...result,status:assessment.premiseStatus==='unsat'?'unsupported':'unknown',reason:assessment.premiseStatus==='unsat'?'infeasible-premise-no-vacuous-equivalence':'premise-not-established'};
 function decode(model){
  const names=contract.variables.map((v,i)=>'v'+i).concat('f07_dummy');
  if(!model||Object.keys(model).sort().join()!==names.sort().join())fail('Witness variables differ');
  const values={};
  for(const [i,v] of contract.variables.entries()){
   const text=model['v'+i];if(typeof text!=='string'||!/^0x[0-9a-f]{1,16}$/.test(text)||BigInt(text)>=1n<<BigInt(v.bits))fail('Witness width differs');values[v.name]=BigInt(text);
  }
  if(!['0x0','0x1'].includes(model.f07_dummy))fail('Dummy witness width differs');
  return values;
 }
 const premiseAssignment=decode(assessment.premiseWitness);
 if(evaluateBitvector(contract.premise,contract.variables,premiseAssignment)!==1n)fail('SAT premise witness failed independent replay');
 result.premiseSatisfiable=true;
 if(queries.length!==2||queries[1].status!==assessment.differenceStatus) return {...result,reason:'difference-query-unavailable'};
 if(assessment.differenceStatus==='unsat')return {...result,status:'pass',equivalentInIR:true,reason:'satisfiable-premise-and-unsat-ir-difference'};
 if(assessment.differenceStatus!=='sat')return {...result,reason:'difference-query-unknown-or-unverified'};
 const assignment=decode(assessment.counterexample),original=evaluateBitvector(contract.original,contract.variables,assignment),changed=evaluateBitvector(candidate,contract.variables,assignment);
 if(evaluateBitvector(contract.premise,contract.variables,assignment)!==1n||original===changed)fail('SAT counterexample failed independent replay');
 return {...result,status:'fail',counterexampleValid:true,reason:'independently-replayed-ir-counterexample',counterexample:{assignment:assessment.counterexample,original:'0x'+original.toString(16),candidate:'0x'+changed.toString(16)}};
}
