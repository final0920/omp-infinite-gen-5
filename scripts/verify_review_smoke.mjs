import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';

const root = path.resolve(process.argv[2]);
const receipt = JSON.parse(fs.readFileSync(path.join(root,'acceptance.json'),'utf8'));
const events = JSON.parse(fs.readFileSync(path.join(root,'events.json'),'utf8'));
const rows = fs.readFileSync(path.join(root,'tools.jsonl'),'utf8').trim().split('\n').map(JSON.parse);
const results = rows.filter(r=>r.phase==='result');
const value = (tool,op) => {
  const row=results.find(r=>r.tool===tool&&(op===undefined||r.args.op===op));
  assert(row && row.result.isError===false, `${tool}/${op} failed`);
  return row.result.value;
};
assert.equal(receipt.cleanupConfirmed,true);
assert.equal(receipt.denied,0);
assert.equal(results.length,9);
const opened=value('ig5_open');
assert.equal(opened.analysisComplete,true);
assert.equal(opened.partial,false);
assert.equal(opened.bits,64);
assert.equal(createHash('sha256').update(fs.readFileSync(opened.target)).digest('hex'),opened.sha256);
assert(value('ig5_funcs').funcs.some(f=>f.ea==='0x140001000'));
assert.match(value('ig5_decompile').code,/return param_1 \+ param_2/);
assert.equal(value('ig5_dbg','load').targetExecuted,false);
const start=value('ig5_dbg','start'),regs=value('ig5_dbg','regs'),step=value('ig5_dbg','step'),stop=value('ig5_dbg','stop');
assert.equal(start.ok,true);assert.equal(start.state,'suspended');assert(start.runId);
assert.equal(regs.runId,start.runId);assert(regs.regs.rip);assert.equal(regs.ok,true);
assert.equal(step.runId,start.runId);assert.equal(step.state,'suspended');assert(step.stopSeq>start.stopSeq);
assert.equal(stop.ok,true);assert.equal(stop.state,'no-task');assert.equal(value('ig5_close').closed,true);
const approvals=events.filter(e=>e.type==='approval/decided');
assert.equal(approvals.length,5);assert(approvals.every(e=>e.data.outcome==='allowed-once'));
const debuggerPid=start.debuggerPid || start.context?.debuggerPid;
assert(Number.isSafeInteger(debuggerPid));
let absent=false;try{process.kill(debuggerPid,0);}catch(error){assert.equal(error.code,'ESRCH');absent=true;}
assert(absent,'Native debugger still has a local process');
const result={pass:true,assertionSource:'independent recorded tool returns and real session events',
  dispatches:results.length,targetSha256:opened.sha256,analysisComplete:true,functions:value('ig5_funcs').total,
  decompileSumVerified:true,debuggerPid,debuggerExitConfirmed:true,runId:start.runId,startStopSeq:start.stopSeq,
  stepStopSeq:step.stopSeq,finalState:stop.state,approvalAsked:events.filter(e=>e.type==='approval/asked').length,
  approvalAllowedOnce:approvals.length,cliExitConfirmed:receipt.cleanupConfirmed,
  modelFinalJsonValid:!receipt.error,modelFinalFormatIssue:receipt.error||null};
fs.writeFileSync(path.join(root,'independent-verification.json'),JSON.stringify(result,null,2)+'\n');
console.log(JSON.stringify(result));
