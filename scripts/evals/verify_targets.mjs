import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { apply } from '../../index.js';
import { root, loadCases } from './registry.mjs';
import { frozenTargets } from './freeze.mjs';
import { reference } from './oracle.mjs';

const output = path.resolve(process.argv[2] || path.join(root, '../../../_research/ig5-eval-verified-v2-20261021'));
fs.mkdirSync(output, { recursive: true });
const cases = loadCases(), freeze = frozenTargets(path.join(root, 'assets/targets.freeze.json'), cases);
const scratch = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-eval-native-'));
const tools = new Map(), events = new Map(), effects = [], checks = [], approvals = [];
const agent = { id: 'eval-target-validator' };
const ctx = { tools: { register(d) { tools.set(d.name,d); return () => tools.delete(d.name); } },
  on(n,h) { events.set(n,h); return () => events.delete(n); }, get(n) { return n === 'approval' ? { async request(r) { assert.equal(r.toolName,'ig5_emulate'); approvals.push(r.callId); return 'allowed-once'; } } : undefined; },
  inject() { return { dispose() {} }; }, effect(fn) { const d=fn(); if(typeof d==='function') effects.push(d); } };
let sequence=0, failed=null, cleaned=false;
const call = async (name,args) => {
  const execution={agent,callId:`eval-${++sequence}`};
  if(name==='ig5_emulate') {
    const decision=await events.get('tools/pre-execute')({name,arguments:args,...execution},async()=>({kind:'allow'}));
    assert.equal(decision.kind,'allow');
  }
  return tools.get(name).execute(args,execution);
};
try {
  apply(ctx,{defaultEngine:'reverse',reverseProvider:'bundled',toolset:'full',memory:false,artifactDir:path.join(scratch,'artifacts'),projectRoot:path.join(scratch,'projects')});
  for(const c of cases) {
    const spec=JSON.parse(fs.readFileSync(path.join(root,c.input.path),'utf8'));
    if(c.category==='data') { checks.push({caseId:c.caseId,status:'reference-ready',inputSha256:c.input.sha256,expected:reference(spec),targetExecuted:false}); continue; }
    const target=freeze.targets.find(t=>t.caseId===c.caseId), binary=path.join(scratch,`${c.caseId}.exe`);
    fs.copyFileSync(target.path,binary);
    const args={target:binary};
    const opened=await call('ig5_open',{path:binary,background:false}); assert.equal(opened.sha256,target.sha256);
    const dossier=await call('ig5_decompile',{...args,name:'eval_fn',style:'dossier'});
    const expected=reference(spec), observed=[];
    for(let i=0;i<spec.values.length;i++) {
      const result=await call('ig5_emulate',{...args,ea:dossier.function.ea,abi:'win64',args:[String(spec.values[i]),'0x60000000'],
        memory:[{ea:'0x60000000',hex:'00'}],capture:[{ea:'0x60000000',size:1}],max_instructions:1000,timeout_ms:1000});
      assert.equal(result.reason,'returned');
      const returned=Number(BigInt(result.return_value)&0xffffffffn);
      const written=parseInt(result.memory[0].hex.slice(0,2),16);
      const value=c.category==='static'?returned:{returned,written};
      assert.deepEqual(value,expected[i],`${c.caseId} input ${spec.values[i]}`); observed.push(value);
    }
    const check={caseId:c.caseId,status:'finite-domain-verified',targetSha256:target.sha256,inputSha256:c.input.sha256,
      functionEa:dossier.function.ea,domain:spec.values,observed,execution:'approved-Unicorn-only',debuggerExecuted:false,nativeTargetProcessStarted:false,
      scope:'listed-input-return-and-one-byte-write; not all-input proof or VM recovery',dossier};
    checks.push(check);
    // One real restored task becomes the frozen model-replay pilot.
    if(c.caseId==='static-01') {
      const task=(await call('ig5_workspace',{...args,workspace:{action:'create',goal:c.question,hypothesis:'分支边界尚待核对'}})).workspace;
      const captured=await call('ig5_decompile',{...args,name:'eval_fn',style:'dossier',task_id:task.taskId});
      const historical=(await call('ig5_workspace',{...args,workspace:{action:'evidence',id:task.taskId,snapshot_id:captured.investigation.snapshotId}})).workspace.report;
      await call('ig5_close',args); await call('ig5_open',{path:binary,background:false});
      const notes=(await call('ig5_workspace',{...args,workspace:{action:'get',id:task.taskId}})).workspace;
      const brief=(await call('ig5_workspace',{...args,workspace:{action:'brief',id:task.taskId}})).workspace;
      const current=await call('ig5_decompile',{...args,name:'eval_fn',style:'dossier'});
      fs.writeFileSync(path.join(output,'pilot-evidence.json'),JSON.stringify({schema:'ig5-eval-pilot-evidence-v1',caseId:c.caseId,
        inputSha256:c.input.sha256,targetSha256:target.sha256,contract:{values:spec.values,returnWidth:32,output:'JSON {returns:number[],functionEa:string,staleEvidence:boolean,unknowns:string[]}'},
        question:'恢复这次调查，核对过期证据，解释函数分支，并给出合同输入的返回值；说明证据与覆盖范围。',
        task:notes,brief,historical,current,catalog:(await call('ig5_profile',{capabilities:true})).capabilities},null,2));
    }
    await call('ig5_close',args);
  }
} catch(error) { failed={code:error.code||null,message:error.message,stack:error.stack}; }
finally {
  try { for(const dispose of effects.reverse()) await dispose();
    assert.equal(path.dirname(scratch),fs.realpathSync(os.tmpdir())); await fs.promises.rm(scratch,{recursive:true,force:true,maxRetries:20,retryDelay:100}); cleaned=true;
  } catch(error) { failed||={message:error.message}; }
  fs.writeFileSync(path.join(output,'target-verification.json'),JSON.stringify({schema:'ig5-eval-target-verification-v1',ok:!failed,
    checks,approvalCalls:approvals.length,cleaned,failure:failed,sourceOracleSha256:createHash('sha256').update(fs.readFileSync(path.join(root,'oracle.mjs'))).digest('hex')},null,2));
}
if(failed) throw new Error(JSON.stringify(failed));
console.log(JSON.stringify({ok:true,cases:checks.length,approvedEmulations:approvals.length,cleaned,output}));
