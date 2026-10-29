// Real fixed Java decoder and owned static analysis only; no PE execution.
import assert from 'node:assert/strict';import fs from 'node:fs';import path from 'node:path';
import {spawn,spawnSync} from 'node:child_process';import {createHash} from 'node:crypto';import {pathToFileURL} from 'node:url';
const root=process.argv[3]||path.resolve(import.meta.dirname,'..'),out=process.argv[2];
assert(out&&path.isAbsolute(out)&&path.isAbsolute(root));fs.mkdirSync(out,{recursive:false});assert.equal(fs.realpathSync(out),path.resolve(out));
const hash=b=>createHash('sha256').update(b).digest('hex'),pin=p=>{const b=fs.readFileSync(p);return{path:p,bytes:b.length,sha256:hash(b)}};
const load=f=>import(pathToFileURL(path.join(root,f))),{buildPE64Fixture}=await load('scripts/fixtures/pe64.mjs'),{defineIntegrationTools}=await load('integration_tools.js'),{LiftJobs}=await load('source/lift_jobs.js');
const image=Buffer.from(buildPE64Fixture().image);image.fill(0x90,0x400,0x800);const gprs='rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15'.split(' '),matrix=[];
let cursor=0x1000;const addresses=[];const put=hex=>{const bytes=Buffer.from(hex,'hex');assert(cursor+bytes.length<=0x1400);const ea='0x'+(0x140000000n+BigInt(cursor)).toString(16);bytes.copy(image,0x400+cursor-0x1000);cursor+=bytes.length;return ea;};
for(const bits of [16,32,64])for(let cc=0;cc<16;cc++){
 const dst=cc,src=cc%2?dst:15-cc,rex=0x40|(bits===64?8:0)|(dst>=8?4:0)|(src>=8?1:0);
 const bytes=Buffer.from([...(bits===16?[0x66]:[]),...(rex!==0x40?[rex]:[]),0x0f,0x40+cc,0xc0|((dst&7)<<3)|(src&7)]).toString('hex');
 const ea=put(bytes);addresses.push(ea);matrix.push({ea,bytes,bits,cc,source:gprs[src],destination:gprs[dst]});
 addresses.push(put(Buffer.from([dst>=8?0x49:0x48,0xb8+(dst&7),0,0,0,0,0,0,0,0]).toString('hex')));
}
const specs=[{id:'all-48-register-condition-width-shapes',path:addresses,registers:gprs,accepted:true}];
function spec(id,code,{accepted=false,mode='strict',registers=gprs,error}={}){specs.push({id,path:code.map(put),registers,mode,accepted,error});}
spec('live-r16-refused',['66440f46d2'],{error:'Live CMOV'});
spec('live-r32-refused',['440f46d2'],{error:'Live CMOV'});
spec('live-r64-refused',['4c0f46d2'],{error:'Live CMOV'});
spec('memory-source-refused',['66440f4612'],{registers:['rax'],error:'register-source CMOV'});
spec('initial-flags-still-refused',['66440f46d2','0f92c0'],{registers:['rax'],error:'undefined initial architectural flags'});
spec('defined-carry-preserved',['f8','66440f46d2','0f92c0'],{registers:['rax'],accepted:true});
spec('side-exit-live-register-refused',['66440f46d2','e302','49ba0000000000000000'],{mode:'guarded-path',error:'Live CMOV'});
spec('redundant-width-refused',['664c0f46d2'],{registers:['rax'],error:'Redundant CMOV'});
const target=path.join(out,'cmov-fixture-data.exe');fs.writeFileSync(target,image,{flag:'wx'});
const python=path.join(root,'runtimes/ghidra/python/python.exe'),cfg={artifactDir:out,projectRoot:out,requestTimeoutMs:60000,host:{id:'win32-x64'},ghidra:{available:true,pythonExe:python}},roots=[],cases=[];
const jobs=new LiftJobs(cfg,{spawnProcess(executable,args,options){assert.equal(executable,python);assert.equal(options.windowsHide,true);assert.equal(options.shell,undefined);const child=spawn(executable,args,options),r={pid:child.pid,stdin:'',stdout:'',stderr:'',exited:false,closed:false};roots.push(r);const write=child.stdin.write.bind(child.stdin);child.stdin.write=(s,...a)=>{r.stdin+=String(s);assert(r.stdin.length<=131072);return write(s,...a);};for(const stream of ['stdout','stderr'])child[stream].on('data',b=>{r[stream]+=String(b);assert(r[stream].length<=2*1024**2)});child.once('exit',code=>{r.exited=true;r.exitCode=code});r.done=new Promise(resolve=>child.once('close',()=>{r.closed=true;resolve()}));return child;}});
const forbidden=()=>{throw Error('Static test must not execute a PE or open a database')},tool=defineIntegrationTools({lifter:jobs,current:forbidden,get:forbidden,rpc:forbidden},cfg).find(t=>t.name==='ig5_ir');
const snapshot=()=>({schema:'ig5-cmov-static-java-runtime-v1',pluginRoot:root,target:pin(target),matrix,cases,roots:roots.map(({done,...r})=>r),activeRequests:jobs.active.size,nativeTargetExecuted:false,businessAccepted:false});
try{for(const s of specs){const args={target,level:'project',projection_decoder:'java',projection_path:s.path,projection_registers:s.registers,...(s.mode&&s.mode!=='strict'?{projection_mode:s.mode}:{})};let result,error;try{result=await tool.execute(args)}catch(e){error=e}const r=roots.at(-1);assert.equal(roots.length,cases.length+1);let timer;try{await Promise.race([r.done,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Owned protocol root close unconfirmed')),5000)})]);}finally{clearTimeout(timer)}assert(r.exited&&r.closed);const request=r.stdin.trim().split(/\r?\n/).map(JSON.parse).find(x=>x.id===1),reply=r.stdout.trim().split(/\r?\n/).map(JSON.parse).find(x=>x.id===1);assert(request&&reply);assert.equal(reply.nonce,request.params.nonce);assert.equal(reply.cleanupConfirmed,true);assert.equal(jobs.active.size,0);
 cases.push({id:s.id,args,accepted:!error,...(error?{error:error.message,analysisFailure:error.analysisFailure}:{result}),rootExited:true,rootClosed:true,cleanupConfirmed:true});fs.writeFileSync(path.join(out,'runtime-results.json'),JSON.stringify(snapshot(),null,2));
 if(s.accepted){assert(!error,error?.message);assert.equal(result.projectionDecoder,'java');assert.equal(result.processStages.length,2);const b=fs.readFileSync(result.reportPath);assert.equal(hash(b),result.reportSha256);const core=JSON.parse(b).result;assert.equal(core.businessAccepted,false);assert.equal(core.nativeTargetExecuted,false);assert.equal(core.stores.length,0);assert.equal(core.internalElisions.length,s.id.startsWith('all-48')?48:1);}else{assert(error);assert(error.message.includes(s.error),error.message);assert(error.analysisFailure);assert.equal(error.analysisFailure.status,'failed-unverified');}
 console.log(JSON.stringify({id:s.id,accepted:!error}));}
 const audit=spawnSync(python,['-I','-B','-X','utf8',path.join(root,'scripts/test_projection_cmov_runtime_verify.py'),path.join(out,'runtime-results.json')],{windowsHide:true,encoding:'utf8',maxBuffer:1024**2,timeout:60000});fs.writeFileSync(path.join(out,'independent.log'),audit.stdout+audit.stderr,{flag:'wx'});assert.equal(audit.status,0,audit.stdout+audit.stderr);assert.equal(hash(fs.readFileSync(target)),hash(image));
 fs.writeFileSync(path.join(out,'verified.json'),JSON.stringify({...snapshot(),passed:true},null,2),{flag:'wx'});console.log(JSON.stringify({passed:true,cases:cases.length,actualJavaCmovShapes:48,nativeTargetExecuted:false}));
}finally{await jobs.dispose();await jobs.artifacts.dispose();}
