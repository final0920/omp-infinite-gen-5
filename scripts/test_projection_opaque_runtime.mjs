// Real readonly decoder/public-route regression. No database or target runs.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';import {spawn,spawnSync} from 'node:child_process';import {createHash} from 'node:crypto';import {pathToFileURL,fileURLToPath} from 'node:url';
const script=path.dirname(fileURLToPath(import.meta.url)),out=process.argv[2],root=process.argv[3]||path.dirname(script),graphfile=process.argv[4];
assert(out&&path.isAbsolute(out)&&path.isAbsolute(root));if(graphfile)assert(path.isAbsolute(graphfile));fs.mkdirSync(out,{recursive:false});
const hash=b=>createHash('sha256').update(b).digest('hex'),pin=f=>{const b=fs.readFileSync(f);return {path:f,bytes:b.length,sha256:hash(b)};};
const {buildPE64Fixture}=await import(pathToFileURL(path.join(root,'scripts/fixtures/pe64.mjs'))),{LiftJobs}=await import(pathToFileURL(path.join(root,'source/lift_jobs.js'))),{defineIntegrationTools}=await import(pathToFileURL(path.join(root,'integration_tools.js')));
const image=Buffer.from(buildPE64Fixture().image);image.fill(0x90,0x400,0x800);const put=(rva,hex)=>Buffer.from(hex,'hex').copy(image,0x400+rva-0x1000);
for(const[rva,hex]of[[0x1000,'9c58'],[0x1020,'0f31'],[0x1040,'9c488b01'],[0x1050,'9c488b442404'],[0x1060,'0f31500f31'],[0x1080,'669c'],[0x1090,'f30f31'],[0x10a0,'0fa2']])put(rva,hex);
const all='rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15'.split(' '),ea=rva=>'0x'+(0x140000000n+BigInt(rva)).toString(16);
for(let n=0;n<16;n++)put(0x1100+8*n,'66'+(n>=8?'41':'')+'0f'+(0xc8+n%8).toString(16));
const target=path.join(out,'opaque-fixture.exe');fs.writeFileSync(target,image);const base={target,level:'project',projection_registers:all};
const opaque=projection_path=>({...base,projection_path,projection_mode:'opaque-effects'});
const specs=[{id:'pushfq-pop',args:opaque([ea(0x1000),ea(0x1001)]),accepted:true},{id:'rdtsc',args:opaque([ea(0x1020)]),accepted:true},
 {id:'unknown-alias-read',args:opaque([ea(0x1040),ea(0x1041)]),accepted:true},{id:'partial-stack-read',args:opaque([ea(0x1050),ea(0x1051)]),accepted:true},
 {id:'two-timestamps-and-store',args:opaque([ea(0x1060),ea(0x1062),ea(0x1063)]),accepted:true},
 ...all.map((name,n)=>({id:'bswap16-'+name,args:opaque([ea(0x1100+8*n)]),accepted:true})),
 ...[['strict-push',0x1000],['strict-tsc',0x1020],['strict-bswap',0x1100]].map(([id,rva])=>({id,args:{...base,projection_path:[ea(rva)]},accepted:false})),
 ...[['prefixed-push',0x1080],['prefixed-rdtsc',0x1090],['cpuid-not-a-fallback',0x10a0]].map(([id,rva])=>({id,args:opaque([ea(rva)]),accepted:false}))];
if(graphfile){const g=JSON.parse(fs.readFileSync(graphfile));assert(g.rows.length>0&&g.rows.length<=128);assert.equal(pin(g.target.path).sha256,g.target.sha256);
 const real={target:g.target.path,level:'project',projection_path:g.rows.map(r=>r.ea),projection_registers:all};
 specs.push({id:'actual-ultra-full98-opaque',args:{...real,projection_mode:'opaque-effects'},accepted:true},{id:'actual-ultra-full98-strict',args:real,accepted:false});}
const files=['integration_tools.js','source/projection_jobs.js','source/projection_opaque.js','source/lift_jobs.js','source/worker_transport.js','worker/ig5_project.py','worker/projection_worker.py','worker/pcode_projection.py','worker/projection_opaque.py','worker/projection_flags.py','worker/projection_bsr.py','worker/projection_bsf.py','worker/projection_composition.py','worker/composition_memory.py','worker/projection_call.py','worker/lift_process.py','scripts/projection_raw_oracle.py','scripts/projection_numerical_oracle.py','scripts/test_projection_opaque_runtime.mjs','scripts/test_projection_opaque_runtime_verify.py','runtimes/manifest.json'].map(f=>({file:f,...pin(path.join(root,f))}));
const processes=[],cases=[],cfg={artifactDir:out,projectRoot:path.join(out,'projects'),host:{id:'win32-x64'},requestTimeoutMs:60000,ghidra:{available:true,pythonExe:path.join(root,'runtimes/ghidra/python/python.exe')}};
const jobs=new LiftJobs(cfg,{spawnProcess(exe,args,options){assert.equal(exe,cfg.ghidra.pythonExe);assert(args.includes(path.join(root,'worker/ig5_project.py')));assert.equal(options.windowsHide,true);
 const c=spawn(exe,args,options),r={pid:c.pid,args,stdin:'',stdout:'',stderr:'',exited:false,closed:false};processes.push(r);const w=c.stdin.write.bind(c.stdin);c.stdin.write=(s,...a)=>{r.stdin+=String(s);assert(r.stdin.length<=65536);return w(s,...a);};
 for(const s of ['stdout','stderr'])c[s].on('data',b=>{r[s]+=String(b);assert(r[s].length<=4*1024**2);});c.once('exit',code=>{r.exited=true;r.exitCode=code;});r.done=new Promise(resolve=>c.once('close',()=>{r.closed=true;resolve();}));return c;}});
const forbidden=()=>{throw Error('No database/target execution');},tool=defineIntegrationTools({lifter:jobs,get:forbidden,rpc:forbidden},cfg).find(t=>t.name==='ig5_ir');
const snapshot=()=>({sourcePins:files,pluginRoot:root,fixture:pin(target),actualGraph:graphfile?pin(graphfile):null,cases,processes:processes.map(({done,...r})=>r),activeRequests:jobs.active.size,nativeTargetExecuted:false,businessAccepted:false,wholeBinaryVerified:false});
const save=()=>fs.writeFileSync(path.join(out,'runtime-results.json'),JSON.stringify(snapshot(),null,2));
try{for(const spec of specs){let result,error;try{result=await tool.execute(spec.args);}catch(e){error=e;}
 assert.equal(processes.length,cases.length+1);const p=processes.at(-1);let timer;try{await Promise.race([p.done,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Owned root close not confirmed')),5000);})]);}finally{clearTimeout(timer);}
 assert(p.closed&&p.exited);const sent=JSON.parse(p.stdin.trim()),ack=p.stdout.trim().split(/\r?\n/).map(s=>JSON.parse(s)).find(x=>x.id===1);assert.equal(ack.nonce,sent.params.nonce);assert.equal(ack.cleanupConfirmed,true);assert.equal(jobs.active.size,0);
 const r={id:spec.id,args:spec.args,expectedAccepted:spec.accepted,rejected:!!error,rootPid:p.pid,rootExited:true,rootClosed:true,nonceMatched:true,cleanupConfirmed:true,...(error?{error:error.message}:{result})};cases.push(r);save();assert.equal(!error,spec.accepted,error?.message);
 if(error)assert(ack.error&&/Projection analysis failed:/.test(error.message));
 else{assert.equal(pin(result.reportPath).sha256,result.reportSha256);assert(result.process.jobAssignedAtCreation&&result.process.childExitConfirmed);assert.equal(result.process.activeProcessLimit,1);assert.equal(result.process.memoryLimitBytes,2*1024**3);
  for(const k of ['nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'])assert.equal(result[k],false);
  if(spec.id==='actual-ultra-full98-opaque'){assert.equal(result.opaqueEffectCount,4);assert.equal(result.storeCount,21);assert.equal(result.statistics.pcodeOperations,650);}}
 console.log(JSON.stringify({id:spec.id,observed:error?'refused':'accepted'}));}
 for(const r of files)assert.equal(pin(r.path).sha256,r.sha256);
 const v=spawnSync(cfg.ghidra.pythonExe,['-I','-B','-X','utf8',path.join(root,'scripts/test_projection_opaque_runtime_verify.py'),path.join(out,'runtime-results.json')],{windowsHide:true,encoding:'utf8',timeout:60000,maxBuffer:4*1024**2});
 fs.writeFileSync(path.join(out,'semantic-verifier.stdout.json'),v.stdout||'');fs.writeFileSync(path.join(out,'semantic-verifier.stderr.log'),v.stderr||'');assert.equal(v.status,0,v.stderr||v.stdout);
 fs.writeFileSync(path.join(out,'verified.json'),JSON.stringify({...snapshot(),verification:JSON.parse(v.stdout)},null,2));
}catch(error){save();fs.writeFileSync(path.join(out,'failure.json'),JSON.stringify({message:error.message,stack:error.stack},null,2));throw error;}
finally{await jobs.dispose();await jobs.artifacts.dispose();}
