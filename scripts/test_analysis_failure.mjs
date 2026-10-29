import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {EventEmitter} from 'node:events';
import {AnalysisArtifacts,hashBytes} from '../source/analysis_artifacts.js';
import {importAnalysisFailure} from '../source/analysis_failure.js';
import {JAVA_PROJECTION_RUNTIME_PIN} from '../source/projection_decoder.js';
import {LiftJobs} from '../source/lift_jobs.js';

const names=['java-input.json','java-decode/started.json','java-decode/stdout.log','java-decode/stderr.log',
  'java-decode-process.json','request.json','state-computation-process.json','stdout.log','stderr.log'];
const base=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'ig5-failure-data-')));
function fixture(artifacts=new AnalysisArtifacts(path.join(base,randomUUID())),params={job_id:randomUUID(),sha256:'a'.repeat(64),projection_decoder:'java'},nonce=randomUUID(),cleanup=true){
  const directory=path.join(artifacts.root,'jobs',params.job_id);fs.mkdirSync(directory,{recursive:true});fs.mkdirSync(path.join(directory,'java-decode'));
  const error={code:'PROJECTION_FAILED',message:'Java projection decode failed: Instruction boundary exceeds available bytes'};
  const process={status:'completed',exitCode:1,pid:1234,childExitConfirmed:true,jobAssignedAtCreation:true,activeProcessLimit:1,memoryLimitBytes:2*1024**3};
  const input={'java-decode/stderr.log':Buffer.from('Exception in thread "main" short input\n\tat Java.main(Java.java:90)'),
    'java-decode-process.json':Buffer.from(JSON.stringify(process))};
  for(const [name,raw]of Object.entries(input))fs.writeFileSync(path.join(directory,name),raw);
  const result={schema:'ig5-analysis-failure-v1',status:'failed-unverified',method:'project',jobId:params.job_id,nonce,targetSha256:params.sha256,
    projectionDecoder:'java',runtimeManifestPin:'8fc4ae42f775f0139aa5f184c912db71f77e68d661c14564ab6f4820d434abea',javaDecoderManifestPin:JAVA_PROJECTION_RUNTIME_PIN,
    failedStage:'java-decode',cleanupConfirmed:cleanup,error,processStages:[{stage:'java-decode',budgetMs:49000,process}],
    nativeTargetExecuted:false,databaseModified:false,businessAccepted:false,wholeBinaryVerified:false,
    files:names.map(name=>({name,...(!cleanup?{status:'not-read-cleanup-unconfirmed'}:input[name]?{status:'captured',bytes:input[name].length,sha256:hashBytes(input[name])}:{status:'missing'})}))};
  const message={id:1,nonce,cleanupConfirmed:cleanup,error};
  const save=()=>{const raw=Buffer.from(JSON.stringify(result));fs.writeFileSync(path.join(directory,'analysis-failure.json'),raw);message.analysisFailure={name:'analysis-failure.json',bytes:raw.length,sha256:hashBytes(raw)};};save();
  return {artifacts,params,nonce,directory,result,message,save,read:()=>importAnalysisFailure(artifacts,params,'project',nonce,message)};
}
test('verified failure imports original stderr and preserves failed scope',async()=>{
  const f=fixture();try{const value=f.read();assert.equal(value.failedStage,'java-decode');assert.equal(value.wholeBinaryVerified,false);
    assert.equal(hashBytes(fs.readFileSync(value.reportPath)),value.reportSha256);
    const r=f.artifacts.get(value.id);assert.equal(r.status,'failed-unverified');assert.equal(r.result.processStages[0].process.exitCode,1);
    assert.equal(f.artifacts.read(r.result.blobs['java-decode/stderr.log'].ref).data.toString(),fs.readFileSync(path.join(f.directory,'java-decode/stderr.log'),'utf8'));
  }finally{await f.artifacts.dispose();}
});
test('tampered identity, digest, file selection, process or scope cannot commit a failure report',async()=>{
  for(const change of [f=>{f.message.analysisFailure.name='../other.json';},f=>{f.result.nonce=randomUUID();f.save();},
    f=>{f.result.targetSha256='b'.repeat(64);f.save();},f=>{f.result.businessAccepted=true;f.save();},
    f=>{f.result.files[0].name='../outside';f.save();},f=>{f.result.processStages[0].process.pid=4321;f.save();},
    f=>{fs.appendFileSync(path.join(f.directory,'java-decode/stderr.log'),'mutation');},f=>{f.message.analysisFailure.sha256='0'.repeat(64);},
    f=>{f.result.files.find(r=>r.status==='captured').bytes=4*1024**2+1;f.save();}]){
    const f=fixture();try{change(f);assert.throws(f.read);assert.equal(fs.readdirSync(path.join(f.artifacts.root,'records')).length,0);}
    finally{await f.artifacts.dispose();}
  }
});
test('unknown cleanup remains explicitly unverified with no imported live logs',async()=>{
  const f=fixture(undefined,undefined,undefined,false);try{const r=f.artifacts.get(f.read().id);assert.equal(r.result.cleanupConfirmed,false);assert.deepEqual(r.result.blobs,{});}
  finally{await f.artifacts.dispose();}
});
test('legacy error or unrelated lift has no fabricated evidence',()=>{
  assert.equal(importAnalysisFailure(null,null,'project',null,{error:{message:'old'}}),undefined);
  assert.equal(importAnalysisFailure(null,null,'lift',null,{analysisFailure:{}}),undefined);
});
test('discovery failure retains original nine-file policy and binds its expected dependency pin',async()=>{
  const f=fixture(undefined,{job_id:randomUUID(),sha256:'a'.repeat(64)});
  try{
    const p=f.result.processStages[0].process,raw=Buffer.from(JSON.stringify(p));fs.writeFileSync(path.join(f.directory,'state-computation-process.json'),raw);
    Object.assign(f.result,{method:'discover',projectionDecoder:'native',javaDecoderManifestPin:null,failedStage:'state-computation',discoveryExpectedManifestPin:'65bf673f1c4304cc2c09076e3b96e368da9e0df72aa0badeba0c2a5cae392934',processStages:[{stage:'state-computation',budgetMs:49000,process:p}]});
    f.result.error.code='DISCOVERY_FAILED';f.result.files=names.map(name=>name==='state-computation-process.json'?{name,status:'captured',bytes:raw.length,sha256:hashBytes(raw)}:{name,status:'missing'});f.save();
    const read=()=>importAnalysisFailure(f.artifacts,f.params,'discover',f.nonce,f.message);assert.equal(read().failedStage,'state-computation');
    f.result.discoveryExpectedManifestPin='b'.repeat(64);f.save();assert.throws(read);
  }finally{await f.artifacts.dispose();}
});
test('transport exposes verified report but capacity still requires actual protocol root exit',async()=>{
  let child,requestFrame;
  const jobs=new LiftJobs({artifactDir:path.join(base,randomUUID()),host:{id:'win32-x64'},requestTimeoutMs:2000,
    ghidra:{available:true,pythonExe:'mock-no-execution'}},{stopTimeoutMs:50,spawnProcess(){
    child=new EventEmitter();Object.assign(child,{pid:12345,stdout:new EventEmitter(),stderr:new EventEmitter(),stdin:new EventEmitter(),kill(){}});
    child.frame=m=>child.stdout.emit('data',Buffer.from(JSON.stringify(m)+'\n'));child.stdin.end=()=>{};
    child.stdin.write=raw=>{const m=JSON.parse(raw);if(m.id!==1)return;requestFrame=m;
      const f=fixture(jobs.artifacts,m.params,m.params.nonce);child.frame(f.message);};
    queueMicrotask(()=>child.frame({ig5:'ready'}));return child;
  }});
  try{let error;try{await jobs.request({job_id:randomUUID(),sha256:'a'.repeat(64),projection_decoder:'java'},undefined,'project');}catch(e){error=e;}
    assert(requestFrame);assert.equal(error.code,'PROJECTION_FAILED');assert(error.analysisFailure);assert.match(error.message,/report=.*SHA256=/);
    assert.equal(jobs.active.size,1);child.emit('exit',0);child.emit('close',0);await new Promise(r=>setImmediate(r));assert.equal(jobs.active.size,0);
  }finally{await jobs.dispose();await jobs.artifacts.dispose();}
});
