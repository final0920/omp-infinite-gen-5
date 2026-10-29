// Evaluation preparation side. Never imported by a recovery runner.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { ownedBranchVmFixture, bytecodeContract } from '../../fixtures/vm_bytecode_cases.mjs';
const digest=b=>createHash('sha256').update(b).digest('hex');
const save=(file,value)=>{const bytes=Buffer.isBuffer(value)?value:Buffer.from(JSON.stringify(value,null,2)+'\n');fs.writeFileSync(file,bytes,{flag:'wx'});return {sha256:digest(bytes),bytes:bytes.length};};
export function prepareSemanticSkeleton(root,seed) {
  if(!Number.isSafeInteger(seed)||seed<0||seed>0xffffffff)throw Error('Unsigned 32-bit frozen seed required');
  root=path.resolve(root);if(fs.existsSync(root))throw Error('Choose a fresh suite directory');
  fs.mkdirSync(root);const publicRoot=path.join(root,'public'),privateRoot=path.join(root,'private');fs.mkdirSync(publicRoot);fs.mkdirSync(privateRoot);
  const key=digest(Buffer.from('semantic-skeleton-v1:'+seed)),add=parseInt(key.slice(0,2),16),xor=parseInt(key.slice(2,4),16);
  const {image}=ownedBranchVmFixture();image.fill(0,0xf00,0x1000);Buffer.from([7,add,8,xor,3,4,0]).copy(image,0xf00);
  const targetSha256=digest(image),contract=bytecodeContract(targetSha256,true);
  const files={target:save(path.join(publicRoot,'target.exe'),image),contract:save(path.join(publicRoot,'contract.json'),contract)};
  const mask=(1n<<64n)-1n,oracle=Array.from({length:256},(_,i)=>{const value=((BigInt(i)+BigInt(add))&mask)^BigInt(xor);return {input:'0x'+i.toString(16),returnValue:'0x'+value.toString(16),outputHex:Buffer.from(Array.from({length:8},(_,n)=>Number((value>>BigInt(8*n))&255n))).toString('hex')};});
  const privateFiles={oracle:save(path.join(privateRoot,'oracle.json'),oracle),
    recipe:save(path.join(privateRoot,'generation.json'),{schema:'ig5-semantic-generation-v1',seed,add,xor,bytecode:[7,add,8,xor,3,4,0],generatorSha256:digest(fs.readFileSync(fileURLToPath(import.meta.url))),targetSha256}),
    canary:save(path.join(privateRoot,'canary.txt'),Buffer.from(key))};
  const freeze={schema:'ig5-semantic-suite-freeze-v1',tier:'U1',purpose:'isolation-skeleton-only',files,privateFiles,
    budget:{toolCalls:20,timeoutMs:60000,bytes:8*1024**2,maxInstructions:50000},
    scoring:{requiresActualIsolation:true,hiddenUsedForTuning:false,referenceModelsNotDiscoveryCredit:true},
    isolationStatus:'exposed',isolatedCreditAllowed:false};
  save(path.join(privateRoot,'freeze.json'),freeze);
  return {root,publicRoot,privateRoot,freeze};
}
export function probeSemanticSkeleton(suite) {
  const probe=fileURLToPath(new URL('./isolation_probe.mjs',import.meta.url));
  const args=['--permission','--allow-fs-read='+probe,'--allow-fs-read='+suite.publicRoot,probe,path.join(suite.publicRoot,'target.exe'),path.join(suite.privateRoot,'canary.txt'),fileURLToPath(import.meta.url)];
  const run=spawnSync(process.execPath,args,{encoding:'utf8',timeout:15000,maxBuffer:64*1024,windowsHide:true});
  if(run.status!==0)throw Error('Isolation probe failed: '+String(run.stderr).slice(0,512));
  const result=JSON.parse(run.stdout);
  return {schema:'ig5-semantic-isolation-probe-v1',...result,isolationStatus:'exposed',isolatedCreditAllowed:false,
    blockers:['Recovery agent host tools are not restricted by this subprocess probe','Network isolation has not been established','Generator/recovery role independence has not been established'],
    scope:'Node subprocess filesystem permission probe only; cannot certify an isolated model investigation'};
}
