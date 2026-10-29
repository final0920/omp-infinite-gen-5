// Deterministic owned input preparation only; never starts a target or guest.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {ownedBranchVmFixture,branchMemoryCode} from './fixtures/vm_bytecode_cases.mjs';
const output=process.argv[2];
assert(output&&path.isAbsolute(output),'Use an explicit absolute new output directory');
const root=path.resolve(output),plugin=path.resolve(import.meta.dirname,'..');
assert(root!==plugin&&!root.startsWith(plugin+path.sep)&&!fs.existsSync(root),'Preserve existing data and keep binaries outside source');
for(let p=path.dirname(root);;p=path.dirname(p)){const s=fs.lstatSync(p);assert(s.isDirectory()&&!s.isSymbolicLink(),'Unlinked existing ancestors required');if(p===path.dirname(p))break;}
fs.mkdirSync(root);const hash=b=>createHash('sha256').update(b).digest('hex');
const {image,labels,instructions}=ownedBranchVmFixture(),sha256=hash(image),id='owned-branch-vm64',file=path.join(root,id+'.exe');
assert.equal(sha256,'d9bf31e34c5e95307f88fcc7ce544101bd61e566c284a4622afc9700f29da61c');
fs.writeFileSync(file,image,{flag:'wx'});
const contract={schema:'ig5-owned-phase-native-contract-v1',name:id,kind:'branch-bytecode-vm',targetSha256:sha256,entryRva:0x1000,labels,instructions,
 inputRegister:'rcx',outputRegister:'rax',outputMemoryRva:0x3000,maxSteps:256,reference:'u64-add7-store-parity-xor55-or-restore',
 bytecode:{rva:0x3100,hex:branchMemoryCode.toString('hex')},finiteTestOnly:true,nativeExecutedByBuilder:false};
const contractPath=path.join(root,id+'-contract.json');fs.writeFileSync(contractPath,JSON.stringify(contract,null,2),{flag:'wx'});
const target={id,path:file,sha256};
const freeze={schema:'ig5-owned-branch-native-freeze-v1',builderSha256:hash(fs.readFileSync(import.meta.filename)),
 fixtureSourceSha256:hash(fs.readFileSync(new URL('./fixtures/vm_bytecode_cases.mjs',import.meta.url))),targets:[target],
 contracts:[{id,path:contractPath,sha256:hash(fs.readFileSync(contractPath))}],nativeTargetExecuted:false};
fs.writeFileSync(path.join(root,'fixture-freeze.json'),JSON.stringify(freeze,null,2),{flag:'wx'});
fs.writeFileSync(path.join(root,'prepare-spec.json'),JSON.stringify({guestCID:4255911716,port:48623,guestLabel:'IG5 owned branch and write-read acceptance',targets:[target]},null,2),{flag:'wx'});
console.log(JSON.stringify({ok:true,targetSha256:sha256,root,nativeTargetExecuted:false}));
