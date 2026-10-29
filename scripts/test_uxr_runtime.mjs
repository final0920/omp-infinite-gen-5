// Explicit real static-engine acceptance on generated fixtures; never executes the target.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { uxrHost } from './fixtures/uxr_host.mjs';
import { buildPE64Fixture } from './fixtures/pe64.mjs';
import { hashBytes } from '../source/analysis_artifacts.js';

for (const engine of ['reverse','ghidra']) test(`actual ${engine} dossier, cache, paging and query discovery`, { timeout: 180000 }, async t => {
  const f=uxrHost(t), target=path.join(f.root,'owned.exe'), image=buildPE64Fixture().image;
  image.set(Buffer.from('e87bffffffc3','hex'),0x480); fs.writeFileSync(target,image);
  const call=(name,args={})=>f.call(name,{target,engine,...args},{id:'native-fixture'});
  const opened=await call('ig5_open',{path:target,background:false});
  assert(opened.artifactId);
  const functions=await call('ig5_funcs',{limit:20}); const rows=functions.funcs || functions.items;
  assert(rows.length);
  const ea=rows[0].ea;
  const first=await call('ig5_decompile',{ea,style:'dossier',dossier_max_bytes:4000});
  assert(first.savedResult); assert.equal(first.cache.hit,false);
  const second=await call('ig5_decompile',{ea,style:'dossier',dossier_max_bytes:4000});
  assert.equal(second.cache.hit,true); assert.equal(second.cache.reason,'matching_snapshot_and_view');
  let cursor,parts=[],digest;
  do { const page=await call('ig5_decompile',{operation:'read',result_ref:first.savedResult,section:'decompile',cursor,page_max_bytes:4000});
    assert(Buffer.byteLength(JSON.stringify(page))<=4000);parts.push(page.data);digest=page.contentSha256;cursor=page.nextCursor || undefined;
  }while(cursor);
  assert.equal(hashBytes(Buffer.from(parts.join(''))),digest);assert(parts.join('').length>0);
  const xrefs=await call('ig5_xrefs',{ea:'0x140001000'});assert(Array.isArray(xrefs.hits));assert(xrefs.hits.length>0);
  assert(xrefs.hits.some(r=>r.isCall===true));
  const calls=await call('ig5_calls',{ea:'0x140001080'});assert(Array.isArray(calls.calls));assert(calls.calls.length>0);
  const cfg=await call('ig5_cfg',{ea});assert(Array.isArray(cfg.blocks));assert(cfg.blocks.length>0);
  const refreshed=await call('ig5_decompile',{ea,style:'dossier',refresh:true});assert.equal(refreshed.cache.reason,'explicit_refresh');
  assert.equal(refreshed.analysis.prototypeStatus,'unknown');assert(refreshed.analysis.warnings.length>0);
  const created=await call('ig5_decompile',{operation:'batch',batch:{action:'create',functions:[ea]}});
  const batch=await call('ig5_decompile',{operation:'batch',batch:{action:'run',id:created.id}});assert.equal(batch.counts.completed,1);
  await call('ig5_close');
});

test('actual Ghidra ELF original source mapping, file offset, nonzero module origin and roundtrip', { timeout:180000 }, async t=>{
  const f=uxrHost(t),target=path.join(f.root,'owned.elf'),image=Buffer.alloc(512);
  Buffer.from('7f454c46020101000000000000000000','hex').copy(image);
  image.writeUInt16LE(2,16);image.writeUInt16LE(62,18);image.writeUInt32LE(1,20);
  image.writeBigUInt64LE(0x400100n,24);image.writeBigUInt64LE(64n,32);image.writeUInt16LE(64,52);image.writeUInt16LE(56,54);image.writeUInt16LE(1,56);
  image.writeUInt32LE(1,64);image.writeUInt32LE(5,68);image.writeBigUInt64LE(0x400000n,80);image.writeBigUInt64LE(0x400000n,88);
  image.writeBigUInt64LE(512n,96);image.writeBigUInt64LE(768n,104);image.writeBigUInt64LE(4096n,112);
  Buffer.from('b82a000000c3','hex').copy(image,256);fs.writeFileSync(target,image);
  const call=(name,args={})=>f.call(name,{target,engine:'ghidra',...args},{id:'native-elf'});
  await call('ig5_open',{path:target,background:false});
  const convert=(value,space,to_space)=>call('ig5_profile',{address:{value,space,to_space}});
  const gva=await convert('0x400100','elf_vaddr','ghidra_va');assert.equal(gva.status,'mapped');
  const vaddr=await convert(gva.value,'ghidra_va','elf_vaddr');assert.equal(vaddr.value,'0x400100');
  assert.equal((await convert(gva.value,'ghidra_va','file_offset')).value,'0x100');
  assert.equal((await convert('0x400100','elf_vaddr','module_offset')).value,'0x100');
  await assert.rejects(convert('0x400200','elf_vaddr','file_offset'),/NOT_FILE_BACKED/);
  await assert.rejects(convert('0x400100','elf_vaddr','runtime_va'),/RUNTIME_MAPPING_UNAVAILABLE/);
  const dossier=await call('ig5_decompile',{ea:gva.value,style:'dossier'});
  assert.equal(dossier.sections.decompile.data.addresses.value,'0x400100');
  await call('ig5_close');
});
