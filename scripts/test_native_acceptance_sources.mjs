import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {selectNativeAcceptances,copyNativeCaptures} from './fixtures/native_acceptance_sources.mjs';

function fixture(t) {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'ig5-native-selection-'));
  t.after(()=>{assert.equal(path.dirname(root),fs.realpathSync(os.tmpdir()));assert(path.basename(root).startsWith('ig5-native-selection-'));fs.rmSync(root,{recursive:true,force:true});});
  const save=(name,extra={})=>{fs.mkdirSync(path.join(root,name));fs.writeFileSync(path.join(root,name,'acceptance.json'),JSON.stringify({ok:true,nativeTargetExecuted:true,captures:[{},{},{}],...extra}));};
  return {root,save};
}
test('ambiguous batches cannot be merged or silently filtered for successful reruns',t=>{
  const f=fixture(t),old='owned-phase-vm64-native-failed',fresh='owned-phase-vm64-native-new';
  f.save(old,{ok:false});f.save(fresh);
  assert.throws(()=>selectNativeAcceptances(f.root),/exactly one/);
  assert.throws(()=>selectNativeAcceptances(f.root,[old]),/failed/);
  assert.throws(()=>selectNativeAcceptances(f.root,[old,fresh]),/exactly one/);
  assert.equal(selectNativeAcceptances(f.root,[fresh]).selection,'explicit-single-batch');
});
test('unique branch batch keeps digest and rejects traversal, missing execution and partial capture sets',t=>{
  const f=fixture(t),name='owned-branch-vm64-native-one';f.save(name);
  const selected=selectNativeAcceptances(f.root);
  assert.equal(selected.selection,'unique-single-batch');assert.match(selected.source.sha256,/^[0-9a-f]{64}$/);
  assert.throws(()=>selectNativeAcceptances(f.root,['../'+name]),/direct child/);
  f.save('owned-branch-vm64-native-not-executed',{nativeTargetExecuted:false});
  assert.throws(()=>selectNativeAcceptances(f.root,['owned-branch-vm64-native-not-executed']),/execution/);
  f.save('owned-branch-vm64-native-incomplete',{captures:[{}]});
  assert.throws(()=>selectNativeAcceptances(f.root,['owned-branch-vm64-native-incomplete']),/three captures/);
});
test('copy binds original report and blob bytes, permits shared blobs and refuses duplicates or escaped reports',t=>{
  const f=fixture(t),store=path.join(f.root,'artifacts','debug-traces'),hash=b=>createHash('sha256').update(b).digest('hex');
  for(const part of ['records','metadata','blobs'])fs.mkdirSync(path.join(store,part),{recursive:true});
  const blob=Buffer.from('original native trace'),digest=hash(blob),captures=[];
  fs.writeFileSync(path.join(store,'blobs',digest+'.bin'),blob);
  for(let i=0;i<3;i++) {
    const id=`00000000-0000-4000-8000-00000000000${i}`,bytes=Buffer.from(JSON.stringify({id,result:{sha256:digest,storeEvents:{sha256:digest}}}));
    const traceReportPath=path.join(store,'records',id+'.json'),traceReportSha256=hash(bytes);
    fs.writeFileSync(traceReportPath,bytes);fs.writeFileSync(path.join(store,'metadata',id+'.json'),JSON.stringify({recordSha256:traceReportSha256}));
    captures.push({traceReportPath,traceReportSha256});
  }
  f.save('owned-branch-vm64-native-test',{targetSha256:'a'.repeat(64),captures});
  const selected=selectNativeAcceptances(f.root),inputs=[];
  assert.equal(copyNativeCaptures(selected,path.join(f.root,'copied'),'a'.repeat(64),inputs).length,3);
  assert(inputs.length>3);
  assert.throws(()=>copyNativeCaptures(selected,path.join(f.root,'wrong-target'),'b'.repeat(64),[]),/target/);
  const duplicate=structuredClone(selected);duplicate.receipt.captures[1]=duplicate.receipt.captures[0];
  assert.throws(()=>copyNativeCaptures(duplicate,path.join(f.root,'duplicate'),'a'.repeat(64),[]),/Duplicate/);
  const escaped=structuredClone(selected),outside=path.join(f.root,'outside.json');fs.copyFileSync(captures[0].traceReportPath,outside);
  escaped.receipt.captures[0].traceReportPath=outside;
  assert.throws(()=>copyNativeCaptures(escaped,path.join(f.root,'escaped'),'a'.repeat(64),[]),/original store/);
  fs.appendFileSync(path.join(store,'blobs',digest+'.bin'),'tampered');
  assert.throws(()=>copyNativeCaptures(selected,path.join(f.root,'tampered'),'a'.repeat(64),[]),/digest mismatch/);
});
