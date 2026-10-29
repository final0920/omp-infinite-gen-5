// Explicit local fixtures from the frozen Mergen research manifest; parsed as
// data only. No protected sample, native target or user executable is launched.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { LiftJobs } from '../source/lift_jobs.js';
import { hashBytes } from '../source/analysis_artifacts.js';
import { defineIntegrationTools } from '../integration_tools.js';

const main=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const [manifestPath,flagsPath,output,fallbackPath,controlManifestPath,loopManifestPath,aliasManifestPath,vmManifestPath]=process.argv.slice(2);
assert(manifestPath && flagsPath && output,'Usage: node scripts/test_lift_runtime.mjs fixtures.json flags-readback.exe new-artifact-directory');
fs.mkdirSync(output,{recursive:false});
const expected={
 'relative-forward':'503bf65329a2c9bcff4daa007a1df3f70ba8e30abffad2409a8dc13175e33fb2',
 'relative-backward':'8ed65a8fb03d4d80767a1e46a6d09c6c2abc8b3cdf8a3e75c935ca7c1809fc83',
 'register-indirect':'25498e8deb35866fb8a0d050bea21c96b910711a768186ac0f369c303ebc1ed6'};
const fixtures=JSON.parse(fs.readFileSync(manifestPath,'utf8')).rows;
assert.equal(fixtures.length,3);
for(const row of fixtures) assert.equal(hashBytes(fs.readFileSync(row.path)),expected[row.id]);
assert.equal(hashBytes(fs.readFileSync(flagsPath)),'00064816a7ec038ad3c7839bcf542702e98908fe563cc0393d4f045faa153733');
const cfg={artifactDir:output,projectRoot:path.join(output,'projects'),host:{id:'win32-x64'},
 ghidra:{available:true,pythonExe:path.join(main,'runtimes/ghidra/python/python.exe')}};
const jobs=new LiftJobs(cfg),mgr={lifter:jobs};
const tool=defineIntegrationTools(mgr,cfg).find(tool=>tool.name==='ig5_ir');
const results=[];
try {
 for(const row of fixtures) {
  const result=await tool.execute({target:row.path,level:'lift',ea:row.entry,lift_inline:[row.inlineTarget],initial_flags:'0x2'});
  assert.equal(result.process.exitCode,0); assert.equal(result.process.childExitConfirmed,true);
  assert.equal(result.nativeTargetExecuted,false);assert.equal(result.databaseModified,false);
  assert.equal(result.businessAccepted,false);assert.equal(result.wholeBinaryVerified,false);
  assert.equal(result.status,'partial');assert.equal(result.recoveryStatus,'unverified');
  assert.equal(result.diagnosticsSummary.summary.warning,0);assert.equal(result.diagnosticsSummary.summary.error,0);
  assert.equal(result.diagnosticsSummary.liftStats.instructions_unsupported,0);
  const ir=jobs.artifacts.read(result.outputRefs['output.ll'].ref,4*1024*1024).data.toString('utf8');
  // Narrow exact fixture contract. Unknown/memory/extra effects are rejected;
  // this is not an IR verifier for arbitrary lifted functions.
  const body=ir.slice(ir.indexOf('\nentry:')+7,ir.indexOf('\n}',ir.indexOf('\nentry:'))).trim().split(/\r?\n/).map(x=>x.trim());
  assert.equal(body.length,2,ir);
  const match=body[0].match(/^(%[\w.]+) = add i64 %(RCX|RDX), %(RCX|RDX)$/);
  assert(match && match[2]!==match[3],ir);assert.equal(body[1],`ret i64 ${match[1]}`);
  assert.equal(hashBytes(fs.readFileSync(result.reportPath)),result.reportSha256);
  results.push({id:row.id,result});
 }
 for(const flags of ['0x0','0x200','0xfff']) {
  const result=await tool.execute({target:flagsPath,level:'lift',ea:'0x140001000',initial_flags:flags});
  assert.equal(result.process.exitCode,0);assert.equal(result.initialFlags,flags);
  assert(result.irPreview.includes(`ret i64 ${BigInt(flags)}`));
  assert.equal(result.diagnosticsSummary.summary.warning,0);
  results.push({id:'flags-'+flags,result});
 }
 if(fallbackPath) {
  assert.equal(hashBytes(fs.readFileSync(fallbackPath)),'4579feb28bae2f69f0425a19c213371aec5b66791613a1f755e25cf54fb32b82');
  const result=await tool.execute({target:fallbackPath,level:'lift',ea:'0x140001000',initial_flags:'0x2'});
  assert.equal(result.process.exitCode,0);assert.equal(result.diagnosticsSummary.summary.warning,0);
  assert.equal(result.businessAccepted,false);assert.equal(result.recoveryStatus,'unverified');
  // Exact module bound to the independently proved SSA fixture; do not accept
  // a constant result that has discarded the free-address memory read.
  assert.equal(result.outputRefs['output.ll'].sha256,'ccb55f5567915003c31114a4ef3c78f4048849bb38ad46d022ebb1993f5ed0ff');
  results.push({id:'partial-address-original-read-preserved',result});
 }
 if(controlManifestPath) {
  const contracts={
   'partial-single':['6a67be61b322bccd548e0cb65487867b5640cf7002530286d5dc08d2aa0d01a7','82def917b92f2b445487d4b3e410429897c99e0fcac642ab62d24a9dcb1e9602',1],
   'partial-two':['082d1357e3489b578f354bab2b4fa0bea82b83595c8704498f60a5b9a81e599e','8305df4b394d38fd5082f37488cbbdaea782fb6a380147ff32bb5ed3abada57c',1],
   'complete-two':['72a65706bfc6b0a10c3caca3cd721d6260bcd29a16e57f042fc665a923a58535','bf3e5072f67c0a51579f04b80807a8dc6c64b1be5da63ab826fb16e1af2db650',0]};
  const rows=JSON.parse(fs.readFileSync(controlManifestPath,'utf8')).rows;
  assert.equal(rows.length,3);assert.equal(new Set(rows.map(row=>row.id)).size,3);
  for(const row of rows) {
   const [targetSHA,irSHA,warnings]=contracts[row.id]??[];
   assert(targetSHA);assert.equal(hashBytes(fs.readFileSync(row.path)),targetSHA);
   const result=await tool.execute({target:row.path,level:'lift',ea:row.entry,initial_flags:'0x2',max_blocks:512});
   assert.equal(result.process.exitCode,0);assert.equal(result.process.childExitConfirmed,true);
   assert.equal(result.status,'partial');assert.equal(result.recoveryStatus,'unverified');
   assert.equal(result.businessAccepted,false);assert.equal(result.wholeBinaryVerified,false);
   assert.equal(result.nativeTargetExecuted,false);assert.equal(result.databaseModified,false);
   assert.equal(result.diagnosticsSummary.summary.warning,warnings);
   assert.equal(result.diagnosticsSummary.summary.error,0);
   assert.equal(result.outputRefs['output.ll'].sha256,irSHA);
   const ir=jobs.artifacts.read(result.outputRefs['output.ll'].ref,4*1024*1024).data.toString('utf8');
   assert.equal(ir.includes('__ig5_unresolved_control_'),warnings===1);
   assert.equal(hashBytes(fs.readFileSync(result.reportPath)),result.reportSha256);
   results.push({id:'control-'+row.id,result});
  }
 }
 if(loopManifestPath) {
  const contracts={
   'three-way-push-ret-valid-unwind':['cbcc21f5eefa129b703ff35f160b196f0175433c75b6c96afaae003db803ae32','fe295378b4b92e6bb1959bd775f8900f447b38d6d39a91cf6ad52a8e12257b50'],
   'three-way-jump-valid-unwind':['c75f064582dd98aae2a500c4a8e056e6bee0e9e8df5184fb4cdce95045605191','33ee60f780dbaeb84ea4fa67ae2bbcd3632d989c8298cec15d11917c84e7b54a']};
  const rows=JSON.parse(fs.readFileSync(loopManifestPath,'utf8')).rows;
  assert.equal(rows.length,2);assert.equal(new Set(rows.map(row=>row.id)).size,2);
  for(const row of rows) {
   const [targetSHA,irSHA]=contracts[row.id]??[];assert(targetSHA);
   assert.equal(hashBytes(fs.readFileSync(row.path)),targetSHA);
   const result=await tool.execute({target:row.path,level:'lift',ea:row.entry,initial_flags:'0x2',max_blocks:512});
   assert.equal(result.process.exitCode,0);assert.equal(result.process.childExitConfirmed,true);
   assert.equal(result.status,'partial');assert.equal(result.recoveryStatus,'unverified');
   assert.equal(result.businessAccepted,false);assert.equal(result.wholeBinaryVerified,false);
   assert.equal(result.nativeTargetExecuted,false);assert.equal(result.databaseModified,false);
   assert.equal(result.outputRefs['output.ll'].sha256,irSHA);
   const d=JSON.parse(jobs.artifacts.read(result.outputRefs['output_diagnostics.json'].ref,4*1024*1024).data.toString('utf8'));
   assert.equal(d.diagnostics.filter(x=>x.code===503).length,0);
   assert.equal(d.summary.error,0);assert.equal(d.summary.warning,0);
   assert.equal(d.lift_stats.blocks_attempted,147);
   assert.equal(hashBytes(fs.readFileSync(result.reportPath)),result.reportSha256);
   results.push({id:'outline-state-'+row.id,result});
  }
 }
 if(aliasManifestPath) {
  // Exact complete modules bound to independent return/data-memory proofs for
  // the first two owned fixtures; indirect control remains explicitly unknown.
  const contracts={
   'unknown-store-file-cell':['c4ea1b280bdd8015776e90c4c0c781353a63b733d5336051bd580bf57cdf253a','1624fc0454ff27e17f68c20c2755fe66092f60d52f6ea0f0d626c18c8e18e86a',1],
   'unknown-store-tracked-cell':['fc7c7d2745aa1102fe9782ea71f71661aba00ac83dab2c96546df0a5b80106ed','96e0e7ab392f08be01e7941e2b413daa5344c7ac44a88f3db558b5283cbc9f2b',1],
   'unknown-store-control-cell':['939359d8de0a1173fd6c83cb74b2724a2dc3959cd9b202fe257dece1b355eee0','f4c85c87d58421796a5a2847c6bc3bf58174504ba35e38a85d657249e9c52583',2]};
  const rows=JSON.parse(fs.readFileSync(aliasManifestPath,'utf8')).rows;
  assert.equal(rows.length,3);assert.equal(new Set(rows.map(row=>row.id)).size,3);
  for(const row of rows) {
   const [targetSHA,irSHA,warnings]=contracts[row.id]??[];assert(targetSHA);
   assert.equal(hashBytes(fs.readFileSync(row.path)),targetSHA);
   const result=await tool.execute({target:row.path,level:'lift',ea:row.entry,initial_flags:'0x2',max_blocks:512});
   assert.equal(result.process.exitCode,0);assert.equal(result.process.childExitConfirmed,true);
   assert.equal(result.process.jobAssignedAtCreation,true);assert.equal(result.status,'partial');assert.equal(result.recoveryStatus,'unverified');
   for(const flag of ['nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'])assert.equal(result[flag],false);
   assert.equal(result.diagnosticsSummary.summary.warning,warnings);assert.equal(result.diagnosticsSummary.summary.error,0);
   assert.equal(result.outputRefs['output.ll'].sha256,irSHA);
   const diagnostic=JSON.parse(jobs.artifacts.read(result.outputRefs['output_diagnostics.json'].ref,4*1024*1024).data.toString('utf8'));
   assert.equal(diagnostic.diagnostics.filter(item=>item.code===411).length,1);
   const ir=jobs.artifacts.read(result.outputRefs['output.ll'].ref,4*1024*1024).data.toString('utf8');
   assert(ir.includes('align 1'));assert(!ir.includes('memory(argmem'));
   if(row.id==='unknown-store-control-cell') {
    assert(ir.includes('load i64'));assert(ir.includes('__ig5_unresolved_control_'));assert(!ir.includes('ret i64 17'));
   } else {assert(ir.includes('load i32'));assert(!ir.includes('ret i64 287454020'));}
   assert.equal(hashBytes(fs.readFileSync(result.reportPath)),result.reportSha256);
   results.push({id:'memory-alias-'+row.id,result});
  }
 }
 if(vmManifestPath) {
  // Complete return SSA for these exact modules is independently certified
  // over every64-bit RCX. This is not a protected-business/memory certificate.
  const contracts={
   'dispatch-selected-vsp4-jump':['c6b9c2ce1f2c3d87e5390f7af8aed9637e013488f3a44d8270eca39ed4e14f38',6,'6c0f446a89da79662e54f5e2e65957240898a87799c3aecad08774ca594b5204'],
   'dispatch-selected-vsp4-push-ret':['60c597551fa67022c587e4b2af1908eaf36fa7eb00fc0ecf42ea943aee2744db',6,'6c0f446a89da79662e54f5e2e65957240898a87799c3aecad08774ca594b5204'],
   'dispatch-selected64-vsp4-jump':['40b379fdd9fefcc8ac163ef8f53bf3c40db64572e570f6159f35405ae2315123',96,'65b1da29bf0920c0a7ce1a84c78ec595405f6e5afcd0852a0a6ff697e6781ae8'],
   'dispatch-selected64-vsp4-push-ret':['24fd56f54789d5ab1fbce4b00ee91d31ad5f9f1e2179f48f0b877646ae1ae84a',96,'65b1da29bf0920c0a7ce1a84c78ec595405f6e5afcd0852a0a6ff697e6781ae8']};
  const rows=JSON.parse(fs.readFileSync(vmManifestPath,'utf8')).rows;
  assert.equal(rows.length,4);assert.equal(new Set(rows.map(row=>row.id)).size,4);
  for(const row of rows) {
   const [targetSHA,increment,irSHA]=contracts[row.id]??[];assert(targetSHA);
   assert.equal(hashBytes(fs.readFileSync(row.path)),targetSHA);
   const result=await tool.execute({target:row.path,level:'lift',ea:row.entry,initial_flags:'0x2',max_blocks:512});
   assert.equal(result.process.exitCode,0);assert.equal(result.process.childExitConfirmed,true);assert.equal(result.process.jobAssignedAtCreation,true);
   assert.equal(result.status,'partial');assert.equal(result.recoveryStatus,'unverified');
   for(const flag of ['nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'])assert.equal(result[flag],false);
   assert.equal(result.diagnosticsSummary.summary.warning,0);assert.equal(result.diagnosticsSummary.summary.error,0);
   assert.equal(result.outputRefs['output.ll'].sha256,irSHA);
   const ir=jobs.artifacts.read(result.outputRefs['output.ll'].ref,4*1024*1024).data.toString('utf8');
   const start=ir.indexOf('\nentry:');assert(start>=0);const stop=ir.indexOf('\n}',start);assert(stop>start);
   const body=ir.slice(start+7,stop).trim().split(/\r?\n/).map(x=>x.trim());assert.equal(body.length,2,ir);
   const match=body[0].match(/^(%[\w.]+) = add i64 %RCX, (6|96)$/);assert(match,ir);
   assert.equal(Number(match[2]),increment);assert.equal(body[1],`ret i64 ${match[1]}`);
   assert.equal(hashBytes(fs.readFileSync(result.reportPath)),result.reportSha256);
   results.push({id:'total-address-'+row.id,result});
  }
 }
 // Admission and worker preflight failures do not launch the target or become
 // successful/complete report records.
 await assert.rejects(tool.execute({target:flagsPath,level:'lift',ea:'0x140001000'}),/initial_flags/);
 await assert.rejects(tool.execute({target:flagsPath,level:'lift',ea:'0x1',initial_flags:'0x2'}),/file-backed/);
 const report={status:'passed',cases:results,nativeTargetExecuted:false,businessModelCountIncrement:0,wholeBinaryVerified:false};
 fs.writeFileSync(path.join(output,'runtime-verification.json'),JSON.stringify(report,null,2));
 console.log(JSON.stringify({status:'passed',publicLifts:results.length,fixtureArithmeticContracts:3,flagsContracts:3,partialAddressContract:!!fallbackPath,controlDomainContracts:controlManifestPath?3:0,outlineStateContracts:loopManifestPath?2:0,memoryAliasContracts:aliasManifestPath?3:0,totalAddressContracts:vmManifestPath?4:0,negativePreflights:2,report:path.join(output,'runtime-verification.json')}));
} finally {await jobs.dispose();}
