import test from 'node:test';
import assert from 'node:assert/strict';
import { observedEffectiveAddress, analyzeVmAddressRoles } from '../source/vm_address_roles.js';
import { selectVmRoleSamples } from '../source/vm_role_samples.js';
import { observationWindow, replaceObservationRows, observationTarget } from './fixtures/vm_observation_cases.mjs';
import { runRecoveryProfile, recoveryProfileSchema } from '../source/vm_recovery_profile.js';
const reg = (name, parent = name, bits = 64, low = 0) => ({ kind: 'register', name, parent, bits, low });
const mem = (base, bytes = 1, extra = {}) => ({ kind: 'memory', bytes, base: base ? reg(base) : null, index: null, scale: 1,
  displacement: '0x0', displacementBits: 64, segment: null, ...extra });
const gprs = () => Object.fromEntries('rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split(' ').map(x => [x,'0x0']));
function group(bytes = '8a06', address = '0x8000', value = '2a', i = 0) {
  const before = { gprs: { ...gprs(), rsi: address, rsp: '0x9000', rax: '0x100' }, rip: '0x140001000', flags: '0x202', sourceLine: 2 };
  return { groupIndex: i, recordingId: 'test', pauseSequence: { before: i + 1, after: i + 2, individuallyAttested: false }, before,
    after: { ...structuredClone(before), gprs: { ...before.gprs, rax: '0x12a' }, rip: '0x140001002' },
    intermediateStateAvailable: true, instructions: [{ pc: before.rip, bytes, sourceLine: 5 }],
    memoryReads: [{ address, bytes: value.length / 2, littleEndianHex: value, sourceLine: 4 }], gsBaseObservation: null };
}
function analyze(groups, operands = [reg('al','rax',8),mem('rsi')], text = 'mov al, byte ptr [rsi]') {
  const site = { pc: groups[0].instructions[0].pc, bytes: groups[0].instructions[0].bytes, count: groups.length, groups };
  const samples = { schema: 'ig5-vm-role-samples-v1', observation: { targetSha256: 'a'.repeat(64), identity: {}, windows: [] }, sampling: {}, sites: [site] };
  const decoded = { schema: 'ig5-observed-decode-v1', decoder: 'pinned-triton-disassembly-only', decoderManifestPin: '65bf673f1c4304cc2c09076e3b96e368da9e0df72aa0badeba0c2a5cae392934',
    nativeTargetExecuted: false, databaseModified: false, businessAccepted: false, wholeBinaryVerified: false,
    sites: [{ pc: site.pc, bytes: site.bytes, status: 'decoded', text, controlFlow: /^(jmp|ret|call)/.test(text), operands }] };
  return analyzeVmAddressRoles(samples, decoded);
}
test('ordinary buffer traversal produces ambiguous stream candidates, never VM roles', () => {
  const result = analyze([group(),group('8a06','0x8001','2a',1)]);
  assert.equal(result.counts.consistentLoads,2); assert.equal(result.streamCandidates.length,1);
  assert.match(result.streamCandidates[0].ordinaryProgramAmbiguity,/byte-buffer/);
  assert.equal(result.streamCandidates[0].vmRoleProved,false); assert.equal(result.vmModelProved,false);
  assert.equal(result.businessAccepted,false); assert.equal(result.phases,'unclassified');
});
test('RIP-relative memory uses next instruction including negative displacement', () => {
  const g = group('488b05fcffffff');
  assert.equal(observedEffectiveAddress(mem('rip',8,{displacement:'0xfffffffffffffffc'}),g).address,'0x140001003');
});
test('32-bit addressing wraps before GS addition, high GPR bits are excluded', () => {
  const g = group('678b448d20'); g.before.gprs.rbp='0xfeed0000fffffff0'; g.before.gprs.rcx='0x1234000000000008';
  const m = mem(null,4,{base:reg('ebp','rbp',32),index:reg('ecx','rcx',32),scale:4,displacement:'0x20',displacementBits:32});
  assert.equal(observedEffectiveAddress(m,g).address,'0x30');
  g.gsBaseObservation='0x100000000'; m.segment='gs'; assert.equal(observedEffectiveAddress(m,g).address,'0x100000030');
});
test('missing FS/GS bases and inconsistent register aliases remain unresolved', () => {
  const g=group(); assert.equal(observedEffectiveAddress(mem('rsi',1,{segment:'fs'}),g).status,'fs-base-unobserved');
  assert.equal(observedEffectiveAddress(mem('rsi',1,{segment:'gs'}),g).status,'gs-base-unobserved');
  assert.equal(observedEffectiveAddress(mem(null,1,{base:reg('esi','rsi',32)}),g).status,'unsupported-address-register');
});
test('high-byte loads preserve other parent bits and mismatches are counterevidence', () => {
  const g=group('8a26'); g.before.gprs.rax='0x12345678';g.after.gprs.rax='0x12342a78';
  assert.equal(analyze([g],[reg('ah','rax',8,8),mem('rsi')],'mov ah, byte ptr [rsi]').counts.consistentLoads,1);
  g.after.gprs.rax='0x2a78'; assert.equal(analyze([g],[reg('ah','rax',8,8),mem('rsi')],'mov ah, byte ptr [rsi]').counts.inconsistentLoads,1);
});
test('32-bit load clears high bits; sign extension differs from zero extension', () => {
  const g=group('0fbe06','0x8000','ff'); g.before.gprs.rax='0xdeadbeef12345678'; g.after.gprs.rax='0xffffffff';
  assert.equal(analyze([g],[reg('eax','rax',32),mem('rsi')],'movsx eax, byte ptr [rsi]').counts.consistentLoads,1);
  assert.equal(analyze([g],[reg('eax','rax',32),mem('rsi')],'movzx eax, byte ptr [rsi]').counts.inconsistentLoads,1);
});
test('conflicting reads at identical locations cannot be silently selected', () => {
  const g=group();g.memoryReads.push({...g.memoryReads[0],littleEndianHex:'2b',sourceLine:8});
  const r=analyze([g]);assert.equal(r.counts.consistentLoads,0); assert.equal(r.sites[0].observations[0].accesses[0].read.status,'conflicting-recorded-reads');
});
test('LEA memory syntax never establishes a memory read or context access', () => {
  const r=analyze([group('488d06')],[reg('rax'),mem('rsi',8)],'lea rax, [rsi]');
  assert.equal(r.counts.effectiveAddressMatches,0);assert.equal(r.counts.consistentLoads,0);assert.equal(r.contextCandidates.length,0);
});
test('RET requires actual recorded stack target plus post-stop RSP', () => {
  const g=group('c3','0x9000','7856341200000000');g.after.rip='0x12345678';g.after.gprs.rsp='0x9008';
  assert.equal(analyze([g],[],'ret').counts.consistentIndirectControls,1);
  g.after.gprs.rsp='0x9000';assert.equal(analyze([g],[],'ret').counts.inconsistentIndirectControls,1);
  g.memoryReads=[];assert.equal(analyze([g],[],'ret').counts.consistentIndirectControls,0);
});
test('indirect register jump matches next RIP without claiming dispatch semantics', () => {
  const g=group('ffe0');g.before.gprs.rax='0x1234';g.after.rip='0x1234';
  const r=analyze([g],[reg('rax')],'jmp rax');assert.equal(r.counts.consistentIndirectControls,1);
  assert.equal(r.sites[0].observations[0].control.dispatchRoleProved,false);
});
test('coalesced instructions do not invent load values from a later stop', () => {
  const g=group();g.instructions.push({pc:'0x140001002',bytes:'90'});g.intermediateStateAvailable=false;
  const r=analyze([g]);assert.equal(r.counts.consistentLoads,0);assert.equal(r.counts.coalescedGroupsUnmodeled,1);
});
test('sampling validates every row even when it will not retain the last groups', () => {
  const w=replaceObservationRows(observationWindow({count:20}),s=>s.replace(/i:0x[0-9a-f]+:/g,'i:0x1000:'));
  w.summary.exit='0x1000';
  const r=selectVmRoleSamples({targetSha256:observationTarget,windows:[w]});
  assert.equal(r.sampling.samples,8);assert.deepEqual(r.sites[0].groups.map(g=>g.groupIndex),[0,1,2,3,16,17,18,19]);
  const corrupt=replaceObservationRows(w,s=>s.replace(/f:.*/,'f:0x1'));
  assert.throws(()=>selectVmRoleSamples({targetSha256:observationTarget,windows:[corrupt]}),/snapshot/);
});
test('public roles cannot mix page/case/observation requests or increase budgets', async () => {
  assert.equal(recoveryProfileSchema.properties.roles.additionalProperties,false);
  await assert.rejects(async()=>runRecoveryProfile({}, {recovery:{roles:{},case_ref:{}}},{}),/requires exactly/);
  await assert.rejects(async()=>runRecoveryProfile({checkCancelled(){}}, {recovery:{roles:{offset:0}}},{}),/offset and limit/);
});
test('cancelled role mode refuses before recording reads or decoder dispatch', async () => {
  const mgr={checkCancelled(){},scope:{getStore(){return {signal:AbortSignal.abort()};}}};
  await assert.rejects(()=>runRecoveryProfile(mgr,{recovery:{roles:{}}},{}),{code:'ABORT_ERR'});
});
test('site tracking overflow remains explicit and selected sites never exceed 128', () => {
  const windows=Array.from({length:9},(_,n)=>observationWindow({id:n+1,count:512,start:1+512*n,pc:0x1000+512*n,value:1+512*n}));
  const r=selectVmRoleSamples({targetSha256:observationTarget,windows});
  assert.equal(r.sampling.trackingComplete,false);assert.equal(r.sampling.countsAreLowerBounds,true);
  assert.equal(r.sampling.trackedSites,4096);assert.equal(r.sites.length,128);assert.equal(r.sampling.samples,128);
});
