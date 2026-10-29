// Opt-in native validation of OUR generated/pinned official-producer outputs.
// No downloaded third-party challenge is executed by this runner.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { apply } from '../index.js';
import { modernOwnedImage, modernOwnedHarnessImage } from './fixtures/modern_owned_cases.mjs';
import { peExport } from './fixtures/pe_export.mjs';

const root = path.resolve(import.meta.dirname, '..');
const base = process.env.IG5_MODERN_EVIDENCE || 'C:/Users/IG5User/.dsh/ig5/artifacts/modern-protection-20261014';
const generation = JSON.parse(fs.readFileSync(path.join(base, process.env.IG5_MODERN_GENERATION || 'generated-vmp311', 'generation.json'), 'utf8'));
const id = process.env.IG5_MODERN_CASE || 'add64', mode = process.env.IG5_MODERN_MODE || 'virtualization';
const item = generation.rows.find(row => row.id === id && row.mode === mode);
assert(item, 'Case not present in generation receipt');
const hash = data => createHash('sha256').update(data).digest('hex');
const compiled = ['owned-compiled-c-v1', 'owned-compiled-suite-c-v1', 'owned-packed-suite-c-v1', 'owned-enigma-suite-c-v1', 'owned-enigma-suite-c-v2'].includes(item.recipe);
let readyRVA, readyFunctionRVA, readyBytes;
if (compiled) {
  const proofData = fs.readFileSync(item.compilerProofPath), proof = JSON.parse(proofData);
  assert.equal(hash(proofData), item.compilerProofSha256);
  const source = item.recipe === 'owned-compiled-c-v1' ? './fixtures/modern_compiled.c' : item.recipe === 'owned-packed-suite-c-v1' ? './fixtures/packed_compiled_suite.c' : item.recipe === 'owned-enigma-suite-c-v1' ? './fixtures/enigma_compiled_suite.c' : item.recipe === 'owned-enigma-suite-c-v2' ? './fixtures/enigma_compiled_suite_v2.c' : './fixtures/modern_compiled_suite.c';
  assert.equal(proof.sourceSHA256, hash(fs.readFileSync(new URL(source, import.meta.url))));
  if (item.recipe === 'owned-compiled-suite-c-v1') {
    assert.equal(proof.schema, 'ig5.owned-compiled-suite.v1'); assert.equal(proof.id, id);
    assert.equal(proof.caseDefine, ['compiled-rotate-mix64', 'compiled-signed-select64', 'compiled-mul-mix32'].indexOf(id));
  }
  if (item.recipe === 'owned-packed-suite-c-v1') {
    assert.equal(proof.schema, 'ig5.owned-packed-suite.v1'); assert.equal(proof.id, id);
    assert.equal(proof.caseDefine, ['packed-branch-mix64', 'packed-round-mix64'].indexOf(id));
    assert.equal(proof.entryRVA, item.entryRVA);
    assert.equal(proof.mapSHA256, hash(fs.readFileSync(path.join(path.dirname(proof.target), id + '.map'))));
  }
  if (['owned-enigma-suite-c-v1', 'owned-enigma-suite-c-v2'].includes(item.recipe)) {
    assert.equal(proof.schema, item.recipe.endsWith('v2') ? 'ig5.owned-enigma-suite.v2' : 'ig5.owned-enigma-suite.v1'); assert.equal(proof.id, id);
    assert.equal(proof.caseDefine, ['packed-branch-mix64', 'packed-round-mix64'].indexOf(id));
    assert.equal(proof.compilerOptimization, 'Od'); assert.deepEqual(proof.markers, ['vm_begin', 'vm_end']);
    assert.equal(proof.sdkLibrarySHA256, '96377e90e1da37b03de22fd348d0dddbcd9b1537fc3af9f5f7a82c3ce23c4cc9');
    assert.equal(hash(fs.readFileSync(proof.sdkLibrary)), proof.sdkLibrarySHA256);
    assert.equal(proof.entryRVA, item.entryRVA);
    assert.equal(proof.mapSHA256, hash(fs.readFileSync(path.join(path.dirname(proof.target), id + '.map'))));
    if (item.recipe.endsWith('v2')) {
      assert.equal(proof.preVmDebugRendezvous, true); assert(/^0x[0-9a-f]+$/.test(proof.readyRVA));
      readyFunctionRVA = proof.readyRVA;
      const exportedReady = peExport(fs.readFileSync(item.input), 'ig5_enigma_debug_ready');
      assert.equal(BigInt(exportedReady.rva), BigInt(readyFunctionRVA));
      // MSVC may emit its two-byte hotpatch NOP before __debugbreak(). The
      // unchanged compiler-bound control determines the trap, never protector
      // heuristics or a guessed address. Only these exact OWN harnesses qualify.
      const prefix = exportedReady.bytes.startsWith('6690ccc3') ? '6690ccc3'
        : exportedReady.bytes.startsWith('ccc3') ? 'ccc3' : null;
      assert(prefix, 'Unexpected compiler-bound OWN rendezvous instructions');
      readyBytes = prefix;
      readyRVA = '0x' + (BigInt(readyFunctionRVA) + (prefix === '6690ccc3' ? 2n : 0n)).toString(16);
    }
  }
  assert.equal(hash(fs.readFileSync(item.input)), proof.inputSHA256);
} else assert.equal(item.inputSha256, hash((item.harness ? modernOwnedHarnessImage : modernOwnedImage)(id)), 'Owned recipe changed');
assert.equal(hash(fs.readFileSync(item.target)), item.targetSha256);
const officialProducer = generation.producerSha256 === '52e23d2f9c959a21bdc2067d03d29e20cd85995a202cb7f2116d89b19c88c527'
  || generation.producerSha256 === 'd20ebe0b7b22b6be968c8c34be61f94ddea12cb11462e2cec27f548ef9574df8'
    && generation.producerVersion === '5.2.1' && generation.archiveSha256 === 'eabc6792a347d45e945be7748423e7868fd01b0d2bcaa2f4b1031fd71ff69bda'
  || generation.producerSha256 === 'c393a08a7259c053ef9eff48fac64051422144bda6a5f7c8927113f50960fd30'
    && generation.producerVersion === '7.80 Demo' && generation.archiveSha256 === '8a31a018feb5ea1fec2fa1d1d3a9e004b143be6b9d16155ba0a2c6bbe8cd2813'
    && (item.mode === 'enigma-packing' && item.codeVirtualizationRequested === false
      || item.mode === 'enigma-classic-vm' && item.codeVirtualizationRequested === true && ['owned-enigma-suite-c-v1', 'owned-enigma-suite-c-v2'].includes(item.recipe));
assert(officialProducer, 'Owned recording requires a pinned official producer');
const runLabel = process.env.IG5_MODERN_RUN_LABEL || '';
assert(!runLabel || /^[a-z0-9-]{1,40}$/.test(runLabel), 'Use a bounded evidence-run label');
const output = path.join(base, 'native-' + id + '-' + mode + (item.harness ? '-harness' : '') + (runLabel ? '-' + runLabel : ''));
fs.mkdirSync(output, { recursive: true });
const definitions = new Map(), effects = [];
const ctx = { tools: { register(d) { definitions.set(d.name, d); return () => definitions.delete(d.name); } },
  get() {}, on() { return () => {}; },
  inject(names, callback) { if (names.includes('webServer')) callback({ webServer: { register() { return () => {}; } } }); return { dispose() {} }; },
  effect(callback) { const dispose = callback(); if (typeof dispose === 'function') effects.push(dispose); },
};
const maxInstructions = Number(process.env.IG5_MODERN_MAX_INSTRUCTIONS || 50000);
assert(Number.isSafeInteger(maxInstructions) && maxInstructions >= 1 && maxInstructions <= 100000, 'Owned trace budget must be 1..100000');
const receipt = { pluginRoot: root, generatedCase: item, target: item.target, nativeTargetExecuted: false, maxInstructions,
  producer: { producerVersion: generation.producerVersion, producerSha256: generation.producerSha256, archiveSha256: generation.archiveSha256 },
  thirdPartySamplesExecuted: false, status: 'starting', calls: [], parts: [] };
const save = () => fs.writeFileSync(path.join(output, 'receipt.json'), JSON.stringify(receipt, null, 2));
apply(ctx, { reverse: false, reverseProvider: 'bundled', toolset: 'full', artifactDir: output, projectRoot: path.join(output, 'projects'), requestTimeoutMs: process.env.IG5_MODERN_UI_WAIT === '1' ? 180000 : 120000 });
const call = async (name, args) => {
  const startedAt = new Date().toISOString();
  receipt.pendingCall = { name, args, startedAt };
  save();
  const result = await definitions.get(name).execute({ target: item.target, engine: 'ghidra', ...args }, { agent: { id: 'owned-vmp311-native-test' }, signal: new AbortController().signal });
  receipt.calls.push({ name, args, startedAt, completedAt: new Date().toISOString(), result });
  delete receipt.pendingCall; save(); return result;
};
const dbg = (op, args = {}) => call('ig5_dbg', { backend: 'x64dbg', op, timeout: 45, ...args });
try {
  await call('ig5_open', { path: item.target, background: false, analysis_profile: 'interactive', analysis_timeout: 20 });
  await dbg('load');
  const started = await dbg('start', process.env.IG5_MODERN_SCYLLAHIDE === '1' ? { anti_debug_profile: 'scyllahide-thread-context' } : {});
  if (started.antiDebugEnvironment) receipt.antiDebugEnvironment = started.antiDebugEnvironment;
  assert.equal(started.state, 'suspended');
  receipt.nativeTargetExecuted = true;
  receipt.runtimeBase = started.context.mainModuleBase;
  const entryRVA = item.entryRVA || '0x1000';
  const entry = '0x' + (BigInt(receipt.runtimeBase) + BigInt(entryRVA)).toString(16);
  // Windows loader context restoration can clear early hardware registers.
  // Reach the protector's normal EXE entry first, then arm the unchanged leaf.
  const initialStop = await dbg('cont');
  assert.equal(initialStop.eventName, 'breakpoint');
  const startupStops = Number(process.env.IG5_MODERN_STARTUP_STOPS || 4);
  assert(Number.isSafeInteger(startupStops) && startupStops >= 1 && startupStops <= 32, 'Owned startup must stay within 1..32 observed stops');
  receipt.startupStopBudget = startupStops;
  let hideHook;
  if (process.env.IG5_MODERN_BLOCK_HIDE_REQUEST === '1') {
    assert(readyRVA && item.recipe === 'owned-enigma-suite-c-v2', 'Hide-request fixture interception requires our compiler-bound v2 harness');
    const modules = await dbg('modules'), nt = modules.modules.filter(row => row.name.toLowerCase() === 'ntdll.dll');
    assert.equal(nt.length, 1); assert.equal(nt[0].path.toLowerCase(), 'c:\\windows\\system32\\ntdll.dll');
    const exported = peExport(fs.readFileSync(nt[0].path), 'NtSetInformationThread');
    const ea = '0x' + (BigInt(nt[0].base) + BigInt(exported.rva)).toString(16);
    const before = await dbg('readmem', { ea, size: 16 }); assert.equal(before.hex, exported.bytes, 'Loaded NT entry bytes differ from the current OS file');
    const installed = await dbg('bpt', { ea, kind: 'software' }); assert.equal(installed.ok, true);
    hideHook = { ea, export: exported, requests: [], observedApiStops: [], maxApiStops: 128 }; receipt.ownedFixtureHideRequestInterception = hideHook; save();
  }
  let consumeOwnedRendezvous = false;
  if (readyRVA) {
    const ready = BigInt(receipt.runtimeBase) + BigInt(readyRVA);
    let readyRegs, stop;
    for (let n = 0; n < startupStops; n++) {
      receipt.status = 'running-to-owned-debug-rendezvous'; save();
      stop = await dbg('cont', { timeout: process.env.IG5_MODERN_UI_WAIT === '1' ? 120 : 45 });
      assert.equal(stop.state, 'suspended', 'Owned target stopped before its compiled debugger rendezvous');
      readyRegs = await dbg('regs');
      if (hideHook && readyRegs.regs.rip === hideHook.ea) {
        const r = readyRegs.regs;
        assert(hideHook.observedApiStops.length < hideHook.maxApiStops, 'Own fixture API observation budget exhausted');
        hideHook.observedApiStops.push({ threadId: readyRegs.context.tid, stopSeq: readyRegs.context.stopSeq, rcx: r.rcx, informationClass: r.rdx, pointer: r.r8, bytes: r.r9 }); save();
        if (r.rdx === '0x11' && r.rcx === '0xfffffffffffffffe' && r.r8 === '0x0' && r.r9 === '0x0' && readyRegs.context.tid === started.context.tid) {
          const stack = await dbg('readmem', { ea: r.rsp, size: 8 }), returnEA = '0x' + Buffer.from(stack.hex, 'hex').readBigUInt64LE().toString(16);
          assert(BigInt(returnEA) >= BigInt(receipt.runtimeBase) && BigInt(returnEA) < BigInt(receipt.runtimeBase) + BigInt(started.context.mainModuleSize), 'Hide-request caller must be inside the owned protector image');
          hideHook.requests.push({ context: stop.context, parameters: { rcx: r.rcx, rdx: r.rdx, r8: r.r8, r9: r.r9 },
            returnEA, policy: 'Own fixture only: simulate STATUS_ACCESS_DENIED for the current-main-thread hide request; original OS API is not executed', nativeTargetEnvironmentModified: true }); save();
          assert.equal((await dbg('setreg', { reg: 'rax', value: '0xc0000022', expected: r.rax })).ok, true);
          assert.equal((await dbg('setreg', { reg: 'rsp', value: '0x' + (BigInt(r.rsp) + 8n).toString(16), expected: r.rsp })).ok, true);
          assert.equal((await dbg('setreg', { reg: 'rip', value: returnEA, expected: r.rip })).ok, true);
        }
        n--; continue;
      }
      if (stop.eventName === 'exception' && readyRegs.context.tid !== started.context.tid) {
        const main = await dbg('regs', { thread_id: started.context.tid });
        receipt.startupMainThreadObservations = [...(receipt.startupMainThreadObservations || []), main]; save();
        if (main.selectedThreadDebuggerVisibility?.hiddenFromDebugger === true)
          throw new Error('Owned main thread reports ThreadHideFromDebugger; native breakpoint events cannot validate the business path');
      }
      if ([ready, ready + 1n].includes(BigInt(readyRegs.regs.rip))) break;
    }
    assert(readyRegs && [ready, ready + 1n].includes(BigInt(readyRegs.regs.rip)), 'Compiled debugger rendezvous was not reached');
    const code = await dbg('readmem', { rva: readyFunctionRVA, size: readyBytes.length / 2 });
    assert.equal(code.hex, readyBytes, 'Loaded OWN rendezvous differs from the pinned compiler control');
    receipt.debugRendezvous = { readyFunctionRVA, readyRVA, context: stop.context, bytes: code.hex, instructionOutsideBusinessVm: true };
    assert.equal(stop.eventName, 'exception');
    assert.equal(stop.context.exception?.code, '0x80000003');
    assert.equal(BigInt(stop.context.exception.ea), ready);
    consumeOwnedRendezvous = true;
    // An INT3 event may expose RIP at the trap or the following RET. Only this
    // compiler-bound harness trap is advanced; no protected business code is skipped.
    if (BigInt(readyRegs.regs.rip) === ready) await dbg('setreg', { reg: 'rip', value: '0x' + (ready + 1n).toString(16), expected: readyRegs.regs.rip });
  }
  const armed = await dbg('bpt', { rva: entryRVA, kind: 'hardware' });
  assert.equal(armed.ok, true, 'Owned leaf hardware breakpoint was rejected');
  const unpackWatch = process.env.IG5_MODERN_UNPACK_WATCH === '1';
  const watchRVA = '0x' + (BigInt(entryRVA) + 1n).toString(16);
  if (unpackWatch) {
    const watch = await dbg('bpt', { rva: watchRVA, kind: 'hardware', access: 'write' });
    assert.equal(watch.ok, true, 'Owned unpack write watch was rejected');
  }
  let regs = await dbg('regs');
  assert.equal(regs.regs['dr' + armed.breakpoint.slot], entry, 'Hardware breakpoint is not armed in the active thread');
  for (let i = 0; regs.regs.rip !== entry && i < startupStops; i++) {
    if (i === 0 && process.env.IG5_MODERN_DIAG === '1') {
      receipt.status = 'diagnose-startup'; save();
      const diagnosticDelay = Number(process.env.IG5_MODERN_DIAG_DELAY_MS || 1500);
      assert(Number.isSafeInteger(diagnosticDelay) && diagnosticDelay >= 1500 && diagnosticDelay <= 35000, 'Owned startup diagnostic delay must stay within 1.5..35 seconds');
      const continued = dbg('cont', { timeout: process.env.IG5_MODERN_UI_WAIT === '1' ? 120 : 45 }).then(result => ({ result }), error => ({ error }));
      await new Promise(resolve => setTimeout(resolve, diagnosticDelay));
      await dbg('suspend', { interrupt_method: 'break-process' }); const continuation = await continued; if (continuation.error) throw continuation.error;
      receipt.diagnostics = { regs: await dbg('regs'), mainThread: await dbg('regs', { thread_id: started.context.tid }),
        threads: await dbg('threads'), stack: await dbg('callstack'), modules: await dbg('modules') };
      receipt.diagnostics.mainStack = await dbg('readmem', { ea: receipt.diagnostics.mainThread.selectedThreadRegs.rsp, size: 512 });
      const nativeRegs = receipt.diagnostics.mainThread.selectedThreadRegs;
      if (nativeRegs.rcx === '0x50000018') {
        const parameters = await dbg('readmem', { ea: nativeRegs.r9, size: 32 });
        const pointers = Buffer.from(parameters.hex, 'hex');
        receipt.diagnostics.serviceNotification = [];
        for (let n = 0; n < 2; n++) {
          const pointer = '0x' + pointers.readBigUInt64LE(n * 8).toString(16);
          const descriptor = Buffer.from((await dbg('readmem', { ea: pointer, size: 16 })).hex, 'hex');
          const size = descriptor.readUInt16LE(), address = '0x' + descriptor.readBigUInt64LE(8).toString(16);
          if (size > 0 && size <= 2048) receipt.diagnostics.serviceNotification.push(Buffer.from((await dbg('readmem', { ea: address, size })).hex, 'hex').toString('utf16le'));
        }
      }
      const error = new Error('Startup diagnostic recorded'); error.code = 'DIAGNOSTIC'; throw error;
    }
    receipt.status = 'running-to-owned-leaf'; save();
    const continued = await dbg('cont', { timeout: process.env.IG5_MODERN_UI_WAIT === '1' ? 120 : 45,
      ...(consumeOwnedRendezvous ? { exception_disposition: 'handled' } : {}) });
    if (consumeOwnedRendezvous) {
      assert.equal(continued.exceptionDisposition, 'handled');
      receipt.debugRendezvous.continuedException = continued.continuedException;
      consumeOwnedRendezvous = false;
    }
    assert.equal(continued.state, 'suspended', 'Owned target stopped before reaching its leaf');
    regs = await dbg('regs');
    if (unpackWatch && continued.eventName === 'breakpoint' && regs.regs.rip !== entry) {
      receipt.unpackWriteStops = [...(receipt.unpackWriteStops || []), { context: continued.context, regs: regs.regs,
        leafBytes: await dbg('readmem', { rva: entryRVA, size: 64 }) }]; save();
      await dbg('unbpt', { rva: watchRVA, kind: 'hardware', access: 'write' });
      await dbg('unbpt', { rva: entryRVA, kind: 'hardware' });
      await dbg('bpt', { rva: entryRVA, kind: 'hardware' });
    }
  }
  assert.equal(regs.regs.rip, entry, 'Owned leaf entry was not reached');
  if (hideHook) await dbg('unbpt', { ea: hideHook.ea, kind: 'software' });
  await dbg('unbpt', { rva: entryRVA, kind: 'hardware' });
  if (unpackWatch && !receipt.unpackWriteStops) await dbg('unbpt', { rva: watchRVA, kind: 'hardware', access: 'write' });
  if (compiled) {
    const stack = await dbg('readmem', { ea: regs.regs.rsp, size: 8 });
    receipt.returnAddress = '0x' + Buffer.from(stack.hex, 'hex').readBigUInt64LE().toString(16);
  }
  const inputX = process.env.IG5_MODERN_X || '0x1', inputY = process.env.IG5_MODERN_Y || '0x2';
  assert([inputX, inputY].every(value => /^0x[0-9a-f]{1,16}$/i.test(value)), 'Own fixture inputs must be explicit uint64 hex');
  await dbg('setreg', { reg: 'rcx', value: inputX, expected: regs.regs.rcx });
  await dbg('setreg', { reg: 'rdx', value: inputY, expected: regs.regs.rdx });
  const lines = [];
  let segmentMarkers;
  let initialFlags;
  let initialRestartRetries = 0;
  let recordedInstructions = 0;
  const traceSteps = Number(process.env.IG5_MODERN_STEPS || 128);
  assert(Number.isInteger(traceSteps) && traceSteps >= 1 && traceSteps <= 512, 'Owned capture window must stay within recorder bounds');
  for (let part = 0; part < 256; part++) {
    if (recordedInstructions >= maxInstructions) throw new Error('Owned native function exceeded its declared instruction budget');
    receipt.status = 'recording-' + part; save();
    const until = receipt.returnAddress || (item.harness ? '0x' + (BigInt(receipt.runtimeBase) + 0x13b3n).toString(16) : undefined);
    const trace = await dbg('trace', { record_trace: true, ...(process.env.IG5_MODERN_RECORD_IMAGE === '1' && !receipt.parts.length ? { record_image: true } : {}), max_steps: Math.min(traceSteps, maxInstructions - recordedInstructions), trace_inputs: item.inputs, trace_output: item.output, ...(until ? { until } : {}) });
    if (!trace.traceSaved && !receipt.parts.length && trace.traceSummary.stopReason === 'instruction-transition-not-observed' && initialRestartRetries++ < 2) {
      receipt.initialRestartObservations = [...(receipt.initialRestartObservations || []), trace.traceSummary]; save(); part--; continue;
    }
    if (!trace.traceSaved) throw new Error('Recording failed: ' + JSON.stringify(trace.traceSummary));
    if (initialFlags === undefined) initialFlags = trace.traceSummary.initialFlags;
    const data = fs.readFileSync(trace.tracePath, 'utf8');
    assert.equal(hash(Buffer.from(data)), trace.traceSha256);
    receipt.parts.push({ reportId: trace.traceReportId, path: trace.tracePath, sha256: trace.traceSha256, summary: trace.traceSummary });
    if (trace.recoveryArgs?.trace_image) receipt.traceImage = trace.recoveryArgs.trace_image;
    recordedInstructions += trace.traceSummary.instructionCount;
    const records = data.trimEnd().split('\n');
    assert(['h:ig5-native-x64-v1', 'h:ig5-native-x64-v2'].includes(records.shift()));
    const segment = records[0]?.startsWith('s:') ? records.shift() : undefined;
    if (part) assert.equal(segment, segmentMarkers); else segmentMarkers = segment;
    if (part) {
      // Prior native final snapshot and next pre-instruction snapshot must be
      // identical in all GPRs; RIP continuity is checked again by the replayer.
      const previousFinal = lines.pop(); assert(previousFinal.startsWith('f:'));
      const previousRegisters = previousFinal.split(':').slice(1, 17).join(':');
      assert.equal(records[0], 'r:' + previousRegisters, 'Chunk register continuation differs');
      const prior = receipt.parts.at(-2).summary;
      assert.equal(prior.runId, trace.traceSummary.runId); assert.equal(prior.threadId, trace.traceSummary.threadId);
      assert.equal(prior.endStopSeq, trace.traceSummary.startStopSeq, 'Pause sequence continuation differs');
    }
    lines.push(...records); save();
    console.log(JSON.stringify({ id, mode, part, instructions: trace.traceSummary.instructionCount, reason: trace.traceSummary.stopReason }));
    if (['returned', 'until-address'].includes(trace.traceSummary.stopReason)) { receipt.status = 'recorded-return'; break; }
    if (!['instruction-budget', 'recording-deadline'].includes(trace.traceSummary.stopReason)) {
      receipt.diagnostics = { regs: await dbg('regs'), events: await dbg('event'), threads: await dbg('threads') }; save();
      throw new Error('Recording stopped before owned leaf return: ' + trace.traceSummary.stopReason);
    }
  }
  assert.equal(receipt.status, 'recorded-return', 'Owned native run exceeded chunk budget');
  const data = Buffer.from('h:ig5-native-x64-v2\n' + (segmentMarkers ? segmentMarkers + '\n' : '') + lines.join('\n') + '\n'), filename = path.join(output, 'joined.trace');
  fs.writeFileSync(filename, data);
  const recoveryArgs = { target: item.target, level: 'trace', traces: [{ path: filename, sha256: hash(data) }],
    trace_entry: receipt.parts[0].summary.entry, trace_exit: receipt.parts.at(-1).summary.exit,
    trace_runtime_base: receipt.runtimeBase, trace_inputs: item.inputs, trace_output: item.output, initial_flags: initialFlags, max_instructions: maxInstructions,
    ...(receipt.traceImage ? { trace_image: receipt.traceImage } : {}) };
  receipt.joinedTrace = { path: filename, bytes: data.length, sha256: hash(data), rawPartsPreserved: true };
  if (process.env.IG5_MODERN_RECORD_ONLY === '1') {
    receipt.status = 'native-path-recorded'; receipt.recoveryDeferred = true;
    receipt.finalRegisters = await dbg('regs');
  } else {
    receipt.recovery = await call('ig5_ir', recoveryArgs);
    receipt.finalRegisters = await dbg('regs');
    assert.equal(receipt.recovery.paths[0].outputProof.status, 'unsat');
    assert(receipt.recovery.paths[0].finalSnapshotVerified && receipt.recovery.paths[0].binaryBinding.allInstructionBytesMatch);
    assert(receipt.recovery.recoveredExpression, 'Complete declared input domain was not recovered');
    receipt.status = 'trace-model-recovered';
  }
} catch (error) { receipt.status = error.code === 'DIAGNOSTIC' ? 'diagnostic' : 'failed'; receipt.error = error.message; if (error.code !== 'DIAGNOSTIC') throw error; }
finally {
  try { await dbg('stop'); } catch (error) { receipt.stopError = error.message; }
  for (const dispose of effects.reverse()) await dispose();
  try { receipt.targetPinAfterRun = hash(fs.readFileSync(item.target)); receipt.targetUnchanged = receipt.targetPinAfterRun === item.targetSha256; }
  catch (error) { receipt.targetUnchanged = false; receipt.targetStorageAfterRun = 'unavailable'; receipt.storageError = error.code; }
  save(); console.log('RECEIPT ' + path.join(output, 'receipt.json'));
  if (!receipt.targetUnchanged && !receipt.error) throw new Error('Owned target changed or became unavailable during validation');
}
