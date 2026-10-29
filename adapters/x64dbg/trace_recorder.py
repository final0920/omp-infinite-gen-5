"""Approved native single-step recording with concrete memory-read observations.

Only the adapter invokes this while it owns a paused debuggee. Triton decodes
instructions and identifies reads; it does not execute the target natively.
Native execution uses the existing owned x64dbg step/event path.
"""
import hashlib
import base64
from pathlib import Path
import sys
import time
from store_observations import capture_store_event, reserve_store_event, same_pause, make_store_events, encode

TT = None
GPRS = 'rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split()


def transition_not_observed(ea, predicted_rip, before, after, has_store, stores_unchanged=False):
    """A trap at the same PC is not evidence that a non-self instruction retired.

    Only debugger TF changes are ignored. Stores require independent before /
    after byte observations for EVERY decoded store. Actual memory, GPR or other
    flag effects remain outside this conservative classification.
    """
    return ((not has_store or stores_unchanged) and predicted_rip != ea and after['rip'] == ea
            and all(after[name] == before[name] for name in GPRS)
            and ((after['eflags'] ^ before['eflags']) & ~0x100) == 0)


def capture_image(adapter, initial, deadline):
    """Observe readable main-image pages at one owned native pause; never fill holes."""
    base, size = int(initial['mainModuleBase'], 16), initial['mainModuleSize']
    if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= 8 * 1024 * 1024:
        raise ValueError('Native image snapshot exceeds 8 MiB module budget')
    chunks, regions, holes, total = [], [], [], 0
    for offset in range(0, size, 4096):
        adapter.check()
        if time.monotonic() > deadline: raise ValueError('Native image snapshot deadline exceeded')
        count = min(4096, size - offset)
        try: data = adapter.call('read_memory', base + offset, count)
        except Exception as error:
            if getattr(error, 'code', None) in ('ECANCELLED', 'ETIMEDOUT', 'ETRANSPORT', 'EEXIT', 'EJOB'): raise
            data = b''
        if len(data) != count:
            holes.append({'rva': hex(offset), 'bytes': count})
            continue
        if regions and int(regions[-1]['rva'], 16) + regions[-1]['bytes'] == offset:
            regions[-1]['bytes'] += count
        else: regions.append({'rva': hex(offset), 'bytes': count, 'blobOffset': total})
        chunks.append(data); total += count
    current = adapter.context()
    if current.get('state') != 'suspended' or current.get('historyGap') or any(current.get(key) != initial.get(key) for key in ('runId', 'pid', 'tid', 'stopSeq', 'mainModuleBase', 'mainModuleSize')):
        raise ValueError('Native image snapshot pause identity changed')
    data = b''.join(chunks)
    if not data: raise ValueError('Native main-image snapshot contains no readable bytes')
    return base64.b64encode(data).decode('ascii'), {'schema': 'ig5.native-main-image.v1', 'runtimeBase': hex(base),
        'moduleSize': size, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'regions': regions,
        'unreadableRanges': holes, 'partial': bool(holes), 'runId': initial['runId'], 'pid': initial['pid'],
        'threadId': initial['tid'], 'stopSeq': initial['stopSeq'], 'nativeTargetExecuted': True,
        'scope': 'Debugger-observed readable main-image bytes at this native pause; holes are absent, future code changes and original-file equality are not proved'}


def record(adapter, params):
    global TT
    count = params.get('count', 100)
    if 'record_events' in params and type(params['record_events']) is not bool:
        raise ValueError('record_events must be boolean')
    record_events = params.get('record_events') is True
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 512:
        raise ValueError('Recorded trace count must be an integer in 1..512')
    if adapter.target['bits'] != 64: raise ValueError('Recorded semantics currently require x64 debuggee')
    if TT is None:
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'worker'))
        from trace_analysis import load_triton
        TT = load_triton()
    tt = TT
    initial = adapter.context()
    if initial.get('state') != 'suspended' or not initial.get('runId') or not initial.get('tid'):
        raise ValueError('Recorded trace requires an identified paused process/thread')
    base, size = int(initial['mainModuleBase'], 16), initial['mainModuleSize']
    until = int(params['until'], 0) if params.get('until') else None
    if until is not None and not base <= until < base + size: raise ValueError('Trace until must be a runtime VA inside the main module')
    started = time.monotonic()
    image_data, image_summary = capture_image(adapter, initial, started + 40) if params.get('record_image') is True else (None, None)
    lines, entries, final_regs, native_steps = ['h:ig5-native-x64-v2'], [], None, 0
    confirmed_step_stops, continuations = 0, []
    store_events, store_event_bytes = [], 0
    threads = adapter.call('get_threads')['threads']
    current = [row for row in threads if row['threadId'] == initial['tid']]
    if len(current) != 1 or not current[0].get('teb'): raise ValueError('Native thread TEB evidence is missing')
    gs_base = int(current[0]['teb'], 16)
    if not 0 < gs_base < 1 << 47: raise ValueError('Native x64 TEB is outside user address space')
    lines.append('s:gs:' + hex(gs_base))
    stopping_instruction = None
    last_confirmed = initial
    flags, reason, last_result = None, 'instruction-budget', None
    for _ in range(count):
        adapter.check()
        state = adapter.state()
        if any(state.get(key) != initial.get(key) for key in ['runId', 'pid', 'tid']) or state.get('state') != 'suspended' or state.get('historyGap'):
            reason = 'process-thread-or-history-changed'; break
        regs = adapter.call('get_regs').context.model_dump()
        if any(name not in regs for name in GPRS + ['rip', 'eflags']): raise ValueError('Incomplete native register snapshot')
        ea = regs['rip']
        if until == ea: reason = 'until-address'; break
        if not base <= ea < base + size: reason = 'left-main-module'; break
        # Read at most 15 backed bytes, with a one-byte fallback at page ends.
        code = adapter.call('read_memory', ea, min(15, base + size - ea))
        if not code: reason = 'unreadable-code'; break
        ctx = tt.TritonContext(tt.ARCH.X86_64)
        for name in GPRS + ['rip', 'eflags']: ctx.setConcreteRegisterValue(getattr(ctx.registers, name), regs[name])
        ctx.setConcreteRegisterValue(ctx.registers.gs, gs_base)
        ins = tt.Instruction(ea, code)
        ctx.disassembly(ins)
        mnemonic = ins.getDisassembly().split(' ')[0]
        stopping_instruction = {'ea': hex(ea), 'disassembly': ins.getDisassembly()}
        if any(op.getType() == tt.OPERAND.MEM and op.getSegmentRegister().getName() == 'fs' for op in ins.getOperands()):
            reason = 'unrecorded-FS-base'; break
        if mnemonic in {'syscall', 'sysenter', 'int', 'int3', 'iret', 'iretq', 'hlt'}:
            reason = 'unsupported-os-transition'; break
        memory = []
        def observe_memory(context, access):
            adapter.check()
            if len(memory) >= 8 or access.getSize() not in (1, 2, 4, 8, 16, 32, 64): raise ValueError('Instruction memory-read budget exceeded')
            try: data = adapter.call('read_memory', access.getAddress(), access.getSize())
            except Exception:
                stopping_instruction['failedMemoryRead'] = {'ea': hex(access.getAddress()), 'bytes': access.getSize()}
                raise
            if len(data) != access.getSize(): raise ValueError('Native memory read is incomplete')
            value = int.from_bytes(data, 'little')
            context.setConcreteMemoryValue(access, value)
            memory.append((access.getAddress(), access.getSize(), value))
        ctx.addCallback(tt.CALLBACK.GET_CONCRETE_MEMORY_VALUE, observe_memory)
        try:
            from trace_hardware import process_instruction
            processed, _ = process_instruction(ctx, ins, tt)
        except Exception as error:
            if getattr(error, 'code', None) in ('ECANCELLED', 'ETIMEDOUT', 'ETRANSPORT', 'EEXIT', 'EJOB'): raise
            stopping_instruction['observationError'] = str(error)[:500]
            reason = 'decode-or-observation-failed'; break
        if processed != tt.EXCEPTION.NO_FAULT:
            reason = 'unsupported-instruction'; break
        if any(reg.getName() in {'gs', 'fs', 'cs', 'ds', 'es', 'ss'} for reg, _ in ins.getWrittenRegisters()):
            reason = 'unrecorded-segment-write'; break
        # Do not invent vector, x87, segment, or other unobserved initial state.
        permitted = set(GPRS + ['rip', 'eflags', 'cf', 'pf', 'af', 'zf', 'sf', 'tf', 'if', 'df', 'of', 'ac', 'id', 'nt', 'vif', 'vip'])
        # TSC is Triton's virtual hardware-input register, not a debuggee GPR
        # whose initial value must be invented. The existing offline model
        # symbolizes RDTSC/P outputs and binds them to actual following native
        # EAX/EDX(/ECX) snapshots. No concrete decoder TSC value is a proof.
        if mnemonic in ('rdtsc', 'rdtscp'): permitted.add('tsc')
        # Long mode ignores CS/DS/ES/SS base overrides for memory addressing.
        # Reading a selector as a register, or FS/GS addressing, still needs
        # a real observation and is refused. No x86 flat-segment assumption.
        direct_segment = any(op.getType() == tt.OPERAND.REG and op.getName() in {'cs', 'ds', 'es', 'ss', 'fs', 'gs'} for op in ins.getOperands())
        if not direct_segment and ins.getLoadAccess() + ins.getStoreAccess(): permitted.update(['cs', 'ds', 'es', 'ss'])
        if not direct_segment and ins.getLoadAccess() + ins.getStoreAccess(): permitted.add('gs')
        unobserved = [reg.getName() for reg, _ in ins.getReadRegisters() if ctx.getParentRegister(reg).getName() not in permitted and reg.getName() not in permitted]
        if unobserved:
            stopping_instruction['unobservedRegisters'] = unobserved
            reason = 'unrecorded-register-bank'; break
        opcode = bytes(ins.getOpcode())[:ins.getSize()]
        reads = [(access.getAddress(), access.getSize()) for access, _ in ins.getLoadAccess()]
        if any(not any(address == a and width == w for address, width, _ in memory) for a, w in reads):
            reason = 'unobserved-memory-read'; break
        frame = ['r:' + ':'.join(hex(regs[name]) for name in GPRS), 'e:' + hex(regs['eflags'])]
        frame.extend('mr:' + hex(address) + ':' + str(width) + ':' + hex(value) for address, width, value in memory)
        frame.append('i:' + hex(ea) + ':' + str(len(opcode)) + ':' + opcode.hex())
        stores = [(access.getAddress(), access.getSize()) for access, _ in ins.getStoreAccess()]
        if len(stores) > 32 or sum(width for _, width in stores) > 256:
            reason = 'store-observation-budget'; break
        store_before = [(address, width, adapter.call('read_memory', address, width)) for address, width in stores]
        if any(len(data) != width for _, width, data in store_before):
            reason = 'unobserved-store-baseline'; break
        if record_events:
            reservation = reserve_store_event(store_before)
            # Reserve before executing. Trace final frame, sidecar root and a
            # possible CPUID continuation share the original 1 MiB budget.
            prefix_bytes = sum(len(line) + 1 for line in lines) + sum(len(line) + 1 for line in frame)
            if prefix_bytes + store_event_bytes + reservation + 4096 > 1024 * 1024:
                reason = 'recording-evidence-budget'; break
            if not same_pause(adapter.context(), state, initial):
                reason = 'store-baseline-pause-changed'; break
        mark = adapter.event_seq
        if not adapter.call('cmd_sync', 'sti'): reason = 'step-rejected'; break
        native_steps += 1
        last_result = adapter.wait_state(mark, recording=True, recording_start_stop=state['stopSeq'], recording_deadline=min(started + 40, time.monotonic() + 2))
        if not last_result.get('ok') or last_result.get('eventName') != 'step' or last_result.get('interruptedBy') or last_result.get('historyGap'):
            reason = 'step-event-deadline' if last_result.get('recordingWaitExpired') else last_result.get('eventName', 'unconfirmed-step')
            stopping_instruction['stepCompletionEvidence'] = {key: last_result.get(key) for key in ['eventName', 'observedEvents', 'state', 'stopSeq', 'stepConfirmed']}
            break
        after_state = last_result
        if any(after_state.get(key) != initial.get(key) for key in ['runId', 'pid', 'tid']):
            reason = 'process-or-thread-changed-after-step'; break
        prior_final_regs = final_regs
        final_regs = adapter.call('get_regs').context.model_dump()
        # A queued hardware/debug trap can publish STEPPED at the unchanged
        # instruction before that instruction retires. Do not record a false
        # instruction merely because two debugger callbacks arrived. A retry begins
        # from the new explicit pause; hidden execution is not inferred away.
        predicted_rip = ctx.getConcreteRegisterValue(ctx.registers.rip)
        stores_unchanged = bool(stores) and final_regs['rip'] == ea and predicted_rip != ea
        store_observations = []
        if stores_unchanged:
            for address, width, before_bytes in store_before:
                after_bytes = adapter.call('read_memory', address, width)
                store_observations.append({'ea': hex(address), 'bytes': width, 'before': before_bytes.hex(), 'after': after_bytes.hex()})
                stores_unchanged = stores_unchanged and len(after_bytes) == width and before_bytes == after_bytes
        if transition_not_observed(ea, predicted_rip, regs, final_regs, bool(stores), stores_unchanged):
            stopping_instruction['observation'] = 'unchanged GPR/RIP and non-TF flags; every decoded store unchanged or no stores; requested instruction transition was not observed'
            stopping_instruction['storeObservations'] = store_observations
            stopping_instruction['stopSeq'] = after_state['stopSeq']
            final_regs = prior_final_regs
            reason = 'instruction-transition-not-observed'; break
        last_confirmed = after_state
        confirmed_step_stops += 1
        # Concrete register outputs must agree, except architecturally undefined
        # state and hardware observations. The offline replayer does the stronger
        # input-dependency preserving validation again before publishing proofs.
        lines.extend(frame); entries.append(ea)
        store_event_incomplete = False
        if record_events:
            event = capture_store_event(adapter, initial, state, after_state, ea, store_before, len(store_events), started + 40)
            store_events.append(event); store_event_bytes += len(encode(event)) + 1
            store_event_incomplete = not event['completeDecodedStoreSet']
        if mnemonic == 'cpuid' and opcode == b'\x0f\xa2' and final_regs['rip'] != ea + 2:
            from trace_continuation import cpuid_continuation, apply_native_continuation
            endpoint = final_regs['rip'] - ea
            tail = code[2:endpoint] if 3 <= endpoint <= len(code) else b''
            description = cpuid_continuation(tail)
            valid = False
            if description:
                # The allowed tail cannot overwrite any CPUID output. Thus the
                # final hardware-output GPRs can validate its deterministic
                # effect, without claiming an observed intermediate snapshot.
                for name in ('rax', 'rbx', 'rcx', 'rdx'):
                    ctx.setConcreteRegisterValue(getattr(ctx.registers, name), final_regs[name])
                continuation = tt.Instruction(ea + 2, tail)
                processed = apply_native_continuation(ctx, continuation, tt, description, final_regs['eflags'])
                control_mask = 0xffffffff & ~((1 << 8) | (1 << 16) | 2)
                valid = processed == tt.EXCEPTION.NO_FAULT and all(ctx.getConcreteRegisterValue(getattr(ctx.registers, name)) == final_regs[name] for name in GPRS + ['rip']) and ctx.getConcreteRegisterValue(ctx.registers.eflags) & control_mask == final_regs['eflags'] & control_mask
            if not valid:
                stopping_instruction.update({'observedEndpoint': hex(final_regs['rip']), 'tailBytes': tail.hex(), 'observation': 'Unmodeled CPUID continuation; raw before/after evidence retained'})
                reason = 'unrecorded-cpuid-continuation'; break
            lines.append('c:' + hex(ea + 2) + ':' + str(len(tail)) + ':' + tail.hex()); entries.append(ea + 2)
            continuations.append({'ea': hex(ea + 2), **description, 'terminalStateVerified': True,
                'source': 'actual pre-step native code and post-step GPR/flags/RIP; no intermediate register/flags snapshot'})
        if flags is None: flags = hex(regs['eflags'])
        stopping_instruction = None
        if store_event_incomplete:
            reason = 'store-followup-unavailable'; break
        if until == final_regs['rip']:
            reason = 'until-address'; break
        # VM dispatchers also use RET internally. Stop at a return only when
        # it leaves the main image; a typed until address handles in-image callers.
        if mnemonic.startswith('ret') and not base <= final_regs['rip'] < base + size:
            reason = 'returned'; break
        if time.monotonic() - started > 40: reason = 'recording-deadline'; break
    final = adapter.context()
    has_final = bool(entries and final_regs)
    current_final = has_final and all(final.get(key) == last_confirmed.get(key) for key in ['runId', 'pid', 'tid', 'stopSeq']) and final.get('state') == 'suspended'
    if has_final:
        lines.append('f:' + ':'.join(hex(final_regs[name]) for name in GPRS + ['rip', 'eflags']))
    data = ('\n'.join(lines) + '\n') if entries else ''
    if len(data.encode('ascii')) > 1024 * 1024: raise ValueError('Recorded trace exceeded 1 MiB')
    trace_sha256 = hashlib.sha256(data.encode('ascii')).hexdigest()
    event_data = encode(make_store_events(initial, last_confirmed, trace_sha256, store_events)) if record_events and entries else None
    if event_data is not None and len(data) + len(event_data) > 1024 * 1024:
        raise ValueError('Combined trace/store-event evidence exceeded 1 MiB')
    return {'ok': bool(entries), 'op': 'trace', 'recording': True, 'nativeStepsPerformed': native_steps,
            **({'storeEventData': event_data, 'storeEventSummary': {'schema': 'ig5.native-store-events.v1',
                'sha256': hashlib.sha256(event_data.encode('ascii')).hexdigest(), 'bytes': len(event_data)}} if event_data is not None else {}),
            **({'imageData': image_data, 'imageSummary': image_summary} if image_data is not None else {}),
            'traceData': data, 'traceSummary': {'format': 'ig5.x86-recording.v2', 'instructionCount': len(entries), 'confirmedStepStops': confirmed_step_stops,
                'unobservedContinuations': continuations,
                'sha256': trace_sha256, 'bytes': len(data),
                'entry': hex(entries[0]) if entries else None, 'exit': hex(entries[-1]) if entries else None,
                'initialFlags': flags, 'runtimeBase': hex(base), 'runId': initial['runId'], 'threadId': initial['tid'],
                'startStopSeq': initial['stopSeq'], 'endStopSeq': last_confirmed.get('stopSeq'), 'stopReason': reason,
                'finalSnapshotIncluded': has_final, 'finalSnapshotCurrent': current_final,
                'stoppingInstruction': stopping_instruction,
                'segmentBaseAssumptions': {'gs': hex(gs_base)}, 'segmentBaseSource': 'Windows-x64-user-ABI-from-native-thread-TEB',
                'wholeFunctionCoverageProved': False, 'elapsedMs': round((time.monotonic() - started) * 1000)},
            'context': final, **final}
