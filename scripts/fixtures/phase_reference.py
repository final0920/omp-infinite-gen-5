"""Fixed finite instruction reference; data simulation only, never executes machine code.

Independent of the JS observation implementation. Source labels describe this
fixture's layout, not inferred VM roles. The native-recording metadata bit is a
format fixture requirement and does not assert native execution by this script.
"""
import hashlib
import json
import sys
from pathlib import Path

GPRS = 'rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split()
CASES = [('clc', 0xf8, 'observed'), ('stc', 0xf9, 'observed'),
         ('unchanged', 0x90, 'observed'), ('missing-after', 0xf8, 'missing'),
         ('duplicate-enumeration', 0xf8, 'duplicate')]


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()


def reference(patch, mode):
    # MOV imm64, absolute MOV store, indirect JMP, NOP and CLC/STC only.
    program = {0x1000: bytes.fromhex('48b80011000000000000'),
               0x100a: bytes.fromhex('4889042500300000'), 0x1012: bytes.fromhex('ffe0'),
               0x1100: b'\x90', 0x1101: bytes.fromhex('48bb0012000000000000'),
               0x110b: bytes.fromhex('ffe3'),
               0x1200: bytes.fromhex('c6042500110000') + bytes([patch]),
               0x1208: bytes.fromhex('48b80011000000000000'), 0x1212: bytes.fromhex('ffe0')}
    image = bytearray(b'\xcc' * 0x214)
    for pc, code in program.items():
        image[pc-0x1000:pc-0x1000+len(code)] = code
    original = bytes(image)
    memory = {0x1000 + i: value for i, value in enumerate(image)}
    memory.update({0x3000 + i: 0 for i in range(8)})
    regs = {name: 0 for name in GPRS}
    pc, flags = 0x1000, 0x203
    rows = ['h:ig5-native-x64-v2']
    oracle, events = [], []
    run_id = digest(original + mode.encode())[:32]
    for index in range(19):
        code = bytes(memory[pc+i] for i in range(len(program[pc])))
        rows += ['r:' + ':'.join(hex(regs[n]) for n in GPRS), 'e:' + hex(flags),
                 f'i:{hex(pc)}:{len(code)}:{code.hex()}']
        before_pc, before_regs, before_flags = pc, dict(regs), flags
        stores = []
        if code[:2] in [b'\x48\xb8', b'\x48\xbb']:
            regs['rax' if code[1] == 0xb8 else 'rbx'] = int.from_bytes(code[2:], 'little')
            pc += 10
        elif code == bytes.fromhex('4889042500300000'):
            address, data = 0x3000, regs['rax'].to_bytes(8, 'little')
            old = bytes(memory[address+i] for i in range(8))
            memory.update({address+i: b for i, b in enumerate(data)})
            stores.append(dict(address=hex(address), bytes=8, beforeHex=old.hex(), afterHex=data.hex(), changed=old != data, status='observed'))
            pc += 8
        elif code[:7] == bytes.fromhex('c6042500110000'):
            address, old, data = 0x1100, memory[0x1100], code[7]
            memory[address] = data
            stores.append(dict(address=hex(address), bytes=1, beforeHex=f'{old:02x}', afterHex=f'{data:02x}', changed=old != data, status='observed'))
            pc += 8
        elif code in [b'\xff\xe0', b'\xff\xe3']:
            pc = regs['rax' if code[1] == 0xe0 else 'rbx']
        elif code in [b'\x90', b'\xf8', b'\xf9']:
            if code == b'\xf8': flags &= ~1
            if code == b'\xf9': flags |= 1
            pc += 1
        else:
            raise AssertionError('Outside fixed reference ISA')
        oracle.append(dict(group=index, pc=hex(before_pc), code=code.hex(), beforeGprs={n: hex(v) for n, v in before_regs.items()},
                           beforeFlags=hex(before_flags), afterPc=hex(pc), afterGprs={n: hex(v) for n, v in regs.items()},
                           afterFlags=hex(flags), stores=json.loads(json.dumps(stores)),
                           fixtureRegion='initialization-prefix' if index < 3 else 'code-update' if before_pc >= 0x1200 else 'repeated-control'))
        if mode == 'missing':
            for store in stores:
                store.update(afterHex=None, changed=None, status='unavailable')
        if mode == 'duplicate':
            stores += json.loads(json.dumps(stores))
        events.append(dict(groupIndex=index, pc=hex(before_pc), beforeStopSeq=index+1, afterStopSeq=index+2,
                           pauseIdentityMatched=True, completeDecodedStoreSet=all(s['status'] == 'observed' for s in stores),
                           actualWriteCausalityProved=False, stores=stores))
    rows += ['f:' + ':'.join(hex(regs[n]) for n in GPRS) + ':' + hex(pc) + ':' + hex(flags), '']
    trace = '\n'.join(rows).encode('ascii')
    summary = dict(format='ig5.x86-recording.v2', targetSha256=digest(original), nativeTargetExecuted=True,
                   finalSnapshotIncluded=True, finalSnapshotCurrent=True, runId=run_id, threadId=7,
                   startStopSeq=1, endStopSeq=20, instructionCount=19, confirmedStepStops=19, runtimeBase='0x1000',
                   entry='0x1000', exit=oracle[-1]['pc'], initialFlags='0x203', stopReason='instruction-budget', bytes=len(trace), sha256=digest(trace))
    sidecar = dict(schema='ig5.native-store-events.v1', runId=run_id, threadId=7, runtimeBase='0x1000', startStopSeq=1,
                   endStopSeq=20, traceSha256=digest(trace), scope='decoded-store-locations-observed-across-native-stop',
                   cpuWriteFootprintProved=False, storeOrder='decoder-enumeration-not-intermediate-write-order', events=events)
    return original, trace, encode(sidecar), summary, oracle


def generate(root):
    root.mkdir(parents=True, exist_ok=False)
    cases = []
    for name, patch, mode in CASES:
        directory = root / name
        directory.mkdir()
        image, trace, sidecar, summary, oracle = reference(patch, mode)
        frozen = {}
        for filename, raw in [('program.bin', image), ('trace.bin', trace), ('stores.json', sidecar),
                              ('summary.json', encode(summary)), ('oracle.json', encode(oracle))]:
            (directory / filename).write_bytes(raw)
            frozen[filename] = digest(raw)
        cases.append(dict(name=name, patch=patch, mode=mode, files=frozen))
    manifest = dict(schema='ig5-phase-reference-fixtures-v1', cases=cases, referenceSha256=digest(Path(__file__).read_bytes()),
                    nativeTargetExecuted=False, machineCodeExecuted=False, syntheticRecordingMetadata=True,
                    scope='Finite offline reference only; region labels are fixture layout, not VM role proof')
    (root / 'reference-fixtures.json').write_bytes(encode(manifest))
    print(json.dumps(dict(ok=True, cases=len(cases), output=str(root), nativeTargetExecuted=False)))


if __name__ == '__main__':
    generate(Path(sys.argv[1]).resolve())
