"""Independent bounded interpreter/reference audit over committed model-verification reports.
No imports from the JS model, decoder or verifier. No target or caller code is executed.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

MASK = (1 << 64) - 1
PE = '71d1ceaedaebeb572c63c33485405fa7612beab047aff0c00f96044bd92223f0'
BRANCH = '6e71d6e35ce1939e6a44825918979e3188cd5c83f3d9d3afafa7d136b979224e'
BRANCH_PE = 'd9bf31e34c5e95307f88fcc7ce544101bd61e566c284a4622afc9700f29da61c'
REGS = 'rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def native_groups(raw):
    groups, registers, reads, final = [], None, [], None
    for line in raw.decode('ascii').splitlines():
        row = line.split(':')
        if row[0] == 'r':
            assert len(row) == 17
            registers = dict(zip(REGS, (int(v, 16) for v in row[1:])))
        elif row[0] == 'd':
            positions = [i for i in range(16) if int(row[1], 16) >> i & 1]
            assert registers is not None and len(positions) == len(row) - 2
            registers = dict(registers)
            for i, value in zip(positions, row[2:]):
                registers[REGS[i]] = int(value, 16)
        elif row[0] == 'e':
            flags = int(row[1], 16)
        elif row[0] == 'mr':
            reads.append((int(row[1], 16), int(row[2]), int(row[3], 16)))
        elif row[0] == 'i':
            code = bytes.fromhex(row[3])
            assert registers is not None and len(code) == int(row[2])
            groups.append({'pc': int(row[1], 16), 'code': code, 'regs': dict(registers), 'flags': flags, 'reads': reads})
            reads = []
        elif row[0] == 'f':
            assert len(row) == 19
            final = {'regs': dict(zip(REGS, (int(v, 16) for v in row[1:17]))), 'pc': int(row[17], 16), 'flags': int(row[18], 16)}
        else:
            assert row[0] in ('h', 's'), 'No coalesced or invented intermediate native state'
    assert final and not reads
    for i, group in enumerate(groups):
        group['after'] = groups[i + 1] if i + 1 < len(groups) else final
    return groups


def recorded_expectation(initial, code):
    accumulator, position, saved = initial, 0, initial
    fetches, writes, loads = [], [initial], []
    for _ in range(1024):
        assert 0 <= position < len(code)
        opcode = code[position]
        fetches.append((position, opcode, False))
        position += 1
        if opcode in (5, 6, 7, 8):
            assert position < len(code)
            operand = code[position]
            fetches.append((position, operand, opcode == 6))
            position += 1
        if opcode == 0:
            writes.append(accumulator)
            return accumulator, fetches, writes, loads
        if opcode == 1:
            accumulator = (accumulator + 7) & MASK
        elif opcode == 2:
            accumulator ^= 85
        elif opcode == 3:
            saved = accumulator
            writes.append(saved)
        elif opcode == 4:
            loads.append(saved)
            accumulator = saved
        elif opcode == 5:
            if accumulator % 2 == 0:
                position = operand
        elif opcode == 6:
            position = operand
        elif opcode == 7:
            accumulator = (accumulator + operand) & MASK
        elif opcode == 8:
            accumulator ^= operand
        else:
            raise AssertionError('Unknown opcode in recorded reference')
    raise AssertionError('Recorded reference exhausted its original 1024 step limit')


def audit_recorded(root, evidence, image, target, lo, hi):
    """Original-capture input/return/output checks only, independently parsed from raw bytes."""
    assert evidence['status'] == ('pass' if evidence['runs'] else 'not-supplied') and evidence['freshNativeExecution'] is False
    assert evidence['nativeCpuEquivalenceProved'] is False and evidence['cpuWriteFootprintProved'] is False
    debug = root.parent.parent / 'debug-traces'
    inputs, run_ids = set(), set()
    for run in evidence['runs']:
        assert target in (PE, BRANCH_PE) and run['status'] == 'pass' and not run['errors']
        groups, stores, previous, total_bytes = [], [], None, 0
        for ref in run['recordingRefs']:
            assert set(ref) == {'id', 'sha256'} and re.fullmatch(r'[a-f0-9-]{36}', ref['id'])
            raw_report = (debug / 'records' / (ref['id'] + '.json')).read_bytes()
            assert digest(raw_report) == ref['sha256']
            record = json.loads(raw_report)
            assert record['kind'] == 'debug-trace' and record['action'] == 'record' and record['id'] == ref['id']
            body = record['result']
            assert body['targetSha256'] == target and body['nativeTargetExecuted'] is True
            trace = (debug / 'blobs' / (body['sha256'] + '.bin')).read_bytes()
            sidecar = body['storeEvents']
            event_raw = (debug / 'blobs' / (sidecar['sha256'] + '.bin')).read_bytes()
            assert digest(trace) == body['sha256'] and len(trace) == body['bytes']
            assert digest(event_raw) == sidecar['sha256'] and len(event_raw) == sidecar['bytes']
            total_bytes += len(trace) + len(event_raw)
            assert total_bytes <= 16 * 1024 * 1024
            events = json.loads(event_raw)
            assert events['traceSha256'] == body['sha256'] and events['runId'] == body['runId']
            assert events['threadId'] == body['threadId'] and events['cpuWriteFootprintProved'] is False
            current = native_groups(trace)
            assert len(current) == len(events['events']) == body['confirmedStepStops']
            if previous:
                assert previous['regs'] == current[0]['regs'] and previous['pc'] == current[0]['pc']
            previous = current[-1]['after']
            base = int(body['runtimeBase'], 16)
            for i, (group, event) in enumerate(zip(current, events['events'])):
                offset = group['pc'] - base
                assert 0x1000 <= offset < 0x1400
                assert image[0x400 + offset - 0x1000:0x400 + offset - 0x1000 + len(group['code'])] == group['code']
                assert event['groupIndex'] == i and int(event['pc'], 16) == group['pc']
                assert event['beforeStopSeq'] == body['startStopSeq'] + i and event['afterStopSeq'] == body['startStopSeq'] + i + 1
                assert event['pauseIdentityMatched'] is True and event['completeDecodedStoreSet'] is True
                for store in event['stores']:
                    assert int(store['address'], 16) == base + 0x3000 and store['bytes'] == 8 and store['status'] == 'observed'
                    stores.append(store)
            groups.extend(current)
        initial = groups[0]['regs']['rcx']
        code = image[0xf00:0xf03 if target == PE else 0xf0c]
        actual_expected, predicted_fetches, predicted_stores, predicted_loads = recorded_expectation(initial, code)
        saved = (initial + 7) & MASK
        expected = saved ^ 85 if target == PE or saved % 2 else saved
        assert actual_expected == expected
        observed_fetches, observed_loads = [], []
        for index, group in enumerate(groups):
            if group['code'] == bytes.fromhex('410fb612'):
                address = group['regs']['r10']
                candidate = next((value for at, size, value in group['reads'] if at == address and size == 1), None)
                assert candidate is not None and group['after']['regs']['rdx'] == candidate
                prediction = predicted_fetches[len(observed_fetches)]
                assert (address - base - 0x3100, candidate) == prediction[:2]
                update = groups[index + 1]
                assert update['code'] == bytes.fromhex('4d8d1413' if prediction[2] else '49ffc2')
                assert update['after']['regs']['r10'] == (base + 0x3100 + candidate if prediction[2] else address + 1)
                observed_fetches.append(prediction)
            if group['code'] == bytes.fromhex('498b01'):
                value = next((v for a, size, v in group['reads'] if a == base + 0x3000 and size == 8), None)
                assert value is not None and group['after']['regs']['rax'] == value
                observed_loads.append(value)
        assert observed_fetches == predicted_fetches and observed_loads == predicted_loads
        assert groups[0]['pc'] == base + 0x1000 and groups[-1]['code'] == b'\xc3' and body['stopReason'] == 'returned'
        assert groups[-1]['regs']['rsp'] == groups[0]['regs']['rsp']
        assert groups[-1]['after']['regs']['rsp'] == groups[0]['regs']['rsp'] + 8
        assert any(a == groups[-1]['regs']['rsp'] and size == 8 and value == groups[-1]['after']['pc'] for a, size, value in groups[-1]['reads'])
        assert groups[-1]['after']['regs']['rax'] == expected and run['returnValue'] == hex(expected)
        assert len(stores) == len(predicted_stores)
        assert [store['afterHex'] for store in stores] == [v.to_bytes(8, 'little').hex() for v in predicted_stores]
        for before, after in zip(stores, stores[1:]):
            assert after['beforeHex'] == before['afterHex']
        assert stores[-1]['afterHex'] == expected.to_bytes(8, 'little').hex() == run['outputMemoryHex']
        assert run['input'] == hex(initial) and run['inDomain'] == (lo <= initial <= hi)
        assert run['codeStableBetweenObservations'] is False
        inputs.add(initial)
        run_ids.add(body['runId'])
    assert evidence['independence']['distinctRuns'] == len(run_ids)
    assert evidence['independence']['distinctInputs'] == len(inputs)
    assert evidence['independence']['inDomainDistinctInputs'] == len([i for i in inputs if lo <= i <= hi])
    return len(evidence['runs'])


def audit(filename):
    filename = Path(filename).resolve()
    root = filename.parent
    total = 0

    def read(ref, kind, action):
        nonlocal total
        assert set(ref) == {'id', 'sha256'} and re.fullmatch(r'[a-f0-9-]{36}', ref['id'])
        file = root / (ref['id'] + '.json')
        assert not file.is_symlink() and file.is_file()
        raw = file.read_bytes()
        total += len(raw)
        assert total <= 8 * 1024 * 1024 and digest(raw) == ref['sha256']
        record = json.loads(raw)
        assert record['schemaVersion'] == 1 and record['id'] == ref['id']
        assert (record['kind'], record['action']) == (kind, action)
        return record['result']

    raw = filename.read_bytes()
    report = json.loads(raw)
    assert report['kind'] == 'vm-function-assessment' and report['action'] == 'assess'
    metadata = json.loads((root.parent / 'metadata' / filename.name).read_bytes())
    assert metadata['recordSha256'] == digest(raw)
    result = report['result']
    assert result['schema'] == 'ig5-finite-function-verification-v1'
    assert result['property'] == 'fixed-owned-model-return-and-output-memory-equivalence'
    program = read(result['programRef'], 'vm-executable-program', 'derive')
    declaration = read(result['contractRef'], 'vm-function-contract', 'declare')
    contract = declaration['contract']
    assert declaration['authority'] == 'caller-declared-scope' and declaration['businessAccepted'] is False
    image = bytes.fromhex(program['sourceImageHex'])
    target = digest(image)
    assert target in (PE, BRANCH, BRANCH_PE) and target == result['targetSha256'] == contract['targetSha256']
    native = target in (PE, BRANCH_PE)
    code = image[0xf00:0xf03 if target == PE else 0xf0c] if native else image
    assert program['model'] == {'codeHex': code.hex(), 'decoder': 'plain', 'initialKey': 0}
    assert contract['entryRva'] == ('0x1000' if native else '0x0')
    assert contract['normalReturn'] == ('native-ret' if native else 'bytecode-halt')
    assert contract['outputs'] == {'returnRegister': 'rax', 'memory': [{'rva': '0x3000', 'bytes': 8}]}
    assert result['scope'] == {'kind': 'virtual-model', 'inputBits': contract['input']['bits'], 'minimum': contract['input']['minimum'],
                               'maximum': contract['input']['maximum'], 'sourceKind': program['sourceKind']}
    lo, hi = (int(contract['input'][k], 16) for k in ('minimum', 'maximum'))
    assert 0 <= lo <= hi < (1 << contract['input']['bits'])
    size = hi - lo + 1
    assert size <= 4096, 'independent exhaustive audit supports only finite domains <=4096'
    transcript = hashlib.sha256()
    edges = set()
    for initial in range(lo, hi + 1):
        acc, position, memory = initial, 0, initial.to_bytes(8, 'little')
        path = []
        for _ in range(1024):
            assert 0 <= position < len(code)
            start = position
            operation = code[position]
            position += 1
            path.append(start)
            if operation in (5, 6, 7, 8):
                assert position < len(code)
                operand = code[position]
                position += 1
            if operation == 0:
                memory = acc.to_bytes(8, 'little')
                break
            if operation == 1:
                acc = (acc + 7) & MASK
            elif operation == 2:
                acc ^= 85
            elif operation == 3:
                memory = acc.to_bytes(8, 'little')
            elif operation == 4:
                acc = int.from_bytes(memory, 'little')
            elif operation == 5:
                if acc % 2 == 0:
                    position = operand
            elif operation == 6:
                position = operand
            elif operation == 7:
                acc = (acc + operand) & MASK
            elif operation == 8:
                acc ^= operand
            else:
                raise AssertionError('unsupported opcode')
        else:
            raise AssertionError('step limit; no invented return')
        expected = (initial + 7) & MASK
        if target == PE or expected % 2:
            expected ^= 85
        actual_row = {'returnValue': hex(acc), 'memoryHex': memory.hex(), 'normalReturn': True}
        reference_row = {'returnValue': hex(expected), 'memoryHex': expected.to_bytes(8, 'little').hex(), 'normalReturn': True}
        assert actual_row == reference_row
        transcript.update(encoded([str(initial), actual_row, reference_row]) + b'\n')
        for i, pc in enumerate(path):
            edges.add(f'{pc}:0->{str(path[i+1])+":0" if i+1 < len(path) else "return"}')
    assert result['status'] == 'pass' and result['finiteTesting']['cases'] == size
    assert result['finiteTesting']['plannedCases'] == size and result['finiteTesting']['transcriptSha256'] == transcript.hexdigest()
    assert result['exhaustiveFiniteDomain'] is True and result['modelContractAccepted'] is True
    assert result['coverage']['observedModelEdges'] == sorted(edges)
    for key in ('universalProof', 'nativeCpuEquivalenceProved', 'nativeInputCoverageProved', 'nativeTargetExecuted', 'businessAccepted', 'wholeVmRecovered', 'wholeBinaryVerified', 'changesExecutionAuthority'):
        assert result[key] is False, key
    recorded = audit_recorded(root, result['recordedFunctionEvidence'], image, target, lo, hi)
    return {'status': 'pass', 'targetSha256': target, 'cases': size, 'modelEdges': len(edges), 'bytes': total,
            'oldRecordedRuns': recorded, 'scope': 'independent finite model and optional original-capture return/output-memory audit; no native CPU completeness proof', 'nativeTargetExecuted': False}


if __name__ == '__main__':
    print(json.dumps(audit(sys.argv[1]), ensure_ascii=False))
