"""Check saved public BSF fixtures against independent post-instruction formulas.

No product imports, decoder, raw-pcode execution, PE execution or solver. The
serialized DAG evaluator is test code; expected values come from the explicit
MOV/load/branch suffix. Undefined or live BSF outputs have no numeric oracle.
"""
import hashlib
import json
from pathlib import Path
import random
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from projection_numerical_oracle import MASK, NAMES, projection_values, total_byte
from projection_bitscan_raw_oracle import check_bsf_raw

OFFSETS = [0, 8, 16, 24, 32, 40, 48, 56, 128, 136, 144, 152, 160, 168, 176, 184]
FLAGS = [0x200, 0x202, 0x204, 0x206, 0x207, 0x20b]


def read_ref(path, maximum=8 * 1024 * 1024):
    path = Path(path)
    raw = path.read_bytes()
    assert len(raw) <= maximum
    return json.loads(raw), {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def normalized_pcode(raw):
    def var(value):
        return None if value is None else {'space': value['space'], 'offset': int(value['offset'], 16), 'size': value['size']}
    return [{'opcode': op['opcode'], 'output': var(op.get('output')), 'inputs': [var(v) for v in op['inputs']]} for op in raw]


def verify_elision(report, case):
    assert len(report['internalElisions']) == 1
    evidence = report['internalElisions'][0]
    instruction = report['decodedPath'][0]
    width = case['operandBits']
    source, destination = (184, 136) if case['id'] == 'dead-all-gprs-load' else (0 if 'self' in case['id'] else 24, 0)
    destination_bytes = 2 if width == 16 else 8
    frame = sorted(set(range(destination, destination + destination_bytes)) | set(FLAGS))
    if case['id'] == 'dead-low16-preserve-upper':
        live = list(range(2, 8))
    elif case['id'] == 'dead-all-gprs-load':
        live = sorted(offset + i for offset in OFFSETS if offset != 136 for i in range(8))
    elif case['id'] == 'guarded-dead-before-side-exit':
        live = list(range(8, 24))
    else:
        live = []
    raw = instruction['decoded']['pcode']
    normalized = normalized_pcode(raw)
    assert len(raw) == (12 if width == 32 else 11)
    assert instruction['decoded']['mnemonic'] == 'BSF'
    assert normalized[1]['inputs'][0] == {'space': 'register', 'offset': source, 'size': width // 8}
    assert normalized[10]['output'] == {'space': 'register', 'offset': destination, 'size': width // 8}
    assert [(i, op['opcode']) for i, op in enumerate(raw) if op['opcode'] in ('BRANCH', 'CBRANCH')] == [(3, 'CBRANCH'), (7, 'CBRANCH'), (9, 'BRANCH')]
    if width == 32:
        assert normalized[11] == {'opcode': 'INT_ZEXT', 'output': {'space': 'register', 'offset': destination, 'size': 8},
                                  'inputs': [{'space': 'register', 'offset': destination, 'size': 4}]}
    expected = {
        'kind': 'register-bsf-bounded-dead-frame-v1', 'operandBits': width,
        'sourceOffset': source, 'destinationOffset': destination, 'destinationBytes': destination_bytes,
        'frameRegisterBytes': [hex(value) for value in frame], 'rawOperationCount': len(raw),
        'internalEdges': [[3, 10], [7, 10], [9, 4]], 'maximumBackedges': width - 1,
        'maximumPcodeSteps': {16: 99, 32: 196, 64: 387}[width],
        'zeroInputRawDestination': 0, 'zeroInputArchitecturalDestination': 'undefined',
        'allInputTermination': 'finite-shape-argument-not-SMT', 'modeledMemoryEffects': 0, 'architectureProved': False,
        'instructionIndex': 0, 'ea': case['args']['projection_path'][0], 'size': len(bytes.fromhex(case['code'][0])),
        'codeBytes': case['code'][0], 'rawPcodeSemanticSha256': hashlib.sha256(json.dumps(
            normalized, sort_keys=True, separators=(',', ':')).encode('ascii')).hexdigest(),
        'exitLiveByteCount': len(live), 'exitLiveRegisterBytes': [hex(value) for value in live],
        'frameLiveIntersection': [], 'omittedRawPcodeOperations': len(raw), 'omittedPurePcodeOperations': len(raw) - 3,
        'omittedInternalControlOperations': 3, 'reason': 'entire-bounded-pure-effect-frame-dead',
    }
    assert evidence == expected, (case['id'], evidence, expected)
    assert not set(frame) & set(live)
    assert report['flagPolicies'][0] == {'status': 'classified', 'family': 'bsf-complete-bounded-shape',
        'defined': ['zf'], 'preserved': [], 'undefined': ['af', 'cf', 'of', 'pf', 'sf'], 'unmodeled': [],
        'encodedWidth': width, 'maskedCount': None, 'codeBytes': case['code'][0]}
    all_raw = [op for item in report['decodedPath'] for op in item['decoded']['pcode']]
    stats = report['statistics']
    assert stats['pcodeOperations'] == len(all_raw)
    assert stats['internalElidedRawOperations'] == len(raw)
    assert stats['omittedInternalControlOperations'] == 3
    pure = sum(op['opcode'] not in ('BRANCH', 'CBRANCH', 'BRANCHIND', 'RETURN', 'CALL', 'CALLIND') for op in all_raw)
    assert stats['selectedOperations'] + stats['omittedPureOperations'] == pure
    return evidence


def main():
    document, result_ref = read_ref(sys.argv[1])
    specification, spec_ref = read_ref(document['specification']['path'])
    assert spec_ref == document['specification']
    cases = document['cases']
    assert len(cases) == len(specification['cases']) == 22
    assert document['activeRequests'] == 0
    assert len(document['processes']) == 22
    assert all(row['exited'] and row['closed'] for row in document['processes'])
    assert all(document[flag] is False for flag in ('nativeTargetExecuted', 'databaseModified', 'businessAccepted', 'wholeBinaryVerified'))
    rng = random.Random(0x425352)
    edges = [0, 1, 2, 0xff, 0x100, 0xffff, 0x10000, 0x7fffffff, 0x80000000,
             0xffffffff, 0x100000000, (1 << 63) - 1, 1 << 63, MASK]
    inputs = [{name: edges[(index + ordinal) % len(edges)] for ordinal, name in enumerate(NAMES)} for index in range(len(edges))]
    inputs += [{name: rng.getrandbits(64) for name in NAMES} for _ in range(256)]
    inputs += [{**inputs[0], 'rcx': 0, 'rdx': 0}, {**inputs[0], 'rcx': 1, 'rdx': 0}]
    accepted, rejected, checks, evidence_rows = [], [], 0, []
    raw_bounds = {}
    for case, wanted, process in zip(cases, specification['cases'], document['processes']):
        assert case['id'] == wanted['id'] and case['code'] == wanted['code']
        assert case['args']['projection_registers'] == wanted['registers']
        assert case['expectedAccepted'] is wanted['accepted']
        assert case['cleanupConfirmed'] and case['nonceMatched'] and case['rootExited'] and case['rootClosed']
        request = json.loads(process['stdin'])
        ack = next(json.loads(line) for line in process['stdout'].splitlines() if json.loads(line).get('id') == 1)
        assert ack['nonce'] == request['params']['nonce'] and ack['cleanupConfirmed'] is True
        assert case['rootPid'] == process['pid']
        if case['rejected']:
            assert 'result' not in ack and ack['error']['message'] == case['message']
            assert document['mode'] == 'baseline' or not wanted['accepted']
            rejected.append(case['id'])
            continue
        assert document['mode'] == 'enforce' and wanted['accepted']
        record, record_ref = read_ref(case['result']['reportPath'], 4 * 1024 * 1024)
        assert record_ref['sha256'] == case['result']['reportSha256']
        report = record['result']
        assert record['input']['sha256'] == report['targetSha256'] == document['target']['sha256']
        assert report['projectionPath'] == case['args']['projection_path']
        assert report['projectionRegisters'] == wanted['registers']
        assert [row['bytes'] for row in report['decodedPath']] == case['code']
        assert [row['ea'] for row in report['decodedPath']] == report['projectionPath']
        evidence = verify_elision(report, case)
        if case['operandBits'] not in raw_bounds:
            raw_bounds[case['operandBits']] = check_bsf_raw(report['decodedPath'][0]['decoded'],
                case['operandBits'], evidence['sourceOffset'], evidence['destinationOffset'])
        assert set(report['registers']) == set(wanted['registers'])
        assert report['stores'] == []
        for number, initial in enumerate(inputs):
            memory = total_byte(0x4253520000 + number)
            values = projection_values(report, initial, memory)
            outputs = {name: values[index] for name, index in report['registers'].items()}
            if wanted['expected'] == 'rax-constant-0x55':
                expected = {'rax': 0x55}
            elif wanted['expected'] == 'rax-upper48-preserved-low16-0x55':
                expected = {'rax': (initial['rax'] & (MASK ^ 0xffff)) | 0x55}
            elif wanted['expected'] == 'rax-0x55-at-side-exit-0xaa-at-final':
                expected = {'rax': 0xaa}
                assert report['schema'] == 'ig5-pcode-guarded-projection-v1'
                assert len(report['sideExits']) == len(report['branchPoints']) == 1
                point, exit_ = report['branchPoints'][0], report['sideExits'][0]
                assert values[point['condition']] == int(initial['rcx'] != initial['rdx'])
                assert values[exit_['guard']] == int(initial['rcx'] != initial['rdx'])
                assert values[report['pathGuard']] == int(initial['rcx'] == initial['rdx'])
                assert values[exit_['registers']['rax']] == 0x55
            elif wanted['expected'] == 'r9-load64-rdx-others-preserved-always-taken':
                loaded = sum(memory((initial['rdx'] + i) & MASK) << (8 * i) for i in range(8))
                expected = {**initial, 'r9': loaded}
            else:
                raise AssertionError('Unknown expected fixture result')
            assert outputs == expected, (case['id'], initial, outputs, expected)
            # No finite-memory default is substituted: both nodes retain the
            # identical total initial-memory function and an empty write overlay.
            assert values[report['initialMemory']] == (memory, {})
            assert values[report['currentMemory']] == (memory, {})
            last = int(report['projectionPath'][-1], 16)
            after = last + len(bytes.fromhex(case['code'][-1]))
            control = report['control']
            if case['id'] == 'dead-all-gprs-load':
                assert control['kind'] == 'conditional' and control['conditionRule'] == 'nonzero-is-taken'
                assert values[control['condition']] == 1
                assert values[control['taken']] == after + 0x10 and values[control['fallthrough']] == after
            else:
                assert control['kind'] == 'fallthrough' and values[control['target']] == after
            checks += 1
        accepted.append(case['id'])
        evidence_rows.append({'case': case['id'], 'report': record_ref, 'numericCases': len(inputs), 'elision': evidence})
    assert (len(accepted), len(rejected)) == ((0, 22) if document['mode'] == 'baseline' else (9, 13))
    print(json.dumps({'schema': 1, 'status': 'baseline-recorded' if document['mode'] == 'baseline' else 'passed',
        'runtimeResults': result_ref, 'verifierSha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'numericalEvaluatorSha256': hashlib.sha256(Path(__file__).with_name('projection_numerical_oracle.py').read_bytes()).hexdigest(),
        'rawOracleSha256': hashlib.sha256(Path(__file__).with_name('projection_bitscan_raw_oracle.py').read_bytes()).hexdigest(),
        'acceptedCases': accepted, 'rejectedCases': rejected, 'numericChecks': checks, 'reports': evidence_rows,
        'rawInternalControlNumericalChecks': list(raw_bounds.values()),
        'method': 'Independent suffix equations and total-memory numerical DAG evaluation; no raw-interpreter or CPU-equivalence claim.',
        'nativeTargetExecuted': False, 'databaseModified': False, 'smtProof': False, 'architectureProved': False,
        'businessAccepted': False, 'wholeBinaryVerified': False}))


if __name__ == '__main__':
    main()
