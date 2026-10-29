"""Independent saved-public-result BSWAP checks; never execute PE or raw p-code.

Expected values use byte reversal of the explicit canonical operand width,
unchanged other GPRs, and the ordered MOV stores in the fixture specification.
Undefined/noncanonical inputs have no value oracle. Baseline acceptance of them
is recorded as a gap, never accepted as architectural evidence.
"""
import hashlib
import json
from pathlib import Path
import random
import re
import struct
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from projection_numerical_oracle import MASK, NAMES, projection_values, total_byte


def reference(path):
    path = Path(path)
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def read_json(path):
    raw = Path(path).read_bytes()
    assert len(raw) <= 8 * 1024 * 1024
    return json.loads(raw)


def instruction_bytes(path, preferred, count):
    raw = Path(path).read_bytes()
    pe = struct.unpack_from('<I', raw, 0x3c)[0]
    assert raw[:2] == b'MZ' and raw[pe:pe+4] == b'PE\0\0'
    count_sections = struct.unpack_from('<H', raw, pe+6)[0]
    optional_size = struct.unpack_from('<H', raw, pe+20)[0]
    optional = pe+24
    assert struct.unpack_from('<H', raw, optional)[0] == 0x20b
    base = struct.unpack_from('<Q', raw, optional+24)[0]
    rva = int(preferred, 16) - base
    assert 0 <= rva < (1 << 32) and 0 < count_sections <= 96
    for index in range(count_sections):
        at = optional+optional_size+40*index
        start, size, offset = struct.unpack_from('<III', raw, at+12)
        if start <= rva and rva+count <= start+size:
            at = offset+rva-start
            assert at+count <= len(raw)
            return raw[at:at+count].hex()
    raise AssertionError('Unbacked preferred instruction')


def numeric_states():
    rng = random.Random(0x4253574150)
    edges = [0, 1, 0xff, 0x100, 0xffff, 0x10000, 0x7fffffff,
             0x80000000, 0xffffffff, 0x100000000, 1 << 63, MASK]
    for index in range(len(edges)):
        yield {name: edges[(index + n) % len(edges)] for n, name in enumerate(NAMES)}
    for bit in range(64):
        yield {name: 1 << ((bit+n) % 64) for n, name in enumerate(NAMES)}
    for _ in range(256):
        yield {name: rng.getrandbits(64) for name in NAMES}
    for address in (0, 1, MASK-7, MASK):
        row = {name: rng.getrandbits(64) for name in NAMES}
        row['rbx'] = address
        yield row


def main():
    document = read_json(sys.argv[1])
    specification = read_json(document['specification']['path'])
    assert reference(document['specification']['path']) == document['specification']
    assert reference(document['runner']['path']) == document['runner']
    assert document['mode'] in ('baseline', 'enforce')
    assert len(document['cases']) == len(specification['cases']) == len(document['processes']) == 25
    assert len({x['id'] for x in specification['cases']}) == 25
    assert sum(x['accepted'] for x in specification['cases']) == 9
    assert document['activeRequests'] == 0
    for flag in ('nativeTargetExecuted', 'databaseModified', 'businessAccepted', 'wholeBinaryVerified'):
        assert document[flag] is False
    accepted, rejected, gaps, reports = [], [], [], []
    checks = 0
    states = list(numeric_states())
    assert len(states) == 336
    for ordinal, (case, wanted, process) in enumerate(zip(document['cases'], specification['cases'], document['processes'])):
        assert case['id'] == wanted['id']
        assert case['code'] == wanted['code']
        assert case['expectedAccepted'] is wanted['accepted']
        assert case['args']['projection_registers'] == wanted['registers']
        assert case['target'] == wanted.get('target', document['target'])
        assert reference(case['target']['path']) == case['target']
        assert case['args']['target'] == case['target']['path']
        addresses = wanted.get('addresses')
        if addresses is None:
            address = 0x140001000 + ordinal*0x20
            addresses = []
            for code in wanted['code']:
                addresses.append(hex(address))
                address += len(bytes.fromhex(code))
        assert case['args']['projection_path'] == addresses
        for address, code in zip(addresses, wanted['code']):
            assert instruction_bytes(case['target']['path'], address, len(code)//2) == code
        assert all(case[k] is True for k in ('cleanupConfirmed', 'nonceMatched', 'rootExited', 'rootClosed'))
        assert process['exited'] is True and process['closed'] is True
        assert process['windowsHide'] is True and process['pid'] == case['rootPid']
        requests = [json.loads(line) for line in process['stdin'].splitlines() if line]
        finals = [json.loads(line) for line in process['stdout'].splitlines() if line]
        assert len(requests) == 1
        request = requests[0]
        assert request['id'] == 1 and request['method'] == 'project'
        finals = [f for f in finals if f.get('id') == 1]
        assert len(finals) == 1
        ack = finals[0]
        assert ack['nonce'] == request['params']['nonce'] and ack['cleanupConfirmed'] is True
        assert re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', ack['nonce'])
        assert request['params']['projection_path'] == addresses
        assert request['params']['projection_registers'] == wanted['registers']
        assert request['params']['sha256'] == case['target']['sha256']
        assert 0 < case['actualChildBudgetMs'] <= case['requestedBudgetMs'] <= 50000
        child = read_json(case['childRequest']['path'])
        assert reference(case['childRequest']['path']) == case['childRequest']
        assert child['sha256'] == case['target']['sha256']
        assert child['projection_path'] == addresses and child['projection_registers'] == wanted['registers']
        assert reference(child['target'])['sha256'] == case['target']['sha256']
        if case['rejected']:
            assert ack['error']['message'] == case['message'] and 'result' not in ack
            if document['mode'] == 'enforce':
                assert not wanted['accepted']
                pattern = r'Architecturally undefined 16-bit BSWAP' if wanted['reason'] == 'undefined' else r'Unsupported BSWAP encoding or metadata|Projection instruction decode failed'
                assert re.search(pattern, case['message']), case['message']
            rejected.append(case['id'])
            continue
        assert 'error' not in ack and 'result' in ack
        result = case['result']
        assert result['targetSha256'] == case['target']['sha256']
        assert result['status'] == 'partial' and result['recoveryStatus'] == 'unverified'
        assert all(result[k] is False for k in ('nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'))
        proc = result['process']
        assert proc['childExitConfirmed'] is True and proc['exitCode'] == 0
        assert proc['jobAssignedAtCreation'] is True and proc['memoryLimitBytes'] == 2*1024**3
        assert proc['activeProcessLimit'] == 1
        report_ref = reference(result['reportPath'])
        assert report_ref['bytes'] <= 4*1024*1024 and report_ref['sha256'] == result['reportSha256']
        record = read_json(result['reportPath'])
        report = record['result']
        assert record['input']['sha256'] == report['targetSha256'] == case['target']['sha256']
        assert report['projectionPath'] == addresses and report['projectionRegisters'] == wanted['registers']
        assert [x['ea'] for x in report['decodedPath']] == addresses
        assert [x['bytes'] for x in report['decodedPath']] == wanted['code']
        if not wanted['accepted']:
            assert document['mode'] == 'baseline'
            gaps.append({'case': case['id'], 'reason': wanted['reason'], 'report': report_ref,
                         'numericOracleApplied': False, 'architecturalAcceptance': False})
            continue
        assert report['internalElisions'] == []
        assert set(report['registers']) == set(NAMES)
        assert len(report['stores']) == len(wanted['stores'])
        raw_store_positions = [(i, j) for i, item in enumerate(report['decodedPath'])
                               for j, op in enumerate(item['decoded']['pcode']) if op['opcode'] == 'STORE']
        assert [(item['instructionIndex'], item['pcodeIndex']) for item in report['stores']] == raw_store_positions
        width, destination = wanted['operandBits'], wanted['destination']
        assert width in (32, 64)
        for number, initial in enumerate(states):
            memory = total_byte(0x425357415000 + number)
            values = projection_values(report, initial, memory)
            swapped = int.from_bytes((initial[destination] & ((1 << width)-1)).to_bytes(width//8, 'little'), 'big')
            expected = {**initial, destination: swapped}
            assert {name: values[node] for name, node in report['registers'].items()} == expected
            overlay = {}
            for actual, store in zip(report['stores'], wanted['stores']):
                address = (initial['rbx'] + store['offset']) & MASK
                value = expected[store['value']] if isinstance(store['value'], str) else store['value']
                assert values[actual['address']] == address and values[actual['value']] == value
                assert actual['size'] == store['bytes']
                for n in range(store['bytes']):
                    overlay[(address+n) & MASK] = (value >> (8*n)) & 255
            assert values[report['initialMemory']] == (memory, {})
            assert values[report['currentMemory']] == (memory, overlay)
            control = report['control']
            assert control['kind'] == 'fallthrough'
            assert values[control['target']] == int(addresses[-1], 16) + len(bytes.fromhex(wanted['code'][-1]))
            checks += 1
        accepted.append(case['id'])
        reports.append({'case': case['id'], 'report': report_ref, 'numericCases': len(states)})
    if document['mode'] == 'enforce':
        assert (len(accepted), len(rejected), len(gaps)) == (9, 16, 0)
    else:
        assert len(accepted) == 9
        assert {'actual-66-bswap-live-rax', 'actual-handler57-all-gprs'} <= {x['case'] for x in gaps}
    assert checks == 9*336
    print(json.dumps({'schema': 1, 'status': 'passed' if document['mode'] == 'enforce' else 'baseline-gap-recorded',
        'runtimeResults': reference(sys.argv[1]), 'verifier': reference(__file__),
        'numericalEvaluator': reference(Path(__file__).with_name('projection_numerical_oracle.py')),
        'acceptedDefinedCases': accepted, 'rejectedCases': rejected, 'acceptedUndefinedOrNoncanonicalGaps': gaps,
        'numericChecks': checks, 'reports': reports,
        'method': 'Independent byte reversal and ordered store formulas with total-memory DAG evaluation; no PE/raw-pcode execution or CPU-equivalence proof.',
        'nativeTargetExecuted': False, 'databaseModified': False, 'architectureProved': False,
        'businessAccepted': False, 'wholeBinaryVerified': False}))


if __name__ == '__main__':
    main()

