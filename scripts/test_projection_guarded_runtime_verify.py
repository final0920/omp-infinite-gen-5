"""Independent instruction equations for saved guarded public projections.

No product, decoder or raw-pcode interpreter imports; no target execution.
"""
from pathlib import Path
import hashlib
import json
import random
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from projection_numerical_oracle import MASK, NAMES, context0_cases, expected, projection_values, total_byte


def ref(path):
    p = Path(path)
    raw = p.read_bytes()
    return {'path': str(p), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def states():
    rng = random.Random(0x6a7263787a)
    edges = [0, 1, 2, 7, 8, 255, 256, 0xffffffff, 1 << 32, (1 << 63)-1, 1 << 63, MASK-7, MASK]
    for n in range(320):
        r = {name: rng.getrandbits(64) for name in NAMES}
        r['rcx'] = 0 if n % 3 == 0 else edges[n % len(edges)]
        if n % 5 == 0:
            r['rdx'] = 0
        if n % 4 == 0:
            r['rbx'] = edges[n % len(edges)]
        if n % 6 == 0:
            r['rax'] = r['rbx']
        if n % 7 == 0:
            r['rax'] = 0
        yield 'generic-' + str(n), r, rng.getrandbits(64), {}


def equations(identity, initial, memory, base):
    """Choose actual execution exit, with ordered writes from native equations."""
    r, overlay, stores = dict(initial), {}, []
    def byte(address):
        return overlay.get(address & MASK, memory(address & MASK))
    def load(address):
        return sum(byte(address+i) << (8*i) for i in range(8))
    def store(address, value):
        address &= MASK
        stores.append((address, value, 8))
        for i in range(8):
            overlay[(address+i) & MASK] = (value >> (8*i)) & 255
    active_exit = None
    guards, targets = [], []
    if identity in ('taken-jrcxz', 'fallthrough-jrcxz'):
        continues = (initial['rcx'] == 0) == (identity == 'taken-jrcxz')
        guards = [True, continues]
        targets = [base + (2 if identity == 'taken-jrcxz' else 4)]
        if continues: r['rax'] = 0x55
        else: active_exit = 0
    elif identity == 'side-exit-live-rax':
        r['rax'] = initial['rdx']
        continues = initial['rcx'] == 0
        targets = [base+5]
        if continues: r['rax'] = 0x55
        else: active_exit = 0
    elif identity == 'prefix-suffix-stores':
        store(initial['rbx'], initial['rax'])
        continues = initial['rcx'] == 0
        guards, targets = [True, continues], [base+5]
        if continues:
            store(initial['rbx'], initial['rdx'])
            r['rcx'] = load(initial['rbx'])
        else: active_exit = 0
    elif identity in ('carry-after-jb', 'carry-after-jnz'):
        a, b = initial['rax'], initial['rbx']
        continues = a < b if identity == 'carry-after-jb' else a != b
        targets = [base+5]
        if continues: r['rax'] = (a + int(a < b)) & MASK
        else: active_exit = 0
    elif identity == 'two-intermediate-branches':
        targets = [base+2, base+10]
        if initial['rcx'] != 0: active_exit = 0
        elif initial['rdx'] != 0: active_exit = 1
        else: r['rax'] = 0x55
    elif identity == 'branch-after-store-load':
        store(initial['rbx'], initial['rax'])
        r['rcx'] = load(initial['rbx'])
        continues = r['rcx'] == 0
        guards, targets = [True, continues], [base+8]
        if continues:
            store(initial['rbx']+1, initial['rdx'])
            r['r8'] = load(initial['rbx'])
        else: active_exit = 0
    elif identity == 'terminal-conditional':
        targets = [base+2]
        if initial['rcx'] != 0: active_exit = 0
    elif identity == 'actual-minimum-dispatch':
        targets = [0x140052162]
        if initial['rbp'] > initial['r8']: r['rax'] = memory(initial['rsi'])
        else: active_exit = 0
    elif identity == 'actual-context0-dispatch':
        e = expected(initial, memory)
        r, overlay = e['registers'], dict(e['memoryWrites'])
        stores = [(s['address'], s['value'], s['size']) for s in e['stores']]
        guards, targets = [True], [0x140052162]
        if e['control']['condition']:
            r['rax'] = byte(r['rsi'])
        else: active_exit = 0
    else:
        raise AssertionError('Unknown independent fixture equations: ' + identity)
    return r, overlay, stores, guards, targets, active_exit


def main():
    result_path = Path(sys.argv[1])
    document = read(result_path)
    specification = read(document['specification']['path'])
    assert ref(document['specification']['path']) == document['specification']
    assert len(document['cases']) == len(document['processes']) == len(specification['cases']) == 18
    assert document['activeRequests'] == 0
    for flag in ('nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'):
        assert document[flag] is False
    accepted, rejected, comparisons, reports, branch_counts = [], [], {}, [], {}
    for row, process, wanted in zip(document['cases'], document['processes'], specification['cases']):
        identity = row['id']
        assert identity == wanted['id'] and row['code'] == wanted['code']
        assert ref(row['target']['path']) == row['target']
        assert row['rootExited'] and row['rootClosed'] and process['exited'] and process['closed']
        request = json.loads(process['stdin'])
        ack = next(json.loads(line) for line in process['stdout'].splitlines() if json.loads(line).get('id') == 1)
        assert ack['cleanupConfirmed'] is True and ack['nonce'] == request['params']['nonce']
        assert request['params']['projection_path'] == row['args']['projection_path']
        assert request['params'].get('projection_mode', 'strict') == wanted.get('projection_mode', 'guarded-path')
        child = read(row['childRequest']['path'])
        assert ref(row['childRequest']['path']) == row['childRequest']
        assert child.get('projection_mode', 'strict') == request['params'].get('projection_mode', 'strict')
        assert 0 < row['actualChildBudgetMs'] <= row['requestedBudgetMs'] <= 50000
        if row['rejected']:
            assert not wanted['accepted'] and wanted['error'] in row['message']
            assert ack['error']['message'] == row['message']
            rejected.append(identity)
            continue
        assert wanted['accepted']
        record_ref = ref(row['result']['reportPath'])
        assert record_ref['sha256'] == row['result']['reportSha256']
        record = read(record_ref['path'])
        report = record['result']
        assert record['input']['sha256'] == row['target']['sha256'] == report['targetSha256']
        assert report['schema'] == 'ig5-pcode-guarded-projection-v1' and report['projectionMode'] == 'guarded-path'
        assert [item['bytes'] for item in report['decodedPath']] == wanted['code']
        assert [item['ea'] for item in report['decodedPath']] == row['args']['projection_path']
        assert report['projectionRegisters'] == NAMES and set(report['registers']) == set(NAMES)
        assert len(report['sideExits']) == len(report['branchPoints']) == (2 if identity == 'two-intermediate-branches' else 1)
        assert row['result']['pathGuard'] == report['pathGuard']
        assert row['result']['sideExitCount'] == len(report['sideExits'])
        assert report['statistics']['pcodeOperations'] == sum(len(item['decoded']['pcode']) for item in report['decodedPath'])
        if identity == 'actual-context0-dispatch':
            original = read(specification['originalContextSource'])['result']['decodedPath']
            assert report['decodedPath'][:14] == original
            assert len(report['internalElisions']) == 1 and report['internalElisions'][0]['rawOperationCount'] == 10
        else:
            assert report['internalElisions'] == []
        data = list(context0_cases()) if identity == 'actual-context0-dispatch' else list(states())
        branch_counts[identity] = [0] * (len(report['sideExits']) + 1)
        for _, initial, seed, overrides in data:
            memory = total_byte(seed, overrides)
            values = projection_values(report, initial, memory)
            r, overlay, stores, guards, targets, selected_exit = equations(identity, initial, memory, int(report['projectionPath'][0], 16))
            active = [i for i, item in enumerate(report['sideExits']) if values[item['guard']] != 0]
            assert active == ([] if selected_exit is None else [selected_exit]), (identity, initial, active, selected_exit)
            assert (values[report['pathGuard']] != 0) == (selected_exit is None)
            branch_counts[identity][0 if selected_exit is None else selected_exit+1] += 1
            state = report if selected_exit is None else report['sideExits'][selected_exit]
            assert {name: values[node] for name, node in state['registers'].items()} == r, identity
            assert values[state['currentMemory']] == (memory, overlay), identity
            assert values[report['initialMemory']] == (memory, {})
            for item, target in zip(report['sideExits'], targets):
                assert values[item['target']] == target
                assert item['continuation'] == 'not-analyzed' and item['statusFlags'] == 'not-exported'
            active_stores = [s for s in report['stores'] if values[s['guard']] != 0]
            assert len(active_stores) == len(stores)
            observed_overlay = {}
            for s, (address, value, size) in zip(active_stores, stores):
                assert values[s['address']] == address and values[s['value']] == value and s['size'] == size
                assert values[s['beforeMemory']] == (memory, observed_overlay)
                for i in range(size): observed_overlay[(address+i) & MASK] = (value >> (8*i)) & 255
                assert values[s['afterMemory']] == (memory, observed_overlay)
            if guards and identity not in ('taken-jrcxz', 'fallthrough-jrcxz'):
                assert [bool(values[s['guard']]) for s in report['stores']] == guards
            if selected_exit is None:
                control = report['control']
                last = report['decodedPath'][-1]
                after = int(last['ea'], 16) + last['decoded']['size']
                if identity == 'terminal-conditional':
                    assert control['kind'] == 'conditional' and control['conditionRule'] == 'nonzero-is-taken'
                    assert bool(values[control['condition']]) == (initial['rax'] == initial['rbx'])
                    assert values[control['taken']] == after+0x10 and values[control['fallthrough']] == after
                else:
                    assert control['kind'] == 'fallthrough' and values[control['target']] == after
        assert all(branch_counts[identity]), (identity, 'Missing exit-domain numerical coverage', branch_counts[identity])
        comparisons[identity] = len(data)
        accepted.append(identity)
        reports.append(record_ref)
    assert len(accepted) == 11 and len(rejected) == 7
    print(json.dumps({'status': 'passed-independent-guarded-numerical-comparison', 'runtimeResults': ref(result_path),
        'verifier': ref(__file__), 'oracle': ref(Path(__file__).with_name('projection_numerical_oracle.py')),
        'accepted': accepted, 'rejected': rejected, 'numericCases': comparisons, 'totalNumericCases': sum(comparisons.values()),
        'branchDomainCounts': branch_counts, 'reports': reports, 'nativeTargetExecuted': False,
        'databaseModified': False, 'businessAccepted': False, 'wholeBinaryVerified': False,
        'smtProof': False, 'architectureProved': False,
        'scope': 'Finite supplied-path ordinary-memory instruction equations; no reachability, universal equivalence or protected-business proof.'}))


if __name__ == '__main__':
    main()
