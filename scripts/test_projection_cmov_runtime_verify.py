"""Audit saved real Java decodes and full DAG roots, without product imports."""
from pathlib import Path
import hashlib
import json
import random
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from projection_cmov_raw_oracle import check_cmov_raw
from projection_numerical_oracle import projection_values, total_byte


def main():
    source = Path(sys.argv[1])
    receipt = json.loads(source.read_text(encoding='utf8'))
    matrix = receipt['matrix']
    assert len(matrix) == 48 and len(receipt['cases']) == 9
    cases = []
    offsets = dict(zip('rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15'.split(), (0, 8, 16, 24, 32, 40, 48, 56, 128, 136, 144, 152, 160, 168, 176, 184)))
    for item in receipt['cases']:
        assert item['rootExited'] and item['rootClosed'] and item['cleanupConfirmed']
        if not item['accepted']:
            ref = item['analysisFailure']; data = Path(ref['reportPath']).read_bytes()
            assert hashlib.sha256(data).hexdigest() == ref['reportSha256']
            failed = json.loads(data)['result']; assert failed['status'] == 'failed-unverified' and failed['cleanupConfirmed']
            continue
        ref = item['result']; data = Path(ref['reportPath']).read_bytes()
        assert hashlib.sha256(data).hexdigest() == ref['reportSha256']
        core = json.loads(data)['result']
        assert not core['nativeTargetExecuted'] and not core['businessAccepted']
        if item['id'].startswith('all-48'):
            assert len(core['internalElisions']) == 48 and len(core['decodedPath']) == 96
            for spec in matrix:
                raw = next(r for r in core['decodedPath'] if r['ea'] == spec['ea'])
                assert raw['bytes'] == spec['bytes']
                audit = check_cmov_raw(raw['decoded'], spec['bits'], offsets[spec['source']], offsets[spec['destination']], spec['cc'])
                e = next(e for e in core['internalElisions'] if e['ea'] == spec['ea'])
                assert e['frameLiveIntersection'] == [] and e['statusFlagsPreserved']
                assert e['destinationBytes'] == (2 if spec['bits'] == 16 else 8)
                normalized = []
                for op in raw['decoded']['pcode']:
                    def norm(v): return None if v is None else {k: int(value, 16) if k == 'offset' else value for k, value in v.items()}
                    normalized.append({'opcode': op['opcode'], 'output': norm(op['output']), 'inputs': [norm(v) for v in op['inputs']]})
                assert e['rawPcodeSemanticSha256'] == hashlib.sha256(json.dumps(normalized, sort_keys=True, separators=(',', ':')).encode('ascii')).hexdigest()
                cases.append(audit)
        rng = random.Random(0x434d4f56)
        for i in range(64):
            initial = {g: rng.getrandbits(64) for g in offsets}
            values = projection_values(core, initial, total_byte(i))
            for name, node in core['registers'].items():
                expected = 0 if item['id'].startswith('all-48') else initial[name] & ~255
                assert values[node] == expected
            assert values[core['initialMemory']] == values[core['currentMemory']]
            assert not core['stores']
    assert len(cases) == 48 and all(r['numericStates'] == 256 for r in cases)
    report = {'schema': 'ig5-cmov-independent-java-numeric-audit-v1', 'passed': True,
              'actualDecodedCmovShapes': 48, 'ordinaryRawNumericStates': 48 * 256,
              'all16FinalGprsAndFlagsChecked': True, 'dagRootNumericScenarios': 128,
              'cases': cases, 'nativeTargetExecuted': False, 'architectureProved': False,
              'businessAccepted': False}
    output = source.parent / 'independent-audit.json'
    with output.open('x', encoding='utf8') as handle: json.dump(report, handle, indent=2)
    print(json.dumps({k: v for k, v in report.items() if k != 'cases'}))


if __name__ == '__main__': main()
