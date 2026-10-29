"""Numerical, non-SMT check of real public-route projections, never executes PE."""
import hashlib
import json
from pathlib import Path
import random
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pcode_projection import evaluate
from projection_numerical_oracle import compare_projection, context0_cases, total_byte

MASK = (1 << 64) - 1
NAMES = 'rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15'.split()


def digest(path):
    raw = Path(path).read_bytes()
    assert len(raw) <= 4 * 1024 * 1024
    return hashlib.sha256(raw).hexdigest(), raw


def main():
    source = Path(sys.argv[1])
    source_hash, raw = digest(source)
    document = json.loads(raw)
    edges = [0, 1, 0xff, 0x100, 0xffff, 0x10000, 0x7fffffff, 0x80000000,
             0xffffffff, 0x100000000, (1 << 63) - 1, 1 << 63, MASK]
    rng = random.Random(0x50434f4445)
    inputs = [{name: edges[(i + n) % len(edges)] for n, name in enumerate(NAMES)} for i in range(len(edges))]
    inputs += [{name: rng.getrandbits(64) for name in NAMES} for _ in range(256)]
    checks, records, scenarios = 0, [], {}
    for case in document['cases']:
        if case['rejected']:
            assert case['cleanupConfirmed'] is True
            continue
        report_hash, report_raw = digest(case['result']['reportPath'])
        assert report_hash == case['result']['reportSha256']
        report = json.loads(report_raw)['result']
        identity = case['id']
        local_checks = 0
        if identity == 'context0-fixed-state':
            assert document['context0Mode'] == 'dead-frame'
            context_hash, context_raw = digest(document['contextSource']['path'])
            assert context_hash == document['contextSource']['sha256']
            context = json.loads(context_raw)
            assert report['targetSha256'] == context['target']['sha256']
            original = next(item for item in context['handlers'] if item['byteIndex'] == 0)['rows']
            assert len(original) == len(report['decodedPath']) == 14
            for saved, actual in zip(original, report['decodedPath']):
                assert actual['bytes'] == saved['observed']['bytes']
                assert int(actual['ea'], 16) == 0x140000000 + int(saved['observed']['rva'], 16)
            # Preserve the original complete BSR raw CFG; no summarized input
            # substitutes for the instruction that the elision describes.
            assert report['decodedPath'][1]['decoded']['pcode'] == original[1]['decoded']['instructions'][0]['pcode']
            assert len(report['decodedPath'][1]['decoded']['pcode']) == 10
            assert len(report['internalElisions']) == 1
            evidence = report['internalElisions'][0]
            assert evidence['instructionIndex'] == 1 and evidence['ea'] == '0x140052284'
            assert evidence['codeBytes'] == '66450fbdcf' and evidence['operandBits'] == 16
            assert evidence['sourceOffset'] == 184 and evidence['destinationOffset'] == 136
            assert evidence['frameRegisterBytes'] == [hex(x) for x in (136,137,512,514,516,518,519,523)]
            assert evidence['frameLiveIntersection'] == [] and evidence['exitLiveByteCount'] == 112
            assert not set(evidence['frameRegisterBytes']) & set(evidence['exitLiveRegisterBytes'])
            assert evidence['maximumPcodeSteps'] == 83 and evidence['maximumBackedges'] == 15
            assert evidence['architectureProved'] is False
            taken = 0
            for _, registers, seed, overrides in context0_cases():
                expected = compare_projection(report, registers, total_byte(seed, overrides))
                taken += expected['control']['condition']
                local_checks += 1
            assert local_checks == 1004 and taken == 336
            checks += local_checks
            records.append({'id': identity, 'path': case['result']['reportPath'], 'sha256': report_hash})
            scenarios[identity] = local_checks
            continue
        for initial in inputs:
            memory = {i: (i * 17 + 9) & 0xff for i in range(16)}
            if identity == 'context137-fixed-state':
                selector = initial['rdx'] & 0xff
                for i in range(8):
                    memory[(initial['rsp'] + selector + i) & MASK] = (initial['rbx'] >> (i * 8)) & 0xff
                memory[initial['rsi']] = selector
            scenarios_for_input = [initial]
            if identity == 'ordered-symbolic-alias':
                # Equal, partial, non-alias and uint64-wrap cases are deliberate.
                scenarios_for_input = [{**initial, 'rax': base, 'rcx': (base + delta) & MASK}
                                       for base in (0, 0x1000, MASK) for delta in (0, 1, 2, MASK)]
            for registers in scenarios_for_input:
                outputs, values = evaluate(report, registers, memory)
                if identity == 'eax-zero-extends':
                    assert outputs == {'rax': registers['rcx'] & 0xffffffff}
                elif identity == 'ah-al-partial-preservation':
                    expected = (registers['rax'] & (MASK ^ 0xffff)) | ((registers['rdx'] & 0xff) << 8) | (registers['rcx'] & 0xff)
                    assert outputs == {'rax': expected}
                elif identity == 'ordered-symbolic-alias':
                    expected_memory = dict(memory)
                    expected_memory[registers['rax']] = registers['rbx'] & 0xff
                    expected_memory[(registers['rax'] + 1) & MASK] = (registers['rbx'] >> 8) & 0xff
                    expected_memory[registers['rcx']] = registers['rdx'] & 0xff
                    expected = expected_memory[registers['rax']] | (expected_memory[(registers['rax'] + 1) & MASK] << 8)
                    assert outputs == {'r8': expected}
                    assert values[report['currentMemory']] == expected_memory
                    assert len(report['stores']) == 2
                elif identity == 'conditional-two-successors':
                    assert outputs == {'rax': registers['rax'], 'rbx': registers['rbx']}
                    assert values[report['control']['condition']] == int(registers['rax'] > registers['rbx'])
                    assert values[report['control']['taken']] == 0x140001075
                    assert values[report['control']['fallthrough']] == 0x140001065
                elif identity == 'push-ret-store-retained':
                    assert outputs == {'rax': registers['rax'], 'rsp': registers['rsp']}
                    assert report['control']['kind'] == 'return'
                    assert values[report['control']['target']] == registers['rax']
                    expected_memory = dict(memory)
                    for i in range(8):
                        expected_memory[(registers['rsp'] - 8 + i) & MASK] = (registers['rax'] >> (i * 8)) & 0xff
                    assert values[report['currentMemory']] == expected_memory
                    assert len(report['stores']) == 1
                elif identity == 'explicit-direct-jump':
                    assert outputs == {'rax': registers['rax']}
                    assert report['control']['kind'] == 'fallthrough'
                    assert values[report['control']['target']] == 0x1400010c1
                elif identity == 'context137-fixed-state':
                    selector = memory.get(registers['rsi'], 0)
                    loaded = sum(memory.get((registers['rsp'] + selector + i) & MASK, 0) << (i * 8) for i in range(8))
                    expected = {**registers, 'rdx': selector, 'rbx': loaded,
                                'rsi': (registers['rsi'] + 1) & MASK,
                                'rbp': (registers['rbp'] - 8) & MASK,
                                'r8': (registers['rsp'] + 0x180) & MASK}
                    assert outputs == expected
                    expected_memory = dict(memory)
                    for i in range(8):
                        expected_memory[(expected['rbp'] + i) & MASK] = (loaded >> (i * 8)) & 0xff
                    assert values[report['currentMemory']] == expected_memory
                    assert values[report['control']['condition']] == int(expected['rbp'] > expected['r8'])
                    assert values[report['control']['taken']] == 0x140052124
                    assert values[report['control']['fallthrough']] == 0x140052162
                else:
                    raise AssertionError(identity)
                checks += 1
                local_checks += 1
        records.append({'id': identity, 'path': case['result']['reportPath'], 'sha256': report_hash})
        scenarios[identity] = local_checks
    assert len(records) == ((8 if document.get('context0Mode') == 'dead-frame' else 7) if document['contextSource'] else 6)
    assert len(document['cases']) == (13 if document['contextSource'] else 11)
    assert all(row['exited'] for row in document['processes'])
    assert document['activeRequests'] == 0
    print(json.dumps({'status': 'passed', 'method': 'boundary and deterministic-random numerical reference checks; no SMT proof',
                      'runtimeResultsSha256': source_hash, 'records': records, 'scenarios': scenarios,
                      'totalScenarios': checks, 'nativeTargetExecuted': False,
                      'businessAccepted': False, 'wholeBinaryVerified': False}, indent=2))


if __name__ == '__main__':
    main()
