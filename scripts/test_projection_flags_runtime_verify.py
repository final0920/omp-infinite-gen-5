"""Independent numerical checks for real decoded flag fixtures; no target execution."""
import hashlib
import json
from pathlib import Path
import random
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pcode_projection import evaluate

MASK = (1 << 64) - 1
NAMES = 'rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15'.split()


def main():
    document = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
    rng = random.Random(0xF1A6)
    edges = [0, 1, 2, 0xff, 0x100, 0xffff, 0x7fffffff, 0x80000000,
             0xffffffff, (1 << 63) - 1, 1 << 63, MASK]
    inputs = [{name: edges[(index + ordinal) % len(edges)] for ordinal, name in enumerate(NAMES)}
              for index in range(len(edges))]
    inputs += [{name: rng.getrandbits(64) for name in NAMES} for _ in range(128)]
    checks, gaps, successful, counterexamples = 0, [], [], []
    for case in document['cases']:
        assert case['cleanupConfirmed'] is True
        if case['architecturalGap']:
            gaps.append({'id': case['id'], 'rejected': case['rejected'], 'reason': case['architecturalReason']})
            if document['mode'] == 'enforce':
                assert case['rejected']
            elif not case['rejected'] and case['id'] in ('add-af-unmodeled', 'cmp-af-unmodeled', 'shr-imm-one-of-unmodeled'):
                raw = Path(case['result']['reportPath']).read_bytes()
                assert hashlib.sha256(raw).hexdigest() == case['result']['reportSha256']
                report = json.loads(raw)['result']
                registers = {name: 0 for name in NAMES}
                registers['rax'] = (1 << 63) if case['id'] == 'shr-imm-one-of-unmodeled' else 0x1000
                outputs, values = evaluate(report, registers, {})
                if case['id'] == 'shr-imm-one-of-unmodeled':
                    observed, expected = values[report['control']['condition']], 1
                    quantity = 'OF consumed by JO after SHR immediate one'
                else:
                    observed, expected = (outputs['rax'] >> 12) & 1, 0
                    quantity = 'AF consumed by LAHF after zero low-nibble add/subtract'
                assert observed != expected, 'Baseline no longer reproduces the specified decoder gap'
                counterexamples.append({'case': case['id'], 'initialRegisters': {name: hex(value) for name, value in registers.items()},
                                        'quantity': quantity, 'projected': observed, 'architecturalExpected': expected})
            # Architecturally undefined values have no deterministic numeric oracle.
            continue
        assert not case['rejected'], case['id'] + ': ' + case.get('message', '')
        raw = Path(case['result']['reportPath']).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == case['result']['reportSha256']
        report = json.loads(raw)['result']
        for registers in inputs:
            outputs, values = evaluate(report, registers, {})
            identity, rax, rbx = case['id'], registers['rax'], registers['rbx']
            guard = None
            if identity == 'shr-implicit-one-of':
                expected = {'rax': rax >> 1}; guard = rax >> 63
            elif identity == 'shl-implicit-one-of':
                shifted = (rax << 1) & MASK
                expected = {'rax': shifted}; guard = (rax >> 63) ^ (shifted >> 63)
            elif identity in ('shl-zero-preserves-zf', 'rol-byte-thirtytwo-preserves-zf'):
                expected = {'rax': rax}; guard = 1
            elif identity == 'rol-cl-preserves-zf':
                count = registers['rcx'] & 63
                expected = {'rax': ((rax << count) | (rax >> ((64 - count) % 64))) & MASK}; guard = 1
            elif identity in ('mul-unobserved-flags', 'mul-then-redefined-flags'):
                product = rax * rbx
                expected = {'rax': product & MASK, 'rdx': product >> 64}
                if identity == 'mul-then-redefined-flags': guard = int(registers['rcx'] > (product >> 64))
            elif identity == 'sahf-restores-af-after-add':
                added = (rax + rbx) & MASK
                expected = {'rax': (added & ~0xff00) | ((((added >> 8) & 0xd5) | 2) << 8)}
            else:
                raise AssertionError('Unknown numeric fixture: ' + identity)
            assert outputs == expected, (identity, registers, outputs, expected)
            if guard is not None:
                assert values[report['control']['condition']] == guard, (identity, registers)
            assert report['stores'] == []
            checks += 1
        successful.append(case['id'])
    print(json.dumps({'status': 'baseline-recorded' if document['mode'] == 'baseline' else 'passed',
                      'verifierSha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      'nativeTargetExecuted': False, 'numericCases': successful, 'numericChecks': checks,
                      'architecturalGaps': gaps, 'numericalDecoderCounterexamples': counterexamples,
                      'independentSmtProof': False}))


if __name__ == '__main__':
    main()
