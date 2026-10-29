"""Independent numerical register-CMOV raw-CFG audit; no product imports.

Enumerates all five consumed Boolean status flags and both AF values, checking
all sixteen GPRs and flag preservation. This is not a CPU/fault certificate.
"""
import itertools
import random


def check_cmov_raw(instruction, bits, source_offset, destination_offset, condition):
    raw = instruction['pcode']
    mask = (1 << bits) - 1
    offsets = (0, 8, 16, 24, 32, 40, 48, 56, 128, 136, 144, 152, 160, 168, 176, 184)
    flag_offsets = (0x200, 0x202, 0x204, 0x206, 0x207, 0x20b)
    rng = random.Random(0x434d4f56 + bits + condition)
    cases, maximum = 0, 0
    for flags in itertools.product((0, 1), repeat=6):
        cf, pf, af, zf, sf, of = flags
        tests = (of, not of, cf, not cf, zf, not zf, cf or zf,
                 not (cf or zf), sf, not sf, pf, not pf, sf != of,
                 sf == of, zf or sf != of, not zf and sf == of)
        for seed in range(4):
            regs, unique = {}, {}
            def write(v, value):
                data = regs if v['space'] == 'register' else unique
                base = int(v['offset'], 16)
                for i in range(v['size']):
                    data[base + i] = (value >> (8 * i)) & 255
            def read(v):
                if v['space'] in ('const', 'ram'):
                    return int(v['offset'], 16)
                data = regs if v['space'] == 'register' else unique
                base = int(v['offset'], 16)
                assert all(base + i in data for i in range(v['size']))
                return sum(data[base + i] << (8 * i) for i in range(v['size']))
            v = lambda base, size=8: {'space': 'register', 'offset': hex(base), 'size': size}
            initial = {o: rng.getrandbits(64) for o in offsets}
            # Include nonzero upper32 even when low32/self-source is zero.
            initial[destination_offset] = (0xd3c2b1a0 << 32) | (0 if seed == 0 else rng.getrandbits(32))
            if source_offset != destination_offset:
                initial[source_offset] = (0x98765432 << 32) | (0 if seed == 1 else rng.getrandbits(32))
            for o, value in initial.items(): write(v(o), value)
            for o, value in zip(flag_offsets, flags): write(v(o, 1), value)
            original = dict(regs)
            pc, steps = 0, 0
            while pc < len(raw):
                steps += 1
                assert steps <= len(raw)
                op = raw[pc]
                values = [read(x) for x in op['inputs']]
                kind = op['opcode']
                if kind == 'CBRANCH':
                    assert op['output'] is None and len(values) == 2
                    assert op['inputs'][0]['space'] == 'ram'
                    assert values[0] == int(instruction['ea'], 16) + instruction['size']
                    if values[1]: break
                else:
                    if kind in ('COPY', 'INT_ZEXT'): value = values[0]
                    elif kind == 'BOOL_NEGATE': value = int(not values[0])
                    elif kind == 'BOOL_OR': value = int(bool(values[0] or values[1]))
                    elif kind == 'BOOL_AND': value = int(bool(values[0] and values[1]))
                    elif kind == 'INT_EQUAL': value = int(values[0] == values[1])
                    elif kind == 'INT_NOTEQUAL': value = int(values[0] != values[1])
                    else: raise AssertionError('Unexpected raw CMOV operation ' + kind)
                    write(op['output'], value)
                pc += 1
            expected = initial.copy()
            if tests[condition]:
                expected[destination_offset] = ((initial[destination_offset] & ~mask) | (initial[source_offset] & mask)) if bits == 16 else initial[source_offset] & mask
            elif bits == 32:
                expected[destination_offset] &= 0xffffffff
            for o, value in expected.items(): assert read(v(o)) == value
            assert all(regs[o] == original[o] for o in flag_offsets)
            maximum = max(maximum, steps)
            cases += 1
    return {'operandBits': bits, 'conditionCode': condition, 'numericStates': cases,
            'allSixBooleanFlagCombinationsEnumerated': True,
            'all16FinalGprsChecked': True, 'flagsPreserved': True,
            'maximumPcodeStepsObserved': maximum, 'architectureProved': False}
