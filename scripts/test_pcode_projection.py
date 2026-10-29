"""Pure-pcode semantic/regression tests; no native decoder or sample executes."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import random
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'worker'))
from pcode_projection import GPRS, ProjectionError, project


def reg(name, size=8, delta=0):
    return {'space': 'register', 'offset': hex(GPRS[name] + delta), 'size': size}


def tmp(offset=0, size=8):
    return {'space': 'unique', 'offset': hex(offset), 'size': size}


def const(number, size=8):
    return {'space': 'const', 'offset': hex(number), 'size': size}


def op(kind, output, *inputs):
    return {'opcode': kind, 'output': output, 'inputs': list(inputs)}


RAM = {'kind': 'address-space', 'space': 'ram', 'spaceId': 3}


def target(address):
    return {'space': 'ram', 'offset': hex(address), 'size': 8}


def ins(*operations, ea=0x1000, size=1, mnemonic='TEST', code=None):
    result = {'ea': hex(ea), 'size': len(code) // 2 if code else size,
              'mnemonic': mnemonic, 'operands': '', 'pcode': list(operations)}
    if code is not None:
        result['codeBytes'] = code
    return result


def flag(name):
    offsets = {'cf': 0x200, 'pf': 0x202, 'af': 0x204, 'zf': 0x206, 'sf': 0x207, 'of': 0x20b}
    return {'space': 'register', 'offset': hex(offsets[name]), 'size': 1}


def append_path(*instructions):
    """Assign contiguous addresses to synthetic byte-bound p-code fixtures."""
    address = 0x1000
    for instruction in instructions:
        instruction['ea'] = hex(address)
        address += instruction['size']
    return list(instructions)


def evaluate(report, registers, memory=None):
    """Independent concrete interpretation of serialized DAG node semantics."""
    values = []
    byte_seed = dict(memory or {})

    def signed(value, bits):
        return value - (1 << bits) if value & (1 << (bits - 1)) else value

    for node in report['dag']['nodes']:
        args = [values[index] for index in node['args']]
        widths = [report['dag']['nodes'][index].get('bits') for index in node['args']]
        kind, bits = node['op'], node.get('bits')
        if kind == 'input':
            value = registers.get(node['name'], 0)
        elif kind == 'const':
            value = int(node['value'], 16)
        elif kind == 'initial_memory':
            value = byte_seed.copy()
        elif kind == 'store_le':
            value = args[0].copy()
            for i in range(node['size']):
                value[(args[1] + i) & ((1 << 64) - 1)] = (args[2] >> (i * 8)) & 255
        elif kind == 'load_le':
            value = sum(args[0].get((args[1] + i) & ((1 << 64) - 1), 0) << (i * 8)
                        for i in range(node['size']))
        elif kind == 'extract':
            value = args[0] >> node['offset']
        elif kind == 'concat':
            value = 0
            for item, width in zip(args, widths):
                value = (value << width) | item
        elif kind == 'INT_ADD':
            value = args[0] + args[1]
        elif kind == 'INT_SUB':
            value = args[0] - args[1]
        elif kind == 'INT_MULT':
            value = args[0] * args[1]
        elif kind == 'INT_REM':
            assert args[1] != 0
            value = args[0] % args[1]
        elif kind == 'INT_AND':
            value = args[0] & args[1]
        elif kind == 'INT_OR':
            value = args[0] | args[1]
        elif kind == 'INT_XOR':
            value = args[0] ^ args[1]
        elif kind == 'INT_NEGATE':
            value = ~args[0]
        elif kind == 'INT_2COMP':
            value = -args[0]
        elif kind == 'INT_ZEXT':
            value = args[0]
        elif kind == 'INT_SEXT':
            value = signed(args[0], widths[0])
        elif kind in ('INT_LEFT', 'INT_RIGHT', 'INT_SRIGHT'):
            if args[1] >= widths[0]:
                value = -1 if kind == 'INT_SRIGHT' and signed(args[0], widths[0]) < 0 else 0
            elif kind == 'INT_LEFT':
                value = args[0] << args[1]
            elif kind == 'INT_RIGHT':
                value = args[0] >> args[1]
            else:
                value = signed(args[0], widths[0]) >> args[1]
        elif kind in ('POPCOUNT', 'LZCOUNT'):
            value = args[0].bit_count() if kind == 'POPCOUNT' else widths[0] - args[0].bit_length()
        elif kind in ('INT_EQUAL', 'INT_NOTEQUAL', 'INT_LESS', 'INT_LESSEQUAL', 'INT_SLESS', 'INT_SLESSEQUAL'):
            a, b = args
            if kind in ('INT_SLESS', 'INT_SLESSEQUAL'):
                a, b = signed(a, widths[0]), signed(b, widths[1])
            value = int((a == b) if kind == 'INT_EQUAL' else (a != b) if kind == 'INT_NOTEQUAL'
                        else (a <= b) if kind.endswith('LESSEQUAL') else (a < b))
        elif kind in ('INT_CARRY', 'INT_SCARRY', 'INT_SBORROW'):
            if kind == 'INT_CARRY':
                value = int(args[0] + args[1] >= (1 << widths[0]))
            else:
                a, b = signed(args[0], widths[0]), signed(args[1], widths[1])
                result = a - b if kind == 'INT_SBORROW' else a + b
                value = int(not -(1 << (widths[0] - 1)) <= result < (1 << (widths[0] - 1)))
        elif kind.startswith('BOOL_'):
            a = args[0] != 0
            b = len(args) > 1 and args[1] != 0
            value = int(not a if kind == 'BOOL_NEGATE' else a and b if kind == 'BOOL_AND'
                        else a or b if kind == 'BOOL_OR' else a != b)
        else:
            raise AssertionError('Evaluator missing ' + kind)
        values.append(value & ((1 << bits) - 1) if bits is not None else value)
    return {name: values[index] for name, index in report['registers'].items()}, values


def bounded_bsr(bits=16, destination='r9', source='r15', unique_base=0x1000):
    """Canonical test fixture derived from the fixed SLEIGH BSR constructors."""
    width = bits // 8
    names = list(GPRS)
    dst, src = names.index(destination), names.index(source)
    rex = 0x40 | (8 if bits == 64 else 0) | (4 if dst >= 8 else 0) | (1 if src >= 8 else 0)
    code = ([0x66] if bits == 16 else []) + ([rex] if rex != 0x40 else []) + [0x0f, 0xbd, 0xc0 | ((dst & 7) << 3) | (src & 7)]
    counter, zero, shifted, nonzero = (tmp(unique_base + n * 0x100, size)
                                     for n, size in enumerate((width, 1, width, 1)))
    operations = [op('COPY', counter, const(bits - 1, width)),
                  op('INT_EQUAL', flag('zf'), reg(source, width), const(0, width)),
                  op('INT_EQUAL', zero, flag('zf'), const(1, 1)),
                  op('CBRANCH', None, const(6, 4), zero),
                  op('INT_RIGHT', shifted, reg(source, width), counter),
                  op('INT_NOTEQUAL', nonzero, shifted, const(0, width)),
                  op('CBRANCH', None, const(3, 4), nonzero),
                  op('INT_SUB', counter, counter, const(1, width)),
                  op('BRANCH', None, const(0xfffffffc, 4)),
                  op('COPY', reg(destination, width), counter)]
    if bits == 32:
        operations.append(op('INT_ZEXT', reg(destination), reg(destination, 4)))
    return ins(*operations, mnemonic='BSR', code=bytes(code).hex())


class ProjectionTests(unittest.TestCase):
    def test_partial_register_writes_and_explicit_zero_extension(self):
        path = [ins(op('COPY', reg('rax', 1, 1), const(0xaa, 1)),
                    op('COPY', reg('rcx', 4), const(0x12345678, 4)),
                    op('COPY', reg('rdx', 4), const(0x87654321, 4)),
                    op('INT_ZEXT', reg('rdx'), reg('rdx', 4)))]
        report = project(path, ['rax', 'rcx', 'rdx'])
        output, _ = evaluate(report, {'rax': 0x1122334455667788, 'rcx': 0xaabbccdd00000000,
                                      'rdx': 0xffffffffffffffff})
        self.assertEqual(output, {'rax': 0x112233445566aa88, 'rcx': 0xaabbccdd12345678, 'rdx': 0x87654321})
        self.assertEqual(json.loads(json.dumps(report)), report)

    def test_overlapping_writes_preserve_symbolic_byte_identity(self):
        report = project([ins(op('COPY', reg('rax', 2), reg('rbx', 2)),
                              op('COPY', reg('rax', 1, 1), reg('rdx', 1)))], ['rax'])
        rng = random.Random(72)
        for _ in range(128):
            a, b, d = (rng.getrandbits(64) for _ in range(3))
            output, _ = evaluate(report, {'rax': a, 'rbx': b, 'rdx': d})
            self.assertEqual(output['rax'], (a & ~65535) | (b & 255) | ((d & 255) << 8))

    def test_symbolic_aliasing_and_store_order(self):
        report = project([ins(op('STORE', None, RAM, reg('rax'), reg('rbx', 2)),
                              op('STORE', None, RAM, reg('rcx'), reg('rdx', 1)),
                              op('LOAD', reg('r8', 2), RAM, reg('rax')),
                              op('INT_ZEXT', reg('r8'), reg('r8', 2)))], ['r8'])
        self.assertEqual(len(report['stores']), 2)
        self.assertEqual(report['stores'][1]['beforeMemory'], report['stores'][0]['afterMemory'])
        for other, expected in ((0x100, 0xabef), (0x101, 0xefcd), (0x102, 0xabcd)):
            output, _ = evaluate(report, {'rax': 0x100, 'rbx': 0xabcd, 'rcx': other, 'rdx': 0xef})
            self.assertEqual(output['r8'], expected)

    def test_total_memory_and_wrapping_address(self):
        report = project([ins(op('STORE', None, RAM, reg('rax'), reg('rbx', 2)),
                              op('LOAD', reg('rdx', 1), RAM, const(0)),
                              op('INT_ZEXT', reg('rdx'), reg('rdx', 1)))], ['rdx'])
        output, values = evaluate(report, {'rax': (1 << 64) - 1, 'rbx': 0x4321})
        self.assertEqual(output['rdx'], 0x43)
        self.assertEqual(values[report['currentMemory']][(1 << 64) - 1], 0x21)

    def test_repeated_loads_share_one_coherent_initial_memory(self):
        report = project([ins(op('LOAD', reg('rax'), RAM, reg('rsi')),
                              op('LOAD', reg('rbx'), RAM, reg('rdi')))], ['rax', 'rbx'])
        output, _ = evaluate(report, {'rsi': 123, 'rdi': 123}, {123: 0x55, 124: 0xaa})
        self.assertEqual(output, {'rax': 0xaa55, 'rbx': 0xaa55})
        self.assertEqual(sum(n['op'] == 'initial_memory' for n in report['dag']['nodes']), 1)

    def test_conditional_retains_both_successors_and_condition(self):
        report = project([ins(op('INT_LESS', tmp(0, 1), reg('rax'), reg('rbx')),
                              op('CBRANCH', None, target(0x5000), tmp(0, 1)), size=5)], ['rax'])
        self.assertEqual(report['control']['kind'], 'conditional')
        for a, b, expected in ((1, 2, 1), (2, 1, 0), ((1 << 64) - 1, 0, 0)):
            _, values = evaluate(report, {'rax': a, 'rbx': b})
            self.assertEqual(values[report['control']['condition']], expected)
            self.assertEqual(values[report['control']['taken']], 0x5000)
            self.assertEqual(values[report['control']['fallthrough']], 0x1005)

    def test_push_ret_keeps_store_and_balanced_stack(self):
        report = project([
            ins(op('INT_SUB', reg('rsp'), reg('rsp'), const(8)),
                op('STORE', None, RAM, reg('rsp'), reg('rax'))),
            ins(op('LOAD', tmp(), RAM, reg('rsp')),
                op('INT_ADD', reg('rsp'), reg('rsp'), const(8)),
                op('RETURN', None, tmp()), ea=0x1001)], ['rsp'])
        self.assertEqual(report['control']['kind'], 'return')
        self.assertEqual(len(report['stores']), 1)
        output, values = evaluate(report, {'rsp': 0x2000, 'rax': 0x777})
        self.assertEqual(output['rsp'], 0x2000)
        self.assertEqual(values[report['control']['target']], 0x777)
        self.assertEqual(values[report['currentMemory']][0x1ff8], 0x77)

    def test_native_ret_rip_shape_and_strict_rip_scope(self):
        rip = {'space': 'register', 'offset': '0x288', 'size': 8}
        report = project([ins(op('LOAD', rip, RAM, reg('rsp')),
                              op('INT_ADD', reg('rsp'), reg('rsp'), const(8)),
                              op('RETURN', None, rip))], ['rsp'])
        output, values = evaluate(report, {'rsp': 0x100}, {0x100: 0x34, 0x101: 0x12})
        self.assertEqual(output['rsp'], 0x108)
        self.assertEqual(values[report['control']['target']], 0x1234)
        self.assertNotIn('rip', report['initialRegisters'])
        rejected = [
            [ins(op('RETURN', None, rip))],
            [ins(op('COPY', rip, const(1)))],
            [ins(op('COPY', rip, const(1))), ins(op('RETURN', None, rip), ea=0x1001)],
            [ins(op('COPY', rip, const(1)), op('BRANCHIND', None, rip))],
        ]
        for path in rejected:
            with self.subTest(path=path), self.assertRaises(ProjectionError):
                project(path, ['rax'])

    def test_direct_branch_can_link_explicit_noncontiguous_path(self):
        report = project([ins(op('BRANCH', None, target(0x8000))), ins(ea=0x8000)], ['rax'])
        _, values = evaluate(report, {})
        self.assertEqual(report['control']['kind'], 'fallthrough')
        self.assertEqual(values[report['control']['target']], 0x8001)

    def test_missing_path_and_intermediate_dynamic_control_rejected(self):
        paths = [
            [ins(), ins(ea=0x1002)],
            [ins(op('BRANCH', None, target(0x8000))), ins(ea=0x1001)],
            [ins(op('CBRANCH', None, target(0x2000), const(1, 1))), ins(ea=0x1001)],
            [ins(op('RETURN', None, reg('rax'))), ins(ea=0x1001)],
            [ins(op('BRANCH', None, target(0x2000)), op('COPY', reg('rax'), const(1)))],
        ]
        for path in paths:
            with self.subTest(path=path), self.assertRaises(ProjectionError):
                project(path, ['rax'])

    def test_unknown_side_effect_rejected_even_when_output_is_dead(self):
        for kind in ('CALLOTHER', 'CALL', 'CALLIND', 'SYSCALL', 'FLOAT_ADD', 'UNKNOWN', 'INT_DIV'):
            with self.subTest(kind=kind), self.assertRaises(ProjectionError):
                project([ins(op(kind, tmp(), const(0)))], ['rax'])
        for offset in (0x280, 0x100, 0x220):
            with self.subTest(offset=offset), self.assertRaises(ProjectionError):
                project([ins(op('COPY', {'space': 'register', 'offset': hex(offset), 'size': 8}, const(0)))], ['rax'])

    def test_internal_branch_rejected_even_when_bsr_outputs_dead(self):
        for kind in ('BRANCH', 'CBRANCH'):
            operands = [const(2)] + ([const(1, 1)] if kind == 'CBRANCH' else [])
            with self.subTest(kind=kind), self.assertRaisesRegex(ProjectionError, 'Internal'):
                project([ins(op(kind, None, *operands))], ['rax'])

    def test_undefined_unique_and_initial_live_flags_rejected(self):
        paths = [[ins(op('COPY', reg('rax'), tmp()))],
                 [ins(op('COPY', tmp(), const(4))), ins(op('COPY', reg('rax'), tmp()), ea=0x1001)],
                 [ins(op('CBRANCH', None, target(0x2000),
                         {'space': 'register', 'offset': '0x200', 'size': 1}))]]
        for path in paths:
            with self.subTest(path=path), self.assertRaises(ProjectionError):
                project(path, ['rax'])

    def test_defined_flags_and_dead_pure_flags(self):
        flag = {'space': 'register', 'offset': '0x200', 'size': 1}
        report = project([ins(op('INT_CARRY', flag, reg('rax'), reg('rbx')),
                              op('INT_ADD', reg('rax'), reg('rax'), reg('rbx')), mnemonic='ADD', code='4801d8'),
                          ins(op('CBRANCH', None, target(0x1005), flag), ea=0x1003, mnemonic='JC', code='7200')], ['rax'])
        _, values = evaluate(report, {'rax': (1 << 64) - 1, 'rbx': 1})
        self.assertEqual(values[report['control']['condition']], 1)
        # Dead flag-only operations require no invented initial flag value.
        dead = project([ins(op('BOOL_NEGATE', flag, flag))], ['rax'])
        self.assertEqual(dead['statistics']['selectedOperations'], 0)
        self.assertEqual(dead['statistics']['omittedPureOperations'], 1)

    def test_bit_operations_extension_slice_and_shift(self):
        report = project([ins(op('INT_SEXT', reg('rax'), reg('rbx', 1)),
                              op('INT_SRIGHT', reg('rax'), reg('rax'), const(100, 1)),
                              op('PIECE', tmp(), reg('rcx', 4), reg('rdx', 4)),
                              op('SUBPIECE', reg('r8', 2), tmp(), const(3, 4)),
                              op('INT_ZEXT', reg('r8'), reg('r8', 2)))], ['rax', 'r8'])
        output, _ = evaluate(report, {'rbx': 0x80, 'rcx': 0x11223344, 'rdx': 0x55667788})
        self.assertEqual(output, {'rax': (1 << 64) - 1, 'r8': 0x4455})

    def test_invalid_shapes_and_register_selection(self):
        for registers in ([], ['RAX'], ['eax'], ['rax', 'rax'], 'rax', [None]):
            with self.subTest(registers=registers), self.assertRaises(ProjectionError):
                project([ins()], registers)
        bad_ops = [op('INT_ADD', reg('rax'), reg('rbx', 4), const(1)),
                   op('COPY', reg('rax'), const(1, 4)),
                   op('INT_ZEXT', reg('rax', 1), reg('rbx')),
                   op('SUBPIECE', reg('rax'), reg('rbx'), const(1)),
                   op('LOAD', reg('rax'), {'kind': 'address-space', 'space': 'io'}, reg('rbx')),
                   op('STORE', None, RAM, reg('rax', 4), reg('rbx')),
                   op('COPY', reg('rax', 8, 1), const(1))]
        for operation in bad_ops:
            with self.subTest(operation=operation), self.assertRaises(ProjectionError):
                project([ins(operation)], ['rax'])

    def test_input_is_not_modified_and_cancellation_is_propagated(self):
        path = [ins(op('INT_ADD', reg('rax'), reg('rax'), const(1)))]
        before = copy.deepcopy(path)
        project(path, ['rax'])
        self.assertEqual(path, before)
        calls = []

        def cancel():
            calls.append(1)
            if len(calls) == 4:
                raise InterruptedError('cancelled')

        with self.assertRaises(InterruptedError):
            project(path, ['rax'], cancel)
        self.assertEqual(len(calls), 4)

    def test_instruction_and_pcode_budgets(self):
        with self.assertRaisesRegex(ProjectionError, 'instruction budget'):
            project([ins(ea=0x1000 + i) for i in range(129)], ['rax'])
        with self.assertRaisesRegex(ProjectionError, 'Per-instruction'):
            project([ins(*[op('COPY', reg('rax'), const(1)) for _ in range(129)])], ['rax'])
        with self.assertRaisesRegex(ProjectionError, 'Total p-code'):
            project([ins(*[op('COPY', reg('rax'), const(1)) for _ in range(128)], ea=0x1000 + i)
                     for i in range(65)], ['rax'])

    def test_memory_budget_counts_dead_reads(self):
        operations = [op('LOAD', tmp(i * 8), RAM, reg('rax')) for i in range(33)]
        with self.assertRaisesRegex(ProjectionError, 'Memory byte'):
            project([ins(*operations)], ['rax'])

    def test_dag_depth_budget(self):
        path = [ins(op('INT_ADD', reg('rax'), reg('rax'), const(i + 1)), ea=0x1000 + i)
                for i in range(128)]
        with self.assertRaisesRegex(ProjectionError, 'DAG depth'):
            project(path, ['rax'])

    def test_dag_node_budget(self):
        # 16 independent live chains stay shallow, but exceed shared node budget.
        operations = [op('INT_ADD', reg(name), reg(name), const(i + 1))
                      for i in range(30) for name in GPRS]
        path = [ins(*operations[i:i + 120], ea=0x1000 + i // 120) for i in range(0, len(operations), 120)]
        with self.assertRaisesRegex(ProjectionError, 'DAG node'):
            project(path, list(GPRS))

    def test_claims_remain_unverified(self):
        report = project([ins()], ['rax'])
        for field in ('nativeTargetExecuted', 'databaseModified', 'businessAccepted', 'wholeBinaryVerified'):
            self.assertIs(report[field], False)
        self.assertEqual(report['status'], 'translated-unverified')
        self.assertIn('no independent proof', report['scope']['representation'])
        self.assertIn('self-modifying code', report['scope']['codeDataCoherence'])

    def test_multiply_cannot_reuse_previously_defined_zero_flag(self):
        path = append_path(
            ins(op('COPY', flag('zf'), const(1, 1)), mnemonic='TEST', code='85c0'),
            ins(op('INT_MULT', reg('rax'), reg('rax'), reg('rbx')),
                op('COPY', flag('cf'), const(0, 1)), op('COPY', flag('of'), const(0, 1)), mnemonic='IMUL', code='480fafc3'),
            ins(op('COPY', reg('rax', 1), flag('zf')), mnemonic='SETZ', code='0f94c0'))
        with self.assertRaisesRegex(ProjectionError, r'IMUL.*zf'):
            project(path, ['rax'])
        # Same multiplication remains available when its undefined flags die.
        result = project(path[:2], ['rax'])
        output, _ = evaluate(result, {'rax': 7, 'rbx': 9})
        self.assertEqual(output['rax'], 63)
        self.assertEqual(result['flagPolicies'][1]['undefined'], ['af', 'pf', 'sf', 'zf'])

    def test_sahf_add_or_test_lahf_rejects_stale_auxiliary_flag(self):
        for name, code in [('ADD', '4801d8'), ('TEST', '4885d8')]:
            path = append_path(
                ins(op('COPY', flag('af'), const(1, 1)), mnemonic='SAHF', code='9e'),
                ins(op('INT_ADD' if name == 'ADD' else 'INT_AND', tmp(), reg('rax'), reg('rbx')), mnemonic=name, code=code),
                ins(op('INT_LEFT', reg('rax', 1, 1), flag('af'), const(4, 1)), mnemonic='LAHF', code='9f'))
            with self.subTest(instruction=name), self.assertRaisesRegex(ProjectionError, name + r'.*af'):
                project(path, ['rax'])

    def test_multiple_shift_cannot_reuse_old_overflow(self):
        path = append_path(
            ins(op('COPY', flag('of'), const(0, 1)), mnemonic='XOR', code='31c0'),
            ins(op('INT_LEFT', reg('rax'), reg('rax'), const(2, 1)),
                op('COPY', flag('of'), flag('of')), mnemonic='SHL', code='48c1e002'),
            ins(op('COPY', reg('rax', 1), flag('of')), mnemonic='SETO', code='0f90c0'))
        with self.assertRaisesRegex(ProjectionError, r'SHL.*of'):
            project(path, ['rax'])

    def test_defined_flag_overwrite_after_barrier_allows_path(self):
        path = append_path(
            ins(op('COPY', flag('zf'), const(1, 1)), mnemonic='TEST', code='85c0'),
            ins(op('INT_MULT', reg('rax'), reg('rax'), reg('rbx')), mnemonic='IMUL', code='480fafc3'),
            ins(op('INT_EQUAL', flag('zf'), reg('rax'), const(0)), mnemonic='TEST', code='4885c0'),
            ins(op('COPY', reg('rax', 1), flag('zf')), mnemonic='SETZ', code='0f94c0'))
        report = project(path, ['rax'])
        output, _ = evaluate(report, {'rax': 3, 'rbx': 7})
        self.assertEqual(output['rax'], 0)  # only low byte is overwritten with ZF=0

    def test_unknown_metadata_rejects_crossing_and_internal_flags(self):
        prefix = ins(op('COPY', flag('cf'), const(1, 1)), mnemonic='STC', code='f9')
        consumer = ins(op('COPY', reg('rax', 1), flag('cf')), mnemonic='SETC', code='0f92c0')
        for middle in (ins(), ins(mnemonic='NOP', code='0f0b'), ins(mnemonic='MYSTERY', code='90')):
            with self.subTest(middle=middle), self.assertRaisesRegex(ProjectionError, 'architectural flag crosses'):
                project(append_path(copy.deepcopy(prefix), middle, copy.deepcopy(consumer)), ['rax'])
        unknown_consumer = ins(op('INT_ZEXT', tmp(), flag('cf')),
                               op('INT_ADD', reg('rax'), reg('rax'), tmp()), mnemonic='MYSTERY', code='90')
        with self.assertRaisesRegex(ProjectionError, 'flag used inside|metadata cannot classify'):
            project(append_path(prefix, unknown_consumer), ['rax'])

    def test_flag_stored_to_memory_is_not_dropped_by_barrier(self):
        path = append_path(
            ins(op('COPY', flag('zf'), const(1, 1)), mnemonic='TEST', code='85c0'),
            ins(op('INT_MULT', reg('rax'), reg('rax'), reg('rbx')), mnemonic='IMUL', code='480fafc3'),
            ins(op('STORE', None, RAM, reg('rsp'), flag('zf')), mnemonic='SETZ', code='0f940424'))
        with self.assertRaisesRegex(ProjectionError, r'IMUL.*zf'):
            project(path, ['rdx'])

    def test_shift_count_binding_ignores_operand_text(self):
        from projection_flags import classify_flags
        from pcode_projection import _validate_op
        writes = [_validate_op(op('COPY', flag(name), const(0, 1))) for name in ('cf', 'pf', 'zf', 'sf', 'of')]
        for code, width, count in [('48c1e002', 64, 2), ('66c1e020', 16, 0), ('c0e008', 8, 8), ('48c1e040', 64, 0)]:
            instruction = ins(mnemonic='SHL', code=code)
            instruction['operands'] = 'RAX,0x1'  # deliberately misleading display text
            policy = classify_flags(instruction, writes)
            self.assertEqual((policy['encodedWidth'], policy['maskedCount']), (width, count))
            if count == 2:
                self.assertIn('of', policy['undefined'])
            if width == 8 and count == 8:
                self.assertIn('cf', policy['undefined'])

    def test_explicit_shr_overflow_macro_stays_unmodeled(self):
        from projection_flags import classify_flags
        from pcode_projection import _validate_op
        writes = [_validate_op(op('COPY', flag(name), const(0, 1))) for name in ('cf', 'pf', 'zf', 'sf', 'of')]
        for code in ('48c1e800', '48c1e801', '48d3e8'):
            policy = classify_flags(ins(mnemonic='SHR', code=code), writes)
            self.assertIn('of', policy['unmodeled'])
        implicit = classify_flags(ins(mnemonic='SHR', code='48d1e8'), writes)
        self.assertIn('of', implicit['defined'])

    def test_flag_preservation_requires_bound_nonwriting_instruction(self):
        path = append_path(
            ins(op('COPY', flag('cf'), const(1, 1)), mnemonic='STC', code='f9'),
            ins(op('COPY', reg('rbx'), reg('rdx')), mnemonic='MOV', code='4889d3'),
            ins(op('COPY', reg('rax', 1), flag('cf')), mnemonic='SETC', code='0f92c0'))
        report = project(path, ['rax', 'rbx'])
        output, _ = evaluate(report, {'rax': 0, 'rdx': 123})
        self.assertEqual(output, {'rax': 1, 'rbx': 123})
        path[1]['pcode'].append(op('COPY', flag('cf'), const(0, 1)))
        with self.assertRaisesRegex(ProjectionError, r'MOV.*cf'):
            project(path, ['rax'])

    def test_known_instruction_blocks_live_interior_unmodeled_flag(self):
        malformed = ins(op('COPY', flag('cf'), const(1, 1)),
                        op('INT_ZEXT', reg('rax'), flag('cf')), mnemonic='MOV', code='4889d8')
        with self.assertRaisesRegex(ProjectionError, 'flag used inside'):
            project([malformed], ['rax'])
        # The same unmodeled raw write is harmless when it does not contribute
        # to any requested register, memory store, or terminal control.
        dead = ins(op('COPY', flag('cf'), const(1, 1)),
                   op('COPY', reg('rax'), reg('rbx')), mnemonic='MOV', code='4889d8')
        report = project([dead], ['rax'])
        self.assertEqual(report['statistics']['omittedPureOperations'], 1)

    def test_bsr_dead_frame_preserves_raw_input_and_distinct_statistics(self):
        for bits in (16, 32, 64):
            with self.subTest(bits=bits):
                instruction = bounded_bsr(bits)
                original = copy.deepcopy(instruction)
                report = project([instruction], ['rax'])
                output, _ = evaluate(report, {'rax': 0xfedcba9876543210, 'r15': 0})
                self.assertEqual(output, {'rax': 0xfedcba9876543210})
                self.assertEqual(instruction, original)
                count = 11 if bits == 32 else 10
                self.assertEqual(report['statistics']['pcodeOperations'], count)
                self.assertEqual(report['statistics']['selectedOperations'], 0)
                self.assertEqual(report['statistics']['omittedPureOperations'], count - 3)
                self.assertEqual(report['statistics']['omittedInternalControlOperations'], 3)
                self.assertEqual(report['statistics']['internalElidedRawOperations'], count)
                evidence = report['internalElisions'][0]
                self.assertEqual(evidence['omittedRawPcodeOperations'], count)
                self.assertEqual(evidence['omittedPurePcodeOperations'], count - 3)
                self.assertEqual(evidence['ea'], instruction['ea'])
                self.assertEqual(evidence['codeBytes'], instruction['codeBytes'])
                self.assertEqual(len(evidence['rawPcodeSemanticSha256']), 64)
                self.assertEqual(evidence['frameLiveIntersection'], [])
                self.assertEqual(evidence['zeroInputArchitecturalDestination'], 'undefined')
                self.assertEqual(evidence['maximumBackedges'], bits - 1)
                self.assertFalse(evidence['architectureProved'])
                self.assertFalse(report['businessAccepted'])

    def test_bsr_live_destination_rejected_for_every_width(self):
        for bits in (16, 32, 64):
            with self.subTest(bits=bits), self.assertRaisesRegex(ProjectionError, 'Live BSR'):
                project([bounded_bsr(bits)], ['r9'])

    def test_bsr_narrow_frame_and_explicit_full_overwrite(self):
        low16 = ins(op('COPY', reg('r9', 2), const(0xabcd, 2)), mnemonic='MOV', code='6641b9cdab')
        report = project(append_path(bounded_bsr(16), low16), ['r9'])
        for initial in (0, 0x123456789abcdef0, (1 << 64) - 1):
            outputs, _ = evaluate(report, {'r9': initial, 'r15': 0})
            self.assertEqual(outputs['r9'], (initial & ~0xffff) | 0xabcd)
        low8 = ins(op('COPY', reg('r9', 1), const(0, 1)), mnemonic='MOV', code='41b100')
        with self.assertRaisesRegex(ProjectionError, 'Live BSR'):
            project(append_path(bounded_bsr(16), low8), ['r9'])
        low32 = ins(op('COPY', reg('r9', 4), const(123, 4)), mnemonic='MOV', code='41b97b000000')
        with self.assertRaisesRegex(ProjectionError, 'Live BSR'):
            project(append_path(bounded_bsr(32), low32), ['r9'])
        low32['pcode'].append(op('INT_ZEXT', reg('r9'), reg('r9', 4)))
        for bits in (32, 64):
            report = project(append_path(bounded_bsr(bits), low32), ['r9'])
            self.assertEqual(evaluate(report, {'r9': (1 << 64) - 1})[0], {'r9': 123})

    def test_bsr_store_address_value_and_transitive_copy_are_roots(self):
        stores = [ins(op('STORE', None, RAM, reg('rax'), reg('r9')), mnemonic='MOV', code='4c8908'),
                  ins(op('STORE', None, RAM, reg('r9'), reg('rax')), mnemonic='MOV', code='498901')]
        overwrite = ins(op('COPY', reg('r9'), const(0)), mnemonic='MOV', code='49b90000000000000000')
        for store in stores:
            with self.assertRaisesRegex(ProjectionError, 'Live BSR'):
                project(append_path(bounded_bsr(), store, overwrite), ['rax'])
        copied = ins(op('COPY', reg('rax'), reg('r9')), mnemonic='MOV', code='4c89c8')
        with self.assertRaisesRegex(ProjectionError, 'Live BSR'):
            project(append_path(bounded_bsr(), copied, overwrite), ['rax'])

    def test_bsr_does_not_drop_earlier_store_or_its_order(self):
        store = ins(op('STORE', None, RAM, reg('rax'), reg('r9')), mnemonic='MOV', code='4c8908')
        report = project(append_path(store, bounded_bsr()), ['rax'])
        outputs, values = evaluate(report, {'rax': (1 << 64) - 4, 'r9': 0x0102030405060708})
        self.assertEqual(outputs, {'rax': (1 << 64) - 4})
        self.assertEqual(len(report['stores']), 1)
        self.assertEqual(report['stores'][0]['instructionIndex'], 0)
        for n in range(8):
            self.assertEqual(values[report['currentMemory']][((1 << 64) - 4 + n) & ((1 << 64) - 1)],
                             (0x0102030405060708 >> (8 * n)) & 255)

    def test_bsr_all_six_flags_are_part_of_dead_frame(self):
        for name, mnemonic, code in [('zf', 'JZ', '7400'), ('cf', 'JC', '7200'), ('of', 'JO', '7000'),
                                     ('sf', 'JS', '7800'), ('pf', 'JP', '7a00')]:
            branch = ins(op('CBRANCH', None, target(0x2000), flag(name)), mnemonic=mnemonic, code=code)
            with self.subTest(flag=name), self.assertRaisesRegex(ProjectionError, 'Live BSR'):
                project(append_path(bounded_bsr(), branch), ['rax'])
        lahf = ins(op('COPY', reg('rax', 1, 1), flag('af')), mnemonic='LAHF', code='9f')
        with self.assertRaisesRegex(ProjectionError, 'Live BSR'):
            project(append_path(bounded_bsr(), lahf), ['rax'])

    def test_bsr_previous_flag_definition_cannot_authorize_new_value(self):
        stc = ins(op('COPY', flag('cf'), const(1, 1)), mnemonic='STC', code='f9')
        setc = ins(op('COPY', reg('rax', 1), flag('cf')), mnemonic='SETC', code='0f92c0')
        with self.assertRaisesRegex(ProjectionError, 'Live BSR'):
            project(append_path(stc, bounded_bsr(), setc), ['rax'])
        report = project(append_path(bounded_bsr(), stc, setc), ['rax'])
        self.assertEqual(evaluate(report, {'rax': 0})[0], {'rax': 1})

    def test_bsr_every_gpr_binding_and_alpha_renaming(self):
        names = list(GPRS)
        for bits in (16, 32, 64):
            for destination in names:
                for source in names:
                    output = 'rax' if destination != 'rax' else 'rcx'
                    report = project([bounded_bsr(bits, destination, source, unique_base=0x123450)], [output])
                    evidence = report['internalElisions'][0]
                    self.assertEqual(evidence['sourceOffset'], GPRS[source])
                    self.assertEqual(evidence['destinationOffset'], GPRS[destination])

    def test_bsr_mutated_structure_rejected_even_when_frame_dead(self):
        mutations = [(0, 'inputs', 0, 'offset', '0xe'), (3, 'inputs', 0, 'offset', '0x7'),
                     (6, 'inputs', 0, 'offset', '0x2'), (8, 'inputs', 0, 'offset', '0x0'),
                     (7, 'inputs', 1, 'offset', '0x0'), (7, 'inputs', 1, 'offset', '0x2'),
                     (4, 'inputs', 0, 'offset', '0xb0'), (2, 'inputs', 1, 'offset', '0x0')]
        for index, field, position, key, value in mutations:
            item = bounded_bsr()
            item['pcode'][index][field][position][key] = value
            with self.subTest(mutation=(index, value)), self.assertRaisesRegex(ProjectionError, 'Internal p-code'):
                project([item], ['rax'])
        for opcode in ('INT_SRIGHT', 'CALL', 'STORE', 'CALLOTHER', 'INT_ADD'):
            item = bounded_bsr()
            item['pcode'][4]['opcode'] = opcode
            with self.subTest(opcode=opcode), self.assertRaisesRegex(ProjectionError, 'Internal p-code'):
                project([item], ['rax'])

    def test_bsr_encoding_width_register_and_unique_binding_rejected(self):
        for code in ('66450fbd0f', 'f3450fbdcf', 'f0450fbdcf', '66450fbccf', '4d0fbdcf'):
            item = bounded_bsr()
            item.update(codeBytes=code, size=len(code) // 2)
            with self.subTest(code=code), self.assertRaisesRegex(ProjectionError, 'Internal p-code'):
                project([item], ['rax'])
        for field, value in [('codeBytes', None), ('mnemonic', 'BSF')]:
            item = bounded_bsr(); item[field] = value
            with self.assertRaises(ProjectionError):
                project([item], ['rax'])
        item = bounded_bsr(); item['pcode'][2]['output']['offset'] = item['pcode'][0]['output']['offset']
        with self.assertRaisesRegex(ProjectionError, 'Overlapping'):
            project([item], ['rax'])
        item = bounded_bsr(); item['pcode'][9]['output']['offset'] = hex(GPRS['r8'])
        with self.assertRaisesRegex(ProjectionError, 'Internal p-code'):
            project([item], ['rax'])

    def test_bsr_32bit_extension_shape_is_mandatory(self):
        for mutation in ('missing', 'signed', 'wrong-register'):
            item = bounded_bsr(32)
            if mutation == 'missing':
                item['pcode'].pop()
            elif mutation == 'signed':
                item['pcode'][-1]['opcode'] = 'INT_SEXT'
            else:
                item['pcode'][-1]['output']['offset'] = hex(GPRS['r8'])
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ProjectionError, 'Internal p-code'):
                project([item], ['rax'])

    def test_bsr_does_not_bypass_path_gap_or_unknown_later_effect(self):
        path = append_path(bounded_bsr(), ins(mnemonic='NOP', code='90'))
        path[1]['ea'] = hex(int(path[1]['ea'], 16) + 1)
        with self.assertRaisesRegex(ProjectionError, 'Missing fallthrough'):
            project(path, ['rax'])
        path = append_path(bounded_bsr(), ins(op('CALLOTHER', None), mnemonic='NOP', code='90'))
        with self.assertRaisesRegex(ProjectionError, 'Unsupported p-code effect'):
            project(path, ['rax'])

    def test_bsr_untrusted_elision_annotation_and_extra_effect_do_not_authorize(self):
        item = bounded_bsr()
        item['pcode'][8]['inputs'][0]['offset'] = '0x0'
        item['internalElisions'] = [{'frameLiveIntersection': [], 'mayEliminate': True}]
        item['bsrDescriptor'] = {'kind': 'register-bsr-bounded-dead-frame-v1', 'frameRegisterBytes': []}
        with self.assertRaisesRegex(ProjectionError, 'Internal p-code'):
            project([item], ['rax'])
        item = bounded_bsr()
        item['pcode'].append(op('STORE', None, RAM, reg('rax'), reg('rbx')))
        with self.assertRaisesRegex(ProjectionError, 'Internal p-code'):
            project([item], ['rax'])




# Exact saved native raw-pcode regression, not a constructed BSWAP model.
# Input handlers-pcode.json SHA256:
# 77137aed5ee5dce5a566d5275a3c810e1d6e535c34c500d50f6b494968177b05
# Original target SHA256:
# 5f9c1b6fcb019366f835d8f02d9ec3b2957fe619e039410d07f288a9c73f63f0
# The first object retains its recorded runtime EA, operands, and all 12 raw ops.
_RECORDED_BSWAP16 = {'ea': '0x7ff71e30211e',
 'size': 3,
 'mnemonic': 'BSWAP',
 'operands': 'EAX',
 'pcode': [{'opcode': 'INT_AND',
            'output': {'space': 'unique', 'offset': '0x65c00', 'size': 4},
            'inputs': [{'space': 'register', 'offset': '0x0', 'size': 4},
                       {'space': 'const', 'offset': '0xff000000', 'size': 4}]},
           {'opcode': 'INT_RIGHT',
            'output': {'space': 'unique', 'offset': '0x65e00', 'size': 4},
            'inputs': [{'space': 'unique', 'offset': '0x65c00', 'size': 4},
                       {'space': 'const', 'offset': '0x18', 'size': 4}]},
           {'opcode': 'INT_AND',
            'output': {'space': 'unique', 'offset': '0x65f00', 'size': 4},
            'inputs': [{'space': 'register', 'offset': '0x0', 'size': 4},
                       {'space': 'const', 'offset': '0xff0000', 'size': 4}]},
           {'opcode': 'INT_RIGHT',
            'output': {'space': 'unique', 'offset': '0x66000', 'size': 4},
            'inputs': [{'space': 'unique', 'offset': '0x65f00', 'size': 4},
                       {'space': 'const', 'offset': '0x8', 'size': 4}]},
           {'opcode': 'INT_OR',
            'output': {'space': 'unique', 'offset': '0x65e00', 'size': 4},
            'inputs': [{'space': 'unique', 'offset': '0x65e00', 'size': 4},
                       {'space': 'unique', 'offset': '0x66000', 'size': 4}]},
           {'opcode': 'INT_AND',
            'output': {'space': 'unique', 'offset': '0x66200', 'size': 4},
            'inputs': [{'space': 'register', 'offset': '0x0', 'size': 4},
                       {'space': 'const', 'offset': '0xff00', 'size': 4}]},
           {'opcode': 'INT_LEFT',
            'output': {'space': 'unique', 'offset': '0x66300', 'size': 4},
            'inputs': [{'space': 'unique', 'offset': '0x66200', 'size': 4},
                       {'space': 'const', 'offset': '0x8', 'size': 4}]},
           {'opcode': 'INT_OR',
            'output': {'space': 'unique', 'offset': '0x65e00', 'size': 4},
            'inputs': [{'space': 'unique', 'offset': '0x65e00', 'size': 4},
                       {'space': 'unique', 'offset': '0x66300', 'size': 4}]},
           {'opcode': 'INT_AND',
            'output': {'space': 'unique', 'offset': '0x66500', 'size': 4},
            'inputs': [{'space': 'register', 'offset': '0x0', 'size': 4},
                       {'space': 'const', 'offset': '0xff', 'size': 4}]},
           {'opcode': 'INT_LEFT',
            'output': {'space': 'unique', 'offset': '0x66600', 'size': 4},
            'inputs': [{'space': 'unique', 'offset': '0x66500', 'size': 4},
                       {'space': 'const', 'offset': '0x18', 'size': 4}]},
           {'opcode': 'INT_OR',
            'output': {'space': 'register', 'offset': '0x0', 'size': 4},
            'inputs': [{'space': 'unique', 'offset': '0x65e00', 'size': 4},
                       {'space': 'unique', 'offset': '0x66600', 'size': 4}]},
           {'opcode': 'INT_ZEXT',
            'output': {'space': 'register', 'offset': '0x0', 'size': 8},
            'inputs': [{'space': 'register', 'offset': '0x0', 'size': 4}]}],
 'codeBytes': '660fc8'}
# Independent actual decoder positive from the public data-only 64-bit fixture.
_DECODED_BSWAP64 = {'ea': '0x140001020',
 'size': 3,
 'mnemonic': 'BSWAP',
 'operands': 'RAX',
 'pcode': [{'opcode': 'INT_AND',
            'output': {'space': 'unique', 'offset': '0x66800', 'size': 8},
            'inputs': [{'space': 'register', 'offset': '0x0', 'size': 8},
                       {'space': 'const', 'offset': '0xff00000000000000', 'size': 8}]},
           {'opcode': 'INT_RIGHT',
            'output': {'space': 'unique', 'offset': '0x66a00', 'size': 8},
            'inputs': [{'space': 'unique', 'offset': '0x66800', 'size': 8},
                       {'space': 'const', 'offset': '0x38', 'size': 4}]},
           {'opcode': 'INT_AND',
            'output': {'space': 'unique', 'offset': '0x66b00', 'size': 8},
            'inputs': [{'space': 'register', 'offset': '0x0', 'size': 8},
                       {'space': 'const', 'offset': '0xff000000000000', 'size': 8}]},
           {'opcode': 'INT_RIGHT',
            'output': {'space': 'unique', 'offset': '0x66c00', 'size': 8},
            'inputs': [{'space': 'unique', 'offset': '0x66b00', 'size': 8},
                       {'space': 'const', 'offset': '0x28', 'size': 4}]},
           {'opcode': 'INT_OR',
            'output': {'space': 'unique', 'offset': '0x66a00', 'size': 8},
            'inputs': [{'space': 'unique', 'offset': '0x66a00', 'size': 8},
                       {'space': 'unique', 'offset': '0x66c00', 'size': 8}]},
           {'opcode': 'INT_AND',
            'output': {'space': 'unique', 'offset': '0x66e00', 'size': 8},
            'inputs': [{'space': 'register', 'offset': '0x0', 'size': 8},
                       {'space': 'const', 'offset': '0xff0000000000', 'size': 8}]},
           {'opcode': 'INT_RIGHT',
            'output': {'space': 'unique', 'offset': '0x66f00', 'size': 8},
            'inputs': [{'space': 'unique', 'offset': '0x66e00', 'size': 8},
                       {'space': 'const', 'offset': '0x18', 'size': 4}]},
           {'opcode': 'INT_OR',
            'output': {'space': 'unique', 'offset': '0x66a00', 'size': 8},
            'inputs': [{'space': 'unique', 'offset': '0x66a00', 'size': 8},
                       {'space': 'unique', 'offset': '0x66f00', 'size': 8}]},
           {'opcode': 'INT_AND',
            'output': {'space': 'unique', 'offset': '0x67100', 'size': 8},
            'inputs': [{'space': 'register', 'offset': '0x0', 'size': 8},
                       {'space': 'const', 'offset': '0xff00000000', 'size': 8}]},
           {'opcode': 'INT_RIGHT',
            'output': {'space': 'unique', 'offset': '0x67200', 'size': 8},
            'inputs': [{'space': 'unique', 'offset': '0x67100', 'size': 8},
                       {'space': 'const', 'offset': '0x8', 'size': 4}]},
           {'opcode': 'INT_OR',
            'output': {'space': 'unique', 'offset': '0x66a00', 'size': 8},
            'inputs': [{'space': 'unique', 'offset': '0x66a00', 'size': 8},
                       {'space': 'unique', 'offset': '0x67200', 'size': 8}]},
           {'opcode': 'INT_AND',
            'output': {'space': 'unique', 'offset': '0x67400', 'size': 8},
            'inputs': [{'space': 'register', 'offset': '0x0', 'size': 8},
                       {'space': 'const', 'offset': '0xff000000', 'size': 8}]},
           {'opcode': 'INT_LEFT',
            'output': {'space': 'unique', 'offset': '0x67500', 'size': 8},
            'inputs': [{'space': 'unique', 'offset': '0x67400', 'size': 8},
                       {'space': 'const', 'offset': '0x8', 'size': 4}]},
           {'opcode': 'INT_OR',
            'output': {'space': 'unique', 'offset': '0x66a00', 'size': 8},
            'inputs': [{'space': 'unique', 'offset': '0x66a00', 'size': 8},
                       {'space': 'unique', 'offset': '0x67500', 'size': 8}]},
           {'opcode': 'INT_AND',
            'output': {'space': 'unique', 'offset': '0x67700', 'size': 8},
            'inputs': [{'space': 'register', 'offset': '0x0', 'size': 8},
                       {'space': 'const', 'offset': '0xff0000', 'size': 8}]},
           {'opcode': 'INT_LEFT',
            'output': {'space': 'unique', 'offset': '0x67800', 'size': 8},
            'inputs': [{'space': 'unique', 'offset': '0x67700', 'size': 8},
                       {'space': 'const', 'offset': '0x18', 'size': 4}]},
           {'opcode': 'INT_OR',
            'output': {'space': 'unique', 'offset': '0x66a00', 'size': 8},
            'inputs': [{'space': 'unique', 'offset': '0x66a00', 'size': 8},
                       {'space': 'unique', 'offset': '0x67800', 'size': 8}]},
           {'opcode': 'INT_AND',
            'output': {'space': 'unique', 'offset': '0x67a00', 'size': 8},
            'inputs': [{'space': 'register', 'offset': '0x0', 'size': 8},
                       {'space': 'const', 'offset': '0xff00', 'size': 8}]},
           {'opcode': 'INT_LEFT',
            'output': {'space': 'unique', 'offset': '0x67b00', 'size': 8},
            'inputs': [{'space': 'unique', 'offset': '0x67a00', 'size': 8},
                       {'space': 'const', 'offset': '0x28', 'size': 4}]},
           {'opcode': 'INT_OR',
            'output': {'space': 'unique', 'offset': '0x66a00', 'size': 8},
            'inputs': [{'space': 'unique', 'offset': '0x66a00', 'size': 8},
                       {'space': 'unique', 'offset': '0x67b00', 'size': 8}]},
           {'opcode': 'INT_AND',
            'output': {'space': 'unique', 'offset': '0x67d00', 'size': 8},
            'inputs': [{'space': 'register', 'offset': '0x0', 'size': 8},
                       {'space': 'const', 'offset': '0xff', 'size': 8}]},
           {'opcode': 'INT_LEFT',
            'output': {'space': 'unique', 'offset': '0x67e00', 'size': 8},
            'inputs': [{'space': 'unique', 'offset': '0x67d00', 'size': 8},
                       {'space': 'const', 'offset': '0x38', 'size': 4}]},
           {'opcode': 'INT_OR',
            'output': {'space': 'register', 'offset': '0x0', 'size': 8},
            'inputs': [{'space': 'unique', 'offset': '0x66a00', 'size': 8},
                       {'space': 'unique', 'offset': '0x67e00', 'size': 8}]}],
 'codeBytes': '480fc8'}


class BswapEncodingTests(unittest.TestCase):
    def test_original_undefined_bswap_rejected(self):
        self.assertEqual(_RECORDED_BSWAP16['codeBytes'], '660fc8')
        self.assertEqual(len(_RECORDED_BSWAP16['pcode']), 12)
        self.assertEqual(_RECORDED_BSWAP16['pcode'][-1]['opcode'], 'INT_ZEXT')
        with self.assertRaisesRegex(ProjectionError, 'Architecturally undefined 16-bit BSWAP'):
            project([copy.deepcopy(_RECORDED_BSWAP16)], ['rax'])

    def test_bswap_dead_destination_still_rejected(self):
        with self.assertRaisesRegex(ProjectionError, 'Architecturally undefined 16-bit BSWAP'):
            project([copy.deepcopy(_RECORDED_BSWAP16)], ['rbx'])

    def test_bswap_missing_or_malformed_bound_bytes_rejected(self):
        for code in (None, '', '66 0fc8', 'zzzzzz', '0fc8', 123):
            item = copy.deepcopy(_RECORDED_BSWAP16)
            if code is None:
                del item['codeBytes']
            else:
                item['codeBytes'] = code
            with self.subTest(code=code), self.assertRaisesRegex(ProjectionError, 'Unsupported BSWAP encoding or metadata'):
                project([item], ['rax'])

    def test_bswap_duplicate_unordered_and_extra_prefixes_rejected(self):
        # An earlier REX.W is ignored once a later legacy prefix appears. It
        # must not make 48 66 0F C8, or any noncanonical order, a supported 64-bit form.
        for code in ('66660fc8', '48480fc8', '48660fc8', '4866480fc8',
                     '6648480fc8', '6648660fc8', 'f00fc8', 'f20fc8', 'f30fc8',
                     '670fc8', '2e0fc8', '64480fc8', '0fc890'):
            item = copy.deepcopy(_RECORDED_BSWAP16)
            item.update(codeBytes=code, size=len(code) // 2)
            with self.subTest(code=code), self.assertRaisesRegex(ProjectionError, 'Unsupported BSWAP encoding or metadata'):
                project([item], ['rax'])

    def test_bswap_encoding_mnemonic_mismatch_rejected(self):
        item = copy.deepcopy(_RECORDED_BSWAP16)
        item.update(codeBytes='0fc8', size=2, mnemonic='MOV')
        with self.assertRaisesRegex(ProjectionError, 'Unsupported BSWAP encoding or metadata'):
            project([item], ['rax'])
        item.update(codeBytes='9090', mnemonic='BSWAP')
        with self.assertRaisesRegex(ProjectionError, 'Unsupported BSWAP encoding or metadata'):
            project([item], ['rax'])

    def test_bswap_no_effective_w_rejected_for_all_opcode_registers(self):
        for rex in ('', '40', '41', '44', '47'):
            for opcode in range(0xc8, 0xd0):
                item = copy.deepcopy(_RECORDED_BSWAP16)
                code = '66' + rex + '0f' + format(opcode, '02x')
                item.update(codeBytes=code, size=len(code) // 2)
                with self.subTest(code=code), self.assertRaisesRegex(ProjectionError, 'Architecturally undefined 16-bit BSWAP'):
                    project([item], ['rax'])

    def test_normal_bswap32_and64_with_effective_rex_w(self):
        rng = random.Random(0xB5A9)
        inputs = [0, 1, (1 << 64) - 1, 0x1122334455667788, 1 << 63, 1 << 32]
        inputs += [rng.getrandbits(64) for _ in range(128)]
        for code, bits in (('0fc8', 32), ('400fc8', 32), ('480fc8', 64), ('66480fc8', 64)):
            item = copy.deepcopy(_RECORDED_BSWAP16 if bits == 32 else _DECODED_BSWAP64)
            item.update(codeBytes=code, size=len(code) // 2)
            report = project([item], list(GPRS))
            for value in inputs:
                initial = {name: rng.getrandbits(64) for name in GPRS}
                initial['rax'] = value
                expected = dict(initial)
                expected['rax'] = int.from_bytes((value & ((1 << bits) - 1)).to_bytes(bits // 8, 'little'), 'big')
                actual, _ = evaluate(report, initial)
                with self.subTest(code=code, value=value):
                    self.assertEqual(actual, expected)
                    self.assertEqual(report['stores'], [])
                    self.assertEqual(report['currentMemory'], report['initialMemory'])
                    self.assertEqual(report['control']['kind'], 'fallthrough')


if __name__ == '__main__':
    unittest.main(verbosity=2)
