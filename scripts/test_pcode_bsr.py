"""Pure complete-shape/frame regression for BSR; no native decoder or PE executes."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pcode_projection import (GPRS, ProjectionError, RAM, append_path, const,
                                   evaluate, flag, ins, op, project, reg, target, tmp)
from test_pcode_bsf import bounded_bsf


def bounded_bsr(bits=16, destination='r9', source='r15', unique_base=0x1000):
    width = bits // 8
    names = list(GPRS)
    dst, src = names.index(destination), names.index(source)
    rex = 0x40 | (8 if bits == 64 else 0) | (4 if dst >= 8 else 0) | (1 if src >= 8 else 0)
    code = ([0x66] if bits == 16 else []) + ([rex] if rex != 0x40 else []) + [0x0f, 0xbd, 0xc0 | ((dst & 7) << 3) | (src & 7)]
    counter, zero, shifted, nonzero = (tmp(unique_base + i * 0x100, size) for i, size in enumerate((width, 1, width, 1)))
    operations = [
        op('COPY', counter, const(bits - 1, width)),
        op('INT_EQUAL', flag('zf'), reg(source, width), const(0, width)),
        op('INT_EQUAL', zero, flag('zf'), const(1, 1)),
        op('CBRANCH', None, const(6, 4), zero),
        op('INT_RIGHT', shifted, reg(source, width), counter),
        op('INT_NOTEQUAL', nonzero, shifted, const(0, width)),
        op('CBRANCH', None, const(3, 4), nonzero),
        op('INT_SUB', counter, counter, const(1, width)),
        op('BRANCH', None, const(0xfffffffc, 4)),
        op('COPY', reg(destination, width), counter),
    ]
    if bits == 32:
        operations.append(op('INT_ZEXT', reg(destination), reg(destination, 4)))
    return ins(*operations, mnemonic='BSR', code=bytes(code).hex())


class BsrProjectionTests(unittest.TestCase):
    def test_dead_frame_is_bound_raw_preserved_and_budget_not_reduced(self):
        for bits, steps in ((16, 83), (32, 164), (64, 323)):
            with self.subTest(bits=bits):
                instruction = bounded_bsr(bits)
                original = copy.deepcopy(instruction)
                result = project([instruction], ['rax'])
                e = result['internalElisions'][0]
                self.assertEqual(instruction, original)
                self.assertEqual(e['kind'], 'register-bsr-bounded-dead-frame-v1')
                self.assertEqual(e['maximumPcodeSteps'], steps)
                self.assertEqual(e['maximumBackedges'], bits - 1)
                self.assertEqual(e['internalEdges'], [[3, 9], [6, 9], [8, 4]])
                self.assertEqual(e['zeroInputRawDestination'], bits - 1)
                self.assertEqual(e['zeroInputArchitecturalDestination'], 'undefined')
                self.assertEqual(e['rawOperationCount'], 11 if bits == 32 else 10)
                self.assertEqual(result['statistics']['pcodeOperations'], len(instruction['pcode']))
                self.assertEqual(result['statistics']['selectedOperations'], 0)
                self.assertEqual(result['statistics']['omittedInternalControlOperations'], 3)
                self.assertEqual(result['statistics']['omittedPureOperations'], len(instruction['pcode']) - 3)
                self.assertEqual(result['flagPolicies'][0]['family'], 'bsr-complete-bounded-shape')
                self.assertEqual(e['frameLiveIntersection'], [])
                self.assertFalse(e['architectureProved'])

    def test_live_destination_all_widths_rejected(self):
        for bits in (16, 32, 64):
            with self.subTest(bits=bits), self.assertRaisesRegex(ProjectionError, 'Live BSR'):
                project([bounded_bsr(bits)], ['r9'])

    def test_every_register_binding_self_source_and_alpha_renaming(self):
        for bits in (16, 32, 64):
            for destination in GPRS:
                for source in GPRS:
                    result = project([bounded_bsr(bits, destination, source, 0x654320)], ['rax' if destination != 'rax' else 'r8'])
                    evidence = result['internalElisions'][0]
                    self.assertEqual((evidence['sourceOffset'], evidence['destinationOffset']), (GPRS[source], GPRS[destination]))

    def test_partial_overwrite_does_not_hide_full_frame(self):
        low16 = ins(op('COPY', reg('r9', 2), const(0x55, 2)), mnemonic='MOV', code='6641b95500')
        result = project(append_path(bounded_bsr(16), low16), ['r9'])
        self.assertEqual(evaluate(result, {'r9': 0x123456789abcdef0})[0], {'r9': 0x123456789abc0055})
        for bits in (32, 64):
            with self.subTest(bits=bits), self.assertRaisesRegex(ProjectionError, 'Live BSR'):
                project(append_path(bounded_bsr(bits), copy.deepcopy(low16)), ['r9'])
        low32 = ins(op('COPY', reg('r9', 4), const(0x55, 4)), mnemonic='MOV', code='41b955000000')
        with self.assertRaisesRegex(ProjectionError, 'Live BSR'):
            project(append_path(bounded_bsr(32), low32), ['r9'])
        low32['pcode'].append(op('INT_ZEXT', reg('r9'), reg('r9', 4)))
        self.assertEqual(evaluate(project(append_path(bounded_bsr(32), low32), ['r9']), {})[0], {'r9': 0x55})

    def test_every_status_flag_is_a_live_barrier(self):
        for name in ('cf', 'pf', 'af', 'zf', 'sf', 'of'):
            read = ins(op('COPY', reg('rax', 1), flag(name)), mnemonic='MOV', code='88d8')
            with self.subTest(flag=name), self.assertRaisesRegex(ProjectionError, 'Live BSR'):
                project(append_path(bounded_bsr(), read), ['rax'])

    def test_store_address_value_and_transitive_read_are_roots(self):
        suffixes = [ins(op('STORE', None, RAM, reg('rax'), reg('r9')), mnemonic='MOV', code='4c8908'),
                    ins(op('STORE', None, RAM, reg('r9'), reg('rax')), mnemonic='MOV', code='498901'),
                    ins(op('COPY', reg('rax'), reg('r9')), mnemonic='MOV', code='4c89c8')]
        for suffix in suffixes:
            overwrite = ins(op('COPY', reg('r9'), const(0)), mnemonic='MOV', code='49b90000000000000000')
            with self.assertRaisesRegex(ProjectionError, 'Live BSR'):
                project(append_path(bounded_bsr(), suffix, overwrite), ['rax'])

    def test_prior_flags_cannot_cross_bsr_but_later_definition_can(self):
        stc = ins(op('COPY', flag('cf'), const(1, 1)), mnemonic='STC', code='f9')
        read = ins(op('COPY', reg('rax', 1), flag('cf')), mnemonic='SETC', code='0f92c0')
        with self.assertRaisesRegex(ProjectionError, 'Live BSR'):
            project(append_path(copy.deepcopy(stc), bounded_bsr(), copy.deepcopy(read)), ['rax'])
        result = project(append_path(bounded_bsr(), stc, read), ['rax'])
        self.assertEqual(evaluate(result, {'rax': 0})[0], {'rax': 1})

    def test_prior_store_preserved_in_order_with_wrapping_address(self):
        store = ins(op('STORE', None, RAM, reg('rax'), reg('r9')), mnemonic='MOV', code='4c8908')
        result = project(append_path(store, bounded_bsr()), ['rax'])
        _, values = evaluate(result, {'rax': (1 << 64) - 4, 'r9': 0x0102030405060708})
        self.assertEqual(len(result['stores']), 1)
        self.assertEqual(result['stores'][0]['instructionIndex'], 0)
        self.assertEqual(values[result['currentMemory']][0], 4)

    def test_each_internal_edge_counter_and_loop_step_must_match(self):
        changes = [(0, 0, '0x0'), (2, 1, '0x0'), (3, 0, '0x5'), (5, 1, '0x1'),
                   (6, 0, '0x2'), (7, 1, '0x0'), (7, 1, '0x2'), (8, 0, '0xfffffffb'), (4, 0, '0xb0')]
        for index, which, offset in changes:
            item = bounded_bsr()
            item['pcode'][index]['inputs'][which]['offset'] = offset
            with self.subTest(change=(index, offset)), self.assertRaisesRegex(ProjectionError, 'Internal p-code'):
                project([item], ['rax'])
        for opcode in ('INT_LEFT', 'INT_ADD', 'STORE', 'CALL', 'CALLOTHER'):
            item = bounded_bsr()
            item['pcode'][7]['opcode'] = opcode
            with self.subTest(opcode=opcode), self.assertRaisesRegex(ProjectionError, 'Internal p-code'):
                project([item], ['rax'])

    def test_memory_bsf_width_prefix_and_mnemonic_cannot_match(self):
        for code in ('66450fbd0f', 'f3450fbdcf', 'f0450fbdcf', 'f2450fbdcf', '66450fbccf',
                     '4d0fbdcf', '6666450fbdcf', '45660fbdcf', '6645450fbdcf', '664d0fbdcf'):
            item = bounded_bsr()
            item.update(codeBytes=code, size=len(code) // 2)
            with self.subTest(code=code), self.assertRaisesRegex(ProjectionError, 'Internal p-code'):
                project([item], ['rax'])
        for key, value in (('codeBytes', None), ('mnemonic', 'LZCNT'), ('mnemonic', 'BSF')):
            item = bounded_bsr()
            item[key] = value
            with self.assertRaises(ProjectionError):
                project([item], ['rax'])

    def test_every_unique_role_is_disjoint_and_width_bound(self):
        for index in (2, 4, 5):
            item = bounded_bsr()
            item['pcode'][index]['output']['offset'] = item['pcode'][0]['output']['offset']
            with self.subTest(index=index), self.assertRaisesRegex(ProjectionError, 'Overlapping'):
                project([item], ['rax'])
        item = bounded_bsr()
        item['pcode'][5]['output']['size'] = 2
        with self.assertRaisesRegex(ProjectionError, 'temporary role'):
            project([item], ['rax'])

    def test_full32_zero_extension_required(self):
        for change in ('missing', 'signed', 'other-register'):
            item = bounded_bsr(32)
            if change == 'missing':
                item['pcode'].pop()
            elif change == 'signed':
                item['pcode'][-1]['opcode'] = 'INT_SEXT'
            else:
                item['pcode'][-1]['output']['offset'] = hex(GPRS['r8'])
            with self.subTest(change=change), self.assertRaisesRegex(ProjectionError, 'Internal p-code'):
                project([item], ['rax'])

    def test_annotations_extra_effect_and_path_gap_cannot_authorize(self):
        item = bounded_bsr()
        item['pcode'][8]['inputs'][0]['offset'] = '0x0'
        item['internalElisions'] = [{'frameLiveIntersection': []}]
        item['bsrDescriptor'] = {'frameRegisterBytes': []}
        with self.assertRaisesRegex(ProjectionError, 'Internal p-code'):
            project([item], ['rax'])
        item = bounded_bsr()
        item['pcode'].append(op('STORE', None, RAM, reg('rax'), reg('rbx')))
        with self.assertRaisesRegex(ProjectionError, 'Internal p-code'):
            project([item], ['rax'])
        path = append_path(bounded_bsr(), ins(mnemonic='NOP', code='90'))
        path[-1]['ea'] = '0x2000'
        with self.assertRaisesRegex(ProjectionError, 'Missing fallthrough'):
            project(path, ['rax'])

    def test_guarded_side_exit_observes_bsr_before_later_overwrite(self):
        first = bounded_bsr(64, 'rax', 'rbx')
        branch = ins(op('INT_EQUAL', tmp(0, 1), reg('rcx'), const(0)),
                     op('CBRANCH', None, target(0x2000), tmp(0, 1)), mnemonic='JRCXZ', code='e300')
        last = ins(op('COPY', reg('rax'), const(0x55)), mnemonic='MOV', code='b855000000')
        with self.assertRaisesRegex(ProjectionError, 'Live BSR'):
            project(append_path(first, branch, last), ['rax'], mode='guarded-path')

    def test_bsr_bsf_mutual_exclusion(self):
        bsr_item = bounded_bsr(16)
        bsf_item = bounded_bsf(16)
        from projection_bsf import match_bsf_structure, BsfRejected
        from projection_bsr import match_bsr_structure, BsrRejected
        with self.assertRaises(BsfRejected):
            match_bsf_structure(bsr_item)
        with self.assertRaises(BsrRejected):
            match_bsr_structure(bsf_item)


if __name__ == '__main__':
    unittest.main()
