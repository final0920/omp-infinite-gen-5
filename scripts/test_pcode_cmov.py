"""Complete raw shape and observable-root regression, without a native target."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pcode_projection import GPRS, ProjectionError, RAM, const, evaluate, flag, ins, op, project, reg, target, tmp
from projection_cmov import match_cmov_structure
from projection_cmov_raw_oracle import check_cmov_raw


NAMES = ('O', 'NO', 'C', 'NC', 'Z', 'NZ', 'BE', 'A', 'S', 'NS', 'P', 'NP', 'L', 'GE', 'LE', 'G')


def cmov(bits=16, cc=6, destination='r10', source='rdx', ea=0x1000, unique_base=0x123400):
    width, names = bits // 8, list(GPRS)
    dst, src = names.index(destination), names.index(source)
    rex = 0x40 | (8 if bits == 64 else 0) | (4 if dst >= 8 else 0) | (1 if src >= 8 else 0)
    code = bytes(([0x66] if bits == 16 else []) + ([rex] if rex != 0x40 else []) + [0x0f, 0x40 + cc, 0xc0 | (dst & 7) << 3 | src & 7])
    operations = []
    def boolean(kind, *args):
        out = tmp(unique_base + len(operations) * 0x100, 1)
        operations.append(op(kind, out, *args))
        return out
    direct = {0: flag('of'), 2: flag('cf'), 4: flag('zf'), 8: flag('sf'), 10: flag('pf')}
    if cc in direct: condition = direct[cc]
    elif cc in (1, 3, 5, 9, 11): condition = boolean('BOOL_NEGATE', direct[cc - 1])
    elif cc in (6, 7):
        condition = boolean('BOOL_OR', flag('cf'), flag('zf'))
        if cc == 7: condition = boolean('BOOL_NEGATE', condition)
    elif cc in (12, 13): condition = boolean('INT_NOTEQUAL' if cc == 12 else 'INT_EQUAL', flag('of'), flag('sf'))
    elif cc == 14: condition = boolean('BOOL_OR', flag('zf'), boolean('INT_NOTEQUAL', flag('of'), flag('sf')))
    else:
        not_zf = boolean('BOOL_NEGATE', flag('zf'))
        condition = boolean('BOOL_AND', not_zf, boolean('INT_EQUAL', flag('of'), flag('sf')))
    captured = tmp(unique_base + len(operations) * 0x100, width)
    operations.append(op('COPY', captured, reg(source, width)))
    if bits == 32: operations.append(op('INT_ZEXT', reg(destination), reg(destination, 4)))
    skip = boolean('BOOL_NEGATE', condition)
    operations += [op('CBRANCH', None, target(ea + len(code)), skip), op('COPY', reg(destination, width), captured)]
    return ins(*operations, ea=ea, mnemonic='CMOV' + NAMES[cc], code=code.hex())


def following(first, *rest):
    address = int(first['ea'], 16) + first['size']
    for item in rest:
        item['ea'] = hex(address)
        address += item['size']
    return [first, *rest]


def overwrite(name='r10', size=8):
    # The size4 negative fixture deliberately omits the real r32 extension:
    # partial low32 writes cannot establish death of a full64 CMOV frame.
    code = {1: '41b200', 2: '6641ba0000', 4: '41ba00000000', 8: '49ba0000000000000000'}[size]
    return ins(op('COPY', reg(name, size), const(0, size)), mnemonic='MOV', code=code)


class CmovTests(unittest.TestCase):
    def test_all_conditions_widths_preserve_raw_and_original_budgets(self):
        for bits in (16, 32, 64):
            for cc in range(16):
                item = cmov(bits, cc); original = copy.deepcopy(item)
                report = project([item], ['rax']); e = report['internalElisions'][0]
                self.assertEqual(item, original)
                self.assertEqual(e['kind'], 'register-cmov-acyclic-dead-frame-v1')
                self.assertEqual(e['operandBits'], bits)
                self.assertEqual(e['omittedInternalControlOperations'], 1)
                self.assertEqual(e['omittedRawPcodeOperations'], len(item['pcode']))
                self.assertEqual(e['maximumBackedges'], 0)
                self.assertEqual(e['frameLiveIntersection'], [])
                self.assertEqual(report['statistics']['pcodeOperations'], len(item['pcode']))
                self.assertEqual(report['statistics']['selectedOperations'], 0)
                self.assertEqual(report['statistics']['omittedPureOperations'], len(item['pcode']) - 1)
                self.assertEqual(report['flagPolicies'][0]['preserved'], ['af', 'cf', 'of', 'pf', 'sf', 'zf'])
                self.assertFalse(e['architectureProved'])

    def test_all_register_bindings_and_self_source(self):
        for bits in (16, 32, 64):
            for destination in GPRS:
                for source in GPRS:
                    e = match_cmov_structure(cmov(bits, 6, destination, source))
                    self.assertEqual(e['sourceOffset'], GPRS[source])
                    self.assertEqual(e['destinationOffset'], GPRS[destination])
                    self.assertEqual(e['destinationBytes'], 2 if bits == 16 else 8)

    def test_independent_raw_oracle_all_boolean_flag_states(self):
        for bits in (16, 32, 64):
            for cc in range(16):
                for source in ('rdx', 'r10'):
                    audit = check_cmov_raw(cmov(bits, cc, source=source), bits, GPRS[source], GPRS['r10'], cc)
                    self.assertEqual(audit['numericStates'], 256)

    def test_live_destination_rejected_for_all_widths(self):
        for bits in (16, 32, 64):
            with self.assertRaisesRegex(ProjectionError, 'Live CMOV'):
                project([cmov(bits)], ['r10'])

    def test_all_gprs_can_be_projected_after_entire_destination_overwrite(self):
        for bits in (16, 32, 64):
            report = project(following(cmov(bits), overwrite()), list(GPRS))
            result, _ = evaluate(report, {n: 0x123456789abcdef0 for n in GPRS})
            self.assertEqual(result['r10'], 0)
            self.assertEqual(result['rax'], 0x123456789abcdef0)

    def test_r32_unconditional_upper_half_is_in_full_frame(self):
        with self.assertRaisesRegex(ProjectionError, 'Live CMOV'):
            project(following(cmov(32), overwrite(size=4)), ['r10'])
        with self.assertRaisesRegex(ProjectionError, 'Live CMOV'):
            project(following(cmov(16), overwrite(size=1)), ['r10'])
        self.assertEqual(len(project(following(cmov(16), overwrite(size=2)), ['r10'])['internalElisions']), 1)

    def test_store_value_address_and_transitive_copy_are_roots(self):
        for store in (op('STORE', None, RAM, reg('r10'), reg('rax')), op('STORE', None, RAM, reg('rax'), reg('r10'))):
            with self.assertRaisesRegex(ProjectionError, 'Live CMOV'):
                project(following(cmov(), ins(store), overwrite()), ['rax'])
        with self.assertRaisesRegex(ProjectionError, 'Live CMOV'):
            project(following(cmov(), ins(op('COPY', reg('rax'), reg('r10'))), overwrite()), ['rax'])

    def test_side_exit_observes_register_before_later_overwrite(self):
        first = cmov(); ea = 0x1000 + first['size']
        branch = ins(op('INT_EQUAL', tmp(0x7800, 1), reg('rcx'), const(0)), op('CBRANCH', None, target(ea + 4), tmp(0x7800, 1)), ea=ea, mnemonic='JRCXZ', code='e302')
        with self.assertRaisesRegex(ProjectionError, 'Live CMOV'):
            project(following(first, branch, overwrite()), ['r10'], mode='guarded-path')

    def test_terminal_control_is_a_root(self):
        with self.assertRaisesRegex(ProjectionError, 'Live CMOV'):
            project(following(cmov(), ins(op('BRANCHIND', None, reg('r10')), mnemonic='JMP', code='41ffe2')), ['rax'])

    def test_flags_survive_dead_cmov_and_no_initial_flag_is_created(self):
        clc = ins(op('COPY', flag('cf'), const(0, 1)), mnemonic='CLC', code='f8')
        setc = ins(op('COPY', reg('rax', 1), flag('cf')), mnemonic='SETC', code='0f92c0')
        report = project([clc, *following(cmov(ea=0x1001), setc)], ['rax'])
        self.assertEqual(evaluate(report, {n: 255 for n in GPRS})[0]['rax'], 0)
        with self.assertRaisesRegex(ProjectionError, 'undefined initial architectural flags'):
            project(following(cmov(), copy.deepcopy(setc)), ['rax'])

    def test_complete_raw_effects_and_binding_mutations_rejected(self):
        original = cmov()
        for i, item in enumerate(original['pcode']):
            mutant = copy.deepcopy(original); mutant['pcode'][i]['opcode'] = 'COPY' if item['opcode'] != 'COPY' else 'INT_NEGATE'
            with self.subTest(operation=i), self.assertRaises(ProjectionError): project([mutant], ['rax'])
        for change in ('target', 'condition', 'source', 'destination', 'unique-overlap', 'extra-store', 'extra-flag', 'metadata', 'width', 'memory', 'repeated-prefix', 'wrong-prefix-order', 'redundant-width'):
            mutant = copy.deepcopy(original)
            if change == 'target': mutant['pcode'][-2]['inputs'][0]['offset'] = '0x9999'
            elif change == 'condition': mutant['pcode'][0]['inputs'][0] = flag('pf')
            elif change == 'source': mutant['pcode'][1]['inputs'][0] = reg('rax', 2)
            elif change == 'destination': mutant['pcode'][-1]['output'] = reg('rax', 2)
            elif change == 'unique-overlap': mutant['pcode'][1]['output']['offset'] = mutant['pcode'][0]['output']['offset']
            elif change == 'extra-store': mutant['pcode'].append(op('STORE', None, RAM, reg('rax'), reg('rbx')))
            elif change == 'extra-flag': mutant['pcode'].append(op('COPY', flag('cf'), const(0, 1)))
            elif change == 'metadata': mutant['mnemonic'] = 'CMOVA'
            elif change == 'width': mutant['codeBytes'] = '440f46d2'; mutant['size'] = 4
            else:
                code = {'memory': '66440f4612', 'repeated-prefix': '6666440f46d2', 'wrong-prefix-order': '44660f46d2', 'redundant-width': '664c0f46d2'}[change]
                mutant['codeBytes'], mutant['size'] = code, len(code) // 2
            with self.subTest(change=change), self.assertRaises(ProjectionError): project([mutant], ['rax'])

    def test_untrusted_annotation_cannot_authorize_liveness_or_missing_shape(self):
        item = cmov(); item['internalElisions'] = [{'frameLiveIntersection': [], 'mayEliminate': True}]
        with self.assertRaisesRegex(ProjectionError, 'Live CMOV'): project([item], ['r10'])
        item['pcode'].pop()
        with self.assertRaises(ProjectionError): project([item], ['rax'])

    def test_no_general_cfg_or_path_gap_is_authorized(self):
        item = cmov(); item['mnemonic'] = 'NOP'
        with self.assertRaises(ProjectionError): project([item], ['rax'])
        item = cmov(); next_ = overwrite(); next_['ea'] = '0x2000'
        with self.assertRaisesRegex(ProjectionError, 'Missing fallthrough'): project([item, next_], ['rax'])


if __name__ == '__main__': unittest.main()
