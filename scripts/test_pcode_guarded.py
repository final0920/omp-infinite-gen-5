"""Guarded exit/state regression tests; no target/decoder/process execution."""
import copy
from pathlib import Path
import random
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pcode_projection import GPRS, ProjectionError, RAM, append_path, bounded_bsr, const, evaluate, flag, ins, op, project, reg, target, tmp
from pcode_projection import LIMITS

MASK = (1 << 64) - 1


def jrcxz(ea=0x1000, destination=0x1004):
    return ins(op('INT_EQUAL', tmp(0, 1), reg('rcx'), const(0)),
               op('CBRANCH', None, target(destination), tmp(0, 1)),
               ea=ea, mnemonic='JRCXZ', code='e302')


def mov_rax(number=0x55, ea=0x1004):
    return ins(op('COPY', reg('rax', 4), const(number, 4)),
               op('INT_ZEXT', reg('rax'), reg('rax', 4)),
               ea=ea, mnemonic='MOV', code='b855000000')


def concrete(report, initial, memory=None):
    _, values = evaluate(report, initial, memory)
    exits = [item for item in report['sideExits'] if values[item['guard']] != 0]
    final = values[report['pathGuard']] != 0
    assert len(exits) + int(final) == 1, 'Guard partition must have exactly one active continuation'
    item = exits[0] if exits else report
    return ({name: values[index] for name, index in item['registers'].items()},
            values[item['currentMemory']], exits[0] if exits else None, values)


class GuardedProjectionTests(unittest.TestCase):
    def states(self):
        rng = random.Random(0x6a7263787a)
        for counter in (0, 1, 255, 256, MASK):
            for _ in range(20):
                state = {name: rng.getrandbits(64) for name in GPRS}
                state['rcx'] = counter
                yield state

    def test_strict_default_still_rejects_midpath_branch(self):
        with self.assertRaisesRegex(ProjectionError, 'only supported at path end'):
            project([jrcxz(), mov_rax()], list(GPRS))

    def test_taken_side_exit_retains_initial_state(self):
        result = project([jrcxz(), mov_rax()], list(GPRS), mode='guarded-path')
        self.assertEqual(result['schema'], 'ig5-pcode-guarded-projection-v1')
        self.assertEqual(result['projectionMode'], 'guarded-path')
        self.assertEqual(result['branchPoints'][0]['continuedSuccessor'], 'taken')
        for initial in self.states():
            state, memory, exit_, values = concrete(result, initial)
            self.assertEqual(state, {**initial, 'rax': 0x55} if initial['rcx'] == 0 else initial)
            self.assertEqual(memory, {})
            if exit_:
                self.assertEqual(values[exit_['target']], 0x1002)
                self.assertEqual(exit_['continuation'], 'not-analyzed')
                self.assertEqual(exit_['statusFlags'], 'not-exported')

    def test_fallthrough_selection_uses_opposite_guard(self):
        result = project([jrcxz(), mov_rax(ea=0x1002)], list(GPRS), mode='guarded-path')
        for initial in self.states():
            state, _, exit_, values = concrete(result, initial)
            self.assertEqual(state, {**initial, 'rax': 0x55} if initial['rcx'] != 0 else initial)
            if exit_:
                self.assertEqual(values[exit_['target']], 0x1004)

    def test_nonzero_condition_is_not_assumed_to_be_one(self):
        branch = ins(op('CBRANCH', None, target(0x1004), reg('rax', 1)), ea=0x1000, mnemonic='JZ', code='7402')
        result = project([branch, mov_rax()], ['rax'], mode='guarded-path')
        for value in (0, 1, 2, 128, 255, 256, MASK):
            state, _, exit_, _ = concrete(result, {'rax': value})
            self.assertEqual(state['rax'], 0x55 if value & 255 else value)
            self.assertEqual(exit_ is None, bool(value & 255))

    def test_side_exit_roots_keep_register_write_overwritten_later(self):
        prefix = ins(op('COPY', reg('rax'), reg('rdx')), ea=0x1000, mnemonic='MOV', code='4889d0')
        result = project([prefix, jrcxz(ea=0x1003, destination=0x1007), mov_rax(ea=0x1007)],
                         list(GPRS), mode='guarded-path')
        for initial in self.states():
            state, _, exit_, _ = concrete(result, initial)
            self.assertEqual(state['rax'], initial['rdx'] if exit_ else 0x55)

    def test_entry_guard_preserves_stores_before_unselected_edge(self):
        prefix = ins(op('STORE', None, RAM, reg('rbx'), reg('rax')), ea=0x1000, mnemonic='MOV', code='488903')
        suffix = ins(op('STORE', None, RAM, reg('rbx'), reg('rdx')), ea=0x1007, mnemonic='MOV', code='488913')
        load = ins(op('LOAD', reg('rcx'), RAM, reg('rbx')), ea=0x100a, mnemonic='MOV', code='488b0b')
        result = project([prefix, jrcxz(ea=0x1003, destination=0x1007), suffix, load],
                         list(GPRS), mode='guarded-path')
        self.assertEqual(len(result['stores']), 2)
        for initial in self.states():
            for address in (0, 1, MASK - 3):
                initial = {**initial, 'rbx': address}
                state, memory, exit_, values = concrete(result, initial)
                expected_value = initial['rax'] if exit_ else initial['rdx']
                expected_memory = {(address + i) & MASK: (expected_value >> (8*i)) & 255 for i in range(8)}
                self.assertEqual(memory, expected_memory)
                self.assertEqual(values[result['stores'][0]['guard']], 1)
                self.assertEqual(values[result['stores'][1]['guard']], int(initial['rcx'] == 0))
                self.assertEqual(state['rcx'], initial['rcx'] if exit_ else initial['rdx'])

    def test_flags_flow_across_midpath_edge_to_adc(self):
        compare = ins(op('INT_LESS', flag('cf'), reg('rax'), reg('rbx')),
                      ea=0x1000, mnemonic='CMP', code='4839d8')
        branch = ins(op('CBRANCH', None, target(0x1007), flag('cf')),
                     ea=0x1003, mnemonic='JC', code='7202')
        add_carry = ins(op('INT_ZEXT', tmp(0), flag('cf')),
                        op('INT_CARRY', flag('cf'), reg('rax'), tmp(0)),
                        op('INT_ADD', reg('rax'), reg('rax'), tmp(0)),
                        ea=0x1007, mnemonic='ADC', code='4883d000')
        result = project([compare, branch, add_carry], list(GPRS), mode='guarded-path')
        for a, b in ((0, 1), (1, 2), (3, 2), (MASK, 0), (0, MASK), (MASK, MASK)):
            initial = {name: 0 for name in GPRS}
            initial.update(rax=a, rbx=b)
            state, _, exit_, _ = concrete(result, initial)
            self.assertEqual(state['rax'], (a + 1) & MASK if a < b else a)
            self.assertEqual(exit_ is None, a < b)

    def test_undefined_flag_barrier_cannot_be_hidden_by_later_cmp(self):
        multiply = ins(op('INT_MULT', reg('rax'), reg('rax'), reg('rbx')),
                       ea=0x1000, mnemonic='MUL', code='48f7e3')
        branch = ins(op('CBRANCH', None, target(0x1007), flag('zf')),
                     ea=0x1003, mnemonic='JZ', code='7402')
        with self.assertRaisesRegex(ProjectionError, 'Undefined/unmodeled architectural flag'):
            project([multiply, branch, mov_rax(ea=0x1007)], ['rax'], mode='guarded-path')

    def test_bsr_live_side_exit_cannot_be_elided_using_final_liveness(self):
        bsr = bounded_bsr(64, 'rax', 'rbx')
        bsr['ea'] = '0x1000'
        branch_address = 0x1000 + bsr['size']
        branch = jrcxz(ea=branch_address, destination=branch_address + 4)
        with self.assertRaisesRegex(ProjectionError, 'Live BSR destination/status-flag frame'):
            project([bsr, branch, mov_rax(ea=branch_address + 4)], ['rax'], mode='guarded-path')

    def test_multiple_edges_partition_inputs_without_feasibility_claim(self):
        first = jrcxz()
        second = jrcxz(ea=0x1004, destination=0x1008)
        # Continue taken at first, fallthrough at second: contradictory RCX tests.
        result = project([first, second, mov_rax(ea=0x1006)], ['rax'], mode='guarded-path')
        self.assertEqual(len(result['sideExits']), 2)
        for initial in self.states():
            _, _, exit_, values = concrete(result, initial)
            self.assertEqual(values[result['pathGuard']], 0)
            self.assertIsNotNone(exit_)
        self.assertIn('no native reachability', result['scope']['coverage'])

    def test_invalid_next_address_and_same_target_are_rejected(self):
        with self.assertRaisesRegex(ProjectionError, 'Conditional branch/path mismatch'):
            project([jrcxz(), mov_rax(ea=0x1010)], ['rax'], mode='guarded-path')
        with self.assertRaisesRegex(ProjectionError, 'same-target'):
            project([jrcxz(destination=0x1002), mov_rax(ea=0x1002)], ['rax'], mode='guarded-path')

    def test_repeated_addresses_and_intermediate_indirect_rejected(self):
        jump = ins(op('BRANCH', None, target(0x1000)), ea=0x1000, mnemonic='JMP', code='ebfe')
        with self.assertRaisesRegex(ProjectionError, 'Repeated instruction addresses'):
            project([jump, copy.deepcopy(jump)], ['rax'], mode='guarded-path')
        indirect = ins(op('BRANCHIND', None, reg('rax')), ea=0x1000, mnemonic='JMP', code='ffe0')
        with self.assertRaisesRegex(ProjectionError, 'only supported at path end'):
            project([indirect, mov_rax(ea=0x1002)], ['rax'], mode='guarded-path')

    def test_mode_and_guard_root_reference_budget(self):
        for mode in (None, False, 'observed-path', {}, []):
            with self.assertRaisesRegex(ProjectionError, 'Unknown projection mode'):
                project([jrcxz()], ['rax'], mode=mode)
        result = project([jrcxz(), mov_rax()], list(GPRS), mode='guarded-path')
        internal = sum(len(node['args']) for node in result['dag']['nodes'])
        roots = len(result['initialRegisters']) + len(result['registers']) + 2 + 1
        roots += 4 * len(result['branchPoints'])
        roots += sum(len(item['registers']) + 3 for item in result['sideExits'])
        roots += 1  # final fallthrough control target
        self.assertEqual(result['dag']['references'], internal + roots)
        with patch.dict(LIMITS, dagReferences=result['dag']['references'] - 1):
            with self.assertRaisesRegex(ProjectionError, 'DAG root reference budget exceeded'):
                project([jrcxz(), mov_rax()], list(GPRS), mode='guarded-path')

    def test_guarded_without_midbranch_remains_explicit(self):
        result = project([mov_rax(ea=0x1000)], ['rax'], mode='guarded-path')
        self.assertEqual(result['sideExits'], [])
        self.assertEqual(result['branchPoints'], [])
        _, values = evaluate(result, {'rax': MASK})
        self.assertEqual(values[result['pathGuard']], 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
