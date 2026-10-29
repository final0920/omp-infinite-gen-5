"""Conservative SSA overlay: semantic, control-flow and hostile-boundary tests."""
import copy
import importlib.util
from pathlib import Path
import unittest
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'adapters/ghidra'))
spec = importlib.util.spec_from_file_location('deobfuscation', ROOT / 'adapters/ghidra/deobfuscation_analysis.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def var(identity, size=4, space='unique', offset='0x10'):
    return {'id': identity, 'size': size, 'space': space, 'offset': offset, 'kind': 'unique'}


def const(value, size=4):
    return {'size': size, 'space': 'const', 'kind': 'constant', 'value': hex(value), 'valueComplete': True}


def op(code, output=None, *inputs):
    return {'mnemonic': code, 'output': output, 'inputs': list(inputs), 'ea': '0xffff800012345678', 'index': 0}


def block(identity, instructions=(), preds=(), succs=(), true=None, false=None):
    return {'id': identity, 'instructions': list(instructions), 'preds': list(preds), 'succs': list(succs), 'trueSuccessor': true, 'falseSuccessor': false}


def graph(*blocks):
    return {'entryBlock': blocks[0]['id'], 'blocks': list(blocks), 'partial': False}


def values(result):
    return {item['ssa']: int(item['value'], 16) for item in result['constants']}


def conditional(condition):
    return op('CBRANCH', None, const(0x2000, 8), condition)


class DeobfuscationTests(unittest.TestCase):
    def test_native_low_slice_assembly_aliases_preserve_symbolic_identity(self):
        x, y = var(1, 8), var(2)
        rows = [op('SUBPIECE', var(3), x, const(0)), op('SUBPIECE', var(4), x, const(0)),
                op('INT_OR', var(5), var(3), y), op('INT_AND', var(6), var(4), y),
                op('PIECE', var(7, 8), var(8), var(5)), op('SUBPIECE', var(9), var(7, 8), const(0)),
                op('INT_ZEXT', var(10, 8), var(9)), op('SUBPIECE', var(11), var(10, 8), const(0)),
                op('INT_SUB', var(12), var(11), var(6)),
                op('SUBPIECE', var(13), x, const(4)), op('INT_AND', var(14), var(13), y),
                op('INT_SUB', var(15), var(11), var(14))]
        proofs = m.analyze_deobfuscation(graph(block(0, rows)))['expressionSimplifications']
        self.assertTrue(any(p['ssa'] == 12 and p['replacement']['opcode'] == 'INT_XOR' for p in proofs))
        self.assertFalse(any(p['ssa'] == 15 for p in proofs))

    def test_linear_mba_exact_modular_identities_and_independent_byte_oracle(self):
        x, y = var(1, 1), var(2, 1)
        rows = [op('INT_XOR', var(3, 1), x, y), op('INT_AND', var(4, 1), y, x),
                op('INT_MULT', var(5, 1), const(2, 1), var(4, 1)),
                op('INT_ADD', var(6, 1), var(3, 1), var(5, 1)),
                op('INT_ADD', var(7, 1), x, y), op('INT_SUB', var(8, 1), var(7, 1), var(5, 1)),
                op('INT_OR', var(9, 1), x, y), op('INT_SUB', var(10, 1), var(9, 1), var(4, 1)),
                op('INT_ADD', var(11, 1), var(9, 1), var(4, 1)), op('INT_ADD', var(12, 1), var(4, 1), var(3, 1))]
        proofs = {p['ssa']: p for p in m.analyze_deobfuscation(graph(block(0, rows)))['expressionSimplifications']}
        self.assertEqual({k: proofs[k]['replacement']['opcode'] for k in (6, 8, 10, 11, 12)},
                         {6: 'INT_ADD', 8: 'INT_XOR', 10: 'INT_XOR', 11: 'INT_ADD', 12: 'INT_OR'})
        for a in range(256):
            for b in range(256):
                self.assertEqual(((a ^ b) + 2 * (a & b)) & 255, (a + b) & 255)
                self.assertEqual(((a + b) - 2 * (a & b)) & 255, a ^ b)
                self.assertEqual(((a | b) - (a & b)) & 255, a ^ b)
                self.assertEqual(((a | b) + (a & b)) & 255, (a + b) & 255)
                self.assertEqual(((a ^ b) + (a & b)) & 255, a | b)

    def test_linear_mba_wrong_coefficient_or_phi_alias_is_not_equivalent(self):
        rows = [op('INT_ADD', var(3), var(1), var(2)), op('INT_AND', var(4), var(1), var(2)),
                op('INT_MULT', var(5), var(4), const(3)), op('INT_SUB', var(6), var(3), var(5)),
                op('MULTIEQUAL', var(7), var(1)), op('INT_AND', var(8), var(7), var(2)),
                op('INT_MULT', var(9), var(8), const(2)), op('INT_SUB', var(10), var(3), var(9))]
        self.assertFalse(any(p['ssa'] in (6, 10) for p in m.analyze_deobfuscation(graph(block(0, rows)))['expressionSimplifications']))

    def test_symbolic_de_morgan_and_bitwise_xor_truth_table(self):
        x, y = var(1), var(2)
        rows = [op('INT_NEGATE', var(3), x), op('INT_NEGATE', var(4), y),
                op('INT_OR', var(5), var(3), var(4)), op('INT_NEGATE', var(6), var(5)),
                op('INT_OR', var(7), x, y), op('INT_AND', var(8), x, y),
                op('INT_NEGATE', var(9), var(8)), op('INT_AND', var(10), var(7), var(9))]
        result = m.analyze_deobfuscation(graph(block(0, rows)))
        proofs = {p['ssa']: p for p in result['expressionSimplifications']}
        self.assertEqual(proofs[6]['replacement']['opcode'], 'INT_AND')
        self.assertEqual(proofs[10]['replacement']['opcode'], 'INT_XOR')
        self.assertEqual(proofs[10]['truthTableRows'], 4)
        for a in range(256):
            for b in range(256):
                self.assertEqual(((a | b) & (~(a & b) & 255)), a ^ b)
                self.assertEqual((~((~a & 255) | (~b & 255)) & 255), a & b)

    def test_local_identity_survives_unresolved_control_without_cfg_proofs(self):
        rows = [op('INT_NEGATE', var(2, 8), var(1, 8)), op('INT_NEGATE', var(3, 8), var(2, 8)),
                op('BRANCHIND', None, var(3, 8))]
        result = m.analyze_deobfuscation(graph(block(0, rows)))
        self.assertTrue(result['partial']); self.assertTrue(result['localExpressionsComplete'])
        self.assertEqual(result['branchDecisions'], [])
        self.assertEqual(result['expressionSimplifications'][0]['replacement']['inputs'][0]['id'], 1)
        self.assertEqual(len(result['indirectTransfers']), 1)
        self.assertFalse(result['indirectTransfers'][0]['targetsResolved'])

    def test_indirect_target_slice_keeps_load_address_and_distinct_ssa(self):
        rows = [op('INT_MULT', var(3, 8), var(1, 8), const(8, 8)),
                op('INT_ADD', var(4, 8), var(3, 8), const(0xffff800012340000, 8)),
                op('LOAD', var(5, 8), const(0, 8), var(4, 8)), op('BRANCHIND', None, var(5, 8))]
        result = m.analyze_deobfuscation(graph(block(0, rows)))
        transfer = result['indirectTransfers'][0]
        self.assertEqual([p['opcode'] for p in transfer['dependencies']], ['LOAD', 'INT_ADD', 'INT_MULT'])
        self.assertEqual(transfer['dependencies'][1]['inputs'][1]['value'], '0xffff800012340000')
        self.assertEqual(transfer['externalInputs'][0]['id'], 1)
        self.assertFalse(transfer['slicePartial']); self.assertFalse(transfer['targetsResolved'])

    def test_symbolic_mixed_mask_width_and_different_identity_not_guessed(self):
        rows = [op('INT_NEGATE', var(3), var(1)), op('INT_OR', var(4), var(3), var(2)),
                op('INT_NEGATE', var(5), var(4)),
                op('INT_AND', var(6), var(5), const(1)),
                op('INT_NEGATE', var(7, 8), var(3)), op('INT_NEGATE', var(8), var(7, 8))]
        proofs = m.analyze_deobfuscation(graph(block(0, rows)))['expressionSimplifications']
        self.assertFalse(any(p['ssa'] in (6, 7, 8) for p in proofs))

    def test_partial_and_work_budget_suppress_local_expression_proofs(self):
        source = graph(block(0, [op('INT_NEGATE', var(2), var(1)), op('INT_NEGATE', var(3), var(2))]))
        source['partial'] = True
        result = m.analyze_deobfuscation(source)
        self.assertEqual(result['expressionSimplifications'], [])
        source['partial'] = False
        result = m.analyze_deobfuscation(source, {'max_steps': 8})
        self.assertEqual(result['expressionSimplifications'], [])
        self.assertTrue(result['budget']['exhausted'])

    def test_dependency_slice_and_expression_depth_caps_are_explicit(self):
        rows = [op('INT_ADD', var(i + 1, 8), var(i, 8), const(1, 8)) for i in range(1, 40)]
        rows.append(op('BRANCHIND', None, var(40, 8)))
        result = m.analyze_deobfuscation(graph(block(0, rows)))
        self.assertTrue(result['indirectTransfers'][0]['slicePartial'])
        self.assertTrue(result['evidenceTruncated'])
        self.assertEqual(len(result['indirectTransfers'][0]['dependencies']), 32)

    def test_modular_width_signed_division_and_precise_address(self):
        result = m.analyze_deobfuscation(graph(block(0, [
            op('INT_ADD', var(1, 8), const(0xffffffffffffffff, 8), const(2, 8)),
            op('INT_SDIV', var(2), const(0xfffffff9), const(3)),
            op('INT_SREM', var(3), const(0xfffffff9), const(3)),
            op('INT_SLESS', var(4, 1), const(0xffffffff), const(1)),
        ])))
        self.assertEqual(values(result), {1: 1, 2: 0xfffffffe, 3: 0xffffffff, 4: 1})
        self.assertEqual(result['constants'][0]['ea'], '0xffff800012345678')
        self.assertFalse(result['rewritten']); self.assertFalse(result['executed'])

    def test_copy_alias_self_identity_does_not_use_physical_offset(self):
        a, b, copied = var(1), var(2), var(3)
        result = m.analyze_deobfuscation(graph(block(0, [op('COPY', copied, a), op('INT_XOR', var(4), copied, a), op('INT_XOR', var(5), a, b)])))
        self.assertEqual(values(result), {4: 0})

    def test_duplicate_definition_and_conflicting_space_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            m.analyze_deobfuscation(graph(block(0, [op('COPY', var(1), const(1)), op('COPY', var(1), const(2))])))
        with self.assertRaisesRegex(ValueError, 'conflicting'):
            m.analyze_deobfuscation(graph(block(0, [op('INT_XOR', var(2), var(1), var(1, space='register'))])))

    def test_opaque_parity_proof_prunes_only_proven_edge(self):
        x, adjacent, product, mask, condition = [var(i) for i in range(1, 6)]
        condition = var(5, 1)
        source = graph(block(0, [op('INT_SUB', adjacent, x, const(1)), op('INT_MULT', product, x, adjacent), op('INT_AND', mask, product, const(1)), op('INT_NOTEQUAL', condition, mask, const(0)), conditional(condition)], succs=[1, 2], true=2, false=1), block(1, preds=[0]), block(2, preds=[0]))
        snapshot = copy.deepcopy(source)
        result = m.analyze_deobfuscation(source)
        self.assertEqual(result['unreachableBlocks'], [2]); self.assertEqual(result['branchDecisions'][0]['destination'], 1)
        self.assertIn('consecutive-integer-product-is-even', [item['rule'] for item in result['simplifications']])
        self.assertEqual(source, snapshot)

    def test_x86_widen_multiply_low_subpiece_parity(self):
        x, step, sx, sy, product, low, mask = var(1), var(2), var(3, 8), var(4, 8), var(5, 8), var(6), var(7)
        result = m.analyze_deobfuscation(graph(block(0, [op('INT_ADD', step, x, const(0xffffffff)), op('INT_SEXT', sx, x), op('INT_SEXT', sy, step), op('INT_MULT', product, sx, sy), op('SUBPIECE', low, product, const(0)), op('INT_AND', mask, const(1), low)])))
        self.assertEqual(values(result)[7], 0)

    def test_bit_slices_do_not_invent_unknown_neighbor_bits(self):
        high, low, joined = var(1, 4), var(2, 4), var(3, 8)
        rows = [op('COPY', low, const(0x87654321)), op('PIECE', joined, high, low),
                op('SUBPIECE', var(4, 4), joined, const(0)),
                op('SUBPIECE', var(5, 4), joined, const(4)),
                op('SUBPIECE', var(6, 4), joined, const(2)),
                op('INT_ZEXT', var(7, 8), high), op('SUBPIECE', var(8, 4), var(7, 8), const(4))]
        result = values(m.analyze_deobfuscation(graph(block(0, rows))))
        self.assertEqual(result[4], 0x87654321); self.assertEqual(result[8], 0)
        self.assertNotIn(5, result); self.assertNotIn(6, result)

    def test_high_subpiece_does_not_inherit_low_bit_parity(self):
        rows = [op('INT_SUB', var(2, 2), var(1, 2), const(1, 2)), op('INT_MULT', var(3, 2), var(1, 2), var(2, 2)),
                op('SUBPIECE', var(4, 1), var(3, 2), const(1)), op('INT_AND', var(5, 1), var(4, 1), const(1, 1))]
        self.assertNotIn(5, values(m.analyze_deobfuscation(graph(block(0, rows)))))

    def test_exhaustive_byte_integer_constant_oracle(self):
        analyzer = m.Analyzer(graph(block(0)), {'max_steps': 250000})
        for a in range(256):
            for b in (0, 1, 2, 7, 127, 128, 254, 255):
                for code, expected in [('INT_ADD', (a + b) & 255), ('INT_SUB', (a - b) & 255),
                                       ('INT_MULT', (a * b) & 255), ('INT_XOR', a ^ b), ('INT_AND', a & b), ('INT_OR', a | b),
                                       ('INT_EQUAL', int(a == b)), ('INT_LESS', int(a < b)), ('INT_SLESS', int(m._signed(a, 8) < m._signed(b, 8)))]:
                    actual = analyzer.evaluate(op(code, var(1, 1), const(a, 1), const(b, 1)))[0]
                    self.assertEqual(actual, expected, (code, a, b))

    def test_similar_nonconsecutive_product_is_not_proven(self):
        x = var(1)
        result = m.analyze_deobfuscation(graph(block(0, [op('INT_ADD', var(2), x, const(2)), op('INT_MULT', var(3), x, var(2)), op('INT_AND', var(4), var(3), const(1))])))
        self.assertNotIn(4, values(result))

    def test_phi_uses_native_predecessor_order_and_executable_edges(self):
        source = graph(block(9, [conditional(const(1, 1))], succs=[2, 7], true=7, false=2), block(2, preds=[9], succs=[3]), block(7, preds=[9], succs=[3]), block(3, [op('MULTIEQUAL', var(4), const(77), const(22))], preds=[7, 2]))
        result = m.analyze_deobfuscation(source)
        self.assertEqual(values(result)[4], 77); self.assertEqual(result['unreachableBlocks'], [2])

    def test_conflicting_phi_widens_and_keeps_both_paths(self):
        source = graph(block(0, [conditional(var(99, 1))], succs=[1, 2], true=1, false=2), block(1, preds=[0], succs=[3]), block(2, preds=[0], succs=[3]), block(3, [op('MULTIEQUAL', var(1, 1), const(0, 1), const(1, 1)), conditional(var(1, 1))], preds=[1, 2], succs=[4, 5], true=4, false=5), block(4, preds=[3]), block(5, preds=[3]))
        result = m.analyze_deobfuscation(source)
        self.assertEqual(result['branchDecisions'], []); self.assertEqual(result['unreachableBlocks'], [])

    def test_undefined_phi_cycle_is_not_unreachable_proof(self):
        source = graph(block(0, [op('MULTIEQUAL', var(1, 1), var(1, 1)), conditional(var(1, 1))], preds=[0], succs=[0, 1], true=0, false=1), block(1, preds=[0]))
        result = m.analyze_deobfuscation(source)
        self.assertEqual(result['unreachableBlocks'], []); self.assertEqual(result['branchDecisions'], [])

    def test_dispatcher_routes_preserve_assignments_without_global_pruning(self):
        state = var(1)
        source = graph(block(0, succs=[1]), block(1, [op('MULTIEQUAL', state, const(1), const(2)), op('INT_EQUAL', var(2, 1), state, const(1)), conditional(var(2, 1))], preds=[0, 2], succs=[3, 2], true=2, false=3), block(2, preds=[1], succs=[1]), block(3, [op('INT_EQUAL', var(3, 1), state, const(2)), conditional(var(3, 1))], preds=[1], succs=[5, 4], true=4, false=5), block(4, preds=[3]), block(5, preds=[3]))
        result = m.analyze_deobfuscation(source)
        routes = {(item['predecessor'], item['destination']) for item in result['dispatcherRoutes']}
        self.assertIn((0, 2), routes); self.assertIn((2, 4), routes)
        self.assertEqual(result['branchDecisions'], [])
        self.assertTrue(all(item['stateEvidence'] for item in result['dispatcherRoutes']))

    def test_duplicate_phi_edge_is_unknown_not_guessed(self):
        result = m.analyze_deobfuscation(graph(block(0, succs=[1, 1]), block(1, [op('MULTIEQUAL', var(1), const(1), const(2))], preds=[0, 0])))
        self.assertEqual(values(result), {})

    def test_dispatcher_route_limit_is_explicit(self):
        predecessors = [block(i, preds=[0], succs=[6]) for i in range(1, 6)]
        merge = block(6, [op('MULTIEQUAL', var(1), *[const(i) for i in range(1, 6)]), op('INT_EQUAL', var(2, 1), var(1), const(1)), conditional(var(2, 1))], preds=list(range(1, 6)), succs=[7, 8], true=7, false=8)
        result = m.analyze_deobfuscation(graph(block(0, succs=list(range(1, 6))), *predecessors, merge, block(7, preds=[6]), block(8, preds=[6])), {'max_evidence': 3})
        self.assertEqual(len(result['dispatcherRoutes']), 3); self.assertTrue(result['evidenceTruncated'])
        self.assertFalse(result['partial'])

    def test_dispatcher_state_assignment_limit_is_explicit(self):
        operations = [op('MULTIEQUAL', var(i), const(i)) for i in range(1, 11)]
        operations.append(conditional(const(1, 1)))
        result = m.analyze_deobfuscation(graph(block(0, succs=[1]), block(1, operations, preds=[0], succs=[2, 3], true=2, false=3), block(2, preds=[1]), block(3, preds=[1])))
        self.assertTrue(result['evidenceTruncated']); self.assertEqual(len(result['dispatcherRoutes'][0]['stateEvidence']), 8)
        self.assertTrue(result['dispatcherRoutes'][0]['stateEvidenceTruncated'])

    def test_dispatcher_path_limit_is_explicit(self):
        blocks = [block(0, succs=[1])]
        for identity in range(1, 19):
            instructions = ([op('MULTIEQUAL', var(1), const(1))] if identity == 1 else []) + [conditional(const(1, 1))]
            blocks.append(block(identity, instructions, preds=[identity - 1], succs=[identity + 1, 99], true=identity + 1, false=99))
        blocks += [block(19, preds=[18]), block(99, preds=list(range(1, 19)))]
        result = m.analyze_deobfuscation(graph(*blocks))
        self.assertTrue(result['evidenceTruncated']); self.assertEqual(len(result['dispatcherRoutes'][0]['path']), 16)
        self.assertTrue(result['dispatcherRoutes'][0]['pathTruncated'])

    def test_faulting_division_overshift_and_wide_constants_unknown(self):
        rows = [op('INT_DIV', var(1), const(1), const(0)), op('INT_SDIV', var(2), const(0x80000000), const(0xffffffff)), op('INT_LEFT', var(3), const(1), const(32)), op('COPY', var(4, 16), const(1, 16)), op('INT_XOR', var(5), var(6, 8), var(6, 8))]
        result = m.analyze_deobfuscation(graph(block(0, rows)))
        self.assertEqual(values(result), {})

    def test_memory_calls_and_indirect_control_explicit_partial(self):
        result = m.analyze_deobfuscation(graph(block(0, [op('LOAD', var(1), const(0), var(2, 8)), op('CALLIND', var(3), var(4, 8)), op('BRANCHIND', None, var(3))]), block(1)))
        self.assertTrue(result['partial']); self.assertTrue(result['controlFlowIncomplete']); self.assertEqual(result['unreachableBlocks'], [])
        self.assertEqual({item['opcode'] for item in result['unresolved']}, {'LOAD', 'CALLIND', 'BRANCHIND'})

    def test_work_budget_withholds_all_provisional_proofs(self):
        result = m.analyze_deobfuscation(graph(block(0, [op('COPY', var(1), const(1)), op('COPY', var(2), const(2))])), {'max_steps': 1})
        self.assertTrue(result['partial']); self.assertTrue(result['budget']['exhausted'])
        self.assertEqual(result['constants'], []); self.assertEqual(result['executableEdges'], [])

    def test_native_graph_partial_withholds_proofs(self):
        source = graph(block(0, [op('COPY', var(1), const(1))])); source['partial'] = True
        self.assertEqual(m.analyze_deobfuscation(source)['constants'], [])

    def test_evidence_bound_and_unknown_boolean(self):
        rows = [op('COPY', var(i), const(i)) for i in range(1, 12)] + [op('BOOL_XOR', var(50, 1), const(2, 1), const(1, 1))]
        result = m.analyze_deobfuscation(graph(block(0, rows)), {'max_evidence': 2})
        self.assertEqual(len(result['constants']), 2); self.assertTrue(result['evidenceTruncated']); self.assertNotIn(50, values(result))

    def test_invalid_budgets(self):
        for args in ({'max_steps': True}, {'max_steps': 250001}, {'max_evidence': 0}):
            with self.assertRaises(ValueError): m.analyze_deobfuscation(graph(block(0)), args)

    def test_monitor_cancellation_propagates(self):
        class Monitor:
            def checkCancelled(self): raise RuntimeError('cancelled')
        with self.assertRaisesRegex(RuntimeError, 'cancelled'):
            m.analyze_deobfuscation(graph(block(0, [op('COPY', var(i), const(i)) for i in range(1, 130)])), monitor=Monitor())


if __name__ == '__main__': unittest.main(verbosity=2)
