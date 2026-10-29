"""Real Triton semantics, adversarial trace consistency and ELF mapping tests."""
import base64
import hashlib
from pathlib import Path
import sys
import struct
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'worker'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from trace_analysis import analyze, load_triton, parse_trace, Recovery
from kernel_image import BinaryImage, ImageFormatError
from test_kernel_image import elf_fixture, pe_fixture, patched
from trace_binding import TraceByteBinding
from trace_expression import normalize_expression
from trace_ast_normalization import normalize_ast
from trace_smt_dag import lower_query
from trace_expression_proof import prove_instance as prove_expression_instance
from trace_guard_domain import diagnose_guard_domain
from trace_recorded_image import NativeSnapshot, RecordedImageIdentity
from trace_continuation import cpuid_continuation, apply_native_continuation
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'adapters/x64dbg'))
from trace_recorder import transition_not_observed, capture_image, GPRS

TT = None


def fixture(code, snapshots, bits=32):
    blob, meta = elf_fixture()
    blob = bytearray(blob)
    blob[0x200:0x200 + sum(len(op) for op in code)] = b''.join(code)
    ea = meta['base'] + 0x200
    lines = []
    for opcode, state in zip(code, snapshots):
        regs = [state.get(name, 0) for name in 'rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split()]
        lines.append('r:' + ':'.join(hex(value) for value in regs))
        lines.append(f'i:{hex(ea)}:{len(opcode)}:{opcode.hex()}')
        last, ea = ea, ea + len(opcode)
    data = ('\n'.join(lines) + '\n').encode()
    params = {'trace_inputs': ['dil', 'sil'] if bits == 8 else ['edi', 'esi'], 'trace_output': 'al' if bits == 8 else 'eax',
              'initial_flags': '0x202', 'trace_entry': hex(meta['base'] + 0x200), 'trace_exit': hex(last),
              'traces': [{'data': base64.b64encode(data).decode(), 'sha256': hashlib.sha256(data).hexdigest()}]}
    return params, BinaryImage.from_bytes(bytes(blob))


class TraceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global TT
        TT = load_triton()

    def test_guard_domain_counterexample_preserves_all_environment_assumptions(self):
        params, image = fixture([b'\x90'], [{'rdi': 1, 'rsi': 2}])
        recovery = Recovery(TT, params, image); ast, ctx = recovery.ast, recovery.ctx
        x = ast.variable(ctx.newSymbolicVariable(64, 'x'))
        y = ast.variable(ctx.newSymbolicVariable(64, 'y'))
        rows = [(0x1000, ast.bvult(x, ast.bv(5, 64)), []),
                (0x1002, ast.equal(y, ast.bv(0, 64)), [ast.equal(x, ast.bv(0, 64))])]
        result = diagnose_guard_domain(rows, ast, recovery.proof, recovery.budget, lambda: recovery.solver_queries < 120)
        self.assertEqual(result['status'], 'not-universal')
        model = result['witness']['proof']['counterexample']
        self.assertEqual(int(model['x'], 16), 0)
        self.assertNotEqual(int(model['y'], 16), 0)
        self.assertEqual(result['fixedAssumptionCount'], 1)
        self.assertTrue(result['diagnosticOnly'])

    def test_guard_domain_actual_large_dag_partitions_without_dropping_conditions(self):
        params, image = fixture([b'\x90'], [{'rdi': 1, 'rsi': 2}])
        recovery = Recovery(TT, params, image); ast, ctx = recovery.ast, recovery.ctx
        rows = []
        for index in range(600):
            x = ast.variable(ctx.newSymbolicVariable(64, 'domain_' + str(index)))
            # Commutativity is valid for every full-width input, but the exact
            # combined DAG exceeds the production 2048-node budget.
            left = ast.bvadd(x, ast.bv(index + 1, 64))
            right = ast.bvadd(ast.bv(index + 1, 64), x)
            rows.append((0x1000 + index, ast.equal(left, right), []))
        # The first group needs an assumption stored in the LAST group. Keeping
        # only each group's own assumptions would invent a false counterexample.
        environment = ast.variable(ctx.newSymbolicVariable(64, 'cross_group_environment'))
        rows[0] = (rows[0][0], ast.equal(environment, ast.bv(0, 64)), [])
        rows[-1][2].append(ast.equal(environment, ast.bv(0, 64)))
        result = diagnose_guard_domain(rows, ast, recovery.proof, recovery.budget, lambda: recovery.solver_queries < 120)
        self.assertEqual(result['status'], 'universal-under-fixed-environment')
        self.assertEqual(result['attempts'][0]['proof']['method'], 'bounded-SMT-DAG-refusal')
        self.assertTrue(result['allConditionsCovered'])
        self.assertGreater(len(result['provedRanges']), 1)
        self.assertEqual(sum(group['end'] - group['start'] for group in result['provedRanges']), 600)
        for group in result['provedRanges']:
            self.assertEqual(result['attempts'][group['attemptIndex']]['proof']['status'], 'unsat')
        unrestricted = diagnose_guard_domain([(ea, node, []) for ea, node, _ in rows], ast,
            recovery.proof, recovery.budget, lambda: recovery.solver_queries < 120)
        self.assertEqual(unrestricted['status'], 'not-universal')
        self.assertNotEqual(int(unrestricted['witness']['proof']['counterexample']['cross_group_environment'], 16), 0)
        refused = diagnose_guard_domain(rows, ast, recovery.proof, recovery.budget, lambda: True, max_attempts=1)
        self.assertEqual(refused['status'], 'unknown')
        self.assertNotIn('allConditionsCovered', refused)

    def test_guard_domain_budget_timeout_and_single_condition_refusal_do_not_pass(self):
        params, image = fixture([b'\x90'], [{'rdi': 1, 'rsi': 2}])
        recovery = Recovery(TT, params, image); ast = recovery.ast
        row = [(0x1000, ast.equal(ast.bv(1, 64), ast.bv(1, 64)), [])]
        for reply in ({'status': 'timeout'}, {'status': 'unknown', 'method': 'bounded-SMT-DAG-refusal', 'reason': 'limit'}):
            result = diagnose_guard_domain(row, ast, lambda *_: reply, recovery.budget, lambda: True)
            self.assertEqual(result['status'], 'unknown')
            self.assertEqual(len(result['attempts']), 1)
            self.assertNotIn('allConditionsCovered', result)
        result = diagnose_guard_domain(row, ast, lambda *_: self.fail('No solver budget'), recovery.budget, lambda: False)
        self.assertEqual(result['status'], 'unknown')
        self.assertEqual(result['attempts'], [])

    def test_guard_candidate_sat_witness_reuse_rejects_only_and_preserves_full_equivalence(self):
        params, image = fixture([b'\x90'], [{'rdi': 1, 'rsi': 2}])
        recovery = Recovery(TT, params, image); ast, ctx = recovery.ast, recovery.ctx
        for alias in ('x', 'y'):
            symbol = ctx.newSymbolicVariable(64, alias)
            recovery.input_nodes[alias] = ast.variable(symbol); ctx.setConcreteVariableValue(symbol, 7 if alias == 'x' else 9)
        x, y = [dict(op='input', name=name, bits=64) for name in ('x', 'y')]
        eq = {'op': 'eq', 'args': [x, y]}; flipped = {'op': 'eq', 'args': [y, x]}
        ne = {'op': 'ne', 'args': [x, y]}
        correct = {'op': 'eq', 'args': [{'op': 'add', 'bits': 64, 'args': [x, y]}, {'op': 'constant', 'bits': 64, 'value': '0x3e9'}]}
        original = recovery.predicate_ast(correct)
        candidates = [(name, recovery.predicate_ast(value), value) for name, value in [('eq', eq), ('flipped', flipped), ('ne', ne), ('correct', correct)]]
        guard, node, search = recovery.search_guard_candidates([(0x1000, original, [])], candidates, [])
        self.assertEqual(guard['expression'], 'correct'); self.assertEqual(guard['proof']['status'], 'unsat')
        self.assertGreaterEqual(len(search['rejectedByWitness']), 1)
        self.assertLess(len(search['attempts']), len(candidates))
        self.assertEqual(recovery.proof(ast.lxor([node, original]))['status'], 'unsat')
        for rejected in search['rejectedByWitness']:
            witness = search['witnesses'][rejected['witnessIndex']]
            self.assertEqual(search['attempts'][witness['sourceAttempt']]['proof']['status'], 'sat')
            fixed = [ast.equal(recovery.input_nodes[name], ast.bv(int(value, 16), 64)) for name, value in witness['inputs'].items()]
            equal_to_guard = ast.lnot(ast.lxor([original, recovery.predicate_ast(rejected['conditionExpression'])]))
            self.assertEqual(recovery.proof(equal_to_guard, fixed)['status'], 'unsat')
        self.assertEqual([ctx.getConcreteVariableValue(recovery.input_nodes[name].getSymbolicVariable()) for name in ('x', 'y')], [7, 9])

    def test_guard_candidate_model_evaluation_keeps_width_sign_and_unknowns(self):
        params, image = fixture([b'\x90'], [{'rdi': 1, 'rsi': 2}])
        recovery = Recovery(TT, params, image)
        for bits in (8, 16, 32, 64):
            recovery.input_nodes = {name: recovery.ast.variable(recovery.ctx.newSymbolicVariable(bits, name)) for name in ('x', 'y')}
            x, y = [dict(op='input', name=name, bits=bits) for name in ('x', 'y')]
            model = {'x': hex(1 << (bits - 1)), 'y': '0x0'}
            self.assertIs(recovery.candidate_value_at_model({'op': 'slt', 'args': [x, y]}, model), True)
            self.assertIs(recovery.candidate_value_at_model({'op': 'ult', 'args': [x, y]}, model), False)
            self.assertIsNone(recovery.candidate_value_at_model({'op': 'eq', 'args': [x, y]}, {'x': model['x']}))
            self.assertIsNone(recovery.candidate_value_at_model({'op': 'eq', 'args': [x, {**y, 'op': 'environment'}]}, model))
            self.assertIsNone(recovery.candidate_value_at_model({'op': 'eq', 'args': [x, y]}, {**model, 'x': hex(1 << bits)}))

    def test_xor_full_width_proof_and_no_native_execution(self):
        params, image = fixture([b'\x89\xf8', b'\x31\xf0'], [{'rdi': 0xffffffff, 'rsi': 2}, {'rax': 0xffffffff, 'rdi': 0xffffffff, 'rsi': 2}])
        result = analyze(params, TT, image)
        self.assertEqual(result['recoveredExpression']['op'], 'xor')
        self.assertEqual(result['paths'][0]['outputProof']['status'], 'unsat')
        self.assertFalse(result['nativeTargetExecuted'])
        self.assertFalse(result['wholeBinaryVerified'])
        self.assertTrue(result['paths'][0]['binaryBinding']['allInstructionBytesMatch'])

    def test_recorded_image_only_replays_without_an_original_file_and_marks_unknown_comparison(self):
        blob, meta = pe_fixture()
        module_size = struct.unpack_from('<I', blob, 0x80 + 80)[0]
        code = b'\x48\x89\xc8'
        native_bytes = blob[:0x200] + code
        with tempfile.TemporaryDirectory() as directory:
            snapshot_file = Path(directory) / 'recorded.bin'; snapshot_file.write_bytes(native_bytes)
            target = str(Path(directory) / 'missing-original.exe')
            base = 0x7ff000000000; entry = base + 0x1000
            snapshot = {'schema': 'ig5.native-main-image.v1', 'targetSha256': 'a' * 64, 'recordedTargetPath': target,
                'runtimeBase': hex(base), 'moduleSize': module_size, 'path': str(snapshot_file), 'bytes': len(native_bytes),
                'sha256': hashlib.sha256(native_bytes).hexdigest(), 'partial': True, 'runId': 'owned', 'threadId': 1, 'stopSeq': 1,
                'sourceReportId': '11111111-1111-4111-8111-111111111111', 'sourceReportSha256': 'b' * 64,
                'regions': [{'rva': '0x0', 'bytes': 0x200, 'blobOffset': 0}, {'rva': '0x1000', 'bytes': len(code), 'blobOffset': 0x200}]}
            image = RecordedImageIdentity(snapshot, 'a' * 64, target)
            registers = [0, 0, 0x11, 0x22] + [0] * 12
            final = list(registers); final[0] = 0x11
            data = ('h:ig5-native-x64-v2\nr:' + ':'.join(hex(n) for n in registers) + '\ne:0x202\n'
                + 'i:' + hex(entry) + ':3:4889c8\nf:' + ':'.join(hex(n) for n in final + [entry + 3, 0x202]) + '\n').encode()
            params = {'target': target, 'target_sha256': 'a' * 64, 'trace_target_sha256': 'a' * 64, 'trace_image_only': True,
                'trace_entry': hex(entry), 'trace_exit': hex(entry), 'trace_runtime_base': hex(base), 'initial_flags': '0x202',
                'trace_inputs': ['rcx', 'rdx'], 'trace_output': 'rax',
                'traces': [{'data': base64.b64encode(data).decode(), 'sha256': hashlib.sha256(data).hexdigest(), 'loaded_image': snapshot}]}
            result = analyze(params, TT, image); binding = result['paths'][0]['binaryBinding']
            self.assertFalse(Path(target).exists())
            self.assertEqual(result['recoveredExpression'], {'op': 'input', 'name': 'x', 'bits': 64})
            self.assertFalse(result['targetVerification']['originalFileRead'])
            self.assertFalse(result['nativeTargetExecuted']); self.assertFalse(result['wholeBinaryVerified'])
            self.assertEqual(binding['capturedImageMatchedInstructions'], 1)
            self.assertTrue(binding['allInstructionBytesMatch'])
            for key in ('originalFileMatchedInstructions', 'allOriginalFileInstructionBytesMatch', 'preferredImageBase'):
                self.assertIsNone(binding[key])
            self.assertEqual(binding['originalFileVerification'], 'not-performed-recorded-image-only')
            self.assertEqual(binding['recordedHeader']['machine'], 'AMD64')
            other_base = 0x7fe000000000; other_entry = other_base + 0x1000
            other_data = data.replace(hex(entry).encode(), hex(other_entry).encode()).replace(hex(entry + 3).encode(), hex(other_entry + 3).encode()).replace(b'0x202', b'0x246')
            other_snapshot = {**snapshot, 'runtimeBase': hex(other_base), 'runId': 'other', 'threadId': 2, 'stopSeq': 4}
            first = {**params['traces'][0], 'recording': {'entry': hex(entry), 'exit': hex(entry), 'runtimeBase': hex(base), 'initialFlags': '0x202'}}
            second = {'data': base64.b64encode(other_data).decode(), 'sha256': hashlib.sha256(other_data).hexdigest(), 'loaded_image': other_snapshot,
                'recording': {'entry': hex(other_entry), 'exit': hex(other_entry), 'runtimeBase': hex(other_base), 'initialFlags': '0x246'}}
            independent = analyze({**params, 'traces': [first, second]}, TT, image)
            self.assertEqual(len(independent['paths']), 2)
            self.assertEqual(independent['paths'][1]['binaryBinding']['runtimeBase'], hex(other_base))
            self.assertTrue(independent['paths'][1]['binaryBinding']['allInstructionBytesMatch'])
            self.assertIsNone(independent['paths'][1]['binaryBinding']['originalFileMatchedInstructions'])
            self.assertFalse(independent['proofScope']['functionReturnEstablishedByReplay'])
            with self.assertRaisesRegex(ValueError, 'source mode'):
                analyze({**params, 'trace_image_only': False}, TT, image)
            with self.assertRaisesRegex(ValueError, 'path identity'):
                TraceByteBinding(image, base, {**snapshot, 'recordedTargetPath': target + '.other'})
            with self.assertRaisesRegex(ValueError, 'every path'):
                TraceByteBinding(image, base)
            wrong = bytearray(native_bytes); wrong[0x84:0x86] = b'\x4c\x01'; snapshot_file.write_bytes(wrong)
            bad = {**snapshot, 'sha256': hashlib.sha256(wrong).hexdigest()}
            with self.assertRaisesRegex(ValueError, 'AMD64'):
                RecordedImageIdentity(bad, 'a' * 64, target)

    def test_recorded_image_sparse_holes_tampering_and_pe_size_are_not_filled(self):
        blob, _ = pe_fixture(); module_size = struct.unpack_from('<I', blob, 0x80 + 80)[0]
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / 'snapshot.bin'; filename.write_bytes(blob[:0x200] + b'\x90\xc3')
            snapshot = {'schema': 'ig5.native-main-image.v1', 'targetSha256': 'a' * 64, 'runtimeBase': '0x140000000',
                'path': str(filename), 'bytes': 0x202, 'sha256': hashlib.sha256(filename.read_bytes()).hexdigest(), 'moduleSize': module_size,
                'regions': [{'rva': '0x0', 'bytes': 0x200, 'blobOffset': 0}, {'rva': '0x1000', 'bytes': 1, 'blobOffset': 0x200}, {'rva': '0x1001', 'bytes': 1, 'blobOffset': 0x201}]}
            view = NativeSnapshot(snapshot, 'a' * 64, 0x140000000)
            self.assertEqual(view.read_rva(0x1000, 2), b'\x90\xc3')
            with self.assertRaisesRegex(ValueError, 'outside captured'): view.read_rva(0x1ff, 2)
            self.assertEqual(view.pe64_header()['machine'], 'AMD64')
            with self.assertRaisesRegex(ValueError, 'digest'): NativeSnapshot({**snapshot, 'sha256': '0' * 64}, 'a' * 64, 0x140000000)
            bad = bytearray(filename.read_bytes()); struct.pack_into('<I', bad, 0x80 + 80, module_size + 4096); filename.write_bytes(bad)
            wrong_size = NativeSnapshot({**snapshot, 'sha256': hashlib.sha256(bad).hexdigest()}, 'a' * 64, 0x140000000)
            with self.assertRaisesRegex(ValueError, 'SizeOfImage'): wrong_size.pe64_header()

    def test_compact_flags_preserve_symbolic_and_observed_environment_bits(self):
        params, image = fixture([b'\x90'], [{'rdi': 1, 'rsi': 2}])
        recovery = Recovery(TT, params, image); ast = recovery.ast; ctx = recovery.ctx
        positions = {'cf': 0, 'pf': 2, 'af': 4, 'zf': 6, 'sf': 7, 'tf': 8, 'if': 9, 'df': 10,
            'of': 11, 'nt': 14, 'ac': 18, 'vif': 19, 'vip': 20, 'id': 21}
        bits = ctx.registers.eflags.getBitSize()
        mask = sum(1 << bit for bit in positions.values()) | 2
        for flags in (0x202, 0x246, 0x243ed5):
            ctx.concretizeAllRegister(); ctx.setConcreteRegisterValue(ctx.registers.eflags, flags)
            for symbolic_names in ((), ('cf',), ('cf', 'zf', 'af', 'tf', 'id')):
                ctx.concretizeAllRegister()
                symbols = [ctx.symbolizeRegister(getattr(ctx.registers, name), 'flag_' + name) for name in symbolic_names]
                # Compare against a separately built full architectural layout.
                original = ast.bv(ctx.getConcreteRegisterValue(ctx.registers.eflags) & ~mask, bits)
                for name, bit in positions.items():
                    original = ast.bvor(original, ast.bvshl(ast.zx(bits - 1, ctx.getRegisterAst(getattr(ctx.registers, name))), ast.bv(bit, bits)))
                compact = recovery.flags_ast()
                self.assertEqual(recovery.proof(ast.distinct(original, compact))['status'], 'unsat')
                self.assertEqual(set(recovery.variables(original)), set(recovery.variables(compact)))
                for value in (0, 1):
                    for symbol in symbols: ctx.setConcreteVariableValue(symbol, value)
                    self.assertEqual(compact.evaluate(), original.evaluate())

    def test_proof_reuse_keeps_different_assumptions_separate(self):
        params, image = fixture([b'\x90'], [{'rdi': 1, 'rsi': 2}])
        recovery = Recovery(TT, params, image); ast = recovery.ast
        sv = recovery.ctx.symbolizeRegister(recovery.ctx.registers.edi, 'x'); x = ast.variable(sv)
        query = ast.equal(x, ast.bv(0, 32)); zero = ast.equal(x, ast.bv(0, 32)); one = ast.equal(x, ast.bv(1, 32))
        self.assertEqual(recovery.proof(query, [zero])['status'], 'sat')
        self.assertEqual(recovery.proof(query, [one])['status'], 'unsat')
        count = recovery.solver_queries
        for _ in range(160):
            self.assertEqual(recovery.proof(query, [zero])['status'], 'sat')
            self.assertEqual(recovery.proof(query, [one])['status'], 'unsat')
        self.assertEqual(recovery.solver_queries, count)
        self.assertEqual(recovery.proof_cache_hits, 320)

    def test_explicit_long_recording_keeps_default_and_hard_bounds(self):
        # Owned loop CPU semantics beyond the default budget; this does not
        # claim a native run or prove that this loop returns.
        params, image = fixture([b'\xeb\xfe'], [{'rdi': 1, 'rsi': 2}])
        first = base64.b64decode(params['traces'][0]['data']).decode().splitlines()
        instruction = first[1]
        data = ('h:ig5-native-x64-v2\n' + first[0] + '\ne:0x202\n' + instruction + '\n' +
                ('d:0x0\ne:0x202\n' + instruction + '\n') * 50000).encode()
        params['traces'] = [{'data': base64.b64encode(data).decode(), 'sha256': hashlib.sha256(data).hexdigest()}]
        with self.assertRaisesRegex(ValueError, 'instruction budget'): analyze(params, TT, image)
        params['max_instructions'] = 60000
        result = analyze(params, TT, image)
        self.assertEqual(result['paths'][0]['instructionCount'], 50001)
        self.assertTrue(result['paths'][0]['binaryBinding']['allInstructionBytesMatch'])
        self.assertEqual(result['budgets']['undefinedVariablesPerPath'], 40000)
        self.assertEqual(result['budgets']['solverQueries'], 128)
        self.assertFalse(result['wholeBinaryVerified'])
        params['max_instructions'] = 100001
        with self.assertRaisesRegex(ValueError, 'max_instructions'): analyze(params, TT, image)

    def test_hardware_outputs_also_enforce_the_independent_state_budget(self):
        params, image = fixture([b'\x0f\x31', b'\x89\xf8'], [{'rdi': 1, 'rsi': 2}, {'rax': 11, 'rdx': 0, 'rdi': 1, 'rsi': 2}])
        recovery = Recovery(TT, params, image); recovery.unknown_budget = 1
        with self.assertRaisesRegex(ValueError, 'independent-state variable budget'): recovery.replay(params['traces'][0], 0)

    def test_compositional_mba_and_split_output_normalization(self):
        params, image = fixture([b'\x90'], [{'rdi': 1, 'rsi': 2}])
        recovery = Recovery(TT, params, image); ast = recovery.ast
        for alias, reg in [('x', 'rcx'), ('y', 'rdx')]:
            sv = recovery.ctx.symbolizeRegister(getattr(recovery.ctx.registers, reg), alias)
            recovery.input_nodes[alias] = ast.variable(sv)
        def raw(bits):
            x, y = [{'op': 'input', 'name': name, 'bits': bits} for name in ('x', 'y')]
            op = lambda name, args: {'op': name, 'bits': bits, 'args': args}
            inv = lambda node: op('not', [node])
            mba = inv(op('or', [inv(op('or', [x, y])), inv(op('or', [inv(x), inv(y)]))]))
            c = lambda value: {'op': 'constant', 'bits': bits, 'value': hex(value & ((1 << bits) - 1))}
            return op('add', [c(157 * 23), op('mul', [c(157), mba])])
        base = raw(32)
        value = {'op': 'concat', 'bits': 64, 'args': [{'op': 'constant', 'bits': 32, 'value': '0x0'},
            {'op': 'extract', 'bits': 24, 'low': 8, 'args': [base]}, raw(8)]}
        normalized, steps, _ = normalize_expression(value, recovery.expression_ast,
            lambda left, right: recovery.proof(ast.distinct(left, right)), recovery.budget)
        self.assertEqual(normalized['op'], 'zx')
        self.assertTrue(steps and all(step['proof']['status'] == 'unsat' for step in steps))
        self.assertTrue({'exclusive-union', 'adjacent-width-projections', 'zero-prefix-extension'} <= {step['rule'] for step in steps})
        x, y = [ast.extract(31, 0, recovery.input_nodes[name]) for name in ('x', 'y')]
        expected = ast.zx(32, ast.bvmul(ast.bvadd(ast.bvxor(x, y), ast.bv(23, 32)), ast.bv(157, 32)))
        self.assertEqual(recovery.proof(ast.distinct(recovery.expression_ast(normalized), expected))['status'], 'unsat')
        rejected, rejected_steps, attempts = normalize_expression(value, recovery.expression_ast,
            lambda left, right: {'status': 'timeout'}, recovery.budget)
        self.assertEqual(rejected, value); self.assertFalse(rejected_steps); self.assertTrue(attempts)
        def expired(left, right): raise ValueError('Trace recovery deadline exceeded')
        with self.assertRaisesRegex(ValueError, 'deadline'): normalize_expression(value, recovery.expression_ast, expired, recovery.budget)

    def test_complemented_word_slices_recover_mask_with_independent_smt(self):
        params, image = fixture([b'\x90'], [{'rdi': 1, 'rsi': 2}])
        recovery = Recovery(TT, params, image); ast = recovery.ast
        for alias, reg in [('x', 'rcx'), ('y', 'rdx')]:
            sv = recovery.ctx.symbolizeRegister(getattr(recovery.ctx.registers, reg), alias)
            recovery.input_nodes[alias] = ast.variable(sv)
        base = {'op': 'add', 'bits': 64, 'args': [
            {'op': 'input', 'name': name, 'bits': 64} for name in ('x', 'y')]}
        mask = 0xd6e8feb86659fd93
        # Unequal runs of complemented/uncomplemented bits, with a narrowed
        # arithmetic low slice, reproduce the actual mutation output pattern.
        parts, high = [], 63
        while high >= 0:
            complement = (mask >> high) & 1; low = high
            while low > 0 and ((mask >> (low - 1)) & 1) == complement: low -= 1
            width = high - low + 1
            piece = {'op': 'extract', 'low': low, 'bits': width, 'args': [base]} if low else {
                'op': 'add', 'bits': width, 'args': [
                    {'op': 'input', 'name': name, 'bits': width} for name in ('x', 'y')]}
            parts.append({'op': 'not', 'bits': width, 'args': [piece]} if complement else piece)
            high = low - 1
        value = {'op': 'concat', 'bits': 64, 'args': parts}
        normalized, steps, _ = normalize_expression(value, recovery.expression_ast,
            lambda left, right: recovery.proof(ast.distinct(left, right)), recovery.budget)
        expected = ast.bvxor(ast.bvadd(recovery.input_nodes['x'], recovery.input_nodes['y']), ast.bv(mask, 64))
        self.assertEqual(normalized['op'], 'xor')
        self.assertEqual(recovery.proof(ast.distinct(recovery.expression_ast(normalized), expected))['status'], 'unsat')
        self.assertTrue(steps and all(step['proof']['status'] == 'unsat' for step in steps))
        rejected, rejected_steps, _ = normalize_expression(value, recovery.expression_ast,
            lambda left, right: {'status': 'timeout'}, recovery.budget)
        self.assertEqual(rejected, value); self.assertFalse(rejected_steps)
        # A reordered slice is different semantics, even with identical base.
        import copy
        wrong = copy.deepcopy(value)
        piece = wrong['args'][0]['args'][0] if wrong['args'][0]['op'] == 'not' else wrong['args'][0]
        piece['low'] -= 1
        unchanged, wrong_steps, _ = normalize_expression(wrong, recovery.expression_ast,
            lambda left, right: recovery.proof(ast.distinct(left, right)), recovery.budget)
        self.assertEqual(unchanged, wrong); self.assertFalse(wrong_steps)

    def test_preorder_shared_rotate_mba_chain_has_local_certificates(self):
        params, image = fixture([b'\x90'], [{'rdi': 1, 'rsi': 2}])
        recovery = Recovery(TT, params, image); ast = recovery.ast
        for name, reg in [('x', 'rcx'), ('y', 'rdx')]:
            symbol = recovery.ctx.symbolizeRegister(getattr(recovery.ctx.registers, reg), name)
            recovery.input_nodes[name] = ast.variable(symbol)
        x, y = [recovery.input_nodes[name] for name in ('x', 'y')]
        state, expected = x, x
        product = ast.bvmul(y, ast.bv(0x9e3779b97f4a7c15, 64))
        for index in range(8):
            word = ast.bvadd(ast.bvadd(state, y), ast.bv(index, 64))
            shifted = ast.extract(127, 64, ast.bvshl(ast.concat([word, word]), ast.bv(7, 128)))
            state = ast.bvand(ast.bvnot(ast.bvand(shifted, product)), ast.bvnot(ast.bvand(ast.bvnot(shifted), ast.bvnot(product))))
            expected = ast.bvxor(ast.bvrol(ast.bvadd(ast.bvadd(expected, y), ast.bv(index, 64)), ast.bv(7, 64)), product)
        normalized, steps, _ = normalize_ast(state, TT, ast, lambda a, b: recovery.proof(ast.distinct(a, b)), recovery.budget)
        self.assertEqual(len(steps), 16)
        self.assertTrue(all(step['proof']['status'] == 'unsat' for step in steps))
        self.assertEqual(recovery.proof(ast.distinct(normalized, expected))['status'], 'unsat')
        self.assertEqual(set(recovery.variables(normalized)), set(recovery.variables(state)))
        # Complemented operands may have lost explicit double-NOT nodes during
        # upstream simplification. Structural matching must work in either direction.
        inverted_union = ast.bvand(ast.bvnot(ast.bvand(ast.bvnot(x), ast.bvnot(y))), ast.bvnot(ast.bvand(x,y)))
        canonical, certificates, _ = normalize_ast(inverted_union, TT, ast,
            lambda a,b: recovery.proof(ast.distinct(a,b)), recovery.budget)
        self.assertEqual(recovery.proof(ast.distinct(canonical, ast.bvxor(x,y)))['status'], 'unsat')
        self.assertTrue(certificates and all(row['proof']['status']=='unsat' for row in certificates))
        small = ast.extract(7,0,x)
        for count in (0,1,7):
            right = ast.extract(7,0,ast.bvlshr(ast.concat([small,small]),ast.bv(count,16)))
            rotated, certificates, _ = normalize_ast(right, TT, ast,
                lambda a,b: recovery.proof(ast.distinct(a,b)), recovery.budget)
            self.assertEqual(recovery.proof(ast.distinct(rotated,ast.bvror(small,ast.bv(count,8))))['status'],'unsat')
            self.assertTrue(all(row['proof']['status']=='unsat' for row in certificates))
            if count: self.assertTrue(certificates)
        # Failed local proofs do not permit a replacement or hide the budget.
        rejected, rejected_steps, _ = normalize_ast(state, TT, ast, lambda a, b: {'status': 'timeout'}, recovery.budget)
        self.assertTrue(rejected.equalTo(state)); self.assertFalse(rejected_steps)
        # Dissimilar words or shifts >= one word are not rotations.
        for wrong in (ast.extract(127,64,ast.bvshl(ast.concat([x,y]),ast.bv(7,128))),
                      ast.extract(127,64,ast.bvshl(ast.concat([x,x]),ast.bv(64,128)))):
            unchanged, rewrites, _ = normalize_ast(wrong, TT, ast, lambda a, b: recovery.proof(ast.distinct(a, b)), recovery.budget)
            self.assertTrue(unchanged.equalTo(wrong)); self.assertFalse(rewrites)

    def test_nonretired_boundary_does_not_discard_real_effects(self):
        before = {name: 1 for name in GPRS}; before.update(rip=0x1000, eflags=0x300)
        after = {**before, 'eflags': 0x200}
        self.assertTrue(transition_not_observed(0x1000, 0x1003, before, after, False))
        self.assertFalse(transition_not_observed(0x1000, 0x1000, before, after, False))
        self.assertFalse(transition_not_observed(0x1000, 0x1003, before, after, True))
        self.assertTrue(transition_not_observed(0x1000, 0x1003, before, after, True, stores_unchanged=True))
        self.assertFalse(transition_not_observed(0x1000, 0x1000, before, after, True, stores_unchanged=True))
        self.assertFalse(transition_not_observed(0x1000, 0x1003, before, {**after, 'rax': 2}, True, stores_unchanged=True))
        self.assertFalse(transition_not_observed(0x1000, 0x1003, before, {**after, 'rax': 2}, False))
        self.assertFalse(transition_not_observed(0x1000, 0x1003, before, {**after, 'eflags': 0x201}, False))

    def test_shared_reference_shift_rotations_have_universal_local_certificates(self):
        params, image = fixture([b'\x90'], [{'rdi': 1, 'rsi': 2}])
        for bits in (8, 16, 32, 64):
            recovery = Recovery(TT, params, image); ast = recovery.ast
            x = ast.variable(recovery.ctx.newSymbolicVariable(bits, 'subject'))
            def rotate(word, count):
                return ast.bvor(ast.bvshl(word, ast.bv(count, bits)), ast.bvlshr(word, ast.bv(bits - count, bits)))
            raw = rotate(rotate(x, 3), 5)
            for _ in range(20): raw = ast.reference(recovery.ctx.newSymbolicExpression(raw))
            normalized, steps, _ = normalize_ast(raw, TT, ast,
                lambda a, b: recovery.proof(ast.distinct(a, b)), recovery.budget, recovery.prove_ast_instance)
            self.assertTrue(steps)
            self.assertTrue(all(step['proof']['status'] == 'unsat' for step in steps))
            self.assertTrue(all(step['proof']['method'] == 'SMT-universal-local-template-and-exact-instantiation' for step in steps))
            expected = ast.bvrol(x, ast.bv(8 % bits, bits))
            self.assertEqual(recovery.proof(ast.distinct(normalized, expected))['status'], 'unsat')
            self.assertEqual(set(recovery.variables(normalized)), set(recovery.variables(x)))
            # Failed template proof cannot authorize the arithmetic replacement.
            rejected, rewrites, _ = normalize_ast(raw, TT, ast, lambda a,b: {'status':'timeout'}, recovery.budget,
                lambda *args: {'status':'timeout'})
            self.assertFalse(rewrites)
            self.assertEqual(recovery.proof(ast.distinct(rejected, raw))['status'], 'unsat')

    def test_shift_rotation_refuses_different_subjects_counts_and_operators(self):
        params, image = fixture([b'\x90'], [{'rdi': 1, 'rsi': 2}]); recovery = Recovery(TT, params, image); ast = recovery.ast
        x = ast.variable(recovery.ctx.newSymbolicVariable(64, 'x')); y = ast.variable(recovery.ctx.newSymbolicVariable(64, 'y'))
        for raw in (ast.bvor(ast.bvshl(x,ast.bv(7,64)),ast.bvlshr(y,ast.bv(57,64))),
                    ast.bvor(ast.bvshl(x,ast.bv(7,64)),ast.bvlshr(x,ast.bv(56,64))),
                    ast.bvxor(ast.bvshl(x,ast.bv(7,64)),ast.bvlshr(x,ast.bv(57,64))),
                    ast.bvor(ast.bvshl(x,y),ast.bvlshr(x,ast.bvsub(ast.bv(64,64),y)))):
            normalized, steps, _ = normalize_ast(raw, TT, ast,
                lambda a,b: recovery.proof(ast.distinct(a,b)), recovery.budget, recovery.prove_ast_instance)
            self.assertTrue(normalized.equalTo(raw)); self.assertFalse(steps)

    def test_reference_expansion_consumes_shared_normalization_budget(self):
        params, image = fixture([b'\x90'], [{'rdi': 1, 'rsi': 2}]); recovery=Recovery(TT,params,image);ast=recovery.ast
        node=ast.variable(recovery.ctx.newSymbolicVariable(64,'x'))
        for _ in range(20):node=ast.reference(recovery.ctx.newSymbolicExpression(node))
        budget=[4];result,steps,_=normalize_ast(node,TT,ast,lambda a,b: recovery.proof(ast.distinct(a,b)),recovery.budget,work_budget=budget)
        self.assertLessEqual(budget[0],0);self.assertFalse(steps)
        self.assertEqual(recovery.proof(ast.distinct(result,node))['status'],'unsat')

    def test_smt_dag_matches_direct_solver_and_preserves_sat_witnesses(self):
        for bits in (8, 16, 32, 64):
            ctx = TT.TritonContext(TT.ARCH.X86_64);ast=ctx.getAstContext()
            sx=ctx.newSymbolicVariable(bits,'x');sy=ctx.newSymbolicVariable(bits,'y');x=ast.variable(sx);y=ast.variable(sy)
            word=ast.bvadd(x,y);ref=ast.reference(ctx.newSymbolicExpression(word))
            cases=[ast.distinct(ref,word), ast.distinct(ast.bvadd(x,ast.bv(1,bits)),x),
                ast.land([ast.bvult(x,y),ast.equal(ast.bvxor(x,y),ast.bv(3,bits))]),
                ast.distinct(ast.ite(ast.bvslt(x,y),x,y),ast.ite(ast.bvslt(x,y),x,y)),
                ast.lxor([ast.equal(x,y),ast.distinct(x,y)])]
            for index,query in enumerate(cases):
                direct=ctx.getModel(query,status=True,timeout=2000)[1]
                lowered,meta=lower_query(ctx,TT,query,lambda:None,'oracle_'+str(index)+'_')
                model,status,_=ctx.getModel(lowered,status=True,timeout=2000)
                self.assertEqual(status,direct);self.assertGreater(meta['definitions'],0)
                if status==TT.SOLVER_STATE.SAT:
                    for value in model.values():
                        if value.getVariable().getId() in (sx.getId(),sy.getId()):ctx.setConcreteVariableValue(value.getVariable(),value.getValue())
                    self.assertTrue(query.evaluate())

    def test_smt_dag_budget_refusal_and_original_variables_remain_unchanged(self):
        ctx=TT.TritonContext(TT.ARCH.X86_64);ast=ctx.getAstContext();sv=ctx.newSymbolicVariable(64,'x');x=ast.variable(sv)
        query=ast.distinct(ast.bvadd(x,ast.bv(1,64)),x);original=str(query)
        with self.assertRaisesRegex(ValueError,'node budget'):lower_query(ctx,TT,query,lambda:None,'limit_',node_limit=2)
        self.assertEqual(str(query),original);self.assertEqual(ctx.getConcreteVariableValue(sv),0)
        ref=ast.reference(ctx.newSymbolicExpression(query))
        with self.assertRaisesRegex(ValueError,'reference budget|traversal budget'):lower_query(ctx,TT,ref,lambda:None,'limit_',reference_limit=0)

    def test_reconciliation_dag_refusal_uses_complete_original_query(self):
        params,image=fixture([b'\x90'],[{'rdi':5,'rsi':2}]);recovery=Recovery(TT,params,image);ctx=recovery.ctx;ast=recovery.ast
        x=ctx.newSymbolicVariable(64,'x');unknown=ctx.newSymbolicVariable(64,'undefined')
        node=ast.bvadd(ast.variable(x),ast.variable(unknown))
        ctx.setConcreteVariableValue(x,5);recovery.remember_unknown(unknown)
        with patch('trace_analysis.lower_query',side_effect=ValueError('SMT DAG node budget exceeded')):
            refusal=recovery.proof(ast.equal(node,ast.bv(9,64)))
            self.assertEqual(refusal['status'],'unknown');self.assertEqual(recovery.solver_queries,0)
            observations=recovery.reconcile(node,9)
        self.assertEqual(ctx.getConcreteVariableValue(x),5);self.assertEqual(ctx.getConcreteVariableValue(unknown),4)
        self.assertEqual(node.evaluate(),9);self.assertEqual(observations,[{'variable':'undefined','value':'0x4'}])
        self.assertEqual(recovery.solver_queries,1);self.assertIn(unknown.getId(),recovery.frozen_unknown)

    def test_modular_normal_forms_have_full_width_universal_and_actual_proofs(self):
        params,image=fixture([b'\x90'],[{'rdi':1,'rsi':2}])
        for bits in (8,16,32,64):
            recovery=Recovery(TT,params,image);ast=recovery.ast
            for name in ('x','y'):
                sv=recovery.ctx.newSymbolicVariable(bits,name);recovery.input_nodes[name]=ast.variable(sv)
            inputs=[{'op':'input','bits':bits,'name':name}for name in ('x','y')]
            constant=lambda n:{'op':'constant','bits':bits,'value':hex(n)}
            for op in ('add','mul','and','or','xor'):
                original={'op':op,'bits':bits,'args':[inputs[1],{'op':op,'bits':bits,'args':[constant(3),inputs[0]]},constant(5)]}
                normalized,steps,_=normalize_expression(original,recovery.expression_ast,
                    lambda a,b:recovery.proof(ast.distinct(a,b)),recovery.budget,
                    lambda a,b,r,m:prove_expression_instance(recovery.ctx,ast,a,b,r,m,recovery.proof,recovery.expression_templates))
                self.assertTrue(steps);self.assertTrue(all(s['proof']['status']=='unsat' for s in steps))
                self.assertTrue(all(s['proof']['method']=='SMT-universal-expression-template-and-exact-instantiation' for s in steps))
                self.assertEqual(recovery.proof(ast.distinct(recovery.expression_ast(original),recovery.expression_ast(normalized)))['status'],'unsat')
                for node in recovery.input_nodes.values():self.assertEqual(recovery.ctx.getConcreteVariableValue(node.getSymbolicVariable()),0)

    def test_expression_shift_or_and_nested_rotations_keep_arbitrary_subject(self):
        params,image=fixture([b'\x90'],[{'rdi':1,'rsi':2}]);recovery=Recovery(TT,params,image);ast=recovery.ast
        for name in ('x','y'):
            sv=recovery.ctx.newSymbolicVariable(64,name);recovery.input_nodes[name]=ast.variable(sv)
        x,y=[{'op':'input','name':n,'bits':64}for n in ('x','y')]
        c=lambda n:{'op':'constant','bits':64,'value':hex(n)}
        subject={'op':'add','bits':64,'args':[x,y]}
        inner={'op':'or','bits':64,'args':[{'op':'lshr','bits':64,'args':[subject,c(58)]},{'op':'shl','bits':64,'args':[subject,c(6)]}]}
        original={'op':'rol','bits':64,'args':[inner,c(1)]}
        normalized,steps,_=normalize_expression(original,recovery.expression_ast,
            lambda a,b:recovery.proof(ast.distinct(a,b)),recovery.budget,
            lambda a,b,r,m:prove_expression_instance(recovery.ctx,ast,a,b,r,m,recovery.proof,recovery.expression_templates))
        self.assertEqual(normalized['op'],'rol');self.assertEqual(normalized['args'][1]['value'],'0x7')
        self.assertIn('complementary-shift-rotation',[s['rule']for s in steps]);self.assertIn('consecutive-constant-rotations',[s['rule']for s in steps])
        self.assertEqual(recovery.proof(ast.distinct(recovery.expression_ast(original),recovery.expression_ast(normalized)))['status'],'unsat')
        self.assertEqual(set(recovery.variables(recovery.expression_ast(normalized))),{n.getSymbolicVariable().getId()for n in recovery.input_nodes.values()})

    def test_expression_lemmas_refuse_unmatched_subjects_and_wrong_constants(self):
        params,image=fixture([b'\x90'],[{'rdi':1,'rsi':2}]);recovery=Recovery(TT,params,image)
        x={'op':'input','name':'x','bits':64};y={'op':'input','name':'y','bits':64}
        before={'op':'add','bits':64,'args':[x,{'op':'constant','bits':64,'value':'0x3'}]}
        wrong={'op':'add','bits':64,'args':[x,{'op':'constant','bits':64,'value':'0x4'}]}
        proof=prove_expression_instance(recovery.ctx,recovery.ast,before,wrong,'modular-associative-commutative-normal-form',None,recovery.proof,{})
        self.assertEqual(proof['status'],'sat')
        with self.assertRaisesRegex(ValueError,'unmatched subject'):
            prove_expression_instance(recovery.ctx,recovery.ast,before,{**wrong,'args':[y,wrong['args'][1]]},'modular-associative-commutative-normal-form',None,recovery.proof,{})
        with self.assertRaisesRegex(ValueError,'width mismatch'):
            prove_expression_instance(recovery.ctx,recovery.ast,before,{**wrong,'bits':32},'modular-associative-commutative-normal-form',None,recovery.proof,{})

    def test_expression_normal_forms_refuse_unproved_and_overlarge_rewrites(self):
        params,image=fixture([b'\x90'],[{'rdi':1,'rsi':2}]);recovery=Recovery(TT,params,image)
        for name in ('x','y'):
            sv=recovery.ctx.newSymbolicVariable(64,name);recovery.input_nodes[name]=recovery.ast.variable(sv)
        x,y=[{'op':'input','name':n,'bits':64}for n in ('x','y')]
        raw={'op':'add','bits':64,'args':[y,x]}
        normalized,steps,_=normalize_expression(raw,recovery.expression_ast,lambda a,b:{'status':'unknown'},recovery.budget)
        self.assertEqual(normalized,raw);self.assertFalse(steps)
        raw={'op':'add','bits':64,'args':[y]*65}
        normalized,steps,_=normalize_expression(raw,recovery.expression_ast,lambda a,b:self.fail('Overlarge rewrite attempted'),recovery.budget)
        self.assertEqual(normalized,raw);self.assertFalse(steps)

    def test_transparent_reference_rendering_and_flat_addition_keep_smt_equality(self):
        params,image=fixture([b'\x90'],[{'rdi':1,'rsi':2}]);recovery=Recovery(TT,params,image);ast=recovery.ast
        for name,reg in [('x','rdi'),('y','rsi')]:
            sv=recovery.ctx.symbolizeRegister(getattr(recovery.ctx.registers,reg),name);recovery.input_nodes[name]=ast.variable(sv)
        recovery.input_variables={name:node.getSymbolicVariable() for name,node in recovery.input_nodes.items()}
        x,y=recovery.input_nodes['x'],recovery.input_nodes['y'];node=ast.bvadd(ast.bvadd(x,y),ast.bv(7,64))
        for _ in range(40):node=ast.reference(recovery.ctx.newSymbolicExpression(node))
        expression=recovery.expression(node)
        self.assertEqual(expression['op'],'add');self.assertEqual(len(expression['args']),3)
        self.assertEqual(recovery.proof(ast.distinct(node,recovery.expression_ast(expression)))['status'],'unsat')
        predicate=ast.equal(ast.bvand(ast.bvxor(x,y),ast.bv(1,64)),ast.bv(0,64))
        for _ in range(40):predicate=ast.reference(recovery.ctx.newSymbolicExpression(predicate))
        rendered=recovery.predicate_expression(predicate)
        self.assertEqual(recovery.proof(ast.lxor([predicate,recovery.predicate_ast(rendered)]))['status'],'unsat')
        candidates=recovery.predicates([(0x1000,predicate,[])])
        self.assertTrue(any(label=='low1(x) == low1(y)' for label,_,_ in candidates))

    def test_native_sparse_snapshot_binds_modified_code_without_filling_holes(self):
        blob, meta = pe_fixture(); image = BinaryImage.from_bytes(blob)
        with tempfile.TemporaryDirectory() as folder:
            filename = Path(folder) / 'observed.bin'; filename.write_bytes(b'\x90\x90')
            snapshot = {'schema': 'ig5.native-main-image.v1', 'path': str(filename), 'sha256': hashlib.sha256(b'\x90\x90').hexdigest(),
                        'bytes': 2, 'moduleSize': 0x3000, 'runtimeBase': hex(meta['base']), 'targetSha256': image.sha256,
                        'regions': [{'rva': '0x1000', 'bytes': 2, 'blobOffset': 0}]}
            binding = TraceByteBinding(image, meta['base'], snapshot)
            original, observed = binding.read(meta['base'] + 0x1000, 1)
            self.assertEqual(original, b'\xc3'); self.assertEqual(observed, b'\x90')
            with self.assertRaisesRegex(ValueError, 'outside captured'): binding.read(meta['base'] + 0x1002, 1)
            with self.assertRaisesRegex(ValueError, 'identity'): TraceByteBinding(image, meta['base'] + 0x1000, snapshot)
            bad = {**snapshot, 'regions': [{'rva': '0x1000', 'bytes': 2, 'blobOffset': 1}]}
            with self.assertRaisesRegex(ValueError, 'regions'): TraceByteBinding(image, meta['base'], bad)
            for region in [{'rva': '0x1000', 'bytes': 2, 'blobOffset': False}, {'rva': '-0x1', 'bytes': 2, 'blobOffset': 0}]:
                with self.assertRaisesRegex(ValueError, 'regions'): TraceByteBinding(image, meta['base'], {**snapshot, 'regions': [region]})
            filename.write_bytes(b'\x90\xc3')
            with self.assertRaisesRegex(ValueError, 'digest'): TraceByteBinding(image, meta['base'], snapshot)

    def test_native_image_capture_preserves_holes_and_rejects_changed_pause(self):
        initial = {'mainModuleBase': '0x10000', 'mainModuleSize': 3 * 4096, 'runId': 'owned', 'pid': 1, 'tid': 2, 'stopSeq': 3, 'state': 'suspended'}
        class Adapter:
            def check(self): pass
            def context(self): return initial
            def call(self, operation, address, count):
                if address == 0x11000: raise ValueError('unreadable page')
                return bytes([address >> 12]) * count
        adapter = Adapter(); encoded, summary = capture_image(adapter, initial, time.monotonic() + 2)
        self.assertEqual(base64.b64decode(encoded), b'\x10' * 4096 + b'\x12' * 4096)
        self.assertEqual(summary['unreadableRanges'], [{'rva': '0x1000', 'bytes': 4096}])
        self.assertEqual(summary['regions'][1], {'rva': '0x2000', 'bytes': 4096, 'blobOffset': 4096})
        self.assertTrue(summary['partial'])
        adapter.context = lambda: {**initial, 'stopSeq': 4}
        with self.assertRaisesRegex(ValueError, 'pause identity'): capture_image(adapter, initial, time.monotonic() + 2)
        adapter.context = lambda: initial
        with self.assertRaisesRegex(ValueError, 'deadline'): capture_image(adapter, initial, time.monotonic() - 1)
        def critical(*unused): raise type('TransportError', (Exception,), {'code': 'ETRANSPORT'})('pipe closed')
        adapter.call = critical
        with self.assertRaisesRegex(Exception, 'pipe closed'): capture_image(adapter, initial, time.monotonic() + 2)

    def test_wrong_symbolic_register_snapshot_is_rejected(self):
        params, image = fixture([b'\x89\xf8', b'\x31\xf0'], [{'rdi': 1, 'rsi': 2}, {'rax': 7, 'rdi': 1, 'rsi': 2}])
        with self.assertRaisesRegex(ValueError, 'input dependency was preserved'): analyze(params, TT, image)

    def test_wrong_concrete_register_snapshot_is_rejected(self):
        params, image = fixture([b'\xb8\x01\0\0\0', b'\x90'], [{'rdi': 1, 'rsi': 2}, {'rax': 7, 'rdi': 1, 'rsi': 2}])
        with self.assertRaisesRegex(ValueError, 'Concrete register snapshot'): analyze(params, TT, image)

    def test_8bit_wrap_and_projection_proof(self):
        params, image = fixture([b'\x89\xf8', b'\x01\xf0'], [{'rdi': 0xfe, 'rsi': 3}, {'rax': 0xfe, 'rdi': 0xfe, 'rsi': 3}], bits=8)
        result = analyze(params, TT, image)
        self.assertEqual(result['paths'][0]['observedOutput'], '0x1')
        self.assertEqual(result['recoveredExpression']['bits'], 8)
        self.assertEqual(result['paths'][0]['outputProof']['status'], 'unsat')

    def test_wrong_boundaries_and_truncated_record_are_rejected(self):
        params, image = fixture([b'\x90'], [{'rdi': 1, 'rsi': 2}])
        params['trace_exit'] = '0x1'
        with self.assertRaisesRegex(ValueError, 'boundaries'): analyze(params, TT, image)
        with self.assertRaisesRegex(ValueError, 'newline-terminated'): parse_trace(b'r:0x0', 10)
        with self.assertRaisesRegex(ValueError, 'ordering'): parse_trace(b'i:0x1000:1:90\n', 10)
        data = base64.b64decode(params['traces'][0]['data'])
        with self.assertRaisesRegex(ValueError, 'instruction budget'): parse_trace(data, 0)

    def test_syscall_and_input_dependent_hardware_are_refused(self):
        params, image = fixture([b'\x0f\x05'], [{'rdi': 1, 'rsi': 2}])
        with self.assertRaisesRegex(ValueError, 'OS/interrupt'): analyze(params, TT, image)
        params, image = fixture([b'\x89\xf8', b'\x0f\xa2'], [{'rdi': 1, 'rsi': 2}, {'rax': 1, 'rdi': 1, 'rsi': 2}])
        with self.assertRaisesRegex(ValueError, 'Input-dependent CPUID'): analyze(params, TT, image)

    def test_program_headers_mode_is_explicit_and_keeps_load_checks(self):
        blob, meta = elf_fixture()
        corrupt = patched(blob, '<Q', meta['shoff'] + meta['shsize'] + 48, 0x400)
        with self.assertRaisesRegex(ImageFormatError, 'misaligned ELF allocated section'): BinaryImage.from_bytes(corrupt)
        image = BinaryImage.from_bytes(corrupt, elf_sections='program-headers')
        self.assertEqual(image.sections, ())
        self.assertEqual(image.read(meta['base'] + 0x200, 1), b'\xc3')
        invalid_load = patched(corrupt, '<Q', meta['phoff'] + 40, 0x10)
        with self.assertRaisesRegex(ImageFormatError, 'LOAD size'): BinaryImage.from_bytes(invalid_load, elf_sections='program-headers')

    def test_zero_bsf_preserves_unknown_parent_and_keeps_partial_coverage(self):
        params, image = fixture([b'\x0f\xbc\xde', b'\x89\xf8'], [{'rbx': 0x7ffd11223344, 'rdi': 1}, {'rbx': 0x7ffd11223344, 'rdi': 1}])
        result = analyze(params, TT, image)
        self.assertEqual(result['paths'][0]['outputExpression']['name'], 'x')
        self.assertEqual(result['paths'][0]['outputProof']['status'], 'unsat')
        self.assertIsNone(result['recoveredExpression'])
        self.assertEqual(result['coverage'], 'single-recorded-path')
        self.assertEqual(result['paths'][0]['guard']['proof']['status'], 'unsat')
        self.assertFalse(result['proofScope']['allInputPairsProved'])
        recovery = Recovery(TT, params, image); row = recovery.replay(params['traces'][0], 0)
        expected = recovery.ast.equal(recovery.input_nodes['y'], recovery.ast.bv(0, recovery.input_nodes['y'].getBitvectorSize()))
        self.assertEqual(recovery.proof(recovery.ast.lxor([row['_guard'], expected]))['status'], 'unsat')

    def test_hardware_snapshot_is_symbolic_and_output_is_independent(self):
        params, image = fixture([b'\xb8\x01\0\0\0', b'\x0f\xa2', b'\x89\xf8'],
                               [{'rdi': 1, 'rsi': 2}, {'rax': 1, 'rdi': 1, 'rsi': 2}, {'rax': 0x806ec, 'rbx': 0x7100800, 'rcx': 0x7ffafbbf, 'rdx': 0xbfebfbff, 'rdi': 1, 'rsi': 2}])
        result = analyze(params, TT, image)
        self.assertEqual(result['paths'][0]['environmentReads'][0]['operation'], 'cpuid')
        self.assertFalse(result['paths'][0]['outputDependsOnUndefinedFlags'])
        self.assertEqual(result['recoveredExpression']['name'], 'x')

    def test_omitted_memory_read_is_rejected(self):
        params, image = fixture([b'\x8b\x07'], [{'rdi': 0x1234, 'rsi': 2}])
        with self.assertRaisesRegex(ValueError, 'omits an uninitialized memory read'): analyze(params, TT, image)

    def test_hardware_dependent_output_is_explicit_environment_not_argument(self):
        params, image = fixture([b'\xb8\x01\0\0\0', b'\x0f\xa2', b'\x90'],
                               [{'rdi': 1, 'rsi': 2}, {'rax': 1, 'rdi': 1, 'rsi': 2},
                                {'rax': 0x806ec, 'rbx': 0x7100800, 'rcx': 0x7ffafbbf, 'rdx': 0xbfebfbff, 'rdi': 1, 'rsi': 2}])
        result = analyze(params, TT, image)
        output = result['paths'][0]['outputExpression']
        self.assertEqual(output['op'], 'environment')
        self.assertTrue(output['name'].startswith('env_'))
        self.assertTrue(result['paths'][0]['outputDependsOnEnvironmentUnknowns'])
        self.assertEqual(result['paths'][0]['outputProof']['status'], 'unsat')
        self.assertIsNone(result['recoveredExpression'])
        self.assertEqual(result['coverage'], 'single-recorded-path')

        self.assertFalse(result['proofScope']['allInputPairsProved'])

    def test_timestamp_outputs_are_external_and_rdtscp_flags_stay_observed(self):
        for opcode, operation in [(b'\x0f\x31', 'rdtsc'), (b'\x0f\x01\xf9', 'rdtscp')]:
            params, image = fixture([opcode, b'\x89\xf8'], [{'rax': 0xffffffffffffffff, 'rdx': 0xffffffffffffffff, 'rdi': 7, 'rsi': 2},
                {'rax': 0x12345678, 'rdx': 0x76543210, 'rcx': 42 if operation == 'rdtscp' else 0, 'rdi': 7, 'rsi': 2}])
            rows = base64.b64decode(params['traces'][0]['data']).decode().splitlines()
            data = ('h:ig5-native-x64-v2\n' + '\n'.join(row + '\ne:0x203' if row.startswith('r:') else row for row in rows) + '\n').encode()
            params['initial_flags'] = '0x203'; params['traces'][0] = {'data': base64.b64encode(data).decode(), 'sha256': hashlib.sha256(data).hexdigest()}
            result = analyze(params, TT, image)
            self.assertEqual(result['recoveredExpression']['name'], 'x')
            self.assertEqual(result['paths'][0]['observedOutput'], '0x7')
            self.assertTrue(any(row['operation'] == operation for row in result['paths'][0]['environmentReads']))
            if operation == 'rdtscp': self.assertTrue(any(row['method'] == 'rdtscp-architectural-external-output' for row in result['paths'][0]['semanticCorrections']))

    def test_arithmetic_guard_is_inferred_at_unseen_boundary_with_wrap(self):
        # mov eax,edi; add eax,esi; cmp eax,37; jb +2.
        # Two recordings with different arguments; no expected predicate is
        # supplied to recovery. Values deliberately include uint32 overflow.
        code = [b'\x89\xf8', b'\x01\xf0', b'\x83\xf8\x25', b'\x72\x02']
        def recording(x, y):
            total = (x + y) & 0xffffffff
            return fixture(code, [{'rdi': x, 'rsi': y}, {'rax': x, 'rdi': x, 'rsi': y},
                                  {'rax': total, 'rdi': x, 'rsi': y}, {'rax': total, 'rdi': x, 'rsi': y}])
        params, image = recording(0xffffffff, 3)
        other, _ = recording(30, 20)
        params['traces'] += other['traces']
        result = analyze(params, TT, image)
        self.assertEqual(result['coverageProof']['exhaustive']['status'], 'unsat')
        self.assertEqual(result['coverageProof']['disjoint']['status'], 'unsat')
        self.assertEqual(result['proofScope']['symbolicInputBits'], {'x': 32, 'y': 32})
        self.assertTrue(result['proofScope']['allInputPairsProved'])
        self.assertFalse(result['proofScope']['originalBinaryWholeProgramProved'])
        predicate = result['recoveredExpression']['conditionExpression']
        self.assertEqual(predicate['op'], 'ult')
        self.assertEqual(predicate['args'][1]['value'], '0x25')
        self.assertFalse(result['nativeTargetExecuted'])

    def test_ordered_comparison_complements_include_equality_and_sign(self):
        # CMP EDI,ESI; JLE/JBE. Equality must belong to the <= path,
        # and the signed sign-bit boundary must differ from unsigned order.
        for opcode, x, y, expected in [(b'\x7e\x02', 1, 2, 'sle'),
                                      (b'\x7e\x02', 2, 1, 'sgt'),
                                      (b'\x7e\x02', 0xffffffff, 0, 'sle'),
                                      (b'\x76\x02', 1, 2, 'ule'),
                                      (b'\x76\x02', 2, 1, 'ugt')]:
            params, image = fixture([b'\x39\xf7', opcode], [{'rdi': x, 'rsi': y}] * 2)
            result = analyze(params, TT, image)
            self.assertEqual(result['paths'][0]['guard']['conditionExpression']['op'], expected)
            self.assertEqual(result['paths'][0]['guard']['proof']['status'], 'unsat')
            self.assertIsNone(result['recoveredExpression'])

    def test_two_paths_with_different_aslr_and_flags_keep_common_inputs(self):
        code = [b'\x89\xf8', b'\x39\xf7', b'\x7e\x02']
        params, image = fixture(code, [{'rdi': 1, 'rsi': 2}, {'rax': 1, 'rdi': 1, 'rsi': 2}, {'rax': 1, 'rdi': 1, 'rsi': 2}])
        other, _ = fixture(code, [{'rdi': 2, 'rsi': 1}, {'rax': 2, 'rdi': 2, 'rsi': 1}, {'rax': 2, 'rdi': 2, 'rsi': 1}])
        runtime = 0x7ff812340000
        data = base64.b64decode(other['traces'][0]['data']).decode()
        for ea in [int(params['trace_entry'], 16), int(params['trace_entry'], 16) + 2, int(params['trace_exit'], 16)]:
            data = data.replace('i:' + hex(ea) + ':', 'i:' + hex(ea - image.imagebase + runtime) + ':')
        encoded = data.encode()
        second = {'data': base64.b64encode(encoded).decode(), 'sha256': hashlib.sha256(encoded).hexdigest(),
                  'recording': {'entry': hex(int(params['trace_entry'], 16) - image.imagebase + runtime),
                                'exit': hex(int(params['trace_exit'], 16) - image.imagebase + runtime),
                                'runtimeBase': hex(runtime), 'initialFlags': '0x246'}}
        params['traces'].append(second)
        result = analyze(params, TT, image)
        self.assertEqual(result['coverage'], 'trace-model-input-domain')
        self.assertEqual(result['coverageProof']['exhaustive']['status'], 'unsat')
        self.assertEqual(result['paths'][1]['recording']['initialFlags'], '0x246')
        self.assertTrue(all(row['binaryBinding']['allInstructionBytesMatch'] for row in result['paths']))
        second['recording']['entry'] = hex(int(second['recording']['entry'], 16) + 1)
        with self.assertRaisesRegex(ValueError, 'entry RVAs'): analyze(params, TT, image)

    def test_independent_paths_bind_their_own_native_image(self):
        code = [b'\x89\xf8', b'\x39\xf7', b'\x7e\x02']
        blob, meta = pe_fixture(); image = BinaryImage.from_bytes(blob)
        with tempfile.TemporaryDirectory() as folder:
            filename = Path(folder) / 'observed.bin'; filename.write_bytes(b''.join(code))
            traces, params = [], None
            for index, (x, y) in enumerate([(1, 2), (2, 1)]):
                local, elf_image = fixture(code, [{'rdi': x, 'rsi': y}, {'rax': x, 'rdi': x, 'rsi': y}, {'rax': x, 'rdi': x, 'rsi': y}])
                runtime = meta['base'] + index * 0x10000
                data = base64.b64decode(local['traces'][0]['data']).decode()
                for delta in (0, 2, 4): data = data.replace('i:' + hex(int(local['trace_entry'], 16) + delta) + ':', 'i:' + hex(runtime + 0x1000 + delta) + ':')
                encoded = data.encode()
                snapshot = {'schema': 'ig5.native-main-image.v1', 'path': str(filename), 'sha256': hashlib.sha256(b''.join(code)).hexdigest(),
                    'bytes': 6, 'moduleSize': 0x3000, 'runtimeBase': hex(runtime), 'targetSha256': image.sha256,
                    'sourceReportId': 'owned-fixture-' + str(index), 'sourceReportSha256': str(index) * 64, 'partial': True,
                    'runId': 'owned-' + str(index), 'threadId': index + 1, 'stopSeq': 1,
                    'regions': [{'rva': '0x1000', 'bytes': 6, 'blobOffset': 0}]}
                traces.append({'data': base64.b64encode(encoded).decode(), 'sha256': hashlib.sha256(encoded).hexdigest(), 'loaded_image': snapshot,
                    'recording': {'entry': hex(runtime + 0x1000), 'exit': hex(runtime + 0x1004), 'runtimeBase': hex(runtime), 'initialFlags': '0x202'}})
                if params is None: params = {**local, 'trace_runtime_base': hex(runtime), 'trace_entry': hex(runtime + 0x1000), 'trace_exit': hex(runtime + 0x1004)}
            params['traces'] = traces
            result = analyze(params, TT, image)
            self.assertEqual(result['coverageProof']['exhaustive']['status'], 'unsat')
            self.assertTrue(all(row['binaryBinding']['capturedImageMatchedInstructions'] == 3 for row in result['paths']))
            traces[1]['loaded_image'] = traces[0]['loaded_image']
            with self.assertRaisesRegex(ValueError, 'identity'): analyze(params, TT, image)

    def test_masked_low_bit_guards_project_without_reference_candidates(self):
        code = [b'\x89\xf8', b'\x31\xf0', b'\xa8\x01', b'\x74\x02']
        params, image = fixture(code, [{'rdi': 1, 'rsi': 2}, {'rax': 1, 'rdi': 1, 'rsi': 2}, {'rax': 3, 'rdi': 1, 'rsi': 2}, {'rax': 3, 'rdi': 1, 'rsi': 2}])
        other, _ = fixture(code, [{'rdi': 1, 'rsi': 1}, {'rax': 1, 'rdi': 1, 'rsi': 1}, {'rax': 0, 'rdi': 1, 'rsi': 1}, {'rax': 0, 'rdi': 1, 'rsi': 1}])
        params['traces'].append(other['traces'][0])
        result = analyze(params, TT, image)
        self.assertEqual(result['coverage'], 'trace-model-input-domain')
        self.assertEqual(result['coverageProof']['exhaustive']['status'], 'unsat')
        self.assertEqual(result['coverageProof']['disjoint']['status'], 'unsat')
        self.assertEqual(result['proofScope']['symbolicInputBits'], {'x': 32, 'y': 32})
        self.assertTrue(result['proofScope']['allInputPairsProved'])
        for row in result['paths']:
            self.assertEqual(row['guard']['proof']['status'], 'unsat')
            self.assertEqual(row['unresolvedGuardCount'], 0)
        recovery = Recovery(TT, params, image)
        for index, trace in enumerate(params['traces']):
            row = recovery.replay(trace, index); ast = recovery.ast
            left, right = ast.extract(0, 0, recovery.input_nodes['x']), ast.extract(0, 0, recovery.input_nodes['y'])
            expected = (ast.distinct if index == 0 else ast.equal)(left, right)
            self.assertEqual(recovery.proof(ast.lxor([row['_guard'], expected]))['status'], 'unsat')

    def test_complement_mask_byte_guard_proves_full_width_domain(self):
        code = [b'\x48\x89\xc8', b'\x48\x31\xd0', b'\x0c\xfe', b'\x3c\xff', b'\x74\x02']
        params, image = fixture(code, [{'rcx': 1, 'rdx': 2}, {'rax': 1, 'rcx': 1, 'rdx': 2},
            {'rax': 3, 'rcx': 1, 'rdx': 2}, {'rax': 0xff, 'rcx': 1, 'rdx': 2}, {'rax': 0xff, 'rcx': 1, 'rdx': 2}])
        other, _ = fixture(code, [{'rcx': 1, 'rdx': 1}, {'rax': 1, 'rcx': 1, 'rdx': 1},
            {'rax': 0, 'rcx': 1, 'rdx': 1}, {'rax': 0xfe, 'rcx': 1, 'rdx': 1}, {'rax': 0xfe, 'rcx': 1, 'rdx': 1}])
        params.update(trace_inputs=['rcx', 'rdx'], trace_output='rax')
        params['traces'].append(other['traces'][0])
        result = analyze(params, TT, image)
        self.assertTrue(result['proofScope']['allInputPairsProved'])
        self.assertEqual(result['proofScope']['symbolicInputBits'], {'x': 64, 'y': 64})
        self.assertEqual(result['coverageProof']['disjoint']['status'], 'unsat')
        self.assertEqual(result['coverageProof']['exhaustive']['status'], 'unsat')
        recovery = Recovery(TT, params, image)
        for index, trace in enumerate(params['traces']):
            row = recovery.replay(trace, index); ast = recovery.ast
            a, b = [ast.extract(0, 0, recovery.input_nodes[name]) for name in ('x', 'y')]
            expected = (ast.distinct if index == 0 else ast.equal)(a, b)
            self.assertEqual(recovery.proof(ast.lxor([row['_guard'], expected]))['status'], 'unsat')

    def test_fixed_rotate_rounds_stay_compact_and_prove_full_width_output(self):
        x, y, state = 0xabcdef0123456789, 0x3141592653589793, 0xabcdef0123456789
        code, states = [b'\x48\x89\xc8'], [{'rcx': x, 'rdx': y}]
        for _ in range(8):
            code.append(b'\x48\xc1\xc0\x07'); states.append({'rcx': x, 'rdx': y, 'rax': state})
            state = ((state << 7) | (state >> 57)) & ((1 << 64) - 1)
            code.append(b'\x48\x33\xc2'); states.append({'rcx': x, 'rdx': y, 'rax': state}); state ^= y
        params, image = fixture(code, states)
        params.update(trace_inputs=['rcx', 'rdx'], trace_output='rax')
        result = analyze(params, TT, image)
        self.assertEqual(result['paths'][0]['observedOutput'], hex(state))
        self.assertEqual(result['proofScope']['symbolicInputBits'], {'x': 64, 'y': 64})
        self.assertTrue(result['proofScope']['allInputPairsProved'])
        recovery = Recovery(TT, params, image); row = recovery.replay(params['traces'][0], 0); ast = recovery.ast
        expected = recovery.input_nodes['x']
        for _ in range(8): expected = ast.bvxor(ast.bvrol(expected, ast.bv(7, 64)), recovery.input_nodes['y'])
        self.assertEqual(recovery.proof(ast.distinct(recovery.expression_ast(row['outputExpression']), expected))['status'], 'unsat')

    def test_independent_paths_release_old_hardware_observations(self):
        code = [b'\x0f\x31', b'\x89\xf8']
        params, image = fixture(code, [{'rdi': 7, 'rsi': 2}, {'rax': 11, 'rdx': 0, 'rdi': 7, 'rsi': 2}])
        other, _ = fixture(code, [{'rdi': 9, 'rsi': 1}, {'rax': 22, 'rdx': 0, 'rdi': 9, 'rsi': 1}])
        recovery = Recovery(TT, params, image)
        first = recovery.replay(params['traces'][0], 0)
        first_ids = set(recovery.unknown)
        self.assertTrue(first_ids)
        second = recovery.replay(other['traces'][0], 1)
        self.assertFalse(first_ids & set(recovery.unknown))
        self.assertEqual(first['observedOutput'], '0x7'); self.assertEqual(second['observedOutput'], '0x9')
        self.assertEqual(second['outputExpression']['name'], 'x')
        self.assertEqual(second['outputProof']['status'], 'unsat')

    def test_bitwise_guard_candidates_are_verified_at_a_different_constant(self):
        code = [b'\x89\xf8', b'\x31\xf0', b'\x83\xf8\x55', b'\x74\x02']
        params, image = fixture(code, [{'rdi': 0x50, 'rsi': 5}, {'rax': 0x50, 'rdi': 0x50, 'rsi': 5},
                                       {'rax': 0x55, 'rdi': 0x50, 'rsi': 5}, {'rax': 0x55, 'rdi': 0x50, 'rsi': 5}])
        result = analyze(params, TT, image)
        guard = result['paths'][0]['guard']
        self.assertEqual(guard['proof']['status'], 'unsat')
        self.assertEqual(guard['conditionExpression']['op'], 'eq')
        self.assertEqual(guard['conditionExpression']['args'][0]['op'], 'xor')
        self.assertIsNone(result['recoveredExpression'])  # One branch cannot prove coverage.

    def test_win64_register_pair_and_explicit_aslr_binding(self):
        params, image = fixture([b'\x89\xc8', b'\x01\xd0'], [{'rcx': 0xffffffff, 'rdx': 3}, {'rax': 0xffffffff, 'rcx': 0xffffffff, 'rdx': 3}])
        original = base64.b64decode(params['traces'][0]['data']).decode()
        runtime_base = 0x7ffa11000000
        for key in ['trace_entry', 'trace_exit']:
            old = params[key]
            new = hex(runtime_base + int(old, 16) - image.imagebase)
            original = original.replace('i:' + old + ':', 'i:' + new + ':')
            params[key] = new
        data = original.encode()
        params.update(trace_inputs=['ecx', 'edx'], trace_runtime_base=hex(runtime_base))
        params['traces'][0] = {'data': base64.b64encode(data).decode(), 'sha256': hashlib.sha256(data).hexdigest()}
        result = analyze(params, TT, image)
        self.assertEqual(result['paths'][0]['observedOutput'], '0x2')
        self.assertTrue(result['paths'][0]['binaryBinding']['allInstructionBytesMatch'])
        self.assertEqual(result['paths'][0]['binaryBinding']['runtimeBase'], hex(runtime_base))
        params['trace_inputs'] = ['ecx', 'esi']
        with self.assertRaisesRegex(ValueError, 'RCX/RDX pair'): analyze(params, TT, image)

    def test_final_snapshot_checks_inputs_and_flags_without_erasing_dependencies(self):
        params, image = fixture([b'\x89\xf8'], [{'rdi': 1, 'rsi': 2}])
        initial = base64.b64decode(params['traces'][0]['data'])
        final = [1, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, int(params['trace_entry'], 16) + 2, 0x202]
        def append(values):
            data = initial + ('f:' + ':'.join(hex(v) for v in values) + '\n').encode()
            params['traces'][0] = {'data': base64.b64encode(data).decode(), 'sha256': hashlib.sha256(data).hexdigest()}
            return data
        data = append(final)
        self.assertTrue(analyze(params, TT, image)['paths'][0]['finalSnapshotVerified'])
        wrong = list(final); wrong[0] = 9; append(wrong)
        with self.assertRaisesRegex(ValueError, 'input dependency was preserved'): analyze(params, TT, image)
        wrong = list(final); wrong[-1] = 0x203; append(wrong)
        with self.assertRaisesRegex(ValueError, 'Final register snapshot'): analyze(params, TT, image)
        with self.assertRaisesRegex(ValueError, 'after final snapshot'): parse_trace(data + b'i:0x1:1:90\n', 100)

    def test_native_flags_and_pushfq_stack_image_are_checked(self):
        params, image = fixture([b'\x9c', b'\x58'], [{'rsp': 0x2000, 'rdi': 1, 'rsi': 2}, {'rsp': 0x1ff8, 'rdi': 1, 'rsi': 2}])
        rows = base64.b64decode(params['traces'][0]['data']).decode().splitlines()
        native = ['h:ig5-native-x64-v1', rows[0], 'e:0x202', rows[1], rows[2], 'e:0x202', 'mr:0x1ff8:8:0x202', rows[3]]
        def use(lines):
            data = ('\n'.join(lines) + '\n').encode()
            params['traces'][0] = {'data': base64.b64encode(data).decode(), 'sha256': hashlib.sha256(data).hexdigest()}
        use(native)
        result = analyze(params, TT, image)
        self.assertEqual(result['paths'][0]['observedOutput'], '0x202')
        self.assertEqual(result['paths'][0]['recordingFormat'], 'ig5-native-x64-v1')
        bad = list(native); bad[5] = 'e:0x203'; use(bad)
        with self.assertRaisesRegex(ValueError, 'flags snapshot conflicts'): analyze(params, TT, image)
        with self.assertRaisesRegex(ValueError, 'omits flags'): parse_trace(('\n'.join(native[:2] + native[3:]) + '\n').encode(), 10)

    def test_wider_read_observes_only_unknown_bytes_of_prior_narrow_store(self):
        for store, input_value in [(b'\xc7\x03\xf8\xff\xff\xff', 0xfffffff8), (b'\x89\x3b', 1)]:
            params, image = fixture([store, b'\x48\x8b\x03'], [{'rdi': 1, 'rsi': 2, 'rbx': 0x7000}] * 2)
            params['trace_output'] = 'rax'
            rows = base64.b64decode(params['traces'][0]['data']).decode().splitlines()
            def use(value):
                lines = ['h:ig5-native-x64-v1', rows[0], 'e:0x202', rows[1], rows[2], 'e:0x202',
                         'mr:0x7000:8:' + hex(value), rows[3]]
                data = ('\n'.join(lines) + '\n').encode()
                params['traces'][0] = {'data': base64.b64encode(data).decode(), 'sha256': hashlib.sha256(data).hexdigest()}
            expected = 0xbaadf00d00000000 | input_value
            use(expected)
            result = analyze(params, TT, image)
            self.assertEqual(result['paths'][0]['observedOutput'], hex(expected))
            self.assertEqual(result['paths'][0]['outputProof']['status'], 'unsat')
            # The observed upper bytes cannot overwrite a known lower byte or
            # change the input symbol stored there.
            use(expected ^ 1)
            with self.assertRaisesRegex(ValueError, 'known trace memory|input dependency was preserved'):
                analyze(params, TT, image)

    def test_observed_zero_memory_is_not_reseeded_as_uninitialized(self):
        params, image = fixture([b'\x8b\x03', b'\x8b\x03'], [{'rdi': 1, 'rsi': 2, 'rbx': 0x7000}] * 2)
        rows = base64.b64decode(params['traces'][0]['data']).decode().splitlines()
        lines = ['h:ig5-native-x64-v1', rows[0], 'e:0x202', 'mr:0x7000:4:0x0', rows[1],
                 rows[2], 'e:0x202', 'mr:0x7000:4:0x1', rows[3]]
        data = ('\n'.join(lines) + '\n').encode()
        params['traces'][0] = {'data': base64.b64encode(data).decode(), 'sha256': hashlib.sha256(data).hexdigest()}
        with self.assertRaisesRegex(ValueError, 'known trace memory'): analyze(params, TT, image)

    def test_cmov_signed_condition_has_a_proved_structured_select(self):
        params, image = fixture([b'\x89\xf8', b'\x39\xf7', b'\x0f\x4c\xc6'],
                               [{'rdi': 0xffffffff, 'rsi': 1}, {'rax': 0xffffffff, 'rdi': 0xffffffff, 'rsi': 1}, {'rax': 0xffffffff, 'rdi': 0xffffffff, 'rsi': 1}])
        result = analyze(params, TT, image)
        self.assertEqual(result['paths'][0]['observedOutput'], '0x1')
        self.assertEqual(result['recoveredExpression']['op'], 'select')
        self.assertEqual(result['paths'][0]['outputProof']['status'], 'unsat')
        self.assertEqual(result['coverage'], 'trace-model-input-domain')

    def test_right_shift_retains_high_source_bits_before_low_projection(self):
        params, image = fixture([b'\x89\xf8', b'\xc1\xe0\x03', b'\xc1\xe8\x07', b'\x31\xf0'],
                               [{'rdi': 0x20, 'rsi': 3}, {'rax': 0x20, 'rdi': 0x20, 'rsi': 3}, {'rax': 0x100, 'rdi': 0x20, 'rsi': 3}, {'rax': 2, 'rdi': 0x20, 'rsi': 3}], bits=8)
        result = analyze(params, TT, image)
        self.assertEqual(result['paths'][0]['observedOutput'], '0x1')
        self.assertEqual(result['paths'][0]['outputProof']['status'], 'unsat')

    def test_native_undefined_af_and_debugger_tf_are_separate_observations(self):
        params, image = fixture([b'\x31\xc0', b'\x89\xf8'], [{'rdi': 1, 'rsi': 2}, {'rdi': 1, 'rsi': 2}])
        def native(flags):
            rows = base64.b64decode(original).decode().splitlines()
            data = ('h:ig5-native-x64-v1\n' + '\n'.join([rows[0], 'e:' + flags[0], rows[1], rows[2], 'e:' + flags[1], rows[3]]) + '\n').encode()
            params['traces'][0] = {'data': base64.b64encode(data).decode(), 'sha256': hashlib.sha256(data).hexdigest()}
        original = params['traces'][0]['data']; params['initial_flags'] = '0x212'
        native(['0x212', '0x246'])
        result = analyze(params, TT, image)
        self.assertEqual(result['recoveredExpression']['name'], 'x')
        self.assertTrue(result['paths'][0]['snapshotRepairs'])
        native(['0x212', '0x247'])
        with self.assertRaisesRegex(ValueError, 'input dependency was preserved'): analyze(params, TT, image)
        params, image = fixture([b'\x89\xf8', b'\x90'], [{'rdi': 1, 'rsi': 2}, {'rax': 1, 'rdi': 1, 'rsi': 2}])
        original = params['traces'][0]['data']; params['initial_flags'] = '0x302'
        native(['0x302', '0x202'])
        result = analyze(params, TT, image)
        self.assertEqual(result['paths'][0]['environmentReads'][0]['operation'], 'debugger-TF-boundary')
        self.assertFalse(result['paths'][0]['outputDependsOnEnvironmentUnknowns'])

    def test_overwritten_unused_inputs_keep_live_symbols_for_guard_validation(self):
        params, image = fixture([b'\x31\xff', b'\x31\xf6', b'\xb8\x07\0\0\0'],
                               [{'rdi': 1, 'rsi': 2}, {'rsi': 2}, {}])
        result = analyze(params, TT, image)
        self.assertEqual(result['recoveredExpression']['value'], '0x7')

    def test_explicit_gs_environment_binds_memory_and_missing_base_is_refused(self):
        params, image = fixture([b'\x65\x48\x8b\x43\x60'], [{'rdi': 1, 'rsi': 2}])
        original = base64.b64decode(params['traces'][0]['data']).decode().splitlines()
        def use(base):
            lines = ['h:ig5-native-x64-v1'] + (['s:gs:0x7000'] if base else []) + [original[0], 'e:0x202', 'mr:0x7060:8:0x2a', original[1]]
            data = ('\n'.join(lines) + '\n').encode()
            params['traces'][0] = {'data': base64.b64encode(data).decode(), 'sha256': hashlib.sha256(data).hexdigest()}
        use(True)
        result = analyze(params, TT, image)
        self.assertEqual(result['paths'][0]['observedOutput'], '0x2a')
        self.assertEqual(result['paths'][0]['environmentReads'][0]['register'], 'gs')
        self.assertEqual(result['paths'][0]['outputProof']['status'], 'unsat')
        use(False)
        with self.assertRaisesRegex(ValueError, 'explicit GS'): analyze(params, TT, image)

    def test_high_byte_parity_is_result_parity_with_input_dependence_retained(self):
        params, image = fixture([b'\x22\xec', b'\x0f\x9a\xc0'], [{'rcx': 1, 'rdx': 2, 'rax': 0xf9d0}, {'rcx': 1, 'rdx': 2, 'rax': 0xf9d0}])
        params.update(trace_inputs=['ecx', 'edx'], trace_output='al')
        result = analyze(params, TT, image)
        self.assertEqual(result['paths'][0]['observedOutput'], '0x1')
        self.assertEqual(result['paths'][0]['semanticCorrections'][0]['flag'], 'PF')
        self.assertEqual(result['paths'][0]['outputProof']['status'], 'unsat')

    def test_rotate_full_word_count_keeps_result_and_has_undefined_of(self):
        params, image = fixture([b'\x66\xc1\xc0\x10', b'\x89\xf8'], [{'rax': 1, 'rdi': 1, 'rsi': 2}, {'rax': 1, 'rdi': 1, 'rsi': 2}])
        rows = base64.b64decode(params['traces'][0]['data']).decode().splitlines()
        # ROL AX,16 keeps AX but updates CF from result bit 0; OF is undefined.
        data = ('h:ig5-native-x64-v2\n' + '\n'.join([rows[0], 'e:0x202', rows[1], rows[2], 'e:0xa03', rows[3]]) + '\n').encode()
        params['traces'][0] = {'data': base64.b64encode(data).decode(), 'sha256': hashlib.sha256(data).hexdigest()}
        result = analyze(params, TT, image)
        self.assertEqual(result['recoveredExpression']['name'], 'x')
        self.assertTrue(result['paths'][0]['snapshotRepairs'])

    def test_rcl_masked_multiple_bit_count_has_undefined_of(self):
        params, image = fixture([b'\xc0\xd2\x1c', b'\x89\xf8'], [{'rdx': 0xa0, 'rdi': 7, 'rsi': 2}, {'rdx': 0x41, 'rdi': 7, 'rsi': 2}])
        params['initial_flags'] = '0x203'
        rows = base64.b64decode(params['traces'][0]['data']).decode().splitlines()
        data = ('h:ig5-native-x64-v2\n' + '\n'.join([rows[0], 'e:0x203', rows[1], rows[2], 'e:0xa03', rows[3]]) + '\n').encode()
        params['traces'][0] = {'data': base64.b64encode(data).decode(), 'sha256': hashlib.sha256(data).hexdigest()}
        result = analyze(params, TT, image)
        self.assertEqual(result['recoveredExpression']['name'], 'x')
        self.assertTrue(result['paths'][0]['snapshotRepairs'])

    def test_variable_rotate_through_carry_keeps_count_and_parent_bits(self):
        for direction, opcode in [('rcl', b'\xd2\xd2'), ('rcr', b'\xd2\xda')]:
            for carry in (0, 1):
                original = 0x11223344556677a0; combined = ((original & 255) << 1) | carry
                rotated = ((combined << 2) | (combined >> 7)) & 511 if direction == 'rcl' else ((combined >> 2) | (combined << 7)) & 511
                after = (original & ~255) | (rotated >> 1)
                params, image = fixture([opcode, b'\x48\x89\xd0'], [{'rcx': 2, 'rdx': original}, {'rcx': 2, 'rdx': after}])
                params.update(trace_inputs=['rcx', 'rdx'], trace_output='rax', initial_flags=hex(0x202 | carry))
                recovery = Recovery(TT, params, image); row = recovery.replay(params['traces'][0], 0); ast = recovery.ast
                actual = recovery.expression_ast(row['outputExpression']); x, y = recovery.input_nodes['x'], recovery.input_nodes['y']
                pair = ast.concat([ast.extract(7, 0, y), ast.bv(carry, 1)])
                for count in range(32):
                    rotated = (ast.bvrol if direction == 'rcl' else ast.bvror)(pair, ast.bv(count % 9, 9))
                    expected = ast.concat([ast.extract(63, 8, y), ast.extract(8, 1, rotated)])
                    self.assertEqual(recovery.proof(ast.distinct(actual, expected), [ast.equal(ast.bvand(x, ast.bv(31, 64)), ast.bv(count, 64))])['status'], 'unsat', (direction, carry, count))

    def test_variable_rol_ror_proved_against_every_constant_count(self):
        # Independent oracle: the pinned library's constant rotation. Under
        # each of 64 exhaustive count classes, compare the recovered expression
        # by SMT. The source count remains symbolic throughout replay.
        for direction, opcode in [('rol', b'\x48\xd3\xc0'), ('ror', b'\x48\xd3\xc8')]:
            params, image = fixture([b'\x48\x89\xd0', opcode], [{'rcx': 2, 'rdx': 0x8000000000000001},
                {'rax': 0x8000000000000001, 'rcx': 2, 'rdx': 0x8000000000000001}])
            params.update(trace_inputs=['rcx', 'rdx'], trace_output='rax')
            recovery = Recovery(TT, params, image); row = recovery.replay(params['traces'][0], 0)
            ast = recovery.ast; actual = recovery.expression_ast(row['outputExpression'])
            count = ast.bvand(recovery.input_nodes['x'], ast.bv(63, 64))
            for n in range(64):
                expected = getattr(ast, 'bv' + direction)(recovery.input_nodes['y'], ast.bv(n, 64))
                self.assertEqual(recovery.proof(ast.distinct(actual, expected), [ast.equal(count, ast.bv(n, 64))])['status'], 'unsat', (direction, n))

    def test_rotate_low_projection_retains_high_source_bits(self):
        params, image = fixture([b'\x48\x89\xd0', b'\x48\xd1\xc0'], [{'rcx': 2, 'rdx': 0x8000000000000001},
            {'rax': 0x8000000000000001, 'rcx': 2, 'rdx': 0x8000000000000001}])
        params.update(trace_inputs=['rcx', 'rdx'], trace_output='al')
        recovery = Recovery(TT, params, image); row = recovery.replay(params['traces'][0], 0); ast = recovery.ast
        expected = ast.extract(7, 0, ast.bvrol(recovery.input_nodes['y'], ast.bv(1, 64)))
        self.assertEqual(row['observedOutput'], '0x3')
        self.assertEqual(recovery.proof(ast.distinct(recovery.expression_ast(row['outputExpression']), expected))['status'], 'unsat')

    def test_memory_rotate_retains_stored_input_and_variable_count(self):
        states = [{'rdi': 0x1230, 'rcx': 2, 'rdx': 9}] * 3
        params, image = fixture([b'\x48\x89\x17', b'\x48\xd3\x07', b'\x48\x8b\x07'], states)
        params.update(trace_inputs=['rcx', 'rdx'], trace_output='rax')
        recovery = Recovery(TT, params, image); row = recovery.replay(params['traces'][0], 0); ast = recovery.ast
        actual = recovery.expression_ast(row['outputExpression']); count = ast.bvand(recovery.input_nodes['x'], ast.bv(63, 64))
        for n in range(64):
            expected = ast.bvrol(recovery.input_nodes['y'], ast.bv(n, 64))
            self.assertEqual(recovery.proof(ast.distinct(actual, expected), [ast.equal(count, ast.bv(n, 64))])['status'], 'unsat', n)

    def test_variable_double_shift_against_every_constant_count(self):
        other = 0xdecafbad01234567
        for direction, opcode in [('shld', b'\x4c\x0f\xa5\xc0'), ('shrd', b'\x4c\x0f\xad\xc0')]:
            params, image = fixture([b'\x48\x89\xd0', opcode], [{'rcx': 2, 'rdx': 1, 'r8': other},
                {'rax': 1, 'rcx': 2, 'rdx': 1, 'r8': other}])
            params.update(trace_inputs=['rcx', 'rdx'], trace_output='rax')
            recovery = Recovery(TT, params, image); row = recovery.replay(params['traces'][0], 0); ast = recovery.ast
            actual = recovery.expression_ast(row['outputExpression']); count = ast.bvand(recovery.input_nodes['x'], ast.bv(63, 64))
            # Constant wide rotation is an independent oracle for each defined
            # SHLD/SHRD count, compared against the recovered variable shift.
            pair = ast.concat([recovery.input_nodes['y'], ast.bv(other, 64)]) if direction == 'shld' else ast.concat([ast.bv(other, 64), recovery.input_nodes['y']])
            for n in range(64):
                rotated = (ast.bvrol if direction == 'shld' else ast.bvror)(pair, ast.bv(n, 128))
                expected = ast.extract(127, 64, rotated) if direction == 'shld' else ast.extract(63, 0, rotated)
                self.assertEqual(recovery.proof(ast.distinct(actual, expected), [ast.equal(count, ast.bv(n, 64))])['status'], 'unsat', (direction, n))

    def test_undefined_16bit_double_shift_is_not_business_input(self):
        params, image = fixture([b'\x66\x44\x0f\xa4\xc2\x12', b'\x89\xd0'],
            [{'rcx': 2, 'rdx': 0x1122334455667788, 'r8': 0x1111222233334444},
             {'rcx': 2, 'rdx': 0x1122334455661234, 'r8': 0x1111222233334444}])
        params.update(trace_inputs=['rcx', 'rdx'])
        result = analyze(params, TT, image)
        self.assertEqual(result['paths'][0]['observedOutput'], '0x55661234')
        self.assertTrue(result['paths'][0]['outputDependsOnEnvironmentUnknowns'])
        self.assertIsNone(result['recoveredExpression'])

    def test_double_shift_zero_preserves_native_flags(self):
        params, image = fixture([b'\x48\x89\xd0', b'\x4c\x0f\xa5\xc0', b'\x90'],
            [{'rcx': 0, 'rdx': 9, 'r8': 17}, {'rax': 9, 'rcx': 0, 'rdx': 9, 'r8': 17}, {'rax': 9, 'rcx': 0, 'rdx': 9, 'r8': 17}])
        # Use an unrelated ABI input pair so the zero count is architectural,
        # rather than an input-dependent flag being overwritten by a snapshot.
        params.update(trace_output='rax', initial_flags='0x203')
        rows = base64.b64decode(params['traces'][0]['data']).decode().splitlines()
        data = ('h:ig5-native-x64-v2\n' + '\n'.join(row + '\ne:0x203' if row.startswith('r:') else row for row in rows) + '\n').encode()
        params['traces'][0] = {'data': base64.b64encode(data).decode(), 'sha256': hashlib.sha256(data).hexdigest()}
        self.assertEqual(analyze(params, TT, image)['paths'][0]['observedOutput'], '0x9')

    def test_cpuid_leaf_one_ignores_input_ecx_and_continuation_is_explicit(self):
        code = [b'\xb8\x01\0\0\0', b'\x0f\xa2', b'\xf9', b'\x89\xf8']
        params, image = fixture(code, [{'rcx': 1, 'rdi': 3, 'rsi': 2}, {'rax': 1, 'rcx': 1, 'rdi': 3, 'rsi': 2},
            {'rax': 0x806ec, 'rbx': 0x7100800, 'rcx': 0x7ffafbbf, 'rdx': 0xbfebfbff, 'rdi': 3, 'rsi': 2},
            {'rax': 0x806ec, 'rbx': 0x7100800, 'rcx': 0x7ffafbbf, 'rdx': 0xbfebfbff, 'rdi': 3, 'rsi': 2}])
        params.update(trace_inputs=['ecx', 'edx'])
        rows = base64.b64decode(params['traces'][0]['data']).decode().splitlines()
        data = ('h:ig5-native-x64-v2\n' + '\n'.join([rows[0], 'e:0x202', rows[1], rows[2], 'e:0x202', rows[3],
            'c:' + rows[5][2:], rows[6], 'e:0x203', rows[7]]) + '\n').encode()
        params['traces'][0] = {'data': base64.b64encode(data).decode(), 'sha256': hashlib.sha256(data).hexdigest()}
        result = analyze(params, TT, image)
        self.assertEqual(result['paths'][0]['unobservedContinuationInstructions'], 1)
        self.assertTrue(any(row.get('operation') == 'cpuid-nonindexed-leaf' for row in result['paths'][0]['semanticCorrections']))
        bad = data.replace(b':1:f9\n', b':1:58\n')
        with self.assertRaisesRegex(ValueError, 'Unsupported unobserved'): parse_trace(bad, 100)

    def test_cpuid_byte_test_continuation_keeps_hardware_flags_explicit(self):
        code = [b'\xb8\x01\0\0\0', b'\x0f\xa2', b'\xf6\xc6\x02', b'\x89\xf8']
        hardware = {'rax': 11, 'rbx': 22, 'rcx': 33, 'rdx': 0x200, 'rdi': 3, 'rsi': 2}
        params, image = fixture(code, [{'rdi': 3, 'rsi': 2}, {'rax': 1, 'rdi': 3, 'rsi': 2}, hardware, hardware])
        rows = base64.b64decode(params['traces'][0]['data']).decode().splitlines()
        data = ('h:ig5-native-x64-v2\n' + '\n'.join([rows[0], 'e:0x202', rows[1], rows[2], 'e:0x202', rows[3],
            'c:' + rows[5][2:], rows[6], 'e:0x202', rows[7]]) + '\n').encode()
        params['traces'][0] = {'data': base64.b64encode(data).decode(), 'sha256': hashlib.sha256(data).hexdigest()}
        result = analyze(params, TT, image)
        self.assertEqual(result['paths'][0]['unobservedContinuationInstructions'], 1)
        self.assertEqual(result['paths'][0]['observedOutput'], '0x3')
        self.assertEqual(result['paths'][0]['outputProof']['status'], 'unsat')
        self.assertTrue(any(row.get('flag') == 'PF' for row in result['paths'][0]['semanticCorrections']))
        self.assertFalse(result['nativeTargetExecuted'])

    def test_cpuid_byte_test_recorder_check_corrects_defined_pf_only(self):
        opcode = b'\xf6\xc6\x02'; description = cpuid_continuation(opcode)
        self.assertEqual(description['register'], 'dh')
        ctx = TT.TritonContext(TT.ARCH.X86_64)
        ctx.setConcreteRegisterValue(ctx.registers.rdx, 0x200)
        ctx.setConcreteRegisterValue(ctx.registers.eflags, 0x213)
        ins = TT.Instruction(0x1000, opcode)
        self.assertEqual(apply_native_continuation(ctx, ins, TT, description, 0x202), TT.EXCEPTION.NO_FAULT)
        self.assertEqual(ctx.getConcreteRegisterValue(ctx.registers.rdx), 0x200)
        self.assertEqual(ctx.getConcreteRegisterValue(ctx.registers.pf), 0)
        self.assertEqual(ctx.getConcreteRegisterValue(ctx.registers.af), 0)
        self.assertEqual(ctx.getConcreteRegisterValue(ctx.registers.rip), 0x1003)
        for rejected in (b'\xf6\x06\x02', b'\xf6\xd6\x02', b'\x74\x01', b'\x88\xd0'):
            self.assertIsNone(cpuid_continuation(rejected))

    def test_cpuid_word_compare_continuation_preserves_hardware_and_input(self):
        tail = b'\x66\x81\xf9\x97\xcd'
        description = cpuid_continuation(tail)
        self.assertEqual(description['register'], 'cx')
        self.assertEqual(description['undefinedFlags'], [])
        for value in (0, 0x7fff, 0x8000, 0xcd97, 0xffff):
            ctx = TT.TritonContext(TT.ARCH.X86_64)
            parent = 0x123456789abc0000 | value
            ctx.setConcreteRegisterValue(ctx.registers.rcx, parent)
            ctx.setConcreteRegisterValue(ctx.registers.eflags, 0x202)
            difference = (value - 0xcd97) & 0xffff
            expected = {'cf': int(value < 0xcd97), 'pf': 1 ^ ((difference & 0xff).bit_count() & 1),
                'af': ((value ^ 0xcd97 ^ difference) >> 4) & 1, 'zf': int(difference == 0),
                'sf': difference >> 15, 'of': ((value ^ 0xcd97) & (value ^ difference)) >> 15 & 1}
            ins = TT.Instruction(0x1000, tail)
            self.assertEqual(apply_native_continuation(ctx, ins, TT, description, 0), TT.EXCEPTION.NO_FAULT)
            self.assertEqual(ctx.getConcreteRegisterValue(ctx.registers.rcx), parent)
            for flag, result in expected.items(): self.assertEqual(ctx.getConcreteRegisterValue(getattr(ctx.registers, flag)), result, (value, flag))
        code = [b'\xb8\x01\0\0\0', b'\x0f\xa2', tail, b'\x89\xf8']
        hardware = {'rax': 11, 'rbx': 22, 'rcx': 0xcd97, 'rdx': 44, 'rdi': 3, 'rsi': 2}
        params, image = fixture(code, [{'rdi': 3, 'rsi': 2}, {'rax': 1, 'rdi': 3, 'rsi': 2}, hardware, hardware])
        rows = base64.b64decode(params['traces'][0]['data']).decode().splitlines()
        data = ('h:ig5-native-x64-v2\n' + '\n'.join([rows[0], 'e:0x202', rows[1], rows[2], 'e:0x202', rows[3],
            'c:' + rows[5][2:], rows[6], 'e:0x246', rows[7]]) + '\n').encode()
        params['traces'][0] = {'data': base64.b64encode(data).decode(), 'sha256': hashlib.sha256(data).hexdigest()}
        result = analyze(params, TT, image)
        self.assertEqual(result['paths'][0]['unobservedContinuationInstructions'], 1)
        self.assertEqual(result['paths'][0]['observedOutput'], '0x3')
        self.assertTrue(result['proofScope']['allInputPairsProved'])
        for bad in (b'\x66\x81\x39\x97\xcd', b'\x66\x81\xd9\x97\xcd', tail + b'\x90', b'\x67\x81\xf9\x97\xcd'):
            self.assertIsNone(cpuid_continuation(bad))

    def test_cpuid_gpr_immediate_continuation_keeps_symbolic_input(self):
        code = [b'\xb8\x01\0\0\0', b'\x0f\xa2', b'\x48\x81\xef\x08\0\0\0', b'\x89\xf8']
        states = [{'rdi': 9, 'rsi': 2}, {'rax': 1, 'rdi': 9, 'rsi': 2},
                  {'rax': 11, 'rbx': 22, 'rcx': 33, 'rdx': 44, 'rdi': 9, 'rsi': 2},
                  {'rax': 11, 'rbx': 22, 'rcx': 33, 'rdx': 44, 'rdi': 1, 'rsi': 2}]
        params, image = fixture(code, states)
        rows = base64.b64decode(params['traces'][0]['data']).decode().splitlines()
        # Deliberately no intermediate CPUID-output snapshot before SUB RDI,8.
        data = ('h:ig5-native-x64-v2\n' + '\n'.join([rows[0], 'e:0x202', rows[1], rows[2], 'e:0x202', rows[3],
            'c:' + rows[5][2:], rows[6], 'e:0x202', rows[7]]) + '\n').encode()
        params['traces'][0] = {'data': base64.b64encode(data).decode(), 'sha256': hashlib.sha256(data).hexdigest()}
        result = analyze(params, TT, image)
        self.assertEqual(result['paths'][0]['observedOutput'], '0x1')
        self.assertEqual(result['paths'][0]['unobservedContinuationInstructions'], 1)
        self.assertEqual(result['paths'][0]['outputProof']['status'], 'unsat')
        self.assertTrue(result['paths'][0]['binaryBinding']['allInstructionBytesMatch'])
        self.assertIsNotNone(result['recoveredExpression'])
        # CPUID outputs, memory operations, arbitrary instructions and multiple
        # hidden instructions must stay rejected; no fabricated snapshot repair.
        for bad in (data.replace(b'4881ef08000000', b'4881e808000000'),
                    data.replace(b'4881ef08000000', b'48812f08000000'),
                    data.replace(b':7:4881ef08000000', b':2:9090')):
            with self.assertRaisesRegex(ValueError, 'Unsupported unobserved'): parse_trace(bad, 100)

    def test_pe_dir64_binding_is_deterministic_and_rejects_unproven_fixups(self):
        blob, meta = pe_fixture(); data = bytearray(blob)
        struct.pack_into('<II', data, meta['directories'] + 5 * 8, 0x2000, 12)
        struct.pack_into('<IIHH', data, 0x400, 0x1000, 12, 0xa010, 0)
        struct.pack_into('<Q', data, 0x210, meta['base'] + 0x1000)
        image = BinaryImage.from_bytes(bytes(data)); binding = TraceByteBinding(image, meta['base'] + 0x100000)
        original, loaded = binding.read(meta['base'] + 0x1010, 8)
        self.assertEqual(int.from_bytes(loaded, 'little'), meta['base'] + 0x101000)
        self.assertEqual(image.read(meta['base'] + 0x1010, 8), original)
        self.assertEqual(binding.fixups_at(meta['base'] + 0x1010, 8)[0]['type'], 'IMAGE_REL_BASED_DIR64')
        bad = bytearray(data); struct.pack_into('<H', bad, 0x408, 0x3010)
        with self.assertRaisesRegex(ValueError, 'Unsupported AMD64'): TraceByteBinding(BinaryImage.from_bytes(bytes(bad)), meta['base'] + 0x100000)
        bad = bytearray(data); struct.pack_into('<H', bad, 0x40a, 0xa010)
        with self.assertRaisesRegex(ValueError, 'Overlapping'): TraceByteBinding(BinaryImage.from_bytes(bytes(bad)), meta['base'] + 0x100000)


if __name__ == '__main__': unittest.main(verbosity=2)
