"""IG5 offline x86-64 trace semantics. Recorded bytes are never executed natively.

Recovery is relative to the supplied trace and recorded environment. A complete
trace model is not a proof of coverage/equivalence of the original executable.
"""
import base64
import hashlib
import importlib.util
import itertools
import json
import os
from pathlib import Path
import re
import sys
import time
from trace_binding import TraceByteBinding
from trace_continuation import cpuid_continuation
from trace_hardware import process_instruction
from trace_expression import normalize_expression
from trace_ast_normalization import normalize_ast
from trace_smt_dag import lower_query
from trace_expression_proof import prove_instance as prove_expression_instance
from trace_guard_domain import diagnose_guard_domain

GPRS = 'rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split()
INPUT_REGS = {'dil': 8, 'sil': 8, 'di': 16, 'si': 16, 'edi': 32, 'esi': 32, 'rdi': 64, 'rsi': 64,
              'cl': 8, 'dl': 8, 'cx': 16, 'dx': 16, 'ecx': 32, 'edx': 32, 'rcx': 64, 'rdx': 64}
INPUT_PAIRS = [('dil', 'sil'), ('di', 'si'), ('edi', 'esi'), ('rdi', 'rsi'),
               ('cl', 'dl'), ('cx', 'dx'), ('ecx', 'edx'), ('rcx', 'rdx')]
OUTPUT_REGS = {'al': 8, 'ax': 16, 'eax': 32, 'rax': 64}
DLL_HANDLES = []
MANIFEST_SHA256 = '65bf673f1c4304cc2c09076e3b96e368da9e0df72aa0badeba0c2a5cae392934'


def load_triton():
    vendor = Path(__file__).resolve().parent / 'trace_vendor'
    manifest_bytes = (vendor / 'ig5-manifest.json').read_bytes()
    if hashlib.sha256(manifest_bytes).hexdigest() != MANIFEST_SHA256: raise ValueError('Pinned trace dependency inventory changed')
    manifest = json.loads(manifest_bytes.decode('utf-8'))
    # Check every new native asset before import. Existing runtime pins are separate.
    for row in manifest['files']:
        filename = vendor / row['path']
        if filename.resolve() != filename.absolute() or not filename.is_file():
            raise ValueError('Trace dependency is missing or linked: ' + row['path'])
        data = filename.read_bytes()
        if len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256']:
            raise ValueError('Trace dependency hash mismatch: ' + row['path'])
    if os.name != 'nt' or sys.version_info[:2] != (3, 12):
        raise ValueError('Offline trace recovery currently requires bundled Windows x64 Python 3.12')
    for directory in (vendor, vendor / 'triton_library-1.0.0rc4.data/platlib'):
        DLL_HANDLES.append(os.add_dll_directory(str(directory)))
    spec = importlib.util.spec_from_file_location('triton', vendor / 'triton.cp312-win_amd64.pyd')
    triton = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(triton)
    sys.modules['triton'] = triton
    return triton


def bounded_int(value, low, high, label):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(label + ' is outside its integer budget')
    return value


def address(value):
    if not isinstance(value, str) or not re.fullmatch(r'0x[0-9a-fA-F]{1,16}', value):
        raise ValueError('Trace addresses/initial_flags must be explicit hexadecimal strings')
    return int(value, 16)


class ParsedTrace(list):
    final_registers = None
    native_semantics = False


def parse_trace(data, maximum):
    if not data or len(data) > 4 * 1024 * 1024 or not data.endswith(b'\n'):
        raise ValueError('Trace must be complete newline-terminated ASCII, at most 4 MiB')
    pending_regs, pending_memory, instructions = None, [], ParsedTrace()
    instructions.flag_snapshots = {}
    instructions.segment_bases = {}
    previous_regs = None
    pending_flags = None
    for line in data.decode('ascii', errors='strict').splitlines():
        if len(line) > 1024: raise ValueError('Trace record exceeds 1024 bytes')
        row = line.split(':')
        if instructions.final_registers is not None: raise ValueError('Records after final snapshot are refused')
        if row in (['h', 'ig5-native-x64-v1'], ['h', 'ig5-native-x64-v2']) and not instructions and pending_regs is None and not pending_memory and not instructions.native_semantics:
            instructions.native_semantics = row[1]
        elif row[0] == 's' and len(row) == 3 and row[1] == 'gs' and instructions.native_semantics and not instructions and pending_regs is None and 'gs' not in instructions.segment_bases:
            instructions.segment_bases['gs'] = address(row[2])
        elif row[0] == 'r' and len(row) == 17 and pending_regs is None:
            pending_regs = [address(value) for value in row[1:]]
        elif row[0] == 'd' and instructions.native_semantics == 'ig5-native-x64-v2' and previous_regs is not None and pending_regs is None and len(row) >= 2:
            mask = address(row[1])
            if mask > 0xffff or len(row) != 2 + mask.bit_count(): raise ValueError('Native register delta mask/value count differs')
            pending_regs = list(previous_regs)
            values = iter(row[2:])
            for index in range(16):
                if mask & (1 << index): pending_regs[index] = address(next(values))
        elif row[0] == 'e' and len(row) == 2 and instructions.native_semantics and pending_regs is not None and pending_flags is None and not pending_memory:
            pending_flags = address(row[1])
            if pending_flags >= 1 << 32: raise ValueError('Native EFLAGS exceeds 32 bits')
        elif row[0] == 'mr' and len(row) == 4:
            size = int(row[2])
            if size not in (1, 2, 4, 8, 16, 32, 64): raise ValueError('Unsupported trace memory width')
            # Memory values may be wider than machine addresses.
            if not re.fullmatch(r'0x[0-9a-fA-F]{1,128}', row[3]): raise ValueError('Invalid trace memory value')
            value = int(row[3], 16)
            if value >= 1 << (size * 8) or len(pending_memory) >= 8: raise ValueError('Trace memory record exceeds its budget')
            pending_memory.append((address(row[1]), size, value))
        elif row[0] == 'i' and len(row) == 4 and pending_regs is not None:
            if instructions.native_semantics and pending_flags is None: raise ValueError('Native trace omits flags snapshot')
            size = int(row[2])
            if not 1 <= size <= 15 or not re.fullmatch(r'[0-9a-fA-F]{' + str(size * 2) + '}', row[3]):
                raise ValueError('Invalid instruction size/bytes')
            instructions.flag_snapshots[len(instructions)] = pending_flags
            instructions.append((address(row[1]), bytes.fromhex(row[3]), pending_regs, pending_memory))
            previous_regs = list(pending_regs)
            pending_regs, pending_memory = None, []
            pending_flags = None
            if len(instructions) > maximum: raise ValueError('Trace instruction budget exceeded; no proof committed')
        elif row[0] == 'c' and len(row) == 4 and instructions.native_semantics == 'ig5-native-x64-v2' and pending_regs is None and not pending_memory and instructions:
            # A native stop can coalesce CPUID with one adjacent instruction.
            # Its bytes are explicit; the intermediate snapshot is NOT invented.
            prior_ea, prior_bytes, _, _ = instructions[-1]
            size = int(row[2])
            if not 1 <= size <= 7 or not re.fullmatch(r'[0-9a-f]{' + str(size * 2) + '}', row[3]): raise ValueError('Unsupported unobserved instruction continuation')
            continuation = bytes.fromhex(row[3])
            if prior_bytes != b'\x0f\xa2' or cpuid_continuation(continuation) is None or address(row[1]) != prior_ea + 2:
                raise ValueError('Unsupported unobserved instruction continuation')
            instructions.append((address(row[1]), continuation, None, []))
            if len(instructions) > maximum: raise ValueError('Trace instruction budget exceeded')
        elif row[0] == 'f' and len(row) == 19 and pending_regs is None and not pending_memory and instructions:
            instructions.final_registers = [address(value) for value in row[1:]]
        else: raise ValueError('Invalid or incomplete trace record ordering')
    if pending_regs is not None or pending_memory or not instructions: raise ValueError('Trace ends with an incomplete instruction')
    return instructions


class Recovery:
    def __init__(self, tt, params, image):
        self.tt, self.params, self.image = tt, params, image
        self.deadline = time.monotonic() + 50
        self.solver_queries = 0
        self.proof_cache = {}
        self.proof_cache_hits = 0
        self.local_templates = {}
        self.expression_templates = {}
        self.ctx = tt.TritonContext(tt.ARCH.X86_64)
        self.ast = self.ctx.getAstContext()
        # rc4 exposes lxor() but omits its AST_NODE constant from Python.
        self.logical_xor_kind = self.ast.lxor([self.ast.equal(self.ast.bv(0, 1), self.ast.bv(0, 1)), self.ast.equal(self.ast.bv(0, 1), self.ast.bv(1, 1))]).getType()
        for mode in (tt.MODE.ALIGNED_MEMORY, tt.MODE.AST_OPTIMIZATIONS, tt.MODE.CONSTANT_FOLDING): self.ctx.setMode(mode, True)
        self.ctx.setSolverTimeout(2000)
        self.ctx.setSolverMemoryLimit(512)
        self.ctx.setConcreteRegisterValue(self.ctx.registers.eflags, address(params['initial_flags']))
        self.unknown = {}
        self.frozen_unknown = set()
        self.input_nodes = {}
        self.projected_environment = {}
        # Default state budget is unchanged. Explicit long recordings get a
        # proportional finite budget, within the same worker time/solver limits.
        self.unknown_budget = 20000 * ((params.get('max_instructions', 50000) + 49999) // 50000)
        self.runtime_base = address(params['trace_runtime_base']) if 'trace_runtime_base' in params else image.imagebase
        self.byte_binding = TraceByteBinding(image, self.runtime_base, params.get('loaded_image') or params.get('traces', [{}])[0].get('loaded_image'))

    def budget(self):
        if time.monotonic() > self.deadline: raise ValueError('Trace recovery deadline exceeded; no proof committed')

    def remember_unknown(self, symbol):
        self.unknown[symbol.getId()] = symbol
        if len(self.unknown) > self.unknown_budget: raise ValueError('Trace independent-state variable budget exceeded')

    def variables(self, node):
        return {v.getSymbolicVariable().getId(): v.getSymbolicVariable() for v in self.ast.search(node, self.tt.AST_NODE.VARIABLE)}

    def conjunction(self, rows):
        if not rows: return self.ast.equal(self.ast.bv(1, 1), self.ast.bv(1, 1))
        return self.ast.land(rows) if len(rows) > 1 else rows[0]

    def flags_ast(self):
        # Triton's aggregate EFLAGS AST does not carry each symbolic flag.
        # Compose the modeled bits explicitly so undefined AF and argument
        # dependencies survive native snapshot validation.
        positions = {'cf': 0, 'pf': 2, 'af': 4, 'zf': 6, 'sf': 7, 'tf': 8, 'if': 9, 'df': 10,
                     'of': 11, 'nt': 14, 'ac': 18, 'vif': 19, 'vip': 20, 'id': 21}
        bits = self.ctx.registers.eflags.getBitSize()
        mask = sum(1 << bit for bit in positions.values()) | 2
        concrete = self.ctx.getConcreteRegisterValue(self.ctx.registers.eflags) & ~mask
        symbolic = []
        for name, bit in positions.items():
            flag = self.ctx.getRegisterAst(getattr(self.ctx.registers, name))
            if flag.isSymbolized(): symbolic.append((flag, bit))
            else: concrete |= flag.evaluate() << bit
        node = self.ast.bv(concrete, bits)
        for flag, bit in symbolic:
            node = self.ast.bvor(node, self.ast.bvshl(self.ast.zx(bits - 1, flag), self.ast.bv(bit, bits)))
        return node

    def operand_ast(self, operand):
        if operand.getType() == self.tt.OPERAND.REG: return self.ctx.getRegisterAst(operand)
        if operand.getType() == self.tt.OPERAND.MEM: return self.ctx.getMemoryAst(operand)
        return self.ctx.getImmediateAst(operand)

    def assign_operand_value(self, operand, value, parent_before, instruction):
        ctx, ast, tt = self.ctx, self.ast, self.tt
        width = value.getBitvectorSize()
        if operand.getType() == tt.OPERAND.REG:
            destination = ctx.getParentRegister(operand); full = destination.getBitSize()
            if width == full: assigned = value
            elif width == 32 and full == 64: assigned = ast.zx(32, value)
            else:
                low = 8 if operand.getName() in ('ah', 'bh', 'ch', 'dh') else 0
                preserve = ((1 << full) - 1) ^ (((1 << width) - 1) << low)
                assigned = ast.bvor(ast.bvand(parent_before, ast.bv(preserve, full)), ast.bvshl(ast.zx(full - width, value), ast.bv(low, full)))
            ctx.assignSymbolicExpressionToRegister(ctx.newSymbolicExpression(assigned), destination)
        else:
            stores = instruction.getStoreAccess()
            if len(stores) != 1: raise ValueError('Modeled memory destination is not unique')
            ctx.assignSymbolicExpressionToMemory(ctx.newSymbolicExpression(value), stores[0][0])

    def proof(self, counterexample, assumptions=(), direct_fallback=False):
        self.budget()
        assumptions = tuple(assumptions)
        key = (counterexample.getHash(), tuple(node.getHash() for node in assumptions))
        # Structural equality verifies hashes before reuse. Assumptions are
        # part of the key; observed environment/input assignments cannot leak
        # across different requests or paths. Only proved SAT/UNSAT is cached.
        for prior_node, prior_assumptions, prior_result in self.proof_cache.get(key, ()):
            if counterexample.equalTo(prior_node) and all(left.equalTo(right) for left, right in zip(assumptions, prior_assumptions)):
                self.proof_cache_hits += 1
                return {**prior_result, 'solverMs': 0, 'cachedSolverMs': prior_result['solverMs'], 'cacheHit': True}
        original_query = self.conjunction(list(assumptions) + [counterexample])
        try:
            query, dag = lower_query(self.ctx, self.tt, original_query, self.budget,
                'ig5_smt_' + str(self.solver_queries) + '_')
            original_variables = set(dag['originalVariableIds'])
        except (ValueError, RecursionError) as error:
            self.budget()
            if not direct_fallback:
                return {'status': 'unknown', 'solverMs': 0, 'counterexample': None,
                    'reason': str(error), 'method': 'bounded-SMT-DAG-refusal'}
            # State reconciliation keeps the previous exact solver route when
            # optional DAG lowering refuses. No constraint is removed; the
            # original 2-second/512-MiB/query/request budgets still apply.
            query, original_variables = original_query, None
            dag = {'method': 'direct-original-AST-fallback', 'dagRefusal': str(error),
                'scope': 'Complete original counterexample and all assumptions retained'}
        self.solver_queries += 1
        if self.solver_queries > 128: raise ValueError('Trace solver query budget exceeded')
        model, status, elapsed = self.ctx.getModel(query, status=True, timeout=2000)
        states = {self.tt.SOLVER_STATE.UNSAT: 'unsat', self.tt.SOLVER_STATE.SAT: 'sat', self.tt.SOLVER_STATE.TIMEOUT: 'timeout', self.tt.SOLVER_STATE.UNKNOWN: 'unknown'}
        result = {'status': states.get(status, 'unknown'), 'solverMs': elapsed,
                'counterexample': {item.getVariable().getAlias(): hex(item.getValue()) for item in model.values()
                    if original_variables is None or item.getVariable().getId() in original_variables} if status == self.tt.SOLVER_STATE.SAT else None,
                'solverDag': {key: value for key, value in dag.items() if key not in ('freshVariableIds','originalVariableIds')}}
        if result['status'] in ('sat', 'unsat'):
            self.proof_cache.setdefault(key, []).append((counterexample, assumptions, result))
        return result

    def prove_ast_instance(self, before, after, rule, counts):
        """Universal small SMT lemma, instantiated by the normalizer's exact match.

        The subject is arbitrary over its FULL width; no observed value,
        reference formula, path assumption or original input assignment is used.
        Actual replacements retain the original subject, never this fresh symbol.
        """
        bits = before.getBitvectorSize()
        if rule != 'complementary-shift-rotation' or bits != after.getBitvectorSize() or len(counts) not in (1, 2) or any(not 0 < count < bits for count in counts):
            raise ValueError('Unknown local AST instantiation')
        key = (rule, bits, tuple(counts))
        if key not in self.local_templates:
            variable = self.ctx.newSymbolicVariable(bits, 'ig5_local_rotation_' + str(len(self.local_templates)))
            subject = self.ast.variable(variable); left = subject
            for count in counts:
                left = self.ast.bvor(self.ast.bvshl(left, self.ast.bv(count, bits)),
                    self.ast.bvlshr(left, self.ast.bv(bits - count, bits)))
            right = self.ast.bvrol(subject, self.ast.bv(sum(counts) % bits, bits))
            self.local_templates[key] = self.ast.distinct(left, right)
        proof = self.proof(self.local_templates[key])
        return {**proof, 'method': 'SMT-universal-local-template-and-exact-instantiation',
            'template': {'rule': rule, 'subjectBits': bits, 'counts': list(counts)},
            'scope': 'Full-width arbitrary subject; exact matched terms are substituted; parent rebuilding preserves equality'}

    def candidate_value_at_model(self, expression, model):
        """Evaluate only a small candidate at a SAT model; never mutate inputs.

        This is negative-search evidence, never an equivalence proof. Missing
        inputs/environment or a large expression simply disable reuse.
        """
        remaining = [256]
        def literal(value, depth=0):
            remaining[0] -= 1
            if remaining[0] < 0 or depth > 32: raise ValueError('Candidate witness evaluation budget')
            if isinstance(value, list): return [literal(item, depth + 1) for item in value]
            if not isinstance(value, dict): return value
            if value.get('op') == 'environment': raise ValueError('Candidate is not input-only')
            if value.get('op') == 'input':
                name, bits = value['name'], value['bits']
                node = self.input_nodes.get(name)
                if node is None or not isinstance(bits, int) or isinstance(bits, bool) or not 1 <= bits <= node.getBitvectorSize():
                    raise ValueError('Candidate input width differs')
                text = model.get(name)
                if not isinstance(text, str) or not re.fullmatch(r'0x[0-9a-fA-F]+', text): raise ValueError('Incomplete candidate model')
                number = int(text, 16)
                if number >= 1 << node.getBitvectorSize(): raise ValueError('Model exceeds input width')
                return {'op': 'constant', 'bits': bits, 'value': hex(number & ((1 << bits) - 1))}
            return {key: literal(item, depth + 1) if isinstance(item, (dict, list)) else item for key, item in value.items()}
        try: return bool(self.predicate_ast(literal(expression)).evaluate())
        except (ValueError, KeyError, TypeError, RecursionError): return None

    def search_guard_candidates(self, rows, candidates, environment_assumptions):
        attempts, rejected, witnesses = [], [], []
        search = {'attempts': attempts, 'rejectedByWitness': rejected, 'witnesses': witnesses,
            'scope': 'SAT counterexamples only reject candidates; acceptance always requires full original guard equivalence UNSAT'}
        if not rows: return None, None, search
        merged = self.conjunction([row[1] for row in rows])
        assumptions = [item for row in rows for item in row[2]]
        for label, candidate, expression in candidates[:42]:
            self.budget()
            if self.solver_queries >= 120: break
            rejection = None
            for index, witness in enumerate(witnesses):
                value = self.candidate_value_at_model(expression, witness['inputs'])
                if value is not None and value != witness['guardValue']:
                    rejection = {'candidate': label, 'conditionExpression': expression, 'witnessIndex': index,
                        'candidateValue': value, 'guardValue': witness['guardValue'], 'method': 'exact-SAT-counterexample-reuse'}
                    break
            if rejection is not None:
                rejected.append(rejection)
                continue
            proof = self.proof(self.ast.lxor([merged, candidate]), assumptions)
            attempts.append({'candidate': label, 'conditionExpression': expression, 'proof': proof})
            if proof['status'] == 'unsat':
                guard = {'expression': label, 'conditionExpression': expression,
                    'sources': [hex(row[0]) for row in rows], 'proof': proof, 'environmentAssumptions': environment_assumptions}
                return guard, candidate, search
            if proof['status'] == 'sat' and len(witnesses) < 16:
                model = proof.get('counterexample') or {}
                value = self.candidate_value_at_model(expression, model)
                if value is not None:
                    witnesses.append({'sourceAttempt': len(attempts) - 1,
                        'inputs': {name: model[name] for name in self.input_nodes if name in model},
                        'guardValue': not value, 'method': 'SAT-of-full-guard-XOR-candidate'})
        return None, None, search

    def reconcile(self, node, expected):
        """Assign only previously unobserved undefined-flag variables; never erase inputs."""
        variables = self.variables(node)
        free = [sv for ident, sv in variables.items() if ident in self.unknown and ident not in self.frozen_unknown]
        if len(free) > 8: raise ValueError('Undefined flag reconciliation exceeds its budget')
        values = [self.ctx.getConcreteVariableValue(sv) for sv in free]
        if any(sv.getBitSize() != 1 for sv in free):
            fixed = [self.ast.equal(self.ast.variable(sv), self.ast.bv(self.ctx.getConcreteVariableValue(sv), sv.getBitSize()))
                     for ident, sv in variables.items() if ident not in {item.getId() for item in free}]
            result = self.proof(self.ast.equal(node, self.ast.bv(expected, node.getBitvectorSize())), fixed, direct_fallback=True)
            if result['status'] != 'sat': raise ValueError('Undefined register reconciliation could not be solved: ' + result['status'] + ' / ' + result.get('reason', ''))
            for sv in free:
                value = result['counterexample'].get(sv.getAlias())
                if value is not None: self.ctx.setConcreteVariableValue(sv, int(value, 16))
            if node.evaluate() != expected: raise ValueError('Undefined register model did not match observation')
            self.frozen_unknown.update(ident for ident in variables if ident in self.unknown)
            return [{'variable': sv.getAlias(), 'value': hex(self.ctx.getConcreteVariableValue(sv))} for sv in free]
        for bits in itertools.product((0, 1), repeat=len(free)):
            for sv, bit in zip(free, bits): self.ctx.setConcreteVariableValue(sv, bit)
            if node.evaluate() == expected:
                self.frozen_unknown.update(ident for ident in variables if ident in self.unknown)
                return [{'variable': sv.getAlias(), 'value': hex(self.ctx.getConcreteVariableValue(sv))} for sv in free]
        for sv, value in zip(free, values): self.ctx.setConcreteVariableValue(sv, value)
        raise ValueError('Recorded state conflicts with symbolic semantics; input dependency was preserved, recovery refused')

    def replay(self, trace, index):
        ctx, ast, tt = self.ctx, self.ast, self.tt
        recording = trace.get('recording')
        if recording is None:
            recording = {'entry': self.params['trace_entry'], 'exit': self.params['trace_exit'],
                         'runtimeBase': self.params.get('trace_runtime_base', hex(self.image.imagebase)), 'initialFlags': self.params['initial_flags']}
        if not isinstance(recording, dict) or set(recording) != {'entry', 'exit', 'runtimeBase', 'initialFlags'}:
            raise ValueError('Incomplete per-path recording environment')
        declared = {key: address(value) for key, value in recording.items()}
        if declared['initialFlags'] >= 1 << 32: raise ValueError('Initial recording flags exceed 32 bits')
        self.runtime_base = declared['runtimeBase']
        self.byte_binding = TraceByteBinding(self.image, self.runtime_base, trace.get('loaded_image') or self.params.get('loaded_image'))
        entry_rva = declared['entry'] - self.runtime_base
        if index == 0: self.entry_rva = entry_rva
        elif entry_rva != self.entry_rva: raise ValueError('Recorded paths have different function entry RVAs')
        records = parse_trace(base64.b64decode(trace['data'], validate=True), self.params.get('max_instructions', 50000))
        if self.params.get('trace_image_only') is True and (not records.native_semantics or records.final_registers is None):
            raise ValueError('Recorded-image-only mode requires native trace semantics and a final snapshot')
        if records[0][0] != declared['entry'] or records[-1][0] != declared['exit']:
            raise ValueError('Trace entry/exit does not match declared boundaries')
        ctx.concretizeAllMemory(); ctx.concretizeAllRegister(); ctx.clearPathConstraints()
        # Independent recordings share only the x/y symbols. Registers/memory
        # no longer reference the previous path's hardware/undefined state;
        # its serialized evidence and proved input-only guard stay in rows.
        # Release those path-local observation maps rather than accumulating
        # stale variables or reusing their observations in the next run.
        self.unknown.clear(); self.frozen_unknown.clear(); self.projected_environment.clear()
        ctx.setConcreteRegisterValue(ctx.registers.eflags, declared['initialFlags'])
        for name, value in records.segment_bases.items(): ctx.setConcreteRegisterValue(getattr(ctx.registers, name), value)
        snapshots, address_conditions, control_conditions, environment_address_checks = [], [], [], []
        environment_reads, semantic_corrections = [], []
        for name, value in records.segment_bases.items():
            environment_reads.append({'operation': 'declared-segment-base', 'register': name, 'value': hex(value),
                                      'policy': 'explicit trace environment assumption; native recorder derives Windows x64 GS from the thread TEB, not a hardware GS measurement'})
        written_memory = set()
        initial_memory = set()
        matches, original_matches, mismatches, unmapped, relocation_matches = 0, 0, [], 0, []
        previous = None
        inputs = {}
        for seq, (ea, opcode, regs, memory) in enumerate(records):
            self.budget()
            if previous is not None:
                rip = ctx.getRegisterAst(ctx.registers.rip)
                if rip.evaluate() != ea: raise ValueError('Instruction sequence disagrees with replayed control flow at #' + str(seq) + ' after ' + hex(previous) + ': expected=' + hex(rip.evaluate()) + ' recorded=' + hex(ea))
                if rip.isSymbolized(): control_conditions.append((previous, ast.equal(rip, ast.bv(ea, 64))))
            for name, expected in zip(GPRS, regs or []):
                reg = getattr(ctx.registers, name)
                if ctx.getConcreteRegisterValue(reg) != expected:
                    node = ctx.getRegisterAst(reg)
                    if node.isSymbolized():
                        try: repairs = self.reconcile(node, expected)
                        except ValueError as error: raise ValueError(str(error) + ' at #' + str(seq) + ' ' + hex(ea) + ' register=' + name + ' after=' + hex(previous or 0) + ' actual=' + hex(node.evaluate()) + ' observed=' + hex(expected)) from error
                        snapshots.append({'instruction': seq, 'register': name, 'undefinedVariables': repairs})
                    elif seq: raise ValueError('Concrete register snapshot conflicts with trace semantics at ' + hex(ea) + ': ' + name + ' after ' + hex(previous) + ' actual=' + hex(ctx.getConcreteRegisterValue(reg)) + ' observed=' + hex(expected))
                    else: ctx.setConcreteRegisterValue(reg, expected)
                # Zero hardware/undefined values are also actual observations,
                # even when they match a decoder's current concrete value.
                # Freeze only independent environment variables, never inputs.
                node = ctx.getRegisterAst(reg)
                if node.isSymbolized(): self.frozen_unknown.update(ident for ident in self.variables(node) if ident in self.unknown)
            observed_flags = records.flag_snapshots.get(seq)
            if observed_flags is not None:
                if not seq and observed_flags != declared['initialFlags']: raise ValueError('Initial native flags differ from declared flags')
                if ctx.getConcreteRegisterValue(ctx.registers.tf) != ((observed_flags >> 8) & 1):
                    node = ctx.getRegisterAst(ctx.registers.tf)
                    if any(ident in {sv.getId() for sv in self.input_variables.values()} for ident in self.variables(node)):
                        raise ValueError('Debugger TF observation conflicts with input-dependent flags')
                    # The debugger sets/clears TF around single-step callbacks.
                    # Treat it as an explicit environment observation, retaining
                    # an independent symbolic variable so output dependence is
                    # visible; never mask CF/ZF/SF/OF or erase argument effects.
                    ctx.setConcreteRegisterValue(ctx.registers.tf, (observed_flags >> 8) & 1)
                    sv = ctx.symbolizeRegister(ctx.registers.tf, 'debug_tf_' + str(index) + '_' + str(seq))
                    self.remember_unknown(sv); self.frozen_unknown.add(sv.getId())
                    environment_reads.append({'ea': hex(ea), 'operation': 'debugger-TF-boundary', 'variable': sv.getAlias(),
                                              'value': hex((observed_flags >> 8) & 1), 'policy': 'recorded debugger control observation; input-dependent TF refused'})
                flag_node = self.flags_ast()
                flag_node = ast.bvand(flag_node, ast.bv(0xfffffffd, flag_node.getBitvectorSize()))
                if flag_node.evaluate() != observed_flags & 0xfffffffd:
                    if flag_node.isSymbolized():
                        try: repairs = self.reconcile(flag_node, observed_flags & 0xfffffffd)
                        except ValueError as error: raise ValueError(str(error) + ' at #' + str(seq) + ' native flags after=' + hex(previous or 0) + ' actual=' + hex(flag_node.evaluate()) + ' observed=' + hex(observed_flags)) from error
                        snapshots.append({'instruction': seq, 'register': 'eflags', 'undefinedVariables': repairs})
                    else: raise ValueError('Native flags snapshot conflicts with semantics at ' + hex(ea) + ' expected=' + hex(flag_node.evaluate()) + ' observed=' + hex(observed_flags))
                self.frozen_unknown.update(ident for ident in self.variables(flag_node) if ident in self.unknown)
            for addr, size, expected in memory:
                mem = tt.MemoryAccess(addr, size)
                # An observed wider read can overlap an earlier narrow store.
                # Seed ONLY bytes never observed or written; keep all known
                # concrete/symbolic bytes. Even an observed zero is now known.
                unknown_bytes = [offset for offset in range(size)
                                 if addr + offset not in written_memory and addr + offset not in initial_memory]
                for offset in unknown_bytes:
                    byte = tt.MemoryAccess(addr + offset, 1)
                    if ctx.getMemoryAst(byte).isSymbolized():
                        raise ValueError('Untracked symbolic memory cannot be replaced by an observation')
                    ctx.setConcreteMemoryValue(byte, (expected >> (offset * 8)) & 255)
                    initial_memory.add(addr + offset)
                node = ctx.getMemoryAst(mem)
                if ctx.getConcreteMemoryValue(mem) != expected:
                    if node.isSymbolized(): snapshots.append({'instruction': seq, 'memory': hex(addr), 'undefinedVariables': self.reconcile(node, expected)})
                    else:
                        raise ValueError('Concrete memory snapshot conflicts with known trace memory at ' + hex(ea))
                elif node.isSymbolized(): self.frozen_unknown.update(ident for ident in self.variables(node) if ident in self.unknown)
                initial_memory.update(range(addr, addr + size))
            if not seq:
                for alias, name in zip(('x', 'y'), self.params['trace_inputs']):
                    reg = getattr(ctx.registers, name)
                    if index == 0:
                        sv = ctx.symbolizeRegister(reg, alias)
                        # Keep an owning AST reference even when a VM prologue
                        # overwrites an argument before using it in this window.
                        self.input_nodes[alias] = ast.variable(sv)
                        inputs[alias] = sv
                    else:
                        sv = self.input_variables[alias]
                        ctx.setConcreteVariableValue(sv, ctx.getConcreteRegisterValue(reg))
                        parent = ctx.getParentRegister(reg)
                        high = ctx.getConcreteRegisterValue(parent) & ~((1 << sv.getBitSize()) - 1)
                        node = ast.bvor(ast.bv(high, 64), ast.zx(64 - sv.getBitSize(), ast.variable(sv))) if sv.getBitSize() < 64 else ast.variable(sv)
                        ctx.assignSymbolicExpressionToRegister(ctx.newSymbolicExpression(node), parent)
                        inputs[alias] = sv
                self.input_variables = inputs
                observed_inputs = {alias: hex(ctx.getConcreteVariableValue(sv)) for alias, sv in inputs.items()}
            try:
                binding_ea = self.image.imagebase + ea - self.runtime_base
                original_bytes, expected_bytes = self.byte_binding.read(binding_ea, len(opcode))
                if original_bytes == opcode: original_matches += 1
                if expected_bytes == opcode:
                    matches += 1
                    if original_bytes != opcode and self.byte_binding.snapshot is None: relocation_matches.append({'ea': hex(ea), 'originalBytes': original_bytes.hex(), 'loadedBytes': expected_bytes.hex(),
                        'fixups': self.byte_binding.fixups_at(binding_ea, len(opcode))})
                elif len(mismatches) < 32: mismatches.append(hex(ea))
            except ValueError: unmapped += 1
            ins = tt.Instruction(ea, opcode)
            ctx.disassembly(ins)
            for operand in ins.getOperands():
                if operand.getType() == tt.OPERAND.MEM:
                    segment = operand.getSegmentRegister().getName()
                    if segment in ('gs', 'fs') and segment not in records.segment_bases: raise ValueError('Trace omits explicit ' + segment.upper() + ' segment base')
            mnemonic = ins.getDisassembly().split(' ')[0]
            if mnemonic in ('syscall', 'sysenter', 'int', 'int3', 'iret', 'iretq'):
                raise ValueError('OS/interrupt transitions are outside offline trace semantics')
            if mnemonic == 'cpuid':
                argument_ids = {sv.getId() for sv in self.input_variables.values()}
                for name in ('eax', 'ecx'):
                    selector = ctx.getRegisterAst(getattr(ctx.registers, name))
                    variables = self.variables(selector)
                    if any(ident in argument_ids for ident in variables):
                        if name == 'ecx' and ctx.getConcreteRegisterValue(ctx.registers.eax) in (0, 1, 0x80000000):
                            leaf = ctx.getRegisterAst(ctx.registers.eax)
                            leaf_vars = self.variables(leaf)
                            assignments = [ast.equal(ast.variable(sv), ast.bv(ctx.getConcreteVariableValue(sv), sv.getBitSize())) for ident, sv in leaf_vars.items() if ident in self.unknown]
                            leaf_proof = self.proof(ast.distinct(leaf, ast.bv(leaf.evaluate(), 32)), assignments)
                            if leaf_proof['status'] == 'unsat':
                                semantic_corrections.append({'ea': hex(ea), 'operation': 'cpuid-nonindexed-leaf', 'leaf': hex(leaf.evaluate()),
                                    'ignoredInputRegister': 'ecx', 'leafProof': leaf_proof, 'policy': 'architectural leaf 0/1 or extended maximum; ECX is not a subleaf selector'})
                                continue
                        fixed = [ast.equal(ast.variable(sv), ast.bv(ctx.getConcreteVariableValue(sv), sv.getBitSize())) for ident, sv in variables.items() if ident in self.unknown]
                        proof = self.proof(ast.distinct(selector, ast.bv(selector.evaluate(), selector.getBitvectorSize())), fixed)
                        if proof['status'] != 'unsat': raise ValueError('Input-dependent CPUID is outside this trace environment model at #' + str(seq) + ' ' + hex(ea) + ' register=' + name + ' leaf=' + hex(ctx.getConcreteRegisterValue(ctx.registers.eax)) + ' subleaf=' + hex(ctx.getConcreteRegisterValue(ctx.registers.ecx)))
                        semantic_corrections.append({'ea': hex(ea), 'operation': 'cpuid-selector-input-independence', 'register': name, 'proof': proof,
                            'environmentAssumptions': [{'variable': sv.getAlias(), 'value': hex(ctx.getConcreteVariableValue(sv))} for ident, sv in variables.items() if ident in self.unknown]})
            zero_scan_destination = None
            high_byte_result = None
            operands = ins.getOperands()
            rotate = None
            double_shift = None
            if mnemonic in ('shld', 'shrd') and len(operands) == 3:
                count = self.operand_ast(operands[2]); width = operands[0].getBitSize()
                masked = ast.bvand(count, ast.bv(63 if width == 64 else 31, count.getBitvectorSize()))
                source = self.operand_ast(operands[0]) if operands[0].getType() == tt.OPERAND.REG else None
                parent = ctx.getRegisterAst(ctx.getParentRegister(operands[0])) if source is not None else None
                double_shift = (masked, source, parent, self.operand_ast(operands[1]),
                    {name: ctx.getRegisterAst(getattr(ctx.registers, name)) for name in ('cf', 'pf', 'af', 'zf', 'sf', 'of')})
            if mnemonic in ('rol', 'ror', 'rcl', 'rcr') and len(operands) == 2:
                width = operands[0].getBitSize()
                count = self.operand_ast(operands[1])
                masked = ast.bvand(count, ast.bv(63 if width == 64 else 31, count.getBitvectorSize()))
                source = self.operand_ast(operands[0]) if operands[0].getType() == tt.OPERAND.REG else None
                parent = ctx.getRegisterAst(ctx.getParentRegister(operands[0])) if source is not None else None
                rotate = (masked, ctx.getRegisterAst(ctx.registers.cf), ctx.getRegisterAst(ctx.registers.of), source, parent)
            high_byte = operands and operands[0].getType() == tt.OPERAND.REG and operands[0].getName() in ('ah', 'bh', 'ch', 'dh')
            if high_byte and mnemonic in ('cmp', 'test'):
                left, right = [self.operand_ast(op) for op in operands[:2]]
                high_byte_result = ast.bvsub(left, right) if mnemonic == 'cmp' else ast.bvand(left, right)
            if mnemonic in ('bsf', 'bsr'):
                destination, source = ins.getOperands()
                source_node = ctx.getRegisterAst(source) if source.getType() == tt.OPERAND.REG else ctx.getMemoryAst(source)
                if source_node.evaluate() == 0:
                    zero_scan_destination = ctx.getParentRegister(destination)
                    if source_node.isSymbolized(): address_conditions.append((ea, ast.equal(source_node, ast.bv(0, source_node.getBitvectorSize()))))
            processed, hardware_correction = process_instruction(ctx, ins, tt)
            if processed != tt.EXCEPTION.NO_FAULT: raise ValueError('Unsupported instruction at ' + hex(ea))
            if hardware_correction:
                semantic_corrections.append({'ea': hex(ea), 'instruction': mnemonic, 'method': hardware_correction,
                    'policy': 'EAX/EDX/ECX external observations, high halves cleared, flags unchanged; timestamp and memory ordering not predicted'})
            parity_ops = ('and', 'or', 'xor', 'add', 'sub', 'adc', 'sbb', 'neg', 'inc', 'dec', 'shl', 'sal', 'shr', 'sar', 'xadd', 'cmp', 'test')
            if high_byte and mnemonic in parity_ops and any(reg.getName() == 'pf' for reg, _ in ins.getWrittenRegisters()) and not any(reg.getName() == 'pf' for reg in ins.getUndefinedRegisters()):
                # Pinned Triton rc4 computes PF from the preserved LOW byte of
                # the parent when the result is AH/BH/CH/DH. Intel PF is parity
                # of the actual result byte. Rebuild that defined flag as an AST
                # retaining every argument dependency; never substitute a
                # recorded flag value or change the pinned vendor binaries.
                value = high_byte_result if high_byte_result is not None else ctx.getRegisterAst(operands[0])
                parity = ast.bv(1, 1)
                for bit in range(8): parity = ast.bvxor(parity, ast.extract(bit, bit, value))
                ctx.assignSymbolicExpressionToRegister(ctx.newSymbolicExpression(parity), ctx.registers.pf)
                semantic_corrections.append({'ea': hex(ea), 'instruction': mnemonic, 'flag': 'PF', 'method': 'even parity of actual high-byte result; symbolic dependencies preserved'})
            if records.native_semantics and mnemonic in ('pushf', 'pushfd', 'pushfq'):
                # Native PUSHF stores architectural bit 1, and clears RF/VM in
                # its stack image. Keep the complete symbolic status flags;
                # this explicit format leaves legacy author recordings intact.
                for mem, _ in ins.getStoreAccess():
                    node = ctx.getMemoryAst(mem)
                    bits = node.getBitvectorSize()
                    fixed = ast.bvor(ast.bvand(node, ast.bv(((1 << bits) - 1) & ~0x30000, bits)), ast.bv(2, bits))
                    ctx.assignSymbolicExpressionToMemory(ctx.newSymbolicExpression(fixed), mem)
            if ins.getSize() != len(opcode): raise ValueError('Recorded instruction contains trailing bytes')
            for mem, _ in ins.getLoadAccess():
                if any(byte not in initial_memory and byte not in written_memory for byte in range(mem.getAddress(), mem.getAddress() + mem.getSize())):
                    raise ValueError('Trace omits an uninitialized memory read at ' + hex(ea))
            for mem, _ in ins.getLoadAccess() + ins.getStoreAccess():
                lea = mem.getLeaAst()
                if lea is not None and lea.isSymbolized():
                    variables = self.variables(lea)
                    if all(ident in self.frozen_unknown for ident in variables):
                        if lea.evaluate() != mem.getAddress(): raise ValueError('Fixed environment address differs from recorded access')
                        environment_address_checks.append({'ea': hex(ea), 'address': hex(mem.getAddress()),
                            'method': 'exact-evaluation-under-fixed-environment-observations',
                            'assignments': [{'variable': sv.getAlias(), 'value': hex(ctx.getConcreteVariableValue(sv))} for sv in variables.values()]})
                        continue
                    address_conditions.append((ea, ast.equal(lea, ast.bv(mem.getAddress(), lea.getBitvectorSize()))))
                    if len(address_conditions) > 256: raise ValueError('Symbolic memory address budget exceeded')
            for mem, _ in ins.getStoreAccess(): written_memory.update(range(mem.getAddress(), mem.getAddress() + mem.getSize()))
            if len(written_memory) + len(initial_memory) > 1024 * 1024: raise ValueError('Trace memory byte budget exceeded')
            undefined_registers = list(ins.getUndefinedRegisters())
            if rotate is not None: undefined_registers = [reg for reg in undefined_registers if reg.getName() not in ('of', 'cf')]
            if double_shift is not None: undefined_registers = [reg for reg in undefined_registers if reg.getName() not in ('cf', 'pf', 'af', 'zf', 'sf', 'of')]
            # BSF/BSR on zero leave an architecturally undefined destination.
            # Triton's 32-bit model clears its upper half whereas the observed
            # CPU preserves it. Overapproximate the parent, retain provenance.
            if zero_scan_destination is not None: undefined_registers.append(zero_scan_destination)
            for reg in undefined_registers:
                if reg.getBitSize() != 1: reg = ctx.getParentRegister(reg)
                sv = ctx.symbolizeRegister(reg, 'undef_' + str(index) + '_' + str(seq) + '_' + reg.getName())
                self.remember_unknown(sv)
            if double_shift is not None:
                masked, source, parent, other, old_flags = double_shift; width = operands[0].getBitSize()
                if source is None:
                    loads = ins.getLoadAccess()
                    if len(loads) != 1 or loads[0][0].getSize() * 8 != width: raise ValueError('Double-shift memory source is not unique')
                    source = loads[0][1]
                wide = width * 2
                count_wide = ast.zx(wide - masked.getBitvectorSize(), masked)
                combined = ast.concat([source, other]) if mnemonic == 'shld' else ast.concat([other, source])
                shifted = ast.bvshl(combined, count_wide) if mnemonic == 'shld' else ast.bvlshr(combined, count_wide)
                value = ast.extract(wide - 1, width, shifted) if mnemonic == 'shld' else ast.extract(width - 1, 0, shifted)
                valid = ast.bvule(masked, ast.bv(width, masked.getBitvectorSize()))
                def unknown_double(label, bits):
                    sv = ctx.newSymbolicVariable(bits, 'undef_' + str(index) + '_' + str(seq) + '_double_' + label)
                    self.remember_unknown(sv)
                    return ast.variable(sv)
                if width == 16 and (masked.isSymbolized() or masked.evaluate() > width):
                    value = ast.ite(valid, value, unknown_double('result', width))
                self.assign_operand_value(operands[0], value, parent, ins)
                zero = ast.equal(masked, ast.bv(0, masked.getBitvectorSize())); one = ast.equal(masked, ast.bv(1, masked.getBitvectorSize()))
                count_width = ast.zx(width - masked.getBitvectorSize(), masked)
                carry_count = ast.bvsub(ast.bv(width, width), count_width) if mnemonic == 'shld' else ast.bvsub(count_width, ast.bv(1, width))
                carry = ast.extract(0, 0, ast.bvlshr(source, carry_count))
                parity = ast.bv(1, 1)
                for bit in range(8): parity = ast.bvxor(parity, ast.extract(bit, bit, value))
                defined_of = ast.bvxor(ast.extract(width - 1, width - 1, value), ast.extract(width - 1, width - 1, source))
                flags = {'cf': carry, 'pf': parity, 'af': unknown_double('af', 1),
                    'zf': ast.ite(ast.equal(value, ast.bv(0, width)), ast.bv(1, 1), ast.bv(0, 1)),
                    'sf': ast.extract(width - 1, width - 1, value), 'of': ast.ite(one, defined_of, unknown_double('of', 1))}
                for name, flag in flags.items():
                    if width == 16 and (masked.isSymbolized() or masked.evaluate() > width): flag = ast.ite(valid, flag, unknown_double(name + '_out_of_range', 1))
                    ctx.assignSymbolicExpressionToRegister(ctx.newSymbolicExpression(ast.ite(zero, old_flags[name], flag)), getattr(ctx.registers, name))
                semantic_corrections.append({'ea': hex(ea), 'instruction': mnemonic,
                    'method': 'symbolic double-shift count via full-width concatenation; zero preserves flags; out-of-range 16-bit result/flags remain undefined'})
            if rotate is not None:
                masked, old_cf, old_of, source, parent = rotate
                width = operands[0].getBitSize()
                if source is None:
                    loads = ins.getLoadAccess()
                    if len(loads) != 1 or loads[0][0].getSize() * 8 != width: raise ValueError('Rotate memory source is not uniquely observed')
                    source = loads[0][1]
                # rc4 concretizes a symbolic CL rotation count into an INTEGER
                # AST child. Rebuild the value using bit-vector shifts so count
                # dependencies survive; constant rotations remain equivalent.
                count_width = ast.zx(width - masked.getBitvectorSize(), masked) if width >= masked.getBitvectorSize() else ast.extract(width - 1, 0, masked)
                effective = ast.bvand(count_width, ast.bv(width - 1, width))
                if mnemonic in ('rcl', 'rcr'):
                    wide = width + 1
                    count_wide = ast.zx(wide - masked.getBitvectorSize(), masked)
                    effective_wide = ast.bvurem(count_wide, ast.bv(wide, wide)) if width in (8, 16) else count_wide
                    combined = ast.concat([source, old_cf]); inverse = ast.bvsub(ast.bv(wide, wide), effective_wide)
                    rotated = ast.bvor(ast.bvshl(combined, effective_wide), ast.bvlshr(combined, inverse)) if mnemonic == 'rcl' else ast.bvor(ast.bvlshr(combined, effective_wide), ast.bvshl(combined, inverse))
                    value = ast.extract(width, 1, rotated); carry = ast.extract(0, 0, rotated)
                else:
                    inverse = ast.bvsub(ast.bv(width, width), effective)
                    if not effective.isSymbolized():
                        # An independent constant count has exact rotate AST
                        # semantics. Keep the shared source once, rather than
                        # expanding both shifts again at every fixed round.
                        value = (ast.bvrol if mnemonic == 'rol' else ast.bvror)(source, ast.bv(effective.evaluate(), width))
                    else:
                        value = ast.bvor(ast.bvshl(source, effective), ast.bvlshr(source, inverse)) if mnemonic == 'rol' else ast.bvor(ast.bvlshr(source, effective), ast.bvshl(source, inverse))
                    carry = ast.extract(0, 0, value) if mnemonic == 'rol' else ast.extract(width - 1, width - 1, value)
                self.assign_operand_value(operands[0], value, parent, ins)
                zero = ast.equal(masked, ast.bv(0, masked.getBitvectorSize()))
                one = ast.equal(masked, ast.bv(1, masked.getBitvectorSize()))
                cf = ast.ite(zero, old_cf, carry)
                defined_of = ast.bvxor(ast.extract(width - 1, width - 1, value), carry if mnemonic in ('rol', 'rcl') else ast.extract(width - 2, width - 2, value))
                if not masked.isSymbolized() and masked.evaluate() in (0, 1):
                    of = old_of if masked.evaluate() == 0 else defined_of
                else:
                    sv = ctx.newSymbolicVariable(1, 'undef_' + str(index) + '_' + str(seq) + '_rotate_of')
                    unknown_of = ast.variable(sv); self.remember_unknown(sv)
                    of = ast.ite(zero, old_of, ast.ite(one, defined_of, unknown_of))
                ctx.assignSymbolicExpressionToRegister(ctx.newSymbolicExpression(cf), ctx.registers.cf)
                ctx.assignSymbolicExpressionToRegister(ctx.newSymbolicExpression(of), ctx.registers.of)
                semantic_corrections.append({'ea': hex(ea), 'instruction': mnemonic, 'flags': ['CF', 'OF'],
                    'method': 'symbolic count retained via full-width shifts; masked-zero preserves flags; CF from actual result; OF defined only for masked count one'})
            environment_outputs = {'cpuid': ('eax', 'ebx', 'ecx', 'edx'), 'rdtsc': ('eax', 'edx'), 'rdtscp': ('eax', 'edx', 'ecx')}.get(mnemonic, ())
            if environment_outputs:
                environment_reads.append({'ea': hex(ea), 'operation': mnemonic, 'policy': 'symbolic hardware observation; fixed only by following recorded snapshots'})
                for name in environment_outputs:
                    sv = ctx.symbolizeRegister(getattr(ctx.registers, name), 'env_' + str(index) + '_' + str(seq) + '_' + name)
                    self.remember_unknown(sv)
            previous = ea
        if records.final_registers is not None:
            for name, expected in zip(GPRS + ['rip', 'eflags'], records.final_registers):
                reg = getattr(ctx.registers, name)
                # Triton's aggregate EFLAGS omits reserved bit 1. x86 CPUs keep
                # it set; it is not an input-dependent status/control flag.
                mask = 0xfffffffd if name == 'eflags' else (1 << 64) - 1
                if ctx.getConcreteRegisterValue(reg) & mask != expected & mask:
                    node = self.flags_ast() if name == 'eflags' else ctx.getRegisterAst(reg)
                    if name == 'eflags': node = ast.bvand(node, ast.bv(mask, node.getBitvectorSize()))
                    if node.isSymbolized(): snapshots.append({'finalRegister': name, 'undefinedVariables': self.reconcile(node, expected & mask)})
                    else: raise ValueError('Final register snapshot conflicts with trace semantics: ' + name)
        ret = ctx.getRegisterAst(getattr(ctx.registers, self.params['trace_output']))
        observed = hex(ret.evaluate())
        normalization_budget = [512]
        pre_output, pre_steps, pre_attempts = normalize_ast(ret, tt, ast,
            lambda before, after: self.proof(ast.distinct(before, after)), self.budget,
            self.prove_ast_instance, normalization_budget)
        pre_projection_failure = None
        if pre_steps:
            try: self.expression(pre_output)
            except ValueError as error:
                self.budget()
                pre_projection_failure = str(error)
                # Local equalities remain valid, but a partially normalized
                # VM expression may still need the legacy synthesis pipeline.
                # Do not force that representation or raise render limits.
                pre_steps = []
        if pre_steps:
            # Every local replacement already has a universal/full SMT proof.
            # Congruence composes those equalities without expanding the original
            # shared VM DAG into a giant global synthesis/SMT query.
            output = pre_output
            output_proof = {'status': 'unsat', 'method': 'SMT-local-equalities-and-parent-congruence',
                'rewriteCount': len(pre_steps), 'localProofs': pre_steps,
                'scope': 'Original output equals the normalized AST by all recorded local UNSAT proofs and congruence'}
            synthesis_attempts = [{'method': 'bounded-certified-AST-before-synthesis', 'proof': output_proof}]
        else:
            output = ctx.synthesize(ret)
            output = output if output is not None else ctx.simplify(ret, solver=True)
            # Synthesis/simplification is a candidate until independently queried.
            output_proof = self.proof(ast.distinct(ret, output))
            synthesis_attempts = [{'method': 'synthesis-or-solver-simplification', 'proof': output_proof}]
            if output_proof['status'] != 'unsat':
                output = ctx.simplify(ret, solver=True)
                output_proof = self.proof(ast.distinct(ret, output))
                synthesis_attempts.append({'method': 'solver-simplification-fallback', 'proof': output_proof})
                if output_proof['status'] != 'unsat':
                    output = ret; output_proof = self.proof(ast.distinct(ret, output))
                    synthesis_attempts.append({'method': 'original-symbolic-AST', 'proof': output_proof})
        if output_proof['status'] != 'unsat': raise ValueError('Output candidate equivalence was not proved')
        conditions = control_conditions + address_conditions + [(pc.getSourceAddress(), pc.getTakenPredicate()) for pc in ctx.getPathConstraints()]
        guard_rows, assumption_rows, fixed_environment_checks = [], [], []
        for source, condition in conditions:
            variables = self.variables(condition)
            # Native VM junk often branches only on already observed flags.
            # Exact evaluation with ALL free variables fixed is a deterministic
            # environment check, not an SMT proof or an argument constraint.
            # Preserve those assignments and report this distinction explicitly.
            if all(ident in self.frozen_unknown for ident in variables):
                if not condition.evaluate(): raise ValueError('Recorded environment constraint is false')
                fixed = [{'variable': sv.getAlias(), 'value': hex(ctx.getConcreteVariableValue(sv))} for sv in variables.values()]
                assumption_rows.extend(fixed)
                fixed_environment_checks.append({'ea': hex(source), 'method': 'exact-evaluation-under-fixed-observations', 'value': True, 'assignments': fixed})
                continue
            # Exact DAG encoding below retains the complete condition. Avoid
            # unbounded eager solver expansion of shared VM flag expressions.
            # Undefined flags are existential environment inputs. Do not mistake them
            # for user arguments, or advertise fixed observations as CPU semantics.
            unknowns = [sv for ident, sv in self.variables(condition).items() if ident in self.unknown]
            assignments = [ast.equal(ast.variable(sv), ast.bv(ctx.getConcreteVariableValue(sv), sv.getBitSize())) for sv in unknowns]
            # Keep ALL symbolic conditions in the conjunction. Individual
            # tautology checks consumed the shared SMT budget before proving
            # useful guards on multi-handler VMs. Candidate equivalence below
            # proves the complete conjunction at once, including these rows;
            # no constraint is dropped or replaced by its observed truth value.
            assumption_rows.extend({'variable': sv.getAlias(), 'value': hex(ctx.getConcreteVariableValue(sv))} for sv in unknowns)
            guard_rows.append((source, condition, assignments))
        candidates = self.predicates(guard_rows)
        guard, guard_node, guard_search = self.search_guard_candidates(guard_rows, candidates, assumption_rows)
        guard_projection_failure = None
        if not guard_rows:
            guard = {'expression': 'true', 'sources': [], 'proof': self.proof(ast.lnot(self.conjunction([]))), 'environmentAssumptions': assumption_rows}
            guard_node = self.conjunction([])
        elif guard is None:
            guard_node = self.conjunction([row[1] for row in guard_rows])
            guard_variables = self.variables(guard_node)
            guard_projection_failure = {'freeVariables': len(guard_variables), 'unfixedEnvironmentVariables': [sv.getAlias() for ident, sv in guard_variables.items() if ident in self.unknown and ident not in self.frozen_unknown][:8]}
            # Render the actual input-only guard if the small heuristic set
            # misses it. No observed argument value or reference condition is
            # substituted. Projection must still be independently UNSAT.
            if set(guard_variables) <= {sv.getId() for sv in self.input_variables.values()} and self.solver_queries < 120:
                try:
                    compact_guard = ctx.simplify(guard_node, solver=True)
                    condition_expression = self.predicate_expression(compact_guard)
                    candidate = self.predicate_ast(condition_expression)
                except ValueError as error:
                    guard_projection_failure['reason'] = str(error)
                    candidate = None
                if candidate is not None:
                    proof = self.proof(ast.lxor([guard_node, candidate]))
                    if proof['status'] == 'unsat':
                        guard = {'expression': 'recorded input predicate', 'conditionExpression': condition_expression,
                            'sources': [hex(row[0]) for row in guard_rows], 'proof': proof, 'environmentAssumptions': assumption_rows,
                            'method': 'input-only-recorded-predicate-projection'}
                        guard_node = candidate
        guard_domain = None
        if guard is None and guard_rows:
            guard_domain = diagnose_guard_domain(guard_rows, ast, self.proof, self.budget,
                lambda: self.solver_queries < 120)
        if pre_steps:
            ast_steps, ast_attempts = pre_steps, pre_attempts
        else:
            output, ast_steps, ast_attempts = normalize_ast(output, tt, ast,
                lambda before, after: self.proof(ast.distinct(before, after)), self.budget,
                self.prove_ast_instance, normalization_budget)
        expression = self.expression(output)
        projected = self.expression_ast(expression)
        projection_proof = self.proof(ast.distinct(output if ast_steps else ret, projected))
        if projection_proof['status'] != 'unsat': raise ValueError('Width-projected expression equivalence was not proved')
        if ast_steps:
            projection_proof = {'status': 'unsat', 'method': 'SMT-local-AST-congruence-and-projection' if pre_steps else 'SMT-synthesis-AST-equality-congruence-and-projection',
                'synthesisProof': output_proof, 'projectionProof': projection_proof, 'rewriteCount': len(ast_steps),
                'scope': 'Every recorded AST rewrite is UNSAT; references expand by definition; parent rebuilding preserves equality; final projection is UNSAT'}
        normalized, normalization_steps, normalization_attempts = normalize_expression(expression, self.expression_ast,
            lambda before, after: self.proof(ast.distinct(before, after)), self.budget,
            lambda before, after, rule, metadata: prove_expression_instance(ctx, ast,
                before, after, rule, metadata, self.proof, self.expression_templates))
        if normalization_steps:
            expression = normalized
            projection_proof = {'status': 'unsat', 'method': 'SMT-projection-and-local-equality-congruence',
                'projectionProof': projection_proof, 'rewriteCount': len(normalization_steps),
                'scope': 'Original output equals its projection; every local rewrite is UNSAT and parent replacement preserves equality'}
        return {'traceSha256': trace['sha256'], 'recording': recording, 'instructionCount': len(records), 'observedInputs': observed_inputs,
                'observedOutput': observed, 'outputExpression': expression, 'outputProof': projection_proof,
                'synthesisProof': output_proof,
                'synthesisAttempts': synthesis_attempts,
                'astNormalization': {'method': 'bounded-preorder-local-SMT-and-equality-congruence', 'steps': ast_steps, 'attempts': ast_attempts,
                    'beforeSynthesis': bool(pre_steps), 'sharedNodeBudget': 512,
                    'preSynthesisProjectionFailure': pre_projection_failure},
                'expressionNormalization': {'method': 'bounded-local-SMT-and-equality-congruence', 'steps': normalization_steps, 'attempts': normalization_attempts},
                'finalSnapshotVerified': records.final_registers is not None,
                'unobservedContinuationInstructions': sum(regs is None for _, _, regs, _ in records),
                'recordingFormat': records.native_semantics or 'legacy-r-mr-i',
                'finalSnapshotScope': 'GPRs/RIP and EFLAGS excluding architectural reserved bit 1' if records.final_registers is not None else None,
                'outputDependsOnUndefinedFlags': any(ident in self.unknown for ident in self.variables(output)),
                'outputDependsOnEnvironmentUnknowns': any(ident in self.unknown for ident in self.variables(output)),
                'guard': guard, 'guardProjectionFailure': guard_projection_failure if guard is None else None, 'unresolvedGuardCount': len(guard_rows) if guard is None else 0,
                'guardDomainDiagnostic': guard_domain,
                'guardCandidateSearch': guard_search,
                'snapshotRepairs': snapshots, 'environmentReads': environment_reads, 'binaryBinding': {'matchedInstructions': matches,
                    'originalFileMatchedInstructions': original_matches if getattr(self.image, 'original_file_available', True) else None,
                    'allOriginalFileInstructionBytesMatch': original_matches == len(records) if getattr(self.image, 'original_file_available', True) else None,
                    'originalFileVerification': 'compared' if getattr(self.image, 'original_file_available', True) else 'not-performed-recorded-image-only',
                    'loaderRelocationMatchedInstructions': len(relocation_matches), 'loaderRelocationEvidence': relocation_matches,
                    'mappingPolicy': 'Recorded VA -> captured readable native main-image bytes at declared pause; original-file equality and future code mutation are not proved' if self.byte_binding.snapshot is not None else 'Recorded VA -> main-image RVA -> ELF PT_LOAD or PE sections; explicit AMD64 DIR64 loader fixups when relocated, no arbitrary code changes',
                    'capturedImageMatchedInstructions': matches if self.byte_binding.snapshot is not None else 0,
                    'capturedImageEvidence': {key: self.byte_binding.snapshot[key] for key in ('sourceReportId', 'sourceReportSha256', 'sha256', 'runtimeBase', 'moduleSize', 'partial', 'runId', 'threadId', 'stopSeq')} if self.byte_binding.snapshot is not None else None,
                    'runtimeBase': hex(self.runtime_base), 'preferredImageBase': hex(self.image.imagebase) if getattr(self.image, 'original_file_available', True) else None,
                    'recordedHeader': getattr(self.byte_binding, 'recorded_header', None),
                    'mismatchAddresses': mismatches, 'unmappedInstructions': unmapped,
                    'allInstructionBytesMatch': matches == len(records)},
                'fixedEnvironmentConstraintChecks': fixed_environment_checks,
                'fixedEnvironmentAddressChecks': environment_address_checks,
                'semanticCorrections': semantic_corrections,
                '_output': output, '_guard': guard_node}

    def predicates(self, guard_rows):
        ast = self.ast
        x, y = [self.input_nodes[name] for name in ('x', 'y')]
        if x.getBitvectorSize() != y.getBitvectorSize(): return []
        bits = x.getBitvectorSize()
        inputs = [{'op': 'input', 'name': name, 'bits': bits} for name in ('x', 'y')]
        result = [(label, function(x, y), {'op': op, 'args': inputs}) for label, op, function in
                  [('signed(x) < signed(y)', 'slt', ast.bvslt), ('signed(x) >= signed(y)', 'sge', ast.bvsge),
                   ('signed(x) <= signed(y)', 'sle', ast.bvsle), ('signed(x) > signed(y)', 'sgt', ast.bvsgt),
                   ('unsigned(x) < unsigned(y)', 'ult', ast.bvult), ('unsigned(x) >= unsigned(y)', 'uge', ast.bvuge),
                   ('unsigned(x) <= unsigned(y)', 'ule', ast.bvule), ('unsigned(x) > unsigned(y)', 'ugt', ast.bvugt),
                   ('x == y', 'eq', ast.equal), ('x != y', 'ne', ast.distinct)]]
        # Infer candidates from the recorded guard AST, never from reference source
        # or a sample name. Search is bounded and every published guard is proved.
        seeds, constants, visited, projection_widths = {}, set(), set(), set()
        stack = [row[1] for row in guard_rows]
        scanned = 0
        allowed = {'input', 'constant', 'add', 'sub', 'xor', 'and', 'or', 'not'}
        def weight(value):
            if value['op'] not in allowed: return 1000
            return 1 + sum(weight(child) for child in value.get('args', []))
        while stack and len(visited) < 2048:
            self.budget()
            node = stack.pop()
            # References hash like their definitions in Triton. Expanding them
            # AFTER hash deduplication silently skipped the real operator.
            while node.getType() == self.tt.AST_NODE.REFERENCE and scanned < 2048:
                scanned += 1; self.budget()
                node = node.getSymbolicExpression().getAst()
            scanned += 1
            if scanned > 2048: break
            ident = node.getHash()
            if ident in visited: continue
            visited.add(ident)
            if node.getType() == self.tt.AST_NODE.REFERENCE:
                stack.append(node.getSymbolicExpression().getAst())
                continue
            if node.getType() == self.tt.AST_NODE.BV and node.getBitvectorSize() == bits:
                constants.add(node.evaluate())
            if node.getType() == self.tt.AST_NODE.EXTRACT:
                children = node.getChildren()
                if children[1].getInteger() == 0 and 0 < children[0].getInteger() + 1 < bits:
                    projection_widths.add(children[0].getInteger() + 1)
            if node.getType() in (self.tt.AST_NODE.BVAND, self.tt.AST_NODE.BVOR):
                word_bits = node.getBitvectorSize()
                for child in node.getChildren():
                    if child.getType() != self.tt.AST_NODE.BV: continue
                    mask = child.evaluate()
                    # AND retains a low prefix; OR with its complement forces
                    # all other bits. Infer width from literal structure only.
                    if node.getType() == self.tt.AST_NODE.BVOR: mask ^= (1 << word_bits) - 1
                    if mask and mask & (mask + 1) == 0 and mask.bit_length() < bits:
                        projection_widths.add(mask.bit_length())
            if node.getType() in (self.tt.AST_NODE.BVADD, self.tt.AST_NODE.BVSUB, self.tt.AST_NODE.BVXOR, self.tt.AST_NODE.BVAND, self.tt.AST_NODE.BVOR):
                if node.getBitvectorSize() == bits and set(self.variables(node)) == {sv.getId() for sv in self.input_variables.values()}:
                    try:
                        value = self.expression(node)
                        if weight(value) <= 9:
                            seeds[json.dumps(value, sort_keys=True)] = value
                            # CMP often becomes addition of a two's-complement
                            # constant. Offer the variable sum as another candidate.
                            def terms(item):
                                if item['op'] == 'add': return [term for child in item['args'] for term in terms(child)]
                                return [] if item['op'] == 'constant' else [item]
                            variable_terms = terms(value) if value['op'] == 'add' else []
                            if len(variable_terms) == 2 and all(term['op'] == 'input' for term in variable_terms):
                                seed = {'op': 'add', 'args': variable_terms, 'bits': bits}
                                seeds[json.dumps(seed, sort_keys=True)] = seed
                    except ValueError: pass
            stack.extend(node.getChildren())
        mask = (1 << bits) - 1
        # Candidate widths come from actual recorded AST projections. Nothing
        # is inferred from the sample name, observed argument pair or source.
        for width in sorted(projection_widths)[:4]:
            a, b = ast.extract(width - 1, 0, x), ast.extract(width - 1, 0, y)
            projected_inputs = [{'op': 'input', 'name': name, 'bits': width} for name in ('x', 'y')]
            for op, function in [('eq', ast.equal), ('ne', ast.distinct)]:
                result.append((f'low{width}(x) ' + ('==' if op == 'eq' else '!=') + f' low{width}(y)', function(a, b), {'op': op, 'args': projected_inputs}))
        constants |= {(-value) & mask for value in constants}
        constants = sorted(constants - {0, 1, mask})[:4]
        def label(value):
            if value['op'] == 'input': return value['name']
            if value['op'] == 'constant': return value['value']
            args = [label(child) for child in value['args']]
            if value['op'] == 'not': return '(~' + args[0] + ')'
            return '(' + {'add': ' + ', 'sub': ' - ', 'xor': ' ^ ', 'and': ' & ', 'or': ' | '}[value['op']].join(args) + ')'
        for value in sorted(seeds.values(), key=weight)[:3]:
            left = self.expression_ast(value)
            for constant in constants:
                for number in (constant, (constant + 1) & mask, (constant - 1) & mask):
                    right = ast.bv(number, bits)
                    for op, function in [('eq', ast.equal), ('ne', ast.distinct), ('ult', ast.bvult), ('uge', ast.bvuge)]:
                        if len(result) >= 42: return result
                        condition = {'op': op, 'args': [value, {'op': 'constant', 'value': hex(number), 'bits': bits}]}
                        comparison = {'eq': ' == ', 'ne': ' != ', 'ult': ' < ', 'uge': ' >= '}[op]
                        result.append(('unsigned' + str(bits) + '(' + label(value) + ')' + comparison + hex(number), function(left, right), condition))
        return result

    def expression(self, node, width=None, depth=0, budget=None):
        """Bounded width projection; avoid expansion of a shared VM AST to a giant string."""
        if budget is None: budget = [256, 8192]
        elif len(budget) == 1: budget.append(8192)
        # Symbolic references are definitions, not rendered operators. Follow
        # them before charging visible nodes/depth, with a separate finite cap
        # equal to the old 256-node x 32-depth worst-case reference work.
        while node.getType() == self.tt.AST_NODE.REFERENCE:
            self.budget(); budget[1] -= 1
            if budget[1] < 0: raise ValueError('Recovered reference expansion exceeds render budget')
            node = node.getSymbolicExpression().getAst()
        budget[0] -= 1
        if budget[0] < 0 or depth > 32: raise ValueError('Recovered expression exceeds render budget')
        tt, ast = self.tt, self.ast
        kind, children = node.getType(), node.getChildren()
        width = width or node.getBitvectorSize()
        recurse = lambda item: self.expression(item, width, depth + 1, budget)
        if kind == tt.AST_NODE.REFERENCE: return recurse(node.getSymbolicExpression().getAst())
        if kind == tt.AST_NODE.VARIABLE:
            sv = node.getSymbolicVariable()
            if sv.getId() in self.unknown:
                self.projected_environment[sv.getAlias()] = node
                fixed = sv.getId() in self.frozen_unknown
                return {'op': 'environment', 'name': sv.getAlias(), 'bits': min(width, sv.getBitSize()),
                        'observationFixed': fixed, **({'observedValue': hex(node.evaluate())} if fixed else {})}
            return {'op': 'input', 'name': sv.getAlias(), 'bits': min(width, sv.getBitSize())}
        if not node.isSymbolized(): return {'op': 'constant', 'value': hex(node.evaluate() & ((1 << width) - 1)), 'bits': width}
        if kind == tt.AST_NODE.EXTRACT and children[1].getInteger() == 0:
            return self.expression(children[2], min(width, children[0].getInteger() + 1), depth + 1, budget)
        if kind == tt.AST_NODE.EXTRACT:
            low = children[1].getInteger()
            return {'op': 'extract', 'low': low, 'bits': min(width, children[0].getInteger() - low + 1),
                    'args': [self.expression(children[2], children[2].getBitvectorSize(), depth + 1, budget)]}
        if kind in (tt.AST_NODE.ZX, tt.AST_NODE.SX) and width <= children[1].getBitvectorSize(): return recurse(children[1])
        if kind in (tt.AST_NODE.ZX, tt.AST_NODE.SX):
            return {'op': 'zx' if kind == tt.AST_NODE.ZX else 'sx', 'bits': width,
                    'args': [self.expression(children[1], children[1].getBitvectorSize(), depth + 1, budget)]}
        if kind == tt.AST_NODE.CONCAT:
            low = children[-1]
            if width <= low.getBitvectorSize(): return recurse(low)
            value = {'op': 'concat', 'bits': node.getBitvectorSize(),
                     'args': [self.expression(child, child.getBitvectorSize(), depth + 1, budget) for child in children]}
            return value if width == node.getBitvectorSize() else {'op': 'extract', 'low': 0, 'bits': width, 'args': [value]}
        if kind == tt.AST_NODE.BVSHL and not children[1].isSymbolized() and children[1].evaluate() >= width:
            return {'op': 'constant', 'value': '0x0', 'bits': width}
        shifts = {tt.AST_NODE.BVSHL: 'shl', tt.AST_NODE.BVLSHR: 'lshr', tt.AST_NODE.BVASHR: 'ashr'}
        if kind in shifts:
            full = node.getBitvectorSize()
            value = {'op': shifts[kind], 'bits': full,
                     'args': [self.expression(child, full, depth + 1, budget) for child in children]}
            # A right shift can move high source bits into the low output.
            # Project only AFTER shifting at the original machine width.
            return value if width == full else {'op': 'extract', 'low': 0, 'bits': width, 'args': [value]}
        if kind == tt.AST_NODE.BVUREM:
            full = node.getBitvectorSize()
            value = {'op': 'urem', 'bits': full, 'args': [self.expression(child, full, depth + 1, budget) for child in children]}
            return value if width == full else {'op': 'extract', 'low': 0, 'bits': width, 'args': [value]}
        if kind in (tt.AST_NODE.BVROL, tt.AST_NODE.BVROR):
            full = node.getBitvectorSize()
            if children[1].getType() != tt.AST_NODE.INTEGER: raise ValueError('Unexpected rotate-count AST representation')
            value = {'op': 'rol' if kind == tt.AST_NODE.BVROL else 'ror', 'bits': full,
                     'args': [self.expression(children[0], full, depth + 1, budget),
                              {'op': 'constant', 'value': hex(children[1].getInteger()), 'bits': full}]}
            return value if width == full else {'op': 'extract', 'low': 0, 'bits': width, 'args': [value]}
        if kind == tt.AST_NODE.ITE:
            return {'op': 'select', 'bits': width,
                    'conditionExpression': self.predicate_expression(children[0], depth + 1, budget),
                    'then': recurse(children[1]), 'else': recurse(children[2])}
        if kind in (tt.AST_NODE.EQUAL, tt.AST_NODE.DISTINCT, tt.AST_NODE.LNOT, tt.AST_NODE.LAND, tt.AST_NODE.LOR, self.logical_xor_kind,
                    tt.AST_NODE.BVULT, tt.AST_NODE.BVULE, tt.AST_NODE.BVUGT, tt.AST_NODE.BVUGE,
                    tt.AST_NODE.BVSLT, tt.AST_NODE.BVSLE, tt.AST_NODE.BVSGT, tt.AST_NODE.BVSGE):
            return {'op': 'bool-bv', 'bits': 1, 'conditionExpression': self.predicate_expression(node, depth + 1, budget)}
        binary = {tt.AST_NODE.BVADD: 'add', tt.AST_NODE.BVSUB: 'sub', tt.AST_NODE.BVMUL: 'mul',
                  tt.AST_NODE.BVXOR: 'xor', tt.AST_NODE.BVAND: 'and', tt.AST_NODE.BVOR: 'or'}
        if kind in binary:
            if kind == tt.AST_NODE.BVADD:
                # Modular addition is associative. Flatten same-width groups
                # before rendering so artificial binary nesting does not spend
                # the semantic depth budget. Every source group still spends
                # a node; the independently proved projection remains required.
                pending=list(reversed(children)); leaves=[]
                while pending:
                    self.budget();child=pending.pop()
                    while child.getType()==tt.AST_NODE.REFERENCE:
                        budget[1]-=1
                        if budget[1]<0:raise ValueError('Recovered reference expansion exceeds render budget')
                        child=child.getSymbolicExpression().getAst()
                    if child.getType()==kind and child.getBitvectorSize()==node.getBitvectorSize():
                        budget[0]-=1
                        if budget[0]<0:raise ValueError('Recovered expression exceeds render budget')
                        pending.extend(reversed(child.getChildren()))
                    else:leaves.append(child)
                args=[recurse(child) for child in leaves]
            else: args = [recurse(child) for child in children]
            if binary[kind] in ('add', 'or', 'xor'):
                args = [arg for arg in args if not (arg['op'] == 'constant' and arg['value'] == '0x0')]
                if len(args) == 1: return args[0]
            return {'op': binary[kind], 'args': args, 'bits': width}
        if kind == tt.AST_NODE.BVNOT: return {'op': 'not', 'args': [recurse(children[0])], 'bits': width}
        raise ValueError('Output recovered but expression projection is unsupported at AST kind ' + str(kind) + ', width ' + str(width))

    def predicate_expression(self, node, depth=0, budget=None):
        if budget is None: budget = [256,8192]
        elif len(budget)==1:budget.append(8192)
        while node.getType()==self.tt.AST_NODE.REFERENCE:
            self.budget();budget[1]-=1
            if budget[1]<0:raise ValueError('Recovered reference expansion exceeds render budget')
            node=node.getSymbolicExpression().getAst()
        budget[0] -= 1
        if budget[0] < 0 or depth > 32: raise ValueError('Recovered predicate exceeds render budget')
        tt = self.tt
        kind, children = node.getType(), node.getChildren()
        if kind == tt.AST_NODE.REFERENCE: return self.predicate_expression(node.getSymbolicExpression().getAst(), depth + 1, budget)
        comparisons = {tt.AST_NODE.EQUAL: 'eq', tt.AST_NODE.DISTINCT: 'ne', tt.AST_NODE.BVULT: 'ult', tt.AST_NODE.BVULE: 'ule',
                       tt.AST_NODE.BVUGT: 'ugt', tt.AST_NODE.BVUGE: 'uge', tt.AST_NODE.BVSLT: 'slt', tt.AST_NODE.BVSLE: 'sle',
                       tt.AST_NODE.BVSGT: 'sgt', tt.AST_NODE.BVSGE: 'sge'}
        if kind in comparisons:
            return {'op': comparisons[kind], 'args': [self.expression(child, child.getBitvectorSize(), depth + 1, budget) for child in children]}
        logical = {tt.AST_NODE.LNOT: 'lnot', tt.AST_NODE.LAND: 'land', tt.AST_NODE.LOR: 'lor', self.logical_xor_kind: 'lxor'}
        if kind in logical: return {'op': logical[kind], 'args': [self.predicate_expression(child, depth + 1, budget) for child in children]}
        raise ValueError('Unsupported predicate AST kind ' + str(kind))

    def predicate_ast(self, value):
        ast = self.ast
        functions = {'eq': ast.equal, 'ne': ast.distinct, 'ult': ast.bvult, 'ule': ast.bvule, 'ugt': ast.bvugt, 'uge': ast.bvuge,
                     'slt': ast.bvslt, 'sle': ast.bvsle, 'sgt': ast.bvsgt, 'sge': ast.bvsge}
        if value['op'] in functions: return functions[value['op']](*(self.expression_ast(arg) for arg in value['args']))
        args = [self.predicate_ast(arg) for arg in value['args']]
        if value['op'] == 'lnot': return ast.lnot(args[0])
        return {'land': ast.land, 'lor': ast.lor, 'lxor': ast.lxor}[value['op']](args)

    def expression_ast(self, value):
        ast = self.ast
        if value['op'] == 'select': return ast.ite(self.predicate_ast(value['conditionExpression']), self.expression_ast(value['then']), self.expression_ast(value['else']))
        if value['op'] == 'bool-bv': return ast.ite(self.predicate_ast(value['conditionExpression']), ast.bv(1, 1), ast.bv(0, 1))
        if value['op'] == 'input':
            node = self.input_nodes[value['name']]
            return ast.extract(value['bits'] - 1, 0, node) if value['bits'] < node.getBitvectorSize() else node
        if value['op'] == 'environment':
            node = self.projected_environment[value['name']]
            return ast.extract(value['bits'] - 1, 0, node) if value['bits'] < node.getBitvectorSize() else node
        if value['op'] == 'constant': return ast.bv(int(value['value'], 16), value['bits'])
        args = [self.expression_ast(arg) for arg in value['args']]
        if value['op'] == 'extract': return ast.extract(value['low'] + value['bits'] - 1, value['low'], args[0])
        if value['op'] in ('zx', 'sx'): return (ast.zx if value['op'] == 'zx' else ast.sx)(value['bits'] - args[0].getBitvectorSize(), args[0])
        if value['op'] == 'concat': return ast.concat(args)
        if value['op'] in ('shl', 'lshr', 'ashr'): return {'shl': ast.bvshl, 'lshr': ast.bvlshr, 'ashr': ast.bvashr}[value['op']](*args)
        if value['op'] in ('rol', 'ror'): return {'rol': ast.bvrol, 'ror': ast.bvror}[value['op']](*args)
        if value['op'] == 'urem': return ast.bvurem(*args)
        if value['op'] == 'not': return ast.bvnot(args[0])
        function = {'add': ast.bvadd, 'sub': ast.bvsub, 'mul': ast.bvmul, 'xor': ast.bvxor, 'and': ast.bvand, 'or': ast.bvor}[value['op']]
        result = args[0]
        for arg in args[1:]: result = function(result, arg)
        return result


def analyze(params, tt, image):
    if not isinstance(params.get('trace_image_only', False), bool):
        raise ValueError('trace_image_only must be an explicit boolean')
    recorded_only = params.get('trace_image_only') is True
    if recorded_only == getattr(image, 'original_file_available', True):
        raise ValueError('Explicit trace source mode differs from image identity')
    inputs = params.get('trace_inputs')
    if not isinstance(inputs, list) or len(inputs) != 2 or inputs[0] not in INPUT_REGS or inputs[1] not in INPUT_REGS:
        raise ValueError('trace_inputs must contain explicit x/y register names')
    if tuple(inputs) not in INPUT_PAIRS: raise ValueError('Inputs must be an equal-width RDI/RSI or RCX/RDX pair')
    if INPUT_REGS[inputs[0]] != INPUT_REGS[inputs[1]]: raise ValueError('Inputs must have equal bit widths')
    if params.get('trace_output') not in OUTPUT_REGS: raise ValueError('Explicit trace_output is required')
    bounded_int(params.get('max_instructions', 50000), 1, 100000, 'max_instructions')
    if image.bits != 64 or image.architecture != 'x86': raise ValueError('Trace analysis currently supports x86-64 images')
    traces = params.get('traces')
    if not isinstance(traces, list) or not 1 <= len(traces) <= 2: raise ValueError('Provide one or two explicit traces')
    for trace in traces:
        if hashlib.sha256(base64.b64decode(trace['data'], validate=True)).hexdigest() != trace['sha256']: raise ValueError('Trace digest mismatch')
    recovery = Recovery(tt, params, image)
    rows = [recovery.replay(trace, index) for index, trace in enumerate(traces)]
    ast = recovery.ast
    recovered = None
    coverage = 'single-recorded-path'
    coverage_proof = None
    if len(rows) == 1 and not rows[0]['outputDependsOnUndefinedFlags'] and rows[0]['guard'] is not None and rows[0]['guard']['expression'] == 'true':
        recovered = rows[0]['outputExpression']
        coverage = 'trace-model-input-domain'
    elif len(rows) == 2 and all(row['guard'] is not None and not row['outputDependsOnUndefinedFlags'] for row in rows):
        disjoint = recovery.proof(ast.land([row['_guard'] for row in rows]))
        exhaustive = recovery.proof(ast.lnot(ast.lor([row['_guard'] for row in rows])))
        coverage_proof = {'disjoint': disjoint, 'exhaustive': exhaustive}
        if disjoint['status'] == exhaustive['status'] == 'unsat':
            recovered = {'op': 'select', 'condition': rows[0]['guard']['expression'],
                         'conditionExpression': rows[0]['guard'].get('conditionExpression'),
                         'then': rows[0]['outputExpression'], 'else': rows[1]['outputExpression'], 'bits': OUTPUT_REGS[params['trace_output']]}
            coverage = 'trace-model-input-domain'
    for row in rows: row.pop('_output'); row.pop('_guard')
    return {'ok': True, 'engine': 'IG5 Offline Trace / Triton', 'method': 'recorded-x86-symbolic-semantics',
            'nativeTargetExecuted': False, 'traceReplayed': True, 'databaseModified': False,
            'targetSha256': image.sha256,
            'targetVerification': {'source': 'hash-bound-native-recording' if recorded_only else 'original-file',
                'originalFileRead': not recorded_only, 'recordedImageOnly': recorded_only,
                'digestScope': 'Target identity recorded at capture; original file not opened or rehashed' if recorded_only else 'Original file digest checked by host and worker'},
            'boundaries': {'entry': params['trace_entry'], 'exit': params['trace_exit'], 'initialFlags': params['initial_flags']},
            'inputs': [{'name': name, 'register': register, 'bits': INPUT_REGS[register]} for name, register in zip(('x', 'y'), inputs)],
            'output': {'register': params['trace_output'], 'bits': OUTPUT_REGS[params['trace_output']]},
            'paths': rows, 'recoveredExpression': recovered, 'coverage': coverage, 'coverageProof': coverage_proof,
            'proofScope': {'symbolicInputBits': {name: INPUT_REGS[register] for name, register in zip(('x', 'y'), inputs)},
                'allInputPairsProved': coverage == 'trace-model-input-domain',
                'environmentScope': 'Each supplied trace\'s explicit environment observations and recorded memory locations',
                'observedInputsRole': 'Concrete snapshot consistency only; not the SMT quantification domain',
                'guardProjectionRole': 'A low-bit guard partitions full-width inputs; it does not narrow their declared widths',
                'functionReturnEstablishedByReplay': False,
                'originalBinaryWholeProgramProved': False},
            'solverQueries': recovery.solver_queries,
            'solverCacheHits': recovery.proof_cache_hits,
            'budgets': {'instructionsPerPath': params.get('max_instructions', 50000), 'undefinedVariablesPerPath': recovery.unknown_budget,
                        'solverQueries': 128, 'solverTimeoutMs': 2000, 'solverMemoryMiB': 512, 'softDeadlineSeconds': 50},
            'wholeBinaryVerified': False, 'limitations': ['Proofs cover supplied recorded instruction semantics under explicit environment observations.',
                'Original binary path coverage, side effects, unrecorded environment, and hidden server logic are not proved.',
                'Symbolic memory addresses are constrained to recorded locations; unknown guards remain partial.']}
