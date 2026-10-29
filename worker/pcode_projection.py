"""Bounded, read-only state projection of an explicit x64 raw SLEIGH path.

The returned DAG is a translation, not a solver certificate.  BV operations use
raw p-code width semantics; arithmetic is modulo 2**bits. Comparisons and BOOL
operations produce an 8-bit zero or one. Shifts use the unsigned full shift
operand (no implicit x86 masking). ``extract`` uses a least-significant bit
offset; ``concat`` lists most-significant operands first. ``load_le`` and
``store_le`` operate on a single total byte array with wrapping uint64 addresses.
All other operation names retain their raw SLEIGH p-code meanings.

Instruction decoding is a separate immutable input. Data stores do not change
that decoding. This is not a model of faults, MMIO, concurrency, instruction
fetch coherence or complete architectural flags. There are no file, process,
network, native-code, solver or database operations in this module.
"""
from __future__ import annotations

import hashlib
import json

from projection_flags import FLAG_OFFSETS, classify_flags
from projection_bsr import BsrRejected, match_bsr_structure
from projection_bsf import match_bsf_structure
from projection_cmov import match_cmov_structure
from projection_call import CallRejected,match_direct_call
from projection_opaque import OpaqueRejected,match_effect as match_opaque_effect,advance_known_flags

GPRS = {name: offset for name, offset in zip(
    ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
     'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'),
    (0, 8, 16, 24, 32, 40, 48, 56, 128, 136, 144, 152, 160, 168, 176, 184))}
_GPR_BYTES = frozenset(offset + i for offset in GPRS.values() for i in range(8))
_FLAG_BYTES = frozenset((0x200, 0x202, 0x204, 0x206, 0x207, 0x20b))
_RIP_OFFSET = 0x288
_BINARY = frozenset(('INT_ADD', 'INT_SUB', 'INT_MULT', 'INT_AND', 'INT_OR', 'INT_XOR', 'INT_REM'))
_COMPARE = frozenset(('INT_EQUAL', 'INT_NOTEQUAL', 'INT_LESS', 'INT_LESSEQUAL',
                      'INT_SLESS', 'INT_SLESSEQUAL', 'INT_CARRY', 'INT_SCARRY', 'INT_SBORROW'))
_SHIFT = frozenset(('INT_LEFT', 'INT_RIGHT', 'INT_SRIGHT'))
_BOOL = frozenset(('BOOL_NEGATE', 'BOOL_AND', 'BOOL_OR', 'BOOL_XOR'))
_UNARY = frozenset(('COPY', 'INT_NEGATE', 'INT_2COMP', 'INT_ZEXT', 'INT_SEXT', 'POPCOUNT', 'LZCOUNT'))
_PURE = _BINARY | _COMPARE | _SHIFT | _BOOL | _UNARY | {'PIECE', 'SUBPIECE'}
_CONTROL = frozenset(('BRANCH', 'CBRANCH', 'BRANCHIND', 'RETURN', 'CALL'))
_U64_MAX = (1 << 64) - 1
LIMITS = {'instructions': 128, 'pcodePerInstruction': 128, 'pcodeOperations': 8192,
          'dagNodes': 2048, 'dagReferences': 8192, 'dagDepth': 128, 'memoryBytes': 256}


class ProjectionError(ValueError):
    """The requested projection cannot be represented within this contract."""


def _require(condition, message):
    if not condition:
        raise ProjectionError(message)


def _integer(value, name, low=0, high=_U64_MAX):
    _require(type(value) is int and low <= value <= high, 'Invalid ' + name)
    return value


def _hex(value, name):
    _require(type(value) is str and 3 <= len(value) <= 34 and value.startswith('0x'), 'Invalid ' + name)
    _require(all(c in '0123456789abcdefABCDEF' for c in value[2:]), 'Invalid ' + name)
    return int(value, 16)


def _varnode(value, output=False, target=False):
    _require(type(value) is dict, 'Invalid p-code varnode')
    space = value.get('space')
    allowed = {'register', 'unique'} if output else {'register', 'unique', 'const'}
    if target:
        allowed = {'ram'}
    _require(space in allowed, 'Unsupported p-code varnode space')
    size = _integer(value.get('size'), 'p-code width', 1, 16)
    offset = _hex(value.get('offset'), 'p-code offset')
    if space == 'const':
        _require(offset < (1 << (size * 8)), 'Constant exceeds p-code width')
    elif space == 'ram':
        _require(offset <= _U64_MAX, 'Control address exceeds uint64')
    else:
        _require(offset + size - 1 <= _U64_MAX, 'P-code location exceeds uint64')
    if space == 'register':
        locations = set(range(offset, offset + size))
        _require(locations <= _GPR_BYTES or (size == 1 and offset in _FLAG_BYTES)
                 or (offset == _RIP_OFFSET and size == 8),
                 'Unsupported architectural register (only x64 GPR/status flags/terminal RIP)')
        # A single varnode cannot straddle independent architectural GPRs.
        if locations <= _GPR_BYTES:
            _require(any(base <= offset and offset + size <= base + 8 for base in GPRS.values()),
                     'Register varnode crosses a GPR boundary')
    if space == 'ram':
        _require(size == 8, 'Control target must be 64-bit')
    return {'space': space, 'size': size, 'offset': offset}


def _locations(value, ordinal):
    if value['space'] not in ('register', 'unique'):
        return set()
    return {(value['space'], ordinal if value['space'] == 'unique' else None, value['offset'] + i)
            for i in range(value['size'])}


def _validate_op(raw):
    _require(type(raw) is dict, 'Invalid p-code operation')
    kind, raw_inputs = raw.get('opcode'), raw.get('inputs')
    _require(type(kind) is str, 'Invalid p-code opcode')
    _require(kind in _PURE | _CONTROL | {'LOAD', 'STORE'}, 'Unsupported p-code effect: ' + kind[:64])
    _require(type(raw_inputs) is list and len(raw_inputs) <= 3, 'Invalid p-code inputs')
    raw_output = raw.get('output')
    if kind in _CONTROL or kind == 'STORE':
        _require(raw_output is None, 'Unexpected p-code effect output')
        out = None
    else:
        out = _varnode(raw_output, output=True)
    if kind in ('LOAD', 'STORE'):
        _require(len(raw_inputs) == (2 if kind == 'LOAD' else 3), 'Invalid memory operands')
        descriptor = raw_inputs[0]
        _require(type(descriptor) is dict and descriptor.get('kind') == 'address-space'
                 and descriptor.get('space') == 'ram', 'Only flat byte-addressed RAM is modeled')
        args = [_varnode(v) for v in raw_inputs[1:]]
        _require(args[0]['size'] == 8, 'Memory address must be 64-bit')
    elif kind in ('BRANCH', 'CBRANCH', 'CALL'):
        _require(len(raw_inputs) == (2 if kind == 'CBRANCH' else 1), 'Invalid direct control operands')
        _require(type(raw_inputs[0]) is dict and raw_inputs[0].get('space') != 'const',
                 'Internal p-code control flow is unsupported')
        args = [_varnode(raw_inputs[0], target=True)]
        if kind == 'CBRANCH':
            args.append(_varnode(raw_inputs[1]))
            _require(args[1]['size'] == 1, 'Branch condition must be one byte')
    elif kind in ('BRANCHIND', 'RETURN'):
        _require(len(raw_inputs) == 1, 'Invalid indirect control operands')
        args = [_varnode(raw_inputs[0])]
        _require(args[0]['size'] == 8, 'Indirect control target must be 64-bit')
    else:
        arity = 1 if kind in _UNARY or kind == 'BOOL_NEGATE' else 2
        _require(len(raw_inputs) == arity, 'Invalid pure p-code operand count')
        args = [_varnode(v) for v in raw_inputs]
        sizes = [v['size'] for v in args]
        if kind in _BINARY or kind in ('COPY', 'INT_NEGATE', 'INT_2COMP'):
            _require(all(size == out['size'] for size in sizes), 'P-code arithmetic width mismatch')
        elif kind in _COMPARE:
            _require(sizes[0] == sizes[1] and out['size'] == 1, 'P-code comparison width mismatch')
        elif kind in _BOOL:
            _require(out['size'] == 1 and all(size == 1 for size in sizes), 'P-code Boolean width mismatch')
        elif kind in _SHIFT:
            _require(sizes[0] == out['size'], 'P-code shift width mismatch')
        elif kind in ('INT_ZEXT', 'INT_SEXT'):
            _require(sizes[0] <= out['size'], 'P-code extension narrows input')
        elif kind == 'PIECE':
            _require(sum(sizes) == out['size'], 'P-code PIECE width mismatch')
        elif kind == 'SUBPIECE':
            _require(args[1]['space'] == 'const' and args[1]['offset'] + out['size'] <= sizes[0],
                     'Invalid p-code SUBPIECE slice')
        elif kind in ('POPCOUNT', 'LZCOUNT'):
            _require((1 << (8 * out['size'])) > sizes[0] * 8, 'P-code count output too narrow')
        if kind == 'INT_REM':
            _require(args[1]['space'] == 'const' and args[1]['offset'] != 0,
                     'INT_REM requires a nonzero immediate divisor')
    return {'opcode': kind, 'output': out, 'inputs': args}


def _validate_bswap_encoding(instruction):
    """Reject undefined or unrecognized BSWAP forms before any dead-code slicing.

    This narrow guard is not a general decoder or undefined-GPR model. Only
    optional 66, followed by at most one immediately adjacent REX, is accepted.
    A REX before a later legacy prefix is ineffective and never supplies W here;
    noncanonical/duplicate prefix orders remain unsupported rather than guessed.
    """
    raw, size = instruction.get('codeBytes'), instruction.get('size')
    named = instruction.get('mnemonic') == 'BSWAP'
    message = 'Unsupported BSWAP encoding or metadata at ' + instruction['ea']
    bound = (type(raw) is str and type(size) is int and len(raw) == size * 2
             and all(char in '0123456789abcdefABCDEF' for char in raw))
    if not bound:
        _require(not named, message)
        return
    code = bytes.fromhex(raw)
    # Recognize this opcode even under unsupported prefixes or a mismatching
    # mnemonic, then fail closed. Recognition does not authorize the encoding.
    scan = 0
    prefixes = {0x66, 0x67, 0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65}
    while scan < len(code) and (code[scan] in prefixes or 0x40 <= code[scan] <= 0x4f):
        scan += 1
    encoded = (scan + 1 < len(code) and code[scan] == 0x0f
               and 0xc8 <= code[scan + 1] <= 0xcf)
    if not named and not encoded:
        return
    _require(named and encoded, message)
    index = 0
    operand16 = code[0] == 0x66
    if operand16:
        index += 1
    rex = 0
    if index < len(code) and 0x40 <= code[index] <= 0x4f:
        rex = code[index]
        index += 1
    _require(index + 2 == len(code) and code[index] == 0x0f
             and 0xc8 <= code[index + 1] <= 0xcf, message)
    _require(not operand16 or bool(rex & 8),
             'Architecturally undefined 16-bit BSWAP is unsupported at ' + instruction['ea'])


def _plan(instructions, registers, check, mode='strict'):
    _require(type(instructions) is list and 1 <= len(instructions) <= LIMITS['instructions'],
             'Path instruction budget exceeded')
    _require(type(registers) is list and 1 <= len(registers) <= 16,
             'Select 1..16 unique lowercase x64 GPRs')
    _require(all(type(name) is str and name in GPRS for name in registers)
             and len(set(registers)) == len(registers), 'Select 1..16 unique lowercase x64 GPRs')
    rows, flat, memory_bytes, total, control, operations_by_instruction, flag_policies = [], [], 0, 0, None, [], []
    internal_candidates, opaque_effects, known_flags = [], [], {}
    for ordinal, instruction in enumerate(instructions):
        check()
        _require(type(instruction) is dict, 'Invalid decoded instruction')
        ea = _hex(instruction.get('ea'), 'instruction address')
        size = _integer(instruction.get('size'), 'instruction size', 1, 15)
        _require(ea + size <= _U64_MAX, 'Instruction fallthrough exceeds uint64')
        mnemonic, operands = instruction.get('mnemonic'), instruction.get('operands')
        _require(type(mnemonic) is str and 1 <= len(mnemonic) <= 64
                 and type(operands) is str and len(operands) <= 512, 'Invalid instruction description')
        pcode = instruction.get('pcode')
        _require(type(pcode) is list and len(pcode) <= LIMITS['pcodePerInstruction'],
                 'Per-instruction p-code budget exceeded')
        total += len(pcode)
        _require(total <= LIMITS['pcodeOperations'], 'Total p-code budget exceeded')
        effect=None
        if mode in ('opaque-effects','opaque-status'):
            try:
                matched=match_opaque_effect(instruction,known_flags if mode=='opaque-status' else None)
            except OpaqueRejected as error:
                raise ProjectionError('Opaque-effect binding rejected: '+str(error)) from error
            if matched is not None:
                pcode,descriptor=matched
                effect={**descriptor,'instructionIndex':ordinal,'source':hex(ea)}
                opaque_effects.append(effect)
        if effect is None:
            _validate_bswap_encoding(instruction)
        # Internal control stays rejected except for a freshly matched complete
        # finite BSR/BSF or register-CMOV shape. No input annotation supplies it.
        has_internal = any(type(raw) is dict and raw.get('opcode') in ('BRANCH', 'CBRANCH')
                           and type(raw.get('inputs')) is list and raw['inputs']
                           and type(raw['inputs'][0]) is dict and raw['inputs'][0].get('space') == 'const'
                           for raw in pcode)
        candidate = None
        if has_internal or mnemonic.startswith('CMOV'):
            try:
                matcher = match_cmov_structure if mnemonic.startswith('CMOV') else match_bsf_structure if mnemonic == 'BSF' else match_bsr_structure
                candidate = matcher(instruction, check)
            except BsrRejected as error:
                raise ProjectionError('Internal p-code control flow is unsupported: ' + str(error)) from error
        row = {'ea': hex(ea), 'size': size, 'mnemonic': mnemonic, 'operands': operands}
        branch, defined_unique, uses_rip, normalized = None, set(), False, []
        for index, raw in enumerate(pcode):
            check()
            internal_control = candidate is not None and raw['opcode'] in ('BRANCH', 'CBRANCH')
            if internal_control:
                # Complete structure matching has checked output, arity,
                # widths, conditions, and signed constant relative targets.
                op = {'opcode': raw['opcode'], 'output': None,
                      'inputs': [_varnode(value, target=value.get('space') == 'ram') for value in raw['inputs']]}
            elif effect is not None and index==0 and raw['opcode']=='IG5_OPAQUE':
                # Only match_opaque_effect can authorize this freshly generated
                # zero-input definition; raw user pseudo-ops remain unsupported.
                op={'opcode':'IG5_OPAQUE','output':_varnode(raw['output'],output=True),'inputs':[]}
            else:
                op = _validate_op(raw)
            normalized.append(op)
            kind = op['opcode']
            uses_rip |= any(value and value['space'] == 'register' and value['offset'] == _RIP_OFFSET
                            for value in [op['output'], *op['inputs']])
            for value in op['inputs']:
                if value['space'] == 'unique':
                    _require(_locations(value, ordinal) <= defined_unique, 'Undefined p-code unique temporary')
            if op['output']:
                defined_unique.update(loc for loc in _locations(op['output'], ordinal) if loc[0] == 'unique')
            if internal_control:
                pass
            elif kind in _CONTROL:
                _require(branch is None and index == len(pcode) - 1,
                         'Control transfer must terminate the instruction')
                branch = op
            else:
                flat.append((ordinal, index, op))
            if kind in ('LOAD', 'STORE'):
                memory_bytes += op['output']['size'] if kind == 'LOAD' else op['inputs'][1]['size']
                _require(memory_bytes <= LIMITS['memoryBytes'], 'Memory byte budget exceeded')
        if uses_rip:
            _require(ordinal == len(instructions) - 1 and branch is not None
                     and branch['opcode'] == 'RETURN'
                     and branch['inputs'][0]['space'] == 'register'
                     and branch['inputs'][0]['offset'] == _RIP_OFFSET,
                     'RIP is supported only as the explicitly defined terminal RETURN target')
        try:
            direct_call=match_direct_call(instruction,normalized)
        except CallRejected as error:
            raise ProjectionError('Unsupported direct CALL: '+str(error)) from error
        if direct_call is not None:
            row['directCall']=direct_call
        row['_branch'] = branch
        if effect is not None:row['opaqueEffect']=effect
        rows.append(row)
        operations_by_instruction.append([(ordinal, index, operation) for index, operation in enumerate(normalized)
                                          if operation['opcode'] not in _CONTROL])
        if candidate is not None:
            candidate = {**candidate, 'instructionIndex': ordinal, 'ea': hex(ea), 'size': size,
                         'codeBytes': instruction['codeBytes'].lower(),
                         'rawPcodeSemanticSha256': hashlib.sha256(json.dumps(
                             normalized, sort_keys=True, separators=(',', ':')).encode('ascii')).hexdigest()}
            if candidate.get('statusFlagsPreserved'):
                flag_policies.append(classify_flags(instruction, normalized))
            else:
                flag_policies.append({'status': 'classified', 'family': mnemonic.lower() + '-complete-bounded-shape',
                                  'defined': ['zf'], 'preserved': [],
                                  'undefined': ['af', 'cf', 'of', 'pf', 'sf'], 'unmodeled': [],
                                  'encodedWidth': candidate['operandBits'], 'maskedCount': None,
                                  'codeBytes': candidate['codeBytes']})
        elif effect is not None:
            flag_policies.append({'status':'classified','family':'opaque-effect-flags-preserved',
                'defined':[],'preserved':list(FLAG_OFFSETS),'undefined':[],'unmodeled':[],
                'encodedWidth':None,'maskedCount':None,'codeBytes':instruction['codeBytes'].lower()})
        else:
            flag_policies.append(classify_flags(instruction, normalized))
        if mode=='opaque-status':
            known_flags=advance_known_flags(known_flags,flag_policies[-1],normalized,ordinal,allow_defined=candidate is None)
        internal_candidates.append(candidate)
    intermediate = {}
    if mode in ('guarded-path','opaque-effects','opaque-status'):
        _require(len({row['ea'] for row in rows}) == len(rows), 'Repeated instruction addresses require a loop model')
    for ordinal, row in enumerate(rows):
        check()
        next_ea = int(rows[ordinal + 1]['ea'], 16) if ordinal + 1 < len(rows) else None
        fallthrough = int(row['ea'], 16) + row['size']
        branch = row.pop('_branch')
        if branch is None:
            _require(next_ea is None or next_ea == fallthrough, 'Missing fallthrough path instruction')
            if next_ea is None:
                control = {'kind': 'fallthrough', 'target': fallthrough, 'ordinal': ordinal}
        elif branch['opcode'] in ('BRANCH','CALL'):
            target = branch['inputs'][0]['offset']
            _require(next_ea is None or next_ea == target, 'Direct branch/path mismatch')
            if next_ea is None:
                control = {'kind': 'direct', 'target': target, 'ordinal': ordinal}
                if branch['opcode']=='CALL' or 'directCall' in row:
                    control.update(transfer='call',returnAddress=fallthrough)
        else:
            kind = branch['opcode']
            if next_ea is not None and mode == 'guarded-path' and kind == 'CBRANCH':
                taken = branch['inputs'][0]['offset']
                _require(taken != fallthrough, 'Ambiguous same-target intermediate conditional branch')
                _require(next_ea in (taken, fallthrough), 'Conditional branch/path mismatch')
                intermediate[ordinal] = {'condition': branch['inputs'][1],
                                         'taken': taken, 'fallthrough': fallthrough,
                                         'continuedSuccessor': 'taken' if next_ea == taken else 'fallthrough'}
                continue
            _require(next_ea is None, 'Conditional/indirect control only supported at path end')
            if kind == 'CBRANCH':
                control = {'kind': 'conditional', 'taken': branch['inputs'][0]['offset'],
                           'fallthrough': fallthrough, 'condition': branch['inputs'][1], 'ordinal': ordinal}
            else:
                control = {'kind': 'return' if kind == 'RETURN' else 'indirect',
                           'value': branch['inputs'][0], 'ordinal': ordinal}
    live = {('register', None, GPRS[name] + i) for name in registers for i in range(8)}
    for key in ('condition', 'value'):
        if key in control:
            live.update(_locations(control[key], control['ordinal']))
    selected, internal_elisions = [], []
    for ordinal in range(len(rows) - 1, -1, -1):
        check()
        if ordinal in intermediate:
            # Every side exit observes the declared GPR projection at this
            # exact point, even if later instructions overwrite those bytes.
            live.update(('register', None, GPRS[name] + i) for name in registers for i in range(8))
            live.update(_locations(intermediate[ordinal]['condition'], ordinal))
        candidate = internal_candidates[ordinal]
        if candidate is not None:
            # The descriptor and live set are generated in this same bounded
            # planner call. Every STORE and terminal dependency already roots
            # the live set; none can be waived by an external certificate.
            frame = {('register', None, offset) for offset in candidate['frameRegisterBytes']}
            _require(not live & frame,
                     'Live ' + rows[ordinal]['mnemonic'] + ' destination/status-flag frame cannot be eliminated at ' + rows[ordinal]['ea'])
            omitted_control = candidate.get('internalControlOperationCount', 3)
            internal_elisions.append({**candidate,
                                      'frameRegisterBytes': [hex(v) for v in candidate['frameRegisterBytes']],
                                      'exitLiveByteCount': len(live),
                                      'exitLiveRegisterBytes': [hex(offset) for space, _, offset in sorted(live)
                                                                if space == 'register'],
                                      'frameLiveIntersection': [],
                                      'omittedRawPcodeOperations': candidate['rawOperationCount'],
                                      'omittedPurePcodeOperations': candidate['rawOperationCount'] - omitted_control,
                                      'omittedInternalControlOperations': omitted_control,
                                      'reason': 'entire-acyclic-register-effect-frame-dead' if candidate.get('statusFlagsPreserved') else 'entire-bounded-pure-effect-frame-dead'})
            continue
        policy = flag_policies[ordinal]
        blocked = {('register', None, FLAG_OFFSETS[name]) for name in policy['undefined'] + policy['unmodeled']}
        crossing = live & blocked
        _require(not crossing, 'Undefined/unmodeled architectural flag crosses ' + rows[ordinal]['ea']
                 + ' (' + rows[ordinal]['mnemonic'] + '): '
                 + ','.join(name for name, offset in FLAG_OFFSETS.items() if ('register', None, offset) in crossing))
        selected_flag_effect = False
        for _, index, op in reversed(operations_by_instruction[ordinal]):
            check()
            defined = _locations(op['output'], ordinal) if op['output'] else set()
            if op['opcode'] == 'STORE' or live & defined:
                used = set().union(*(_locations(value, ordinal) for value in op['inputs']))
                internal_blocked = (defined | used) & blocked
                _require(not internal_blocked,
                         'Undefined/unmodeled architectural flag used inside ' + rows[ordinal]['ea']
                         + ' (' + rows[ordinal]['mnemonic'] + '): '
                         + ','.join(name for name, offset in FLAG_OFFSETS.items()
                                    if ('register', None, offset) in internal_blocked))
                selected_flag_effect |= any(space == 'register' and offset in _FLAG_BYTES
                                            for space, _, offset in defined | used)
                live.difference_update(defined)
                live.update(used)
                selected.append((ordinal, index, op))
        _require(policy['status'] == 'classified' or not selected_flag_effect,
                 'Instruction metadata cannot classify a live architectural flag effect at ' + rows[ordinal]['ea'])
    _require(not any(space == 'unique' for space, _, _ in live), 'Undefined live p-code unique temporary')
    _require(all(space != 'register' or offset in _GPR_BYTES for space, _, offset in live),
             'Projection depends on undefined initial architectural flags or RIP')
    return (rows, list(reversed(selected)), control, total, len(flat), memory_bytes,
            flag_policies, list(reversed(internal_elisions)), intermediate, opaque_effects)


class _Dag:
    def __init__(self, check):
        self.check, self.nodes, self.intern, self.depth, self.references = check, [], {}, [], 0

    def make(self, op, args=(), bits=None, **data):
        self.check()
        key = (op, tuple(args), bits, tuple(sorted(data.items())))
        if key in self.intern:
            return self.intern[key]
        depth = 1 + max((self.depth[arg] for arg in args), default=0)
        _require(len(self.nodes) < LIMITS['dagNodes'], 'DAG node budget exceeded')
        _require(self.references + len(args) <= LIMITS['dagReferences'], 'DAG reference budget exceeded')
        _require(depth <= LIMITS['dagDepth'], 'DAG depth budget exceeded')
        identity = len(self.nodes)
        node = {'id': identity, 'op': op, 'type': 'memory' if bits is None else 'bv', 'args': list(args)}
        if bits is not None:
            node['bits'] = bits
        node.update(data)
        self.nodes.append(node)
        self.depth.append(depth)
        self.intern[key] = identity
        self.references += len(args)
        return identity

    def const(self, value, bits):
        return self.make('const', bits=bits, value=hex(value % (1 << bits)))

    def extract(self, value, offset, bits):
        node = self.nodes[value]
        _require(0 <= offset and offset + bits <= node['bits'], 'Invalid DAG extract')
        if offset == 0 and bits == node['bits']:
            return value
        if node['op'] == 'const':
            return self.const(int(node['value'], 16) >> offset, bits)
        if node['op'] == 'extract':
            return self.extract(node['args'][0], offset + node['offset'], bits)
        return self.make('extract', (value,), bits, offset=offset)

    def concat(self, values):
        if len(values) == 1:
            return values[0]
        nodes = [self.nodes[value] for value in values]
        bits = sum(node['bits'] for node in nodes)
        if all(node['op'] == 'const' for node in nodes):
            number = 0
            for node in nodes:
                number = (number << node['bits']) | int(node['value'], 16)
            return self.const(number, bits)
        if all(node['op'] == 'extract' and node['args'] == nodes[0]['args'] for node in nodes):
            position = nodes[-1]['offset']
            if all(node['offset'] == position + sum(n['bits'] for n in nodes[i + 1:])
                   for i, node in enumerate(nodes)):
                return self.extract(nodes[0]['args'][0], position, bits)
        return self.make('concat', values, bits)


def project(instructions, registers, check=lambda: None, *, mode='strict', _memory_account=None):
    """Translate a complete supplied fixed path, or raise ProjectionError.

    ``instructions`` are raw single-instruction objects from SleighDecoder;
    ``registers`` is an explicit list of final x64 GPRs. All stores and final
    control remain observable even when no selected GPR depends on them.
    ``check`` is called throughout validation and DAG creation for cancellation.
    """
    _require(type(mode) is str and mode in ('strict', 'guarded-path', 'opaque-effects','opaque-status'), 'Unknown projection mode')
    _require(callable(check), 'Cancellation check must be callable')
    (rows, selected, terminal, total, flat_count, memory_bytes,
     flag_policies, internal_elisions, intermediate, opaque_effects) = _plan(instructions, registers, check, mode)
    opaque=mode in ('opaque-effects','opaque-status')
    if opaque:
        from projection_opaque import make_dag
        dag=make_dag(check)
    else:
        dag=_Dag(check)
    if _memory_account is not None:
        # Internal composition-only shared counters, never public input. Caches
        # and expression identities stay local to each independently built DAG.
        _require(opaque and type(_memory_account) is dict and
                 _memory_account.get('method') == 'exact-ordered-byte-forwarding' and
                 _memory_account.get('maxStoreVisits') == 4096 and
                 type(_memory_account.get('storeVisits')) is int and
                 0 <= _memory_account['storeVisits'] <= 4096, 'Invalid internal shared memory account')
        dag.memory_normalization = _memory_account
    initial = {name: dag.make('input', bits=64, name=name) for name in GPRS}
    initial_memory = dag.make('initial_memory', name='M0', addressBits=64, elementBits=8)
    memory, stores, register_bytes, unique_bytes = initial_memory, [], {}, {}
    current_ordinal = None
    guarded = mode == 'guarded-path'
    path_guard = dag.const(1, 8) if guarded else None
    branch_points, side_exits, nondeterministic_inputs = [], [], []

    def begin(ordinal):
        nonlocal current_ordinal, unique_bytes
        if ordinal != current_ordinal:
            current_ordinal, unique_bytes = ordinal, {}

    def read(value):
        space, offset, size = value['space'], value['offset'], value['size']
        if space == 'const':
            return dag.const(offset, size * 8)
        storage = register_bytes if space == 'register' else unique_bytes
        values = []
        for i in range(size):
            check()
            location = offset + i
            if location not in storage:
                _require(space == 'register' and location in _GPR_BYTES,
                         'Undefined live p-code register or unique temporary')
                name, base = next((name, base) for name, base in GPRS.items() if base <= location < base + 8)
                storage[location] = dag.extract(initial[name], (location - base) * 8, 8)
            values.append(storage[location])
        return dag.concat(list(reversed(values)))

    def write(output, value):
        storage = register_bytes if output['space'] == 'register' else unique_bytes
        for i in range(output['size']):
            storage[output['offset'] + i] = dag.extract(value, i * 8, 8)

    def emit(ordinal, index, op):
        nonlocal memory
        check()
        begin(ordinal)
        kind, inputs, output = op['opcode'], op['inputs'], op['output']
        args = [read(value) for value in inputs]
        if kind == 'STORE':
            before = memory
            memory = dag.make('store_le', (memory, args[0], args[1]), size=inputs[1]['size'])
            store = {'instructionIndex': ordinal, 'pcodeIndex': index, 'address': args[0],
                     'value': args[1], 'size': inputs[1]['size'],
                     'beforeMemory': before, 'afterMemory': memory}
            if opaque and 'opaqueEffect' in rows[ordinal]:
                effect=rows[ordinal]['opaqueEffect']
                store.update(pcodeIndex=effect['rawStorePcodeIndex'],replacementPcodeIndex=index)
                if 'flagImageRefinement' in effect:effect['flagImageRefinement']['valueNode']=args[1]
            if guarded:
                store['guard'] = path_guard
            stores.append(store)
            return
        bits = output['size'] * 8
        if kind=='IG5_OPAQUE':
            effect=next(e for e in opaque_effects if e['instructionIndex']==ordinal)
            value=dag.make('nondeterministic',bits=bits,name='opaque_'+str(ordinal),kind=effect['kind'],source=effect['source'])
            nondeterministic_inputs.append({'node':value,'bits':bits,'kind':effect['kind'],'source':effect['source'],'instructionIndex':ordinal})
        elif kind == 'LOAD':
            value = dag.make('load_le', (memory, args[0]), bits, size=output['size'])
        elif kind == 'COPY':
            value = args[0]
        elif kind == 'PIECE':
            value = dag.concat(args)
        elif kind == 'SUBPIECE':
            value = dag.extract(args[0], inputs[1]['offset'] * 8, bits)
        elif kind in ('INT_ZEXT', 'INT_SEXT') and dag.nodes[args[0]]['bits'] == bits:
            value = args[0]
        else:
            effect=rows[ordinal].get('opaqueEffect',{})
            # Keep a small canonical mask/boolean/placement tree so the host
            # can rebind every overlay bit. Normal data/memory optimization
            # and all original node/reference/work budgets remain unchanged.
            overlay='flagImageRefinement' in effect and 0<index<effect['replacementOperationCount']-2
            value = _Dag.make(dag,kind,args,bits) if overlay else dag.make(kind, args, bits)
        write(output, value)
    if guarded:
        by_instruction = {}
        for ordinal, index, operation in selected:
            by_instruction.setdefault(ordinal, []).append((index, operation))
        for ordinal in range(len(rows)):
            check()
            begin(ordinal)
            for index, operation in by_instruction.get(ordinal, ()):
                emit(ordinal, index, operation)
            if ordinal in intermediate:
                edge = intermediate[ordinal]
                condition = dag.make('INT_NOTEQUAL', (read(edge['condition']), dag.const(0, 8)), 8)
                chosen = condition if edge['continuedSuccessor'] == 'taken' else dag.make('BOOL_NEGATE', (condition,), 8)
                opposite = dag.make('BOOL_NEGATE', (chosen,), 8)
                exit_guard = dag.make('BOOL_AND', (path_guard, opposite), 8)
                continued_guard = dag.make('BOOL_AND', (path_guard, chosen), 8)
                exit_target = edge['fallthrough'] if edge['continuedSuccessor'] == 'taken' else edge['taken']
                continued_target = edge[edge['continuedSuccessor']]
                exit_registers = {name: read({'space': 'register', 'offset': GPRS[name], 'size': 8}) for name in registers}
                side_exits.append({'instructionIndex': ordinal, 'source': rows[ordinal]['ea'],
                                   'guard': exit_guard, 'target': dag.const(exit_target, 64),
                                   'registers': exit_registers, 'currentMemory': memory,
                                   'continuation': 'not-analyzed', 'statusFlags': 'not-exported'})
                branch_points.append({'instructionIndex': ordinal, 'source': rows[ordinal]['ea'],
                                      'condition': condition, 'prefixGuard': path_guard,
                                      'continuedGuard': continued_guard,
                                      'continuedSuccessor': edge['continuedSuccessor'],
                                      'continuedTarget': dag.const(continued_target, 64),
                                      'sideExitIndex': len(side_exits) - 1})
                path_guard = continued_guard
    else:
        for ordinal, index, operation in selected:
            emit(ordinal, index, operation)
    begin(terminal['ordinal'])
    control = {'kind': terminal['kind'], 'source': rows[terminal['ordinal']]['ea']}
    if terminal['kind'] == 'conditional':
        control.update(condition=read(terminal['condition']), taken=dag.const(terminal['taken'], 64),
                       fallthrough=dag.const(terminal['fallthrough'], 64), conditionRule='nonzero-is-taken')
    elif 'value' in terminal:
        control['target'] = read(terminal['value'])
    else:
        control['target'] = dag.const(terminal['target'], 64)
    if terminal.get('transfer')=='call':
        control.update(transfer='call',returnAddress=hex(terminal['returnAddress']))
    outputs = {name: read({'space': 'register', 'offset': GPRS[name], 'size': 8}) for name in registers}
    root_references = (len(initial) + len(outputs) + 2 + 4 * len(stores)
                       + sum(key in control for key in ('target', 'condition', 'taken', 'fallthrough')))
    if opaque:root_references+=len(nondeterministic_inputs)+sum('flagImageRefinement' in e for e in opaque_effects)
    if guarded:
        root_references += 1 + len(stores) + 4 * len(branch_points)
        root_references += sum(3 + len(item['registers']) for item in side_exits)
    _require(dag.references + root_references <= LIMITS['dagReferences'], 'DAG root reference budget exceeded')
    result = {
        'schema': 'ig5-pcode-projection-v1', 'status': 'translated-unverified',
        'nativeTargetExecuted': False, 'databaseModified': False,
        'businessAccepted': False, 'wholeBinaryVerified': False,
        'path': rows, 'dag': {'nodes': dag.nodes, 'references': dag.references + root_references,
                             'depth': max(dag.depth)},
        'initialRegisters': initial, 'registers': outputs,
        'initialMemory': initial_memory, 'currentMemory': memory, 'stores': stores, 'control': control,
        'flagPolicies': flag_policies, 'internalElisions': internal_elisions,
        'statistics': {'instructions': len(rows), 'pcodeOperations': total,
                       'selectedOperations': len(selected), 'omittedPureOperations': flat_count - len(selected),
                       'omittedInternalControlOperations': sum(item['omittedInternalControlOperations'] for item in internal_elisions),
                       'internalElidedRawOperations': sum(item['omittedRawPcodeOperations'] for item in internal_elisions),
                       'memoryBytes': memory_bytes, 'dagNodes': len(dag.nodes)},
        'limits': dict(LIMITS),
        'scope': {
            'representation': 'fixed-path raw SLEIGH p-code state projection; no independent proof',
            'initialState': 'sixteen independent free uint64 GPRs and one arbitrary coherent total byte memory',
            'memory': 'little-endian loads/stores, ordered aliasing, uint64 address wraparound',
            'coverage': 'only the explicitly supplied instruction path; no reachability or all-input coverage proof',
            'flags': 'byte-bound instruction flag barriers reject live undefined/unmodeled effects; remaining raw-pcode flag formulas are not independently proved',
            'instructionPointer': 'RIP is only a defined terminal RETURN value; no initial RIP or general instruction-pointer state is supplied',
            'internalControl': 'only complete register-source BSR bounded shapes whose entire destination/status-flag frame is dead may be elided; original raw p-code is retained in decoder provenance',
            'codeDataCoherence': 'fixed decoded code and symbolic data memory are separate; self-modifying code is not modeled',
            'excluded': ['OS', 'MMIO', 'faults', 'exceptions', 'concurrency', 'instruction-fetch coherence',
                         'general internal p-code control flow', 'live BSR effects', 'calls', 'syscalls', 'complete business recovery'],
        },
    }

    if any('directCall' in row for row in rows):
        result['scope']['directCalls']=('Only byte-bound unprefixed E8 rel32 with the exact3-operation fixed SLEIGH stack/control shape. '
            'Return-address STORE remains observable; subsequent supplied address must be the actual callee entry, never a guessed call-return/ABI summary. '
            'A terminal call retains its target and literal preferred return address; its callee is not analyzed.')
        result['scope']['excluded'].remove('calls')
        result['scope']['excluded'].extend(['indirect/far/prefixed calls','ABI/callee summaries','CET/shadow-stack effects'])

    if any(item['kind'] == 'register-bsf-bounded-dead-frame-v1' for item in internal_elisions):
        result['scope']['internalControl'] = ('only complete register-source BSR/BSF bounded shapes whose entire destination/status-flag frame is dead may be elided; original raw p-code is retained in decoder provenance')
        result['scope']['excluded'].append('live BSF effects')

    if any(item['kind'] == 'register-cmov-acyclic-dead-frame-v1' for item in internal_elisions):
        result['scope']['internalControl'] += ('; complete byte-bound register-CMOV acyclic shapes may also be elided only when the entire destination frame is dead at every STORE/control/GPR/side-exit root. Flags are preserved; r32 includes the full64 destination frame')
        result['scope']['excluded'].extend(['live CMOV results', 'memory-source CMOV elision'])

    if opaque:
        result.update(schema='ig5-pcode-opaque-status-projection-v1' if mode=='opaque-status' else 'ig5-pcode-opaque-projection-v1',projectionMode=mode,
                      opaqueEffects=opaque_effects,nondeterministicInputs=nondeterministic_inputs,
                      memoryNormalization=dict(dag.memory_normalization))
        result['statistics'].update(abstractedInstructions=len(opaque_effects),
            abstractedRawOperations=sum(e['rawOperationCount'] for e in opaque_effects),
            replacementOperations=sum(e['replacementOperationCount'] for e in opaque_effects))
        result['scope'].update(
            representation='explicit supplied-path conservative opaque-effect projection; no independent proof',
            opaqueEffects='Only complete byte-bound pinned-decoder PUSHFQ/RDTSC/canonical16-bit BSWAP shapes; unknown values are fresh unconstrained64-bit definitions, never observations.',
            approximation='PUSHFQ stores an arbitrary flag image without flag correlations/reserved-bit constraints. RDTSC returns fresh EDX:EAX with upper32 RAX/RDX cleared; no cross-read timing relation. Undefined16-bit BSWAP havocs the whole destination GPR. These are conservative supersets of ordinary fault-free data results, not exact instructions or a CPU/fault model.',
            memory='exact ordered-byte forwarding with4096 store visits; unknown aliases/budget exhaustion keep original LOAD and all STORE effects')
        result['scope']['excluded'].extend(['full flag-image correlations','hardware-time relations','exact undefined-GPR behavior'])
        if mode=='opaque-status':
            result['scope']['approximation']=('Byte-bound PUSHFQ overlays only status bits with prior classified modeled definitions onto a fresh arbitrary64-bit image. '
                'Unknown, unmodeled, undefined and initial flags are not supplied or fixed; AF remains unknown when unmodeled. RDTSC/BSWAP retain their original conservative models. '
                'The overlay preserves raw-pcode correlations, not independent CPU/fault/complete-RFLAGS equivalence.')
            result['scope']['opaqueEffects']='Original pinned raw fingerprints; internally generated status mask/bit placement and forward definition provenance. No caller-supplied status values.'

    if guarded:
        result.update(schema='ig5-pcode-guarded-projection-v1', projectionMode='guarded-path',
                      pathGuard=path_guard, branchPoints=branch_points, sideExits=side_exits)
        result['scope'].update(
            representation='guarded supplied-path raw SLEIGH p-code state projection; no independent proof',
            finalStateValidity='registers/currentMemory/control are valid only when pathGuard is nonzero',
            sideExitValidity='each side exit state is valid only under its own guard; continuation is not analyzed',
            stores='each ordered STORE is executed only under its instruction-entry guard; later path guards must not suppress earlier writes',
            coverage='retained guards for the supplied continuation and explicit side exits; no native reachability, feasibility or all-input business proof',
            statusFlagsExport='flags may flow within this single path but are not exported as resumable exit state')
    return result
