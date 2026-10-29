"""Ghidra-side facts for string decoding: decoder candidates and the constants passed at each call site.

Reads the program only; nothing here emulates or modifies it. Everything is bounded. The scoring and the
emulation live in worker/string_decoding.py; this module supplies engine facts in a neutral shape.

Argument recovery is a bounded backward scan inside one straight-line block. It understands immediate moves,
RIP-relative / absolute LEA, ``xor r,r`` and plain register copies, and recognizes stack-relative LEA as a
buffer. Anything else (loads, arithmetic, values flowing in from other blocks) is reported as unknown.
"""

WIN64 = (('RCX',), ('RDX',), ('R8',), ('R9',))
SYSV64 = (('RDI',), ('RSI',), ('RDX',), ('RCX',), ('R8',), ('R9',))
# Instructions that transform data (as opposed to loop bookkeeping on 32/64-bit pointers and counters).
MIXING = {'XOR', 'ADD', 'SUB', 'ROL', 'ROR', 'NOT', 'NEG', 'SHL', 'SHR', 'SAR', 'SAL', 'AND', 'OR', 'INC', 'DEC'}
ALWAYS_DATA_OPS = {'XOR', 'ROL', 'ROR', 'NOT', 'NEG', 'SHL', 'SHR', 'SAR', 'SAL'}
MEMORY_WRITE_OPS = MIXING | {'MOV', 'XCHG'}
STRING_STORES = {'STOSB', 'STOSW', 'STOSD', 'STOSQ', 'MOVSB', 'MOVSW', 'MOVSD', 'MOVSQ'}
MAX_BACKTRACK, MAX_COPY_DEPTH, MAX_FUNCTION_INSTRUCTIONS, MAX_SITES_PER_DECODER = 40, 3, 2000, 500
MAX_FUNCTIONS, MAX_REFERENCES = 50000, 2000


def _base(register):
    return str(register.getBaseRegister().getName()).upper()


def _operand(instruction, index):
    return str(instruction.getDefaultOperandRepresentation(index)) if index < instruction.getNumOperands() else ''


def function_features(listing, functions, function, each):
    """Structural facts about one function: loop, byte-level mixing, memory stores, calls."""
    entry, loop, mixing, stores, calls, external = function.getEntryPoint(), False, 0, False, 0, 0
    for count, instruction in enumerate(each(listing.getInstructions(function.getBody(), True))):
        if count >= MAX_FUNCTION_INSTRUCTIONS:
            break
        mnemonic, flow = str(instruction.getMnemonicString()).upper(), instruction.getFlowType()
        if flow.isCall():
            targets = instruction.getFlows()
            callee = functions.getFunctionAt(targets[0]) if len(targets) else None
            if callee is None or callee.isExternal() or callee.isThunk():
                external += 1          # an indirect call, an import or a stub: not emulatable here
            else:
                calls += 1
        elif flow.isJump():
            here = instruction.getAddress()
            loop = loop or any(entry.compareTo(target) <= 0 and target.compareTo(here) <= 0 for target in instruction.getFlows())
        destination = _operand(instruction, 0)
        to_memory = '[' in destination
        if mnemonic in STRING_STORES or (to_memory and mnemonic in MEMORY_WRITE_OPS):
            stores = True
        if mnemonic in MIXING:
            register = instruction.getRegister(0)
            zeroing = (mnemonic == 'XOR' and register is not None and instruction.getRegister(1) is not None
                       and _base(register) == _base(instruction.getRegister(1)) and register.getBitLength() == instruction.getRegister(1).getBitLength())
            small = register is not None and register.getBitLength() <= 16
            if not zeroing and (to_memory or small or (mnemonic in ALWAYS_DATA_OPS and register is not None)):
                mixing += 1
    return {'hasLoop': loop, 'arithmetic': mixing, 'memoryWrites': stores, 'calls': calls, 'externalCalls': external}


def _evaluate(instruction, register_name):
    """Value assigned to ``register_name`` by ``instruction``: ('const', v) | ('stack', off) | ('copy', reg) | None."""
    from ghidra.program.model.lang import Register
    mnemonic, destination = str(instruction.getMnemonicString()).upper(), instruction.getRegister(0)
    if destination is None:
        return None
    if mnemonic == 'MOV':
        scalar = instruction.getScalar(1)
        if scalar is not None and destination.getBitLength() >= 32:
            return 'const', scalar.getValue() & ((1 << destination.getBitLength()) - 1)
        source = instruction.getRegister(1)
        if source is not None and '[' not in _operand(instruction, 1) and destination.getBitLength() >= 32:
            return 'copy', _base(source)
        return None
    if mnemonic == 'XOR':
        source = instruction.getRegister(1)
        if source is not None and _base(source) == register_name:
            return 'const', 0
        return None
    if mnemonic == 'LEA':
        objects = [item for item in instruction.getOpObjects(1)]
        frame = [item for item in objects if isinstance(item, Register) and _base(item) in ('RSP', 'RBP')]
        if frame:
            offset = sum(int(item.getSignedValue()) for item in objects if hasattr(item, 'getSignedValue'))
            return 'stack', offset
        for reference in instruction.getOperandReferences(1):
            if reference.isMemoryReference() and not reference.isStackReference():
                return 'const', int(reference.getToAddress().getOffset())
    return None


def resolve_argument(call, register_name):
    """Backward scan from a call for the last assignment to ``register_name`` inside the same straight-line block."""
    from ghidra.program.model.lang import Register
    current, copies, following, instruction = register_name, 0, call, call.getPrevious()
    for _ in range(MAX_BACKTRACK):
        if instruction is None:
            break
        fall_through = instruction.getFallThrough()
        if fall_through is None or not fall_through.equals(following.getAddress()):
            break                                     # a jump or return ends the block: earlier code is not on this path
        if instruction.getFlowType().isCall():
            break                                     # a call clobbers the argument registers
        written = [item for item in instruction.getResultObjects() if isinstance(item, Register)]
        if any(_base(item) == current for item in written):
            value = _evaluate(instruction, current)
            if value is None:
                break
            if value[0] == 'copy':
                copies += 1
                if copies > MAX_COPY_DEPTH:
                    break
                current = value[1]
            elif value[0] == 'stack':
                return {'kind': 'stack', 'offset': value[1]}
            else:
                return {'kind': 'const', 'value': value[1]}
        following, instruction = instruction, instruction.getPrevious()
    return {'kind': 'unknown'}


def collect_candidates(program, abi, limits, each, addrstr, forced=None):
    """Decoder candidates (with call-site arguments) for string_decoding.decode_strings."""
    if abi not in ('win64', 'sysv64'):
        raise ValueError('decode_strings supports the win64 and sysv64 x86-64 calling conventions')
    families = WIN64 if abi == 'win64' else SYSV64
    listing, functions, references = program.getListing(), program.getFunctionManager(), program.getReferenceManager()
    considered, candidates, truncated = 0, [], False
    pool = [forced] if forced is not None else each(functions.getFunctions(True))
    for function in pool:
        considered += 1
        if considered > MAX_FUNCTIONS:
            truncated = True
            break
        size = int(function.getBody().getNumAddresses())
        if forced is None and (function.isThunk() or function.isExternal() or size > limits['max_size']):
            continue
        entry, sites, fan_in = function.getEntryPoint(), [], 0
        for count, reference in enumerate(each(references.getReferencesTo(entry))):
            if count >= MAX_REFERENCES:
                truncated = True
                break
            if not reference.getReferenceType().isCall():
                continue
            fan_in += 1
            if len(sites) >= MAX_SITES_PER_DECODER:
                continue
            call = listing.getInstructionAt(reference.getFromAddress())
            if call is None:
                continue
            caller = functions.getFunctionContaining(call.getAddress())
            sites.append({'ea': addrstr(call.getAddress()),
                          'caller': None if caller is None else {'ea': addrstr(caller.getEntryPoint()), 'name': str(caller.getName())},
                          'args': [resolve_argument(call, family[0]) for family in families]})
        if forced is None and fan_in < limits['min_calls']:
            continue
        features = dict(function_features(listing, functions, function, each), fanIn=fan_in)
        candidates.append({'ea': addrstr(entry), 'name': str(function.getName()), 'size': size, 'bits': 64, 'features': features,
                           'sites': sites, **({'forced': True} if forced is not None else {})})
    return {'functionsConsidered': considered, 'candidates': candidates, 'truncated': truncated}
