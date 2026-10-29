"""Complete byte-bound register CMOV shape, only for a dead destination frame.

No live conditional result is modeled. The same reverse planner must establish
that every destination byte is dead at all observable roots. Status flags are
preserved, not defined by this recognizer. Memory-source forms are rejected.
"""
from projection_bsr import GPR_OFFSETS, BsrRejected, normalized_var, operation, var


class CmovRejected(BsrRejected):
    pass


def require(condition, message):
    if not condition:
        raise CmovRejected(message)


def match_cmov_structure(instruction, check=lambda: None):
    require(type(instruction) is dict, 'Invalid CMOV instruction')
    raw, size, ea = instruction.get('codeBytes'), instruction.get('size'), instruction.get('ea')
    require(type(raw) is str and type(size) is int and 3 <= size <= 5
            and len(raw) == size * 2 and all(c in '0123456789abcdefABCDEF' for c in raw),
            'Missing or invalid CMOV bound bytes')
    require(type(ea) is str and ea.startswith('0x') and 1 <= len(ea[2:]) <= 16
            and all(c in '0123456789abcdefABCDEF' for c in ea[2:]), 'Invalid CMOV address')
    code, index, operand16, rex = bytes.fromhex(raw), 0, False, 0
    if code[index] == 0x66:
        operand16, index = True, index + 1
    if index < len(code) and 0x40 <= code[index] <= 0x4f:
        rex, index = code[index], index + 1
    require(not (operand16 and rex & 8), 'Redundant CMOV width prefixes unsupported')
    require(len(code) - index == 3 and code[index] == 0x0f
            and 0x40 <= code[index + 1] <= 0x4f and code[index + 2] >> 6 == 3,
            'Only bound register-source CMOV encoding is supported')
    condition, modrm = code[index + 1] & 15, code[index + 2]
    names = ('O', 'NO', 'C', 'NC', 'Z', 'NZ', 'BE', 'A', 'S', 'NS', 'P', 'NP', 'L', 'GE', 'LE', 'G')
    require(instruction.get('mnemonic') == 'CMOV' + names[condition], 'CMOV condition/mnemonic mismatch')
    width = 8 if rex & 8 else 2 if operand16 else 4
    destination = GPR_OFFSETS[((modrm >> 3) & 7) | ((rex & 4) << 1)]
    source = GPR_OFFSETS[(modrm & 7) | ((rex & 1) << 3)]
    pcode = instruction.get('pcode')
    require(type(pcode) is list and 4 <= len(pcode) <= 8, 'Unexpected CMOV complete p-code size')
    ops = []
    for op in pcode:
        check()
        require(type(op) is dict and type(op.get('opcode')) is str
                and type(op.get('inputs')) is list and len(op['inputs']) <= 2,
                'Invalid CMOV p-code operation')
        def normalize(v):
            if type(v) is dict and v.get('space') == 'ram':
                require(v.get('size') == 8 and type(v.get('offset')) is str
                        and v['offset'].startswith('0x') and 1 <= len(v['offset'][2:]) <= 16
                        and all(c in '0123456789abcdefABCDEF' for c in v['offset'][2:]),
                        'Invalid CMOV fallthrough target')
                return var('ram', int(v['offset'], 16), 8)
            return normalized_var(v)
        ops.append(operation(op['opcode'], normalize(op['output']) if op.get('output') is not None else None,
                             *(normalize(v) for v in op['inputs'])))
    cursor, occupied = 0, set()
    def take(kind, *inputs, out=None, temporary_size=None):
        nonlocal cursor
        check()
        require(cursor < len(ops), 'Incomplete CMOV shape')
        actual = ops[cursor]
        if temporary_size is not None:
            out = actual['output']
            require(out is not None and out['space'] == 'unique' and out['size'] == temporary_size,
                    'Invalid CMOV temporary role')
            locations = set(range(out['offset'], out['offset'] + out['size']))
            require(not occupied & locations, 'Overlapping CMOV temporary roles')
            occupied.update(locations)
        require(actual == operation(kind, out, *inputs), 'CMOV p-code is not the complete recognized acyclic shape')
        cursor += 1
        return out
    f = lambda offset: var('register', offset, 1)
    cf, pf, zf, sf, of = (f(o) for o in (0x200, 0x202, 0x206, 0x207, 0x20b))
    boolean = lambda kind, *inputs: take(kind, *inputs, temporary_size=1)
    direct = {0: of, 2: cf, 4: zf, 8: sf, 10: pf}
    if condition in direct:
        cc = direct[condition]
    elif condition in (1, 3, 5, 9, 11):
        cc = boolean('BOOL_NEGATE', direct[condition - 1])
    elif condition in (6, 7):
        cc = boolean('BOOL_OR', cf, zf)
        if condition == 7:
            cc = boolean('BOOL_NEGATE', cc)
    elif condition in (12, 13):
        cc = boolean('INT_NOTEQUAL' if condition == 12 else 'INT_EQUAL', of, sf)
    elif condition == 14:
        cc = boolean('BOOL_OR', zf, boolean('INT_NOTEQUAL', of, sf))
    else:
        not_zf = boolean('BOOL_NEGATE', zf)
        cc = boolean('BOOL_AND', not_zf, boolean('INT_EQUAL', of, sf))
    source_copy = take('COPY', var('register', source, width), temporary_size=width)
    # The pinned x64 SLEIGH clears upper32 before testing the condition. This
    # entire full64 destination frame must be dead, including false-condition
    # upper32 writes and self-source copies captured before this extension.
    if width == 4:
        take('INT_ZEXT', var('register', destination, 4), out=var('register', destination, 8))
    skip = boolean('BOOL_NEGATE', cc)
    target = int(ea, 16) + size
    require(target <= (1 << 64) - 1, 'CMOV fallthrough exceeds uint64')
    branch_index = cursor
    take('CBRANCH', var('ram', target, 8), skip)
    take('COPY', source_copy, out=var('register', destination, width))
    require(cursor == len(ops), 'Unexpected CMOV trailing effect')
    destination_size = 8 if width == 4 else width
    return {'kind': 'register-cmov-acyclic-dead-frame-v1', 'operandBits': width * 8,
            'conditionCode': condition, 'sourceOffset': source, 'destinationOffset': destination,
            'destinationBytes': destination_size, 'frameRegisterBytes': list(range(destination, destination + destination_size)),
            'rawOperationCount': len(ops), 'internalControlOperationCount': 1,
            'fallthroughBranchIndex': branch_index, 'fallthroughAddress': hex(target),
            'maximumBackedges': 0, 'maximumPcodeSteps': len(ops),
            'allInputTermination': 'acyclic-shape-argument-not-SMT', 'modeledMemoryEffects': 0,
            'statusFlagsPreserved': True, 'architectureProved': False}
