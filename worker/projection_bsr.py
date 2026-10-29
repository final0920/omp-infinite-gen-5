"""Finite raw-pcode BSR shape recognizer for the internal projection planner.

No execution, decoder, solver, filesystem or process operations. The caller
must bind a raw decoded instruction and codeBytes to one immutable byte slice.
This recognizes one complete register-source SLEIGH CFG, not generic loops.
"""

GPR_OFFSETS = (0, 8, 16, 24, 32, 40, 48, 56, 128, 136, 144, 152, 160, 168, 176, 184)
FLAG_OFFSETS = (0x200, 0x202, 0x204, 0x206, 0x207, 0x20b)


class BsrRejected(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise BsrRejected(message)


def var(space, offset, size):
    return {'space': space, 'offset': offset, 'size': size}


def operation(opcode, output, *inputs):
    return {'opcode': opcode, 'output': output, 'inputs': list(inputs)}


def normalized_var(value):
    require(type(value) is dict, 'Invalid BSR varnode')
    space, size, offset = value.get('space'), value.get('size'), value.get('offset')
    require(type(space) is str and space in ('register', 'unique', 'const'), 'Unsupported BSR varnode space')
    require(type(size) is int and 1 <= size <= 8, 'Invalid BSR varnode width')
    require(type(offset) is str and 3 <= len(offset) <= 18 and offset.startswith('0x')
            and all(c in '0123456789abcdefABCDEF' for c in offset[2:]), 'Invalid BSR varnode offset')
    offset = int(offset, 16)
    require(offset < 1 << (size * 8) if space == 'const' else offset + size <= 1 << 64,
            'BSR varnode out of range')
    return var(space, offset, size)


def match_bsr_structure(instruction, check=lambda: None):
    """Return a complete effect-frame descriptor or reject, never partial match.

    Intended only as the finite alternative to existing rejection of internal
    raw p-code branches. A match does not itself permit dropping the operation:
    the same planner must check its own reverse byte liveness at the exit.
    This function never accepts a caller-provided effect summary or certificate.
    """
    require(type(instruction) is dict, 'Invalid BSR instruction')
    raw, size = instruction.get('codeBytes'), instruction.get('size')
    require(type(raw) is str and type(size) is int and 3 <= size <= 5
            and len(raw) == size * 2 and all(c in '0123456789abcdefABCDEF' for c in raw),
            'Missing or invalid BSR bound bytes')
    code, index, operand16, rex = bytes.fromhex(raw), 0, False, 0
    if code[index] == 0x66:
        operand16, index = True, index + 1
    if index < len(code) and 0x40 <= code[index] <= 0x4f:
        rex, index = code[index], index + 1
    require(not (operand16 and rex & 8), 'Redundant BSR width prefixes unsupported')
    require(len(code) - index == 3 and code[index:index + 2] == b'\x0f\xbd'
            and code[index + 2] >> 6 == 3 and instruction.get('mnemonic') == 'BSR',
            'Only bound register-source BSR encoding is supported')
    width = 8 if rex & 8 else 2 if operand16 else 4
    modrm = code[index + 2]
    destination = GPR_OFFSETS[((modrm >> 3) & 7) | ((rex & 4) << 1)]
    source = GPR_OFFSETS[(modrm & 7) | ((rex & 1) << 3)]
    raw_ops = instruction.get('pcode')
    require(type(raw_ops) is list and len(raw_ops) == (11 if width == 4 else 10),
            'Unexpected BSR complete p-code size')
    ops = []
    for raw_op in raw_ops:
        check()
        require(type(raw_op) is dict and type(raw_op.get('opcode')) is str
                and type(raw_op.get('inputs')) is list and len(raw_op['inputs']) <= 2,
                'Invalid BSR p-code operation')
        ops.append(operation(raw_op['opcode'], normalized_var(raw_op['output']) if raw_op.get('output') is not None else None,
                             *(normalized_var(v) for v in raw_op['inputs'])))
    temporaries = [ops[i]['output'] for i in (0, 2, 4, 5)]
    occupied = set()
    for temp, expected_size in zip(temporaries, (width, 1, width, 1)):
        require(temp is not None and temp['space'] == 'unique' and temp['size'] == expected_size,
                'Invalid BSR temporary role')
        locations = set(range(temp['offset'], temp['offset'] + temp['size']))
        require(not occupied & locations, 'Overlapping BSR unique temporary roles')
        occupied |= locations
    counter, zero_test, shifted, nonzero_test = temporaries
    reg_source, reg_destination = var('register', source, width), var('register', destination, width)
    zf = var('register', 0x206, 1)
    const = lambda n, w: var('const', n, w)
    expected = [
        operation('COPY', counter, const(width * 8 - 1, width)),
        operation('INT_EQUAL', zf, reg_source, const(0, width)),
        operation('INT_EQUAL', zero_test, zf, const(1, 1)),
        operation('CBRANCH', None, const(6, 4), zero_test),
        operation('INT_RIGHT', shifted, reg_source, counter),
        operation('INT_NOTEQUAL', nonzero_test, shifted, const(0, width)),
        operation('CBRANCH', None, const(3, 4), nonzero_test),
        operation('INT_SUB', counter, counter, const(1, width)),
        operation('BRANCH', None, const(0xfffffffc, 4)),
        operation('COPY', reg_destination, counter),
    ]
    if width == 4:
        expected.append(operation('INT_ZEXT', var('register', destination, 8), reg_destination))
    require(ops == expected, 'BSR p-code is not the complete recognized bounded CFG')
    # The only register writes are the final destination and ZF. Architecture
    # additionally makes the five other status flags undefined. All are in the
    # frame, even when the raw p-code simply retains their previous values.
    destination_size = 8 if width == 4 else width
    frame = sorted(set(range(destination, destination + destination_size)) | set(FLAG_OFFSETS))
    return {
        'kind': 'register-bsr-bounded-dead-frame-v1', 'operandBits': width * 8,
        'sourceOffset': source, 'destinationOffset': destination, 'destinationBytes': destination_size,
        'frameRegisterBytes': frame, 'rawOperationCount': len(ops),
        'internalEdges': [[3, 9], [6, 9], [8, 4]], 'maximumBackedges': width * 8 - 1,
        'maximumPcodeSteps': 5 * (width * 8 - 1) + 8 + (1 if width == 4 else 0),
        'zeroInputRawDestination': width * 8 - 1, 'zeroInputArchitecturalDestination': 'undefined',
        'allInputTermination': 'finite-shape-argument-not-SMT',
        'modeledMemoryEffects': 0, 'architectureProved': False,
    }
