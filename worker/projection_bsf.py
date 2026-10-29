"""Recognize the complete fixed register-source BSF p-code CFG.

The caller binds bytes/decoder output and proves the entire destination and
six-status-flag frame dead in the same planner. This is not general loop
support or a model for live/zero-input architectural BSF outputs.
"""
from projection_bsr import (FLAG_OFFSETS, GPR_OFFSETS, BsrRejected,
                            normalized_var, operation, var)


class BsfRejected(BsrRejected):
    pass


def require(condition, message):
    if not condition:
        raise BsfRejected(message)


def normalize(value):
    try:
        return normalized_var(value)
    except BsrRejected as error:
        raise BsfRejected(str(error).replace('BSR', 'BSF')) from error


def match_bsf_structure(instruction, check=lambda: None):
    require(type(instruction) is dict, 'Invalid BSF instruction')
    raw, size = instruction.get('codeBytes'), instruction.get('size')
    require(type(raw) is str and type(size) is int and 3 <= size <= 5
            and len(raw) == size * 2 and all(c in '0123456789abcdefABCDEF' for c in raw),
            'Missing or invalid BSF bound bytes')
    code, index, operand16, rex = bytes.fromhex(raw), 0, False, 0
    if code[index] == 0x66:
        operand16, index = True, index + 1
    if index < len(code) and 0x40 <= code[index] <= 0x4f:
        rex, index = code[index], index + 1
    require(not (operand16 and rex & 8), 'Redundant BSF width prefixes unsupported')
    require(len(code) - index == 3 and code[index:index + 2] == b'\x0f\xbc'
            and code[index + 2] >> 6 == 3 and instruction.get('mnemonic') == 'BSF',
            'Only bound register-source BSF encoding is supported')
    width = 8 if rex & 8 else 2 if operand16 else 4
    modrm = code[index + 2]
    destination = GPR_OFFSETS[((modrm >> 3) & 7) | ((rex & 4) << 1)]
    source = GPR_OFFSETS[(modrm & 7) | ((rex & 1) << 3)]
    raw_ops = instruction.get('pcode')
    require(type(raw_ops) is list and len(raw_ops) == (12 if width == 4 else 11),
            'Unexpected BSF complete p-code size')
    ops = []
    for raw_op in raw_ops:
        check()
        require(type(raw_op) is dict and type(raw_op.get('opcode')) is str
                and type(raw_op.get('inputs')) is list and len(raw_op['inputs']) <= 2,
                'Invalid BSF p-code operation')
        ops.append(operation(raw_op['opcode'], normalize(raw_op['output']) if raw_op.get('output') is not None else None,
                             *(normalize(v) for v in raw_op['inputs'])))
    temporaries = [ops[i]['output'] for i in (0, 2, 4, 5, 6)]
    occupied = set()
    for temp, expected_size in zip(temporaries, (width, 1, width, width, 1)):
        require(temp is not None and temp['space'] == 'unique' and temp['size'] == expected_size,
                'Invalid BSF temporary role')
        locations = set(range(temp['offset'], temp['offset'] + temp['size']))
        require(not occupied & locations, 'Overlapping BSF unique temporary roles')
        occupied |= locations
    counter, zero_test, shifted, low_bit, nonzero_test = temporaries
    reg_source, reg_destination = var('register', source, width), var('register', destination, width)
    zf = var('register', 0x206, 1)
    const = lambda n, w: var('const', n, w)
    expected = [
        operation('COPY', counter, const(0, width)),
        operation('INT_EQUAL', zf, reg_source, const(0, width)),
        operation('INT_EQUAL', zero_test, zf, const(1, 1)),
        operation('CBRANCH', None, const(7, 4), zero_test),
        operation('INT_RIGHT', shifted, reg_source, counter),
        operation('INT_AND', low_bit, shifted, const(1, width)),
        operation('INT_NOTEQUAL', nonzero_test, low_bit, const(0, width)),
        operation('CBRANCH', None, const(3, 4), nonzero_test),
        operation('INT_ADD', counter, counter, const(1, width)),
        operation('BRANCH', None, const(0xfffffffb, 4)),
        operation('COPY', reg_destination, counter),
    ]
    if width == 4:
        expected.append(operation('INT_ZEXT', var('register', destination, 8), reg_destination))
    require(ops == expected, 'BSF p-code is not the complete recognized bounded CFG')
    destination_size = 8 if width == 4 else width
    frame = sorted(set(range(destination, destination + destination_size)) | set(FLAG_OFFSETS))
    return {
        'kind': 'register-bsf-bounded-dead-frame-v1', 'operandBits': width * 8,
        'sourceOffset': source, 'destinationOffset': destination, 'destinationBytes': destination_size,
        'frameRegisterBytes': frame, 'rawOperationCount': len(ops),
        'internalEdges': [[3, 10], [7, 10], [9, 4]], 'maximumBackedges': width * 8 - 1,
        'maximumPcodeSteps': 6 * (width * 8 - 1) + 9 + (1 if width == 4 else 0),
        'zeroInputRawDestination': 0, 'zeroInputArchitecturalDestination': 'undefined',
        'allInputTermination': 'finite-shape-argument-not-SMT',
        'modeledMemoryEffects': 0, 'architectureProved': False,
    }
