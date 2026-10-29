"""Independent formula oracle for the saved context0 fixed path.

The equations below were derived from the ordered native instruction listing,
not from a product DAG. No product/decoder imports or native execution occur.
Any total, deterministic byte memory callable is accepted, with no restriction
on aliasing among RSI, RSP, RBP, the selector byte, and the eight-byte regions.
"""

MASK = (1 << 64) - 1
NAMES = 'rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15'.split()
TAKEN = 0x140052124
FALLTHROUGH = 0x140052162


def context0_cases():
    """Independent boundary/alias/random states; never imports the raw interpreter."""
    import random
    rng = random.Random(0x43545830)
    edges = [0, 1, 7, 8, 255, 256, 0xffff, 0xffffffff, 1 << 32, (1 << 63) - 1, 1 << 63, MASK - 7, MASK]
    for n in range(len(edges)):
        yield 'boundary-' + str(n), {name: edges[(i + n) % len(edges)] for i, name in enumerate(NAMES)}, rng.getrandbits(64), {}
    for n in range(256):
        registers = {name: rng.getrandbits(64) for name in NAMES}
        if n % 4 == 0:
            registers['r15'] &= MASK ^ 0xffff
        yield 'random-' + str(n), registers, rng.getrandbits(64), {}
    for base in (0, 1, MASK - 7, MASK):
        for selector in (0, 1, 127, 255):
            source = (base + selector) & MASK
            for delta in range(-7, 8):
                for selector_position in (-16, 0, 7):
                    registers = {name: rng.getrandbits(64) for name in NAMES}
                    registers.update(rsp=base, rsi=(source + selector_position) & MASK,
                                     rbp=(source + delta + 8) & MASK)
                    yield 'alias-%x-%x-%d-%d' % (base, selector, delta, selector_position), registers, rng.getrandbits(64), {registers['rsi']: selector}
    for threshold in (0, 1, 1 << 63, MASK - 1, MASK):
        for delta in (-1, 0, 1):
            registers = {name: rng.getrandbits(64) for name in NAMES}
            registers.update(rsp=(threshold - 0x180) & MASK, rbp=(threshold + delta + 8) & MASK)
            yield 'branch-%x-%d' % (threshold, delta), registers, rng.getrandbits(64), {}


def expected(initial, initial_byte):
    assert set(initial) == set(NAMES)
    assert all(type(v) is int and 0 <= v <= MASK for v in initial.values())
    def byte(address):
        value = initial_byte(address & MASK)
        assert type(value) is int and 0 <= value <= 255
        return value
    # MOVZX EDX, byte[RSI] also clears the upper32 of RDX.
    selector = byte(initial['rsi'])
    # Both reads precede the single store, including when the addresses alias.
    source = (initial['rsp'] + selector) & MASK
    loaded = sum(byte(source + n) << (8 * n) for n in range(8))
    destination = (initial['rbp'] - 8) & MASK
    threshold = (initial['rsp'] + 0x180) & MASK
    outputs = {**initial, 'rdx': selector, 'rsi': (initial['rsi'] + 1) & MASK,
               'rbp': destination, 'r8': threshold, 'r9': loaded}
    writes = {(destination + n) & MASK: (loaded >> (8 * n)) & 255 for n in range(8)}
    return {
        'registers': outputs,
        'stores': [{'instructionIndex': 7, 'pcodeIndex': 2, 'address': destination, 'value': loaded, 'size': 8}],
        'memoryWrites': writes,
        'control': {'kind': 'conditional', 'condition': int(destination > threshold),
                    'taken': TAKEN, 'fallthrough': FALLTHROUGH},
        'reads': [{'address': initial['rsi'], 'size': 1}, {'address': source, 'size': 8}],
    }


def total_byte(seed, overrides=None):
    """Deterministic total test memory, not a program-state assumption."""
    overrides = dict(overrides or {})
    def read(address):
        address &= MASK
        if address in overrides:
            return overrides[address]
        mixed = (address ^ seed) & MASK
        mixed = ((mixed ^ (mixed >> 30)) * 0xbf58476d1ce4e5b9) & MASK
        mixed = ((mixed ^ (mixed >> 27)) * 0x94d049bb133111eb) & MASK
        return (mixed ^ (mixed >> 31)) & 255
    return read


def projection_values(report, registers, initial_byte, *, unknowns=None):
    """Numerically evaluate serialized DAGs against total byte memory.

    This evaluator does not infer any expected result from the DAG. Memory
    nodes are (initial callable, finite overlay), so all addresses stay defined.
    """
    values = []
    def signed(value, bits):
        return value - (1 << bits) if value & (1 << (bits - 1)) else value
    for index, node in enumerate(report['dag']['nodes']):
        assert node['id'] == index and all(0 <= n < index for n in node['args'])
        args = [values[n] for n in node['args']]
        widths = [report['dag']['nodes'][n].get('bits') for n in node['args']]
        kind, bits = node['op'], node.get('bits')
        if kind == 'input':
            value = registers[node['name']]
        elif kind == 'nondeterministic':
            assert unknowns is not None and node['name'] in unknowns
            value = unknowns[node['name']]
            assert type(value) is int and 0 <= value < (1 << bits)
        elif kind == 'const':
            value = int(node['value'], 16)
        elif kind == 'initial_memory':
            value = (initial_byte, {})
        elif kind == 'state_binding':
            # Serialized definitional equality; never allocate a new input.
            assert 0 <= node['source'] < index and not node['args']
            value = values[node['source']]
        elif kind == 'store_le':
            original, overlay = args[0]
            overlay = dict(overlay)
            for n in range(node['size']):
                overlay[(args[1] + n) & MASK] = (args[2] >> (8 * n)) & 255
            value = (original, overlay)
        elif kind == 'load_le':
            original, overlay = args[0]
            value = 0
            for n in range(node['size']):
                address = (args[1] + n) & MASK
                value |= (overlay[address] if address in overlay else original(address)) << (8 * n)
        elif kind == 'extract':
            value = args[0] >> node['offset']
        elif kind == 'concat':
            value = 0
            for item, width in zip(args, widths):
                value = (value << width) | item
        elif kind == 'INT_ADD':
            value = args[0] + args[1]
        elif kind == 'INT_SUB':
            value = args[0] - args[1]
        elif kind == 'INT_MULT':
            value = args[0] * args[1]
        elif kind == 'INT_REM':
            assert args[1] != 0
            value = args[0] % args[1]
        elif kind == 'INT_AND':
            value = args[0] & args[1]
        elif kind == 'INT_OR':
            value = args[0] | args[1]
        elif kind == 'INT_XOR':
            value = args[0] ^ args[1]
        elif kind == 'INT_NEGATE':
            value = ~args[0]
        elif kind == 'INT_2COMP':
            value = -args[0]
        elif kind == 'INT_ZEXT':
            value = args[0]
        elif kind == 'INT_SEXT':
            value = signed(args[0], widths[0])
        elif kind in ('INT_LEFT', 'INT_RIGHT', 'INT_SRIGHT'):
            if args[1] >= widths[0]:
                value = -1 if kind == 'INT_SRIGHT' and signed(args[0], widths[0]) < 0 else 0
            elif kind == 'INT_LEFT':
                value = args[0] << args[1]
            elif kind == 'INT_RIGHT':
                value = args[0] >> args[1]
            else:
                value = signed(args[0], widths[0]) >> args[1]
        elif kind in ('POPCOUNT', 'LZCOUNT'):
            value = args[0].bit_count() if kind == 'POPCOUNT' else widths[0] - args[0].bit_length()
        elif kind in ('INT_EQUAL', 'INT_NOTEQUAL', 'INT_LESS', 'INT_LESSEQUAL', 'INT_SLESS', 'INT_SLESSEQUAL'):
            a, b = args
            if kind in ('INT_SLESS', 'INT_SLESSEQUAL'):
                a, b = signed(a, widths[0]), signed(b, widths[1])
            value = int(a == b if kind == 'INT_EQUAL' else a != b if kind == 'INT_NOTEQUAL'
                        else a <= b if kind.endswith('LESSEQUAL') else a < b)
        elif kind in ('INT_CARRY', 'INT_SCARRY', 'INT_SBORROW'):
            if kind == 'INT_CARRY':
                value = int(args[0] + args[1] >= 1 << widths[0])
            else:
                a, b = signed(args[0], widths[0]), signed(args[1], widths[1])
                result = a - b if kind == 'INT_SBORROW' else a + b
                value = int(not -(1 << (widths[0] - 1)) <= result < 1 << (widths[0] - 1))
        elif kind in ('BOOL_NEGATE', 'BOOL_AND', 'BOOL_OR', 'BOOL_XOR'):
            a, b = args[0] != 0, len(args) > 1 and args[1] != 0
            value = int(not a if kind == 'BOOL_NEGATE' else a and b if kind == 'BOOL_AND'
                        else a or b if kind == 'BOOL_OR' else a != b)
        else:
            raise AssertionError('Unsupported DAG operation: ' + kind)
        values.append(value & ((1 << bits) - 1) if bits is not None else value)
    return values


def compare_projection(report, initial, initial_byte):
    wanted = expected(initial, initial_byte)
    values = projection_values(report, initial, initial_byte)
    assert set(report['registers']) == set(NAMES), 'Oracle requires all16 output registers'
    assert {name: values[index] for name, index in report['registers'].items()} == wanted['registers']
    actual_stores = [{key: row[key] for key in ('instructionIndex', 'pcodeIndex', 'size')} |
                     {'address': values[row['address']], 'value': values[row['value']]}
                     for row in report['stores']]
    assert actual_stores == wanted['stores']
    assert values[report['initialMemory']][1] == {}
    assert values[report['stores'][0]['beforeMemory']][1] == {}
    assert values[report['stores'][0]['afterMemory']][1] == wanted['memoryWrites']
    assert values[report['currentMemory']][1] == wanted['memoryWrites']
    actual_control = {'kind': report['control']['kind']} | {
        key: values[report['control'][key]] for key in ('condition', 'taken', 'fallthrough')}
    assert actual_control == wanted['control']
    assert all(report[key] is False for key in ('nativeTargetExecuted', 'databaseModified', 'businessAccepted', 'wholeBinaryVerified'))
    return wanted
