"""Conservative x64 status-flag barriers for fixed raw-pcode projection.

This is a small flag-effect classifier, not an instruction decoder. The caller
must obtain codeBytes and the decoded instruction from the same immutable byte
slice. Unknown encodings, mnemonic mismatches and missing metadata stay unknown.
No caller-supplied flag annotations or operand-text counts are consumed.
"""

FLAG_OFFSETS = {'cf': 0x200, 'pf': 0x202, 'af': 0x204, 'zf': 0x206, 'sf': 0x207, 'of': 0x20b}
_ALL = frozenset(FLAG_OFFSETS)
_ARITHMETIC = frozenset(('cf', 'pf', 'zf', 'sf', 'of'))
_JCC = frozenset(('JO', 'JNO', 'JB', 'JC', 'JNAE', 'JAE', 'JNB', 'JNC', 'JE', 'JZ', 'JNE', 'JNZ',
                  'JBE', 'JNA', 'JA', 'JNBE', 'JS', 'JNS', 'JP', 'JPE', 'JNP', 'JPO',
                  'JL', 'JNGE', 'JGE', 'JNL', 'JLE', 'JNG', 'JG', 'JNLE'))
_CONDITIONS = frozenset(name[1:] for name in _JCC)


def _encoding(instruction):
    raw = instruction.get('codeBytes')
    size = instruction.get('size')
    if (type(raw) is not str or type(size) is not int or not 1 <= size <= 15 or len(raw) != size * 2
            or any(char not in '0123456789abcdefABCDEF' for char in raw)):
        return None
    code = bytes.fromhex(raw)
    index, operand16, rex, seen = 0, False, 0, set()
    # Duplicate or conflicting prefixes are deliberately outside this classifier.
    while index < len(code):
        value = code[index]
        if value in (0x66, 0x67, 0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65):
            if value in seen or value in (0xf2, 0xf3) and seen & {0xf2, 0xf3}:
                return None
            seen.add(value)
            operand16 |= value == 0x66
            rex = 0  # A legacy prefix after REX makes that REX ineffective.
            index += 1
        elif 0x40 <= value <= 0x4f:
            if rex:
                return None
            rex = value
            index += 1
        else:
            break
    if index >= len(code):
        return None
    # REP/REPNZ reinterpret several opcode families. Do not guess their effects.
    if seen & {0xf2, 0xf3}:
        return None
    opcode = code[index]
    width = 64 if rex & 8 else 16 if operand16 else 32
    return code, index, opcode, width


def classify_flags(instruction, operations):
    """Return status-flag effect metadata; all lists contain lowercase names.

    ``operations`` are the fully validated raw p-code operations. A claimed
    defined flag absent from raw writes, or a write to a preserved flag, is an
    unmodeled effect. Architectural undefined flags remain barriers even when
    raw p-code happens to assign a concrete value.
    """
    unknown = {'status': 'unknown', 'family': 'unclassified', 'defined': [], 'preserved': [],
               'undefined': [], 'unmodeled': sorted(_ALL), 'encodedWidth': None, 'maskedCount': None}
    encoding = _encoding(instruction)
    if encoding is None:
        return {**unknown, 'reason': 'missing-or-unsupported-bound-code-bytes'}
    code, index, opcode, width = encoding
    name = instruction.get('mnemonic')
    if type(name) is not str:
        return {**unknown, 'reason': 'missing-decoded-mnemonic'}
    family, expected, defined, undefined, unmodeled = None, set(), set(), set(), set()
    count = None

    def select(label, mnemonics, outputs=(), undefined_flags=(), unmodeled_flags=()):
        nonlocal family, expected, defined, undefined, unmodeled
        family, expected = label, set(mnemonics)
        defined, undefined, unmodeled = set(outputs), set(undefined_flags), set(unmodeled_flags)

    group = (code[index + 1] >> 3) & 7 if index + 1 < len(code) else None
    # Integer arithmetic, including group-1 immediate forms.
    arithmetic = {0: 'ADD', 1: 'OR', 2: 'ADC', 3: 'SBB', 4: 'AND', 5: 'SUB', 6: 'XOR', 7: 'CMP'}
    operation = arithmetic.get(opcode >> 3) if opcode <= 0x3d and (opcode & 7) <= 5 else None
    if opcode in (0x80, 0x81, 0x83):
        operation = arithmetic.get(group)
    if operation:
        if opcode == 0x80 or opcode <= 0x3d and not opcode & 1:
            width = 8
        if operation in ('OR', 'AND', 'XOR'):
            select('logical', [operation], _ARITHMETIC, ['af'])
        else:
            select('arithmetic', [operation], _ARITHMETIC, unmodeled_flags=['af'])
    elif opcode in (0x84, 0x85, 0xa8, 0xa9) or opcode in (0xf6, 0xf7) and group == 0:
        if opcode in (0x84, 0xa8, 0xf6):
            width = 8
        select('logical', ['TEST'], _ARITHMETIC, ['af'])
    elif opcode in (0xfe, 0xff) and group in (0, 1):
        if opcode == 0xfe:
            width = 8
        select('increment-decrement', ['INC' if group == 0 else 'DEC'], _ARITHMETIC - {'cf'}, unmodeled_flags=['af'])
    elif opcode in (0xf6, 0xf7) and group == 3:
        if opcode == 0xf6:
            width = 8
        select('negate', ['NEG'], _ARITHMETIC, unmodeled_flags=['af'])
    elif opcode in (0xf6, 0xf7) and group in (4, 5):
        if opcode == 0xf6:
            width = 8
        select('multiply', ['MUL' if group == 4 else 'IMUL'], ['cf', 'of'], ['sf', 'zf', 'af', 'pf'])
    elif opcode in (0x69, 0x6b):
        select('multiply', ['IMUL'], ['cf', 'of'], ['sf', 'zf', 'af', 'pf'])
    elif opcode in (0xd0, 0xd1, 0xd2, 0xd3, 0xc0, 0xc1) and group in (0, 1, 4, 5, 6, 7):
        width = 8 if opcode in (0xd0, 0xd2, 0xc0) else width
        count = 1 if opcode in (0xd0, 0xd1) else code[-1] & (0x3f if width == 64 else 0x1f) if opcode in (0xc0, 0xc1) else None
        operation = {0: 'ROL', 1: 'ROR', 4: 'SHL', 5: 'SHR', 6: 'SHL', 7: 'SAR'}[group]
        mnemonics = ['SHL', 'SAL'] if operation == 'SHL' else [operation]
        if operation in ('ROL', 'ROR'):
            if count == 0:
                select('rotate-zero', mnemonics)
            elif count == 1:
                select('rotate-one', mnemonics, ['cf', 'of'])
            elif count is not None and count % width != 0:
                select('rotate-multiple', mnemonics, ['cf'], ['of'])
            else:
                # Modulo-width zero and variable counts need a more precise
                # decoder/architecture reconciliation before using CF or OF.
                select('rotate-unknown-count', mnemonics, undefined_flags=['of'], unmodeled_flags=['cf'])
        elif count == 0:
            select('shift-zero', mnemonics)
        elif count == 1:
            select('shift-one', mnemonics, _ARITHMETIC, ['af'])
        else:
            outputs = {'sf', 'zf', 'pf', 'cf'}
            uncertain = {'of', 'af'}
            if operation != 'SAR' and (count is not None and count >= width or count is None and width < 32):
                outputs.remove('cf')
                uncertain.add('cf')
            select('shift-variable' if count is None else 'shift-multiple', mnemonics, outputs, uncertain)
    elif opcode in (0xf8, 0xf9, 0xf5):
        select('carry-control', [{0xf8: 'CLC', 0xf9: 'STC', 0xf5: 'CMC'}[opcode]], ['cf'])
    elif opcode == 0x9e:
        select('store-status-flags', ['SAHF'], ['cf', 'pf', 'af', 'zf', 'sf'])
    elif opcode == 0x9f:
        select('load-status-flags', ['LAHF'])
    elif opcode in (0x88, 0x89, 0x8a, 0x8b, 0xa0, 0xa1, 0xa2, 0xa3) or 0xb0 <= opcode <= 0xbf or opcode in (0xc6, 0xc7) and group == 0:
        select('preserve', ['MOV'])
    elif opcode == 0x63:
        select('preserve', ['MOVSXD'])
    elif opcode == 0x8d:
        select('preserve', ['LEA'])
    elif opcode in (0x86, 0x87) or 0x91 <= opcode <= 0x97:
        select('preserve', ['XCHG'])
    elif opcode == 0x90:
        select('preserve', ['NOP', 'XCHG'])
    elif opcode in (0x98, 0x99):
        select('preserve', ['CBW', 'CWDE', 'CDQE', 'CWD', 'CDQ', 'CQO'])
    elif opcode in (0xf6, 0xf7) and group == 2:
        select('preserve', ['NOT'])
    elif 0x50 <= opcode <= 0x57 or opcode in (0x68, 0x6a) or opcode == 0xff and group == 6:
        select('preserve', ['PUSH'])
    elif 0x58 <= opcode <= 0x5f or opcode == 0x8f and group == 0:
        select('preserve', ['POP'])
    elif opcode in (0xc2, 0xc3):
        select('preserve', ['RET'])
    elif opcode==0xe8 and index==0 and len(code)==5:
        select('preserve',['CALL'])
    elif opcode in (0xe9, 0xeb) or opcode == 0xff and group == 4:
        select('preserve', ['JMP'])
    elif 0x70 <= opcode <= 0x7f:
        select('preserve', _JCC)
    elif opcode == 0xe3:
        select('preserve', ['JCXZ', 'JECXZ', 'JRCXZ'])
    elif opcode == 0x0f and index + 1 < len(code):
        second = code[index + 1]
        if second == 0xaf:
            select('multiply', ['IMUL'], ['cf', 'of'], ['sf', 'zf', 'af', 'pf'])
        elif second in (0xb6, 0xb7):
            select('preserve', ['MOVZX'])
        elif second in (0xbe, 0xbf):
            select('preserve', ['MOVSX'])
        elif 0x80 <= second <= 0x8f:
            select('preserve', _JCC)
        elif 0x40 <= second <= 0x4f:
            select('preserve', ['CMOV' + value for value in _CONDITIONS])
        elif 0x90 <= second <= 0x9f:
            select('preserve', ['SET' + value for value in _CONDITIONS])
        elif 0xc8 <= second <= 0xcf:
            select('preserve', ['BSWAP'])
        elif second == 0x1f:
            select('preserve', ['NOP'])
    if family is None or name not in expected:
        return {**unknown, 'reason': 'unsupported-encoding-or-mnemonic-mismatch', 'codeBytes': code.hex()}
    # The pinned SLEIGH shrflags macro differs from the implicit-one form:
    # explicit/CL shifts assign OF=0 for count==1 and old-MSB otherwise. This
    # also fails to preserve OF for count==0. Never certify that OF as modeled.
    if name == 'SHR' and opcode in (0xc0, 0xc1, 0xd2, 0xd3):
        defined.discard('of')
        unmodeled.add('of')
    written = {flag for operation in operations if operation.get('output')
               for flag, offset in FLAG_OFFSETS.items()
               if operation['output']['space'] == 'register'
               and operation['output']['offset'] <= offset < operation['output']['offset'] + operation['output']['size']}
    preserved = set(_ALL) - defined - undefined - unmodeled
    unmodeled |= defined - written
    # Zero-count raw SLEIGH uses conditional assignments to preserve flags.
    # Its writes are allowed here only because exact zero is bound to the bytes.
    if family not in ('shift-zero', 'rotate-zero'):
        unmodeled |= preserved & written
    defined -= unmodeled
    preserved -= unmodeled
    return {'status': 'classified', 'family': family, 'defined': sorted(defined),
            'preserved': sorted(preserved), 'undefined': sorted(undefined), 'unmodeled': sorted(unmodeled),
            'encodedWidth': width, 'maskedCount': count, 'codeBytes': code.hex()}
