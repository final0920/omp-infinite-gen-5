"""Strict single-instruction continuations after a coalesced native CPUID stop.

No intermediate snapshot exists. Flags/NOP, non-output GPR ADD/SUB immediate,
and exact byte-register TEST or 16-bit-register CMP immediates are allowed.
No memory or branch.
"""


def cpuid_continuation(opcode):
    if opcode in (b'\xf8', b'\xf9', b'\xf5', b'\x90'):
        return {'kind': 'flags-or-nop', 'bytes': opcode.hex()}
    if len(opcode) == 3 and opcode[0] == 0xf6 and 0xc0 <= opcode[1] <= 0xc7:
        register = ('al', 'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh')[opcode[1] - 0xc0]
        return {'kind': 'byte-register-test', 'register': register, 'immediate': opcode[2], 'bytes': opcode.hex(),
                'definedFlags': ['CF', 'PF', 'ZF', 'SF', 'OF'], 'undefinedFlags': ['AF']}
    if len(opcode) == 5 and opcode[:2] == b'\x66\x81' and 0xf8 <= opcode[2] <= 0xff:
        register = ('ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di')[opcode[2] - 0xf8]
        return {'kind': 'word-register-compare', 'register': register, 'bits': 16,
                'immediate': int.from_bytes(opcode[3:], 'little'), 'bytes': opcode.hex(),
                'definedFlags': ['CF', 'PF', 'AF', 'ZF', 'SF', 'OF'], 'undefinedFlags': []}
    if len(opcode) not in (4, 7) or opcode[0] not in (0x48, 0x49): return None
    if (opcode[1], len(opcode)) not in ((0x83, 4), (0x81, 7)): return None
    modrm = opcode[2]
    if modrm >> 6 != 3 or (modrm >> 3) & 7 not in (0, 5): return None
    register = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
                'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'][(modrm & 7) + (8 if opcode[0] == 0x49 else 0)]
    if register in ('rax', 'rbx', 'rcx', 'rdx'): return None
    return {'kind': 'gpr-immediate', 'register': register, 'operation': 'add' if (modrm >> 3) & 7 == 0 else 'sub',
            'immediate': int.from_bytes(opcode[3:], 'little', signed=True), 'bytes': opcode.hex()}


def apply_native_continuation(context, instruction, tt, description, observed_flags):
    """Validate deterministic tails with defined high-byte PF and observed AF.

    This concrete recorder check never replaces input-dependent offline state;
    offline replay separately reconstructs symbolic flag semantics and proofs.
    """
    value = None
    if description['kind'] == 'byte-register-test':
        value = context.getConcreteRegisterValue(getattr(context.registers, description['register'])) & description['immediate']
    processed = context.processing(instruction)
    if processed == tt.EXCEPTION.NO_FAULT and value is not None:
        # Pinned decoder PF uses the preserved low parent byte for high-byte
        # operands. Intel TEST defines even parity from its actual result byte.
        context.setConcreteRegisterValue(context.registers.pf, 1 ^ (value.bit_count() & 1))
        context.setConcreteRegisterValue(context.registers.af, (observed_flags >> 4) & 1)
    return processed
