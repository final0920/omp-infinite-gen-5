"""Documented hardware-output decoding absent from the pinned Triton build.

RDTSCP: EDX:EAX=TSC, ECX=TSC_AUX[31:0], high halves cleared, flags unchanged.
Outputs remain external observations, never predicted timestamps. No memory or
ordering/serialization proof is provided by this instruction-semantics shim.
Intel SDM Vol.2B RDTSCP: https://cdrdv2-public.intel.com/782156/325383-sdm-vol-2abcd.pdf
"""


def process_instruction(context, instruction, tt):
    result = context.processing(instruction)
    if result != tt.EXCEPTION.NO_FAULT and instruction.getSize() == 3 and bytes(instruction.getOpcode()) == b'\x0f\x01\xf9':
        for name in ('rax', 'rdx', 'rcx'): context.setConcreteRegisterValue(getattr(context.registers, name), 0)
        context.setConcreteRegisterValue(context.registers.rip, instruction.getAddress() + 3)
        return tt.EXCEPTION.NO_FAULT, 'rdtscp-architectural-external-output'
    return result, None
