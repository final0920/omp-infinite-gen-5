"""AMD64 SDK byte-layout checks for read-only selected-thread observations."""
from pathlib import Path
import struct
import sys
import unittest
import ctypes
from types import SimpleNamespace
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'adapters/x64dbg'))
from native_thread_context import decode_context, debugger_visibility


class ThreadContextTests(unittest.TestCase):
    def test_control_integer_and_debug_registers_preserve_distinct_64bit_values(self):
        data = bytearray(1232)
        struct.pack_into('<I', data, 68, 0x246)
        debug = (0x7ff123abcdef1030, 0x7ff123abcdef2000, 3, 4, 0xffff0ff0, 0x401)
        struct.pack_into('<6Q', data, 72, *debug)
        integers = tuple(0x123456789abcdef0 + n for n in range(17))
        struct.pack_into('<17Q', data, 120, *integers)
        regs = decode_context(data)
        self.assertEqual(regs['rax'], hex(integers[0]))
        self.assertEqual(regs['rsp'], hex(integers[4]))
        self.assertEqual(regs['rip'], hex(integers[-1]))
        self.assertEqual(regs['eflags'], '0x246')
        for name, value in zip(('dr0', 'dr1', 'dr2', 'dr3', 'dr6', 'dr7'), debug): self.assertEqual(regs[name], hex(value))
        self.assertTrue(all(isinstance(value, str) for value in regs.values()))

    def test_partial_or_extra_context_is_rejected(self):
        for size in (0, 256, 1231, 1233):
            with self.assertRaisesRegex(ValueError, 'Incomplete'): decode_context(bytes(size))

    def test_hidden_thread_visibility_preserves_false_true_and_unavailable(self):
        class Query:
            def __init__(self, value, status): self.value, self.status, self.calls = value, status, []
            def __call__(self, handle, info, pointer, size, returned):
                self.calls.append((handle, info, size))
                ctypes.cast(pointer, ctypes.POINTER(ctypes.c_ubyte))[0] = self.value
                return self.status
        for value, status, expected in ((0, 0, False), (1, 0, True), (0, -1073741790, None), (2, 0, None)):
            query = Query(value, status)
            observed = debugger_visibility(17, SimpleNamespace(NtQueryInformationThread=query))
            self.assertIs(observed['hiddenFromDebugger'], expected)
            self.assertEqual(observed['querySucceeded'], expected is not None)
            self.assertEqual(observed['ntStatus'], hex(status & 0xffffffff))
            self.assertFalse(observed['threadModified'])
            self.assertEqual(query.calls, [(17, 0x11, 1)])


if __name__ == '__main__': unittest.main(verbosity=2)
