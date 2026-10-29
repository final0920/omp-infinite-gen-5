import struct
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'adapters' / 'ghidra'))
from elf_addresses import convert, parse_loads
from result_capture import captured_rows


class AddressContract(unittest.TestCase):
    def test_generated_calls_capture_does_not_lose_rows_to_display_limit(self):
        rows = [dict(ea=hex(0x1000 + i), name='f' + str(i), refs=1) for i in range(72)]
        self.assertEqual(len(captured_rows(rows, 32)), 32)
        self.assertEqual(captured_rows(rows, 32, 131072), rows)
        self.assertLess(len(captured_rows(rows, 32, 200)), 32)
        with self.assertRaisesRegex(ValueError, 'budget'):
            captured_rows(rows, 32, 131073)
    def setUp(self):
        self.loads = [dict(offset=0, vaddr=0x4000, filesz=0x100, memsz=0x200),
                      dict(offset=0x200, vaddr=0x8000, filesz=0x100, memsz=0x100)]
        self.sources = [dict(offset=0, start=0x104000, size=0x100),
                        dict(offset=0x200, start=0x208000, size=0x100)]

    def test_actual_ranges_and_nonuniform_rebase(self):
        for address in ('0x4000', '0x40ff', '0x8000', '0x80ff'):
            gva = convert(address, 'elf_vaddr', 'ghidra_va', self.loads, self.sources)
            self.assertEqual(convert(gva, 'ghidra_va', 'elf_vaddr', self.loads, self.sources), address)
        self.assertEqual(convert('0x8008', 'elf_vaddr', 'file_offset', self.loads, self.sources), '0x208')
        self.assertEqual(convert('0x8008', 'elf_vaddr', 'module_offset', self.loads, self.sources), '0x4008')
        self.assertEqual(convert('0x104008', 'ghidra_va', 'elf_vaddr', self.loads, self.sources), '0x4008')

    def test_bss_overlap_unknown_and_precision(self):
        with self.assertRaisesRegex(ValueError, 'NOT_FILE_BACKED'):
            convert('0x4100', 'elf_vaddr', 'file_offset', self.loads, self.sources)
        with self.assertRaisesRegex(ValueError, 'AMBIGUOUS'):
            convert('0x104008', 'ghidra_va', 'elf_vaddr', self.loads, self.sources * 2)
        with self.assertRaisesRegex(ValueError, 'RUNTIME_MAPPING_UNAVAILABLE'):
            convert('0x1000', 'runtime_va', 'elf_vaddr', self.loads, self.sources)
        with self.assertRaisesRegex(ValueError, 'UNMAPPED'):
            convert('0x4200', 'elf_vaddr', 'file_offset', self.loads, self.sources)
        large = [dict(offset=0, vaddr=0xfedcba9876540000, filesz=256, memsz=256)]
        self.assertEqual(convert('0xfedcba9876540008', 'elf_vaddr', 'file_offset', large, []), '0x8')
        with self.assertRaisesRegex(ValueError, 'OVERFLOW'):
            convert('0x10000000000000000', 'elf_vaddr', 'file_offset', large, [])

    def test_bounded_program_header_reader(self):
        image = bytearray(512)
        image[:16] = b'\x7fELF\x02\x01\x01' + b'\0' * 9
        struct.pack_into('<HHIQQQIHHHHHH', image, 16, 2, 62, 1, 0x400100, 64, 0, 0, 64, 56, 1, 0, 0, 0)
        struct.pack_into('<IIQQQQQQ', image, 64, 1, 5, 0, 0x400000, 0x400000, 512, 768, 4096)
        loads = parse_loads(lambda offset, size: image[offset:offset+size], len(image))
        self.assertEqual(loads, [dict(offset=0, vaddr=0x400000, filesz=512, memsz=768)])
        struct.pack_into('<Q', image, 64+32, 1024)
        with self.assertRaisesRegex(ValueError, 'INVALID'):
            parse_loads(lambda offset, size: image[offset:offset+size], len(image))


if __name__ == '__main__':
    unittest.main(verbosity=2)
