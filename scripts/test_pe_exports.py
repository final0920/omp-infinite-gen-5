import struct
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'adapters' / 'ghidra'))
from pe_exports import pe_exports


def fixture(magic=0x10b):
    data = bytearray(4096)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<H', data, 0x94, 240)
    struct.pack_into('<H', data, 0x98, magic)
    dd = 0x98 + (96 if magic == 0x10b else 112)
    struct.pack_into('<III', data, dd - 4, 16, 0x200, 0x100)
    struct.pack_into('<10I', data, 0x200, 0, 0, 0, 0, 7, 3, 2, 0x240, 0x250, 0x260)
    struct.pack_into('<III', data, 0x240, 0x500, 0x280, 0)
    struct.pack_into('<II', data, 0x250, 0x270, 0x278)
    struct.pack_into('<HH', data, 0x260, 0, 1)
    data[0x270:0x275] = b'Hook\0'
    data[0x278:0x27e] = b'Alias\0'
    data[0x280:0x28d] = b'KERNEL32.Foo\0'
    return data, dd


class ExportsTest(unittest.TestCase):
    def parse(self, data):
        return pe_exports(lambda r, n: data[r:r+n], 0x140000000)

    def test_pe32_and_64_exports_not_entries(self):
        for magic in [0x10b, 0x20b]:
            data, _ = fixture(magic)
            value = self.parse(data)
            self.assertEqual(len(value['rows']), 2)
            self.assertEqual(value['rows'][0]['ordinal'], 7)
            self.assertEqual(value['rows'][0]['ea'], '0x140000500')
            self.assertEqual(value['rows'][1]['forwarder'], 'KERNEL32.Foo')
            self.assertNotIn('ea', value['rows'][1])
            self.assertFalse(value['partial'])

    def test_absent_exports_and_nonpe(self):
        data, dd = fixture()
        struct.pack_into('<II', data, dd, 0, 0)
        self.assertEqual(self.parse(data)['rows'], [])
        self.assertFalse(self.parse(b'ELF')['supported'])

    def test_invalid_names_retained_as_partial(self):
        data, _ = fixture()
        data[0x270] = 255
        value = self.parse(data)
        self.assertTrue(value['partial'])
        self.assertEqual(value['rows'][0]['name'], None)
        self.assertEqual(len(value['rows']), 2)

    def test_bad_ordinal_and_budget(self):
        data, _ = fixture()
        struct.pack_into('<H', data, 0x260, 50)
        self.assertTrue(self.parse(data)['partial'])
        struct.pack_into('<I', data, 0x214, 8193)
        with self.assertRaisesRegex(ValueError, 'budget'):
            self.parse(data)


if __name__ == '__main__':
    unittest.main()
