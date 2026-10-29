"""Deterministic, data-only dependency admission; no DLL is loaded."""
import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('ig5_prepare_test', Path(__file__).with_name('prepare_guest_debug.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class Dependencies(unittest.TestCase):
    def test_legacy_empty_and_nonlist(self):
        self.assertEqual(module.dependency_files({}, 0x8664), {})
        for value in (None, {}, [None]*17):
            with self.assertRaises(ValueError): module.dependency_files({'dependencies': value}, 0x8664)

    def test_hash_arch_dll_names_and_traversal(self):
        with tempfile.TemporaryDirectory(prefix='ig5-dependencies-') as directory:
            file = Path(directory).resolve() / 'runtime.dll'
            data = bytearray(128); data[:2] = b'MZ'; struct.pack_into('<I', data, 60, 64)
            data[64:68] = b'PE\0\0'; struct.pack_into('<H', data, 68, 0x8664); struct.pack_into('<H', data, 86, 0x2000)
            file.write_bytes(data)
            dep = {'name': file.name, 'path': str(file), 'sha256': hashlib.sha256(data).hexdigest()}
            row = {'dependencies':[dep]}
            self.assertEqual(module.dependency_files(row, 0x8664), {'runtime.dll': bytes(data)})
            for changed in ({'name':'../runtime.dll'}, {'name':'runtime.exe'}, {'name':'renamed.dll'}, {'path':'relative.dll'}, {'sha256':'0'*64}, {'extra':True}):
                with self.assertRaises(ValueError): module.dependency_files({'dependencies':[{**dep, **changed}]}, 0x8664)
            with self.assertRaises(ValueError): module.dependency_files(row, 0x14c)
            with self.assertRaises(ValueError): module.dependency_files({'dependencies':[dep, {**dep,'name':'RUNTIME.DLL'}]},0x8664)
            struct.pack_into('<H',data,86,0); file.write_bytes(data)
            dep['sha256']=hashlib.sha256(data).hexdigest()
            with self.assertRaises(ValueError): module.dependency_files({'dependencies':[dep]},0x8664)

if __name__ == '__main__': unittest.main(verbosity=2)
