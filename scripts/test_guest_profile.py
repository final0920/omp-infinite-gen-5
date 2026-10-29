"""Real stable-file snapshots, including copied Windows creation/write times."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'adapters/vmci'))
from guest_profile import stable_read, load_profile

class ProfileTests(unittest.TestCase):
    def test_copied_file_with_different_creation_write_times_is_stable(self):
        with tempfile.TemporaryDirectory(prefix='ig5-guest-snapshot-') as root:
            source = Path(root) / 'source.bin'; copy = Path(root) / 'copy.bin'
            source.write_bytes(b'bounded snapshot'); os.utime(source, (1000000000, 1000000000)); shutil.copy2(source, copy)
            self.assertEqual(stable_read(copy, 64), b'bounded snapshot')
            with self.assertRaises(ValueError): stable_read(copy, 2)
            with self.assertRaises(ValueError): stable_read('relative.bin', 64)

    def test_profile_snapshot_binds_key_catalog_and_exact_file_bytes(self):
        with tempfile.TemporaryDirectory(prefix='ig5-guest-profile-') as root:
            key = Path(root) / 'test.key'; key.write_bytes(os.urandom(32))
            profile = {'schema': 'ig5-vmci-guest-profile-v1', 'guestCID': 112233, 'port': 48561, 'guestLabel': 'test',
                'bundleSha256': 'a'*64, 'pairingKeyRef': {'path': str(key), 'sha256': hashlib.sha256(key.read_bytes()).hexdigest()},
                'targets': [{'id': 'owned', 'sha256': 'b'*64}]}
            file = Path(root) / 'profile.json'; file.write_text(json.dumps(profile), encoding='utf-8')
            sha = hashlib.sha256(file.read_bytes()).hexdigest()
            observed, material = load_profile(file, sha)
            self.assertEqual(observed, profile); self.assertEqual(material, key.read_bytes())
            file.write_bytes(file.read_bytes()+b' ')
            with self.assertRaisesRegex(ValueError, 'digest changed'): load_profile(file, sha)
            sha = hashlib.sha256(file.read_bytes()).hexdigest(); key.write_bytes(os.urandom(32))
            with self.assertRaisesRegex(ValueError, 'key differs'): load_profile(file, sha)

if __name__ == '__main__': unittest.main(verbosity=2)
