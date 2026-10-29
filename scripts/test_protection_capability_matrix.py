"""Verify consistency, integrity and boundaries of protection_capability_matrix.json."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / 'scripts' / 'fixtures' / 'protection_capability_matrix.json'


class ProtectionCapabilityMatrixTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(MATRIX_PATH.is_file(), f"Matrix file missing: {MATRIX_PATH}")
        with open(MATRIX_PATH, 'r', encoding='utf-8') as f:
            self.matrix = json.load(f)

    def test_schema_and_version(self):
        self.assertEqual(self.matrix.get('schema'), 'ig5/protection-capability-matrix-v1')
        self.assertEqual(self.matrix.get('version'), 1)
        self.assertIn('statusLabels', self.matrix)
        self.assertIn('strengthLabels', self.matrix)

    def test_vmp38_boundary_integrity(self):
        vmp38 = next((p for p in self.matrix['protectors'] if p['id'] == 'vmp-3.8.x'), None)
        self.assertIsNotNone(vmp38, "VMP 3.8 entry missing from matrix")
        self.assertFalse(vmp38['exactVersionVerified'])
        self.assertEqual(vmp38['qualifiedSampleCount'], 0)
        for cap in vmp38['capabilities']:
            self.assertFalse(cap['businessRecovery'], f"VMP 3.8 cannot claim business recovery: {cap['capabilityId']}")
            self.assertIn(cap['status'], ('unverified', 'partial', 'blocked'))

    def test_enigma_and_themida_boundaries(self):
        enigma = next((p for p in self.matrix['protectors'] if p['id'] == 'enigma-7.80-demo'), None)
        self.assertIsNotNone(enigma)
        for cap in enigma['capabilities']:
            self.assertFalse(cap['businessRecovery'], "Enigma cannot claim business recovery while guards remain unresolved")

        themida = next((p for p in self.matrix['protectors'] if p['id'] == 'themida-3.2.4.34-demo'), None)
        self.assertIsNotNone(themida)
        for cap in themida['capabilities']:
            self.assertEqual(cap['status'], 'blocked')
            self.assertFalse(cap['businessRecovery'])

    def test_engine_test_suites_exist(self):
        for subsystem in self.matrix.get('engineCapabilities', []):
            for feature in subsystem.get('features', []):
                for suite in feature.get('testSuites', []):
                    suite_path = ROOT / suite
                    self.assertTrue(suite_path.exists(), f"Test suite path missing: {suite_path} for feature {feature['feature']}")

    def test_all_capability_statuses_valid(self):
        valid_statuses = set(self.matrix['statusLabels'])
        valid_strengths = set(self.matrix['strengthLabels'])
        for p in self.matrix['protectors']:
            for cap in p['capabilities']:
                self.assertIn(cap['status'], valid_statuses, f"Invalid status: {cap['status']}")
                self.assertIn(cap['strength'], valid_strengths, f"Invalid strength: {cap['strength']}")


if __name__ == '__main__':
    unittest.main()
