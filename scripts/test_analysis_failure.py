"""Failure evidence tests use ordinary data files; no target/JVM is executed."""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'worker'))
from analysis_failure import capture, diagnostic, FILES


class FailureEvidenceTests(unittest.TestCase):
    def test_first_java_exception_and_causes_not_final_stack_frame(self):
        raw = b'Exception in thread "main" java.lang.IllegalStateException: Instruction boundary exceeds available bytes\n\tat IG5.main(IG5.java:90)\nCaused by: java.lang.IllegalArgumentException: short input\n\tat other.frame(X.java:3)\n'
        value = diagnostic(raw, java=True)
        self.assertIn('Instruction boundary exceeds available bytes', value)
        self.assertIn('Caused by:', value)
        self.assertNotIn('other.frame', value)

    def test_java_fallback_utf8_and_bound(self):
        self.assertEqual(diagnostic(b'\xff invalid\n\tat X.main(X.java:1)', java=True), '\ufffd invalid')
        self.assertLessEqual(len(diagnostic(b'Exception in thread ' + b'x' * 4000, java=True)), 1024)
        self.assertIn('no diagnostic', diagnostic(b''))

    def test_python_retains_exception_tail(self):
        self.assertEqual(diagnostic(b'Traceback:\n  at helper\nProjectionError: undefined flags'), 'ProjectionError: undefined flags')

    def capture(self, directory, cleanup=True):
        return capture(directory, params={'job_id':'a', 'nonce':'b', 'sha256':'c'*64, 'projection_decoder':'java'},
                       method='project', runtime_pin='d'*64, java_pin='e'*64, stage='java-decode', stages=[],
                       cleanup=cleanup, code='PROJECTION_FAILED', message='preserved refusal')

    def test_capture_hashes_original_logs_and_scope(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name).resolve(); (directory / 'java-decode').mkdir()
            raw = b'Exception in thread main\n\tat x'
            (directory / 'java-decode/stderr.log').write_bytes(raw)
            ref = self.capture(directory)
            data = (directory / ref['name']).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), ref['sha256'])
            self.assertEqual(len(data), ref['bytes'])
            result = json.loads(data)
            self.assertEqual(len(result['files']), len(FILES))
            row = next(r for r in result['files'] if r['name']=='java-decode/stderr.log')
            self.assertEqual(row, {'name':'java-decode/stderr.log','status':'captured','bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
            self.assertFalse(result['businessAccepted']); self.assertFalse(result['wholeBinaryVerified'])
            self.assertEqual((directory / 'java-decode/stderr.log').read_bytes(), raw)
            with self.assertRaises(FileExistsError): self.capture(directory)

    def test_unknown_cleanup_never_reads_live_logs_or_invents_process(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name).resolve()
            with patch('analysis_failure.locked_file', side_effect=AssertionError('live log read')):
                self.capture(directory, cleanup=False)
            result = json.loads((directory / 'analysis-failure.json').read_bytes())
            self.assertFalse(result['cleanupConfirmed']); self.assertEqual(result['processStages'], [])
            self.assertTrue(all(r['status']=='not-read-cleanup-unconfirmed' for r in result['files']))

    def test_over_budget_log_preserved_without_read(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name).resolve()
            with (directory / 'stdout.log').open('wb') as stream: stream.truncate(4*1024**2+1)
            self.capture(directory)
            result = json.loads((directory / 'analysis-failure.json').read_bytes())
            self.assertEqual(next(r for r in result['files'] if r['name']=='stdout.log')['status'], 'output-limit')
            self.assertEqual((directory / 'stdout.log').stat().st_size, 4*1024**2+1)


if __name__ == '__main__': unittest.main()
