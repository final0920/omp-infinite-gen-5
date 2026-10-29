"""Known-block capability history tests; no executable or target is started."""
from pathlib import Path
import json
import os
import sys
import tempfile
import subprocess
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'adapters/x64dbg'))
from runtime_policy import record_block, read_block, record_path, assert_launch_permitted, RuntimePolicyBlocked
from adapter import Adapter

class RuntimePolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ig5-runtime-policy-')
        self.root = Path(self.temp.name); self.blocks = self.root / 'blocks'
        self.component = self.root / 'not-an-executable.exe'; self.component.write_bytes(b'fixture-data-never-executed')
        self.error = OSError('synthetic policy refusal'); self.error.winerror = 4551
    def tearDown(self): self.temp.cleanup()
    def test_unknown_is_not_a_verified_launch(self):
        self.assertIsNone(read_block(self.blocks, self.component)); assert_launch_permitted(self.blocks, self.component)
        self.assertFalse(self.blocks.exists())
    def test_exact_4551_is_retained_without_an_expiry_or_automatic_clear(self):
        value = record_block(self.blocks, self.component, self.error)
        self.assertIsInstance(value['recordedAt'], str)
        self.assertEqual(value, read_block(self.blocks, self.component))
        self.assertFalse(value['automaticRetryAllowed'])
        with self.assertRaises(RuntimePolicyBlocked): assert_launch_permitted(self.blocks, self.component)
        self.assertEqual(record_block(self.blocks, self.component, self.error), value)
    def test_other_errors_are_not_misclassified_as_application_policy(self):
        self.assertIsNone(record_block(self.blocks, self.component, OSError('not policy')))
        self.assertIsNone(read_block(self.blocks, self.component))
    def test_record_is_component_bound_and_does_not_grant_permission_for_another_path(self):
        record_block(self.blocks, self.component, self.error)
        self.assertIsNone(read_block(self.blocks, self.root / 'another.exe'))
        value = json.loads(record_path(self.blocks, self.component).read_text())
        value['component'] += '-wrong'; record_path(self.blocks, self.component).write_text(json.dumps(value))
        with self.assertRaises(RuntimePolicyBlocked): read_block(self.blocks, self.component)
    def test_corrupt_state_is_not_silently_ignored(self):
        record_block(self.blocks, self.component, self.error)
        record_path(self.blocks, self.component).write_text('{')
        with self.assertRaises(RuntimePolicyBlocked): assert_launch_permitted(self.blocks, self.component)
    def test_imported_evidence_is_separate_from_a_fresh_os_observation(self):
        ref = {'path': str(self.root / 'prior-report.json'), 'sha256': 'a'*64}
        value = record_block(self.blocks, self.component, self.error, ref)
        self.assertEqual(value['source'], 'imported-policy-evidence'); self.assertEqual(value['evidence'], ref)
    def test_adapter_denies_a_cached_component_before_Popen_or_any_target_execution(self):
        config = self.root / 'runtime.json'
        config.write_text(json.dumps({'mode': 'headless', 'headlessExe': str(self.component)}))
        with patch.dict(os.environ, {'IG5_HOME': str(self.root)}):
            adapter = Adapter(config_path=config)
        adapter.target = {'bits': 64}
        record_block(adapter.runtime_policy_root, self.component, self.error)
        with patch('adapter.subprocess.Popen') as process:
            with self.assertRaises(Exception) as raised: adapter.launch()
            self.assertEqual(raised.exception.code, 'ERUNTIME_POLICY'); process.assert_not_called()
    def test_readonly_doctor_reports_cache_without_a_launch_and_preserves_file_presence(self):
        config = self.root / 'runtime.json'
        config.write_text(json.dumps({key: str(self.component) for key in ('pythonExe','x64dbgExe','x32dbgExe','headlessExe','headless32Exe')}))
        with patch.dict(os.environ, {'IG5_HOME': str(self.root)}): adapter = Adapter(config_path=config)
        record_block(adapter.runtime_policy_root, self.component, self.error)
        with patch('adapter.subprocess.Popen') as process:
            result = adapter.doctor(); process.assert_not_called()
        self.assertFalse(result['ok']); self.assertTrue(result['filesReady']); self.assertFalse(result['launchVerified'])
        self.assertEqual(result['launchReadiness']['64']['state'], 'blocked-by-application-control')
        self.assertFalse(result['launchReadiness']['64']['nativeLaunchAttempted'])
    def test_failed_cache_write_still_blocks_a_second_attempt_in_the_same_adapter(self):
        config = self.root / 'runtime.json'; config.write_text(json.dumps({'mode': 'headless', 'headlessExe': str(self.component)}))
        with patch.dict(os.environ, {'IG5_HOME': str(self.root)}): adapter = Adapter(config_path=config)
        adapter.target = {'bits': 64}
        with patch('adapter.subprocess.Popen', side_effect=self.error) as process, patch('runtime_policy.record_block', side_effect=OSError('fixture state unwritable')):
            for _ in range(2):
                with self.assertRaises(Exception) as raised: adapter.launch()
                self.assertEqual(raised.exception.code, 'ERUNTIME_POLICY')
            self.assertEqual(process.call_count, 1)
        adapter.cleanup()
    def test_evidence_is_bounded_and_unsafe_records_never_enable_a_launch(self):
        with self.assertRaises(ValueError): record_block(self.blocks, self.component, self.error, {'path': 'relative', 'sha256': 'a'*64})
        record_block(self.blocks, self.component, self.error)
        record_path(self.blocks, self.component).write_bytes(b' ' * 8193)
        with self.assertRaises(RuntimePolicyBlocked): assert_launch_permitted(self.blocks, self.component)
    def test_isolated_python_import_and_readonly_doctor_find_the_owned_helper(self):
        config = self.root / 'runtime.json'
        config.write_text(json.dumps({key: str(self.component) for key in ('pythonExe','x64dbgExe','x32dbgExe','headlessExe','headless32Exe')}))
        record_block(self.root / 'runtime-policy-blocks', self.component, self.error)
        program = "import runpy,sys,json; ns=runpy.run_path(sys.argv[1],run_name='readonly_policy_fixture'); print(json.dumps(ns['Adapter'](config_path=sys.argv[2]).doctor()))"
        env = dict(os.environ, IG5_HOME=str(self.root))
        child = subprocess.run([sys.executable, '-I', '-B', '-c', program,
            str(Path(__file__).resolve().parents[1] / 'adapters/x64dbg/adapter.py'), str(config)],
            capture_output=True, timeout=5, env=env, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        self.assertEqual(child.returncode, 0, child.stderr.decode('utf-8', errors='replace'))
        result = json.loads(child.stdout)
        self.assertFalse(result['ok']); self.assertFalse(result['launchReadiness']['64']['nativeLaunchAttempted'])

class DecoderPolicyTests(unittest.TestCase):
    def setUp(self):
        import types
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'worker'))
        import kernel_analysis
        self.module = kernel_analysis
        self.temp = tempfile.TemporaryDirectory(prefix='ig5-decoder-policy-')
        self.home = Path(self.temp.name); self.library = self.home / 'fake-decoder.dll'
        self.library.write_bytes(b'not a native library')
        self.error = OSError('synthetic decoder 4551'); self.error.winerror = 4551
        self.env = patch.dict(os.environ, {'IG5_HOME': str(self.home)}); self.env.start()
        self.bootstrap = patch.dict(sys.modules, {'native_bootstrap': types.SimpleNamespace(bootstrap_windows_dlls=lambda _: None)}); self.bootstrap.start()
    def tearDown(self):
        self.bootstrap.stop(); self.env.stop(); self.temp.cleanup()
    def test_existing_block_precedes_loader(self):
        record_block(self.home / 'runtime-policy-blocks', self.library, self.error)
        with patch.object(self.module.c, 'CDLL') as loader:
            with self.assertRaises(RuntimePolicyBlocked): self.module.load_native_decoder(self.library, self.home)
            loader.assert_not_called()
    def test_first_4551_persists_and_new_adapter_refuses_retry(self):
        with patch.object(self.module.c, 'CDLL', side_effect=self.error) as loader:
            with self.assertRaises(OSError) as raised: self.module.load_native_decoder(self.library, self.home)
            self.assertIs(raised.exception, self.error)
            self.assertIsNotNone(read_block(self.home / 'runtime-policy-blocks', self.library))
            self.module._native_policy_denied.clear()
            with self.assertRaises(RuntimePolicyBlocked): self.module.load_native_decoder(self.library, self.home)
            self.assertEqual(loader.call_count, 1)
    def test_persistence_failure_still_remembers_block_in_process(self):
        with patch('runtime_policy.record_block', side_effect=OSError('read-only policy store')), patch.object(self.module.c, 'CDLL', side_effect=self.error) as loader:
            with self.assertRaises(OSError) as raised: self.module.load_native_decoder(self.library, self.home)
            self.assertIs(raised.exception, self.error)
            with self.assertRaises(RuntimePolicyBlocked): self.module.load_native_decoder(self.library, self.home)
            self.assertEqual(loader.call_count, 1)
    def test_ordinary_loader_error_is_not_policy(self):
        with patch.object(self.module.c, 'CDLL', side_effect=OSError('ordinary missing dependency')) as loader:
            for _ in range(2):
                with self.assertRaises(OSError): self.module.load_native_decoder(self.library, self.home)
            self.assertEqual(loader.call_count, 2)
            self.assertIsNone(read_block(self.home / 'runtime-policy-blocks', self.library))

if __name__ == '__main__': unittest.main(verbosity=2)
