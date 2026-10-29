"""Real owned-helper lifecycle tests; never execute a target/sample."""
from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'worker'))
from lift_process import run_owned, OwnedProcessError


@unittest.skipUnless(os.name == 'nt', 'Windows job-object integration')
class OwnedJobTests(unittest.TestCase):
    def run_code(self, code, **options):
        with tempfile.TemporaryDirectory(prefix='ig5-job-test-') as tmp:
            result = run_owned(sys.executable, ['-I', '-B', '-c', code], tmp, **options)
            out = (Path(tmp) / 'stdout.log').read_text(encoding='utf-8')
            err = (Path(tmp) / 'stderr.log').read_text(encoding='utf-8')
        self.assertTrue(result['childExitConfirmed'])
        self.assertTrue(result['jobAssignedAtCreation'])
        return result, out, err

    def test_complete_and_secret_not_inherited(self):
        os.environ['IG5_JOB_TEST_SECRET'] = 'must-not-reach-child'
        try:
            r, out, _ = self.run_code('import os;print(os.getenv("IG5_JOB_TEST_SECRET", "absent"))')
            self.assertEqual(r['exitCode'], 0)
            self.assertEqual(out.strip(), 'absent')
        finally:
            del os.environ['IG5_JOB_TEST_SECRET']

    def test_deadline_and_companion_untouched(self):
        other = subprocess.Popen([sys.executable, '-I', '-B', '-c', 'import time;time.sleep(20)'],
                                 creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            r, _, _ = self.run_code('import time;time.sleep(20)', budget_ms=120)
            self.assertEqual(r['limitReason'], 'deadline')
            self.assertIsNone(other.poll())
        finally:
            other.terminate(); other.wait(timeout=5)

    def test_cancel(self):
        cancel = threading.Event()
        timer = threading.Timer(.15, cancel.set); timer.start()
        try:
            r, _, _ = self.run_code('import time;time.sleep(20)', cancel=cancel)
            self.assertEqual(r['status'], 'cancelled')
        finally:
            timer.cancel()

    def test_pre_cancel_does_not_launch(self):
        cancel = threading.Event(); cancel.set(); started = []
        with tempfile.TemporaryDirectory(prefix='ig5-job-test-') as tmp:
            with self.assertRaises(OwnedProcessError) as error:
                run_owned(sys.executable, ['-c', 'raise RuntimeError()'], tmp,
                          cancel=cancel, on_started=started.append)
        self.assertEqual(started, [])
        self.assertTrue(error.exception.child_exit_confirmed)

    def test_output_limit(self):
        r, _, _ = self.run_code('import os,time;os.write(1,b"x"*65536);time.sleep(20)', output_bytes=1024)
        self.assertEqual(r['limitReason'], 'output-limit')

    def test_os_memory_limit(self):
        r, _, err = self.run_code('x=bytearray(256*1024*1024)', memory_bytes=32*1024**2)
        self.assertNotEqual(r['exitCode'], 0)
        self.assertIn('MemoryError', err)
        self.assertLessEqual(r['peakPrivateBytes'], 32*1024**2)

    def test_grandchild_creation_is_denied(self):
        r, out, _ = self.run_code('import subprocess,sys\ntry:\n subprocess.Popen([sys.executable,"-c","pass"])\nexcept OSError:\n print("denied")')
        self.assertEqual(r['exitCode'], 0)
        self.assertEqual(out.strip(), 'denied')

    def test_worker_death_closes_job(self):
        # Open a capability to the exact helper, not a PID selected by the user.
        # It is acquired before intentionally exiting the helper's parent.
        import ctypes as C
        from ctypes import wintypes as W
        k = C.WinDLL('kernel32', use_last_error=True)
        k.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]; k.OpenProcess.restype = W.HANDLE
        k.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]; k.WaitForSingleObject.restype = W.DWORD
        k.CloseHandle.argtypes = [W.HANDLE]; k.CloseHandle.restype = W.BOOL
        with tempfile.TemporaryDirectory(prefix='ig5-job-test-') as tmp:
            marker, go = Path(tmp)/'pid.json', Path(tmp)/'go'
            code = ('import sys,os,time,json\nfrom pathlib import Path\n'
                    'sys.path.insert(0,sys.argv[1])\nfrom lift_process import run_owned\n'
                    'def started(pid):\n Path(sys.argv[3]).write_text(json.dumps(pid))\n'
                    ' while not Path(sys.argv[4]).exists(): time.sleep(.01)\n'
                    ' os._exit(17)\n'
                    'run_owned(sys.executable,["-I","-B","-c","import time;time.sleep(20)"],sys.argv[2],on_started=started)')
            worker = subprocess.Popen([sys.executable,'-I','-B','-c',code,
                str(Path(__file__).resolve().parents[1]/'worker'),tmp,str(marker),str(go)],
                creationflags=subprocess.CREATE_NO_WINDOW)
            handle = None
            try:
                until = time.monotonic()+5
                while not marker.exists() and time.monotonic()<until and worker.poll() is None: time.sleep(.01)
                self.assertTrue(marker.exists())
                pid = json.loads(marker.read_text())
                handle = k.OpenProcess(0x100000, False, pid)  # SYNCHRONIZE only
                self.assertTrue(handle)
                go.write_text('exit')
                self.assertEqual(worker.wait(timeout=5), 17)
                self.assertEqual(k.WaitForSingleObject(handle, 5000), 0)
            finally:
                if worker.poll() is None: worker.terminate(); worker.wait(timeout=5)
                if handle: k.CloseHandle(handle)


if __name__ == '__main__': unittest.main(verbosity=2)
