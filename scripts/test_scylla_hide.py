"""Pinned asset/refusal tests; actual hooks are a separate OWN runtime test."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'adapters/x64dbg'))
from scylla_hide import load_bundle, verify_owned, MANIFEST_SHA256
from types import SimpleNamespace

class Tests(unittest.TestCase):
    def test_shipped_bundle_and_narrow_profile_are_pinned(self):
        manifest,files=load_bundle()
        self.assertEqual(manifest['revision'],'baa5c8e853ace2bee752631f27fdfe5b271d92f6')
        self.assertEqual(len(files),4)
        text=files['scylla_hide.ini'].decode('ascii')
        for setting in ('RemoveDebugPrivileges=0','KillAntiAttach=0','PebOsBuildNumber=0','PreventThreadCreation=0','AutostartServer=0'):
            self.assertIn(setting,text)
        self.assertIn('NtSetInformationThreadHook=1',text)
    def test_tampered_inventory_is_rejected_before_loading_code(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()
            (root/'ig5-manifest.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'inventory changed'):load_bundle(root)
    def test_nonowned_running_or_wrong_architecture_refused_before_OS_calls(self):
        for bits,job,state,pid in ((32,None,'suspended',1),(64,None,'suspended',1),(64,SimpleNamespace(handle=1),'running',1),(64,SimpleNamespace(handle=1),'suspended',None)):
            adapter=SimpleNamespace(target={'bits':bits},job=job)
            with self.assertRaisesRegex(RuntimeError,'paused owned native'):
                verify_owned(adapter,{'state':state,'pid':pid},lambda code,message:RuntimeError(message))

if __name__=='__main__':unittest.main(verbosity=2)
