"""Physical receipt identity must survive slash/case spelling, not substitution."""
from pathlib import Path
import hashlib,sys,tempfile,unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from verify_handler137_semantics import same_source_receipt


class ReceiptIdentity(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='ig5-handler137-path-')
        self.root=Path(self.temp.name).resolve();self.path=self.root/'receipt.json';self.path.write_bytes(b'{"passed":true}\n')
        self.ref={'path':str(self.path),'sha256':hashlib.sha256(self.path.read_bytes()).hexdigest()}
    def tearDown(self):
        assert self.root.is_absolute() and self.root.name.startswith('ig5-handler137-path-')
        self.temp.cleanup()
    def test_same_and_forward_slashes(self):
        self.assertTrue(same_source_receipt(self.ref,self.ref))
        self.assertTrue(same_source_receipt(self.ref,{**self.ref,'path':self.path.as_posix()}))
    @unittest.skipUnless(sys.platform=='win32','Windows filesystem case semantics')
    def test_windows_case_spelling(self):
        self.assertTrue(same_source_receipt(self.ref,{**self.ref,'path':str(self.path).upper()}))
    def test_digest_and_real_file_identity_both_required(self):
        copy=self.root/'other.json';copy.write_bytes(self.path.read_bytes())
        self.assertFalse(same_source_receipt(self.ref,{**self.ref,'path':str(copy)}))
        self.assertFalse(same_source_receipt(self.ref,{**self.ref,'sha256':'0'*64}))
    def test_missing_relative_and_noncanonical_alias_rejected(self):
        self.assertFalse(same_source_receipt(self.ref,{**self.ref,'path':str(self.root/'missing.json')}))
        self.assertFalse(same_source_receipt(self.ref,{**self.ref,'path':'receipt.json'}))
        child=self.root/'child';child.mkdir()
        self.assertFalse(same_source_receipt(self.ref,{**self.ref,'path':str(child/'..'/'receipt.json')}))
        self.assertFalse(same_source_receipt(self.ref,{'path':str(self.path),'sha256':None}))


if __name__=='__main__':unittest.main()
