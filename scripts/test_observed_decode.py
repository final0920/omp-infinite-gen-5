"""Actual pinned decoder, data only. No target process or blocked runtime launch."""
import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'worker'))
from trace_analysis import load_triton
from observed_decode_worker import decode_sites
class RecordedDecodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.tt=load_triton()
    def decode(self,code): return decode_sites(self.tt,[{'pc':'0x140001000','bytes':code}])[0]
    def test_rip_and_signed_displacement(self):
        m=self.decode('488b05fcffffff')['operands'][1]
        self.assertEqual(m['base']['name'],'rip');self.assertEqual(m['displacement'],'0xfffffffffffffffc')
    def test_address_override_and_high_byte(self):
        r=self.decode('678b048d78563412');self.assertEqual(r['operands'][1]['index']['bits'],32)
        r=self.decode('8a642410');self.assertEqual(r['operands'][0]['low'],8);self.assertEqual(r['operands'][0]['parent'],'rax')
    def test_lea_ret_and_gs(self):
        self.assertEqual(self.decode('c3')['operands'],[])
        self.assertEqual(self.decode('65488b042560000000')['operands'][1]['segment'],'gs')
        self.assertTrue(self.decode('488d45f8')['text'].startswith('lea'))
    def test_trailing_and_unknown_bytes_rejected(self):
        self.assertEqual(self.decode('9090')['status'],'decode-rejected')
        self.assertEqual(self.decode('63c0')['status'],'decode-rejected')
    def test_invalid_and_duplicate_sites_rejected(self):
        for sites in [[{'pc':'1','bytes':'90'}],[{'pc':'0x1','bytes':'90','extra':1}],[{'pc':'0x1','bytes':'90'}]*129,[{'pc':'0x1','bytes':'90'}]*2]:
            with self.assertRaises(ValueError):decode_sites(self.tt,sites)
if __name__=='__main__':unittest.main()
