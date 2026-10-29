"""Cross-language original-byte/runtime-coordinate validation, no PE execution."""
import base64,copy,hashlib,json,os,shutil,subprocess,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'worker'))
from recorded_coordinates import prepare_recorded_input


class RecordedCoordinateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        node=os.environ.get('IG5_TEST_NODE') or shutil.which('node')
        if not node:raise RuntimeError('A Node runtime is required for the independent JS-built PE fixture')
        code="import{recordedCoordinateCase}from'./scripts/fixtures/recorded_coordinate_cases.mjs';const q=recordedCoordinateCase();console.log(JSON.stringify({data:q.data.toString('base64'),input:q.input}));"
        b=subprocess.check_output([node,'--input-type=module','-e',code],cwd=ROOT,timeout=15,creationflags=0x08000000 if os.name=='nt' else 0)
        assert len(b)<=65536
        fixture=json.loads(b);cls.data=base64.b64decode(fixture['data'],validate=True);cls.original=fixture['input']
    def run_case(self,x=None,raw=None,data=None,addresses=None,digest=None):
        x=copy.deepcopy(self.original if x is None else x)
        raw=json.dumps(x,separators=(',',':')).encode() if raw is None else raw
        return prepare_recorded_input(self.data if data is None else data,x['targetSha256'],[int(r['preferred'],16) for r in x['rows']] if addresses is None else addresses,raw,hashlib.sha256(raw).hexdigest() if digest is None else digest)
    def test_js_built_snapshot_exactly_binds_runtime_bytes(self):
        raw,binding=self.run_case();r=json.loads(raw)
        self.assertEqual(r['instructions'],[{'ea':x['runtimePc'],'codeBytes':x['bytes']} for x in self.original['rows']])
        self.assertEqual(binding['input'],self.original);self.assertFalse(binding['ordinaryDataRelocated']);self.assertFalse(binding['globalCodeEpochProved'])
    def test_wrong_original_target_and_coordinate_digest_refused(self):
        with self.assertRaises(ValueError):self.run_case(digest='0'*64)
        data=bytearray(self.data);data[0x400]^=1
        with self.assertRaises(ValueError):self.run_case(data=bytes(data))
    def test_bad_mapping_bytes_offsets_and_address_selection_refused(self):
        for key,value in [('bytes','90'),('fileOffset',1025),('preferred','0x140001001'),('runtimePc','0x7ff700001001')]:
            x=copy.deepcopy(self.original);x['rows'][0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.run_case(x)
        with self.assertRaises(ValueError):self.run_case(addresses=[0]*4)
    def test_headers_are_not_executable_file_code(self):
        x=copy.deepcopy(self.original);x['rows']=x['rows'][:1];r=x['rows'][0]
        r.update(preferred=x['preferredBase'],runtimePc=x['runtimeBase'],fileOffset=0,bytes='4d5a')
        with self.assertRaises(ValueError):self.run_case(x)
    def test_source_identity_pause_and_extra_proof_fields_refused(self):
        for change in ('thread','window','pause','group','extra'):
            x=copy.deepcopy(self.original)
            if change=='thread':x['source']['threadId']=True
            elif change=='window':x['source']['windows'][0]['traceSha256']='bad'
            elif change=='pause':x['rows'][1]['pauseBefore']+=2
            elif change=='group':x['rows'][1]['groupIndex']+=2
            else:x['rows'][0]['callerProof']='accepted'
            with self.subTest(change=change),self.assertRaises(ValueError):self.run_case(x)
    def test_duplicate_json_property_is_not_normalized_away(self):
        raw=json.dumps(self.original,separators=(',',':')).encode();raw=raw.replace(b'"schema":',b'"schema":"forged","schema":',1)
        with self.assertRaises(ValueError):self.run_case(raw=raw)
    def test_raw64k_byte_bound_is_enforced_before_parsing(self):
        raw=b' '*65536+json.dumps(self.original).encode()
        with self.assertRaises(ValueError):self.run_case(raw=raw)
    def test_unrelated_missing_and_duplicate_windows_refused(self):
        for mode in ('missing','duplicate','unrelated'):
            x=copy.deepcopy(self.original)
            if mode=='missing':x['source']['windows']=[]
            else:
                window=copy.deepcopy(x['source']['windows'][0])
                if mode=='unrelated':window['reportId']='33333333-3333-4333-8333-333333333333'
                x['source']['windows'].append(window)
            with self.subTest(mode=mode),self.assertRaises(ValueError):self.run_case(x)


if __name__=='__main__':unittest.main()
