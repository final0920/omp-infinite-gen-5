"""Decode data validation and Windows streaming-lock regressions; no target runs."""
from pathlib import Path
from contextlib import contextmanager
import copy,hashlib,json,os,sys,tempfile,unittest
from importlib.machinery import PathFinder
MAIN=Path(__file__).resolve().parents[1];sys.path.insert(0,str(MAIN/'worker'))
from java_projection import PREFIX,JAVA_RUNTIME_PIN,validate_output,load_manifest,locked_asset

class JavaProjectionTests(unittest.TestCase):
    def setUp(self):
        self.prepared=json.dumps({'schema':'ig5-java-projection-input-v1','targetSha256':'a'*64,'instructions':[{'ea':'0x140001000','codeBytes':'488d0411c3'}]},separators=(',',':')).encode()
        self.row={'ea':'0x140001000','size':4,'codeBytes':'488d0411','mnemonic':'LEA','operands':'RAX,[RCX+RDX]','pcode':[{'opcode':'INT_ADD','output':{'space':'register','offset':'0x0','size':8},'inputs':[{'space':'register','offset':'0x8','size':8},{'space':'register','offset':'0x10','size':8}]}]}
        self.result={'schema':'ig5-java-projection-decode-v1','language':'x86:LE:64:default','targetSha256':'a'*64,'inputSha256':hashlib.sha256(self.prepared).hexdigest(),'nativeTargetExecuted':False,'databaseModified':False,'addressSpaces':[{'space':'ram','javaSpaceId':433,'uniqueIndex':3}],'instructions':[self.row]}
    def encoded(self,result=None):return PREFIX+json.dumps(result or self.result,separators=(',',':')).encode()+b'\n'
    def test_full_instruction_prefix_not_padding_is_accepted(self):
        self.assertEqual(validate_output(self.encoded(),self.prepared),self.result)
    def test_wrong_target_input_language_and_effect_scope_are_rejected(self):
        for key,value in [('targetSha256','b'*64),('inputSha256','b'*64),('language','x86:LE:32:default'),('nativeTargetExecuted',0),('databaseModified',True)]:
            with self.subTest(key=key):
                r=copy.deepcopy(self.result);r[key]=value
                with self.assertRaises(ValueError):validate_output(self.encoded(r),self.prepared)
    def test_duplicate_keys_and_output_preamble_are_rejected(self):
        raw=self.encoded().replace(b'"schema":',b'"schema":"duplicate","schema":',1)
        for value in (raw,b'log\n'+self.encoded(),self.encoded()[:-1]):
            with self.assertRaises(ValueError):validate_output(value,self.prepared)
    def test_instruction_bytes_boundaries_order_and_missing_rows_are_rejected(self):
        for key,value in [('codeBytes','488d0412'),('size',True),('size',6),('ea','0x140001001'),('pcode',None)]:
            r=copy.deepcopy(self.result);r['instructions'][0][key]=value
            with self.assertRaises(ValueError):validate_output(self.encoded(r),self.prepared)
        r=copy.deepcopy(self.result);r['instructions']=[]
        with self.assertRaises(ValueError):validate_output(self.encoded(r),self.prepared)
    def test_missing_null_output_or_extra_semantic_declaration_is_rejected(self):
        for mutation in ('missing','extra'):
            r=copy.deepcopy(self.result);op=r['instructions'][0]['pcode'][0]
            if mutation=='missing':del op['output']
            else:op['certificate']='caller-certified'
            with self.assertRaises(ValueError):validate_output(self.encoded(r),self.prepared)
    def test_memory_space_operand_is_not_a_constant_or_java_internal_number(self):
        r=copy.deepcopy(self.result);op=r['instructions'][0]['pcode'][0];op['opcode']='LOAD'
        for operand in ({'space':'const','offset':'0x1b1','size':8},{'kind':'address-space','space':'ram','spaceId':433},{'kind':'address-space','space':'ram','spaceId':True}):
            op['inputs'][0]=operand
            with self.assertRaises(ValueError):validate_output(self.encoded(r),self.prepared)
        op['inputs'][0]={'kind':'address-space','space':'ram','spaceId':3}
        self.assertEqual(validate_output(self.encoded(r),self.prepared),r)
    def test_asset_manifest_cannot_be_resealed_by_a_caller(self):
        raw=(MAIN/'adapters/ghidra/projection-java/manifest.json').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),JAVA_RUNTIME_PIN)
        self.assertEqual(load_manifest(raw)['language'],'x86:LE:64:default')
        with self.assertRaisesRegex(ValueError,'pin mismatch'):load_manifest(raw+b' ')
    def test_helper_directory_cannot_shadow_jpype_java_package(self):
        self.assertIsNone(PathFinder.find_spec('java',[str(MAIN/'adapters/ghidra')]))
        self.assertTrue((MAIN/'adapters/ghidra/projection-java/ig5-java-decode.jar').is_file())
    @unittest.skipUnless(os.name=='nt','Windows share-deny semantics')
    def test_streamed_runtime_capability_blocks_write_delete_and_replace_until_close(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory).resolve()/'字节锁.bin';data=b'ab'*(1024*1024);p.write_bytes(data)
            pin={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()};checks=[]
            with locked_asset(p,pin,lambda:checks.append(True)):
                for mutation in (lambda:p.write_bytes(b'x'),lambda:p.unlink()):
                    with self.assertRaises(PermissionError):mutation()
                candidate=Path(directory).resolve()/'candidate.bin';candidate.write_bytes(b'x')
                with self.assertRaises(PermissionError):os.replace(candidate,p)
            self.assertGreaterEqual(len(checks),3);self.assertEqual(p.read_bytes(),data);p.write_bytes(b'x')
    @unittest.skipUnless(os.name=='nt','Windows share-deny semantics')
    def test_wrong_digest_and_cancel_close_the_asset_handle(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory).resolve()/'asset.bin';p.write_bytes(b'abc')
            with self.assertRaisesRegex(ValueError,'digest mismatch'):
                with locked_asset(p,{'bytes':3,'sha256':'0'*64},lambda:None):pass
            def cancelled():raise ValueError('cancelled')
            with self.assertRaisesRegex(ValueError,'cancelled'):
                with locked_asset(p,{'bytes':3,'sha256':hashlib.sha256(b'abc').hexdigest()},cancelled):pass
            p.write_bytes(b'handle-released')

if __name__=='__main__':unittest.main(verbosity=2)
