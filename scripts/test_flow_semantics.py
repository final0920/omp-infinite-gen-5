"""Data-only bounded parser and solver-error regressions; no DLL/PE launched."""
from pathlib import Path
import sys,tempfile,time,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'worker'))
from flow_semantics import forms,model_values,SemanticSolver

class FakeLibrary:
    def __init__(self,status,model=''):self.status=status;self.model=model;self.calls=[]
    def Z3_mk_config(self):return 1
    def Z3_mk_context(self,_):return 2
    def Z3_del_config(self,_):pass
    def Z3_del_context(self,_):pass
    def Z3_set_error_handler(self,*_):pass
    def Z3_eval_smtlib2_string(self,ctx,raw):
        self.calls.append(raw)
        return (self.model if raw.startswith(b'(get-value') else self.status).encode()

class Tests(unittest.TestCase):
    def test_exact_values(self):
        for value in ['#x01','#b00000001','(_ bv1 8)']:
            self.assertEqual(model_values('((v '+value+'))',[('v',8)]),{'v':1})
    def test_width_and_identity(self):
        for text in ['((v #x1))','((v #x0001))','((v #b1))','((v (_ bv1 64)))','((x #x01))','((v #xgg))','((v #x01)(v #x02))']:
            with self.assertRaises(ValueError):model_values(text,[('v',8)])
    def test_model_limits(self):
        for text in ['('*129+')'*129,'('*(128)+')'*127,')','x '*8193,'x'*65537]:
            with self.assertRaises(ValueError):forms(text)
    def solver(self,folder,status,model=''):
        s=object.__new__(SemanticSolver);s.out=Path(folder);s.rows=[];s.deadline=time.monotonic()+5;s.output_bytes=0;s.errors=[];s.handler=None;s.lib=FakeLibrary(status,model)
        return s
    def test_unknown_and_unsat_never_request_model(self):
        for status in ['unknown','unsat']:
            with tempfile.TemporaryDirectory() as folder:
                s=self.solver(folder,status);i,w=s.check('test','(declare-const v (_ BitVec 8))',[],[('v',8)])
                self.assertEqual(s.rows[i]['status'],status);self.assertIsNone(w);self.assertEqual(len(s.lib.calls),1)
                self.assertNotIn(b'get-value',(Path(folder)/'q000.smt2').read_bytes())
    def test_invalid_solver_status_is_unverified_and_attempt_retained(self):
        with tempfile.TemporaryDirectory() as folder:
            s=self.solver(folder,'error');i,w=s.check('test','',[],[])
            self.assertEqual(s.rows[i]['status'],'unverified');self.assertIsNone(w);self.assertTrue((Path(folder)/'q000.smt2').exists())
    def test_invalid_sat_model_is_unverified_and_original_retained(self):
        with tempfile.TemporaryDirectory() as folder:
            s=self.solver(folder,'sat','((v #x1))');i,w=s.check('test','(declare-const v (_ BitVec 8))',[],[('v',8)])
            self.assertEqual(s.rows[i]['status'],'unverified');self.assertEqual(s.rows[i]['solverStatus'],'sat');self.assertIsNone(w)
            self.assertEqual((Path(folder)/'q000.model.txt').read_text().strip(),'((v #x1))')
    def test_query_budget_precedes_native_call(self):
        with tempfile.TemporaryDirectory() as folder:
            s=self.solver(folder,'sat')
            for text in ['('*129+')'*129,'(x)\n'*2049,'a '*8193,'a'*1048577]:
                with self.assertRaises(ValueError):s.check('test',text,[],[])
            self.assertFalse(s.lib.calls);self.assertFalse(list(Path(folder).iterdir()))

if __name__=='__main__':unittest.main()
