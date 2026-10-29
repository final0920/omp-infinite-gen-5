"""Pure independent encoder/unknown-status tests; no native library is loaded."""
import sys,json,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'worker'))
from bitvector_verify import assess,digest,encode,check_ast,strict
def ast(value='0x0',bits=8):return {'nodes':[{'id':0,'op':'const','bits':bits,'args':[],'value':value}],'root':0}
def contract():
    original=ast();premise=ast('0x1',1)
    return {'schema':'ig5-bitvector-contract-v1','version':'20261024-bv-contract-1','variables':[],'original':original,'premise':premise,'originalDigest':digest(original),'premiseDigest':digest(premise)}
class FakeSolver:
    def __init__(self,statuses):self.statuses=statuses;self.rows=[];self.inputs=[]
    def check(self,name,base,conditions,witnesses):
        status=self.statuses[len(self.rows)];self.rows.append({'status':status});self.inputs.append((base,conditions,witnesses))
        return len(self.rows)-1,{'f07_dummy':0} if status=='sat' else None
class Tests(unittest.TestCase):
    def test_unsat_premise_stops(self):
        s=FakeSolver(['unsat']);r=assess(contract(),ast(),s);self.assertEqual(len(s.rows),1);self.assertEqual(r['differenceStatus'],'not-run')
    def test_unknown_premise_stops(self):
        s=FakeSolver(['unknown']);self.assertEqual(assess(contract(),ast(),s)['premiseStatus'],'unknown');self.assertEqual(len(s.rows),1)
    def test_unknown_difference_retained(self):
        s=FakeSolver(['sat','unknown']);r=assess(contract(),ast(),s);self.assertEqual(r['differenceStatus'],'unknown');self.assertEqual(r['status'],'unknown')
    def test_queries_are_constructed_not_caller_smt(self):
        s=FakeSolver(['sat','unsat']);assess(contract(),ast(),s);self.assertIn('(distinct O0 C0)',s.inputs[1][1]);self.assertEqual(s.inputs[0][2],[('f07_dummy',1)])
    def test_duplicate_and_nonfinite_json(self):
        for raw in ['{"x":1,"x":2}','{"x":NaN}']:
            with self.assertRaises(ValueError):strict(raw)
    def test_width_or_operator_fail_before_solver(self):
        for value in [ast('0x100'),{'nodes':[{'id':0,'op':'CALL','bits':8,'args':[]}],'root':0}]:
            with self.assertRaises(ValueError):check_ast(value,{})
    def test_extension_and_extract_have_explicit_indices(self):
        a={'nodes':[{'id':0,'op':'const','bits':8,'args':[],'value':'0xff'},{'id':1,'op':'sext','bits':16,'args':[0]},{'id':2,'op':'extract','bits':8,'args':[1],'offset':8}],'root':2}
        check_ast(a,{});encoded,_=encode(a,'O',{});self.assertIn('sign_extend 8',encoded[1]);self.assertIn('extract 15 8',encoded[2])
if __name__=='__main__':unittest.main()
