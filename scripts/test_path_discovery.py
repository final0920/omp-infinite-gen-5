"""Walker boundaries with explicit byte fixtures; no native decoder/CPU."""
from pathlib import Path
from types import SimpleNamespace as NS
import sys,unittest
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/'worker')]
from path_discovery import walk,control

class DiscoveryTests(unittest.TestCase):
    def image(self,code,permissions=4):return NS(regions=[NS(start=0x1000,data=bytes.fromhex(code),permissions=permissions)])
    def decode(self,ea,code):
        size,text,flow,branch={0x90:(1,'nop',False,False),0xeb:(2,'jmp ignored_operand_text',True,True),0xc3:(1,'ret',True,False),0xe8:(5,'call ignored',True,False),0x74:(2,'je ignored',True,True),0xcc:(1,'int3',False,False),0x48:(3,'mov rax, rax',False,False),0x0f:(2,'syscall',False,False)}[code[0]]
        return dict(size=size,text=text,controlFlow=flow,branch=branch)
    def test_direct_jump_skips_unvisited_data_without_using_text(self):
        r=walk(self.image('90 eb02 0f0b c3'),0x1000,128,self.decode)
        self.assertEqual(r['candidatePath'],['0x1000','0x1001','0x1005']);self.assertEqual(r['stop'],{'reason':'return','next':None})
    def test_conditional_never_selects_observed_side(self):
        r=walk(self.image('7401 90c3'),0x1000,128,self.decode);self.assertEqual(r['candidatePath'],['0x1000']);self.assertEqual(r['instructions'][0]['control'],{'kind':'conditional','successors':['0x1003','0x1002']})
    def test_call_stops_without_return_or_callee_summary(self):
        r=walk(self.image('e800000000 c3'),0x1000,128,self.decode);self.assertEqual(r['stop']['reason'],'call');self.assertEqual(len(r['instructions']),1)
    def test_opt_in_direct_call_enters_callee_and_stops_at_ret(self):
        r=walk(self.image('e800000000 c3'),0x1000,128,self.decode,follow_direct_calls=True)
        self.assertEqual(r['candidatePath'],['0x1000','0x1005']);self.assertEqual(r['stop']['reason'],'return');self.assertEqual(r['instructions'][0]['control']['returnAddress'],'0x1005')
        with self.assertRaises(ValueError):walk(self.image('c3'),0x1000,128,self.decode,follow_direct_calls=1)
    def test_cycle_retains_closing_jump(self):
        r=walk(self.image('90ebfd'),0x1000,128,self.decode);self.assertEqual(len(r['instructions']),2);self.assertEqual(r['stop'],{'reason':'cycle','next':'0x1000'})
    def test_jump_into_previously_decoded_instruction_stops(self):
        r=walk(self.image('4889c0ebfc'),0x1000,128,self.decode);self.assertEqual(r['stop'],{'reason':'overlap','next':'0x1001'})
    def test_whole_decoded_extent_cannot_overlap_prior_bytes(self):
        def decode(ea,code):return dict(size=5,text='mov eax, 0',controlFlow=False,branch=False) if ea==0x1002 else self.decode(ea,code)
        r=walk(self.image('eb03 909090 ebfb'),0x1000,128,decode);self.assertEqual(r['candidatePath'],['0x1000','0x1005']);self.assertEqual(r['stop'],{'reason':'overlap','next':'0x1002','nextSize':5})
    def test_instruction_budget_does_not_claim_completion(self):
        r=walk(self.image('90'*129),0x1000,128,self.decode);self.assertEqual(len(r['instructions']),128);self.assertEqual(r['stop'],{'reason':'instruction-budget','next':'0x1080'});self.assertTrue(r['candidateOnly']);self.assertFalse(r['pathSemanticsValidated'])
    def test_unmapped_successor_is_not_zero_filled(self):
        r=walk(self.image('eb7f'),0x1000,128,self.decode);self.assertEqual(r['stop'],{'reason':'unmapped-or-nonexecutable','next':'0x1081'})
    def test_nonexecutable_entry_refuses(self):
        with self.assertRaisesRegex(ValueError,'executable'):walk(self.image('c3',0),0x1000,128,self.decode)
    def test_missing_entry_refuses(self):
        with self.assertRaises(ValueError):walk(self.image('c3'),0x2000,128,self.decode)
    def test_ambiguous_mapping_refuses(self):
        image=self.image('c3');image.regions*=2
        with self.assertRaises(ValueError):walk(image,0x1000,128,self.decode)
    def test_truncated_instruction_refuses(self):
        with self.assertRaises(ValueError):walk(self.image('e8'),0x1000,128,self.decode)
    def test_indirect_and_prefixed_control_never_follow(self):
        self.assertEqual(control(bytes.fromhex('ffe0'),0x1000,'jmp rax',True,True),{'kind':'unresolved-control','successors':[]})
        self.assertEqual(control(bytes.fromhex('66eb00'),0x1000,'jmp 0x1003',True,True),{'kind':'unresolved-control','successors':[]})
    def test_system_stop_does_not_need_cpu_semantics(self):
        for code in ('0f05','cc'):
            self.assertEqual(walk(self.image(code),0x1000,128,self.decode)['stop']['reason'],'system')
    def test_decoder_control_disagreement_refuses(self):
        with self.assertRaises(ValueError):control(bytes.fromhex('eb00'),0x1000,'jmp 0x1002',False,False)
    def test_cancel_deadline_stops_walking(self):
        def check():raise ValueError('cancelled')
        with self.assertRaisesRegex(ValueError,'cancelled'):walk(self.image('90c3'),0x1000,128,self.decode,check)
    def test_selection_types_and_limits(self):
        for entry,limit in [(0,1),(-1,1),(1<<64,1),(True,1),(0x1000,0),(0x1000,129),(0x1000,True)]:
            with self.assertRaises(ValueError):walk(self.image('c3'),entry,limit,self.decode)

if __name__=='__main__':unittest.main()
