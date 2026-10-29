"""Direct CALL stack/control transfer; no decoder, target or database executes."""
from pathlib import Path
import copy,random,sys,unittest
sys.path[:0]=[str(Path(__file__).resolve().parent),str(Path(__file__).resolve().parents[1]/'worker')]
from test_pcode_projection import GPRS,ProjectionError,RAM,const,flag,ins,op,reg,target,tmp
from pcode_projection import project
from projection_composition import compose_paths
from projection_numerical_oracle import MASK,NAMES,projection_values,total_byte

def call(ea=0x1000,destination=0x1020):
    displacement=destination-(ea+5);assert -(1<<31)<=displacement<(1<<31)
    code='e8'+displacement.to_bytes(4,'little',signed=True).hex()
    return ins(op('INT_SUB',reg('rsp'),reg('rsp'),const(8)),op('STORE',None,RAM,reg('rsp'),const(ea+5)),
               op('CALL',None,target(destination)),ea=ea,code=code,mnemonic='CALL')
def ret(ea=0x1020):
    rip={'space':'register','offset':'0x288','size':8}
    return ins(op('LOAD',rip,RAM,reg('rsp')),op('INT_ADD',reg('rsp'),reg('rsp'),const(8)),op('RETURN',None,rip),ea=ea,code='c3',mnemonic='RET')

class DirectCallTests(unittest.TestCase):
    def test_exact_zero_rel32_branch_form_retains_original_raw_and_full_state(self):
        rng=random.Random(0x63616c6c30)
        for ea in (0x1000,0x140001000,MASK-5):
            instruction=call(ea,ea+5);instruction['pcode'][-1]['opcode']='BRANCH'
            result=project([instruction],list(NAMES));descriptor=result['path'][0]['directCall']
            self.assertEqual(descriptor['decoderForm'],'canonical-e8-rel0-branch-next-v1');self.assertEqual(descriptor['decoderControlOpcode'],'BRANCH')
            self.assertEqual(result['statistics']['pcodeOperations'],3);self.assertEqual(result['control']['transfer'],'call');self.assertEqual(result['control']['returnAddress'],hex(ea+5));self.assertEqual(result['stores'][0]['pcodeIndex'],1)
            for stack in [0,1,MASK-7,MASK]+[rng.getrandbits(64) for _ in range(64)]:
                initial={n:rng.getrandbits(64) for n in NAMES};initial['rsp']=stack;memory=total_byte(rng.getrandbits(64));v=projection_values(result,initial,memory)
                self.assertEqual({n:v[i] for n,i in result['registers'].items()},{**initial,'rsp':(stack-8)&MASK})
                writes={((stack-8+i)&MASK):((ea+5)>>(8*i))&255 for i in range(8)};self.assertEqual(v[result['currentMemory']],(memory,writes));self.assertEqual(v[result['control']['target']],ea+5)
        first=call(0x1000,0x1005);first['pcode'][-1]['opcode']='BRANCH'
        joined=project([first,ret(0x1005)],list(NAMES));composed=compose_paths([[first],[ret(0x1005)]])
        self.assertEqual(joined['statistics']['pcodeOperations'],6);self.assertEqual(len(joined['stores']),1);self.assertEqual(len(composed['stores']),1)
        self.assertEqual(composed['dag']['nodes'][composed['control']['target']]['value'],'0x1005');self.assertEqual(composed['boundaries'][0]['control']['transfer'],'call')

    def test_zero_branch_exception_does_not_generalize_to_missing_or_nonzero_call_effects(self):
        for mutate in [lambda c:c.update(codeBytes='e801000000'),lambda c:c.update(codeBytes='66e800000000',size=6),lambda c:c.update(mnemonic='JMP'),lambda c:c['pcode'].pop(0),lambda c:c['pcode'].pop(1),lambda c:c['pcode'][-1]['inputs'].__setitem__(0,target(0x1006)),lambda c:c['pcode'][1]['inputs'].__setitem__(2,const(0x1006)),lambda c:c['pcode'][0]['inputs'].__setitem__(1,const(16))]:
            c=call(0x1000,0x1005);c['pcode'][-1]['opcode']='BRANCH';mutate(c)
            with self.assertRaises(ProjectionError):project([c],list(NAMES))
        adc=ins(op('COPY',reg('rax',1),flag('cf')),ea=0x1005,code='0f92c0',mnemonic='SETC');c=call(0x1000,0x1005);c['pcode'][-1]['opcode']='BRANCH'
        with self.assertRaisesRegex(ProjectionError,'initial architectural flags'):project([c,adc],['rax'])

    def test_terminal_call_keeps_return_address_and_all_ordered_stack_bytes(self):
        rng=random.Random(0x43414c4c)
        for ea,destination in [(0x1000,0x1020),(0x2000,0x1000),(0x80001000,0x1005),(0x1000,0x80001004)]:
            result=project([call(ea,destination)],list(NAMES));self.assertEqual(result['control']['transfer'],'call')
            self.assertEqual(result['control']['returnAddress'],hex(ea+5));self.assertEqual(len(result['stores']),1)
            self.assertEqual(result['statistics']['pcodeOperations'],3);self.assertEqual(result['statistics']['memoryBytes'],8)
            for stack in [0,1,MASK-7,MASK]+[rng.getrandbits(64) for _ in range(32)]:
                state={n:rng.getrandbits(64) for n in NAMES};state['rsp']=stack;memory=total_byte(rng.getrandbits(64))
                values=projection_values(result,state,memory)
                self.assertEqual({n:values[v] for n,v in result['registers'].items()},{**state,'rsp':(stack-8)&MASK})
                writes={((stack-8+i)&MASK):((ea+5)>>(8*i))&255 for i in range(8)}
                self.assertEqual(values[result['currentMemory']],(memory,writes));self.assertEqual(values[result['control']['target']],destination)

    def test_exact_callee_entry_can_follow_but_call_fallthrough_is_not_a_return_summary(self):
        result=project([call(),ret()],list(NAMES));self.assertEqual(result['control']['kind'],'return')
        wrong=ins(ea=0x1005,code='90',mnemonic='NOP')
        with self.assertRaisesRegex(ProjectionError,'branch/path mismatch'):project([call(),wrong],['rsp'])

    def test_compose_call_then_ret_forwards_return_value_without_dropping_stack_store(self):
        result=compose_paths([[call()],[ret()]])
        node=result['dag']['nodes'][result['control']['target']];self.assertEqual(node['value'],'0x1005')
        self.assertEqual(result['boundaries'][0]['control']['transfer'],'call');self.assertEqual(result['boundaries'][0]['control']['returnAddress'],'0x1005')
        self.assertEqual(len(result['stores']),1);self.assertEqual(result['memoryNormalization']['forwardedBytes'],8)
        for stack in (0,1,MASK):
            state={n:0x123456789abcdef0 for n in NAMES};state['rsp']=stack;v=projection_values(result,state,total_byte(stack))
            self.assertEqual(v[result['registers']['rsp']],stack)

    def test_call_preserves_in_path_defined_flags_but_initial_flags_still_reject(self):
        start=ins(op('COPY',flag('cf'),const(1,1)),ea=0xfff,code='f9',mnemonic='STC')
        after=ins(op('COPY',reg('rax',1),flag('cf')),ea=0x1020,code='0f92c0',mnemonic='SETC')
        result=project([start,call(),after],['rax']);self.assertEqual(result['flagPolicies'][1]['preserved'],['af','cf','of','pf','sf','zf'])
        with self.assertRaisesRegex(ProjectionError,'initial architectural flags'):project([call(),after],['rax'])

    def test_only_complete_bound_e8_shape_accepts_not_prefix_indirect_missing_or_replaced_effects(self):
        cases=[]
        for mutate in [lambda c:c.update(codeBytes='e900000000'),lambda c:c.update(codeBytes='66e81a000000',size=6),
                       lambda c:c.update(codeBytes='ffe0',size=2),lambda c:c.update(mnemonic='JMP'),
                       lambda c:c.pop('codeBytes'),lambda c:c['pcode'].pop(0),lambda c:c['pcode'].pop(1),
                       lambda c:c['pcode'].append(op('COPY',reg('rax'),const(0))),
                       lambda c:c['pcode'][0]['inputs'].__setitem__(1,const(16)),
                       lambda c:c['pcode'][1]['inputs'].__setitem__(1,reg('rbp')),
                       lambda c:c['pcode'][1]['inputs'].__setitem__(2,const(0x1006)),
                       lambda c:c['pcode'][1]['inputs'].__setitem__(2,const(0x1005,4)),
                       lambda c:c['pcode'][2]['inputs'].__setitem__(0,target(0x1021))]:
            c=call();mutate(c);cases.append(c)
        for c in cases:
            with self.assertRaises(ProjectionError):project([c],['rsp'])
        good=call();good['pcode'][2]['opcode']='CALLIND'
        with self.assertRaisesRegex(ProjectionError,'Unsupported p-code effect'):project([good],['rsp'])

    def test_selected_register_set_does_not_erase_return_address_store(self):
        result=project([call()],['rax']);self.assertEqual(len(result['stores']),1)
        self.assertEqual(result['path'][0]['directCall']['stackWriteBytes'],8);self.assertFalse(result['path'][0]['directCall']['calleeSummaryUsed'])

if __name__=='__main__':unittest.main(verbosity=2)
