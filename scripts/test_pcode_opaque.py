"""Independent numerical/scope tests of conservative opaque effects; no CPU."""
import copy,json,random,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'worker'))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from pcode_projection import GPRS,ProjectionError,project
from projection_opaque import OpaqueRejected,match_effect,make_dag
from test_pcode_projection import evaluate,append_path,ins,op,reg,tmp,const,RAM

FIXTURE=json.loads((Path(__file__).parent/'fixtures/projection_opaque.json').read_text(encoding='utf-8'))
PUSH,TSC,BSWAP=FIXTURE['instructions']
MASK=(1<<64)-1


def concrete(report,registers,unknowns,memory=None):
    # The independent existing DAG interpreter treats a fresh unknown as an
    # unconstrained scalar input. It does not interpret replacement p-code.
    transformed=copy.deepcopy(report)
    for n in transformed['dag']['nodes']:
        if n['op']=='nondeterministic':n['op']='input'
    return evaluate(transformed,{**registers,**unknowns},memory)


def states(count=128):
    randomizer=random.Random(67241)
    for i in range(count):
        values={r:randomizer.getrandbits(64) for r in GPRS}
        if i<18:values['rsp']=[0,1,2,3,4,5,6,7,8,MASK,MASK-1,MASK-7,MASK-8,1<<63,0x1000,0x1007,0x1008,0x100f][i]
        yield values,randomizer.getrandbits(64)


class OpaqueTests(unittest.TestCase):
    def test_push_store_and_full_state_wrapping(self):
        result=project([PUSH],list(GPRS),mode='opaque-effects');name=result['dag']['nodes'][result['nondeterministicInputs'][0]['node']]['name']
        self.assertEqual(len(result['stores']),1);self.assertEqual(result['statistics']['pcodeOperations'],57)
        self.assertEqual(result['stores'][0]['pcodeIndex'],56);self.assertEqual(result['stores'][0]['replacementPcodeIndex'],2)
        for state,unknown in states():
            outputs,values=concrete(result,state,{name:unknown},{31:72});memory=values[result['currentMemory']]
            expected={**state,'rsp':(state['rsp']-8)&MASK};self.assertEqual(outputs,expected)
            want={31:72}
            for i in range(8):want[((state['rsp']-8)+i)&MASK]=(unknown>>(i*8))&255
            self.assertEqual(memory,want)
        self.assertFalse(result['scope'].get('architectureProved',False))

    def test_timestamp_whole64_clears_both_upper_halves(self):
        r=project([TSC],list(GPRS),mode='opaque-effects');n=r['dag']['nodes'][r['nondeterministicInputs'][0]['node']]['name']
        self.assertEqual(r['statistics']['pcodeOperations'],3);self.assertEqual(len(r['stores']),0)
        for state,unknown in states():
            outputs,*_=concrete(r,state,{n:unknown})
            self.assertEqual(outputs,{**state,'rax':unknown&0xffffffff,'rdx':unknown>>32})

    def test_bswap_all16_destinations_unknown_and_other_gprs_preserved(self):
        for number,name in enumerate(GPRS):
            b=copy.deepcopy(BSWAP);b['codeBytes']='66'+('41' if number>=8 else '')+'0f'+hex(0xc8+(number%8))[2:];b['size']=len(b['codeBytes'])//2
            for operation in b['pcode']:
                for v in [operation.get('output'),*operation['inputs']]:
                    if v and v['space']=='register':v['offset']=hex(GPRS[name])
            r=project([b],list(GPRS),mode='opaque-effects');n=r['dag']['nodes'][r['nondeterministicInputs'][0]['node']]['name']
            for state,unknown in states(16):
                outputs,*_=concrete(r,state,{n:unknown});self.assertEqual(outputs,{**state,name:unknown})
            for mode in ['strict','guarded-path']:
                with self.assertRaisesRegex(ProjectionError,'undefined 16-bit BSWAP'):project([b],['rsp' if name!='rsp' else 'rax'],mode=mode)

    def test_each_complete_raw_shape_is_required(self):
        for original in [PUSH,TSC,BSWAP]:
            for index in range(len(original['pcode'])):
                b=copy.deepcopy(original);b['pcode'][index]['unexpectedEffect']=True
                with self.assertRaises(OpaqueRejected):match_effect(b)
            for changed in [original['pcode'][:-1],original['pcode']+[original['pcode'][0]]]:
                b={**original,'pcode':changed}
                with self.assertRaises(OpaqueRejected):match_effect(b)

    def test_no_external_unknown_pseudo_op(self):
        b=ins(op('IG5_OPAQUE',reg('rax')),mnemonic='NOP',code='90')
        for mode in ['strict','guarded-path','opaque-effects']:
            with self.assertRaisesRegex(ProjectionError,'Unsupported p-code effect'):project([b],['rax'],mode=mode)

    def test_prefixed_push_and_rdtsc_refused(self):
        for original in [PUSH,TSC]:
            for prefix in ['66','67','40','f0','f2','f3','64']:
                b={**original,'codeBytes':prefix+original['codeBytes'],'size':original['size']+1}
                with self.assertRaises(ProjectionError):project([b],['rax'],mode='opaque-effects')

    def test_extra_bswap_prefixes_refused(self):
        for code in ['66660fc8','6641410fc8','41660fc8','66f30fc8','6641660fc8']:
            b={**BSWAP,'codeBytes':code,'size':len(code)//2}
            with self.assertRaises(ProjectionError):project([b],['rax'],mode='opaque-effects')

    def test_exact_same_stack_read_forwards_unknown(self):
        load=ins(op('LOAD',reg('rax'),RAM,reg('rsp')),mnemonic='MOV',code='488b0424')
        r=project(append_path(copy.deepcopy(PUSH),load),['rax','rsp'],mode='opaque-effects')
        self.assertEqual(r['registers']['rax'],r['nondeterministicInputs'][0]['node']);self.assertEqual(r['memoryNormalization']['forwardedBytes'],8)
        self.assertEqual(len(r['stores']),1)

    def test_different_address_bases_do_not_skip_unknown_alias(self):
        load=ins(op('LOAD',reg('rax'),RAM,reg('rcx')),mnemonic='MOV',code='488b01')
        r=project(append_path(copy.deepcopy(PUSH),load),['rax','rsp'],mode='opaque-effects')
        node=r['dag']['nodes'][r['registers']['rax']];self.assertEqual(node['op'],'load_le');self.assertEqual(node['args'][0],r['currentMemory'])
        self.assertEqual(r['memoryNormalization']['unknownAliasFallbacks'],1)
        name=r['dag']['nodes'][r['nondeterministicInputs'][0]['node']]['name']
        for state,unknown in states():
            for alias in [True,False]:
                state={**state,'rcx':((state['rsp']-8) if alias else state['rsp']+8192)&MASK}
                seed={((state['rcx']+i)&MASK):i+1 for i in range(8)}
                out,*_=concrete(r,state,{name:unknown},seed)
                self.assertEqual(out['rax'],unknown if alias else 0x0807060504030201)

    def test_unknown_values_are_fresh_at_each_instruction(self):
        second=copy.deepcopy(PUSH);r=project(append_path(copy.deepcopy(PUSH),second),['rsp'],mode='opaque-effects')
        ids=[x['node'] for x in r['nondeterministicInputs']];self.assertEqual(len(set(ids)),2)
        self.assertEqual([s['value'] for s in r['stores']],ids)
        names=[r['dag']['nodes'][n]['name'] for n in ids];self.assertNotEqual(*names)

    def test_legacy_strict_still_rejects_new_effects(self):
        for b in [PUSH,TSC,BSWAP]:
            for mode in ['strict','guarded-path']:
                with self.assertRaises(ProjectionError):project([b],['rax'],mode=mode)

    def test_unknown_not_a_way_to_supply_initial_flags(self):
        branch=ins(op('CBRANCH',None,{'space':'ram','offset':'0x1003','size':8},reg('rax',size=1)),mnemonic='JNZ',code='7501')
        branch['pcode'][0]['inputs'][1]={'space':'register','offset':'0x206','size':1}
        with self.assertRaisesRegex(ProjectionError,'initial architectural flags'):project([branch],['rax'],mode='opaque-effects')

    def test_same_old_budgets_and_no_unknown_effect_fallback(self):
        huge=copy.deepcopy(PUSH);huge['pcode']=huge['pcode']*3
        with self.assertRaisesRegex(ProjectionError,'Per-instruction'):project([huge],['rsp'],mode='opaque-effects')
        unsupported=ins(op('CALLOTHER',reg('rax'),const(42,4)),mnemonic='CPUID',code='0fa2')
        with self.assertRaisesRegex(ProjectionError,'CALLOTHER'):project([unsupported],['rax'],mode='opaque-effects')
        with self.assertRaisesRegex(ProjectionError,'Repeated'):project([PUSH,PUSH],['rsp'],mode='opaque-effects')

    def test_local_constant_width_shift_boundary_formulas(self):
        for bits in [8,16,32,64,128]:
            for x in [0,1,(1<<bits)-1,1<<(bits-1),(1<<(bits-1))-1]:
                for count in [0,1,bits-1,bits,bits+1,255]:
                    for kind in ['INT_LEFT','INT_RIGHT','INT_SRIGHT']:
                        d=make_dag(lambda:None);a=d.const(x,bits);b=d.const(count,64);n=d.make(kind,(a,b),bits);node=d.nodes[n]
                        signed=x-(1<<bits) if x&(1<<(bits-1)) else x
                        want=(x<<count if kind=='INT_LEFT' else x>>count if kind=='INT_RIGHT' else signed>>count)&((1<<bits)-1)
                        self.assertEqual(node['op'],'const');self.assertEqual(int(node['value'],16),want)


if __name__=='__main__':unittest.main(verbosity=2)
