"""Internal closed-template composition checks; no PE/decoder/solver executes."""
from pathlib import Path
import copy,random,sys,unittest
sys.path[:0]=[str(Path(__file__).resolve().parent),str(Path(__file__).resolve().parents[1]/'worker')]
from test_pcode_projection import GPRS,ProjectionError,RAM,const,flag,ins,op,reg,target,tmp
from projection_numerical_oracle import MASK,NAMES,projection_values,total_byte
from projection_composition import compose_paths,compose_until_exit

def instruction(*operations,ea,code='90',mnemonic='NOP'):
    return ins(*operations,ea=ea,code=code,mnemonic=mnemonic)
def mov(dst,src,ea):return instruction(op('COPY',reg(dst),reg(src)),ea=ea,code='4889d8',mnemonic='MOV')
def jump(ea,destination):return instruction(op('BRANCH',None,target(destination)),ea=ea,code='eb00',mnemonic='JMP')
def compare_loop():
    return [instruction(op('INT_SUB',reg('rbx'),reg('rbx'),const(1)),
                        op('INT_EQUAL',flag('zf'),reg('rbx'),const(0)),
                        ea=0x2000,code='4883eb01',mnemonic='SUB'),
            instruction(op('BOOL_NEGATE',tmp(0,1),flag('zf')),
                        op('CBRANCH',None,target(0x2000),tmp(0,1)),
                        ea=0x2004,code='75fa',mnemonic='JNZ')]
def values(result,initial=None,memory=None):
    initial=initial or {n:0 for n in NAMES};memory=memory or total_byte(0x434f4d50)
    v=projection_values(result,initial,memory)
    return {n:v[i] for n,i in result['registers'].items()},v

class CompositionTests(unittest.TestCase):
    def test_linear_state_is_substituted_instead_of_restarted(self):
        result=compose_paths([[mov('rax','rbx',0x1000)],[mov('rcx','rax',0x1003)]])
        state={n:random.Random(i).getrandbits(64) for i,n in enumerate(NAMES)}
        actual,v=values(result,state)
        self.assertEqual(actual,{**state,'rax':state['rbx'],'rcx':state['rbx']})
        self.assertEqual(v[result['pathGuard']],1)
        self.assertEqual(result['statistics']['logicalInstructions'],2)
        self.assertTrue(result['fitsPublicFixedPathLimits'])
        self.assertFalse(result['publicToolRouteExposed'])

    def test_ordered_aliases_use_previous_memory_with_wraparound(self):
        a=instruction(op('STORE',None,RAM,reg('rdi'),reg('rax')),ea=0x1000,code='488907',mnemonic='MOV')
        b=instruction(op('LOAD',reg('rcx'),RAM,reg('rsi')),ea=0x1003,code='488b0e',mnemonic='MOV')
        result=compose_paths([[a],[b]])
        for offset in range(-7,8):
            state={n:0 for n in NAMES};state.update(rax=0x0123456789abcdef,rdi=MASK-3,rsi=(MASK-3+offset)&MASK)
            memory=total_byte(offset&MASK)
            overlay={(state['rdi']+i)&MASK:(state['rax']>>(8*i))&255 for i in range(8)}
            wanted=sum((overlay[(state['rsi']+i)&MASK] if (state['rsi']+i)&MASK in overlay else memory((state['rsi']+i)&MASK))<<(8*i) for i in range(8))
            actual,v=values(result,state,memory)
            self.assertEqual(actual['rcx'],wanted)
            self.assertEqual(v[result['currentMemory']],(memory,overlay))

    def test_register_partial_writes_cross_segment_boundaries(self):
        first=instruction(op('COPY',reg('rax',1,1),const(0xab,1)),ea=0x1000,code='b4ab',mnemonic='MOV')
        second=mov('rdx','rax',0x1002)
        result=compose_paths([[first],[second]])
        initial={n:0 for n in NAMES};initial['rax']=0x123456789abcdef0
        actual,_=values(result,initial)
        self.assertEqual(actual['rdx'],0x123456789abcabf0)

    def test_all_gprs_remain_live_at_every_template_exit(self):
        from test_pcode_bsf import bounded_bsf
        with self.assertRaisesRegex(ProjectionError,'Live BSF'):
            compose_paths([[bounded_bsf(64,'rax','rbx')],[instruction(op('COPY',reg('rax'),const(0)),ea=0x1004,code='b800000000',mnemonic='MOV')]])

    def test_initial_flag_dependency_cannot_cross_templates(self):
        first=instruction(op('COPY',flag('cf'),const(1,1)),ea=0x1000,code='f9',mnemonic='STC')
        second=instruction(op('COPY',reg('rax',1),flag('cf')),ea=0x1001,code='0f92c0',mnemonic='SETC')
        with self.assertRaisesRegex(ProjectionError,'initial architectural flags'):
            compose_paths([[first],[second]])

    def test_control_guard_and_side_exit_state_keep_store_before_branch(self):
        first=instruction(op('STORE',None,RAM,reg('rdi'),reg('rax')),
                          ea=0x1000,code='488907',mnemonic='MOV')
        branch=instruction(op('INT_EQUAL',tmp(0,1),reg('rcx'),const(0)),
                           op('CBRANCH',None,target(0x1010),tmp(0,1)),
                           ea=0x1003,code='e30b',mnemonic='JRCXZ')
        after=instruction(op('COPY',reg('rax'),const(0x55)),ea=0x1010,code='b855000000',mnemonic='MOV')
        result=compose_paths([[first,branch],[after]])
        self.assertEqual(len(result['sideExits']),1)
        for rcx in (0,1,MASK):
            initial={n:0 for n in NAMES};initial.update(rcx=rcx,rax=0x8877665544332211,rdi=0x4000)
            _,v=values(result,initial)
            self.assertEqual(v[result['pathGuard']],int(rcx==0))
            exit_=result['sideExits'][0]
            self.assertEqual(v[exit_['guard']],int(rcx!=0))
            self.assertEqual(v[exit_['registers']['rax']],initial['rax'])
            self.assertEqual(v[result['stores'][0]['guard']],1)
            self.assertEqual(v[exit_['currentMemory']][1][0x4000],0x11)

    def test_fixed_counter_loop_retains_all_iterations_and_known_exits(self):
        prefix=[instruction(op('COPY',reg('rbx'),const(3)),ea=0x1000,code='bb03000000',mnemonic='MOV'),jump(0x1005,0x2000)]
        after=[instruction(op('COPY',reg('rax'),reg('rbx')),ea=0x2006,code='4889d8',mnemonic='MOV')]
        loop=compare_loop();original=copy.deepcopy(loop)
        result=compose_paths([prefix,loop,loop,loop,after])
        actual,v=values(result)
        self.assertEqual(actual['rbx'],0);self.assertEqual(actual['rax'],0)
        self.assertEqual(loop,original)
        self.assertEqual(v[result['pathGuard']],1)
        self.assertEqual([v[e['guard']] for e in result['sideExits']],[0,0,0])
        self.assertEqual(result['statistics']['templates'],3)
        self.assertEqual(result['statistics']['logicalInstructions'],9)
        self.assertFalse(result['fitsPublicFixedPathLimits'])

    def test_wrong_loop_count_remains_false_guard_not_success(self):
        prefix=[instruction(op('COPY',reg('rbx'),const(3)),ea=0x1000,code='bb03000000',mnemonic='MOV'),jump(0x1005,0x2000)]
        after=[instruction(op('COPY',reg('rax'),reg('rbx')),ea=0x2006,code='4889d8',mnemonic='MOV')]
        result=compose_paths([prefix,compare_loop(),compare_loop(),after])
        _,v=values(result)
        self.assertEqual(v[result['pathGuard']],0)
        self.assertEqual(v[result['sideExits'][-1]['guard']],1)

    def test_free_counter_keeps_input_dependent_guards(self):
        result=compose_paths([compare_loop(),compare_loop()])
        for counter in (0,1,2,3,MASK):
            initial={n:0 for n in NAMES};initial['rbx']=counter
            actual,v=values(result,initial)
            self.assertEqual(v[result['pathGuard']],int(counter!=1))
            self.assertEqual(actual['rbx'],(counter-2)&MASK)

    def test_same_target_conditional_is_not_arbitrarily_selected(self):
        branch=instruction(op('INT_EQUAL',tmp(0,1),reg('rcx'),const(0)),op('CBRANCH',None,target(0x1002),tmp(0,1)),ea=0x1000,code='e300',mnemonic='JRCXZ')
        with self.assertRaisesRegex(ProjectionError,'exactly one side'):
            compose_paths([[branch],[instruction(ea=0x1002)]])

    def test_direct_gap_indirect_middle_and_local_repeat_rejected(self):
        for paths in ([[jump(0x1000,0x2000)],[instruction(ea=0x2001)]],
                      [[instruction(op('BRANCHIND',None,reg('rax')),ea=0x1000,code='ffe0',mnemonic='JMP')],[instruction(ea=0x2000)]],
                      [[jump(0x1000,0x1000),jump(0x1000,0x1000)]]):
            with self.assertRaises(ProjectionError):compose_paths(paths)

    def test_conflicting_decodes_at_same_address_rejected(self):
        first=[jump(0x1000,0x1000)];second=copy.deepcopy(first);second[0]['codeBytes']='ebfe'
        with self.assertRaisesRegex(ProjectionError,'conflicting bytes/p-code'):
            compose_paths([first,second])

    def test_extra_caller_annotations_do_not_authorize_missing_bytes(self):
        item=jump(0x1000,0x1000);item['codeBytes']=None
        item['certificate']={'verified':True,'frameRegisterBytes':[]}
        with self.assertRaisesRegex(ProjectionError,'bound bytes required'):compose_paths([[item]])

    def test_step_and_expanded_memory_budgets_include_repetitions(self):
        with self.assertRaisesRegex(ProjectionError,'step budget'):
            compose_paths([[jump(0x1000,0x1000)]]*65)
        body=[instruction(op('LOAD',reg('rax'),RAM,reg('rdi')),
                          op('STORE',None,RAM,reg('rsi'),reg('rax')),ea=0x1000,code='488b07',mnemonic='MOV'),jump(0x1003,0x1000)]
        # 17 raw memory bytes per application, not16, to exceed1024 before64.
        body[0]['pcode'].insert(0,op('LOAD',reg('r8',1),RAM,reg('rdi')))
        with self.assertRaisesRegex(ProjectionError,'expanded memory byte budget'):
            compose_paths([body]*61)
        no_memory=[instruction(ea=0x1000+i) for i in range(16)]+[jump(0x1010,0x1000)]
        with self.assertRaisesRegex(ProjectionError,'logical instruction budget'):
            compose_paths([no_memory]*61)

    def test_unknown_effect_and_initial_flags_still_refused(self):
        with self.assertRaisesRegex(ProjectionError,'Unsupported p-code effect'):
            compose_paths([[instruction(op('CALLOTHER',None),ea=0x1000)]])
        with self.assertRaisesRegex(ProjectionError,'initial architectural flags'):
            compose_paths([[instruction(op('COPY',reg('rax',1),flag('zf')),ea=0x1000)]])

    def test_repeat_count_inferred_from_semantics_not_a_supplied_number(self):
        prefix=[instruction(op('COPY',reg('rbx'),const(3)),ea=0x1000,code='bb03000000',mnemonic='MOV'),jump(0x1005,0x2000)]+compare_loop()
        after=[[instruction(op('COPY',reg('rax'),reg('rbx')),ea=0x2006,code='4889d8',mnemonic='MOV')]]
        result=compose_until_exit(prefix,compare_loop(),after)
        actual,v=values(result)
        self.assertEqual(actual['rbx'],0);self.assertEqual(v[result['pathGuard']],1)
        self.assertEqual(result['inferredRepeat']['bodyApplicationsAfterPrefix'],2)
        self.assertEqual(result['inferredRepeat']['attempts'],3)
        self.assertFalse(result['inferredRepeat']['observedValuesUsed'])

    def test_repeat_count_unknown_or_nonterminating_stays_rejected(self):
        after=[[instruction(ea=0x2006)]]
        with self.assertRaisesRegex(ProjectionError,'constant closed-state condition'):
            compose_until_exit(compare_loop(),compare_loop(),after)
        prefix=[instruction(op('COPY',reg('rbx'),const(100)),ea=0x1000,code='bb64000000',mnemonic='MOV'),jump(0x1005,0x2000)]+compare_loop()
        with self.assertRaisesRegex(ProjectionError,'step budget'):
            compose_until_exit(prefix,compare_loop(),after)

    def test_repeat_inference_checks_suffix_and_cancellation(self):
        with self.assertRaisesRegex(ProjectionError,'header/exit'):
            compose_until_exit(compare_loop(),compare_loop(),[[instruction(ea=0x3000)]])
        def cancel():raise ValueError('cancelled')
        with self.assertRaisesRegex(ValueError,'cancelled'):
            compose_until_exit(compare_loop(),compare_loop(),[[instruction(ea=0x2006)]],cancel)

    def test_repeat_inference_can_exit_without_an_additional_body_application(self):
        prefix=[instruction(op('COPY',reg('rbx'),const(1)),ea=0x1000,code='bb01000000',mnemonic='MOV'),jump(0x1005,0x2000)]+compare_loop()
        result=compose_until_exit(prefix,compare_loop(),[[instruction(ea=0x2006)]])
        self.assertEqual(result['inferredRepeat']['bodyApplicationsAfterPrefix'],0)
        self.assertEqual(result['inferredRepeat']['attempts'],1)
        self.assertEqual(values(result)[1][result['pathGuard']],1)

    def test_repeat_inference_also_handles_fallthrough_back_to_body(self):
        sub=compare_loop()[0]
        branch=instruction(op('CBRANCH',None,target(0x3000),flag('zf')),ea=0x2004,code='7400',mnemonic='JZ')
        body=[instruction(ea=0x2006),jump(0x2007,0x2000),sub,branch]
        prefix=[instruction(op('COPY',reg('rbx'),const(3)),ea=0x1000,code='bb03000000',mnemonic='MOV'),jump(0x1005,0x2000),sub,branch]
        result=compose_until_exit(prefix,body,[[instruction(ea=0x3000)]])
        self.assertEqual(result['inferredRepeat']['bodyApplicationsAfterPrefix'],2)
        state,v=values(result);self.assertEqual(state['rbx'],0)
        self.assertEqual(v[result['pathGuard']],1)

    def test_guarded_indirect_requires_explicit_valid_mode_and_keeps_default(self):
        paths=[[instruction(op('BRANCHIND',None,reg('rax')),ea=0x1000,code='ffe0',mnemonic='JMP')],
               [instruction(ea=0x2000)]]
        with self.assertRaisesRegex(ProjectionError,'explicit guarded-target'):
            compose_paths(paths)
        for mode in (True,None,'guarded',''):
            with self.assertRaisesRegex(ProjectionError,'invalid indirect mode'):
                compose_paths(paths,indirect_mode=mode)
        result=compose_paths(paths,indirect_mode='guarded-target')
        self.assertEqual(result['schema'],'ig5-internal-guarded-target-composition-v1')
        self.assertFalse(result['publicToolRouteExposed'])
        for destination in (0,0x2000,0x2001,1<<63,MASK):
            state={n:0 for n in NAMES};state['rax']=destination
            actual,v=values(result,state)
            exit_=result['sideExits'][0]
            self.assertEqual(actual['rax'],destination)
            self.assertEqual(v[result['pathGuard']],int(destination==0x2000))
            self.assertEqual(v[exit_['guard']],int(destination!=0x2000))
            self.assertEqual(v[exit_['target']],destination)
            self.assertEqual(v[exit_['selectedTarget']],0x2000)
            self.assertEqual(v[exit_['selectionCondition']],int(destination==0x2000))

    def test_guarded_memory_target_reads_prior_write_and_keeps_store_entry_guard(self):
        store=instruction(op('STORE',None,RAM,reg('rdi'),reg('rax')),ea=0x1000,code='488907',mnemonic='MOV')
        branch=instruction(op('LOAD',tmp(),RAM,reg('rdi')),op('BRANCHIND',None,tmp()),ea=0x1003,code='ff27',mnemonic='JMP')
        after=instruction(op('STORE',None,RAM,reg('rsi'),reg('rbx')),ea=0x2000,code='48891e',mnemonic='MOV')
        result=compose_paths([[store,branch],[after]],indirect_mode='guarded-target')
        for destination in (0x2000,0x2001,MASK):
            state={n:0 for n in NAMES};state.update(rax=destination,rdi=MASK-3,rsi=MASK-1,rbx=0x8877665544332211)
            _,v=values(result,state)
            exit_=result['sideExits'][0]
            self.assertEqual(v[exit_['target']],destination)
            self.assertEqual(v[result['stores'][0]['guard']],1)
            self.assertEqual(v[result['stores'][1]['guard']],int(destination==0x2000))
            overlay={(state['rdi']+i)&MASK:(destination>>(8*i))&255 for i in range(8)}
            self.assertEqual(v[exit_['currentMemory']][1],overlay)

    def test_guarded_return_side_exit_retains_post_pop_stack_state(self):
        ret=instruction(op('LOAD',tmp(),RAM,reg('rsp')),
                        op('INT_ADD',reg('rsp'),reg('rsp'),const(8)),
                        op('RETURN',None,tmp()),ea=0x1000,code='c3',mnemonic='RET')
        after=instruction(op('COPY',reg('rsp'),const(0x55)),ea=0x2000,code='bc55000000',mnemonic='MOV')
        result=compose_paths([[ret],[after]],indirect_mode='guarded-target')
        for stack in (0,MASK-3,MASK):
            for destination in (0x2000,0x2001):
                initial={n:0 for n in NAMES};initial['rsp']=stack
                memory=total_byte(0,{(stack+i)&MASK:(destination>>(8*i))&255 for i in range(8)})
                actual,v=values(result,initial,memory);exit_=result['sideExits'][0]
                self.assertEqual(exit_['controlKind'],'return')
                self.assertEqual(v[exit_['registers']['rsp']],(stack+8)&MASK)
                self.assertEqual(v[exit_['target']],destination)
                self.assertEqual(v[exit_['guard']],int(destination!=0x2000))
                self.assertEqual(actual['rsp'],0x55)
                self.assertEqual(v[result['pathGuard']],int(destination==0x2000))

    def test_multiple_dynamic_exits_partition_guards_and_keep_each_state(self):
        first=instruction(op('BRANCHIND',None,reg('rax')),ea=0x1000,code='ffe0',mnemonic='JMP')
        second=[mov('rax','rbx',0x2000),instruction(op('BRANCHIND',None,reg('rdx')),ea=0x2003,code='ffe2',mnemonic='JMP')]
        last=instruction(op('STORE',None,RAM,reg('rdi'),reg('rax')),ea=0x3000,code='488907',mnemonic='MOV')
        result=compose_paths([[first],second,[last]],indirect_mode='guarded-target')
        for a,b in ((0x2000,0x3000),(0x2000,0x3001),(0x2001,0x3000),(0x2001,0x3001)):
            state={n:0 for n in NAMES};state.update(rax=a,rdx=b,rbx=0x77)
            _,v=values(result,state);left,right=result['sideExits']
            guards=[v[left['guard']],v[right['guard']],v[result['pathGuard']]]
            self.assertEqual(guards,[int(a!=0x2000),int(a==0x2000 and b!=0x3000),int(a==0x2000 and b==0x3000)])
            self.assertEqual(sum(guards),1)
            self.assertEqual(v[left['registers']['rax']],a)
            self.assertEqual(v[right['registers']['rax']],0x77)
            self.assertEqual(v[result['stores'][0]['guard']],guards[-1])

    def test_constant_target_mismatch_is_false_guard_and_live_alternate_exit(self):
        branch=instruction(op('COPY',reg('rax'),const(0x2001)),op('BRANCHIND',None,reg('rax')),ea=0x1000,code='ffe0',mnemonic='JMP')
        after=instruction(op('STORE',None,RAM,reg('rdi'),reg('rax')),ea=0x2000,code='488907',mnemonic='MOV')
        result=compose_paths([[branch],[after]],indirect_mode='guarded-target');_,v=values(result)
        self.assertEqual(v[result['pathGuard']],0)
        self.assertEqual(v[result['sideExits'][0]['guard']],1)
        self.assertEqual(v[result['stores'][0]['guard']],0)

    def test_conditional_before_dynamic_exit_keeps_exhaustive_ordered_guards(self):
        conditional=instruction(op('INT_EQUAL',tmp(0,1),reg('rcx'),const(0)),
                                op('CBRANCH',None,target(0x2000),tmp(0,1)),ea=0x1000,code='e300',mnemonic='JRCXZ')
        branch=instruction(op('BRANCHIND',None,reg('rax')),ea=0x2000,code='ffe0',mnemonic='JMP')
        result=compose_paths([[conditional],[branch],[instruction(ea=0x3000)]],indirect_mode='guarded-target')
        for counter,destination in ((0,0x3000),(0,0x3001),(1,0x3000),(1,0x3001)):
            state={n:0 for n in NAMES};state.update(rcx=counter,rax=destination)
            _,v=values(result,state)
            self.assertEqual([v[e['guard']] for e in result['sideExits']],
                             [int(counter!=0),int(counter==0 and destination!=0x3000)])
            self.assertEqual(sum(v[e['guard']] for e in result['sideExits'])+v[result['pathGuard']],1)


if __name__=='__main__':unittest.main()
