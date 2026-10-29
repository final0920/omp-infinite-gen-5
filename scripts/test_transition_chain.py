"""State-binding regression and independent ordinary-memory numeric checks."""
from pathlib import Path
import json, random, sys, unittest
sys.path[:0] = [str(Path(__file__).resolve().parent), str(Path(__file__).resolve().parents[1] / 'worker')]
from test_projection_composition import instruction, jump, mov
from test_pcode_projection import RAM, const, flag, op, reg, target, tmp, ProjectionError
from projection_composition import compose_paths
from composition_selection import validate_plan
from projection_numerical_oracle import MASK, NAMES, total_byte, projection_values

def walking():
    return [instruction(op('LOAD',reg('rax'),RAM,reg('rax')),ea=0x1000,code='488b00',mnemonic='MOV'),
            instruction(op('INT_ADD',reg('rax'),reg('rax'),const(8)),ea=0x1003,code='4883c008',mnemonic='ADD'),
            jump(0x1007,0x1000)]

def aliases():
    a=instruction(op('STORE',None,RAM,reg('rdi'),reg('rax')),ea=0x2000,code='488907',mnemonic='MOV')
    b=instruction(op('LOAD',reg('rcx'),RAM,reg('rsi')),ea=0x2003,code='488b0e',mnemonic='MOV')
    return [[a],[b]]

def returned():
    ret=instruction(op('LOAD',tmp(),RAM,reg('rsp')),op('INT_ADD',reg('rsp'),reg('rsp'),const(8)),
                    op('RETURN',None,tmp()),ea=0x3000,code='c3',mnemonic='RET')
    return [[ret],[mov('rax','rsp',0x4000)]]

def conditional():
    a=instruction(op('INT_EQUAL',flag('zf'),reg('rax'),const(0)),ea=0x5000,code='4883f800',mnemonic='CMP')
    b=instruction(op('CBRANCH',None,target(0x6000),flag('zf')),ea=0x5004,code='7400',mnemonic='JZ')
    return [[a,b],[mov('rax','rsp',0x6000)]]

def translated(paths,**options):
    return compose_paths(paths,representation='transition-chain',**options)

def view(report,initial,memory):
    v=projection_values(report,initial,memory)
    return ({n:v[i] for n,i in report['registers'].items()},v[report['currentMemory']],v[report['pathGuard']],
        [{**{k:v[b[k]] for k in ('entryGuard','continuedGuard','currentMemory')},
          'registers':{n:v[i] for n,i in b['registers'].items()}} for b in report['boundaries']],
        [{k:v[s[k]] for k in ('address','value','beforeMemory','afterMemory','guard')} for s in report['stores']],
        [{**{k:v[e[k]] for k in ('guard','target','currentMemory')},
          'registers':{n:v[i] for n,i in e['registers'].items()}} for e in report['sideExits']])

class ChainTests(unittest.TestCase):
    def test_long_chain_retains_budgets_and_reports_expanded_depth(self):
        paths=[walking()]*64
        with self.assertRaisesRegex(ProjectionError,'DAG depth budget exceeded'):compose_paths(paths)
        result=translated(paths)
        self.assertLessEqual(result['dag']['depth'],128)
        self.assertGreater(result['dag']['expandedDependencyDepth'],128)
        self.assertEqual(result['dag']['bindingCount'],1152)
        self.assertLessEqual(len(result['dag']['nodes']),2048)
        self.assertLessEqual(result['dag']['references'],8192)
        rng=random.Random(0x7472616e)
        for sample in range(64):
            initial={n:rng.getrandbits(64) for n in NAMES};memory=total_byte(sample)
            want=dict(initial)
            for _ in paths:want['rax']=(sum(memory((want['rax']+i)&MASK)<<(8*i) for i in range(8))+8)&MASK
            actual=view(result,initial,memory)
            self.assertEqual(actual[0],want);self.assertEqual(actual[1],(memory,{}));self.assertEqual(actual[2],1)

    def test_cross_layer_aliases_and_wrap_match_flat_and_independent_memory(self):
        paths=aliases();chain=translated(paths);flat=compose_paths(paths)
        for delta in range(-8,9):
            for base in (0,1,MASK-3,MASK):
                initial={n:0 for n in NAMES};initial.update(rax=0x123456789abcdef0,rdi=base,rsi=(base+delta)&MASK)
                memory=total_byte(delta&MASK);c=view(chain,initial,memory)
                self.assertEqual(c,view(flat,initial,memory))
                writes={(base+i)&MASK:(initial['rax']>>(8*i))&255 for i in range(8)}
                want=sum((writes.get((initial['rsi']+i)&MASK,memory((initial['rsi']+i)&MASK)))<<(8*i) for i in range(8))
                self.assertEqual(c[0]['rcx'],want);self.assertEqual(c[1],(memory,writes))

    def test_dynamic_return_exits_keep_post_pop_state_on_both_sides(self):
        paths=returned();chain=translated(paths,indirect_mode='guarded-target');flat=compose_paths(paths,indirect_mode='guarded-target')
        for destination in (0x4000,0,0xffffffffffffffff):
            initial={n:MASK-3 for n in NAMES};memory=total_byte(1,{(initial['rsp']+i)&MASK:(destination>>(8*i))&255 for i in range(8)})
            c=view(chain,initial,memory);self.assertEqual(c,view(flat,initial,memory))
            self.assertEqual(c[2],int(destination==0x4000));self.assertEqual(c[5][0]['registers']['rsp'],4)
            self.assertEqual(c[5][0]['guard'],int(destination!=0x4000))

    def test_conditional_paths_match_flat_without_reachability_assumption(self):
        for value in (0,1,MASK):
            initial={n:value for n in NAMES};memory=total_byte(value)
            self.assertEqual(view(translated(conditional()),initial,memory),view(compose_paths(conditional()),initial,memory))

    def test_new_option_does_not_supply_flags_or_opaque_values(self):
        p=instruction(op('COPY',reg('rax',1),flag('cf')),ea=0x1000,code='0f92c0',mnemonic='SETC')
        with self.assertRaisesRegex(ProjectionError,'initial architectural flags'):translated([[p]])
        with self.assertRaisesRegex(ProjectionError,'explicit guarded-target'):translated(returned())

    def test_plan_option_is_explicit_sequence_only_and_address_only(self):
        base={'strategy':'sequence','paths':[['0x1000']],'representation':'transition-chain'}
        self.assertEqual(validate_plan(base)['representation'],'transition-chain')
        for value in (None,True,{},'chain'):
            with self.assertRaises(ValueError):validate_plan({**base,'representation':value})
        with self.assertRaisesRegex(ValueError,'explicit sequence'):
            validate_plan({'strategy':'constant-loop','prefix':['0x1000'],'body':['0x1000'],'suffix':[['0x1000']],'representation':'transition-chain'})
        with self.assertRaises(ValueError):validate_plan({**base,'binding_values':{}})

    def test_cancellation_remains_cooperative_and_original_budgets_reject(self):
        count=0
        def stop():
            nonlocal count
            count+=1
            if count==250:raise RuntimeError('cancelled test')
        with self.assertRaisesRegex(RuntimeError,'cancelled test'):compose_paths([walking()]*64,stop,representation='transition-chain')
        with self.assertRaisesRegex(ProjectionError,'step budget'):translated([walking()]*65)

def fixtures():
    return [{'core':translated(paths,**options),'paths':[[row['ea'] for row in path] for path in paths],**options}
        for paths,options in [([walking()]*64,{}),(aliases(),{}),(returned(),{'indirect_mode':'guarded-target'}),(conditional(),{})]]

if __name__=='__main__':
    if '--fixtures' in sys.argv:print(json.dumps(fixtures(),separators=(',',':')))
    else:unittest.main()
