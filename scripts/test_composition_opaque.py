"""Explicit conservative-chain scope, freshness, ordinary memory and budgets."""
from pathlib import Path
import copy,json,random,sys,unittest
sys.path[:0]=[str(Path(__file__).resolve().parent),str(Path(__file__).resolve().parents[1]/'worker')]
from projection_composition import compose_paths,CompositionDag
from pcode_projection import project,ProjectionError,GPRS
from composition_selection import validate_plan
from test_projection_composition import instruction,jump
from test_pcode_projection import op,reg,flag,const,RAM,tmp
from projection_numerical_oracle import projection_values,total_byte,MASK
FIXTURE=json.loads((Path(__file__).parent/'fixtures/projection_opaque.json').read_bytes())['instructions']

def repeated(effect,count=3):
    row=copy.deepcopy(FIXTURE[effect]);row['ea']='0x1000'
    return [[row,jump(0x1000+row['size'],0x1000)]]*count

def chain(paths):return compose_paths(paths,representation='transition-chain',template_mode='opaque-effects')

class OpaqueCompositionTests(unittest.TestCase):
    def test_repeated_pushes_have_independent_values_full_ordered_memory_and_wrap(self):
        paths=repeated(0,16);result=chain(paths)
        self.assertEqual(result['schema'],'ig5-internal-opaque-transition-chain-v1')
        self.assertEqual(len(result['templates']),1);self.assertEqual(len(result['nondeterministicInputs']),16)
        self.assertEqual(result['statistics']['expandedAbstractedInstructions'],16)
        self.assertEqual(result['statistics']['expandedAbstractedRawOperations'],16*57)
        self.assertEqual(result['statistics']['expandedMemoryBytes'],128)
        self.assertEqual(len({x['node'] for x in result['nondeterministicInputs']}),16)
        rng=random.Random(0x6f706171)
        for sample in range(64):
            initial={n:rng.getrandbits(64) for n in GPRS};initial['rsp']=(MASK-3 if sample%2 else 32)
            unknowns={result['dag']['nodes'][x['node']]['name']:rng.getrandbits(64) for x in result['nondeterministicInputs']}
            memory=total_byte(sample);values=projection_values(result,initial,memory,unknowns=unknowns);overlay={}
            for step,store in enumerate(result['stores']):
                value=unknowns[f'step_{step}_opaque_0'];address=(initial['rsp']-8*(step+1))&MASK
                self.assertEqual(store['pcodeIndex'],56);self.assertEqual(store['replacementPcodeIndex'],2)
                self.assertEqual((values[store['address']],values[store['value']],values[store['guard']]),(address,value,1))
                for j in range(8):overlay[(address+j)&MASK]=(value>>(8*j))&255
            self.assertEqual(values[result['currentMemory']],(memory,overlay))
            actual={n:values[x] for n,x in result['registers'].items()}
            self.assertEqual(actual,{**initial,'rsp':(initial['rsp']-128)&MASK})

    def test_repeated_timestamp_and_bswap_do_not_reuse_cached_unknown(self):
        for effect in (1,2):
            result=chain(repeated(effect));self.assertEqual(len(result['nondeterministicInputs']),3)
            initial={n:MASK for n in GPRS};unknowns={f'step_{s}_opaque_0':0x123456789abcdef0+s for s in range(3)}
            values=projection_values(result,initial,total_byte(1),unknowns=unknowns)
            for step,b in enumerate(result['boundaries']):
                state={n:values[x] for n,x in b['registers'].items()};value=unknowns[f'step_{step}_opaque_0']
                if effect==1:self.assertEqual(state,{**initial,'rax':value&0xffffffff,'rdx':value>>32})
                else:
                    self.assertEqual(FIXTURE[2]['codeBytes'],'660fc8')
                    self.assertEqual(state,{**initial,'rax':value})

    def test_original_strict_and_unsupported_flags_keep_rejecting(self):
        with self.assertRaises(ProjectionError):compose_paths(repeated(0),representation='transition-chain')
        live=instruction(op('COPY',reg('rax',1),flag('cf')),ea=0x1000,code='0f92c0',mnemonic='SETC')
        with self.assertRaisesRegex(ProjectionError,'initial architectural flags'):chain([[live]])
        bad=copy.deepcopy(repeated(0));bad[0][0]['pcode'][-1]['inputs'][2]['size']=4
        with self.assertRaisesRegex(ProjectionError,'shape mismatch'):chain(bad)

    def test_opt_in_requires_chain_sequence_and_rejects_observations(self):
        base={'strategy':'sequence','paths':[['0x1000']],'template_mode':'opaque-effects','representation':'transition-chain'}
        self.assertEqual(validate_plan(base)['template_mode'],'opaque-effects')
        for update in ({'representation':'flat'},{'template_mode':None},{'template_mode':True},{'unknown_values':{}},{'summaries':[]}):
            with self.assertRaises(ValueError):validate_plan({**base,**update})
        with self.assertRaises(ProjectionError):compose_paths(repeated(0),template_mode='opaque-effects')

    def test_shared_normalization_account_cannot_reset_between_templates(self):
        push=copy.deepcopy(FIXTURE[0]);pop=instruction(op('LOAD',reg('rax'),RAM,reg('rsp')),
            op('INT_ADD',reg('rsp'),reg('rsp'),const(8)),ea=int(push['ea'],16)+1,code='58',mnemonic='POP')
        account=CompositionDag(lambda:None).memory_normalization;account['storeVisits']=4095
        first=project([push,pop],list(GPRS),mode='opaque-effects',_memory_account=account)
        second=project([push,pop],list(GPRS),mode='opaque-effects',_memory_account=account)
        self.assertEqual(first['memoryNormalization']['storeVisits'],4096)
        self.assertEqual(second['memoryNormalization']['storeVisits'],4096)
        self.assertGreater(second['memoryNormalization']['budgetFallbacks'],0)
        self.assertTrue(any(n['op']=='load_le' for n in second['dag']['nodes']))

    def test_aliasing_unknown_writes_must_affect_following_template_load(self):
        push=copy.deepcopy(FIXTURE[0]);push['ea']='0x1000'
        load=instruction(op('LOAD',reg('rax'),RAM,reg('rsp')),ea=0x1001,code='488b0424',mnemonic='MOV')
        result=chain([[push],[load]]);initial={n:0 for n in GPRS};initial['rsp']=3
        values=projection_values(result,initial,total_byte(7),unknowns={'step_0_opaque_0':0xabcddcba12345678})
        self.assertEqual(values[result['registers']['rax']],0xabcddcba12345678)

def fixtures():return [{'core':chain(paths),'paths':[[r['ea'] for r in p] for p in paths]}
    for paths in (repeated(0,3),repeated(1,3),repeated(2,3))]
if __name__=='__main__':
    if '--fixtures' in sys.argv:print(json.dumps(fixtures(),separators=(',',':')))
    else:unittest.main()
