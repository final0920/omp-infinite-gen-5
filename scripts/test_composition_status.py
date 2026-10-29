"""Stored status-image data crosses exact memory/GPR boundaries, never CPU flags."""
from pathlib import Path
import copy,json,random,sys,unittest
sys.path[:0]=[str(Path(__file__).resolve().parent),str(Path(__file__).resolve().parents[1]/'worker')]
from projection_composition import compose_paths,CompositionDag
from pcode_projection import project,ProjectionError,GPRS
from composition_selection import validate_plan
from test_pcode_status import ADD,PUSH,POP,TSC,BSWAP
from test_pcode_projection import append_path,ins,op,reg,const,flag
from test_projection_composition import jump
from projection_numerical_oracle import projection_values,total_byte,MASK

def chain(paths):return compose_paths(paths,representation='transition-chain',template_mode='opaque-status')
def loop(items,count=3):
    body=append_path(*copy.deepcopy(items));body.append(jump(int(body[-1]['ea'],16)+body[-1]['size'],int(body[0]['ea'],16)))
    return [body]*count
def constant_loop(count=3):
    a=ins(op('COPY',reg('rbx'),const(0)),mnemonic='MOV',code='48c7c300000000')
    b=ins(op('COPY',reg('r10'),const(0)),mnemonic='MOV',code='49c7c200000000')
    return loop([a,b,ADD,PUSH,POP],count)
def split():
    body=append_path(copy.deepcopy(ADD),copy.deepcopy(PUSH),copy.deepcopy(POP));return [body[:2],body[2:]]

class StatusCompositionTests(unittest.TestCase):
    def test_repeated_status_has_fresh_noise_and_complete_ordinary_state(self):
        c=chain(loop([ADD,PUSH,POP],4));self.assertEqual(c['schema'],'ig5-internal-opaque-status-transition-chain-v1')
        self.assertEqual(c['dag']['bindingCount'],72);self.assertEqual(len(c['templates']),1)
        self.assertEqual(len({x['node'] for x in c['nondeterministicInputs']}),4)
        self.assertNotIn('valueNode',c['templates'][0]['opaqueEffects'][0]['flagImageRefinement'])
        self.assertEqual(c['statistics']['expandedAbstractedRawOperations'],4*57)
        rng=random.Random(0x73746174757332)
        for sample in range(256):
            initial={n:rng.getrandbits(64) for n in GPRS};initial['rsp']=[0,1,MASK-7,MASK,4096][sample%5]
            unknown={f'step_{i}_opaque_1':rng.getrandbits(64) for i in range(4)};origin=total_byte(sample)
            values=projection_values(c,initial,origin,unknowns=unknown);state=dict(initial);overlay={}
            for i,layer in enumerate(c['layers']):
                a,b=state['rbx'],state['r10'];s=(a+b)&MASK
                flags=int(a+b>MASK)|(int((s&255).bit_count()%2==0)<<2)|(int(s==0)<<6)|((s>>63)<<7)|(int(((a^s)&(b^s))>>63!=0)<<11)
                image=(unknown[f'step_{i}_opaque_1']&(MASK^0x8c5))|flags;state.update(rbx=s,r10=image)
                self.assertEqual({n:values[node] for n,node in layer['registers'].items()},state)
                overlay.update({(initial['rsp']-8+j)&MASK:(image>>(8*j))&255 for j in range(8)})
                self.assertEqual(values[layer['currentMemory']],(origin,dict(overlay)))
                self.assertEqual(values[layer['flagImages'][0]['valueNode']],image)
                self.assertEqual(values[layer['pathGuard']],1)
            self.assertEqual(values[c['currentMemory']],(origin,overlay));self.assertEqual(len(c['stores']),4)

    def test_flag_image_survives_memory_binding_without_cpu_flag_export(self):
        c=chain(split());initial={n:0 for n in GPRS};initial.update(rsp=3,rbx=MASK,r10=1)
        v=projection_values(c,initial,total_byte(1),unknowns={'step_0_opaque_1':16})
        self.assertEqual(v[c['registers']['r10']],0x55);self.assertEqual(v[c['registers']['rbx']],0)
        self.assertEqual(v[c['registers']['rsp']],3);self.assertEqual(len(c['layers'][1]['flagImages']),0)
        self.assertEqual(c['templates'][0]['flagsExported'],False)

    def test_constants_do_not_share_overlay_nodes_across_layers(self):
        c=chain(constant_loop())
        for step,layer in enumerate(c['layers']):
            root=layer['flagImages'][0]['valueNode'];self.assertEqual(c['dag']['nodes'][root]['statusOverlayStep'],step)
            self.assertTrue(layer['nodeStart']<=root<layer['nodeEnd'])
        initial={n:0 for n in GPRS};initial['rsp']=16
        v=projection_values(c,initial,total_byte(3),unknowns={f'step_{i}_opaque_3':16*i for i in range(3)})
        self.assertEqual(v[c['registers']['r10']],0x64)

    def test_cpu_flags_still_require_local_definitions(self):
        clc=ins(op('COPY',flag('cf'),const(0,1)),mnemonic='CLC',code='f8')
        use=ins(op('COPY',reg('rax',1),flag('cf')),mnemonic='SETC',code='0f92c0')
        rows=append_path(clc,use)
        with self.assertRaisesRegex(ProjectionError,'initial architectural flags'):chain([[rows[0]],[rows[1]]])
        rows=append_path(copy.deepcopy(ADD),copy.deepcopy(PUSH));c=chain([[rows[0]],[rows[1]]])
        self.assertEqual(c['templates'][1]['opaqueEffects'][0]['unknownBits'],64)
        self.assertEqual(c['templates'][1]['opaqueEffects'][0]['flagImageRefinement']['knownFlags'],[])

    def test_whole_unknown_timestamp_and_bswap_remain_fresh(self):
        for item in (PUSH,TSC,BSWAP):
            c=chain(loop([item]));self.assertEqual(len(c['nondeterministicInputs']),3)
            for layer in c['layers']:self.assertEqual(len(layer['flagImages']),int(item['mnemonic']=='PUSHFQ'))
            if item['mnemonic']=='PUSHFQ':
                for layer,x in zip(c['layers'],c['nondeterministicInputs']):self.assertEqual(layer['flagImages'][0]['valueNode'],x['node'])

    def test_new_mode_opt_in_and_original_budgets(self):
        base={'strategy':'sequence','paths':[['0x1000']],'representation':'transition-chain','template_mode':'opaque-status'}
        self.assertEqual(validate_plan(base)['template_mode'],'opaque-status')
        for extra in ({'representation':'flat'},{'strategy':'constant-loop'},{'initial_flags':'0x0'},{'flagImages':[]},{'observed_values':{}}):
            with self.assertRaises(ValueError):validate_plan({**base,**extra})
        with self.assertRaises(ProjectionError):compose_paths(loop([PUSH]),template_mode='opaque-status')
        with self.assertRaisesRegex(ProjectionError,'budget'):chain(loop([ADD,PUSH,POP],64))
        self.assertEqual(chain(split())['unchangedPublicProjectionLimits']['instructions'],128)

    def test_shared_store_visit_budget_remains_monotone(self):
        account=CompositionDag(lambda:None).memory_normalization;account['storeVisits']=4095
        rows=append_path(copy.deepcopy(ADD),copy.deepcopy(PUSH),copy.deepcopy(POP))
        a=project(rows,list(GPRS),mode='opaque-status',_memory_account=account);b=project(rows,list(GPRS),mode='opaque-status',_memory_account=account)
        self.assertEqual(a['memoryNormalization']['storeVisits'],4096);self.assertEqual(b['memoryNormalization']['storeVisits'],4096)
        self.assertGreater(b['memoryNormalization']['budgetFallbacks'],0)

def fixtures():
    return [{'core':chain(paths),'paths':[[r['ea'] for r in p] for p in paths]} for paths in
            (loop([ADD,PUSH,POP],4),split(),constant_loop(),loop([PUSH]),loop([TSC]),loop([BSWAP]))]

if __name__=='__main__':
    if '--fixtures' in sys.argv:print(json.dumps(fixtures(),separators=(',',':')))
    else:unittest.main()
