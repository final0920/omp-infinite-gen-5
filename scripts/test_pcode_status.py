"""Independent ordinary-state/math checks of the explicit status overlay."""
import copy,json,random,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'worker'),str(ROOT/'scripts')]
from pcode_projection import GPRS,ProjectionError,project
from test_pcode_projection import append_path,ins,op,reg,const,tmp
from test_pcode_opaque import PUSH,TSC,BSWAP
from projection_numerical_oracle import MASK,total_byte,projection_values

ADD=json.loads((Path(__file__).parent/'fixtures/projection_status.json').read_text(encoding='utf8'))['instructions']['add64']
BARRIERS=json.loads((Path(__file__).parent/'fixtures/projection_status_barriers.json').read_text(encoding='utf8'))['instructions']
POP=ins(op('LOAD',reg('r10'),{'kind':'address-space','space':'ram','spaceId':3},reg('rsp')),op('INT_ADD',reg('rsp'),reg('rsp'),const(8)),mnemonic='POP',code='415a')


class StatusTests(unittest.TestCase):
    def test_undefined_and_unmodeled_overlap_is_blocked_until_redefinition(self):
        for barrier in BARRIERS:
            report=project(append_path(copy.deepcopy(barrier),copy.deepcopy(ADD),copy.deepcopy(PUSH),copy.deepcopy(POP)),list(GPRS),mode='opaque-status')
            p=report['flagPolicies'][0];self.assertIn('of',p['undefined']);self.assertIn('of',p['unmodeled'])
            e=report['opaqueEffects'][0];self.assertEqual(e['unknownBits'],59)
            self.assertTrue(all(x['definitionInstructionIndex']==1 for x in e['flagImageRefinement']['knownFlags']))
            use=ins(op('BOOL_NEGATE',reg('rax',1),{'space':'register','offset':'0x20b','size':1}),mnemonic='SETNO',code='0f91c0')
            for mode in ('strict','opaque-effects','opaque-status'):
                with self.assertRaisesRegex(ProjectionError,'Undefined/unmodeled'):
                    project(append_path(copy.deepcopy(barrier),copy.deepcopy(use)),['rax'],mode=mode)

    def test_add_push_pop_all16_memory_and_five_status_bits(self):
        report=project(append_path(copy.deepcopy(ADD),copy.deepcopy(PUSH),copy.deepcopy(POP)),list(GPRS),mode='opaque-status')
        e=report['opaqueEffects'][0];self.assertEqual(e['replacementOperationCount'],24)
        self.assertEqual(e['unknownBits'],59);self.assertEqual(e['flagImageRefinement']['freshInputBits'],64)
        self.assertEqual(e['flagImageRefinement']['knownMask'],'0x8c5');self.assertEqual(e['flagImageRefinement']['unknownMask'],'0xfffffffffffff73a')
        self.assertEqual([x['name'] for x in e['flagImageRefinement']['knownFlags']],['cf','pf','zf','sf','of'])
        self.assertTrue(all(x['definitionInstructionIndex']==0 for x in e['flagImageRefinement']['knownFlags']))
        rng=random.Random(0x737461747573);edges=[0,1,2,7,8,(1<<63)-1,1<<63,MASK-7,MASK-1,MASK]
        pairs=[(a,b) for a in edges for b in edges]+[(rng.getrandbits(64),rng.getrandbits(64)) for _ in range(256)]
        name=report['dag']['nodes'][report['nondeterministicInputs'][0]['node']]['name']
        for i,(a,b) in enumerate(pairs):
            state={n:rng.getrandbits(64) for n in GPRS};state.update(rbx=a,r10=b,rsp=edges[i%len(edges)])
            U=rng.getrandbits(64);memory=total_byte(rng.getrandbits(64));values=projection_values(report,state,memory,unknowns={name:U});s=(a+b)&MASK
            cf=int(a+b>MASK);pf=int((s&255).bit_count()%2==0);zf=int(s==0);sf=s>>63;of=int(((a^s)&(b^s))>>63!=0)
            image=(U&(MASK^0x8c5))|cf|(pf<<2)|(zf<<6)|(sf<<7)|(of<<11)
            outputs={n:values[node] for n,node in report['registers'].items()}
            self.assertEqual(outputs,{**state,'rbx':s,'r10':image})
            original,overlay=values[report['currentMemory']];self.assertIs(original,memory)
            self.assertEqual(overlay,{(state['rsp']-8+j)&MASK:(image>>(8*j))&255 for j in range(8)})
        self.assertEqual(len(pairs),356)

    def test_no_prior_definition_keeps_whole_image_free(self):
        report=project([copy.deepcopy(PUSH)],list(GPRS),mode='opaque-status');effect=report['opaqueEffects'][0]
        self.assertEqual(effect['flagImageRefinement']['knownFlags'],[]);self.assertEqual(effect['flagImageRefinement']['knownMask'],'0x0')
        self.assertEqual(effect['replacementOperationCount'],3);self.assertEqual(report['stores'][0]['value'],report['nondeterministicInputs'][0]['node'])

    def test_unmodeled_af_and_ambient_bits_remain_free(self):
        report=project(append_path(copy.deepcopy(ADD),copy.deepcopy(PUSH),copy.deepcopy(POP)),list(GPRS),mode='opaque-status')
        name=report['dag']['nodes'][report['nondeterministicInputs'][0]['node']]['name'];state={n:0 for n in GPRS};state['rsp']=4096
        results=[]
        for U in (0,16,1<<60,16|(1<<60)):
            v=projection_values(report,state,total_byte(7),unknowns={name:U});results.append(v[report['registers']['r10']]);self.assertEqual(results[-1]&0x8c5,0x44)
        self.assertEqual(results,[0x44,0x54,(1<<60)|0x44,(1<<60)|0x54])

    def test_unknown_instruction_clears_definition_provenance(self):
        unknown=ins(op('COPY',reg('r12'),reg('r12')),mnemonic='UNCLASSIFIED',code='90')
        report=project(append_path(copy.deepcopy(ADD),unknown,copy.deepcopy(PUSH)),list(GPRS),mode='opaque-status')
        self.assertEqual(report['opaqueEffects'][0]['flagImageRefinement']['knownFlags'],[])

    def test_carry_requires_definition_and_preserved_flags_keep_source(self):
        clc=ins(op('COPY',{'space':'register','offset':'0x200','size':1},const(0,1)),mnemonic='CLC',code='f8')
        cmc=ins(op('BOOL_NEGATE',{'space':'register','offset':'0x200','size':1},{'space':'register','offset':'0x200','size':1}),mnemonic='CMC',code='f5')
        unknown=project(append_path(copy.deepcopy(cmc),copy.deepcopy(PUSH)),['rsp'],mode='opaque-status')
        self.assertEqual(unknown['opaqueEffects'][0]['flagImageRefinement']['knownFlags'],[])
        report=project(append_path(clc,cmc,copy.deepcopy(PUSH)),['rsp'],mode='opaque-status')
        self.assertEqual(report['opaqueEffects'][0]['flagImageRefinement']['knownFlags'],[{'name':'cf','bit':0,'definitionInstructionIndex':1}])
        name=report['dag']['nodes'][report['nondeterministicInputs'][0]['node']]['name']
        v=projection_values(report,{n:0 for n in GPRS},total_byte(9),unknowns={name:0});self.assertEqual(v[report['stores'][0]['value']],1)

    def test_old_opaque_mode_unchanged_and_no_initial_flag_route(self):
        report=project(append_path(copy.deepcopy(ADD),copy.deepcopy(PUSH)),list(GPRS),mode='opaque-effects')
        self.assertNotIn('flagImageRefinement',report['opaqueEffects'][0]);self.assertEqual(report['opaqueEffects'][0]['replacementOperationCount'],3)
        raw=ins(op('IG5_OPAQUE',reg('rax')),mnemonic='NOP',code='90')
        with self.assertRaises(ProjectionError):project([raw],['rax'],mode='opaque-status')
        adc=ins(op('INT_ZEXT',tmp(),{'space':'register','offset':'0x200','size':1}),op('INT_ADD',reg('rax'),reg('rax'),tmp()),mnemonic='ADC',code='4811c8')
        with self.assertRaisesRegex(ProjectionError,'Undefined/unmodeled|initial architectural flags'):project(append_path(adc,copy.deepcopy(PUSH)),['rax'],mode='opaque-status')
        for item in (TSC,BSWAP):
            r=project([copy.deepcopy(item)],list(GPRS),mode='opaque-status');self.assertNotIn('flagImageRefinement',r['opaqueEffects'][0])


if __name__=='__main__':unittest.main()
