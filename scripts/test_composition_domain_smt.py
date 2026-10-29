"""Encoder regressions plus optional pinned, owned-process SMT controls."""
from pathlib import Path
import argparse,copy,json,sys,time,unittest
MAIN=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(MAIN/'worker'),str(MAIN/'scripts')]
from composition_domain_smt import ARRAY,Queries,bv,encode,read,store

def node(op,args=(),bits=64,**fields):
    return {'op':op,'args':list(args),'type':'memory' if bits is None else 'bv',**({} if bits is None else {'bits':bits}),**fields}
def core(rows):
    rows=copy.deepcopy(rows);depth=[]
    for i,n in enumerate(rows):n['id']=i;depth.append(1+max([0]+[depth[j] for j in n['args']]))
    return {'dag':{'nodes':rows,'depth':max(depth),'references':sum(len(n['args'])+int(n['op']=='state_binding') for n in rows)}}
def binding_fixture():
    return core([node('input',name='rax'),node('const',value='0x1'),node('INT_ADD',[0,1]),
        node('state_binding',source=2),node('INT_ADD',[3,1])])
def memory_fixture():
    return core([node('initial_memory',bits=None,addressBits=64,elementBits=8),node('input',name='rsp'),
        node('load_le',[0,1],size=8),node('load_le',[0,1],size=8)])

class EncoderTests(unittest.TestCase):
    def test_binding_retains_complete_source_equality(self):
        lines,roots,meta=encode(binding_fixture(),[4]);text='\n'.join(lines)
        self.assertIn('(assert (= n3 n2))',text);self.assertNotIn('I_n3',text)
        self.assertEqual(roots,['n4']);self.assertTrue(meta['wholeSourceDagValidated'])

    def test_iterative_long_chain_never_introduces_free_state(self):
        rows=[node('input',name='rax'),node('const',value='0x1')]
        for i in range(256):rows += [node('INT_ADD',[len(rows)-2 if i==0 else len(rows)-1,1]),node('state_binding',source=len(rows))]
        c=core(rows);lines,roots,_=encode(c,[len(rows)-1])
        self.assertEqual(c['dag']['depth'],2);self.assertEqual(sum('(assert (= n' in x for x in lines),len(rows))
        self.assertEqual(sum('I_rax' in x for x in lines),2)

    def test_cuts_do_not_hide_corrupt_binding_sources(self):
        for source in (3,4,True,-1):
            c=binding_fixture();c['dag']['nodes'][3]['source']=source
            with self.assertRaises(AssertionError):encode(c,[3],cuts={3:bv(7)})

    def test_unreachable_corruption_is_rejected(self):
        c=binding_fixture();c['dag']['nodes'][4]['args']=[4,1]
        with self.assertRaises(AssertionError):encode(c,[0])

    def test_type_width_and_arity_are_checked_before_cuts(self):
        for changes in ({'bits':32},{'type':'memory','bits':None},{'args':[0]}):
            c=binding_fixture();c['dag']['nodes'][3].update(changes)
            with self.assertRaises(AssertionError):encode(c,[3],cuts={3:bv(7)})

    def test_load_cuts_are_fresh_typed_weakening(self):
        c=memory_fixture();before=copy.deepcopy(c);lines,roots,meta=encode(c,[2,3],cut_loads=True)
        self.assertEqual(roots,['free_load_2','free_load_3']);self.assertEqual(meta['weakenedLoadNodes'],[2,3])
        self.assertIn('(declare-const free_load_2 (_ BitVec 64))',lines);self.assertEqual(c,before)

    def test_load_cut_does_not_hide_bad_size_or_memory(self):
        for changes in ({'size':True},{'size':4},{'args':[1,1]}):
            c=memory_fixture();c['dag']['nodes'][2].update(changes)
            with self.assertRaises(AssertionError):encode(c,[2],cut_loads=True)

    def test_initial_memory_is_arbitrary_coherent_array(self):
        lines,_,_=encode(memory_fixture(),[2]);text='\n'.join(lines)
        self.assertIn('(declare-const M0 '+ARRAY+')',text);self.assertNotIn('as const',text)
        self.assertIn('(select n0',text)

    def test_unsupported_operation_cannot_hide_behind_cut(self):
        c=binding_fixture();c['dag']['nodes'][4]['op']='CALL'
        with self.assertRaisesRegex(ValueError,'Unsupported'):encode(c,[4],cuts={4:bv(0)})

    def test_original_node_reference_and_depth_limits_remain(self):
        for key,value in [('references',8193),('depth',129),('references',0)]:
            c=binding_fixture();c['dag'][key]=value
            with self.assertRaises(AssertionError):encode(c,[0])
        c=core([node('input',name='rax')]*2049)
        with self.assertRaises(AssertionError):encode(c,[0])

    def test_constant_overflow_and_non_integer_ids_rejected(self):
        for changes in ({'value':'0x10000000000000000'},{'bits':True},{'id':True}):
            c=binding_fixture();c['dag']['nodes'][1].update(changes)
            with self.assertRaises(AssertionError):encode(c,[0])

    def test_unsigned_less_and_not_equal_are_typed_boolean_values(self):
        for op,spelling in [('INT_LESS','bvult'),('INT_NOTEQUAL','distinct')]:
            c=core([node('input',name='rax'),node('input',name='rbx'),node(op,[0,1],bits=8)])
            lines,roots,_=encode(c,[2]);self.assertIn(f'(assert (= n2 (ite ({spelling} n0 n1) {bv(1,8)} {bv(0,8)})))',lines)
            for changes in ({'bits':64},{'args':[0]},{'args':[0,2]}):
                changed=copy.deepcopy(c);changed['dag']['nodes'][2].update(changes)
                with self.assertRaises(AssertionError):encode(changed,[0])
            c['dag']['nodes'][1]['bits']=32
            with self.assertRaises(AssertionError):encode(c,[2])

def smt(out):
    q=Queries(MAIN,out/'queries',time.monotonic()+45)
    try:
        declaration=f'(declare-const M {ARRAY})\n'
        word=bv(0x12345678,32);address=bv((1<<64)-2)
        loaded=read(store('M',address,word,4),address,4)
        q.expect(q.query('wrapping-little-endian-write-read',declaration+f'(assert (distinct {loaded} {word}))'))
        q.expect(q.query('negative-wrong-endian-is-not-equivalent',declaration+f'(assert (distinct {loaded} {bv(0x78563412,32)}))','sat'))
        lines,roots,_=encode(binding_fixture(),[3]);body='\n'.join(lines)
        predicate=f'(assert (distinct {roots[0]} (bvadd I_rax {bv(1)})))'
        q.expect(q.query('binding-definition-is-an-equality',body+'\n'+predicate))
        omitted='\n'.join(line for line in lines if line!='(assert (= n3 n2))')
        q.expect(q.query('negative-omitted-binding-equality-is-free',omitted+'\n'+predicate,'sat'))
        lines,roots,_=encode(memory_fixture(),[2,3]);predicate=f'(assert (distinct {roots[0]} {roots[1]}))'
        q.expect(q.query('same-memory-same-address-coherent','\n'.join(lines)+'\n'+predicate))
        lines,roots,_=encode(memory_fixture(),[2,3],cut_loads=True)
        q.expect(q.query('negative-cut-loads-are-independent','\n'.join(lines)+f'\n(assert (distinct {roots[0]} {roots[1]}))','sat'))
        q.expect(q.query('negative-unconstrained-memory-is-not-zero',f'(declare-const M0 {ARRAY})\n(assert (distinct (select M0 {bv(0)}) {bv(0,8)}))','sat'))
        for op,spelling in [('INT_LESS','bvult'),('INT_NOTEQUAL','distinct')]:
            c=core([node('input',name='rax'),node('input',name='rbx'),node(op,[0,1],bits=8)])
            lines,roots,_=encode(c,[2]);body='\n'.join(lines)
            q.expect(q.query('typed-'+op.lower().replace('_','-'),body+f'\n(assert (distinct {roots[0]} (ite ({spelling} I_rax I_rbx) {bv(1,8)} {bv(0,8)})))'))
        c=core([node('input',name='rax'),node('input',name='rbx'),node('INT_LESS',[0,1],bits=8)])
        lines,roots,_=encode(c,[2]);q.expect(q.query('negative-unsigned-is-not-signed','\n'.join(lines)+f'\n(assert (distinct {roots[0]} (ite (bvslt I_rax I_rbx) {bv(1,8)} {bv(0,8)})))','sat'))
        result={'passed':True,'queries':q.rows,'solverDllSha256':q.dll_sha,'nativeTargetExecuted':False,'businessAccepted':False}
        (out/'verified.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
    finally:q.close()

if __name__=='__main__':
    if '--smt' not in sys.argv:unittest.main()
    else:
        parser=argparse.ArgumentParser();parser.add_argument('--smt',action='store_true');parser.add_argument('--child',action='store_true');parser.add_argument('--out',required=True);args=parser.parse_args()
        out=Path(args.out);assert out.is_absolute()
        if args.child:smt(out)
        else:
            from lift_process import run_owned
            from lift_runtime import locked_file
            out.mkdir(exist_ok=False);job=out/'job';job.mkdir()
            result=run_owned(str(MAIN/'runtimes/ghidra/python/python.exe'),['-I','-B','-X','utf8',str(Path(__file__)),*sys.argv[1:],'--child'],job,budget_ms=50000)
            (out/'process.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
            assert result['childExitConfirmed'] and result['jobAssignedAtCreation']
            with locked_file(job/'stderr.log',4*1024**2) as raw:error=raw.decode('utf8')
            assert result['exitCode']==0,error
            print(json.dumps({'passed':True,'queries':10,'process':result}))
