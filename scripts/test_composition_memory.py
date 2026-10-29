"""Independent ordered-byte checks of composition LOAD normalization."""
from pathlib import Path
import random,sys,unittest
sys.path[:0]=[str(Path(__file__).resolve().parent),str(Path(__file__).resolve().parents[1]/'worker')]
from projection_composition import CompositionDag,compose_until_exit
from composition_memory import MASK,STORE_VISIT_LIMIT,address_form
from projection_numerical_oracle import NAMES,projection_values,total_byte
from test_pcode_projection import RAM,const,flag,ins,op,reg,target,tmp

def setup(check=lambda:None):
    d=CompositionDag(check)
    inputs={n:d.make('input',bits=64,name=n) for n in NAMES}
    memory=d.make('initial_memory',name='M0',addressBits=64,elementBits=8)
    return d,inputs,memory

def add(d,base,offset):return d.make('INT_ADD',(base,d.const(offset,64)),64)
def store(d,m,a,v,size):return d.make('store_le',(m,a,v),size=size)
def load(d,m,a,size):return d.make('load_le',(m,a),size*8,size=size)
def evaluate(d,initial,memory):return projection_values({'dag':{'nodes':d.nodes}},initial,memory)
def expected(initial_byte,writes,address,size):
    overlay={}
    for a,v,n in writes:
        for i in range(n):overlay[(a+i)&MASK]=(v>>(8*i))&255
    return sum((overlay[(address+i)&MASK] if (address+i)&MASK in overlay else initial_byte((address+i)&MASK))<<(8*i) for i in range(size))

class MemoryNormalizationTests(unittest.TestCase):
    def test_all_widths_overlaps_and_disjoint_offsets_with_uint64_wrap(self):
        rng=random.Random(0x4d454d46)
        for width in range(1,17):
            for size in range(1,17):
                for delta in range(-17,18):
                    d,r,m=setup();value=d.extract(d.concat([r['rbx'],r['rax']]),0,width*8)
                    m1=store(d,m,r['rdi'],value,width);address=add(d,r['rdi'],delta);out=load(d,m1,address,size)
                    for base in (0,1,MASK-7,MASK,rng.getrandbits(64)):
                        state={n:rng.getrandbits(64) for n in NAMES};state['rdi']=base;memory=total_byte(rng.getrandbits(64))
                        values=evaluate(d,state,memory);v=((state['rbx']<<64)|state['rax'])&((1<<(width*8))-1)
                        self.assertEqual(values[out],expected(memory,[(base,v,width)],(base+delta)&MASK,size),(width,size,delta,base))
                        self.assertEqual(values[m1][1],{(base+i)&MASK:(v>>(8*i))&255 for i in range(width)})
        # 8960 distinct width/offset cases, each checked at five arbitrary/wrap bases.

    def test_latest_partial_store_wins_and_earlier_other_bytes_survive(self):
        d,r,m=setup();m=store(d,m,r['rdi'],r['rax'],8)
        m=store(d,m,add(d,r['rdi'],3),d.extract(r['rbx'],0,16),2)
        out=load(d,m,r['rdi'],8);self.assertNotEqual(d.nodes[out]['op'],'load_le')
        for base in (0,MASK-3,MASK):
            state={n:(0x0123456789abcdef if n=='rax' else 0xfedcba9876543210) for n in NAMES};state['rdi']=base
            memory=total_byte(base);self.assertEqual(evaluate(d,state,memory)[out],expected(memory,[(base,state['rax'],8),((base+3)&MASK,state['rbx']&65535,2)],base,8))

    def test_unknown_new_store_blocks_forwarding_from_older_matching_store(self):
        d,r,m=setup();m=store(d,m,r['rdi'],r['rax'],8);m=store(d,m,r['rsi'],r['rbx'],8)
        out=load(d,m,r['rdi'],8);self.assertEqual(d.nodes[out]['op'],'load_le');self.assertEqual(d.nodes[out]['args'][0],m)
        self.assertEqual(d.memory_normalization['unknownAliasFallbacks'],1)
        for delta in range(-9,10):
            state={n:0x0123456789abcdef if n=='rax' else 0xfedcba9876543210 for n in NAMES};state.update(rdi=MASK-3,rsi=(MASK-3+delta)&MASK)
            memory=total_byte(delta&MASK);self.assertEqual(evaluate(d,state,memory)[out],expected(memory,[(state['rdi'],state['rax'],8),(state['rsi'],state['rbx'],8)],state['rdi'],8))

    def test_known_disjoint_store_is_skipped_without_assuming_other_bases_disjoint(self):
        d,r,m=setup();m1=store(d,m,r['rdi'],r['rax'],8);m2=store(d,m1,add(d,r['rdi'],96),r['rbx'],8)
        self.assertEqual(load(d,m2,r['rdi'],8),r['rax']);self.assertEqual(d.memory_normalization['disjointStoreBypasses'],1)
        unknown=add(d,r['rsi'],96);out=load(d,m2,unknown,8)
        self.assertEqual(d.nodes[out]['op'],'load_le');self.assertEqual(d.nodes[out]['args'][0],m2)

    def test_only_full_width_constant_affine_address_structure_is_recognized(self):
        d,r,m=setup();a=d.make('INT_SUB',(add(d,r['rdi'],0x123),d.const(0x127,64)),64)
        b=d.make('INT_ADD',(d.const(MASK-3,64),r['rdi']),64)
        self.assertEqual(address_form(d,a),address_form(d,b))
        m1=store(d,m,a,r['rax'],8);self.assertEqual(load(d,m1,b,8),r['rax'])
        opaque=d.make('INT_AND',(r['rdi'],d.const(MASK^15,64)),64)
        out=load(d,m1,opaque,8);self.assertEqual(d.nodes[out]['op'],'load_le')
        narrowed=d.make('INT_ZEXT',(d.extract(r['rdi'],0,32),),64)
        self.assertNotEqual(address_form(d,narrowed),address_form(d,r['rdi']))

    def test_absolute_addresses_wrap_exactly_and_never_become_file_constants(self):
        d,r,m=setup();m=store(d,m,d.const(MASK-3,64),r['rax'],8);out=load(d,m,d.const(0,64),8)
        state={n:0x123456789abcdef0 for n in NAMES};memory=total_byte(123)
        self.assertEqual(evaluate(d,state,memory)[out],expected(memory,[(MASK-3,state['rax'],8)],0,8))
        self.assertTrue(any(n['op']=='load_le' and n['args'][0]==0+len(NAMES) for n in d.nodes))

    def test_optimization_work_exhaustion_preserves_the_complete_original_read(self):
        d,r,m=setup()
        for i in range(32):m=store(d,m,d.const(i*16,64),d.extract(r['rax'],0,8),1)
        outputs=[load(d,m,d.const(0x10000+i*16,64),8) for i in range(160)]
        self.assertEqual(d.memory_normalization['storeVisits'],STORE_VISIT_LIMIT)
        self.assertGreater(d.memory_normalization['budgetFallbacks'],0)
        self.assertEqual(d.nodes[outputs[-1]]['op'],'load_le');self.assertEqual(d.nodes[outputs[-1]]['args'][0],m)
        state={n:0 for n in NAMES};memory=total_byte(99);values=evaluate(d,state,memory)
        for i,out in enumerate(outputs):self.assertEqual(values[out],expected(memory,[],0x10000+i*16,8))

    def test_cached_reads_and_cancellation_do_not_change_the_memory(self):
        d,r,m=setup();m=store(d,m,r['rdi'],r['rax'],8);out=load(d,m,r['rdi'],8)
        self.assertEqual(load(d,m,r['rdi'],8),out);self.assertEqual(d.memory_normalization['cacheHits'],1)
        def cancel():raise RuntimeError('cancelled normalization')
        d.check=cancel
        with self.assertRaisesRegex(RuntimeError,'cancelled'):load(d,m,r['rdi'],8)

    def test_memory_controlled_finite_loop_closes_without_initial_memory_or_observations(self):
        first=ins(op('STORE',None,RAM,reg('rdi'),const(3,1)),ea=0x1000,code='c60703',mnemonic='MOV')
        body=[ins(op('LOAD',reg('rax',1),RAM,reg('rdi')),ea=0x1003,code='8a07',mnemonic='MOV'),
              ins(op('INT_SUB',reg('rax',1),reg('rax',1),const(1,1)),op('INT_EQUAL',flag('zf'),reg('rax',1),const(0,1)),ea=0x1005,code='2c01',mnemonic='SUB'),
              ins(op('STORE',None,RAM,reg('rdi'),reg('rax',1)),ea=0x1007,code='8807',mnemonic='MOV'),
              ins(op('BOOL_NEGATE',tmp(0,1),flag('zf')),op('CBRANCH',None,target(0x1003),tmp(0,1)),ea=0x1009,code='75f8',mnemonic='JNZ')]
        suffix=[ins(op('LOAD',reg('rax',1),RAM,reg('rdi')),ea=0x100b,code='8a07',mnemonic='MOV')]
        result=compose_until_exit([first]+body,body,[suffix]);self.assertEqual(result['inferredRepeat']['bodyApplicationsAfterPrefix'],2)
        self.assertEqual(result['statistics']['expandedMemoryBytes'],8);self.assertEqual(len(result['stores']),4)
        self.assertGreater(result['memoryNormalization']['forwardedBytes'],0)
        for base in (0,1,MASK):
            state={n:0x123456789abcdef0 for n in NAMES};state['rdi']=base;memory=total_byte(base)
            values=projection_values(result,state,memory);self.assertEqual(values[result['registers']['rax']],state['rax']&~255)
            self.assertEqual(values[result['currentMemory']],(memory,{base:0}))

if __name__=='__main__':unittest.main(verbosity=2)
