"""Bounded independent array/bitvector lemmas, never target execution.

Uses the installed pinned Triton solver. This verifies mathematical memory/DAG
rewrites, not machine decoding, native reachability or protected business.
"""
from pathlib import Path
import hashlib,json,sys,time
MAIN=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(MAIN/'worker'),str(MAIN/'scripts')]
from trace_analysis import load_triton
from projection_composition import CompositionDag

if len(sys.argv)!=2:raise SystemExit('Usage: test_composition_memory_smt.py NEW-ABSOLUTE-OUTPUT-DIRECTORY')
OUT=Path(sys.argv[1]);assert OUT.is_absolute() and not OUT.exists();OUT.mkdir()
tt=load_triton();ctx=tt.TritonContext(tt.ARCH.X86_64);ast=ctx.getAstContext()
ctx.setSolverTimeout(2000);ctx.setSolverMemoryLimit(512)
deadline=time.monotonic()+50;queries=[]
def check():
    if time.monotonic()>=deadline:raise ValueError('Shared local SMT deadline exceeded')
def bind(p):
    p=Path(p);b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def variable(name,bits):return ast.variable(ctx.newSymbolicVariable(bits,name))
def concat(values):return values[0] if len(values)==1 else ast.concat(values)
def write(memory,address,value,size):
    for i in range(size):memory=ast.store(memory,address+ast.bv(i,64),ast.extract(i*8+7,i*8,value))
    return memory
def read(memory,address,size):return concat([ast.select(memory,address+ast.bv(i,64)) for i in reversed(range(size))])
memory_projections=[]
def finite_memory(name,addresses):
    # Triton ast.array starts at zero. Seed EVERY possible initial-read point
    # in this query with a free byte. The remainder is never read. Ordered SMT
    # stores keep alias consistency; every total initial byte map has a choice
    # of these free bytes (assign byte_i=M(address_i)), including equal points.
    result=ast.array(64)
    for index,address in enumerate(addresses):result=ast.store(result,address,variable(name+'_initial_byte_'+str(index),8))
    memory_projections.append({'name':name,'initialReadPoints':len(addresses),'otherAddressesRead':False,
        'method':'free byte per finite queried address; alias consistency from SMT stores; zero remainder unobserved'})
    return result
def prove(name,formula,expected):
    check();assert len(queries)<128
    text=str(formula).encode('ascii');assert len(text)<=1024**2
    p=OUT/(name+'.smt.txt');p.write_bytes(text)
    model,status,elapsed=ctx.getModel(formula,status=True,timeout=2000)
    label={tt.SOLVER_STATE.SAT:'sat',tt.SOLVER_STATE.UNSAT:'unsat',tt.SOLVER_STATE.TIMEOUT:'timeout',tt.SOLVER_STATE.UNKNOWN:'unknown'}.get(status,'unknown')
    row={'name':name,'status':label,'expected':expected,'solverMs':elapsed,'formula':bind(p),
         'scalarWitness':{v.getVariable().getAlias():hex(v.getValue()) for v in model.values()} if label=='sat' else None}
    queries.append(row);(OUT/'queries-progress.json').write_text(json.dumps(queries,indent=2)+'\n',encoding='utf-8')
    check()
    assert label==expected,row

a,b=variable('address_a',64),variable('address_b',64);value=variable('store_value',128)
memory=finite_memory('array-probe',[a,b])
# Confirm queried bytes are arbitrary, nonuniform and consistent, not zero fill.
prove('array-can-be-nonzero',ast.distinct(ast.select(memory,a),ast.bv(0,8)),'sat')
prove('array-can-be-nonuniform',ast.land([ast.distinct(a,b),ast.distinct(ast.select(memory,a),ast.select(memory,b))]),'sat')
prove('array-same-address-consistency',ast.distinct(ast.select(memory,a),ast.select(memory,a)),'unsat')
for size in range(1,17):
    memory=finite_memory('byte-lemma-'+str(size),[b])
    # Same arbitrary A/B/value coverage without a 128-bit variable barrel
    # shift. Newest-write order is explicit; each addressed byte is selected
    # independently. Affine modular address equalities are checked below.
    candidate=ast.select(memory,b)
    for index in range(size):
        candidate=ast.ite(ast.equal(b,a+ast.bv(index,64)),ast.extract(index*8+7,index*8,value),candidate)
    prove('read-newest-store-byte-width-'+str(size),ast.distinct(ast.select(write(memory,a,value,size),b),candidate),'unsat')
c1,c2=variable('offset_1',64),variable('offset_2',64)
prove('uint64-add-offset-grouping',ast.distinct((a+c1)+c2,a+(c1+c2)),'unsat')
prove('uint64-sub-offset-grouping',ast.distinct((a+c1)-c2,a+(c1-c2)),'unsat')
prove('uint64-constant-left-add',ast.distinct(c1+a,a+c1),'unsat')
prove('uint64-relative-offset-identity',ast.distinct(a+(b-a),b),'unsat')

def scenario(name,stores,load_offset,load_size,other_base=False):
    d=CompositionDag(check);ids={n:d.make('input',bits=64,name=n) for n in ('rax','rbx','rdi','rsi')}
    initial=d.make('initial_memory',name='M0',addressBits=64,elementBits=8);current=initial
    symbols={n:variable(name+'_'+n,64) for n in ids};base='rsi' if other_base else 'rdi'
    selected=symbols[base]+ast.bv(load_offset&((1<<64)-1),64)
    memory=finite_memory(name,[selected+ast.bv(i,64) for i in range(load_size)]);original=memory
    for base,offset,source,size in stores:
        pointer=d.make('INT_ADD',(ids[base],d.const(offset,64)),64)
        v=d.extract(ids[source],0,size*8);current=d.make('store_le',(current,pointer,v),size=size)
        original=write(original,symbols[base]+ast.bv(offset&((1<<64)-1),64),symbols[source],size)
    pointer=d.make('INT_ADD',(ids[base],d.const(load_offset,64)),64)
    output=d.make('load_le',(current,pointer),load_size*8,size=load_size)
    evaluated=[]
    for n in d.nodes:
        check();children=[evaluated[i] for i in n['args']];op=n['op']
        if op=='input':v=symbols[n['name']]
        elif op=='initial_memory':v=memory
        elif op=='const':v=ast.bv(int(n['value'],16),n['bits'])
        elif op=='INT_ADD':v=children[0]+children[1]
        elif op=='INT_SUB':v=children[0]-children[1]
        elif op=='extract':v=ast.extract(n['offset']+n['bits']-1,n['offset'],children[0])
        elif op=='concat':v=concat(children)
        elif op=='store_le':v=write(children[0],children[1],children[2],n['size'])
        elif op=='load_le':v=read(children[0],children[1],n['size'])
        else:raise ValueError('Unexpected local memory DAG operator: '+op)
        evaluated.append(v)
    wanted=read(original,symbols[base]+ast.bv(load_offset&((1<<64)-1),64),load_size)
    prove(name,ast.distinct(evaluated[output],wanted),'unsat')
    return {'name':name,'normalization':d.memory_normalization,'dagNodes':len(d.nodes)}

scenarios=[scenario('actual-dag-exact-full-store',[('rdi',0,'rax',8)],0,8),
 scenario('actual-dag-narrow-inside-store',[('rdi',0,'rax',8)],3,2),
 scenario('actual-dag-partial-before-store',[('rdi',0,'rax',8)],-3,8),
 scenario('actual-dag-partial-after-store',[('rdi',0,'rax',8)],5,8),
 scenario('actual-dag-newest-partial-overwrite',[('rdi',0,'rax',8),('rdi',3,'rbx',2)],0,8),
 scenario('actual-dag-proven-disjoint-write',[('rdi',0,'rax',8),('rdi',16,'rbx',8)],0,8),
 scenario('actual-dag-unknown-alias-barrier',[('rdi',0,'rax',8),('rsi',0,'rbx',8)],0,8),
 scenario('actual-dag-wrapping-offset',[('rdi',-4,'rax',8)],0,8)]
memory=finite_memory('negative-controls',[a+ast.bv(i,64) for i in range(8)])
prove('negative-use-pre-store-memory',ast.distinct(read(write(memory,a,value,8),a,8),read(memory,a,8)),'sat')
patched=write(write(memory,a,value,8),a+ast.bv(3,64),ast.bv(0x55,8),1)
prove('negative-ignore-latest-narrow-store',ast.distinct(read(patched,a,8),ast.extract(63,0,value)),'sat')
unknown=write(write(memory,a,value,8),b,ast.bv(0,64),8)
prove('negative-assume-unknown-bases-disjoint',ast.distinct(read(unknown,a,8),ast.extract(63,0,value)),'sat')
reversed_bytes=concat([ast.extract(i*8+7,i*8,value) for i in range(8)])
prove('negative-reverse-little-endian-bytes',ast.distinct(read(write(memory,a,value,8),a,8),reversed_bytes),'sat')
result={'schema':'ig5-local-memory-normalization-smt-v1','status':'passed-local-mathematical-memory-lemmas',
 'queries':queries,'unsat':sum(q['status']=='unsat' for q in queries),'sat':sum(q['status']=='sat' for q in queries),
 'scenarios':scenarios,'initialMemoryProjections':memory_projections,'limits':{'queries':128,'eachTimeoutMs':2000,'solverMemoryMiB':512,'sharedSeconds':50},
 'sourcePins':[bind(MAIN/p) for p in ('worker/composition_memory.py','worker/projection_composition.py','worker/pcode_projection.py','worker/trace_analysis.py','worker/trace_vendor/ig5-manifest.json','scripts/test_composition_memory_smt.py')],
 'documentation':'https://triton-library.github.io/documentation/doxygen/py_AstContext_page.html',
 'scope':'Every initial-read point in each finite formula has a free byte, with SMT-array alias consistency; the unobserved array remainder is zero. This finite projection represents every total byte memory at all queried addresses, by assigning each free byte its value from that memory, also when addresses coincide. Unconstrained full-width scalar roots and wrapping little-endian stores/loads. Local rewrites only; no decoder/CPU/OS/code-fetch/reachability/business proof. SAT negatives are mathematical counterexamples, never native executions.',
 'architectureProved':False,'nativeTargetExecuted':False,'businessAccepted':False,'wholeBinaryVerified':False}
(OUT/'verified.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':result['status'],'queries':len(queries),'unsat':result['unsat'],'sat':result['sat']}))
