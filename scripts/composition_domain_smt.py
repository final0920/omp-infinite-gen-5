"""Bounded SMT encoding of saved state chains; never execute target bytes.

Bindings receive complete source equalities. Optional LOAD cuts are fresh
unconstrained values: a weakening suitable for universal address bounds only.
Explicit semantic cuts must be justified by separately identified certificates.
"""
from contextlib import ExitStack
from pathlib import Path
import ctypes as C,hashlib,json,re,time

ARRAY='(Array (_ BitVec 64) (_ BitVec 8))'
TRACE_PIN='65bf673f1c4304cc2c09076e3b96e368da9e0df72aa0badeba0c2a5cae392934'
GPRS='rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15'.split()
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def bv(value,bits=64):return f'(_ bv{value%(1<<bits)} {bits})'
def add(a,b):return f'(bvadd {a} {b})'
def sub(a,b):return f'(bvsub {a} {b})'
def concat(values):
    assert values
    result=values[-1]
    for v in reversed(values[:-1]):result=f'(concat {v} {result})'
    return result
def read(memory,address,size):return concat([f'(select {memory} {add(address,bv(i))})' for i in reversed(range(size))])
def store(memory,address,value,size):
    for i in range(size):memory=f'(store {memory} {add(address,bv(i))} ((_ extract {8*i+7} {8*i}) {value}))'
    return memory

def validate(core):
    """Check the entire source DAG, including definitions hidden by proof cuts.

    This validates this encoder's finite operation subset, not host provenance.
    A source binding resets retained depth only; its equality is still required.
    """
    dag=core['dag'];nodes=dag['nodes'];assert type(nodes) is list and 1<=len(nodes)<=2048
    assert type(dag['references']) is int and 0<=dag['references']<=8192
    assert type(dag['depth']) is int and 1<=dag['depth']<=128
    references=0;depths=[]
    for i,n in enumerate(nodes):
        assert type(n) is dict and type(n['id']) is int and n['id']==i
        args=n['args'];assert type(args) is list
        assert all(type(j) is int and 0<=j<i for j in args)
        op=n['op'];kind=n['type'];bits=n.get('bits');assert kind in ('bv','memory')
        assert (type(bits) is int and 1<=bits<=128) if kind=='bv' else bits is None
        source=[]
        if op=='state_binding':
            j=n['source'];assert type(j) is int and 0<=j<i and not args
            assert (nodes[j]['type'],nodes[j].get('bits'))==(kind,bits);source=[j]
        def shape(count,output='bv'):
            assert len(args)==count and kind==output
        def bv_args():assert all(nodes[j]['type']=='bv' for j in args)
        if op=='input':shape(0);assert n['name'] in GPRS and bits==64
        elif op=='nondeterministic':shape(0);assert bits==64
        elif op=='initial_memory':shape(0,'memory');assert n['addressBits']==64 and n['elementBits']==8
        elif op=='const':
            shape(0);assert type(n['value']) is str and re.fullmatch(r'0x[0-9a-fA-F]+',n['value'])
            assert 0<=int(n['value'],16)<1<<bits
        elif op=='state_binding':pass
        elif op in ('INT_ADD','INT_SUB','INT_MULT','INT_AND','INT_OR','INT_XOR'):
            shape(2);bv_args();assert all(nodes[j]['bits']==bits for j in args)
        elif op=='extract':
            shape(1);bv_args();assert type(n['offset']) is int and 0<=n['offset'] and n['offset']+bits<=nodes[args[0]]['bits']
        elif op=='concat':
            assert kind=='bv' and len(args)>=2;bv_args();assert sum(nodes[j]['bits'] for j in args)==bits
        elif op in ('INT_ZEXT','INT_SEXT'):
            shape(1);bv_args();assert nodes[args[0]]['bits']<=bits
        elif op in ('BOOL_AND','BOOL_OR','BOOL_NEGATE','INT_EQUAL','INT_NOTEQUAL','INT_LESS','INT_SLESS','INT_CARRY','INT_SCARRY'):
            shape(1 if op=='BOOL_NEGATE' else 2);bv_args();assert bits==8
            if op in ('INT_EQUAL','INT_NOTEQUAL','INT_LESS','INT_SLESS','INT_CARRY','INT_SCARRY'):assert nodes[args[0]]['bits']==nodes[args[1]]['bits']
        elif op=='POPCOUNT':shape(1);bv_args()
        elif op in ('load_le','store_le'):
            size=n['size'];assert type(size) is int and 1<=size<=16
            shape(2 if op=='load_le' else 3,'bv' if op=='load_le' else 'memory')
            assert nodes[args[0]]['type']=='memory' and (nodes[args[1]]['type'],nodes[args[1]].get('bits'))==('bv',64)
            if op=='load_le':assert bits==8*size
            else:assert (nodes[args[2]]['type'],nodes[args[2]].get('bits'))==('bv',8*size)
        else:raise ValueError('Unsupported proof DAG operation: '+str(op))
        references+=len(args)+len(source);assert references<=8192
        depths.append(1+max([0]+[depths[j] for j in args]));assert depths[-1]<=128
    assert references<=dag['references'] and max(depths)<=dag['depth']
    return nodes

def encode(core,roots,*,cuts=None,cut_loads=False):
    nodes=validate(core);cuts=cuts or {}
    assert type(cuts) is dict and all(type(i) is int and 0<=i<len(nodes) and type(v) is str and v for i,v in cuts.items())
    needed=set();work=list(roots);explicit=set();loads=set();refs=0
    while work:
        i=work.pop();assert type(i) is int and 0<=i<len(nodes)
        if i in needed:continue
        needed.add(i);n=nodes[i];assert n['id']==i and type(n['args']) is list
        if i in cuts:explicit.add(i);continue
        if cut_loads and n['op']=='load_le':loads.add(i);continue
        deps=n['args']+([n['source']] if n['op']=='state_binding' else [])
        assert all(type(j) is int and 0<=j<i for j in deps);refs+=len(deps);assert refs<=8192
        work.extend(deps)
    lines=[f'(declare-const I_{name} (_ BitVec 64))' for name in GPRS]
    lines += [f'(declare-const M0 {ARRAY})',f'(declare-const M_dispatch {ARRAY})'];values={}
    for i in sorted(needed):
        n=nodes[i];op=n['op'];bits=n.get('bits');args=[values[j] for j in n['args']] if i not in explicit|loads else []
        if i in explicit:values[i]=cuts[i];continue
        if i in loads:
            assert n['type']=='bv' and type(bits) is int and 1<=bits<=128
            value=f'free_load_{i}';lines.append(f'(declare-const {value} (_ BitVec {bits}))');values[i]=value;continue
        if op=='input':assert n['name'] in GPRS and bits==64;term='I_'+n['name']
        elif op=='nondeterministic':assert bits==64;term=f'opaque_{i}';lines.append(f'(declare-const {term} (_ BitVec 64))')
        elif op=='initial_memory':term='M0'
        elif op=='const':term=bv(int(n['value'],16),bits)
        elif op=='state_binding':
            source=nodes[n['source']];assert source['type']==n['type'] and source.get('bits')==bits and not args
            term=values[n['source']]
        elif op in ('INT_ADD','INT_SUB','INT_MULT','INT_AND','INT_OR','INT_XOR'):
            term='('+{'INT_ADD':'bvadd','INT_SUB':'bvsub','INT_MULT':'bvmul','INT_AND':'bvand','INT_OR':'bvor','INT_XOR':'bvxor'}[op]+' '+' '.join(args)+')'
        elif op=='extract':term=f'((_ extract {n["offset"]+bits-1} {n["offset"]}) {args[0]})'
        elif op=='concat':term=concat(args)
        elif op in ('INT_ZEXT','INT_SEXT'):
            extension=bits-nodes[n['args'][0]]['bits'];assert extension>=0
            term=args[0] if extension==0 else f'((_ {"zero_extend" if op=="INT_ZEXT" else "sign_extend"} {extension}) {args[0]})'
        elif op in ('BOOL_AND','BOOL_OR','BOOL_NEGATE','INT_EQUAL','INT_NOTEQUAL','INT_LESS','INT_SLESS','INT_CARRY','INT_SCARRY'):
            nonzero=[f'(distinct {a} {bv(0,nodes[j]["bits"])})' for a,j in zip(args,n['args'])]
            compare={'INT_EQUAL':'=','INT_NOTEQUAL':'distinct','INT_LESS':'bvult','INT_SLESS':'bvslt'}.get(op)
            if op=='INT_CARRY':condition=f'(bvult {add(args[0],args[1])} {args[0]})'
            elif op=='INT_SCARRY':
                top=nodes[n['args'][0]]['bits']-1;msb=lambda a:f'((_ extract {top} {top}) {a})'
                condition=f'(and (= {msb(args[0])} {msb(args[1])}) (distinct {msb(add(args[0],args[1]))} {msb(args[0])}))'
            else:condition=(f'({compare} {args[0]} {args[1]})' if compare else f'(not {nonzero[0]})' if op=='BOOL_NEGATE' else
                '('+('and' if op=='BOOL_AND' else 'or')+' '+' '.join(nonzero)+')')
            term=f'(ite {condition} {bv(1,bits)} {bv(0,bits)})'
        elif op=='POPCOUNT':
            width=nodes[n['args'][0]]['bits'];terms=[f'((_ zero_extend {bits-1}) ((_ extract {i} {i}) {args[0]}))' for i in range(width)]
            # Balanced addition keeps encoded depth logarithmic, not linear.
            while len(terms)>1:terms=[add(terms[i],terms[i+1]) if i+1<len(terms) else terms[i] for i in range(0,len(terms),2)]
            term=terms[0]
        elif op=='load_le':term=read(args[0],args[1],n['size'])
        elif op=='store_le':term=store(args[0],args[1],args[2],n['size'])
        else:raise ValueError('Unsupported proof DAG operation: '+op)
        name=f'n{i}';sort=f'(_ BitVec {bits})' if bits is not None else ARRAY
        lines += [f'(declare-const {name} {sort})',f'(assert (= {name} {term}))'];values[i]=name
    return lines,[values[i] for i in roots],{'wholeSourceDagValidated':True,'sourceNodes':len(needed),'sourceReferences':refs,
        'explicitCuts':sorted(explicit),'weakenedLoadNodes':sorted(loads)}

class Queries:
    def __init__(self,main,out,deadline):
        from lift_runtime import locked_file
        self.held=ExitStack();self.out=Path(out);self.out.mkdir(exist_ok=False);self.rows=[];self.deadline=deadline
        inventory=Path(main)/'worker/trace_vendor/ig5-manifest.json'
        raw=self.held.enter_context(locked_file(inventory,4*1024**2));assert hashlib.sha256(raw).hexdigest()==TRACE_PIN
        pin=next(r for r in json.loads(raw)['files'] if '/libz3-' in r['path']);self.dll=inventory.parent/pin['path']
        assert self.dll.resolve().is_relative_to(inventory.parent.resolve())
        binary=self.held.enter_context(locked_file(self.dll,64*1024**2));self.dll_sha=hashlib.sha256(binary).hexdigest();assert self.dll_sha==pin['sha256']
        self.lib=C.CDLL(str(self.dll))
        for name,args,result in [('Z3_mk_config',[],C.c_void_p),('Z3_mk_context',[C.c_void_p],C.c_void_p),
                ('Z3_del_config',[C.c_void_p],None),('Z3_del_context',[C.c_void_p],None),
                ('Z3_eval_smtlib2_string',[C.c_void_p,C.c_char_p],C.c_char_p)]:
            f=getattr(self.lib,name);f.argtypes=args;f.restype=result
    def close(self):self.held.close()
    def query(self,name,body,expected='unsat',metadata=None):
        assert re.fullmatch(r'[a-z0-9-]+',name) and len(self.rows)<128
        remaining=int((self.deadline-time.monotonic())*1000);assert remaining>0,'Shared proof deadline exhausted'
        timeout=min(2000,remaining)
        text=f'(set-option :timeout {timeout})\n(set-option :memory_max_size 512)\n'+body+'\n(check-sat)\n'
        raw=text.encode('ascii');assert len(raw)<=1024**2
        depth=maximum=0
        for c in text:
            if c=='(':depth+=1;maximum=max(maximum,depth)
            elif c==')':depth-=1;assert depth>=0
        assert depth==0 and maximum<=128
        # Conservative encoded-form counters, including sort/index forms and
        # all atom tokens. Named equalities keep expressions local; expanded
        # source dependency depth is a different quantity.
        expressions=text.count('(');tokens=len(re.findall(r'[^\s()]+',text))
        assert expressions<=2048 and tokens<=8192,'Encoded proof budget exceeded'
        file=self.out/(name+'.smt2')
        with file.open('xb') as stream:stream.write(raw)
        config=self.lib.Z3_mk_config();context=self.lib.Z3_mk_context(config);self.lib.Z3_del_config(config);start=time.monotonic()
        try:response=self.lib.Z3_eval_smtlib2_string(context,raw).decode('utf8').strip()
        finally:self.lib.Z3_del_context(context)
        row={'name':name,'status':response,'expected':expected,'elapsedMs':round((time.monotonic()-start)*1000),
            'timeoutMs':timeout,'bytes':len(raw),'sha256':sha(file),'path':str(file),
            'encodedSexpressions':expressions,'encodedAtomTokens':tokens,'encodedDepth':maximum,**(metadata or {})}
        self.rows.append(row);(self.out.parent/'progress.json').write_text(json.dumps(self.rows,indent=2)+'\n',encoding='utf8')
        print(json.dumps(row),flush=True);return len(self.rows)-1
    def expect(self,index):
        row=self.rows[index];assert row['status']==row['expected'],row
        assert time.monotonic()<self.deadline,'Shared proof deadline exhausted';return index
