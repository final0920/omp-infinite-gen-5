"""Bounded ordinary-state certificates for status250 -> context-store136.

Generic public address composition is independently checked on fixed owned
bytes here. No CPU flags cross a template boundary, target execution, native
reachability, exact3.8 admission or complete protected-business claim.
"""
from pathlib import Path
from contextlib import ExitStack
import argparse,hashlib,json,random,sys,time
MAIN=Path(__file__).resolve().parents[1];sys.path[:0]=[str(MAIN/'worker'),str(MAIN/'scripts')]
from composition_domain_smt import ARRAY,GPRS,Queries,encode,bv,add,sub,read,store,sha
from projection_numerical_oracle import projection_values,total_byte,MASK

def image_formula(a,b,u):
    s=add(a,b);parity=[f'((_ extract {i} {i}) {s})' for i in range(8)]
    while len(parity)>1:parity=[f'(bvxor {parity[i]} {parity[i+1]})' for i in range(0,len(parity),2)]
    wide=add(f'((_ zero_extend 1) {a})',f'((_ zero_extend 1) {b})');signed=add(f'((_ sign_extend 1) {a})',f'((_ sign_extend 1) {b})')
    bits={0:f'(bvuge {wide} {bv(1<<64,65)})',2:f'(= {parity[0]} {bv(0,1)})',6:f'(= {s} {bv(0)})',7:f'(= ((_ extract 63 63) {s}) {bv(1,1)})',11:f'(distinct ((_ extract 64 64) {signed}) ((_ extract 63 63) {signed}))'}
    result=f'(bvand {u} {bv(MASK^0x8c5)})'
    for bit,predicate in bits.items():result=f'(bvor {result} (ite {predicate} {bv(1<<bit)} {bv(0)}))'
    return result

def summary(kind,r,m,tag,flag_image=None):
    """Independent ordinary equations with all aliasing and ordered writes."""
    lines=[];writes=[]
    def define(name,term,sort='(_ BitVec 64)'):
        name=tag+'_'+name;lines.append(f'(define-fun {name} () {sort} {term})');return name
    def put(name,address,value):
        nonlocal m
        before=m;m=define(name,store(m,address,value,8),ARRAY);writes.append([address,value,before,m]);return m
    q=dict(r)
    if kind==250:
        value=define('sum',add('A','B'));put('pushImage',sub(r['rsp'],bv(8)),flag_image)
        put('sumMemory',add(r['rbp'],bv(8)),value);put('flagMemory',r['rbp'],flag_image);q.update(rbx=value,r10=flag_image)
        vip=r['rsi']
    else:
        assert kind==136
        value=define('word',read(m,r['rbp'],8));index=define('index',f'((_ zero_extend 56) {read(m,r["rsi"],1)})')
        put('contextMemory',add(r['rsp'],index),value);q.update(rbx=value,rbp=add(r['rbp'],bv(8)))
        vip=add(r['rsi'],bv(1))
    selector=define('selector',f'((_ zero_extend 56) {read(m,vip,1)})')
    displacement=define('disp',f'((_ sign_extend 32) {read(m,add(r["r11"],f"(bvmul {selector} {bv(4)})"),4)})')
    target=define('target',add(r['r11'],displacement));put('dispatchMemory',sub(r['rsp'],bv(8)),target)
    q.update(rax=selector,r8=target,rsi=add(r['rsi'],bv(1 if kind==250 else 2)))
    return lines,q,m,target,writes

def roots_and_expected(boundary,stores,registers,memory,target,writes,entry,guard):
    roots=[boundary['registers'][n] for n in GPRS]+[boundary['currentMemory'],boundary['control']['target'],boundary['entryGuard'],boundary['continuedGuard']]
    expected=[registers[n] for n in GPRS]+[memory,target,entry,guard]
    assert len(stores)==len(writes)
    for s,w in zip(stores,writes):roots += [s[k] for k in ('address','value','beforeMemory','afterMemory','guard')];expected += w+[entry]
    return roots,expected

def main():
    p=argparse.ArgumentParser()
    for k in ('receipt','receipt-sha','handler136','handler136-sha','out'):p.add_argument('--'+k,required=True)
    p.add_argument('--child',action='store_true');a=p.parse_args();out=Path(a.out);assert all(Path(x).is_absolute() for x in (a.out,a.receipt,a.handler136))
    from lift_runtime import locked_file
    if not a.child:
        from lift_process import run_owned
        out.mkdir(exist_ok=False);job=out/'job';job.mkdir();r=run_owned(str(MAIN/'runtimes/ghidra/python/python.exe'),['-I','-B','-X','utf8',str(Path(__file__)),*sys.argv[1:],'--child'],job,budget_ms=50000)
        (out/'process.json').write_text(json.dumps(r,indent=2)+'\n',encoding='utf8');assert r['childExitConfirmed'] and r['jobAssignedAtCreation']
        if r['exitCode']!=0:
            with locked_file(job/'stderr.log',4*1024**2) as raw:error=raw.decode('utf8')
            with locked_file(job/'stdout.log',4*1024**2) as raw:error+='\n'+raw.decode('utf8')[-8192:]
            raise AssertionError(error)
        with locked_file(out/'verified.json',4*1024**2) as raw:v=json.loads(raw)
        print(json.dumps({'passed':v['passed'],'queries':len(v['queries']),'statuses':{s:sum(q['status']==s for q in v['queries']) for s in ('unsat','sat','unknown')},'numeric':v['numeric'],'verifiedSha256':sha(out/'verified.json'),'process':r}));return
    deadline=time.monotonic()+45
    with ExitStack() as held:
        def load(path,pin):
            raw=held.enter_context(locked_file(Path(path),4*1024**2));assert hashlib.sha256(raw).hexdigest()==pin;return json.loads(raw)
        receipt=load(a.receipt,a.receipt_sha);assert receipt['passed'];cores={};refs={}
        for c in receipt['cases']:
            if c['rejected']:continue
            assert c['cleanupConfirmed'] and c['rootExitConfirmed'];ref=c['result'];cores[c['id']]=load(ref['reportPath'],ref['reportSha256'])['result'];refs[c['id']]={'path':ref['reportPath'],'sha256':ref['reportSha256']}
        assert len(cores)==5;local=load(a.handler136,a.handler136_sha)['result'];cores['local136']=local;refs['local136']={'path':a.handler136,'sha256':a.handler136_sha}
        target=Path(receipt['cases'][0]['args']['target']);raw=held.enter_context(locked_file(target,4*1024**2));assert hashlib.sha256(raw).hexdigest()=='5f9c1b6fcb019366f835d8f02d9ec3b2957fe619e039410d07f288a9c73f63f0'
        from kernel_image import BinaryImage
        image=BinaryImage.from_bytes(raw)
        for core in cores.values():
            assert all(core[k] is False for k in ('nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'))
            assert core['targetSha256']==hashlib.sha256(raw).hexdigest()
            assert all(image.read(int(r['ea'],16),r['decoded']['size']).hex()==r['bytes'] for r in core['decodedPath'])
        q=Queries(MAIN,out/'queries',deadline)
        try:prove(a,out,receipt,cores,refs,image,q,deadline)
        finally:q.close()

def prove(a,out,receipt,cores,refs,image,q,deadline):
    c=cores['status250-136'];nodes=c['dag']['nodes'];sum_node=nodes[c['stores'][1]['value']];assert sum_node['op']=='INT_ADD'
    loads=sum_node['args'];assert all(nodes[i]['op']=='load_le' and nodes[i]['args'][0]==c['initialMemory'] for i in loads)
    noise=c['nondeterministicInputs'][0]['node'];flag=c['layers'][0]['flagImages'][0]['valueNode']
    declarations='\n'.join(f'(declare-const {n} (_ BitVec 64))' for n in ('A','B','U','F'))
    def query(name,case,roots,expected=None,*,cuts=None,extra='',assertion=None,status='unsat'):
        lines,actual,meta=encode(cores[case],roots,cuts=cuts or {});meta.update(sourceCase=case,rootNodes=roots,cutNames={str(i):n for i,n in (cuts or {}).items()})
        if expected is not None:
            assert len(actual)==len(expected);assertion='(or '+' '.join(f'(distinct {x} {y})' for x,y in zip(actual,expected))+')'
        if callable(assertion):assertion=assertion(actual)
        # Independent formulas refer to I_*/M0; encoded definitions may refer
        # to explicit-cut names declared in extra. Declare all source symbols
        # first, then formulas/cut symbols, then encoded node definitions.
        declared=[line for line in lines if line.startswith('(declare-')]
        defined=[line for line in lines if not line.startswith('(declare-')]
        return q.expect(q.query(name.lower(),declarations+'\n'+'\n'.join(declared)+'\n'+extra+'\n'+'\n'.join(defined)+'\n(assert '+assertion+')',status,meta))
    operand=query('public250-original-operands-read-initial-rbp-and-rbp-plus8','status250-136',[nodes[i]['args'][1] for i in loads],['I_rbp',add('I_rbp',bv(8))])
    status_eq=query('public250-whole-status-image-independent-add64-equation','status250-136',[flag],[image_formula('A','B','U')],cuts={loads[0]:'A',loads[1]:'B',noise:'U'})
    r={n:'I_'+n for n in GPRS};s0=summary(250,r,'M0','S0','F');g0=f'(ite (= {s0[3]} {bv(0x1400545b6)}) {bv(1,8)} {bv(0,8)})'
    roots,wanted=roots_and_expected(c['boundaries'][0],[s for s in c['stores'] if s['stepIndex']==0],*s0[1:],bv(1,8),g0)
    layer0=query('public250-complete-all16-whole-memory-writes-guard-control','status250-136',roots,wanted,cuts={loads[0]:'A',loads[1]:'B',flag:'F'},extra='\n'.join(s0[0]))
    local=cores['local136'];lr,lg,lm,lt,lw=summary(136,r,'M0','Local136');boundary={'registers':local['registers'],'currentMemory':local['currentMemory'],'control':local['control'],'entryGuard':None,'continuedGuard':None}
    roots=[local['registers'][n] for n in GPRS]+[local['currentMemory'],local['control']['target']];wanted=[lg[n] for n in GPRS]+[lm,lt]
    for s,w in zip(local['stores'],lw):roots += [s[k] for k in ('address','value','beforeMemory','afterMemory')];wanted += w
    assert len(local['stores'])==2 and len(local['projectionPath'])==22
    local_query=query('local136-all16-entire-memory-ordered-context-and-dispatch-writes-control','local136',roots,wanted,extra='\n'.join(lr))
    layer=c['layers'][1];bindings={layer['inputRegisters'][n]:'Q_'+n for n in GPRS};bindings[layer['inputMemory']]='Q_memory';bindings[layer['entryGuard']]='Q_guard'
    declared='\n'.join(f'(declare-const Q_{n} (_ BitVec 64))' for n in GPRS)+f'\n(declare-const Q_memory {ARRAY})\n(declare-const Q_guard (_ BitVec 8))'
    s1=summary(136,{n:'Q_'+n for n in GPRS},'Q_memory','S1');roots,wanted=roots_and_expected(c['boundaries'][1],[s for s in c['stores'] if s['stepIndex']==1],*s1[1:],'Q_guard','Q_guard')
    layer1=query('public136-complete-state-from-exact-prior18-bindings','status250-136',roots,wanted,cuts=bindings,extra=declared+'\n'+'\n'.join(s1[0]))
    # Pure target partition, not an assertion that either edge is natively reachable.
    target=c['boundaries'][0]['control']['target'];exit0=c['sideExits'][0]
    partition=query('actual-selected-target-guard-and-complement-retain-prior-state','status250-136',[c['boundaries'][0]['continuedGuard'],exit0['guard'],exit0['target'],*[exit0['registers'][n] for n in GPRS],exit0['currentMemory']],
        [f'(ite (= T {bv(0x1400545b6)}) {bv(1,8)} {bv(0,8)})',f'(ite (= T {bv(0x1400545b6)}) {bv(0,8)} {bv(1,8)})','T',*[f'Q_{n}' for n in GPRS],'Q_memory'],
        cuts={target:'T',**{c['layers'][0]['registers'][n]:'Q_'+n for n in GPRS},c['layers'][0]['currentMemory']:'Q_memory'},extra=declared+'\n(declare-const T (_ BitVec 64))')
    af=[]
    for bit in (0,1):af.append(query('unmodeled-AF-still-free-'+str(bit),'status250-136',[flag],cuts={loads[0]:'A',loads[1]:'B',noise:'U'},assertion=lambda roots,bit=bit:f'(and (= A {bv(0)}) (= B {bv(0)}) (= ((_ extract 4 4) {roots[0]}) {bv(bit,1)}))',status='sat'))
    legacy=cores['legacy250-136'];legacy_image=legacy['stores'][0]['value']
    loss=query('legacy-entire-unknown-image-loses-known-status-mask44','legacy250-136',[legacy_image],cuts={legacy_image:'U'},assertion=lambda roots:f'(distinct (bvand {roots[0]} {bv(0x8c5)}) {bv(0x44)})',status='sat')
    # Restore every cut definition before asking for a genuine symbolic-data
    # witness; a free cut alone cannot establish a concrete path counterexample.
    restored='\n'.join([f'(assert (= A {read("M0","I_rbp",8)}))',f'(assert (= B {read("M0",add("I_rbp",bv(8)),8)}))',f'(assert (= F {image_formula("A","B","U")}))'])
    stale=query('negative136-must-read-post250-memory-not-original-M0','status250-136',[c['stores'][4]['value'],c['boundaries'][0]['control']['target']],cuts={loads[0]:'A',loads[1]:'B',flag:'F'},extra=restored,
        assertion=lambda roots:f'(and (= {roots[1]} {bv(0x1400545b6)}) (distinct {roots[0]} {read("M0","I_rbp",8)}))',status='sat')
    numeric=numeric_checks(receipt,cores,image,deadline)
    result={'schema':'ig5-status-chain-ordinary-certificates-v1','passed':True,'sourceReceipt':{'path':a.receipt,'sha256':a.receipt_sha},'reports':refs,
        'queries':q.rows,'operandAddressQuery':operand,'wholeFlagImageEquationQuery':status_eq,'fullLayer0Query':layer0,'fullLocal136Query':local_query,'fullLayer1Query':layer1,'guardComplementQuery':partition,
        'unmodeledAFQueries':af,'legacyLossQuery':loss,'postWriteReadCounterexampleQuery':stale,'numeric':numeric,
        'cutCertificates':'A/B universally rename originalM0 operand loads, separately address-certified. F names the original application STORE image, certified by the whole64-bit independent formula. Layer1 universally quantifies the exact preceding16GPR/memory/guard bindings. All source definitions/types checked even behind cuts. Counterexample query restores every cut definition.',
        'compositionalInduction':'Full250 state/writes/control/guard plus exact18 source bindings, full136 state/writes/control relative to those bindings, and the complete complementary exit state imply the conditional two-handler ordinary-data summary. No monolithic whole-chain query is claimed.',
        'wholeTwoHandlerUncutQueryPerformed':False,'nativeReachabilityProved':False,'entry250To136InitialByteFactJoinProved':False,
        'sourceProofScriptSha256':sha(__file__),'encoderSourceSha256':sha(MAIN/'scripts/composition_domain_smt.py'),'solverDllSha256':q.dll_sha,
        'limits':{'queries':128,'queryTimeoutMs':2000,'queryMemoryMiB':512,'sharedSeconds':45,'ownedJobSeconds':50,'ownedJobMemoryBytes':2147483648},
        'nativeTargetExecuted':False,'databaseModified':False,'architectureProved':False,'businessAccepted':False,'wholeBinaryVerified':False}
    raw=(json.dumps(result,indent=2)+'\n').encode('utf8');assert len(raw)<=4*1024**2 and time.monotonic()<deadline
    with (out/'verified.json').open('xb') as f:f.write(raw)

def numeric_checks(receipt,cores,image,deadline):
    vip=0x1400846c4;table=0x140056098;facts={vip+i:b for i,b in enumerate(image.read(vip,64))};facts.update({table+i:b for i,b in enumerate(image.read(table,1024))})
    rows=[];rng=random.Random(0x7374617475736368)
    for case in receipt['cases']:
        if case['rejected']:continue
        c=cores[case['id']];true=false=0
        for sample in range(512):
            assert time.monotonic()<deadline;initial={n:rng.getrandbits(64) for n in GPRS};overrides=dict(facts)
            if sample<128:
                initial.update(rsp=0x100000+sample*16,rbp=0x100400+sample*16,r11=table,rsi=vip+(44 if case['id']=='status137-250-136' else 46))
                if case['id']=='repeat250':overrides[vip+46]=250
            elif sample<384:
                base=[0,1,MASK-7,MASK,vip-16,table-8][sample%6];initial.update(rsp=base,rbp=(base+[-16,-8,-1,0,1,7,8,16][sample%8])&MASK,
                    rsi=(base+[-8,0,7,8,16][sample%5])&MASK,r11=(base+sample%17)&MASK)
            origin=total_byte(rng.getrandbits(64),overrides);state=dict(initial);memory={};guard=1;stores=[];boundaries=[];exits=[]
            unknowns={c['dag']['nodes'][x['node']]['name']:rng.getrandbits(64) for x in c['nondeterministicInputs']}
            def word(a,n):return sum(memory.get((a+i)&MASK,origin((a+i)&MASK))<<(8*i) for i in range(n))
            def put(address,value,step,instruction):
                address&=MASK;before=dict(memory);memory.update({(address+i)&MASK:(value>>(8*i))&255 for i in range(8)})
                stores.append((step,instruction,address,value,guard,before,dict(memory)))
            for step,path in enumerate(case['args']['composition_plan']['paths']):
                ea=int(path[0],16);before=dict(state);full=True
                if ea==0x140055f66:
                    a,b=word(state['rbp'],8),word(state['rbp']+8,8);s=(a+b)&MASK
                    status=int(a+b>MASK)|(int((s&255).bit_count()%2==0)<<2)|(int(s==0)<<6)|((s>>63)<<7)|(int(((a^s)&(b^s))>>63!=0)<<11)
                    u=unknowns[f'step_{step}_opaque_7'];f=u if case['args']['composition_plan']['template_mode']=='opaque-effects' else (u&(MASK^0x8c5))|status
                    put(state['rsp']-8,f,step,7);put(state['rbp']+8,s,step,10);put(state['rbp'],f,step,12);state.update(rbx=s,r10=f)
                    full=len(path)==27;dispatch_index=25;direct=0x140052124
                elif ea==0x1400545b6:
                    value=word(state['rbp'],8);index=word(state['rsi'],1);put(state['rsp']+index,value,step,8)
                    state.update(rbx=value,rbp=(state['rbp']+8)&MASK,rsi=(state['rsi']+1)&MASK);dispatch_index=20
                elif ea==0x1400545e7:
                    index=word(state['rsi'],1);value=word(state['rsp']+index,8);new_rbp=(state['rbp']-8)&MASK;put(new_rbp,value,step,9)
                    state.update(rbx=value,rdx=index,rbp=new_rbp,rsi=(state['rsi']+1)&MASK,r8=(state['rsp']+384)&MASK)
                    control={'kind':'conditional','condition':int(state['rbp']>state['r8']),'taken':0x140052124,'fallthrough':0x140052162};full=False;direct=None
                else:assert ea==0x140052124;dispatch_index=10
                if full:
                    selector=word(state['rsi'],1);w=word(state['r11']+4*selector,4);target=(state['r11']+(w if w<1<<31 else w-(1<<32)))&MASK
                    state.update(rax=selector,r8=target,rsi=(state['rsi']+1)&MASK);put(state['rsp']-8,target,step,dispatch_index);control={'kind':'return','target':target}
                elif direct is not None:control={'kind':'direct','target':direct}
                entered=guard
                if step+1<len(case['args']['composition_plan']['paths']):
                    next_ea=int(case['args']['composition_plan']['paths'][step+1][0],16)
                    if control['kind']=='conditional':selected=control['condition'];assert next_ea==control['taken'];alternate=control['fallthrough']
                    elif control['kind']=='return':selected=int(control['target']==next_ea);alternate=control['target']
                    else:assert control['target']==next_ea;selected=1;alternate=None
                    if alternate is not None:exits.append((int(bool(guard) and not selected),alternate,dict(state),dict(memory)))
                    guard=int(bool(guard) and selected)
                boundaries.append((entered,guard,dict(state),dict(memory),dict(control)))
            actual=projection_values(c,initial,origin,unknowns=unknowns)
            assert {n:actual[i] for n,i in c['registers'].items()}==state and actual[c['currentMemory']]==(origin,memory) and actual[c['pathGuard']]==guard
            assert actual[c['control']['target']]==control['target'] and len(c['stores'])==len(stores) and len(c['sideExits'])==len(exits)
            for s,(step,i,address,value,g,before,after) in zip(c['stores'],stores):
                assert (s['stepIndex'],s['instructionIndex'],actual[s['address']],actual[s['value']],actual[s['guard']])==(step,i,address,value,g)
                assert actual[s['beforeMemory']]==(origin,before) and actual[s['afterMemory']]==(origin,after)
            for b,(entered,g,regs,mem,ctrl) in zip(c['boundaries'],boundaries):
                assert actual[b['entryGuard']]==entered and actual[b['continuedGuard']]==g and actual[b['currentMemory']]==(origin,mem) and {n:actual[i] for n,i in b['registers'].items()}==regs
                assert b['control']['kind']==ctrl['kind'] and all(actual[b['control'][k]]==v for k,v in ctrl.items() if k!='kind')
            for e,(g,target,regs,mem) in zip(c['sideExits'],exits):assert (actual[e['guard']],actual[e['target']],actual[e['currentMemory']],{n:actual[i] for n,i in e['registers'].items()})==(g,target,(origin,mem),regs)
            true+=bool(guard);false+=not guard
        assert true>0 and false>0
        rows.append({'id':case['id'],'states':512,'guardTrue':true,'guardFalse':false,'aliasAndWrapStates':256,'all16GPRsWholeMemoryStoresBoundariesAndSideExitsCompared':True})
    return {'cases':rows,'states':2560,'independentOrdinaryHandlerFormulas':True,'notIndependentCPUInterpreter':True,'sameBatchesAcrossDeploymentsNotExtraCoverage':True,'guardFalseLaterStatesHypotheticalOnly':True}

if __name__=='__main__':main()
