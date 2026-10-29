"""Owned handler17 ordinary-state proof, conditional joins and numeric controls.

The incoming entry+17 report is independently domain-certified. No target or
emulator is executed; the owned analysis process evaluates symbolic formulas.
"""
from contextlib import ExitStack
from pathlib import Path
import argparse,hashlib,json,random,sys,time
MAIN=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(MAIN/'worker'),str(MAIN/'scripts')]
from composition_domain_smt import ARRAY,GPRS,Queries,add,sub,bv,read,store,encode,sha
from projection_numerical_oracle import MASK,NAMES,total_byte,projection_values

def main():
    parser=argparse.ArgumentParser()
    for name in ('receipt','receipt-sha','domain-proof','domain-sha','out'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--child',action='store_true');args=parser.parse_args();out=Path(args.out)
    assert out.is_absolute() and Path(args.receipt).is_absolute() and Path(args.domain_proof).is_absolute()
    if not args.child:
        from lift_process import run_owned
        from lift_runtime import locked_file
        out.mkdir(exist_ok=False);job=out/'job';job.mkdir()
        p=run_owned(str(MAIN/'runtimes/ghidra/python/python.exe'),['-I','-B','-X','utf8',str(Path(__file__)),*sys.argv[1:],'--child'],job,budget_ms=50000)
        (out/'process.json').write_text(json.dumps(p,indent=2)+'\n',encoding='utf8');assert p['childExitConfirmed'] and p['jobAssignedAtCreation']
        with locked_file(job/'stderr.log',4*1024**2) as raw:error=raw.decode('utf8')
        assert p['exitCode']==0,error
        with locked_file(out/'verified.json',4*1024**2) as raw:r=json.loads(raw)
        print(json.dumps({'passed':r['passed'],'queries':len(r['queries']),'statuses':{s:sum(x['status']==s for x in r['queries']) for s in ('unsat','sat','unknown')},
            'numericStates':r['numeric']['states'],'extraInitialByteFacts':len(r['extraInitialImageByteFacts']),'nextSelector':r['nextSelector'],
            'nextTarget':r['nextTarget'],'guardFalseInitialRSPRange':[8,263],'verifiedPath':str(out/'verified.json'),'verifiedSha256':sha(out/'verified.json'),'process':p}));return
    from lift_runtime import locked_file
    from kernel_image import BinaryImage
    deadline=time.monotonic()+45
    with ExitStack() as held:
        def load(path,pin):
            raw=held.enter_context(locked_file(Path(path),4*1024**2));assert hashlib.sha256(raw).hexdigest()==pin;return json.loads(raw)
        receipt=load(args.receipt,args.receipt_sha);domain=load(args.domain_proof,args.domain_sha)
        assert receipt['passed'] and domain['passed'] and domain['schema']=='ig5-entry-chain-conditional-domain-proof-v2' and domain['caseId']=='entry-plus17'
        domain_process=json.loads(held.enter_context(locked_file(Path(args.domain_proof).parent/'process.json',65536)))
        assert domain_process['exitCode']==0 and domain_process['childExitConfirmed'] and domain_process['jobAssignedAtCreation']
        assert domain['sourceProofScriptSha256']==sha(MAIN/'scripts/prove_entry_chain_domain.py') and domain['encoderSourceSha256']==sha(MAIN/'scripts/composition_domain_smt.py')
        assert domain['sourceReceipt']['sha256']==args.receipt_sha
        for row in domain['queries']:
            assert row['status']==row['expected'] or row['name']=='all55-write-starts-in671-window' and row['status']=='unknown'
            assert sha(row['path'])==row['sha256'] and row['timeoutMs']<=2000
        byid={c['id']:c for c in receipt['cases']};cores={};refs={}
        for name in ('entry-plus17','literal-push6','literal-push-and-stack-check10','literal-fast-dispatch22'):
            c=byid[name];assert not c['rejected'] and c['cleanupConfirmed'] and c['rootExitConfirmed']
            ref=c['result'];record=load(ref['reportPath'],ref['reportSha256']);cores[name]=record['result'];refs[name]={'path':ref['reportPath'],'sha256':ref['reportSha256']}
        assert domain['sourceReport']==refs['entry-plus17']
        target=Path(byid['entry-plus17']['args']['target']);data=held.enter_context(locked_file(target,4*1024**2));assert hashlib.sha256(data).hexdigest()==domain['targetSha256']
        image=BinaryImage.from_bytes(data)
        for core in cores.values():
            assert all(core[k] is False for k in ('nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'))
            assert all(image.read(int(r['ea'],16),r['decoded']['size']).hex()==r['bytes'] for r in core['decodedPath'])
        q=Queries(MAIN,out/'queries',deadline)
        try:prove(cores,refs,domain,args,q,image,out,deadline)
        finally:q.close()

def prove(cores,refs,domain,args,q,image,out,deadline):
    declarations=[];results=[]
    def query(core,name,roots,assertion,*,expected='unsat',cuts=None,extra=None):
        lines,actual,meta=encode(core,roots,cuts=cuts)
        if extra is None:extra='\n'.join(declarations)
        return q.expect(q.query(name,'\n'.join(lines)+'\n'+extra+'\n(assert '+assertion(actual)+')',expected,meta))
    def different(actual,wanted):return '(or '+' '.join(f'(distinct {a} {b})' for a,b in zip(actual,wanted))+')'
    def define(name,bits,term):
        sort=ARRAY if bits is None else f'(_ BitVec {bits})'
        declarations.extend([f'(declare-const E_{name} {sort})',f'(assert (= E_{name} {term}))']);return 'E_'+name
    literal=define('literal',64,read('M0','I_rsi',8));rp=define('rp',64,sub('I_rbp',bv(8)));si=define('si',64,add('I_rsi',bv(8)));threshold=define('threshold',64,add('I_rsp',bv(384)))
    M1=define('M1',None,store('M0',rp,literal,8));g=define('guard',8,f'(ite (bvugt {rp} {threshold}) {bv(1,8)} {bv(0,8)})');ng=define('notguard',8,f'(ite (= {g} {bv(0,8)}) {bv(1,8)} {bv(0,8)})')
    base_regs={'rax':literal,'rbp':rp,'rsi':si};check_regs={**base_regs,'r8':threshold}
    for case,changes,target in [('literal-push6',base_regs,0x14005214d),('literal-push-and-stack-check10',check_regs,None)]:
        c=cores[case];s=c['stores'][0];assert len(c['stores'])==1 and s['size']==8
        roots=[c['registers'][n] for n in GPRS]+[c['currentMemory'],s['address'],s['value']]
        wanted=[changes.get(n,'I_'+n) for n in GPRS]+[M1,rp,literal]
        if target is not None:roots.append(c['control']['target']);wanted.append(bv(target))
        else:
            roots += [c['control'][k] for k in ('condition','taken','fallthrough')];wanted += [g,bv(0x140052124),bv(0x140052162)]
        i=query(c,case+'-all16-memory-write-and-control',roots,lambda a,w=wanted:different(a,w))
        results.append({'case':case,'query':i,'all16GPRsAndEntireByteArrayMemory':True,'completeControl':True})
    c=cores['literal-fast-dispatch22'];s0,s1=c['stores'];exit=c['sideExits'][0];assert len(c['stores'])==2 and len(c['sideExits'])==1
    selector=define('selector',8,read(M1,si,1));target=define('target',64,add('I_r11',f'((_ sign_extend 32) {read(M1,add("I_r11",f"(bvmul ((_ zero_extend 56) {selector}) {bv(4)})"),4)})'))
    M2=define('M2',None,store(M1,sub('I_rsp',bv(8)),target,8))
    fast_regs={'rax':f'((_ zero_extend 56) {selector})','r8':target,'rbp':rp,'rsi':add(si,bv(1))}
    roots=[c['registers'][n] for n in GPRS]+[c['pathGuard'],c['control']['target']]
    wanted=[fast_regs.get(n,'I_'+n) for n in GPRS]+[g,target]
    i=query(c,'fast-all16-registers-path-guard-and-return',roots,lambda a:different(a,wanted));results.append({'case':'literal-fast-dispatch22','query':i,'validOnlyUnderPathGuard':True})
    roots=[c['currentMemory']]+[s[k] for s in (s0,s1) for k in ('address','value','beforeMemory','afterMemory','guard')]
    wanted=[M2,rp,literal,'M0',M1,bv(1,8),sub('I_rsp',bv(8)),target,M1,M2,g]
    i=query(c,'fast-entire-memory-both-store-orders-and-entry-guards',roots,lambda a:different(a,wanted));results.append({'case':'literal-fast-dispatch22','query':i,'earlyLiteralStoreNotSuppressedByLaterGuard':True})
    roots=[exit['registers'][n] for n in GPRS]+[exit[k] for k in ('currentMemory','guard','target')]
    wanted=[check_regs.get(n,'I_'+n) for n in GPRS]+[M1,ng,bv(0x140052162)]
    i=query(c,'stack-check-complementary-exit-all16-memory-and-target',roots,lambda a:different(a,wanted));results.append({'case':'literal-fast-dispatch22','query':i,'alternateContinuationRetainedAndNotAnalyzed':True})
    # Exact incoming pointers use their complete original state_binding chains.
    incoming=cores['entry-plus17'];S='I_rsp';frame=f'(bvand {sub(S,bv(648))} {bv(MASK-15)})';vip=image.imagebase+0x846c4;table=image.imagebase+0x56098
    roots=[incoming['registers'][n] for n in ('rsp','rbp','rsi','r11')]
    wanted=[frame,S,bv(vip+35),bv(table)]
    pointers=query(incoming,'incoming18-boundary-pointers-to-literal-handler',roots,lambda a:different(a,wanted))
    assert int(domain['targetCertificates'][-1]['target'],16)==0x1400525ca
    # Local universal summary can now be instantiated at the certified cutpoint.
    # This is not a133-distinct-instruction public composition or native run.
    check=cores['literal-push-and-stack-check10'];extra='(declare-const S (_ BitVec 64))\n'+f'(assert (= I_rbp S))\n(assert (= I_rsp (bvand {sub("S",bv(648))} {bv(MASK-15)})))'
    false_range=f'(and (bvuge S {bv(8)}) (bvult S {bv(264)}))';cut_guard=f'(ite {false_range} {bv(0,8)} {bv(1,8)})'
    guard=query(check,'joined-stack-guard-false-exactly8-through263',[check['control']['condition']],lambda a:f'(distinct {a[0]} {cut_guard})',extra=extra)
    normal=query(check,'sufficient-nonwrapping-window-stack-takes-fast-edge',[check['control']['condition']],lambda a:f'(distinct {a[0]} {bv(1,8)})',extra=extra+f'\n(assert (bvuge S {bv(671)}))')
    window=q.expect(q.query('literal-push-stays-in-original671-window','(declare-const S (_ BitVec 64))\n'+f'(assert (distinct {sub(sub("S",bv(8)),sub("S",bv(671)))} {bv(663)}))'))
    literal_address=vip+35;literal_bytes=image.read(literal_address,8);literal_value=int.from_bytes(literal_bytes,'little')
    next_selector_address=vip+43;opcode=image.read(next_selector_address,1)[0];word_address=table+opcode*4;word=image.read(word_address,4)
    target_value=(table+int.from_bytes(word,'little',signed=True))&MASK
    extra_facts={literal_address+i:b for i,b in enumerate(literal_bytes)};extra_facts[next_selector_address]=opcode
    extra_facts.update({word_address+i:b for i,b in enumerate(word)})
    assert all(image.imagebase<=a<image.imagebase+domain['image']['bytes'] for a in extra_facts)
    literal_facts='\n'.join(f'(assert (= (select M0 {bv(literal_address+i)}) {bv(b,8)}))' for i,b in enumerate(literal_bytes))
    literal_q=query(cores['literal-push6'],'literal-value-under-eight-derived-initial-bytes',[cores['literal-push6']['registers']['rax']],lambda a:f'(distinct {a[0]} {bv(literal_value)})',extra=f'(assert (= I_rsi {bv(literal_address)}))\n'+literal_facts)
    # The memory cut is M1 before dispatcher PUSH; the previous55 writes and
    # literal PUSH preserve these image bytes by certified window lemmas.
    dispatch_known=[(next_selector_address,opcode)]+[(word_address+i,b) for i,b in enumerate(word)]
    target_q=query(c,'fast-next-target-under-derived-current-image-bytes',[c['control']['target']],lambda a:f'(distinct {a[0]} {bv(target_value)})',cuts={s1['beforeMemory']:'M_dispatch'},
        extra=f'(assert (= I_rsi {bv(literal_address)}))\n(assert (= I_r11 {bv(table)}))\n'+'\n'.join(f'(assert (= (select M_dispatch {bv(a)}) {bv(b,8)}))' for a,b in dispatch_known))
    facts={int(a,16):v for a,v in domain['initialImageByteFacts']};facts.update(extra_facts)
    premises=f'(declare-const S (_ BitVec 64))\n(declare-const M0 {ARRAY})\n';L=sub('S',bv(671))
    premises+=f'(assert (bvuge {sub(L,bv(image.imagebase))} {bv(domain["image"]["bytes"])}))\n(assert (bvuge {sub(bv(image.imagebase),L)} {bv(671)}))\n'
    premises+='\n'.join(f'(assert (= (select M0 {bv(a)}) {bv(b,8)}))' for a,b in facts.items())
    consistent=q.expect(q.query('all-initial-byte-and-region-premises-consistent',premises,'sat'))
    negative=q.expect(q.query('negative-image-separation-alone-does-not-force-fast-stack-edge',premises+f'\n(assert (= S {bv(8)}))\n(assert {false_range})','sat'))
    absent=query(cores['literal-push6'],'negative-no-literal-byte-premises-value-can-differ',[cores['literal-push6']['registers']['rax']],lambda a:f'(distinct {a[0]} {bv(literal_value)})',expected='sat',extra=f'(assert (= I_rsi {bv(literal_address)}))')
    numeric=numeric_checks(cores,deadline)
    result={'schema':'ig5-handler17-conditional-semantics-proof-v1','passed':True,'sourceReceipt':{'path':args.receipt,'sha256':args.receipt_sha},'reports':refs,
        'incomingDomainProof':{'path':args.domain_proof,'sha256':args.domain_sha},'queries':q.rows,'localSummaryCertificates':results,
        'incomingCompletePointerQuery':pointers,'joinedStackGuardQuery':guard,'sufficientFastEdgeQuery':normal,'newStoreWindowQuery':window,
        'literalValueQuery':literal_q,'nextTargetQuery':target_q,'premisesSatisfiableQuery':consistent,'negativeControls':[negative,absent],
        'extraInitialImageByteFacts':[[hex(a),b] for a,b in sorted(extra_facts.items())],'allInitialByteFactCount':len(facts),
        'literalAddress':hex(literal_address),'literalValue':hex(literal_value),'nextSelectorAddress':hex(next_selector_address),'nextSelector':opcode,'nextTarget':hex(target_value),
        'nextTargetCurrentMemoryCut':s1['beforeMemory'],'currentImageBytesDerivation':{'incomingWindow':domain['window'],'incomingStores':55,'newStoreQuery':window,'windowBytes':671,'newStoreStartOffset':663},
        'guardConclusion':'At the certified entry+17 boundary, the stack-check fast edge is false exactly when8<=initialRSP<264 (unsigned64). A nonwrapping671-byte initial window is sufficient for the fast edge. Image separation alone is insufficient.',
        'joinScope':'Separate complete free-state summaries instantiated using the certified incoming pointer/memory-preservation relations. The133-distinct public combined plan remains rejected; no public cross-report join or native reachability claim.',
        'numeric':numeric,'sourceProofScriptSha256':sha(__file__),'encoderSourceSha256':sha(MAIN/'scripts/composition_domain_smt.py'),'solverDllSha256':q.dll_sha,
        'limits':domain['limits'],'publicProductProofRouteExposed':False,'unproven':['Native stack allocation and loaded code/data/relocation correspondence','Independent CPU/fault/flags equivalence','Stack-relocation alternate continuation and remaining VM ISA/business/coverage','Exact3.8 and full Ultra/Enigma business recovery'],
        'nativeTargetExecuted':False,'databaseModified':False,'architectureProved':False,'businessAccepted':False,'wholeBinaryVerified':False}
    raw=(json.dumps(result,indent=2)+'\n').encode('utf8');assert len(raw)<=4*1024**2 and time.monotonic()<deadline
    with (out/'verified.json').open('xb') as stream:stream.write(raw)

def numeric_checks(cores,deadline):
    rng=random.Random(0x6c69746572616c17);states=[]
    for i in range(512):states.append(({n:rng.getrandbits(64) for n in NAMES},rng.getrandbits(64)))
    for S in list(range(672))+[MASK-i for i in range(16)]:
        r={n:rng.getrandbits(64) for n in NAMES};r.update(rsp=((S-648)&MASK)&(MASK-15),rbp=S);states.append((r,rng.getrandbits(64)))
    for address in (0,1,MASK-3,MASK):
        for delta in range(-8,9):
            r={n:rng.getrandbits(64) for n in NAMES};r.update(rbp=(address+8)&MASK,rsi=(address+delta)&MASK,rsp=(address+8)&MASK,r11=(address-delta)&MASK);states.append((r,rng.getrandbits(64)))
    counts={name:{'states':0,'fast':0,'alternate':0} for name in ('literal-push6','literal-push-and-stack-check10','literal-fast-dispatch22')}
    for r,seed in states:
        assert time.monotonic()<deadline;origin=total_byte(seed);value=sum(origin((r['rsi']+i)&MASK)<<(8*i) for i in range(8));rp=(r['rbp']-8)&MASK;si=(r['rsi']+8)&MASK;threshold=(r['rsp']+384)&MASK
        overlay={(rp+i)&MASK:(value>>(8*i))&255 for i in range(8)}
        def get(a,n):return sum(overlay.get((a+i)&MASK,origin((a+i)&MASK))<<(8*i) for i in range(n))
        selected=int(rp>threshold);selector=get(si,1);word=get(r['r11']+4*selector,4);target=(r['r11']+(word if word<1<<31 else word-(1<<32)))&MASK
        final_overlay={**overlay,**{(r['rsp']-8+i)&MASK:(target>>(8*i))&255 for i in range(8)}}
        for name,count in counts.items():
            c=cores[name];v=projection_values(c,r,origin);changes={'rax':value,'rbp':rp,'rsi':si}
            if name!='literal-push6':changes['r8']=threshold
            if name=='literal-fast-dispatch22':changes.update(rax=selector,r8=target,rsi=(si+1)&MASK)
            assert {n:v[x] for n,x in c['registers'].items()}=={**r,**changes}
            assert v[c['currentMemory']]==(origin,final_overlay if name=='literal-fast-dispatch22' else overlay)
            if name=='literal-push6':assert v[c['control']['target']]==0x14005214d
            elif name=='literal-push-and-stack-check10':assert v[c['control']['condition']]==selected and v[c['control']['taken']]==0x140052124 and v[c['control']['fallthrough']]==0x140052162
            else:
                assert v[c['pathGuard']]==selected and v[c['control']['target']]==target
                e=c['sideExits'][0];assert v[e['guard']]==1-selected and v[e['target']]==0x140052162 and v[e['currentMemory']]==(origin,overlay)
                assert {n:v[x] for n,x in e['registers'].items()}=={**r,'rax':value,'rbp':rp,'rsi':si,'r8':threshold}
                assert v[c['stores'][0]['guard']]==1 and v[c['stores'][1]['guard']]==selected
            count['states']+=1;count['fast']+=selected;count['alternate']+=1-selected
        if r['rbp']<672 and r['rsp']==(((r['rbp']-648)&MASK)&(MASK-15)):assert selected==int(not 8<=r['rbp']<264)
    return {'states':len(states),'evaluations':3*len(states),'cases':counts,'all16GPRsEntireMemoryAndControlCompared':True,'orderedStoreEntryGuardsAndFullSideExitChecked':True,'cutpointAll672SmallInitialStackValuesIncluded':True,'arbitraryCoherentTotalMemory':True,'notIndependentCPUInterpreter':True,'notUniversalProof':True}

if __name__=='__main__':main()
