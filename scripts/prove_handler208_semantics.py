"""Owned handler208, complete relocation loop, and conditional75->76 join.

Ordinary total-byte memory only. No target/CPU execution or public summary input.
"""
from contextlib import ExitStack
from pathlib import Path
import argparse,hashlib,json,random,sys,time
MAIN=Path(__file__).resolve().parents[1];sys.path[:0]=[str(MAIN/'worker'),str(MAIN/'scripts')]
from composition_domain_smt import ARRAY,GPRS,Queries,encode,validate,add,sub,bv,read,store,sha
from projection_numerical_oracle import MASK,projection_values,total_byte
TARGET='5f9c1b6fcb019366f835d8f02d9ec3b2957fe619e039410d07f288a9c73f63f0'
VIP=0x1400846c4;TABLE=0x140056098

def different(xs,ys):
    assert len(xs)==len(ys)
    return '(or '+' '.join(f'(distinct {x} {y})' for x,y in zip(xs,ys))+')'

def flag(term):return f'(ite {term} {bv(1,8)} {bv(0,8)})'

def ordinary(kind,r,m,prefix):
    """Independent instruction equations, retaining reads before each store."""
    lines=[];out=dict(r)
    def define(name,bits,term):
        name=prefix+'_'+name;lines.extend([f'(declare-const {name} {ARRAY if bits is None else f"(_ BitVec {bits})"})',f'(assert (= {name} {term}))']);return name
    if kind=='check':
        a=define('address',64,sub(r['rbp'],bv(8)));v=r['rbp'];out.update(rbx=v,rbp=a,r8=add(r['rsp'],bv(384)))
        condition=flag(f'(bvugt {a} {out["r8"]})');control=[condition,bv(0x140052124),bv(0x140052162)]
    elif kind in ('relocation','body'):
        a=define('destination',64,f'(bvand {sub(r["rbp"],bv(384))} {bv(MASK-15)})') if kind=='relocation' else r['r8']
        source=r['rsp'] if kind=='relocation' else r['rdi'];v=define('word',64,read(m,source,8))
        out.update(rbx=bv(248) if kind=='relocation' else sub(r['rbx'],bv(8)),rdi=add(source,bv(8)),r8=add(a,bv(8)),r10=v)
        if kind=='relocation':out['rsp']=a
        condition=flag(f'(distinct {out["rbx"]} {bv(0)})');control=[condition,bv(0x1400521a6),bv(0x1400521d5)]
    else:
        assert kind=='dispatch'
        selector=define('selector',8,read(m,r['rsi'],1));target=define('target',64,add(r['r11'],f'((_ sign_extend 32) {read(m,add(r["r11"],f"(bvmul ((_ zero_extend 56) {selector}) {bv(4)})"),4)})'))
        out.update(rax=f'((_ zero_extend 56) {selector})',rsi=add(r['rsi'],bv(1)),r8=target);a=sub(r['rsp'],bv(8));v=target;control=[target]
    after=define('memory',None,store(m,a,v,8))
    return lines,out,after,control,[a,v,m,after]

def main():
    p=argparse.ArgumentParser()
    for k in ('receipt','receipt-sha','alternate-receipt','alternate-sha','incoming-proof','incoming-sha','out'):p.add_argument('--'+k,required=True)
    p.add_argument('--child',action='store_true');a=p.parse_args();out=Path(a.out)
    assert all(Path(v).is_absolute() for v in (a.receipt,a.alternate_receipt,a.incoming_proof,a.out))
    from lift_runtime import locked_file
    if not a.child:
        from lift_process import run_owned
        out.mkdir(exist_ok=False);job=out/'job';job.mkdir()
        process=run_owned(str(MAIN/'runtimes/ghidra/python/python.exe'),['-I','-B','-X','utf8',str(Path(__file__)),*sys.argv[1:],'--child'],job,budget_ms=50000)
        (out/'process.json').write_text(json.dumps(process,indent=2)+'\n',encoding='utf8');assert process['childExitConfirmed'] and process['jobAssignedAtCreation']
        if process['exitCode']!=0:
            with locked_file(job/'stderr.log',4*1024**2) as raw:error=raw.decode('utf8')
            with locked_file(job/'stdout.log',4*1024**2) as raw:error+='\n'+raw.decode('utf8')[-8192:]
            raise AssertionError(error)
        with locked_file(out/'verified.json',4*1024**2) as raw:v=json.loads(raw)
        print(json.dumps({'passed':v['passed'],'queries':len(v['queries']),'statuses':{s:sum(r['status']==s for r in v['queries']) for s in ('unsat','sat','unknown')},'numeric':v['numeric'],'verifiedSha256':sha(out/'verified.json'),'process':process}));return
    deadline=time.monotonic()+45
    with ExitStack() as held:
        def load(path,pin=None,maximum=4*1024**2):
            assert Path(path).is_absolute() and '..' not in Path(path).parts
            raw=held.enter_context(locked_file(Path(path),maximum));assert pin is None or hashlib.sha256(raw).hexdigest()==pin;return json.loads(raw)
        def certificate(ref,script,audit=True):
            v=load(ref['path'],ref['sha256']);assert v['passed'] and v['sourceProofScriptSha256']==sha(MAIN/'scripts'/script) and v['encoderSourceSha256']==sha(MAIN/'scripts/composition_domain_smt.py')
            proc=load(Path(ref['path']).parent/'process.json',maximum=65536)
            assert proc['exitCode']==0 and proc['childExitConfirmed'] and proc['jobAssignedAtCreation'] and proc['activeProcessLimit']==1 and proc['memoryLimitBytes']==2147483648
            if audit:
                ar=load(Path(ref['path']).parent/'independent-audit.json');assert ar['passed'] and ar['proofSha256']==ref['sha256']
            for row in v['queries']:assert sha(row['path'])==row['sha256'] and row['timeoutMs']<=2000 and row['status'] in (row['expected'],'unknown')
            return v
        incoming=certificate({'path':a.incoming_proof,'sha256':a.incoming_sha},'prove_context_write_join.py')
        p250=certificate(incoming['incoming250Proof'],'prove_handler250_semantics.py')
        p137=certificate(p250['incoming137Proof'],'prove_handler137_semantics.py')
        context=certificate(p137['incomingContextProof'],'prove_context_mapping.py',False)
        domain=certificate(context['incomingDomainProof'],'prove_entry_chain_domain.py')
        literal=certificate(p137['incomingLiteralProof'],'prove_handler17_semantics.py',False)
        assert incoming['nextSelector']==208 and incoming['nextTarget']=='0x1400556d4' and len(incoming['initialImageByteFacts'])==75
        for key in ('offsetWidthBridgeLemma','preservationLemma','imageSeparationLemma'):assert domain['queries'][domain['window'][key]]['status']=='unsat'
        assert p137['queries'][p137['contextWordNonaliasQuery']]['status']=='unsat' and context['queries'][context['lemmas']['bytePreservation']]['status']=='unsat'
        cores={};refs={};receipts=[]
        for path,pin in ((a.receipt,a.receipt_sha),(a.alternate_receipt,a.alternate_sha)):
            receipt=load(path,pin);receipts.append(receipt);assert receipt['passed'] and receipt['activeRequests']==0
            for case in receipt['cases']:
                assert not case['rejected'] and case['cleanupConfirmed'] and case['rootExitConfirmed'];ref=case['result']
                cores[case['id']]=load(ref['reportPath'],ref['reportSha256'])['result'];refs[case['id']]={'path':ref['reportPath'],'sha256':ref['reportSha256']}
        assert len(cores)==7
        from kernel_image import BinaryImage
        data=held.enter_context(locked_file(Path(receipts[0]['cases'][0]['args']['target']),4*1024**2));assert hashlib.sha256(data).hexdigest()==TARGET;image=BinaryImage.from_bytes(data)
        for c in cores.values():
            validate(c);assert c['targetSha256']==TARGET and set(c['registers'])==set(GPRS)
            assert all(c[k] is False for k in ('nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'))
            assert all(image.read(int(r['ea'],16),r['decoded']['size']).hex()==r['bytes'] for r in c['decodedPath'])
        q=Queries(MAIN,out/'queries',deadline)
        try:prove(a,out,cores,refs,incoming,p137,context,domain,literal,image,q,deadline,load)
        finally:q.close()

def prove(a,out,cores,refs,incoming,p137,context,domain,literal,image,q,deadline,load):
    def query(name,case,roots,wanted=None,*,cuts=None,extra='',predicate=None,status='unsat'):
        cuts=cuts or {};lines,actual,meta=encode(cores[case],roots,cuts=cuts);meta.update(sourceCase=case,rootNodes=roots,cutNames={str(i):n for i,n in cuts.items()})
        declarations=[l for l in lines if l.startswith('(declare-')];definitions=[l for l in lines if not l.startswith('(declare-')]
        pred=different(actual,wanted) if wanted is not None else predicate(actual)
        return q.expect(q.query(name,'\n'.join(declarations)+'\n'+extra+'\n'+'\n'.join(definitions)+'\n(assert '+pred+')',status,meta))
    r={n:'I_'+n for n in GPRS};local=[]
    def root_state(c,regs,m,control,writes,guards=None):
        roots=[c['registers'][n] for n in GPRS]+[c['currentMemory']];wanted=[regs[n] for n in GPRS]+[m]
        keys=('condition','taken','fallthrough') if len(control)==3 else ('target',)
        roots += [c['control'][k] for k in keys];wanted += control
        assert len(writes)==len(c['stores'])
        for j,(s,w) in enumerate(zip(c['stores'],writes)):
            roots += [s[k] for k in ('address','value','beforeMemory','afterMemory')];wanted += w
            if guards is not None:roots.append(s['guard']);wanted.append(guards[j])
        return roots,wanted
    for case,kind in (('context208-check12','check'),('relocation-prefix29','relocation'),('relocation-body13','body')):
        lines,regs,m,control,w=ordinary(kind,r,'M0','Local');roots,wanted=root_state(cores[case],regs,m,control,[w])
        local.append(query(case+'-all16-entire-memory-ordered-write-both-targets',case,roots,wanted,extra='\n'.join(lines)))
    lines,checked,M1,check_control,w0=ordinary('check',r,'M0','Check');g=check_control[0];ng=flag(f'(= {g} {bv(0,8)})')
    for case,kind,path_guard,exit_target in (('context208-fast24','dispatch',g,0x140052162),('context208-alternate41','relocation',ng,0x140052124)):
        more,regs,m,control,w1=ordinary(kind,checked,M1,'Next');c=cores[case];roots,wanted=root_state(c,regs,m,control,[w0,w1],[bv(1,8),path_guard]);roots.append(c['pathGuard']);wanted.append(path_guard)
        assert len(c['sideExits'])==1;e=c['sideExits'][0];roots += [e['registers'][n] for n in GPRS]+[e[k] for k in ('currentMemory','guard','target')]
        wanted += [checked[n] for n in GPRS]+[M1,ng if kind=='dispatch' else g,bv(exit_target)]
        local.append(query(case+'-complete-state-two-writes-and-full-complement',case,roots,wanted,extra='\n'.join(lines+more)))
    # Every public transition layer is independently renamed through the exact
    # input16GPR/memory/guard roots. The complete original DAG is validated too.
    c=cores['context208-relocation32'];assert len(c['layers'])==34 and len(c['stores'])==34 and len(c['sideExits'])==33
    layer_queries=[]
    for step,(layer,boundary) in enumerate(zip(c['layers'],c['boundaries'])):
        kind='check' if step==0 else 'relocation' if step==1 else 'dispatch' if step==33 else 'body'
        cuts={layer['inputRegisters'][n]:'Q_'+n for n in GPRS};cuts[layer['inputMemory']]='Q_memory'
        guard=bv(1,8) if step==0 else 'Q_guard'
        if step:cuts[layer['entryGuard']]=guard
        decl='\n'.join(f'(declare-const Q_{n} (_ BitVec 64))' for n in GPRS)+f'\n(declare-const Q_memory {ARRAY})'
        if step:decl+='\n(declare-const Q_guard (_ BitVec 8))'
        eq,regs,m,control,w=ordinary(kind,{n:'Q_'+n for n in GPRS},'Q_memory','Layer')
        roots=[boundary['registers'][n] for n in GPRS]+[boundary['currentMemory'],boundary['entryGuard']];wanted=[regs[n] for n in GPRS]+[m,guard]
        keys=('condition','taken','fallthrough') if len(control)==3 else ('target',);roots += [boundary['control'][k] for k in keys];wanted += control
        s=c['stores'][step];assert s['stepIndex']==step;roots += [s[k] for k in ('address','value','beforeMemory','afterMemory','guard')];wanted += w+[guard]
        selected=None if step==33 else False if step in (0,32) else True
        continued=guard if selected is None else flag(f'(and (distinct {guard} {bv(0,8)}) '+(f'(distinct {control[0]} {bv(0,8)}))' if selected else f'(= {control[0]} {bv(0,8)}))'))
        roots.append(boundary['continuedGuard']);wanted.append(continued)
        if step<33:
            e=c['sideExits'][step];assert e['stepIndex']==step
            complement=flag(f'(and (distinct {guard} {bv(0,8)}) '+(f'(= {control[0]} {bv(0,8)}))' if selected else f'(distinct {control[0]} {bv(0,8)}))'))
            roots += [e['registers'][n] for n in GPRS]+[e[k] for k in ('currentMemory','guard','target')]
            wanted += [regs[n] for n in GPRS]+[m,complement,control[2 if selected else 1]]
        layer_queries.append(query('public-relocation-layer-'+str(step)+'-all-state-writes-and-partition','context208-relocation32',roots,wanted,cuts=cuts,extra=decl+'\n'+'\n'.join(eq)))
    # Flat constant-loop's independently re-derived counter, full finite STORE
    # links and per-copy ordinary memory equations; never assume nonaliasing.
    flat=cores['relocation-loop32'];assert len(flat['stores'])==33 and len(flat['boundaries'])==33
    repeat=flat['inferredRepeat'];assert repeat['bodyApplicationsAfterPrefix']==31 and not repeat['observedValuesUsed']
    copy_queries=[];D='CopyDestination';destination_node=flat['stores'][0]['address']
    flat_destination=query('flat-relocation-original-destination-equation','relocation-loop32',[destination_node],[f'(bvand {sub("I_rbp",bv(384))} {bv(MASK-15)})'])
    for i,s in enumerate(flat['stores'][:32]):
        previous=flat['initialMemory'] if i==0 else flat['stores'][i-1]['afterMemory'];assert s['beforeMemory']==previous
        dest=add(D,bv(8*i));source=add('I_rsp',bv(8*i));v=read('CopyBefore',source,8);after=store('CopyBefore',dest,v,8)
        roots=[s[k] for k in ('address','value','beforeMemory','afterMemory','guard')]
        b=flat['boundaries'][i];roots += [b['registers'][n] for n in GPRS]+[b['control'][k] for k in ('condition','taken','fallthrough')]
        changes={'rsp':D,'rdi':add('I_rsp',bv(8*(i+1))),'r8':add(D,bv(8*(i+1))),'r10':v,'rbx':bv(248-8*i)}
        wanted=[dest,v,'CopyBefore',after,bv(1,8)]+[changes.get(n,'I_'+n) for n in GPRS]+[bv(int(i<31),8),bv(0x1400521a6),bv(0x1400521d5)]
        e=flat['sideExits'][i];assert e['stepIndex']==i
        roots += [b['entryGuard'],b['continuedGuard']]+[e['registers'][n] for n in GPRS]+[e[k] for k in ('currentMemory','guard','target')]
        wanted += [bv(1,8),bv(1,8)]+[changes.get(n,'I_'+n) for n in GPRS]+[after,bv(0,8),bv(0x1400521d5 if i<31 else 0x1400521a6)]
        copy_queries.append(query('flat-relocation-copy-'+str(i)+'-complete-state-and-memory','relocation-loop32',roots,wanted,cuts={previous:'CopyBefore',destination_node:D},extra=f'(declare-const CopyBefore {ARRAY})\n(declare-const {D} (_ BitVec 64))'))
    last=flat['stores'][-1];assert last['beforeMemory']==flat['stores'][31]['afterMemory'];last_word=flat['stores'][31]['value']
    eq,regs,m,control,w=ordinary('dispatch',{n:({'rsp':D,'rdi':add('I_rsp',bv(256)),'r8':add(D,bv(256)),'r10':'LastWord','rbx':bv(0)}.get(n,'I_'+n)) for n in GPRS},'CopyDone','Tail')
    roots=[flat['registers'][n] for n in GPRS]+[flat['currentMemory'],flat['control']['target'],flat['pathGuard']]+[last[k] for k in ('address','value','beforeMemory','afterMemory','guard')]
    wanted=[regs[n] for n in GPRS]+[m,control[0],bv(1,8)]+w+[bv(1,8)]
    flat_tail=query('flat-relocation-dispatch-all16-memory-and-final-write','relocation-loop32',roots,wanted,cuts={last['beforeMemory']:'CopyDone',last_word:'LastWord',destination_node:D},extra=f'(declare-const CopyDone {ARRAY})\n(declare-const LastWord (_ BitVec 64))\n(declare-const {D} (_ BitVec 64))\n'+'\n'.join(eq))
    init=f'(declare-const S (_ BitVec 64))\n(declare-const F (_ BitVec 64))\n(assert (= F (bvand {sub("S",bv(648))} {bv(MASK-15)})))'
    pointers=init+f'\n(assert (= I_rsp F))\n(assert (= I_rbp S))\n(assert (= I_rsi {bv(VIP+51)}))\n(assert (= I_r11 {bv(TABLE)}))'
    false_range=f'(and (bvuge S {bv(8)}) (bvult S {bv(264)}))';old_fast=f'(bvugt {sub("S",bv(8))} {add("F",bv(384))})'
    guard=query('joined208-guard-false-exactly8-through263','context208-check12',[cores['context208-check12']['control']['condition']],[flag(f'(not {false_range})')],extra=pointers)
    implication=q.expect(q.query('prior-literal-fast-implies208-fast',init+f'\n(assert {old_fast})\n(assert (not (bvugt {sub("S",bv(8))} {add("F",bv(384))})))'))
    starts=[sub('S',bv(8)),sub('F',bv(8))]
    window=q.expect(q.query('208-both-writes-within-original671-window',init+'\n(assert (or '+' '.join(f'(bvugt {sub(x,sub("S",bv(671)))} {bv(663)})' for x in starts)+'))'))
    nonalias=init+'\n(declare-const slot (_ BitVec 8))\n(declare-const i (_ BitVec 3))\n(declare-const j (_ BitVec 3))\n(assert (or '
    nonalias+=' '.join(f'(= {add(add("F","((_ zero_extend 56) slot)"),"((_ zero_extend 61) i)")} {add(x,"((_ zero_extend 61) j)")})' for x in starts)+'))'
    preserved=q.expect(q.query('208-writes-disjoint-from-all256-context-byte-starts',nonalias))
    mem=init+f'\n(declare-const Before {ARRAY})\n(declare-const T (_ BitVec 64))\n(define-fun After () {ARRAY} {store(store("Before",starts[0],"S",8),starts[1],"T",8)})'
    virtual=q.expect(q.query('208-virtual-stack-word-now-original-s',mem+f'\n(assert (distinct {read("After",starts[0],8)} S))'))
    facts={int(x,16):v for x,v in incoming['initialImageByteFacts']};current={VIP+51:image.read(VIP+51,1)[0],**{TABLE+4*136+i:b for i,b in enumerate(image.read(TABLE+4*136,4))}}
    assert current[VIP+51]==136 and (TABLE+int.from_bytes(image.read(TABLE+4*136,4),'little',signed=True))&MASK==0x1400545b6
    added={x:v for x,v in current.items() if x not in facts};reused={x:v for x,v in current.items() if x in facts};assert len(added)==1 and len(reused)==4 and all(facts[x]==v for x,v in reused.items());facts.update(added);assert len(facts)==76
    c=cores['context208-fast24'];cut=c['stores'][1]['beforeMemory'];assert cut==c['stores'][0]['afterMemory']
    known='\n'.join(f'(assert (= (select DispatchMemory {bv(x)}) {bv(v,8)}))' for x,v in current.items())
    changes={'rsp':'F','rbp':sub('S',bv(8)),'rsi':bv(VIP+52),'r11':bv(TABLE),'rax':bv(136),'rbx':'S','r8':bv(0x1400545b6)}
    roots=[c['registers'][n] for n in GPRS]+[c['currentMemory'],c['control']['target'],c['pathGuard']]
    wanted=[changes.get(n,'I_'+n) for n in GPRS]+[store('DispatchMemory',sub('F',bv(8)),bv(0x1400545b6),8),bv(0x1400545b6),bv(1,8)]
    dispatch_decl=f'(declare-const DispatchMemory {ARRAY})'
    joined=query('208-joined-all16-next136-target-and-dispatch-memory','context208-fast24',roots,wanted,cuts={cut:'DispatchMemory'},extra=dispatch_decl+'\n'+pointers+'\n'+known+f'\n(assert {old_fast})')
    negative=query('negative208-without-dispatch-bytes-target-can-differ','context208-fast24',[c['control']['target']],predicate=lambda xs:f'(distinct {xs[0]} {bv(0x1400545b6)})',cuts={cut:'DispatchMemory'},extra=dispatch_decl+'\n'+pointers,status='sat')
    overlap=query('negative-relocation-overlap-is-sequential-not-initial-snapshot','relocation-loop32',[flat['stores'][1]['value']],predicate=lambda xs:f'(distinct {xs[0]} {read("M0",bv(0x1010),8)})',extra=f'(assert (= I_rsp {bv(0x1008)}))\n(assert (= I_rbp {bv(0x1190)}))',status='sat')
    both=[query('208-free-state-guard-'+str(v),'context208-check12',[cores['context208-check12']['control']['condition']],[bv(v,8)],predicate=lambda xs,v=v:f'(= {xs[0]} {bv(v,8)})',status='sat') for v in (0,1)]
    premises=init+f'\n(declare-const M0 {ARRAY})\n(assert (bvuge {sub(sub("S",bv(671)),bv(image.imagebase))} {bv(domain["image"]["bytes"])}))\n(assert (bvuge {sub(bv(image.imagebase),sub("S",bv(671)))} {bv(671)}))\n(assert {old_fast})'
    premises+='\n'+'\n'.join(f'(assert (= (select M0 {bv(x)}) {bv(v,8)}))' for x,v in facts.items());consistent=q.expect(q.query('208-all76-byte-region-and-fast-premises-consistent',premises,'sat'))
    numeric=numeric_checks(cores,facts,deadline)
    result={'schema':'ig5-handler208-relocation-conditional-proof-v1','passed':True,'sourceReceipt':{'path':a.receipt,'sha256':a.receipt_sha},'alternateReceipt':{'path':a.alternate_receipt,'sha256':a.alternate_sha},'reports':refs,'incomingProof':{'path':a.incoming_proof,'sha256':a.incoming_sha},
        'queries':q.rows,'uncutLocalQueries':local,'public34LayerQueries':layer_queries,'flatDestinationQuery':flat_destination,'flat32CopyQueries':copy_queries,'flatDispatchQuery':flat_tail,
        'joinedGuardQuery':guard,'previousFastImpliesCurrentFastQuery':implication,'joinedGuardFalseInitialRSPRange':[8,263],'newWriteWindowQuery':window,'contextNonaliasQuery':preserved,'virtualStackWordQuery':virtual,'joinedStateQuery':joined,'negativeControls':[negative,overlap],'bothLocalGuardSATQueries':both,'premisesSatisfiableQuery':consistent,
        'flatLoopInduction':{'copies':32,'bodyApplicationsAfterPrefix':31,'copyBytes':256,'wholeSourceDagValidated':True,'eachMemoryCutIsOriginalBeforeMemory':True,'destinationCutIsOriginalFirstStoreAddress':True,'destinationEquationCertifiedByUncutRelocationPrefix':True,'tailLastWordCutIsLastCopyValue':True,'all33OrderedStoreLinksChecked':True,'aliasingPreserved':True,'notOneUncutWholeLoopQuery':True},
        'publicLayerInduction':{'layers':34,'stateBindings':34*18,'stores':34,'sideExits':33,'everyInputFromPreviousFullState':True,'allComplementsFullStateAndOwnWriteGuardsChecked':True,'notOneUncutWholeChainQuery':True},
        'contextPreservation':{'slots':[x['slotByteOffset'] for x in context['contextMap']]+[176,192],'readByteOffsets':list(range(8)),'writeByteOffsets':list(range(8)),'orderedWriteAddresses':['S-8','F-8'],'bytePairInstantiations':19*8*2*8,'incomingSingleBytePreservationQuery':context['lemmas']['bytePreservation'],'all19PriorWordsPreserved':True,'unknownEntry64And25059BitsRemainFree':True},
        'imagePreservation':{'originalWindowBytes':671,'wordStartMax':663,'offsetWidthBridgeLemma':domain['window']['offsetWidthBridgeLemma'],'preservationLemma':domain['window']['preservationLemma'],'imageSeparationLemma':domain['window']['imageSeparationLemma'],'all76FactsPreservedAtEveryPrefix':True},
        'initialImageByteFacts':[[hex(x),v] for x,v in sorted(facts.items())],'addedInitialFacts':[[hex(x),v] for x,v in sorted(added.items())],'reusedInitialFacts':[[hex(x),v] for x,v in sorted(reused.items())],'nextSelector':136,'nextTarget':'0x1400545b6','nextVirtualWord':'original initial RSP S','numeric':numeric,
        'sourceProofScriptSha256':sha(__file__),'encoderSourceSha256':sha(MAIN/'scripts/composition_domain_smt.py'),'solverDllSha256':q.dll_sha,'limits':incoming['limits'],'publicCrossReportJoinIntegrated':False,
        'scope':'Full local ordinary equations, exact public34-layer induction and flat32-copy memory induction. Prior75-byte conditional certificate plus original window/image lemmas connect next136 under76 facts. No CPU/fault/OS/native reachability/complete VM business proof.',
        'nativeTargetExecuted':False,'databaseModified':False,'architectureProved':False,'nativeReachabilityProved':False,'businessAccepted':False,'wholeBinaryVerified':False}
    raw=(json.dumps(result,indent=2)+'\n').encode('utf8');assert len(raw)<=4*1024**2 and time.monotonic()<deadline
    with (out/'verified.json').open('xb') as f:f.write(raw)

def numeric_checks(cores,facts,deadline):
    rng=random.Random(0x32303872656c6f63);states=[]
    for _ in range(128):states.append(({n:rng.getrandbits(64) for n in GPRS},{}))
    for S in list(range(280))+[MASK-i for i in range(16)]:
        r={n:rng.getrandbits(64) for n in GPRS};r.update(rsp=((S-648)&MASK)&(MASK-15),rbp=S);states.append((r,{}))
    for src in (0,16,MASK-15,1<<63):
        for delta in (-256,-16,0,16,240,256):
            r={n:rng.getrandbits(64) for n in GPRS};r.update(rsp=src,rbp=(src+delta+384)&MASK);states.append((r,{}))
    counts={'states':len(states),'reportEvaluations':0,'fast':0,'alternate':0,'fullRelocationPathGuardTrue':0}
    for r,overrides in states:
        assert time.monotonic()<deadline;origin=total_byte(rng.getrandbits(64),overrides);evaluated={}
        def model(kind,regs,overlay):
            out=dict(regs);memory=dict(overlay)
            def word(a,n):return sum(memory.get((a+i)&MASK,origin((a+i)&MASK))<<(8*i) for i in range(n))
            if kind=='check':a=(out['rbp']-8)&MASK;v=out['rbp'];out.update(rbx=v,rbp=a,r8=(out['rsp']+384)&MASK);control=[int(a>out['r8']),0x140052124,0x140052162]
            elif kind in ('relocation','body'):
                a=((out['rbp']-384)&MASK)&(MASK-15) if kind=='relocation' else out['r8'];src=out['rsp'] if kind=='relocation' else out['rdi'];v=word(src,8)
                out.update(rbx=248 if kind=='relocation' else (out['rbx']-8)&MASK,rdi=(src+8)&MASK,r8=(a+8)&MASK,r10=v)
                if kind=='relocation':out['rsp']=a
                control=[int(out['rbx']!=0),0x1400521a6,0x1400521d5]
            else:
                selector=word(out['rsi'],1);disp=word((out['r11']+4*selector)&MASK,4);target=(out['r11']+(disp if disp<1<<31 else disp-(1<<32)))&MASK
                a=(out['rsp']-8)&MASK;v=target;out.update(rax=selector,rsi=(out['rsi']+1)&MASK,r8=target);control=[target]
            memory.update({(a+i)&MASK:(v>>(8*i))&255 for i in range(8)});return out,memory,control,(a,v,dict(overlay),memory)
        def compare(case,expected,mem,control,writes,guard=1,exits=None):
            c=cores[case];v=projection_values(c,r,origin);evaluated[case]=v;counts['reportEvaluations']+=1
            assert {n:v[i] for n,i in c['registers'].items()}==expected and v[c['currentMemory']]==(origin,mem)
            keys=('condition','taken','fallthrough') if len(control)==3 else ('target',)
            assert [v[c['control'][k]] for k in keys]==control and len(c['stores'])==len(writes)
            for s,(a,x,before,after,g) in zip(c['stores'],writes):
                assert [v[s[k]] for k in ('address','value','beforeMemory','afterMemory')]==[a,x,(origin,before),(origin,after)]
                if 'guard' in s:assert v[s['guard']]==g
            if 'pathGuard' in c:assert v[c['pathGuard']]==guard
            if exits is not None:
                assert len(c['sideExits'])==len(exits)
                for e,(er,em,eg,et) in zip(c['sideExits'],exits):assert {n:v[i] for n,i in e['registers'].items()}==er and [v[e[k]] for k in ('currentMemory','guard','target')]==[(origin,em),eg,et]
        cr,cm,cc,cw=model('check',r,{});g=cc[0];counts['fast']+=g;counts['alternate']+=1-g
        compare('context208-check12',cr,cm,cc,[(*cw,1)])
        fr,fm,fc,fw=model('dispatch',cr,cm);compare('context208-fast24',fr,fm,fc,[(*cw,1),(*fw,g)],g,[(cr,cm,1-g,0x140052162)])
        ar,am,ac,aw=model('relocation',cr,cm);compare('context208-alternate41',ar,am,ac,[(*cw,1),(*aw,1-g)],1-g,[(cr,cm,g,0x140052124)])
        rr,rm,rc,rw=model('relocation',r,{});compare('relocation-prefix29',rr,rm,rc,[(*rw,1)])
        br,bm,bc,bw=model('body',r,{});compare('relocation-body13',br,bm,bc,[(*bw,1)])
        flat_writes=[(*rw,1)];flat_boundaries=[(rr,rm,rc)];er,em=rr,rm
        for _ in range(31):er,em,ec,ew=model('body',er,em);flat_writes.append((*ew,1));flat_boundaries.append((er,em,ec))
        er,em,ec,ew=model('dispatch',er,em);flat_writes.append((*ew,1));compare('relocation-loop32',er,em,ec,flat_writes,exits=[(br,bm,0,0x1400521d5 if i<31 else 0x1400521a6) for i,(br,bm,bc) in enumerate(flat_boundaries)])
        fv=evaluated['relocation-loop32']
        for b,(er,em,ec) in zip(cores['relocation-loop32']['boundaries'][:32],flat_boundaries):assert {n:fv[i] for n,i in b['registers'].items()}==er and fv[b['currentMemory']]==(origin,em) and fv[b['control']['condition']]==ec[0]
        writes=[(*cw,1),(*aw,1-g)];exits=[(cr,cm,g,0x140052124)];er,em,ec=ar,am,ac;pg=1-g
        for step in range(1,33):
            selected=step<32;cond=ec[0];exits.append((dict(er),dict(em),pg*(1-cond if selected else cond),ec[2 if selected else 1]));pg*=cond if selected else 1-cond
            if step<32:er,em,ec,ew=model('body',er,em);writes.append((*ew,pg))
        er,em,ec,ew=model('dispatch',er,em);writes.append((*ew,pg));compare('context208-relocation32',er,em,ec,writes,pg,exits);counts['fullRelocationPathGuardTrue']+=pg
    return {**counts,'all16GPRsWholeMemoryOrderedWritesBoundaryConditionsAndFullComplementsCompared':True,'arbitraryCoherentTotalMemoryAndCopyOverlapCases':True,'notIndependentCPUInterpreter':True,'notUniversalProof':True,'sameBatchesAcrossDeploymentsNotExtraCoverage':True}

if __name__=='__main__':main()
