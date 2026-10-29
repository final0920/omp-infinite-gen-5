"""Owned context-load handler: full ordinary state and certified conditional join.

No PE execution. Local universal SMT summaries keep all aliasing and both exits.
Separate memory/pointer certificates justify each current-memory fact at a join.
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
    for name in ('receipt','receipt-sha','context-proof','context-sha','literal-proof','literal-sha','out'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--child',action='store_true');args=parser.parse_args();out=Path(args.out)
    assert all(Path(p).is_absolute() for p in (args.receipt,args.context_proof,args.literal_proof,args.out))
    from lift_runtime import locked_file
    if not args.child:
        from lift_process import run_owned
        out.mkdir(exist_ok=False);job=out/'job';job.mkdir()
        p=run_owned(str(MAIN/'runtimes/ghidra/python/python.exe'),['-I','-B','-X','utf8',str(Path(__file__)),*sys.argv[1:],'--child'],job,budget_ms=50000)
        (out/'process.json').write_text(json.dumps(p,indent=2)+'\n',encoding='utf8');assert p['childExitConfirmed'] and p['jobAssignedAtCreation']
        with locked_file(job/'stderr.log',4*1024**2) as raw:error=raw.decode('utf8')
        if p['exitCode']!=0:
            with locked_file(job/'stdout.log',4*1024**2) as raw:error+='\n'+raw.decode('utf8')[-4096:]
            raise AssertionError(f'Owned handler137 proof exited{p["exitCode"]}: '+error)
        with locked_file(out/'verified.json',4*1024**2) as raw:r=json.loads(raw)
        print(json.dumps({'passed':r['passed'],'queries':len(r['queries']),'statuses':{s:sum(q['status']==s for q in r['queries']) for s in ('unsat','sat','unknown')},
            'initialByteFacts':len(r['initialImageByteFacts']),'nextSelector':r['nextSelector'],'nextTarget':r['nextTarget'],
            'localNumeric':r['localNumeric'],'joinedNumeric':r['joinedNumeric'],'verifiedPath':str(out/'verified.json'),'verifiedSha256':sha(out/'verified.json'),'process':p}));return
    from kernel_image import BinaryImage
    deadline=time.monotonic()+45
    with ExitStack() as held:
        def load(path,pin=None,maximum=4*1024**2):
            raw=held.enter_context(locked_file(Path(path),maximum));assert pin is None or hashlib.sha256(raw).hexdigest()==pin;return json.loads(raw)
        receipt=load(args.receipt,args.receipt_sha);context=load(args.context_proof,args.context_sha);literal=load(args.literal_proof,args.literal_sha)
        assert receipt['passed'] and context['passed'] and literal['passed']
        assert context['schema']=='ig5-context17-conditional-mapping-proof-v1' and literal['schema']=='ig5-handler17-conditional-semantics-proof-v1'
        assert all(p['sourceReceipt']['sha256']==args.receipt_sha for p in (context,literal))
        domain=load(context['incomingDomainProof']['path'],context['incomingDomainProof']['sha256'])
        assert domain['sourceReceipt']['sha256']==args.receipt_sha and domain['caseId']=='entry-plus17'
        assert literal['incomingDomainProof']==context['incomingDomainProof']
        audit=load(Path(context['incomingDomainProof']['path']).parent/'independent-audit.json')
        assert audit['passed'] and audit['proofSha256']==context['incomingDomainProof']['sha256'] and audit['allStoreLinksAndMemoryBindingsChecked']
        for proof,filename in ((domain,'prove_entry_chain_domain.py'),(context,'prove_context_mapping.py'),(literal,'prove_handler17_semantics.py')):
            assert proof['sourceProofScriptSha256']==sha(MAIN/'scripts'/filename) and proof['encoderSourceSha256']==sha(MAIN/'scripts/composition_domain_smt.py')
            for q in proof['queries']:
                assert sha(q['path'])==q['sha256'] and q['timeoutMs']<=2000
                assert q['status']==q['expected'] or q['name']=='all55-write-starts-in671-window' and q['status']=='unknown'
        for source in (args.context_proof,args.literal_proof,context['incomingDomainProof']['path']):
            p=load(Path(source).parent/'process.json',maximum=65536)
            assert p['exitCode']==0 and p['childExitConfirmed'] and p['jobAssignedAtCreation'] and p['activeProcessLimit']==1 and p['memoryLimitBytes']==2147483648
        assert context['all55OrderedMemoryLinksAnd18BindingsChecked'] and len(context['contextMap'])==17
        zero=next(c for c in context['contextMap'] if c['slotByteOffset']==48)
        assert zero['latestEntryStoreIndex']==17 and zero['valueLabel']=='zero' and zero['valueSMT']==bv(0)
        cores={};refs={};byid={c['id']:c for c in receipt['cases']}
        for name in ('entry-plus17','literal-fast-dispatch22','context137-check16','context137-fast28'):
            c=byid[name];assert not c['rejected'] and c['cleanupConfirmed'] and c['rootExitConfirmed']
            ref=c['result'];cores[name]=load(ref['reportPath'],ref['reportSha256'])['result'];refs[name]={'path':ref['reportPath'],'sha256':ref['reportSha256']}
        assert domain['sourceReport']==context['sourceReport']==literal['reports']['entry-plus17']==refs['entry-plus17']
        assert literal['reports']['literal-fast-dispatch22']==refs['literal-fast-dispatch22']
        target=Path(byid['entry-plus17']['args']['target']);data=held.enter_context(locked_file(target,4*1024**2))
        assert hashlib.sha256(data).hexdigest()==domain['targetSha256']=='5f9c1b6fcb019366f835d8f02d9ec3b2957fe619e039410d07f288a9c73f63f0'
        image=BinaryImage.from_bytes(data)
        for core in cores.values():
            assert core['targetSha256']==domain['targetSha256']
            assert all(core[k] is False for k in ('nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'))
            assert all(image.read(int(r['ea'],16),r['decoded']['size']).hex()==r['bytes'] for r in core['decodedPath'])
        check,fast=cores['context137-check16'],cores['context137-fast28']
        assert len(check['projectionPath'])==16 and len(fast['projectionPath'])==28 and check['projectionPath']==fast['projectionPath'][:16]
        assert check['projectionPath'][0]=='0x1400545e7' and fast['projectionPath'][16:]==cores['literal-fast-dispatch22']['projectionPath'][-12:]
        q=Queries(MAIN,out/'queries',deadline)
        try:prove(cores,refs,context,literal,domain,args,q,image,out,deadline)
        finally:q.close()


def prove(cores,refs,context,literal,domain,args,q,image,out,deadline):
    definitions=[];certificates=[]
    def define(name,bits,term):
        sort=ARRAY if bits is None else f'(_ BitVec {bits})';definitions.extend([f'(declare-const E_{name} {sort})',f'(assert (= E_{name} {term}))']);return 'E_'+name
    def different(a,w):assert len(a)==len(w);return '(or '+' '.join(f'(distinct {x} {y})' for x,y in zip(a,w))+')'
    def query(core,name,roots,predicate,*,extra='',cuts=None,expected='unsat'):
        lines,actual,meta=encode(core,roots,cuts=cuts)
        return q.expect(q.query(name,'\n'.join(lines+definitions)+'\n'+extra+'\n(assert '+predicate(actual)+')',expected,meta))
    index=define('index',8,read('M0','I_rsi',1));source=define('source',64,add('I_rsp',f'((_ zero_extend 56) {index})'))
    value=define('value',64,read('M0',source,8));rp=define('rp',64,sub('I_rbp',bv(8)));si=define('si',64,add('I_rsi',bv(1)))
    threshold=define('threshold',64,add('I_rsp',bv(384)));M1=define('M1',None,store('M0',rp,value,8))
    g=define('g',8,f'(ite (bvugt {rp} {threshold}) {bv(1,8)} {bv(0,8)})');ng=define('ng',8,f'(ite (= {g} {bv(0,8)}) {bv(1,8)} {bv(0,8)})')
    changes={'rbx':value,'rdx':f'((_ zero_extend 56) {index})','rsi':si,'rbp':rp,'r8':threshold}
    check=cores['context137-check16'];s=check['stores'][0];assert len(check['stores'])==1 and s['size']==8
    roots=[check['registers'][n] for n in GPRS]+[check['currentMemory'],s['address'],s['value']]+[check['control'][k] for k in ('condition','taken','fallthrough')]
    wanted=[changes.get(n,'I_'+n) for n in GPRS]+[M1,rp,value,g,bv(0x140052124),bv(0x140052162)]
    i=query(check,'check16-all16-gprs-entire-memory-write-and-both-control-targets',roots,lambda a:different(a,wanted));certificates.append({'kind':'complete-check-state','query':i})
    fast=cores['context137-fast28'];s0,s1=fast['stores'];exit=fast['sideExits'][0];assert len(fast['stores'])==2 and len(fast['sideExits'])==1
    selector=define('selector',8,read(M1,si,1));target=define('target',64,add('I_r11',f'((_ sign_extend 32) {read(M1,add("I_r11",f"(bvmul ((_ zero_extend 56) {selector}) {bv(4)})"),4)})'))
    M2=define('M2',None,store(M1,sub('I_rsp',bv(8)),target,8));end={**changes,'rax':f'((_ zero_extend 56) {selector})','rsi':add(si,bv(1)),'r8':target}
    i=query(fast,'fast28-all16-gprs-path-guard-and-return-target',[fast['registers'][n] for n in GPRS]+[fast['pathGuard'],fast['control']['target']],lambda a:different(a,[end.get(n,'I_'+n) for n in GPRS]+[g,target]))
    certificates.append({'kind':'complete-fast-registers-control','query':i,'validOnlyUnderPathGuard':True})
    roots=[fast['currentMemory']]+[s[k] for s in (s0,s1) for k in ('address','value','beforeMemory','afterMemory','guard')]
    i=query(fast,'fast28-entire-memory-both-ordered-stores-and-guards',roots,lambda a:different(a,[M2,rp,value,'M0',M1,bv(1,8),sub('I_rsp',bv(8)),target,M1,M2,g]))
    certificates.append({'kind':'complete-fast-memory-write-order','query':i,'earlyContextStoreNotSuppressedByLaterGuard':True})
    roots=[exit['registers'][n] for n in GPRS]+[exit[k] for k in ('currentMemory','guard','target')]
    i=query(fast,'alternate-check-exit-all16-gprs-entire-memory-and-target',roots,lambda a:different(a,[changes.get(n,'I_'+n) for n in GPRS]+[M1,ng,bv(0x140052162)]))
    certificates.append({'kind':'complete-complementary-exit','query':i,'alternateContinuationNotAnalyzed':True})
    alias=query(check,'negative-reading-context-after-stack-write-can-change-value',[s['value']],lambda a:f'(distinct {a[0]} {read(M1,source,8)})',extra=f'(assert (= {rp} {add(source,bv(1))}))',expected='sat')
    guard_sat=[query(check,'free-state-stack-guard-'+label,[check['control']['condition']],lambda a,v=v:f'(= {a[0]} {bv(v,8)})',expected='sat') for label,v in (('true',1),('false',0))]
    S='S';F='F';L=sub(S,bv(671));vip=image.imagebase+0x846c4;table=image.imagebase+0x56098
    decl=f'(declare-const S (_ BitVec 64))\n(declare-const F (_ BitVec 64))\n(assert (= F (bvand {sub(S,bv(648))} {bv(MASK-15)})))'
    pointers=decl+f'\n(assert (= I_rsp F))\n(assert (= I_rbp {sub(S,bv(8))}))\n(assert (= I_rsi {bv(vip+44)}))\n(assert (= I_r11 {bv(table)}))'
    false_range=f'(and (bvuge S {bv(16)}) (bvult S {bv(264)}))';old_fast=f'(bvugt {sub(S,bv(8))} {add(F,bv(384))})'
    guard=query(check,'joined-137-guard-false-exactly16-through263',[check['control']['condition']],lambda a:f'(distinct {a[0]} (ite {false_range} {bv(0,8)} {bv(1,8)}))',extra=pointers)
    implication=q.expect(q.query('literal-fast-edge-implies-next137-fast-edge',decl+f'\n(assert {old_fast})\n(assert (not (bvugt {sub(S,bv(16))} {add(F,bv(384))})))'))
    new_starts=[sub(S,bv(8)),sub(F,bv(8)),sub(S,bv(16))]
    window=q.expect(q.query('all-new-write-starts-in-original671-window',decl+'\n(assert (or '+' '.join(f'(bvugt {sub(a,L)} {bv(663)})' for a in new_starts)+'))'))
    slots=[c['slotByteOffset'] for c in context['contextMap']];assert len(set(slots))==17
    memdecl=decl+f'\n(declare-const A0 {ARRAY})\n(declare-const A1 {ARRAY})\n(declare-const A2 {ARRAY})\n(declare-const A3 {ARRAY})\n'
    memdecl+='\n'.join(f'(declare-const W{i} (_ BitVec 64))' for i in range(3))
    for i,address in enumerate(new_starts):memdecl+=f'\n(assert (= A{i+1} {store("A"+str(i),address,"W"+str(i),8)}))'
    whole_preservation=q.query('all17-context-words-preserved-by-literal-dispatch-and-next-stack-write',memdecl+'\n(assert '+different([read('A3',add(F,bv(slot)),8) for slot in slots],[read('A0',add(F,bv(slot)),8) for slot in slots])+')')
    assert q.rows[whole_preservation]['status'] in ('unsat','unknown')
    # Retain a timed-out whole-array query. Prove every byte pair disjoint,
    # then instantiate the incoming universal single-byte preservation lemma
    # for all17 words,8 read bytes and the four8-byte post-entry writes.
    assert all(type(slot) is int and 0<=slot<=255 for slot in slots)
    byte_decl=decl+'\n(declare-const slot (_ BitVec 8))\n(declare-const i (_ BitVec 3))\n(declare-const j (_ BitVec 3))'
    destination=add(add(F,'((_ zero_extend 56) slot)'),'((_ zero_extend 61) i)')
    nonalias='(or '+' '.join(f'(= {destination} {add(a,"((_ zero_extend 61) j)")})' for a in new_starts)+')'
    preserved=q.expect(q.query('all-context-bytes-disjoint-from-every-new-write-byte',byte_decl+'\n(assert '+nonalias+')'))
    byte_preservation=context['lemmas']['bytePreservation'];assert context['queries'][byte_preservation]['status']=='unsat'
    operand=image.read(vip+44,1)[0];opcode=image.read(vip+45,1)[0];word_address=table+4*opcode;word=image.read(word_address,4);target_value=(table+int.from_bytes(word,'little',signed=True))&MASK
    assert operand==48 and opcode==250 and target_value==0x140055f66 and literal['nextSelector']==137 and literal['nextTarget']=='0x1400545e7'
    facts={int(a,16):v for a,v in context['initialImageByteFacts']}
    for a,v in literal['extraInitialImageByteFacts']:
        a=int(a,16);assert a not in facts or facts[a]==v;facts[a]=v
    extras={vip+44:operand,vip+45:opcode,**{word_address+i:b for i,b in enumerate(word)}};assert not set(facts)&set(extras);facts.update(extras);assert len(facts)==66
    current_facts=f'(assert (= (select M0 {bv(vip+44)}) {bv(operand,8)}))\n(assert (= {read("M0",add(F,bv(48)),8)} {bv(0)}))'
    loaded=query(check,'derived-context48-word-reads-the-later-entry-zero',[s['value']],lambda a:f'(distinct {a[0]} {bv(0)})',extra=pointers+'\n'+current_facts)
    dispatch_facts='\n'.join(f'(assert (= (select M_dispatch {bv(a)}) {bv(v,8)}))' for a,v in extras.items() if a!=vip+44)
    next_target=query(fast,'next250-target-from-five-derived-current-image-bytes',[fast['control']['target']],lambda a:f'(distinct {a[0]} {bv(target_value)})',cuts={s1['beforeMemory']:'M_dispatch'},extra=pointers+'\n'+dispatch_facts)
    joined_changes={'rsp':F,'rbp':sub(S,bv(16)),'rsi':bv(vip+46),'r11':bv(table),'rax':bv(opcode),'rdx':bv(operand),'rbx':bv(0),'r8':bv(target_value)}
    roots=[fast['registers'][n] for n in GPRS]+[fast['pathGuard'],fast['control']['target'],fast['currentMemory']]
    wanted=[joined_changes.get(n,'I_'+n) for n in GPRS]+[bv(1,8),bv(target_value),store('M_dispatch',sub(F,bv(8)),bv(target_value),8)]
    joined=query(fast,'joined-all16-gprs-guard-target-and-final-dispatch-memory',roots,lambda a:different(a,wanted),cuts={s1['beforeMemory']:'M_dispatch'},extra=pointers+'\n'+current_facts+'\n'+dispatch_facts+f'\n(assert {old_fast})')
    no_word=query(check,'negative-without-context-word-zero-premise-value-can-differ',[s['value']],lambda a:f'(distinct {a[0]} {bv(0)})',extra=pointers+f'\n(assert (= (select M0 {bv(vip+44)}) {bv(48,8)}))',expected='sat')
    no_operand=query(check,'negative-without-operand-byte-premise-value-can-differ',[s['value']],lambda a:f'(distinct {a[0]} {bv(0)})',extra=pointers+f'\n(assert (= {read("M0",add(F,bv(48)),8)} {bv(0)}))',expected='sat')
    no_target=query(fast,'negative-without-next-selector-and-table-premises-target-can-differ',[fast['control']['target']],lambda a:f'(distinct {a[0]} {bv(target_value)})',cuts={s1['beforeMemory']:'M_dispatch'},extra=pointers,expected='sat')
    premises=decl+f'\n(declare-const M0 {ARRAY})\n(assert (bvuge {sub(L,bv(image.imagebase))} {bv(domain["image"]["bytes"])}))\n(assert (bvuge {sub(bv(image.imagebase),L)} {bv(671)}))\n(assert {old_fast})\n'
    premises+='\n'.join(f'(assert (= (select M0 {bv(a)}) {bv(v,8)}))' for a,v in facts.items())
    consistent=q.expect(q.query('all66-initial-image-byte-region-and-fast-edge-premises-consistent',premises,'sat'))
    local_numeric=numeric_local(cores,deadline);joined_numeric=numeric_join(cores,facts,slots,deadline)
    result={'schema':'ig5-handler137-conditional-semantics-proof-v1','passed':True,'sourceReceipt':{'path':args.receipt,'sha256':args.receipt_sha},'reports':refs,
        'incomingContextProof':{'path':args.context_proof,'sha256':args.context_sha},'incomingLiteralProof':{'path':args.literal_proof,'sha256':args.literal_sha},'incomingDomainProof':context['incomingDomainProof'],
        'queries':q.rows,'localSummaryCertificates':certificates,'loadBeforeWriteAliasNegativeQuery':alias,'bothLocalGuardDirectionsSATQueries':guard_sat,
        'joinedGuardFalseRangeQuery':guard,'joinedGuardFalseInitialRSPRange':[16,263],'previousFastImpliesCurrentFastQuery':implication,
        'newWriteWindowQuery':window,'newWriteAddresses':['S-8','F-8','S-16'],'wholeContextPreservationQuery':whole_preservation,
        'contextWordNonaliasQuery':preserved,'contextPreservationCertificate':{'method':'Explicit finite pointwise byte-memory induction','slots':slots,
            'readByteOffsets':list(range(8)),'newOrderedWriteAddresses':['S-8','F-8','S-16','F-8'],'writeByteOffsets':list(range(8)),
            'allBytePairNonaliasQuery':preserved,'incomingSingleBytePreservationQuery':byte_preservation,
            'all17ContextWordsPreserved':True,'noNodeIdInequalityUsed':True,'wholeQueryUnknownNotUsedAsProof':True},
        'contextSlot48SourceCertificate':next(c for c in context['contextMap'] if c['slotByteOffset']==48),'contextZeroReadQuery':loaded,
        'nextTargetQuery':next_target,'joinedAll16StateAndFinalDispatchMemoryQuery':joined,'nextTargetCurrentMemoryCut':s1['beforeMemory'],
        'memoryFactDerivation':{'originalOrderedWrites':55,'originalBindings':18,'originalImagePreservationLemma':domain['window']['preservationLemma'],
            'originalImageSeparationLemma':domain['window']['imageSeparationLemma'],'allNewWritesInSameWindowQuery':window,
            'contextWordNonaliasQuery':preserved,'contextWordBytePreservationIncomingQuery':byte_preservation,'contextZeroIsLaterEntryWrite17NotMemoryDefault':True,
            'eachNewPrefixPreservesAll66StatedInitialImageBytes':'Apply original universal byte-window/image-separation preservation lemma to each four new8-byte writes; frame-8 dispatcher write occurs twice.'},
        'negativeControls':[alias,no_word,no_operand,no_target],'premisesSatisfiableQuery':consistent,
        'initialImageByteFacts':[[hex(a),v] for a,v in sorted(facts.items())],'additionalInitialByteFacts':[[hex(a),v] for a,v in sorted(extras.items())],
        'nextSelector':opcode,'nextTarget':hex(target_value),'contextOperand':operand,'contextLoadedValue':'0x0',
        'localNumeric':local_numeric,'joinedNumeric':joined_numeric,'sourceProofScriptSha256':sha(__file__),'encoderSourceSha256':sha(MAIN/'scripts/composition_domain_smt.py'),
        'solverDllSha256':q.dll_sha,'limits':domain['limits'],'publicCrossReportJoinIntegrated':False,
        'joinScope':'Complete local free-state summaries plus explicit certified pointer, context-memory and image-preservation relations. Final memory cut is justified by the original ordered store. No public budget bypass, monolithic whole-VM certificate or CPU execution.',
        'unproven':['Native stack allocation, loaded bytes and relocation correspondence','Independent CPU/fault/flags equivalence','Alternate stack-relocation continuation and remaining VM ISA/business/path coverage','Exact3.8 and complete Ultra/Enigma business recovery'],
        'nativeTargetExecuted':False,'databaseModified':False,'architectureProved':False,'businessAccepted':False,'wholeBinaryVerified':False}
    raw=(json.dumps(result,indent=2)+'\n').encode('utf8');assert len(raw)<=4*1024**2 and time.monotonic()<deadline
    with (out/'verified.json').open('xb') as stream:stream.write(raw)


def numeric_local(cores,deadline):
    rng=random.Random(0x636f6e74657874313337);states=[]
    for _ in range(512):states.append(({n:rng.getrandbits(64) for n in NAMES},rng.getrandbits(64),{}))
    for S in list(range(672))+[MASK-i for i in range(16)]:
        r={n:rng.getrandbits(64) for n in NAMES};r.update(rsp=((S-648)&MASK)&(MASK-15),rbp=(S-8)&MASK);states.append((r,rng.getrandbits(64),{}))
    for base in (0,1,MASK-7,MASK):
        for index in (0,1,127,255):
            for delta in range(-7,8):
                for position in (-1,0,7):
                    r={n:rng.getrandbits(64) for n in NAMES};source=(base+index)&MASK;r.update(rsp=base,rbp=(source+delta+8)&MASK,rsi=(source+position)&MASK)
                    states.append((r,rng.getrandbits(64),{r['rsi']:index}))
    counts={'states':len(states),'evaluations':2*len(states),'fast':0,'alternate':0}
    for r,seed,facts in states:
        assert time.monotonic()<deadline;origin=total_byte(seed,facts);index=origin(r['rsi']);source=(r['rsp']+index)&MASK
        value=sum(origin((source+i)&MASK)<<(8*i) for i in range(8));rp=(r['rbp']-8)&MASK;si=(r['rsi']+1)&MASK;threshold=(r['rsp']+384)&MASK;g=int(rp>threshold)
        overlay={(rp+i)&MASK:(value>>(8*i))&255 for i in range(8)}
        def get(a,n):return sum(overlay.get((a+i)&MASK,origin((a+i)&MASK))<<(8*i) for i in range(n))
        selector=get(si,1);word=get(r['r11']+4*selector,4);target=(r['r11']+(word if word<1<<31 else word-(1<<32)))&MASK
        final={**overlay,**{(r['rsp']-8+i)&MASK:(target>>(8*i))&255 for i in range(8)}}
        changes={'rbx':value,'rdx':index,'rsi':si,'rbp':rp,'r8':threshold}
        for name in ('context137-check16','context137-fast28'):
            c=cores[name];v=projection_values(c,r,origin);fast=name.endswith('fast28');expected={**r,**changes}
            if fast:expected.update(rax=selector,r8=target,rsi=(si+1)&MASK)
            assert {n:v[x] for n,x in c['registers'].items()}==expected and v[c['currentMemory']]==(origin,final if fast else overlay)
            if not fast:assert v[c['control']['condition']]==g and v[c['control']['taken']]==0x140052124 and v[c['control']['fallthrough']]==0x140052162
            else:
                assert v[c['pathGuard']]==g and v[c['control']['target']]==target and v[c['stores'][0]['guard']]==1 and v[c['stores'][1]['guard']]==g
                e=c['sideExits'][0];assert v[e['guard']]==1-g and v[e['target']]==0x140052162 and v[e['currentMemory']]==(origin,overlay)
                assert {n:v[x] for n,x in e['registers'].items()}=={**r,**changes}
        counts['fast']+=g;counts['alternate']+=1-g
    return {**counts,'all16GPRsWholeMemoryControlOrderedStoresAndFullAlternateExitCompared':True,'includes720ByteAliasCases':True,'includesAll672SmallJoinedStackValues':True,'arbitraryCoherentTotalMemory':True,'notIndependentCPUInterpreter':True,'notUniversalProof':True}


def numeric_join(cores,facts,slots,deadline):
    rng=random.Random(0x6a6f696e313337);vip=0x1400846c4;base=0x140000000;size=1384448
    stacks=[rng.getrandbits(64) for _ in range(512)]+list(range(672))+[(vip-256+i*8)&MASK for i in range(64)]+[MASK-i for i in range(16)]
    counts={'states':len(stacks),'separatedEntry':0,'nonseparatedSkipped':0,'literalAlternate':0,'reached137Fast':0,'reached137Alternate':0}
    def get_memory(pair):
        initial,overlay=pair
        return lambda a:overlay.get(a&MASK,initial(a&MASK))
    def run(c,r,m,unknowns=None):
        v=projection_values(c,r,m,unknowns=unknowns)
        return v,{n:v[i] for n,i in c['registers'].items()},get_memory(v[c['currentMemory']])
    def word(memory,address):return sum(memory((address+i)&MASK)<<(8*i) for i in range(8))
    for S in stacks:
        assert time.monotonic()<deadline;L=(S-671)&MASK
        if ((L-base)&MASK)<size or ((base-L)&MASK)<671:counts['nonseparatedSkipped']+=1;continue
        counts['separatedEntry']+=1;r={n:rng.getrandbits(64) for n in NAMES};r['rsp']=S;origin=total_byte(rng.getrandbits(64),facts)
        entry=cores['entry-plus17'];unknowns={entry['dag']['nodes'][x['node']]['name']:rng.getrandbits(64) for x in entry['nondeterministicInputs']}
        v,r1,m1=run(entry,r,origin,unknowns);assert v[entry['pathGuard']]==1 and v[entry['control']['target']]==0x1400525ca
        F=((S-648)&MASK)&(MASK-15);saved={slot:word(m1,F+slot) for slot in slots};assert saved[48]==0
        c=cores['literal-fast-dispatch22'];v,r2,m2=run(c,r1,m1)
        assert v[c['pathGuard']]==int(not 8<=S<264)
        if not v[c['pathGuard']]:counts['literalAlternate']+=1;continue
        assert v[c['control']['target']]==0x1400545e7 and all(word(m2,F+slot)==x for slot,x in saved.items())
        c=cores['context137-fast28'];v,r3,m3=run(c,r2,m2)
        assert v[c['stores'][0]['value']]==0 and r3['rdx']==48 and r3['rbx']==0 and all(word(m3,F+slot)==x for slot,x in saved.items())
        if not v[c['pathGuard']]:counts['reached137Alternate']+=1;continue
        counts['reached137Fast']+=1;assert r3['rax']==250 and r3['r8']==v[c['control']['target']]==0x140055f66
        assert r3['rsp']==F and r3['rbp']==(S-16)&MASK and r3['rsi']==vip+46
    assert counts['separatedEntry']==1200 and counts['literalAlternate']==256 and counts['reached137Fast']==944 and counts['reached137Alternate']==0
    return {**counts,'only66InitialImageBytesFixed':True,'all17ContextWordsPreservedAcrossBothHandlers':True,'opaqueFlagImageVaries':True,'guardFalseFinalStatesNeverUsedAsNextInputs':True,'notIndependentCPUInterpreter':True,'notUniversalProof':True}


if __name__=='__main__':main()
