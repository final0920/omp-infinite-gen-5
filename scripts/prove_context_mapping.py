"""Conditional17-slot context mapping from the complete owned entry+17 DAG.

No target execution. Universal local SMT lemmas plus checked ordered-memory
induction keep source words, overwrite order and all free opaque values.
"""
from contextlib import ExitStack
from pathlib import Path
import argparse,hashlib,json,random,sys,time
MAIN=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(MAIN/'worker'),str(MAIN/'scripts')]
from composition_domain_smt import ARRAY,Queries,add,sub,bv,read,store,encode,sha
from projection_numerical_oracle import MASK,NAMES,total_byte,projection_values
OFFSETS=[8*i for i in range(1,18)]+[72,16,8]
SLOTS=[136,96,80,184,64,120,144,168,48,16,88,104,56,160,32,8,72]
LABELS=['opaque-flag-image','rdx','r14','r13','r8','rbp','rsi','r10','zero','r15','r9','rax','rbx','r11','rcx','r12','rdi']

def main():
    parser=argparse.ArgumentParser()
    for name in ('receipt','receipt-sha','domain-proof','domain-sha','out'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--child',action='store_true');args=parser.parse_args();out=Path(args.out)
    assert out.is_absolute() and Path(args.receipt).is_absolute() and Path(args.domain_proof).is_absolute()
    from lift_runtime import locked_file
    if not args.child:
        from lift_process import run_owned
        out.mkdir(exist_ok=False);job=out/'job';job.mkdir()
        p=run_owned(str(MAIN/'runtimes/ghidra/python/python.exe'),['-I','-B','-X','utf8',str(Path(__file__)),*sys.argv[1:],'--child'],job,budget_ms=50000)
        (out/'process.json').write_text(json.dumps(p,indent=2)+'\n',encoding='utf8');assert p['childExitConfirmed'] and p['jobAssignedAtCreation']
        with locked_file(job/'stderr.log',4*1024**2) as raw:error=raw.decode('utf8')
        if p['exitCode']!=0:
            with locked_file(job/'stdout.log',4*1024**2) as raw:error+='\n'+raw.decode('utf8')[-4096:]
            raise AssertionError(f'Owned context proof exited{p["exitCode"]}: '+error)
        with locked_file(out/'verified.json',4*1024**2) as raw:r=json.loads(raw)
        print(json.dumps({'passed':r['passed'],'queries':len(r['queries']),'statuses':{s:sum(q['status']==s for q in r['queries']) for s in ('unsat','sat','unknown')},
            'contextSlots':len(r['contextMap']),'initialByteFacts':len(r['initialImageByteFacts']),'numeric':r['numeric'],'verifiedPath':str(out/'verified.json'),'verifiedSha256':sha(out/'verified.json'),'process':p}));return
    from kernel_image import BinaryImage
    deadline=time.monotonic()+45
    with ExitStack() as held:
        def load(path,pin=None):
            raw=held.enter_context(locked_file(Path(path),4*1024**2));assert pin is None or hashlib.sha256(raw).hexdigest()==pin;return json.loads(raw)
        receipt=load(args.receipt,args.receipt_sha);domain=load(args.domain_proof,args.domain_sha)
        audit=load(Path(args.domain_proof).parent/'independent-audit.json');assert audit['passed'] and audit['proofSha256']==args.domain_sha and audit['allStoreLinksAndMemoryBindingsChecked']
        assert receipt['passed'] and domain['passed'] and domain['schema']=='ig5-entry-chain-conditional-domain-proof-v2' and domain['caseId']=='entry-plus17'
        assert domain['sourceReceipt']['sha256']==args.receipt_sha and domain['applications']==18 and domain['orderedStoreCount']==55
        assert domain['encoderSourceSha256']==sha(MAIN/'scripts/composition_domain_smt.py')
        assert domain['sourceProofScriptSha256']==sha(MAIN/'scripts/prove_entry_chain_domain.py')
        for row in domain['queries']:
            assert sha(row['path'])==row['sha256'] and row['timeoutMs']<=2000
            assert row['status']==row['expected'] or row['name']=='all55-write-starts-in671-window' and row['status']=='unknown'
        for c in domain['certificates']:
            for i in c.get('queries',[c.get('query')]):assert domain['queries'][i]['status']=='unsat'
        assert next(c for c in domain['certificates'] if c['kind']=='exact-address-decomposition')['first20Offsets']==OFFSETS
        case=next(c for c in receipt['cases'] if c['id']=='entry-plus17');assert not case['rejected'] and case['rootExitConfirmed'] and case['cleanupConfirmed']
        core=load(case['result']['reportPath'],case['result']['reportSha256'])['result'];assert domain['sourceReport']['sha256']==case['result']['reportSha256']
        target=Path(case['args']['target']);data=held.enter_context(locked_file(target,4*1024**2));assert hashlib.sha256(data).hexdigest()==core['targetSha256']=='5f9c1b6fcb019366f835d8f02d9ec3b2957fe619e039410d07f288a9c73f63f0'
        image=BinaryImage.from_bytes(data);q=Queries(MAIN,out/'queries',deadline)
        try:prove(core,domain,audit,args,q,image,out,deadline)
        finally:q.close()

def prove(core,domain,audit,args,q,image,out,deadline):
    nodes=core['dag']['nodes'];stores=core['stores'];layers=core['layers'];assert len(stores)==55 and len(layers)==18
    def query(name,roots,predicate,*,cuts=None,extra='',expected='unsat'):
        lines,actual,meta=encode(core,roots,cuts=cuts)
        # Cuts must be declared before the DAG equalities that reference them.
        return q.expect(q.query(name,extra+'\n'+'\n'.join(lines)+'\n(assert '+predicate(actual)+')',expected,meta))
    def diff(actual,wanted):return '(or '+' '.join(f'(distinct {a} {b})' for a,b in zip(actual,wanted))+')'
    S='I_rsp';frame=f'(bvand {sub(S,bv(648))} {bv(MASK-15)})';vip=image.imagebase+0x846c4
    opaque=core['nondeterministicInputs'];assert len(opaque)==1 and nodes[opaque[0]['node']]['kind']=='unknown-pushed-flag-image'
    unknown=f'opaque_{opaque[0]["node"]}'
    expected=[bv(0xfffffffff2e7defb),bv(0x1400141b4),*['I_'+n for n in ['rcx','r11','rbx','rax','r9','r15','rax','r10','rsi','rbp','r8','r13','r14','rdx']],unknown,bv(0),'I_r12','I_rdi']
    assert len(expected)==20
    entry_values=query('all20-entry-store-values-keep-original-overwrites',[s['value'] for s in stores[:20]],lambda a:diff(a,expected))
    def lemma(name,declarations,assumptions,counterexample):
        return q.expect(q.query(name,declarations+'\n'+'\n'.join('(assert '+x+')' for x in assumptions)+'\n(assert '+counterexample+')'))
    basic=f'(declare-const M {ARRAY})\n(declare-const A (_ BitVec 64))\n(declare-const P (_ BitVec 64))\n(declare-const V (_ BitVec 64))\n(declare-const B (_ BitVec 8))'
    own=lemma('whole-little-endian-word-written-at-own-address',basic,[],f'(distinct {read(store("M","A","V",8),"A",8)} V)')
    preserve=lemma('a-disjoint-write-byte-preserves-read-byte',basic,['(distinct A P)'],'(distinct (select (store M A B) P) (select M P))')
    decl='(declare-const S (_ BitVec 64))\n(declare-const a (_ BitVec 8))\n(declare-const b (_ BitVec 8))\n(declare-const i (_ BitVec 3))\n(declare-const j (_ BitVec 3))\n(declare-const align (_ BitVec 4))'
    z=lambda name,bits:f'((_ zero_extend {64-bits}) {name})'
    sa=sub('S',z('a',8));sb=sub('S',z('b',8));i=z('i',3);j=z('j',3)
    distinct_words=lemma('distinct-aligned-relative-word-offsets-have-no-shared-byte',decl,
        [f'(= (bvand a {bv(7,8)}) {bv(0,8)})',f'(= (bvand b {bv(7,8)}) {bv(0,8)})','(distinct a b)'],f'(= {add(sa,i)} {add(sb,j)})')
    F=sub(sub('S',bv(648)),z('align',4));context=add(F,z('b',8));push=sub(F,bv(8))
    source_range=[f'(bvuge a {bv(8,8)})',f'(bvule a {bv(136,8)})']
    context_saved=lemma('all-byte-context-offsets-disjoint-from17-source-words',decl,source_range,f'(= {add(context,i)} {add(sa,j)})')
    push_saved=lemma('frame-dispatch-push-disjoint-from17-source-words',decl,source_range,f'(= {add(push,i)} {add(sa,j)})')
    push_context=lemma('frame-dispatch-push-disjoint-from-context-words',decl,[],f'(= {add(push,i)} {add(context,j)})')
    assert len(set(SLOTS))==17 and all(0<=slot<=255 and slot%8==0 for slot in SLOTS)
    assert all(image.read(vip+2*step+1,1)[0]==slot for step,slot in enumerate(SLOTS))
    facts={int(a,16):v for a,v in domain['initialImageByteFacts']};extra={vip+2*step+1:slot for step,slot in enumerate(SLOTS)};assert not set(facts)&set(extra);facts.update(extra);assert len(facts)==47
    latest={offset:index for index,offset in enumerate(OFFSETS)};certificates=[];previous=core['initialMemory'];link_count=0
    for step,layer in enumerate(layers):
        assert layer['inputMemory']==previous
        for s in [s for s in stores if s['stepIndex']==step]:
            n=nodes[s['afterMemory']];assert s['size']==8 and s['beforeMemory']==previous and s['guard']==layer['entryGuard']
            assert n['op']=='store_le' and n['size']==8 and n['args']==[previous,s['address'],s['value']]
            previous=s['afterMemory'];link_count+=1
        binding=nodes[layer['currentMemory']];assert binding['op']=='state_binding' and binding['source']==previous;previous=layer['currentMemory']
    assert link_count==55 and previous==core['currentMemory']
    # These cuts are universally arbitrary current arrays. Each current operand
    # fact follows separately from the pinned domain's image preservation and
    # the additional explicit initial byte; no observed memory is substituted.
    for step,(slot,label) in enumerate(zip(SLOTS,LABELS),1):
        body=[s for s in stores if s['stepIndex']==step];assert len(body)==2 and body[0]['beforeMemory']==layers[step]['inputMemory']
        memory=body[0]['beforeMemory'];address=vip+2*(step-1)+1;offset=136-8*(step-1);source=latest[offset]
        scalar=read('M_context',sub(S,bv(offset)),8)
        identity=query(f'context-store-{step:02}-source-and-destination',[body[0]['value'],body[0]['address']],lambda a,s=scalar,w=add(frame,bv(slot)):diff(a,[s,w]),
            cuts={memory:'M_context'},extra=f'(declare-const M_context {ARRAY})\n(assert (= (select M_context {bv(address)}) {bv(slot,8)}))')
        # Every earlier frame write misses every saved source word. Each later
        # context word is a different aligned8 slot; each later frame PUSH is
        # disjoint. This finite induction applies byte preservation8 times per
        # write and own-word readback once. Do not skip the3 late entry stores.
        earlier=[s for s in stores[21:] if s['stepIndex']<step]
        later=[s for s in stores[21:] if s['stepIndex']>step]+[body[1]]
        assert len(earlier)==2*(step-1) and len(later)==2*(17-step)+1
        # Node-ID inequality is not an address-disjointness certificate. Use
        # distinct concrete slot offsets and the universal byte lemmas instead.
        assert all(SLOTS[k-1]!=slot for k in range(step+1,18))
        certificates.append({'stepIndex':step,'slotByteOffset':slot,'valueLabel':label,'valueSMT':expected[source],
            'sourceStackOffset':offset,'latestEntryStoreIndex':source,'entryValueQuery':entry_values,
            'sourceValueNode':stores[source]['value'],'contextStoreValueNode':body[0]['value'],'contextStoreAddressNode':body[0]['address'],
            'localCurrentMemoryNode':memory,'currentOperandAddress':hex(address),'currentOperandByte':slot,'localIdentityQuery':identity,
            'initialSavedWordConstruction':[own,preserve,distinct_words],'savedWordPreservedByPriorFrameWrites':[preserve,context_saved,push_saved],
            'finalContextWordPreservedByLaterWrites':[own,preserve,distinct_words,push_context],
            'entryDispatchPushStoreIndex':20,'priorSourcePreservationStoreIndices':list(range(20,21+2*(step-1))),
            'earlierBodyWritesChecked':len(earlier),'laterBodyWritesChecked':len(later),
            'laterContextSlots':SLOTS[step:],'laterPreservationStoreIndices':list(range(22+2*(step-1),55)),
            'allCurrentImageOperandsDerivedFromInitialFacts':True})
    first=[s for s in stores if s['stepIndex']==1][0]
    missing=query('negative-without-first-operand-fact-destination-can-change',[first['address']],lambda a:f'(distinct {a[0]} {add(frame,bv(SLOTS[0]))})',cuts={first['beforeMemory']:'M_context'},extra=f'(declare-const M_context {ARRAY})',expected='sat')
    overwrite=query('negative-dropping-sminus72-zero-overwrite-changes-source',[stores[17]['value']],lambda a:f'(distinct {a[0]} I_rax)',expected='sat')
    premises=f'(declare-const S (_ BitVec 64))\n(declare-const M0 {ARRAY})\n';L=sub('S',bv(671));base=image.imagebase
    premises+=f'(assert (bvuge {sub(L,bv(base))} {bv(domain["image"]["bytes"])}))\n(assert (bvuge {sub(bv(base),L)} {bv(671)}))\n'
    premises+='\n'.join(f'(assert (= (select M0 {bv(a)}) {bv(v,8)}))' for a,v in facts.items())
    consistent=q.expect(q.query('all47-initial-byte-and-region-premises-consistent',premises,'sat'))
    numeric=check_numeric(core,facts,deadline)
    result={'schema':'ig5-context17-conditional-mapping-proof-v1','passed':True,'sourceReceipt':{'path':args.receipt,'sha256':args.receipt_sha},
        'incomingDomainProof':{'path':args.domain_proof,'sha256':args.domain_sha},'sourceReport':domain['sourceReport'],'targetSha256':core['targetSha256'],
        'queries':q.rows,'contextMap':certificates,'initialImageByteFacts':[[hex(a),v] for a,v in sorted(facts.items())],
        'additionalOddOperandByteFacts':[[hex(a),v] for a,v in sorted(extra.items())],'initialByteFactCount':47,'regionPremises':domain['regionPremises'],
        'all55OrderedMemoryLinksAnd18BindingsChecked':True,'initialLatestWriteOffsets':OFFSETS,'initialStoreValueQuery':entry_values,
        'lemmas':{'ownWord':own,'bytePreservation':preserve,'distinctAlignedRelativeWords':distinct_words,'contextSavedWords':context_saved,'framePushSavedWords':push_saved,'framePushContextWords':push_context},
        'negativeControls':[missing,overwrite],'premisesSatisfiableQuery':consistent,'numeric':numeric,
        'contextSlot48ConditionalValue':'0x0 from the later entry S-72 write; not initialRAX and not memory default',
        'opaqueFlagImageRemainsFree':True,'originalGPRSlots':15,'initialRSPContextSlotClaimed':False,
        'inductionScope':'Finite checked pointwise byte-memory induction using universally proved local lemmas, original store/binding links and derived current image operands. No single monolithic whole-context SMT query or independent CPU certificate is claimed.',
        'publicCrossReportJoinIntegrated':False,'sourceProofScriptSha256':sha(__file__),'encoderSourceSha256':sha(MAIN/'scripts/composition_domain_smt.py'),'solverDllSha256':q.dll_sha,'limits':domain['limits'],
        'unproven':['Native stack allocation and loaded code/data/relocation correspondence','Independent CPU/fault/flags equivalence','Context137 continuation/current-state composition and remaining VM ISA/business/path coverage','Exact3.8 and complete Ultra/Enigma business recovery'],
        'nativeTargetExecuted':False,'databaseModified':False,'architectureProved':False,'businessAccepted':False,'wholeBinaryVerified':False}
    raw=(json.dumps(result,indent=2)+'\n').encode('utf8');assert len(raw)<=4*1024**2 and time.monotonic()<deadline
    with (out/'verified.json').open('xb') as stream:stream.write(raw)

def check_numeric(core,facts,deadline):
    rng=random.Random(0x636f6e746578743137);vip=0x1400846c4;base=0x140000000;size=1384448
    stacks=[rng.getrandbits(64) for _ in range(512)]+list(range(672))+[(vip-256+i*8)&MASK for i in range(64)]+[MASK-i for i in range(16)]
    stacks=list(dict.fromkeys(stacks));counts={'separatedAll17Match':0,'overlapAll17Match':0,'overlapMismatch':0};witness=None
    for S in stacks:
        assert time.monotonic()<deadline;r={n:rng.getrandbits(64) for n in NAMES};r['rsp']=S;origin=total_byte(rng.getrandbits(64),facts)
        unknowns={core['dag']['nodes'][x['node']]['name']:rng.getrandbits(64) for x in core['nondeterministicInputs']};opaque=next(iter(unknowns.values()))
        values=projection_values(core,r,origin,unknowns=unknowns);memory,overlay=values[core['currentMemory']];F=((S-648)&MASK)&(MASK-15);L=(S-671)&MASK
        separated=((L-base)&MASK)>=size and ((base-L)&MASK)>=671
        def word(a):return sum(overlay.get((a+i)&MASK,memory((a+i)&MASK))<<(8*i) for i in range(8))
        expected=[opaque if n=='opaque-flag-image' else 0 if n=='zero' else r[n] for n in LABELS]
        matches=[word(F+slot)==want for slot,want in zip(SLOTS,expected)]
        if separated:assert all(matches) and values[core['pathGuard']]==1;counts['separatedAll17Match']+=1
        elif all(matches):counts['overlapAll17Match']+=1
        else:
            counts['overlapMismatch']+=1
            if witness is None:witness={'initialRSP':hex(S),'mismatchedSlots':[slot for slot,ok in zip(SLOTS,matches) if not ok],'guard':values[core['pathGuard']]}
    assert counts['separatedAll17Match']>=1024 and counts['overlapMismatch']>0
    return {'states':len(stacks),'results':counts,'overlapWitness':witness,'all17CellsChecked':True,'only47InitialBytesFixed':True,'otherMemoryArbitraryDeterministicTotal':True,
        'all672SmallInitialStackValuesIncluded':True,'opaqueFlagImageVariesAndIsNotConstant':True,'overlapGuardFalseStatesAreHypothetical':True,'notIndependentCPUInterpreter':True,'notUniversalProof':True}

if __name__=='__main__':main()
