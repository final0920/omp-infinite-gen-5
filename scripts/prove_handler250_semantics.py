"""Owned VM ADD: full ordinary state and five status-bit correlations.

Other flag-image bits, including unmodeled AF, remain free. This is not a
complete CPU/flags/VM certificate. No target or native emulator executes.
"""
from contextlib import ExitStack
from pathlib import Path
import argparse,hashlib,json,random,sys,time
MAIN=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(MAIN/'worker'),str(MAIN/'scripts')]
from composition_domain_smt import ARRAY,GPRS,Queries,add,sub,bv,read,store,encode,sha
from projection_numerical_oracle import MASK,total_byte,projection_values
KNOWN=0x8c5;UNKNOWN=MASK^KNOWN


def main():
    p=argparse.ArgumentParser()
    for k in ('receipt','receipt-sha','incoming-proof','incoming-sha','out'):p.add_argument('--'+k,required=True)
    p.add_argument('--child',action='store_true');a=p.parse_args();out=Path(a.out)
    assert all(Path(x).is_absolute() for x in (a.receipt,a.incoming_proof,a.out))
    from lift_runtime import locked_file
    if not a.child:
        from lift_process import run_owned
        out.mkdir(exist_ok=False);job=out/'job';job.mkdir()
        process=run_owned(str(MAIN/'runtimes/ghidra/python/python.exe'),['-I','-B','-X','utf8',str(Path(__file__)),*sys.argv[1:],'--child'],job,budget_ms=50000)
        (out/'process.json').write_text(json.dumps(process,indent=2)+'\n',encoding='utf8');assert process['childExitConfirmed'] and process['jobAssignedAtCreation']
        if process['exitCode']!=0:
            with locked_file(job/'stderr.log',4*1024**2) as raw:error=raw.decode('utf8')
            with locked_file(job/'stdout.log',4*1024**2) as raw:error+='\n'+raw.decode('utf8')[-4096:]
            raise AssertionError('Owned250 proof failed: '+error)
        with locked_file(out/'verified.json',4*1024**2) as raw:r=json.loads(raw)
        print(json.dumps({'passed':r['passed'],'queries':len(r['queries']),'statuses':{s:sum(q['status']==s for q in r['queries']) for s in ('unsat','sat','unknown')},
            'knownMask':hex(KNOWN),'effectiveUnknownFlagBits':59,'initialByteFacts':len(r['initialImageByteFacts']),'nextSelector':r['nextSelector'],'nextTarget':r['nextTarget'],
            'numeric':r['numeric'],'verifiedPath':str(out/'verified.json'),'verifiedSha256':sha(out/'verified.json'),'process':process}));return
    from kernel_image import BinaryImage
    deadline=time.monotonic()+45
    with ExitStack() as held:
        def load(path,pin=None,maxbytes=4*1024**2):
            raw=held.enter_context(locked_file(Path(path),maxbytes));assert pin is None or hashlib.sha256(raw).hexdigest()==pin;return json.loads(raw)
        receipt=load(a.receipt,a.receipt_sha);incoming=load(a.incoming_proof,a.incoming_sha)
        assert receipt['passed'] and incoming['passed'] and incoming['schema']=='ig5-handler137-conditional-semantics-proof-v1'
        assert incoming['sourceProofScriptSha256']==sha(MAIN/'scripts/prove_handler137_semantics.py') and incoming['encoderSourceSha256']==sha(MAIN/'scripts/composition_domain_smt.py')
        audit=load(Path(a.incoming_proof).parent/'independent-audit.json');assert audit['passed'] and audit['proofSha256']==a.incoming_sha
        process=load(Path(a.incoming_proof).parent/'process.json',maxbytes=65536);assert process['exitCode']==0 and process['childExitConfirmed'] and process['jobAssignedAtCreation']
        for row in incoming['queries']:
            assert sha(row['path'])==row['sha256'] and row['timeoutMs']<=2000
            assert row['status']==row['expected'] or row['name']=='all17-context-words-preserved-by-literal-dispatch-and-next-stack-write' and row['status']=='unknown'
        assert incoming['nextSelector']==250 and incoming['nextTarget']=='0x140055f66'
        cores={};refs={}
        for name in ('legacy-opaque27','status-prefix15','status-dispatch27'):
            c=next(c for c in receipt['cases'] if c['id']==name);assert not c['rejected'] and c['cleanupConfirmed'] and c['rootExitConfirmed']
            r=c['result'];cores[name]=load(r['reportPath'],r['reportSha256'])['result'];refs[name]={'path':r['reportPath'],'sha256':r['reportSha256']}
        target=Path(receipt['cases'][0]['args']['target']);data=held.enter_context(locked_file(target,4*1024**2))
        assert hashlib.sha256(data).hexdigest()=='5f9c1b6fcb019366f835d8f02d9ec3b2957fe619e039410d07f288a9c73f63f0';image=BinaryImage.from_bytes(data)
        for core in cores.values():
            assert core['targetSha256']==hashlib.sha256(data).hexdigest() and all(core[k] is False for k in ('nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'))
            assert all(image.read(int(r['ea'],16),r['decoded']['size']).hex()==r['bytes'] for r in core['decodedPath'])
        assert cores['status-prefix15']['projectionPath']==cores['status-dispatch27']['projectionPath'][:15]
        q=Queries(MAIN,out/'queries',deadline)
        try:prove(cores,refs,incoming,a,q,image,out,deadline)
        finally:q.close()


def prove(cores,refs,incoming,args,q,image,out,deadline):
    def different(actual,wanted):assert len(actual)==len(wanted);return '(or '+' '.join(f'(distinct {a} {b})' for a,b in zip(actual,wanted))+')'
    def details(c):
        e=c['opaqueEffects'][0];assert len(c['opaqueEffects'])==1 and e['instructionIndex']==7
        value=c['stores'][1]['value'];n=c['dag']['nodes'][value];assert n['op']=='INT_ADD' and n['bits']==64
        loads=n['args'];assert len(loads)==2
        for i in loads:
            x=c['dag']['nodes'][i];assert x['op']=='load_le' and x['bits']==64 and x['size']==8 and x['args'][0]==c['initialMemory']
        return e,loads,c['nondeterministicInputs'][0]['node']
    declarations='\n'.join(f'(declare-const {n} (_ BitVec 64))' for n in ('A','B','U','FlagsImage'))
    total=add('A','B');unsigned=add('((_ zero_extend 1) A)','((_ zero_extend 1) B)');signed=add('((_ sign_extend 1) A)','((_ sign_extend 1) B)')
    parity=[f'((_ extract {i} {i}) {total})' for i in range(8)]
    while len(parity)>1:parity=[f'(bvxor {parity[i]} {parity[i+1]})' for i in range(0,len(parity),2)]
    predicates={'cf':f'(bvuge {unsigned} {bv(1<<64,65)})','pf':f'(= {parity[0]} {bv(0,1)})','zf':f'(= {total} {bv(0)})',
        'sf':f'(= ((_ extract 63 63) {total}) {bv(1,1)})','of':f'(distinct ((_ extract 64 64) {signed}) ((_ extract 63 63) {signed}))'}
    bits={'cf':0,'pf':2,'zf':6,'sf':7,'of':11};word=bv(0)
    for name,bit in bits.items():word=f'(bvor {word} (ite {predicates[name]} {bv(1<<bit)} {bv(0)}))'
    expected_image=f'(bvor (bvand U {bv(UNKNOWN)}) {word})'
    def query(c,name,roots,predicate,*,image_cut=False,cuts=None,extra='',expected='unsat',allow_unknown=False):
        e,loads,noise=details(c);cut={loads[0]:'A',loads[1]:'B',noise:'U'}
        if image_cut:cut[e['flagImageRefinement']['valueNode']]='FlagsImage'
        cut.update(cuts or {});lines,actual,meta=encode(c,roots,cuts=cut)
        meta['sourceCase']=next(name for name,core in cores.items() if core is c)
        i=q.query(name,declarations+'\n'+'\n'.join(lines)+'\n'+extra+'\n(assert '+predicate(actual)+')',expected,meta)
        if allow_unknown:assert q.rows[i]['status'] in ('unsat','unknown')
        else:q.expect(i)
        return i
    prefix=cores['status-prefix15'];full=cores['status-dispatch27'];e,loads,noise=details(prefix);flag=e['flagImageRefinement']
    assert e['unknownBits']==59 and flag['knownMask']==hex(KNOWN) and flag['unknownMask']==hex(UNKNOWN) and flag['effectiveUnknownBits']==59
    assert [x['name'] for x in flag['knownFlags']]==list(bits) and all(x['definitionInstructionIndex']==4 for x in flag['knownFlags'])
    address_roots=[prefix['dag']['nodes'][i]['args'][1] for i in loads]
    addresses=query(prefix,'alu-operands-read-initial-words-at-rbp-and-rbp-plus8',address_roots,lambda a:different(a,['I_rbp',add('I_rbp',bv(8))]))
    whole=query(prefix,'whole-status-image-matches-independent-add64-flag-formulas',[flag['valueNode']],lambda a:f'(distinct {a[0]} {expected_image})',allow_unknown=True)
    bit_queries={}
    for name,bit in bits.items():
        bit_queries[name]=query(prefix,'known-add64-'+name+'-bit-correlation',[flag['valueNode']],lambda a,p=predicates[name],b=bit:f'(distinct ((_ extract {b} {b}) {a[0]}) (ite {p} {bv(1,1)} {bv(0,1)}))')
    unknown=query(prefix,'all-unmodeled-and-ambient-image-bits-still-equal-fresh-input',[flag['valueNode']],lambda a:f'(distinct (bvand {a[0]} {bv(UNKNOWN)}) (bvand U {bv(UNKNOWN)}))')
    partition=q.expect(q.query('disjoint-mask-parts-determine-whole64-bit-image',f'(declare-const X (_ BitVec 64))\n(declare-const Y (_ BitVec 64))\n(assert (= (bvand X {bv(KNOWN)}) (bvand Y {bv(KNOWN)})))\n(assert (= (bvand X {bv(UNKNOWN)}) (bvand Y {bv(UNKNOWN)})))\n(assert (distinct X Y))'))
    definitions=[]
    def define(name,sort,term):definitions.extend([f'(declare-const E_{name} {sort})',f'(assert (= E_{name} {term}))']);return 'E_'+name
    m1=define('M1',ARRAY,store('M0',sub('I_rsp',bv(8)),'FlagsImage',8));m2=define('M2',ARRAY,store(m1,add('I_rbp',bv(8)),total,8));m3=define('M3',ARRAY,store(m2,'I_rbp','FlagsImage',8))
    select=define('selector','(_ BitVec 8)',read(m3,'I_rsi',1));target=define('target','(_ BitVec 64)',add('I_r11',f'((_ sign_extend 32) {read(m3,add("I_r11",f"(bvmul ((_ zero_extend 56) {select}) {bv(4)})"),4)})'))
    m4=define('M4',ARRAY,store(m3,sub('I_rsp',bv(8)),target,8));state_certificates=[]
    for name,c,memory,change,control,store_wanted in [
        ('status-prefix15',prefix,m3,{'rbx':total,'r10':'FlagsImage'},bv(0x140052124),['M0',sub('I_rsp',bv(8)),'FlagsImage',m1,m1,add('I_rbp',bv(8)),total,m2,m2,'I_rbp','FlagsImage',m3]),
        ('status-dispatch27',full,m4,{'rbx':total,'r10':'FlagsImage','rax':f'((_ zero_extend 56) {select})','rsi':add('I_rsi',bv(1)),'r8':target},target,
         ['M0',sub('I_rsp',bv(8)),'FlagsImage',m1,m1,add('I_rbp',bv(8)),total,m2,m2,'I_rbp','FlagsImage',m3,m3,sub('I_rsp',bv(8)),target,m4])]:
        roots=[c['registers'][n] for n in GPRS]+[c['currentMemory'],c['control']['target']]+[s[k] for s in c['stores'] for k in ('beforeMemory','address','value','afterMemory')]
        wanted=[change.get(n,'I_'+n) for n in GPRS]+[memory,control]+store_wanted
        i=query(c,name+'-all16-gprs-entire-memory-all-ordered-writes-and-control',roots,lambda a,w=wanted:different(a,w),image_cut=True,extra='\n'.join(definitions))
        state_certificates.append({'case':name,'query':i,'imageCutBoundToSeparateBitAndUnknownRegionProofs':True,'all16GPRsEntireMemoryOrderedWritesAndControl':True})
    old=cores['legacy-opaque27'];old_noise=old['nondeterministicInputs'][0]['node'];lines,actual,meta=encode(old,[old['registers']['r10']],cuts={old_noise:'U'})
    meta['sourceCase']='legacy-opaque27'
    baseline=q.expect(q.query('negative-legacy-whole-unknown-image-loses-add-status-correlation','(declare-const U (_ BitVec 64))\n'+'\n'.join(lines)+f'\n(assert (distinct (bvand {actual[0]} {bv(KNOWN)}) {bv(0x44)}))','sat',meta))
    free_af=[query(prefix,'unmodeled-af-remains-free-'+str(value),[flag['valueNode']],lambda a,v=value:f'(= ((_ extract 4 4) {a[0]}) {bv(v,1)})',extra=f'(assert (= A {bv(0)}))\n(assert (= B {bv(0)}))',expected='sat') for value in (0,1)]
    S='S';F='F';vip=image.imagebase+0x846c4;table=image.imagebase+0x56098
    pointers=f'(declare-const S (_ BitVec 64))\n(declare-const F (_ BitVec 64))\n(assert (= F (bvand {sub(S,bv(648))} {bv(MASK-15)})))\n(assert (= I_rsp F))\n(assert (= I_rbp {sub(S,bv(16))}))\n(assert (= I_rsi {bv(vip+46)}))\n(assert (= I_r11 {bv(table)}))'
    zero=query(full,'joined-zero-operands-give-known-status-mask44',[full['opaqueEffects'][0]['flagImageRefinement']['valueNode']],lambda a:f'(distinct (bvand {a[0]} {bv(KNOWN)}) {bv(0x44)})',extra=f'(assert (= A {bv(0)}))\n(assert (= B {bv(0)}))')
    missing=query(full,'negative-no-zero-operands-status-mask-can-differ',[full['opaqueEffects'][0]['flagImageRefinement']['valueNode']],lambda a:f'(distinct (bvand {a[0]} {bv(KNOWN)}) {bv(0x44)})',expected='sat')
    init=f'(declare-const S (_ BitVec 64))\n(declare-const F (_ BitVec 64))\n(assert (= F (bvand {sub(S,bv(648))} {bv(MASK-15)})))\n'
    starts=[sub(F,bv(8)),sub(S,bv(8)),sub(S,bv(16))]
    window=q.expect(q.query('all250-write-starts-stay-in-original671-window',init+'(assert (or '+' '.join(f'(bvugt {sub(a,sub(S,bv(671)))} {bv(663)})' for a in starts)+'))'))
    operand_decl=init+f'(declare-const M_before {ARRAY})\n(declare-const M_after {ARRAY})\n(declare-const T (_ BitVec 64))\n(assert (= {read("M_before",sub(S,bv(8)),8)} {bv(0)}))\n(assert (= M_after {store(store("M_before",sub(S,bv(16)),bv(0),8),sub(F,bv(8)),"T",8)}))'
    operands=q.expect(q.query('incoming137-both-virtual-stack-operands-are-zero',operand_decl+'\n(assert '+different([read('M_after',sub(S,bv(8)),8),read('M_after',sub(S,bv(16)),8)],[bv(0),bv(0)])+')'))
    opcode=image.read(vip+46,1)[0];wa=table+4*opcode;word_bytes=image.read(wa,4);next_target=(table+int.from_bytes(word_bytes,'little',signed=True))&MASK
    target_facts={vip+46:opcode,**{wa+i:b for i,b in enumerate(word_bytes)}};facts={int(a,16):v for a,v in incoming['initialImageByteFacts']}
    assert all(a not in facts or facts[a]==v for a,v in target_facts.items())
    extras={a:v for a,v in target_facts.items() if a not in facts};reused={a:v for a,v in target_facts.items() if a in facts};facts.update(extras)
    assert len(facts)==67 and len(extras)==1 and len(reused)==4
    dispatch=full['stores'][-1]['beforeMemory'];assert dispatch==full['stores'][-2]['afterMemory']
    known='\n'.join(f'(assert (= (select M_dispatch {bv(a)}) {bv(v,8)}))' for a,v in target_facts.items())
    next_query=query(full,'next-handler-target-from-five-derived-current-image-bytes',[full['control']['target']],lambda a:f'(distinct {a[0]} {bv(next_target)})',cuts={dispatch:'M_dispatch'},extra=pointers+'\n'+known)
    absent=query(full,'negative-missing-next-image-bytes-target-can-differ',[full['control']['target']],lambda a:f'(distinct {a[0]} {bv(next_target)})',cuts={dispatch:'M_dispatch'},extra=pointers,expected='sat')
    changes={'rsp':F,'rbp':sub(S,bv(16)),'rsi':bv(vip+47),'r11':bv(table),'rax':bv(opcode),'r8':bv(next_target),'rbx':bv(0),'r10':'FlagsImage'}
    joined=query(full,'joined-all16-registers-target-and-final-dispatch-memory',[full['registers'][n] for n in GPRS]+[full['control']['target'],full['currentMemory']],
        lambda a:different(a,[changes.get(n,'I_'+n) for n in GPRS]+[bv(next_target),store('M_dispatch',sub(F,bv(8)),bv(next_target),8)]),image_cut=True,cuts={dispatch:'M_dispatch'},
        extra=pointers+'\n'+known+f'\n(assert (= A {bv(0)}))\n(assert (= B {bv(0)}))')
    premises=init+f'(declare-const M0 {ARRAY})\n(assert (bvuge {sub(sub(S,bv(671)),bv(image.imagebase))} {bv(1384448)}))\n(assert (bvuge {sub(bv(image.imagebase),sub(S,bv(671)))} {bv(671)}))\n(assert (bvuge S {bv(671)}))\n'
    premises+='\n'.join(f'(assert (= (select M0 {bv(a)}) {bv(v,8)}))' for a,v in facts.items())
    consistent=q.expect(q.query('all67-byte-region-and-sufficient-fast-edge-premises-consistent',premises,'sat'))
    numeric=numeric_checks(cores,deadline)
    result={'schema':'ig5-handler250-status-conditional-proof-v1','passed':True,'sourceReceipt':{'path':args.receipt,'sha256':args.receipt_sha},'reports':refs,
        'incoming137Proof':{'path':args.incoming_proof,'sha256':args.incoming_sha},'queries':q.rows,'originalOperandLoadAddressQuery':addresses,
        'wholeFlagImageEquationQuery':whole,'knownFlagBitQueries':bit_queries,'unknownRegionEqualityQuery':unknown,'wholeImageMaskPartitionQuery':partition,
        'sourceFlagImageCutCertificate':'Every local FlagsImage cut denotes the original byte-bound PUSHFQ image node. Five proven bit identities plus unchanged unknown-mask bits and partition lemma imply its full64-bit equation for all A,B,U.',
        'operandLoadCutCertificate':'A/B universally rename the two original64-bit M0 LOADs; complete source DAG/types checked and both addresses separately proved. No observed values or alias assumptions.',
        'localStateCertificates':state_certificates,'legacyLossNegativeQuery':baseline,'unmodeledAFBothSATQueries':free_af,'joinedKnownStatus44Query':zero,
        'newWriteWindowQuery':window,'incomingVirtualOperandsZeroQuery':operands,'zeroOperandDerivation':'Incoming literal bytes prove the prior S-8 word0; complete137 summary writes0 toS-16 then target toF-8. The new universal array lemma preserves both words, including wraparound.',
        'nextTargetQuery':next_query,'nextTargetMemoryCut':dispatch,'joinedStateQuery':joined,'negativeControls':[baseline,missing,absent],
        'initialImageByteFacts':[[hex(a),v] for a,v in sorted(facts.items())],'additionalInitialByteFacts':[[hex(a),v] for a,v in sorted(extras.items())],
        'reusedTargetTableByteFacts':[[hex(a),v] for a,v in sorted(reused.items())],'nextTargetCurrentImageByteFacts':[[hex(a),v] for a,v in sorted(target_facts.items())],
        'nextSelector':opcode,'nextTarget':hex(next_target),'knownStatusMask':hex(KNOWN),'effectiveUnknownFlagBits':59,'unmodeledAFRemainsUnknown':True,
        'currentImageDerivation':'Incoming66 byte/image premises and certified pointers plus1 new selector byte; all4 table bytes were already explicit premises and are reused, not counted twice. All four handler250 stores use the original671-byte window, so every prefix preserves stated image bytes by the incoming universal image-preservation lemma.',
        'premisesSatisfiableQuery':consistent,'numeric':numeric,'sourceProofScriptSha256':sha(__file__),'encoderSourceSha256':sha(MAIN/'scripts/composition_domain_smt.py'),
        'solverDllSha256':q.dll_sha,'limits':incoming['limits'],'publicCrossReportJoinIntegrated':False,
        'unproven':['Native stack, loaded-byte/relocation and CPU/fault correspondence','AF, ambient/full-RFLAGS correlations and remaining VM ISA/alternate paths','Exact3.8 and complete Ultra/Enigma business/path/stability recovery'],
        'nativeTargetExecuted':False,'databaseModified':False,'architectureProved':False,'businessAccepted':False,'wholeBinaryVerified':False}
    raw=(json.dumps(result,indent=2)+'\n').encode('utf8');assert len(raw)<=4*1024**2 and time.monotonic()<deadline
    with (out/'verified.json').open('xb') as f:f.write(raw)


def numeric_checks(cores,deadline):
    rng=random.Random(0x616464666c616773);states=[]
    for _ in range(512):states.append(({n:rng.getrandbits(64) for n in GPRS},rng.getrandbits(64),rng.getrandbits(64),{}))
    for base in (0,1,MASK-7,MASK):
        for delta in range(-8,9):
            for position in (-1,0,7,8):
                r={n:rng.getrandbits(64) for n in GPRS};r.update(rbp=base,rsp=(base+delta)&MASK,rsi=(base+position)&MASK,r11=(base-delta)&MASK)
                states.append((r,rng.getrandbits(64),rng.getrandbits(64),{}))
    edges=[0,1,(1<<63)-1,1<<63,MASK]
    for a in edges:
        for b in edges:
            r={n:rng.getrandbits(64) for n in GPRS};r.update(rbp=0x1000,rsp=0x3000)
            facts={0x1000+i:(a>>(8*i))&255 for i in range(8)};facts.update({0x1008+i:(b>>(8*i))&255 for i in range(8)})
            states.append((r,rng.getrandbits(64),rng.getrandbits(64),facts))
    for r,seed,U,facts in states:
        assert time.monotonic()<deadline;origin=total_byte(seed,facts)
        def word(m,a,n):return sum(m((a+i)&MASK)<<(8*i) for i in range(n))
        a=word(origin,r['rbp'],8);b=word(origin,r['rbp']+8,8);s=(a+b)&MASK
        f=int(a+b>MASK)|(int((s&255).bit_count()%2==0)<<2)|(int(s==0)<<6)|((s>>63)<<7)|(int(((a^s)&(b^s))>>63!=0)<<11)
        for name,c in cores.items():
            image=U if name=='legacy-opaque27' else (U&UNKNOWN)|f;overlay={}
            def put(address,value):overlay.update({(address+i)&MASK:(value>>(8*i))&255 for i in range(8)})
            put(r['rsp']-8,image);put(r['rbp']+8,s);put(r['rbp'],image)
            m=lambda a:overlay.get(a&MASK,origin(a&MASK));prefix=name=='status-prefix15';expected={**r,'rbx':s,'r10':image}
            if prefix:target=0x140052124
            else:
                selector=m(r['rsi']);w=word(m,r['r11']+4*selector,4);target=(r['r11']+(w if w<1<<31 else w-(1<<32)))&MASK
                expected.update(rax=selector,r8=target,rsi=(r['rsi']+1)&MASK);put(r['rsp']-8,target)
            unknown={c['dag']['nodes'][c['nondeterministicInputs'][0]['node']]['name']:U};v=projection_values(c,r,origin,unknowns=unknown)
            assert {n:v[i] for n,i in c['registers'].items()}==expected and v[c['currentMemory']]==(origin,overlay) and v[c['control']['target']]==target
    return {'states':len(states),'evaluations':3*len(states),'aliasStates':272,'arithmeticBoundaryPairs':25,'all16GPRsEntireMemoryOrderedWritesAndControl':True,
        'unknownAFAndAmbientImageVaried':True,'notIndependentCPUInterpreter':True,'notUniversalProof':True,'sameBatchesAcrossDeploymentsNotExtraCoverage':True}


if __name__=='__main__':main()
