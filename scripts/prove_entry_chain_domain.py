"""Reproducible conditional domain proof for owned Ultra entry+16/+17 chains.

This is a maintenance/research verifier of an existing immutable public report,
not a new public proof route, CPU interpreter or native reachability certificate.
"""
from contextlib import ExitStack
from pathlib import Path
import argparse,hashlib,json,struct,sys,time
MAIN=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(MAIN/'worker'),str(MAIN/'scripts')]
from composition_domain_smt import ARRAY,Queries,add,sub,bv,read,store,encode,sha

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--receipt',required=True);parser.add_argument('--receipt-sha',required=True)
    parser.add_argument('--case-id',choices=('entry-plus16','entry-plus17'),default='entry-plus16')
    parser.add_argument('--out',required=True);parser.add_argument('--child',action='store_true');parser.add_argument('--verbose',action='store_true');args=parser.parse_args()
    out=Path(args.out);receipt=Path(args.receipt);assert out.is_absolute() and receipt.is_absolute()
    if not args.child:
        from lift_process import run_owned
        out.mkdir(exist_ok=False);job=out/'job';job.mkdir()
        result=run_owned(str(MAIN/'runtimes/ghidra/python/python.exe'),['-I','-B','-X','utf8',str(Path(__file__)),*sys.argv[1:],'--child'],job,budget_ms=50000)
        (out/'process.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
        print(json.dumps(result))
        assert result['childExitConfirmed'] and result['jobAssignedAtCreation'],'Owned proof child exit unconfirmed; do not read live output'
        from lift_runtime import locked_file
        logs={}
        for name in ('stdout.log','stderr.log'):
            with locked_file(job/name,4*1024**2) as raw:logs[name]=raw.decode('utf8')
        if args.verbose:print(logs['stdout.log'])
        assert result['exitCode']==0,logs['stderr.log']
        with locked_file(out/'verified.json',4*1024**2) as raw:verified=json.loads(raw)
        print(json.dumps({'passed':verified['passed'],'queries':len(verified['queries']),
            'statuses':{s:sum(r['status']==s for r in verified['queries']) for s in ('unsat','sat','unknown')},
            'writes':len(verified['allOrderedMemoryLinks']),'byteFacts':len(verified['initialImageByteFacts']),
            'verifiedPath':str(out/'verified.json'),'verifiedSha256':sha(out/'verified.json')}))
        return
    deadline=time.monotonic()+45
    from lift_runtime import locked_file
    from kernel_image import BinaryImage
    with ExitStack() as held:
        raw=held.enter_context(locked_file(receipt,4*1024**2));assert hashlib.sha256(raw).hexdigest()==args.receipt_sha
        observed=json.loads(raw);case=next(c for c in observed['cases'] if c['id']==args.case_id);assert observed['passed'] and not case['rejected']
        report=Path(case['result']['reportPath']);raw=held.enter_context(locked_file(report,4*1024**2));assert hashlib.sha256(raw).hexdigest()==case['result']['reportSha256']
        record=json.loads(raw);core=record['result'];nodes=core['dag']['nodes'];layers=core['layers'];stores=core['stores']
        applications=17 if args.case_id=='entry-plus16' else 18
        assert core['schema']=='ig5-pcode-opaque-transition-chain-v1' and len(layers)==applications and len(stores)==21+2*(applications-1)
        target=Path(case['args']['target']);data=held.enter_context(locked_file(target,64*1024**2))
        assert hashlib.sha256(data).hexdigest()==core['targetSha256']=='5f9c1b6fcb019366f835d8f02d9ec3b2957fe619e039410d07f288a9c73f63f0'
        image=BinaryImage.from_bytes(data);base=image.imagebase;pe=struct.unpack_from('<I',data,0x3c)[0]
        size=struct.unpack_from('<I',data,pe+24+56)[0];assert base==0x140000000 and size==1384448
        assert all(image.read(int(r['ea'],16),r['decoded']['size']).hex()==r['bytes'] for r in core['decodedPath'])
        q=Queries(MAIN,out/'queries',deadline)
        try:prove(core,record,case,image,base,size,q,out,receipt,args.receipt_sha,report,target)
        finally:q.close()

def prove(core,record,case,image,base,size,q,out,receipt,receipt_sha,report,target):
    nodes=core['dag']['nodes'];layers=core['layers'];stores=core['stores'];S='I_rsp';L=sub(S,bv(671))
    applications=len(layers);write_count=len(stores);body_count=applications-1
    frame=f'(bvand {sub(S,bv(648))} {bv((1<<64)-16)})';vip=base+0x846c4;table=base+0x56098
    certificates=[];memory_links=[]
    def query_terms(name,roots,predicate,*,cuts=None,cut_loads=False,expected='unsat'):
        lines,actual,metadata=encode(core,roots,cuts=cuts,cut_loads=cut_loads)
        return q.query(name,'\n'.join(lines)+'\n(assert '+predicate(actual)+')',expected,metadata)
    # All LOAD cuts below are unconstrained, typed values, never observations.
    # UNSAT with these weaker constraints proves the address bounds for the
    # original coherent memory as well. No such weakening is used for targets.
    bounds=query_terms(f'all{write_count}-write-starts-in671-window',[s['address'] for s in stores],
        lambda a:'(or '+' '.join(f'(bvugt {sub(x,L)} {bv(663)})' for x in a)+')',cut_loads=True)
    assert q.rows[bounds]['status'] in ('unsat','unknown'),q.rows[bounds]
    # Exact scalar pointer identities and independent address decomposition also
    # provide a bounded fallback if the monolithic53-way range query is unknown.
    pointer_roots=[];pointer_expected=[]
    for step,layer in enumerate(layers):
        for name,wanted in [('rsp',frame),('rbp',add(sub(S,bv(136)),bv(step*8))),('rsi',bv(vip+1+2*step)),('r11',bv(table))]:
            pointer_roots.append(layer['registers'][name]);pointer_expected.append(wanted)
    p=q.expect(query_terms(f'all{applications}-boundary-pointer-identities',pointer_roots,
        lambda a:'(or '+' '.join(f'(distinct {x} {y})' for x,y in zip(a,pointer_expected))+')'))
    certificates.append({'kind':'pointer-identities','query':p,'roots':pointer_roots,'expected':pointer_expected})
    offsets=[8*i for i in range(1,18)]+[72,16,8];address_expected=[sub(S,bv(i)) for i in offsets]+[sub(frame,bv(8))]
    variable_offsets=[]
    for step in range(1,applications):
        pair=[s for s in stores if s['stepIndex']==step];assert len(pair)==2
        node=nodes[pair[0]['address']];assert node['op']=='INT_ADD' and node['args'][0]==layers[step]['inputRegisters']['rsp']
        variable_offsets.append(node['args'][1]);address_expected += [None,sub(frame,bv(8))]
    roots=[s['address'] for s in stores]+variable_offsets
    def decomposed(actual):
        wanted=list(address_expected)
        for step,offset in enumerate(actual[write_count:],1):wanted[21+(step-1)*2]=add(frame,offset)
        return '(or '+' '.join([*(f'(distinct {a} {b})' for a,b in zip(actual[:write_count],wanted)),
            *(f'(bvugt {value} {bv(255)})' for value in actual[write_count:])])+')'
    a=q.expect(query_terms(f'all{write_count}-exact-addresses-and{body_count}-byte-offset-bounds',roots,decomposed,cut_loads=True))
    certificates.append({'kind':'exact-address-decomposition','query':a,'variableOffsetNodes':variable_offsets,'first20Offsets':offsets})
    generic='(declare-const S (_ BitVec 64))\n(declare-const a (_ BitVec 4))\n(declare-const j (_ BitVec 8))\n'
    x=sub('S',bv(648));aligned=f'(bvand {x} {bv((1<<64)-16)})'
    g=q.expect(q.query('alignment-is-subtract-low-nibble',generic+f'(assert (distinct {aligned} {sub(x,f"((_ zero_extend 60) ((_ extract 3 0) {x}))")}))'))
    z='((_ zero_extend 60) a)';j='((_ zero_extend 56) j)';lower=sub('S',bv(671));candidate=sub(x,z)
    c=q.expect(q.query('context-offset-cancellation',generic+f'(assert (or (distinct {sub(add(candidate,j),lower)} {add(sub(bv(23),z),j)}) (distinct {sub(sub(candidate,bv(8)),lower)} {sub(bv(15),z)})))'))
    r=q.expect(q.query('all-context-and-push-offsets-fit-window',generic+f'(assert (or (bvugt {add(sub(bv(23),z),j)} {bv(663)}) (bvugt {sub(bv(15),z)} {bv(663)})))'))
    # The first20 fixed offsets give [0,663] word starts directly; the final
    # entry PUSH and all handler STOREs follow the three generic lemmas above.
    assert all(0<=671-offset<=663 for offset in offsets)
    certificates.append({'kind':'composed-window-bound','queries':[a,g,c,r],'windowBytes':671,'maxWordStart':663,'allWritesCovered':True,'writes':write_count})
    bridge=q.expect(q.query('bounded64-offset-equals-zero-extended10-bit-offset',
        '(declare-const A (_ BitVec 64))\n(declare-const L (_ BitVec 64))\n'+
        f'(assert (bvule {sub("A","L")} {bv(663)}))\n'+
        f'(assert (distinct A {add("L",f"((_ zero_extend 54) ((_ extract 9 0) {sub('A','L')}))")}))'))
    decl=f'(declare-const M {ARRAY})\n(declare-const L (_ BitVec 64))\n(declare-const P (_ BitVec 64))\n(declare-const i (_ BitVec 10))\n(declare-const j (_ BitVec 3))\n(declare-const V (_ BitVec 8))\n'
    destination=add(add('L','((_ zero_extend 54) i)'),'((_ zero_extend 61) j)')
    preserve=q.expect(q.query('any-outside-byte-survives-any-window-word-byte',decl+f'(assert (bvule i {bv(663,10)}))\n(assert (bvuge {sub("P","L")} {bv(671)}))\n(assert (distinct (select (store M {destination} V) P) (select M P)))'))
    region=f'(bvuge {sub("L",bv(base))} {bv(size)})';separation=f'(bvuge {sub(bv(base),"L")} {bv(671)})'
    separate=q.expect(q.query('image-region-outside-circular-stack-window',f'(declare-const L (_ BitVec 64))\n(declare-const P (_ BitVec 64))\n(assert {region})\n(assert {separation})\n(assert (bvult {sub("P",bv(base))} {bv(size)}))\n(assert (bvult {sub("P","L")} {bv(671)}))'))
    previous=core['initialMemory']
    for step,layer in enumerate(layers):
        assert layer['inputMemory']==previous
        for s in [s for s in stores if s['stepIndex']==step]:
            assert s['size']==8 and s['beforeMemory']==previous and s['guard']==layer['entryGuard']
            n=nodes[s['afterMemory']];assert n['op']=='store_le' and n['args']==[previous,s['address'],s['value']]
            memory_links.append({k:s[k] for k in ('stepIndex','instructionIndex','pcodeIndex','address','value','beforeMemory','afterMemory','guard','size')});previous=s['afterMemory']
        binding=nodes[layer['currentMemory']];assert binding['op']=='state_binding' and binding['source']==previous
        previous=layer['currentMemory']
    assert previous==core['currentMemory']
    # Each image-byte preservation instance follows from proved word bounds,
    # the single-byte store theorem,8 little-endian bytes and these exact links.
    facts={};target_cuts={};target_certificates=[]
    for step,layer in enumerate(layers):
        memory=[s for s in stores if s['stepIndex']==step][-1]['beforeMemory']
        selector_address=vip+2*step;opcode=image.read(selector_address,1)[0];word_address=table+opcode*4
        word=image.read(word_address,4);destination=(table+int.from_bytes(word,'little',signed=True))&((1<<64)-1)
        known=[(selector_address,opcode)]+[(word_address+i,value) for i,value in enumerate(word)]
        assert all(base<=address<base+size for address,value in known)
        for address,value in known:assert address not in facts or facts[address]==value;facts[address]=value
        formula=add(bv(table),f'((_ sign_extend 32) {read("M_dispatch",add(bv(table),f"(bvmul ((_ zero_extend 56) {read('M_dispatch',bv(selector_address),1)}) {bv(4)})"),4)})')
        root=core['boundaries'][step]['control']['target'];lines,actual,metadata=encode(core,[root],cuts={memory:'M_dispatch'})
        identity=q.expect(q.query(f'dispatch-{step:02}-current-memory-identity','\n'.join(lines)+f'\n(assert (distinct {actual[0]} {formula}))',metadata=metadata))
        body='\n'.join(lines+[f'(assert (= (select M_dispatch {bv(address)}) {bv(value,8)}))' for address,value in known])
        condition=q.expect(q.query(f'dispatch-{step:02}-under-derived-image-bytes',body+f'\n(assert (distinct {actual[0]} {bv(destination)}))',metadata=metadata))
        if step<body_count:assert destination==int(case['args']['composition_plan']['paths'][step+1][0],16)
        target_cuts[root]=bv(destination)
        target_certificates.append({'stepIndex':step,'targetNode':root,'currentMemoryNode':memory,'imageByteFacts':[[hex(a),v] for a,v in known],
            'target':hex(destination),'identityQuery':identity,'conditionalQuery':condition,'derivedImageBytesFrom':[bridge,preserve,separate],
            'allPriorMemoryLinksPreserveBytes':True,'priorStoreCount':sum(s['afterMemory']<=memory for s in stores)})
    assert len(facts)==(25 if applications==17 else 30)
    guards=[core['pathGuard'],*[e['guard'] for e in core['sideExits']]]
    guarded=q.expect(query_terms('all-selected-path-and-complementary-exit-guards',guards,
        lambda a:'(or '+f'(distinct {a[0]} {bv(1,8)}) '+' '.join(f'(distinct {x} {bv(0,8)})' for x in a[1:])+')',cuts=target_cuts))
    initial_facts='\n'.join(f'(assert (= (select M0 {bv(address)}) {bv(value,8)}))' for address,value in facts.items())
    premises=f'(declare-const I_rsp (_ BitVec 64))\n(declare-const L (_ BitVec 64))\n(declare-const M0 {ARRAY})\n(assert (= L {L}))\n(assert {region})\n(assert {separation})\n'+initial_facts
    consistent=q.expect(q.query('explicit-initial-byte-and-region-premises-satisfiable',premises,'sat'))
    # Without the initial byte fact the target is not fixed, even in the free
    # current-memory target formula. This is a negative control, not a CPU run.
    first=target_certificates[0];memory=first['currentMemoryNode'];root=first['targetNode']
    lines,actual,metadata=encode(core,[root],cuts={memory:'M_dispatch'})
    negative=q.expect(q.query('negative-missing-byte-facts-does-not-fix-first-target','\n'.join(lines)+f'\n(assert (distinct {actual[0]} {bv(int(first["target"],16))}))','sat',metadata))
    # Concrete SP chooses an ordinary overlap state; every initial image-byte
    # premise remains in place. No memory cut is used in this negative query.
    lines,actual,metadata=encode(core,[root]);overlap_sp=vip+8
    bad=q.expect(q.query('negative-no-region-first-target-can-change','\n'.join(lines)+f'\n(assert (= I_rsp {bv(overlap_sp)}))\n'+initial_facts+f'\n(assert (distinct {actual[0]} {bv(int(first["target"],16))}))','sat',metadata))
    result={'schema':'ig5-entry-chain-conditional-domain-proof-v2','passed':True,'caseId':case['id'],'applications':applications,'passedContinuations':body_count,'orderedStoreCount':write_count,
        'sourceReport':{'path':str(report),'sha256':sha(report)},
        'sourceReceipt':{'path':str(receipt),'sha256':receipt_sha},'targetSha256':sha(target),'producer':'3.11 Demo2835; not exact3.8',
        'queries':q.rows,'certificates':certificates,'allWordBoundsQuery':bounds,'monolithicStatusPreserved':q.rows[bounds]['status'],
        'window':{'base':'initialRSP-671 mod2^64','bytes':671,'wordStartMax':663,'offsetWidthBridgeLemma':bridge,'preservationLemma':preserve,'imageSeparationLemma':separate},
        'image':{'base':hex(base),'bytes':size},'initialImageByteFacts':[[hex(a),v] for a,v in sorted(facts.items())],
        'regionPremises':['unsigned(L-imageBase)>=imageSize','unsigned(imageBase-L)>=671'],
        'allOrderedMemoryLinks':memory_links,'memoryBindingSourcesChecked':applications,'targetCertificates':target_certificates,
        'allContinuationSelectionsAndComplementaryExitGuardsQuery':guarded,'premisesSatisfiableQuery':consistent,
        'negativeControls':[negative,bad],'conditionalResult':f'Under the{len(facts)} explicit initial data-memory bytes and circular image/window separation, all{write_count} writes preserve image bytes; all{body_count} selected continuations are true, all{body_count} complementary exits are false, and the terminal target has its stated conditional value. Every source STORE and alternate exit remains in the original report.',
        'loadCutsAreUniversalWeakeningsNotObservations':True,'targetMemoryAndTargetCutsAreExplicitCertifiedLemmaInstantiations':True,
        'publicProductProofRouteExposed':False,'sourceProofScriptSha256':sha(__file__),'encoderSourceSha256':sha(Path(__file__).with_name('composition_domain_smt.py')),
        'solverDllSha256':q.dll_sha,'limits':{'queries':128,'eachMs':2000,'solverMiB':512,'sharedSeconds':45,'jobSeconds':50,'jobMiB':2048,'jobProcesses':1,
            'sourceDagNodes':2048,'sourceDagReferences':8192,'retainedDepth':128,'queryBytes':1024**2,'encodedSexpressions':2048,'encodedAtomTokens':8192},
        'unproven':['Native stack allocation/region premises','Actual initial code/data memory and relocation correspondence','Independent CPU/fault/flags equivalence','All VM initialization/handler ISA/business and input-path coverage','Exact3.8 and full Ultra/Enigma business recovery'],
        'nativeTargetExecuted':False,'architectureProved':False,'businessAccepted':False,'wholeBinaryVerified':False}
    raw=(json.dumps(result,indent=2)+'\n').encode('utf8');assert len(raw)<=4*1024**2
    with (out/'verified.json').open('xb') as stream:stream.write(raw)
    print(json.dumps({'passed':True,'queries':len(q.rows),'unsat':sum(x['status']=='unsat' for x in q.rows),'sat':sum(x['status']=='sat' for x in q.rows),
        'windowBytes':671,'writes':write_count,'byteFacts':len(facts),'passedContinuations':body_count}),flush=True)

if __name__=='__main__':main()
