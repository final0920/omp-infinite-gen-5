"""Fixed owned bytes: ordinary136/78 summaries and conditional context join.

No target execution. Component universal equations, exact public bindings and
explicit byte-memory induction are used; no monolithic uncut-chain theorem.
"""
from pathlib import Path
from contextlib import ExitStack
import argparse,hashlib,json,random,sys,time
MAIN=Path(__file__).resolve().parents[1];sys.path[:0]=[str(MAIN/'worker'),str(MAIN/'scripts')]
from composition_domain_smt import ARRAY,GPRS,Queries,encode,validate,bv,add,sub,read,store,sha
from projection_numerical_oracle import projection_values,total_byte,MASK
TARGET='5f9c1b6fcb019366f835d8f02d9ec3b2957fe619e039410d07f288a9c73f63f0'
VIP=0x1400846c4;TABLE=0x140056098
SEMANTIC_FIELDS=('initialRegisters','initialMemory','registers','currentMemory','pathGuard','stores','sideExits','boundaries','control','steps','nondeterministicInputs')

def different(actual,wanted):
    assert len(actual)==len(wanted)
    return '(or '+' '.join(f'(distinct {a} {b})' for a,b in zip(actual,wanted))+')'

def ordinary(kind,full,r,m,tag):
    """Independent equations; both input reads precede any write, aliasing kept."""
    lines=[];writes=[];out=dict(r)
    def define(name,term,sort='(_ BitVec 64)'):
        name=tag+'_'+name;lines.append(f'(define-fun {name} () {sort} {term})');return name
    value=define('word',read(m,r['rbp'],8));index=define('index',f'((_ zero_extend 56) {read(m,r["rsi"],1)})')
    before=m;address=add(r['rsp'],index);m=define('contextMemory',store(m,address,value,8),ARRAY);writes.append([address,value,before,m])
    out.update(rbp=add(r['rbp'],bv(8)),rsi=add(r['rsi'],bv(1)))
    if kind==136:out.update(rbx=value,rax=index)
    else:assert kind==78;out.update(rdi=value,r10=index)
    target=bv(0x140052124)
    if full:
        selector=define('selector',f'((_ zero_extend 56) {read(m,out["rsi"],1)})')
        displacement=define('displacement',f'((_ sign_extend 32) {read(m,add(r["r11"],f"(bvmul {selector} {bv(4)})"),4)})')
        target=define('target',add(r['r11'],displacement));before=m;address=sub(r['rsp'],bv(8))
        m=define('dispatchMemory',store(m,address,target,8),ARRAY);writes.append([address,target,before,m])
        out.update(rax=selector,r8=target,rsi=add(r['rsi'],bv(2)))
    return lines,out,m,target,writes

def main():
    p=argparse.ArgumentParser()
    for k in ('receipt','receipt-sha','incoming-proof','incoming-sha','chain-proof','chain-sha','out'):p.add_argument('--'+k,required=True)
    p.add_argument('--child',action='store_true');a=p.parse_args();out=Path(a.out)
    assert all(Path(x).is_absolute() for x in (a.receipt,a.incoming_proof,a.chain_proof,a.out))
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
        print(json.dumps({'passed':v['passed'],'queries':len(v['queries']),'statuses':{s:sum(q['status']==s for q in v['queries']) for s in ('unsat','sat','unknown')},'numeric':v['numeric'],'verifiedSha256':sha(out/'verified.json'),'process':process}));return
    deadline=time.monotonic()+45
    with ExitStack() as held:
        def load(path,pin=None,maxbytes=4*1024**2):
            assert Path(path).is_absolute() and '..' not in Path(path).parts
            raw=held.enter_context(locked_file(Path(path),maxbytes));assert pin is None or hashlib.sha256(raw).hexdigest()==pin
            return json.loads(raw)
        def certificate(ref,audit_required=True):
            v=load(ref['path'],ref['sha256']);assert v['passed']
            if audit_required:
                audit=load(Path(ref['path']).parent/'independent-audit.json');assert audit['passed'] and audit['proofSha256']==ref['sha256']
            proc=load(Path(ref['path']).parent/'process.json',maxbytes=65536)
            assert proc['exitCode']==0 and proc['childExitConfirmed'] and proc['jobAssignedAtCreation'] and proc['activeProcessLimit']==1 and proc['memoryLimitBytes']==2147483648
            assert v['encoderSourceSha256']==sha(MAIN/'scripts/composition_domain_smt.py')
            for row in v['queries']:
                assert sha(row['path'])==row['sha256'] and row['timeoutMs']<=2000 and row['status'] in (row['expected'],'unknown')
            return v
        incoming=certificate({'path':a.incoming_proof,'sha256':a.incoming_sha});chain=certificate({'path':a.chain_proof,'sha256':a.chain_sha})
        prior137=certificate(incoming['incoming137Proof']);context=certificate(prior137['incomingContextProof'],False);domain=certificate(context['incomingDomainProof']);literal=certificate(prior137['incomingLiteralProof'],False)
        assert context['sourceProofScriptSha256']==sha(MAIN/'scripts/prove_context_mapping.py') and literal['sourceProofScriptSha256']==sha(MAIN/'scripts/prove_handler17_semantics.py')
        assert incoming['nextSelector']==136 and incoming['nextTarget']=='0x1400545b6'
        for key in ('offsetWidthBridgeLemma','preservationLemma','imageSeparationLemma'):assert domain['queries'][domain['window'][key]]['status']=='unsat'
        assert context['queries'][context['lemmas']['bytePreservation']]['status']=='unsat' and prior137['queries'][prior137['contextWordNonaliasQuery']]['status']=='unsat'
        receipt=load(a.receipt,a.receipt_sha);assert receipt['passed'] and receipt['activeRequests']==0
        cores={};refs={}
        for case in receipt['cases']:
            if case['rejected']:assert case['id']=='combined-entry-refused' and case['spawnedRoots']==0;continue
            assert case['cleanupConfirmed'] and case['rootExitConfirmed'];ref=case['result'];cores[case['id']]=load(ref['reportPath'],ref['reportSha256'])['result'];refs[case['id']]={'path':ref['reportPath'],'sha256':ref['reportSha256']}
        assert len(cores)==7
        from kernel_image import BinaryImage
        with locked_file(Path(receipt['cases'][0]['args']['target']),4*1024**2) as raw:
            assert hashlib.sha256(raw).hexdigest()==TARGET;image=BinaryImage.from_bytes(raw)
        for c in cores.values():
            validate(c);assert c['targetSha256']==TARGET and all(c[k] is False for k in ('nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'))
            assert all(image.read(int(r['ea'],16),r['decoded']['size']).hex()==r['bytes'] for r in c['decodedPath'])
        old_entry=load(context['sourceReport']['path'],context['sourceReport']['sha256'])['result'];entry=cores['entry17-status']
        assert old_entry['dag']['nodes']==entry['dag']['nodes'] and all(old_entry[k]==entry[k] for k in SEMANTIC_FIELDS)
        e=entry['templates'][0]['opaqueEffects'][0]['flagImageRefinement'];assert e['knownMask']=='0x0' and e['effectiveUnknownBits']==64 and not e['knownFlags']
        old_chain=load(chain['reports']['status250-136']['path'],chain['reports']['status250-136']['sha256'])['result'];public=cores['public250-136-78']
        end=public['layers'][0]['nodeEnd'];assert end==103 and public['dag']['nodes'][:end]==old_chain['dag']['nodes'][:end]
        assert public['layers'][0]==old_chain['layers'][0] and public['boundaries'][0]==old_chain['boundaries'][0]
        replay={'entry17-status':entry}
        for name,proof,case in (('literal-fast-dispatch22',literal,'literal-fast-dispatch22'),('context137-fast28',prior137,'context137-fast28')):
            ref=proof['reports'][case];replay[name]=load(ref['path'],ref['sha256'])['result']
        q=Queries(MAIN,out/'queries',deadline)
        try:prove(a,out,cores,refs,incoming,chain,prior137,context,domain,image,replay,q,deadline)
        finally:q.close()

def prove(a,out,cores,refs,incoming,chain,prior137,context,domain,image,replay,q,deadline):
    def query(name,case,roots,wanted=None,*,cuts=None,extra='',predicate=None,status='unsat'):
        cuts=cuts or {};lines,actual,meta=encode(cores[case],roots,cuts=cuts)
        meta.update(sourceCase=case,rootNodes=roots,cutNames={str(i):n for i,n in cuts.items()})
        declarations=[l for l in lines if l.startswith('(declare-')];definitions=[l for l in lines if not l.startswith('(declare-')]
        pred=different(actual,wanted) if wanted is not None else predicate(actual)
        return q.expect(q.query(name,'\n'.join(declarations)+'\n'+extra+'\n'+'\n'.join(definitions)+'\n(assert '+pred+')',status,meta))
    local=[];r={n:'I_'+n for n in GPRS}
    for kind,length in ((136,10),(136,22),(78,15),(78,27)):
        full=length in (22,27);case=f'context{kind}-'+('full' if full else 'prefix')+str(length);c=cores[case]
        lines,regs,m,t,writes=ordinary(kind,full,r,'M0','Local')
        roots=[c['registers'][n] for n in GPRS]+[c['currentMemory'],c['control']['target']]+[s[k] for s in c['stores'] for k in ('address','value','beforeMemory','afterMemory')]
        wanted=[regs[n] for n in GPRS]+[m,t]+[v for w in writes for v in w]
        i=query(case+'-all16-entire-memory-ordered-writes-control',case,roots,wanted,extra='\n'.join(lines));local.append({'case':case,'query':i})
    public=cores['public250-136-78'];layer_queries=[]
    for step,kind in ((1,136),(2,78)):
        layer=public['layers'][step];boundary=public['boundaries'][step];cuts={layer['inputRegisters'][n]:'Q_'+n for n in GPRS}
        cuts.update({layer['inputMemory']:'Q_memory',layer['entryGuard']:'Q_guard'})
        declared='\n'.join(f'(declare-const Q_{n} (_ BitVec 64))' for n in GPRS)+f'\n(declare-const Q_memory {ARRAY})\n(declare-const Q_guard (_ BitVec 8))'
        lines,regs,m,t,writes=ordinary(kind,True,{n:'Q_'+n for n in GPRS},'Q_memory','Layer')
        g=f'(ite (and (distinct Q_guard {bv(0,8)}) (= {t} {bv(0x14005242b)})) {bv(1,8)} {bv(0,8)})' if step==1 else 'Q_guard'
        roots=[boundary['registers'][n] for n in GPRS]+[boundary['currentMemory'],boundary['control']['target'],boundary['entryGuard']]
        wanted=[regs[n] for n in GPRS]+[m,t,'Q_guard']
        for s,w in zip([s for s in public['stores'] if s['stepIndex']==step],writes):roots += [s[k] for k in ('address','value','beforeMemory','afterMemory','guard')];wanted += w+['Q_guard']
        if step==2:roots.append(boundary['continuedGuard']);wanted.append('Q_guard')
        i=query(f'public{kind}-all16-memory-writes-guard-control-from-exact18-bindings','public250-136-78',roots,wanted,cuts=cuts,extra=declared+'\n'+'\n'.join(lines));layer_queries.append(i)
        if step==1:
            e=public['sideExits'][1];target_node=boundary['control']['target']
            partition_cuts={target_node:'T',layer['entryGuard']:'G',**{boundary['registers'][n]:'Z_'+n for n in GPRS},boundary['currentMemory']:'Z_memory'}
            partition_decl='\n'.join(f'(declare-const Z_{n} (_ BitVec 64))' for n in GPRS)+f'\n(declare-const Z_memory {ARRAY})\n(declare-const T (_ BitVec 64))\n(declare-const G (_ BitVec 8))'
            roots=[boundary['continuedGuard'],e['guard'],e['target'],*[e['registers'][n] for n in GPRS],e['currentMemory']]
            wanted=[f'(ite (and (distinct G {bv(0,8)}) (= T {bv(0x14005242b)})) {bv(1,8)} {bv(0,8)})',f'(ite (and (distinct G {bv(0,8)}) (distinct T {bv(0x14005242b)})) {bv(1,8)} {bv(0,8)})','T',*[f'Z_{n}' for n in GPRS],'Z_memory']
            layer_queries.append(query('public136-complete-target-partition-and-complementary-state','public250-136-78',roots,wanted,cuts=partition_cuts,extra=partition_decl))
    init=f'(declare-const S (_ BitVec 64))\n(declare-const F (_ BitVec 64))\n(assert (= F (bvand {sub("S",bv(648))} {bv(MASK-15)})))'
    starts=[sub('F',bv(8)),sub('S',bv(8)),sub('S',bv(16)),add('F',bv(176)),add('F',bv(192))]
    bounds=q.expect(q.query('all-five-write-classes-stay-in-original671-window',init+'\n(assert (or '+' '.join(f'(bvugt {sub(x,sub("S",bv(671)))} {bv(663)})' for x in starts)+'))'))
    slots=[row['slotByteOffset'] for row in context['contextMap']];assert len(slots)==17 and 176 not in slots and 192 not in slots
    nonalias=init+'\n(declare-const i (_ BitVec 3))\n(declare-const j (_ BitVec 3))\n(assert (or '
    nonalias+=' '.join(f'(= {add(add("F",bv(slot)),"((_ zero_extend 61) i)")} {add(add("F",bv(new)),"((_ zero_extend 61) j)")})' for slot in slots for new in (176,192))+'))'
    new_disjoint=q.expect(q.query('all-old17-context-words-disjoint-from-new176-and192-bytes',nonalias))
    mem=init+f'\n(declare-const H {ARRAY})\n(declare-const FlagsImage (_ BitVec 64))';m='H';memory_queries=[]
    values=['FlagsImage',bv(0),'FlagsImage',bv(0x1400545b6),'FlagsImage',bv(0x14005242b),bv(0),bv(0x1400556d4)]
    classes=[0,1,2,0,3,0,4,0]
    for step,(cls,value) in enumerate(zip(classes,values),1):
        after='M'+str(step);mem+=f'\n(define-fun {after} () {ARRAY} {store(m,starts[cls],value,8)})';m=after
        if step in (4,6,8):
            words=[read(m,sub('S',bv(8)),8)];wanted=[bv(0)]
            if step==4:words.append(read(m,sub('S',bv(16)),8));wanted.append('FlagsImage')
            if step>=6:words.append(read(m,add('F',bv(176)),8));wanted.append('FlagsImage')
            if step==8:words.append(read(m,add('F',bv(192)),8));wanted.append(bv(0))
            memory_queries.append(q.expect(q.query(f'after-{step}-writes-virtual-and-new-context-words-exact',mem+'\n(assert '+different(words,wanted)+')')))
    join_queries=[];negative=[];facts={int(x,16):v for x,v in incoming['initialImageByteFacts']};assert len(facts)==67
    fact_stages=[]
    for kind,offset,index,selector,target in ((136,47,176,78,0x14005242b),(78,49,192,208,0x1400556d4)):
        wa=TABLE+4*selector;newfacts={VIP+offset:image.read(VIP+offset,1)[0],VIP+offset+1:image.read(VIP+offset+1,1)[0],**{wa+i:b for i,b in enumerate(image.read(wa,4))}}
        assert newfacts[VIP+offset]==index and newfacts[VIP+offset+1]==selector and (TABLE+int.from_bytes(image.read(wa,4),'little',signed=True))&MASK==target
        added={x:v for x,v in newfacts.items() if x not in facts};reused={x:v for x,v in newfacts.items() if x in facts};assert all(facts[x]==v for x,v in reused.items());facts.update(added)
        assert (len(facts),len(added),len(reused))==((69,2,4) if kind==136 else (75,6,0))
        fact_stages.append({'handler':kind,'total':len(facts),'added':[[hex(x),v] for x,v in sorted(added.items())],'reused':[[hex(x),v] for x,v in sorted(reused.items())],'current':[[hex(x),v] for x,v in sorted(newfacts.items())],'selector':selector,'target':hex(target)})
        prefix=f'context{kind}-prefix'+('10' if kind==136 else '15');full=f'context{kind}-full'+('22' if kind==136 else '27');word='FlagsImage' if kind==136 else bv(0)
        pointers=init+f'\n(declare-const FlagsImage (_ BitVec 64))\n(assert (= I_rsp F))\n(assert (= I_rbp {sub("S",bv(16 if kind==136 else 8))}))\n(assert (= I_rsi {bv(VIP+offset)}))\n(assert (= I_r11 {bv(TABLE)}))'
        loaded=f'(assert (= {read("M0","I_rbp",8)} {word}))';indexed=f'(assert (= {read("M0","I_rsi",1)} {bv(index,8)}))'
        changes={'rsp':'F','rbp':sub('S',bv(8)) if kind==136 else 'S','rsi':bv(VIP+offset+1),'r11':bv(TABLE)}
        if kind==136:changes.update(rbx=word,rax=bv(index))
        else:changes.update(rdi=word,r10=bv(index))
        c=cores[prefix];roots=[c['registers'][n] for n in GPRS]+[c['currentMemory'],c['control']['target']]
        wanted=[changes.get(n,'I_'+n) for n in GPRS]+[store('M0',add('F',bv(index)),word,8),bv(0x140052124)]
        join_queries.append(query(f'joined{kind}-prefix-all16-whole-context-write',prefix,roots,wanted,extra=pointers+'\n'+loaded+'\n'+indexed))
        negative.append(query(f'negative{kind}-missing-virtual-word-can-change-written-value',prefix,[c['stores'][0]['value']],predicate=lambda a,w=word:f'(distinct {a[0]} {w})',extra=pointers+'\n'+indexed,status='sat'))
        if kind==136:negative.append(query('negative136-missing-index-can-change-context-address',prefix,[c['stores'][0]['address']],predicate=lambda a:f'(distinct {a[0]} {add("F",bv(176))})',extra=pointers+'\n'+loaded,status='sat'))
        c=cores[full];dispatch=c['stores'][-1]['beforeMemory'];known='\n'.join(f'(assert (= (select M_dispatch {bv(x)}) {bv(v,8)}))' for x,v in newfacts.items() if x!=VIP+offset)
        changes.update(rax=bv(selector),r8=bv(target),rsi=bv(VIP+offset+2))
        roots=[c['registers'][n] for n in GPRS]+[c['currentMemory'],c['control']['target']]
        wanted=[changes.get(n,'I_'+n) for n in GPRS]+[store('M_dispatch',sub('F',bv(8)),bv(target),8),bv(target)]
        i=query(f'joined{kind}-full-all16-target-and-dispatch-memory',full,roots,wanted,cuts={dispatch:'M_dispatch'},extra=pointers+'\n'+loaded+'\n'+indexed+'\n'+known);join_queries.append(i)
        negative.append(query(f'negative{kind}-missing-derived-dispatch-bytes-can-change-target',full,[c['control']['target']],predicate=lambda a,t=target:f'(distinct {a[0]} {bv(t)})',cuts={dispatch:'M_dispatch'},extra=pointers+'\n'+loaded+'\n'+indexed,status='sat'))
    premises=init+f'\n(declare-const M0 {ARRAY})\n(assert (bvuge {sub(sub("S",bv(671)),bv(image.imagebase))} {bv(1384448)}))\n(assert (bvuge {sub(bv(image.imagebase),sub("S",bv(671)))} {bv(671)}))\n(assert (not (and (bvuge S {bv(8)}) (bvult S {bv(264)}))))'
    premises+='\n'+'\n'.join(f'(assert (= (select M0 {bv(x)}) {bv(v,8)}))' for x,v in facts.items());consistent=q.expect(q.query('all75-image-region-and-prior-fast-premises-consistent',premises,'sat'))
    numeric=numeric_join(replay,public,facts,context['contextMap'],deadline)
    result={'schema':'ig5-context-write-conditional-join-v1','passed':True,'sourceReceipt':{'path':a.receipt,'sha256':a.receipt_sha},'reports':refs,'incoming250Proof':{'path':a.incoming_proof,'sha256':a.incoming_sha},'incomingChainProof':{'path':a.chain_proof,'sha256':a.chain_sha},
        'entryOrdinaryEquivalence':{'sourceReport':context['sourceReport'],'newCase':'entry17-status','entireDagNodesEqual':True,'semanticFieldsEqual':list(SEMANTIC_FIELDS),'entryKnownMask':'0x0','entryEffectiveUnknownBits':64},
        'reused250Prefix':{'case':'public250-136-78','oldCase':'status250-136','nodeEndExclusive':103,'allNodesLayerAndBoundaryEqual':True,'fullLayerQuery':chain['fullLayer0Query'],'wholeImageEquationQuery':chain['wholeFlagImageEquationQuery']},
        'queries':q.rows,'localStateCertificates':local,'publicLayerQueries':layer_queries,'writeWindowQuery':bounds,'newContextByteNonaliasQuery':new_disjoint,'orderedMemoryWordQueries':memory_queries,'joinedStateQueries':join_queries,'negativeControls':negative,'premisesSatisfiableQuery':consistent,
        'contextPreservationCertificate':{'method':'Explicit finite pointwise byte-memory induction','slots':slots,'readByteOffsets':list(range(8)),'writeByteOffsets':list(range(8)),'writeClasses':['F-8','S-8','S-16','F+176','F+192'],'orderedWriteClassIndices':classes,'bytePairInstantiations':17*8*8*8,'priorThreeClassNonaliasQuery':prior137['contextWordNonaliasQuery'],'newTwoClassNonaliasQuery':new_disjoint,'singleBytePreservationQuery':context['lemmas']['bytePreservation'],'all17PriorWordsPreserved':True,'noNodeIdInequalityUsed':True},
        'imagePreservationCertificate':{'windowBytes':671,'wordStartMax':663,'allFiveStartsQuery':bounds,'offsetWidthBridgeLemma':domain['window']['offsetWidthBridgeLemma'],'preservationLemma':domain['window']['preservationLemma'],'imageSeparationLemma':domain['window']['imageSeparationLemma'],'everyPrefixOfEightWritesPreservesAll75InitialImageFacts':True},
        'initialImageByteFacts':[[hex(x),v] for x,v in sorted(facts.items())],'factStages':fact_stages,'conditionalNewSlots':{'176':'fresh250FlagsImage; mask0x8c5==0x44; other59bits unknown','192':'0'},'nextSelector':208,'nextTarget':'0x1400556d4','numeric':numeric,
        'inductionScope':'Whole local equations and public exact18 binding summaries; original671-window/image lemmas and explicit byte induction connect67->69->75 facts and preserve17 prior words. Dispatch-memory cuts denote certified post-context-write memories; all source DAGs are checked behind cuts. No single uncut whole-chain SMT query.',
        'sourceProofScriptSha256':sha(__file__),'encoderSourceSha256':sha(MAIN/'scripts/composition_domain_smt.py'),'solverDllSha256':q.dll_sha,'limits':incoming['limits'],'publicCrossReportJoinIntegrated':False,'wholeChainUncutQueryPerformed':False,
        'nativeTargetExecuted':False,'databaseModified':False,'architectureProved':False,'nativeReachabilityProved':False,'businessAccepted':False,'wholeBinaryVerified':False}
    raw=(json.dumps(result,indent=2)+'\n').encode('utf8');assert len(raw)<=4*1024**2 and time.monotonic()<deadline
    with (out/'verified.json').open('xb') as f:f.write(raw)

def numeric_join(replay,public,facts,context_map,deadline):
    rng=random.Random(0x3133363738);stacks=[rng.getrandbits(64) for _ in range(512)]+list(range(672))+[(VIP-256+i*8)&MASK for i in range(64)]+[MASK-i for i in range(16)]
    counts={'states':len(stacks),'separatedEntry':0,'nonseparatedSkipped':0,'literalAlternate':0,'reachedFullChain':0}
    def memory(pair):
        initial,overlay=pair
        return lambda a:overlay.get(a&MASK,initial(a&MASK))
    def run(c,r,m,unknowns=None):
        v=projection_values(c,r,m,unknowns=unknowns);return v,{n:v[i] for n,i in c['registers'].items()},memory(v[c['currentMemory']])
    def word(m,a):return sum(m((a+i)&MASK)<<(8*i) for i in range(8))
    for S in stacks:
        assert time.monotonic()<deadline;L=(S-671)&MASK
        if ((L-0x140000000)&MASK)<1384448 or ((0x140000000-L)&MASK)<671:counts['nonseparatedSkipped']+=1;continue
        counts['separatedEntry']+=1;initial={n:rng.getrandbits(64) for n in GPRS};initial['rsp']=S;origin=total_byte(rng.getrandbits(64),facts)
        c=replay['entry17-status'];unknowns={c['dag']['nodes'][x['node']]['name']:rng.getrandbits(64) for x in c['nondeterministicInputs']};v,r,m=run(c,initial,origin,unknowns);F=((S-648)&MASK)&(MASK-15)
        assert v[c['pathGuard']]==1 and v[c['control']['target']]==0x1400525ca
        saved={}
        for row in context_map:
            label=row['valueLabel'];value=0 if label=='zero' else unknowns[c['dag']['nodes'][int(row['valueSMT'].split('_')[1])]['name']] if label=='opaque-flag-image' else initial[label]
            saved[row['slotByteOffset']]=value;assert word(m,F+row['slotByteOffset'])==value
        c=replay['literal-fast-dispatch22'];v,r,m=run(c,r,m);assert v[c['pathGuard']]==int(not 8<=S<264)
        if not v[c['pathGuard']]:counts['literalAlternate']+=1;continue
        c=replay['context137-fast28'];v,r,m=run(c,r,m);assert v[c['pathGuard']]==1 and r['rsp']==F and r['rbp']==(S-16)&MASK and r['rsi']==VIP+46 and r['rdx']==48
        before=dict(r);prior=m;U=rng.getrandbits(64);unknown={public['dag']['nodes'][public['nondeterministicInputs'][0]['node']]['name']:U};v,r,m=run(public,r,m,unknown);flags=(U&(MASK^0x8c5))|0x44
        expected={**before,'rax':208,'rsp':F,'rbp':S,'rsi':VIP+51,'r8':0x1400556d4,'rbx':flags,'r10':192,'rdi':0}
        assert r==expected and v[public['pathGuard']]==1 and v[public['control']['target']]==0x1400556d4
        expected_writes=[(F-8,flags),(S-8,0),(S-16,flags),(F-8,0x1400545b6),(F+176,flags),(F-8,0x14005242b),(F+192,0),(F-8,0x1400556d4)];overlay={}
        for s,(address,value) in zip(public['stores'],expected_writes):
            assert v[s['address']]==address&MASK and v[s['value']]==value and v[s['guard']]==1
            overlay.update({(address+i)&MASK:(value>>(8*i))&255 for i in range(8)})
        assert v[public['currentMemory']]==(prior,overlay)
        assert all(word(m,F+slot)==value for slot,value in saved.items()) and word(m,F+176)==flags and word(m,F+192)==0 and word(m,S-8)==0
        assert all(m(x)==value for x,value in facts.items()) and all(v[e['guard']]==0 for e in public['sideExits'])
        counts['reachedFullChain']+=1
    assert counts=={'states':1264,'separatedEntry':1200,'nonseparatedSkipped':64,'literalAlternate':256,'reachedFullChain':944}
    return {**counts,'initialImageByteFacts':75,'all16GPRsWholeMemoryEightOrderedWritesAndComplementaryGuardsCompared':True,'all17OriginalContextWordsAndNew176192Compared':True,'independentEntryAnd250UnknownInputsVaried':True,'guardFalseNeverUsedAsNextInput':True,'notIndependentCPUInterpreter':True,'notUniversalProof':True,'sameBatchesAcrossDeploymentsNotExtraCoverage':True}

if __name__=='__main__':main()
