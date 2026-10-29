"""Conditional context208 and next137 -> context144 -> next136 join.

Reuses byte-identical free-state certificates instead of recounting them as new
queries. New public bindings, actual memories, byte facts and guards are proved.
"""
from pathlib import Path
from contextlib import ExitStack
import argparse,hashlib,json,random,sys,time
MAIN=Path(__file__).resolve().parents[1];sys.path[:0]=[str(MAIN/'worker'),str(MAIN/'scripts')]
from composition_domain_smt import ARRAY,GPRS,Queries,encode,validate,add,sub,bv,read,store,sha
from projection_numerical_oracle import MASK,projection_values,total_byte
from prove_context_write_join import ordinary as context_ordinary
from prove_context200_join import ordinary as previous_ordinary
from prove_handler208_semantics import flag,different
TARGET='5f9c1b6fcb019366f835d8f02d9ec3b2957fe619e039410d07f288a9c73f63f0'
VIP=0x1400846c4;TABLE=0x140056098
AUX=('prove_context_write_join.py','prove_context200_join.py','prove_handler208_semantics.py','projection_numerical_oracle.py')

def ordinary(kind,r,m,tag):
    if kind=='78':
        lines,regs,after,t,writes=context_ordinary(78,True,r,m,tag);return lines,regs,after,[t],writes
    if kind=='dispatch':return previous_ordinary(kind,r,m,tag)
    assert kind=='137'
    # Same independent context-read/stack-write equations as0;137 writes the
    # loaded word toRBX, preservingR9. Fresh original16/28 cores are also checked
    # identical to the prior four uncut universal137 certificates.
    lines,regs,after,control,writes=previous_ordinary('0',r,m,tag)
    regs.update(rbx=regs['r9'],r9=r['r9']);return lines,regs,after,control,writes

def main():
    p=argparse.ArgumentParser()
    for k in ('receipt','receipt-sha','incoming-proof','incoming-sha','out'):p.add_argument('--'+k,required=True)
    p.add_argument('--child',action='store_true');a=p.parse_args();out=Path(a.out)
    assert all(Path(x).is_absolute() for x in (a.receipt,a.incoming_proof,a.out))
    from lift_runtime import locked_file
    if not a.child:
        from lift_process import run_owned
        out.mkdir(exist_ok=False);job=out/'job';job.mkdir();proc=run_owned(str(MAIN/'runtimes/ghidra/python/python.exe'),['-I','-B','-X','utf8',str(Path(__file__)),*sys.argv[1:],'--child'],job,budget_ms=50000)
        (out/'process.json').write_text(json.dumps(proc,indent=2)+'\n',encoding='utf8');assert proc['childExitConfirmed'] and proc['jobAssignedAtCreation']
        if proc['exitCode']!=0:
            with locked_file(job/'stderr.log',4*1024**2) as raw:error=raw.decode('utf8')
            with locked_file(job/'stdout.log',4*1024**2) as raw:error+='\n'+raw.decode('utf8')[-6000:]
            raise AssertionError(error)
        with locked_file(out/'verified.json',4*1024**2) as raw:v=json.loads(raw)
        print(json.dumps({'passed':v['passed'],'newQueries':len(v['queries']),'statuses':{s:sum(r['status']==s for r in v['queries']) for s in ('unsat','sat','unknown')},'numeric':v['numeric'],'verifiedSha256':sha(out/'verified.json'),'process':proc}));return
    deadline=time.monotonic()+45
    with ExitStack() as held:
        def load(path,pin=None,maximum=4*1024**2):
            assert Path(path).is_absolute() and '..' not in Path(path).parts
            raw=held.enter_context(locked_file(Path(path),maximum));assert pin is None or hashlib.sha256(raw).hexdigest()==pin;return json.loads(raw)
        def cert(ref,script,audit=True):
            v=load(ref['path'],ref['sha256']);assert v['passed'] and v['sourceProofScriptSha256']==sha(MAIN/'scripts'/script) and v['encoderSourceSha256']==sha(MAIN/'scripts/composition_domain_smt.py')
            proc=load(Path(ref['path']).parent/'process.json',maximum=65536);assert proc['exitCode']==0 and proc['childExitConfirmed'] and proc['jobAssignedAtCreation'] and proc['activeProcessLimit']==1 and proc['memoryLimitBytes']==2147483648
            if audit:
                ar=load(Path(ref['path']).parent/'independent-audit.json');assert ar['passed'] and ar['proofSha256']==ref['sha256']
            for row in v['queries']:assert sha(row['path'])==row['sha256'] and row['timeoutMs']<=2000 and row['status'] in (row['expected'],'unknown')
            return v
        incoming=cert({'path':a.incoming_proof,'sha256':a.incoming_sha},'prove_context200_join.py');p208=cert(incoming['incoming208Proof'],'prove_handler208_semantics.py');prior=cert(p208['incomingProof'],'prove_context_write_join.py')
        p250=cert(prior['incoming250Proof'],'prove_handler250_semantics.py');p137=cert(p250['incoming137Proof'],'prove_handler137_semantics.py');context=cert(p137['incomingContextProof'],'prove_context_mapping.py',False);domain=cert(context['incomingDomainProof'],'prove_entry_chain_domain.py');literal=cert(p137['incomingLiteralProof'],'prove_handler17_semantics.py',False)
        assert len(incoming['initialImageByteFacts'])==84 and incoming['nextSelector']==78 and incoming['nextTarget']=='0x14005242b'
        for k in ('offsetWidthBridgeLemma','preservationLemma','imageSeparationLemma'):assert domain['queries'][domain['window'][k]]['status']=='unsat'
        assert p208['queries'][p208['contextNonaliasQuery']]['status']=='unsat' and context['queries'][context['lemmas']['bytePreservation']]['status']=='unsat'
        receipt=load(a.receipt,a.receipt_sha);assert receipt['passed'] and receipt['activeRequests']==0;cores={};refs={}
        for c in receipt['cases']:
            assert not c['rejected'] and c['cleanupConfirmed'] and c['rootExitConfirmed'];ref=c['result'];cores[c['id']]=load(ref['reportPath'],ref['reportSha256'])['result'];refs[c['id']]={'path':ref['reportPath'],'sha256':ref['reportSha256']}
        from kernel_image import BinaryImage
        data=held.enter_context(locked_file(Path(receipt['cases'][0]['args']['target']),4*1024**2));assert hashlib.sha256(data).hexdigest()==TARGET;image=BinaryImage.from_bytes(data)
        for c in cores.values():
            validate(c);assert c['targetSha256']==TARGET and set(c['registers'])==set(GPRS) and all(c[k] is False for k in ('nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'))
            assert all(image.read(int(r['ea'],16),r['decoded']['size']).hex()==r['bytes'] for r in c['decodedPath'])
        reused=[]
        for name,proof,proofref,indices in (('context78-prefix15',prior,p208['incomingProof'],[2]),('context78-full27',prior,p208['incomingProof'],[3]),('context137-check16',p137,p250['incoming137Proof'],[0]),('context137-fast28',p137,p250['incoming137Proof'],[1,2,3])):
            ref=proof['reports'][name];assert cores[name]==load(ref['path'],ref['sha256'])['result']
            for i in indices:row=proof['queries'][i];assert row['status']=='unsat' and not row['explicitCuts'] and row['wholeSourceDagValidated']
            reused.append({'case':name,'priorProof':proofref,'priorReport':ref,'queries':indices,'entireFreshCoreEqual':True,'notNewQueriesOrCoverage':True})
        replay={}
        for name,ref in (('entry',prior['reports']['entry17-status']),('literal',literal['reports']['literal-fast-dispatch22']),('137',p137['reports']['context137-fast28']),('25078',prior['reports']['public250-136-78']),('2000',incoming['reports']['public208-136-0'])):replay[name]=load(ref['path'],ref['sha256'])['result']
        q=Queries(MAIN,out/'queries',deadline)
        try:prove(a,out,cores,refs,incoming,p208,context,domain,image,replay,reused,q,deadline)
        finally:q.close()

def prove(a,out,cores,refs,incoming,p208,context,domain,image,replay,reused,q,deadline):
    def query(name,case,roots,wanted=None,*,cuts=None,extra='',predicate=None,status='unsat'):
        cuts=cuts or {};lines,actual,meta=encode(cores[case],roots,cuts=cuts);meta.update(sourceCase=case,rootNodes=roots,cutNames={str(i):n for i,n in cuts.items()})
        dec=[s for s in lines if s.startswith('(declare-')];eq=[s for s in lines if not s.startswith('(declare-')]
        return q.expect(q.query(name,'\n'.join(dec)+'\n'+extra+'\n'+'\n'.join(eq)+'\n(assert '+(different(actual,wanted) if wanted is not None else predicate(actual))+')',status,meta))
    public=cores['public78-137'];assert len(public['layers'])==3 and len(public['stores'])==4 and len(public['sideExits'])==2;layer_queries=[];partition_queries=[]
    for step,kind in enumerate(('78','137','dispatch')):
        l=public['layers'][step];b=public['boundaries'][step];cuts={l['inputRegisters'][n]:'Q_'+n for n in GPRS};cuts[l['inputMemory']]='Q_memory';g=bv(1,8) if step==0 else 'Q_guard'
        if step:cuts[l['entryGuard']]=g
        decl='\n'.join(f'(declare-const Q_{n} (_ BitVec 64))' for n in GPRS)+f'\n(declare-const Q_memory {ARRAY})'+('' if step==0 else '\n(declare-const Q_guard (_ BitVec 8))')
        eq,r,m,control,writes=ordinary(kind,{n:'Q_'+n for n in GPRS},'Q_memory','Layer')
        roots=[b['registers'][n] for n in GPRS]+[b['currentMemory'],b['entryGuard']]+[b['control'][k] for k in (('condition','taken','fallthrough') if len(control)==3 else ('target',))];want=[r[n] for n in GPRS]+[m,g]+control
        for s,w in zip([s for s in public['stores'] if s['stepIndex']==step],writes):roots += [s[k] for k in ('address','value','beforeMemory','afterMemory','guard')];want += w+[g]
        if step==1:
            e=public['sideExits'][1];roots += [b['continuedGuard'],e['guard'],e['target'],*[e['registers'][n] for n in GPRS],e['currentMemory']]
            want += [flag(f'(and (distinct {g} {bv(0,8)}) (distinct {control[0]} {bv(0,8)}))'),flag(f'(and (distinct {g} {bv(0,8)}) (= {control[0]} {bv(0,8)}))'),control[2],*[r[n] for n in GPRS],m]
        elif step==2:roots.append(b['continuedGuard']);want.append(g)
        layer_queries.append(query('public-layer-'+str(step)+'-all16-memory-writes-guards-control','public78-137',roots,want,cuts=cuts,extra=decl+'\n'+'\n'.join(eq)))
        if step==0:
            e=public['sideExits'][0];pc={b['control']['target']:'T',**{b['registers'][n]:'Z_'+n for n in GPRS},b['currentMemory']:'Z_memory'};dec='\n'.join(f'(declare-const Z_{n} (_ BitVec 64))' for n in GPRS)+f'\n(declare-const Z_memory {ARRAY})\n(declare-const T (_ BitVec 64))'
            roots=[b['continuedGuard'],e['guard'],e['target'],*[e['registers'][n] for n in GPRS],e['currentMemory']];want=[flag(f'(= T {bv(0x1400545e7)})'),flag(f'(distinct T {bv(0x1400545e7)})'),'T',*[f'Z_{n}' for n in GPRS],'Z_memory']
            partition_queries.append(query('public78-complete-target-partition-and-alternate-state','public78-137',roots,want,cuts=pc,extra=dec))
    init=f'(declare-const S (_ BitVec 64))\n(declare-const F (_ BitVec 64))\n(assert (= F (bvand {sub("S",bv(648))} {bv(MASK-15)})))';fast=f'(bvugt {sub("S",bv(8))} {add("F",bv(384))})';starts=[add('F',bv(208)),sub('F',bv(8)),sub('S',bv(8))]
    bounds=q.expect(q.query('new208-and-stack-write-classes-in-original671-window',init+'\n(assert (or '+' '.join(f'(bvugt {sub(x,sub("S",bv(671)))} {bv(663)})' for x in starts)+'))'))
    oldslots=incoming['contextPreservation']['priorSlots']+[200];assert len(set(oldslots))==20 and 208 not in oldslots
    text=init+'\n(declare-const i (_ BitVec 3))\n(declare-const j (_ BitVec 3))\n(assert (or '+' '.join(f'(= {add(add("F",bv(slot)),"((_ zero_extend 61) i)")} {add(add("F",bv(208)),"((_ zero_extend 61) j)")})' for slot in oldslots)+'))'
    disjoint=q.expect(q.query('new208-word-disjoint-from-all20-prior-words',text))
    mem=init+f'\n(declare-const Before {ARRAY})\n(declare-const EntryRBP (_ BitVec 64))\n(declare-const EntryRSI (_ BitVec 64))';m='Before';memory_queries=[];classes=[0,1,2,1];vals=['EntryRBP',bv(0x1400545e7),'EntryRSI',bv(0x1400545b6)]
    for step,(cls,value) in enumerate(zip(classes,vals),1):
        after='After'+str(step);mem+=f'\n(define-fun {after} () {ARRAY} {store(m,starts[cls],value,8)})';m=after
        if step in (2,4):
            roots=[read(m,starts[0],8)];want=['EntryRBP']
            if step==4:roots.append(read(m,starts[2],8));want.append('EntryRSI')
            memory_queries.append(q.expect(q.query('after-'+str(step)+'-writes-saved208-and-virtual-word',mem+'\n(assert '+different(roots,want)+')')))
    facts={int(x,16):v for x,v in incoming['initialImageByteFacts']};stages=[];word_queries=[];join_queries=[];negative=[]
    for kind,offset,index,selector,target in ((78,56,208,137,0x1400545e7),(137,58,144,136,0x1400545b6)):
        wa=TABLE+4*selector;current={VIP+offset:image.read(VIP+offset,1)[0],VIP+offset+1:image.read(VIP+offset+1,1)[0],**{wa+i:b for i,b in enumerate(image.read(wa,4))}}
        assert current[VIP+offset]==index and current[VIP+offset+1]==selector and TABLE+int.from_bytes(image.read(wa,4),'little',signed=True)==target
        added={x:v for x,v in current.items() if x not in facts};old={x:v for x,v in current.items() if x in facts};assert len(added)==2 and len(old)==4 and all(facts[x]==v for x,v in old.items());facts.update(added);assert len(facts)==(86 if kind==78 else 88)
        stages.append({'handler':kind,'total':len(facts),'added':[[hex(x),v] for x,v in sorted(added.items())],'reused':[[hex(x),v] for x,v in sorted(old.items())]})
        word='EntryRBP' if kind==78 else 'EntryRSI';source=sub('S',bv(8)) if kind==78 else add('F',bv(144));address=add('F',bv(208)) if kind==78 else sub('S',bv(8))
        pointers=init+f'\n(declare-const {word} (_ BitVec 64))\n(assert (= I_rsp F))\n(assert (= I_rbp {sub("S",bv(8)) if kind==78 else "S"}))\n(assert (= I_rsi {bv(VIP+offset)}))\n(assert (= I_r11 {bv(TABLE)}))';loaded=f'(assert (= {read("M0",source,8)} {word}))';indexed=f'(assert (= {read("M0","I_rsi",1)} {bv(index,8)}))'
        prefix='context78-prefix15' if kind==78 else 'context137-check16';c=cores[prefix];s=c['stores'][0]
        word_queries.append(query('joined'+str(kind)+'-original-load-source-word',prefix,[s['value']],[word],extra=pointers+'\n'+loaded+'\n'+indexed))
        changes={'rsp':'F','r11':bv(TABLE),'rbp':'S' if kind==78 else sub('S',bv(8)),'rsi':bv(VIP+offset+1)}
        if kind==78:changes.update(rdi=word,r10=bv(index))
        else:changes.update(rbx=word,rdx=bv(index),r8=add('F',bv(384)))
        roots=[c['registers'][n] for n in GPRS]+[c['currentMemory']];want=[changes.get(n,'I_'+n) for n in GPRS]+[store('M0',address,word,8)]
        join_queries.append(query('joined'+str(kind)+'-prefix-all16-whole-memory',prefix,roots,want,cuts={s['value']:word},extra=pointers+'\n'+loaded+'\n'+indexed))
        negative.append(query('negative'+str(kind)+'-missing-source-word-changes-value',prefix,[s['value']],predicate=lambda xs,w=word:f'(distinct {xs[0]} {w})',extra=pointers+'\n'+indexed,status='sat'))
        if kind==78:negative.append(query('negative78-missing-index-changes-destination',prefix,[s['address']],predicate=lambda xs:f'(distinct {xs[0]} {add("F",bv(208))})',extra=pointers+'\n'+loaded,status='sat'))
        name='context78-full27' if kind==78 else 'context137-fast28';c=cores[name];cut=c['stores'][1]['beforeMemory'];known=f'(declare-const DispatchMemory {ARRAY})\n'+'\n'.join(f'(assert (= (select DispatchMemory {bv(x)}) {bv(v,8)}))' for x,v in current.items() if x!=VIP+offset)
        changes.update(rax=bv(selector),r8=bv(target),rsi=bv(VIP+offset+2));roots=[c['registers'][n] for n in GPRS]+[c['currentMemory'],c['control']['target']];want=[changes.get(n,'I_'+n) for n in GPRS]+[store('DispatchMemory',sub('F',bv(8)),bv(target),8),bv(target)]
        if kind==137:roots.append(c['pathGuard']);want.append(bv(1,8))
        join_queries.append(query('joined'+str(kind)+'-full-all16-target-dispatch-memory',name,roots,want,cuts={cut:'DispatchMemory',c['stores'][0]['value']:word},extra=pointers+'\n'+loaded+'\n'+indexed+'\n'+known+f'\n(assert {fast})'))
        negative.append(query('negative'+str(kind)+'-missing-dispatch-bytes-changes-target',name,[c['control']['target']],predicate=lambda xs,t=target:f'(distinct {xs[0]} {bv(t)})',cuts={cut:'DispatchMemory'},extra=f'(declare-const DispatchMemory {ARRAY})\n'+pointers+'\n'+loaded+'\n'+indexed+f'\n(assert (= S {bv(0x100000)}))\n(assert (= DispatchMemory {store("M0",address,word,8)}))',status='sat'))
    false_range=f'(and (bvuge S {bv(8)}) (bvult S {bv(264)}))';c=cores['context137-check16']
    guard=query('joined137-guard-false-exactly8-through263','context137-check16',[c['control']['condition']],[flag(f'(not {false_range})')],extra=init+'\n(assert (= I_rsp F))\n(assert (= I_rbp S))')
    implies=q.expect(q.query('prior-fast-implies-new137-fast',init+f'\n(assert (not {false_range}))\n(assert (not {fast}))'))
    premises=init+f'\n(declare-const M0 {ARRAY})\n(assert (bvuge {sub(sub("S",bv(671)),bv(image.imagebase))} {bv(domain["image"]["bytes"])}))\n(assert (bvuge {sub(bv(image.imagebase),sub("S",bv(671)))} {bv(671)}))\n(assert {fast})'+'\n'+'\n'.join(f'(assert (= (select M0 {bv(x)}) {bv(v,8)}))' for x,v in facts.items())
    consistent=q.expect(q.query('all88-byte-region-and-fast-premises-consistent',premises,'sat'));numeric=numeric_checks(cores,facts,context,replay,deadline)
    result={'schema':'ig5-context208-and137-conditional-join-v1','passed':True,'sourceReceipt':{'path':a.receipt,'sha256':a.receipt_sha},'reports':refs,'incoming200Proof':{'path':a.incoming_proof,'sha256':a.incoming_sha},'reusedFreeStateCertificates':reused,'queries':q.rows,'publicLayerQueries':layer_queries,'publicTargetPartitionQueries':partition_queries,'newWriteWindowQuery':bounds,'newContext208NonaliasQuery':disjoint,'orderedMemoryWordQueries':memory_queries,'originalSourceWordQueries':word_queries,'joinedStateQueries':join_queries,'guardFalseRangeQuery':guard,'priorFastImpliesCurrentFastQuery':implies,'negativeControls':negative,'premisesSatisfiableQuery':consistent,'initialImageByteFacts':[[hex(x),v] for x,v in sorted(facts.items())],'factStages':stages,'nextSelector':136,'nextTarget':'0x1400545b6','newContextSlot':208,'newContextValue':'original entry RBP','context144SourceCertificate':next(x for x in context['contextMap'] if x['slotByteOffset']==144),'finalVirtualWord':'original entry RSI','joinedGuardFalseInitialRSPRange':[8,263],
        'contextPreservation':{'priorSlots':oldslots,'newSlot':208,'readByteOffsets':list(range(8)),'writeByteOffsets':list(range(8)),'bytePairInstances':20*8*8,'priorAny256SlotStackNonaliasQuery':p208['contextNonaliasQuery'],'singleBytePreservationQuery':context['lemmas']['bytePreservation'],'all21WordsPreservedAfterFinalStackWrite':True,'orderedWriteClasses':['F+208','F-8','S-8','F-8']},'imagePreservation':{'windowBytes':671,'wordStartMax':663,'offsetWidthBridgeLemma':domain['window']['offsetWidthBridgeLemma'],'preservationLemma':domain['window']['preservationLemma'],'imageSeparationLemma':domain['window']['imageSeparationLemma'],'all88FactsPreservedAtEveryPrefix':True},'numeric':numeric,'sourceProofScriptSha256':sha(__file__),'encoderSourceSha256':sha(MAIN/'scripts/composition_domain_smt.py'),'auxiliarySources':{f:sha(MAIN/'scripts'/f) for f in AUX},'solverDllSha256':q.dll_sha,'limits':incoming['limits'],'publicCrossReportJoinIntegrated':False,'wholeChainUncutQueryPerformed':False,'scope':'Prior byte-identical free-state proofs reused; new exact3-layer54-binding/4write/2complement induction, certified sourceword/postSTORE memory cuts and original671-window/context byte induction connect84->86->88. SAT memory cuts restored. Not one uncut wholeVM/CPU/native/exact3.8/business proof.','nativeTargetExecuted':False,'databaseModified':False,'architectureProved':False,'nativeReachabilityProved':False,'businessAccepted':False,'wholeBinaryVerified':False}
    raw=(json.dumps(result,indent=2)+'\n').encode('utf8');assert len(raw)<=4*1024**2 and time.monotonic()<deadline
    with (out/'verified.json').open('xb') as f:f.write(raw)

def numeric_checks(cores,facts,context,replay,deadline):
    rng=random.Random(0x323038313337);stacks=[rng.getrandbits(64) for _ in range(128)]+list(range(672))+[(VIP-256+i*8)&MASK for i in range(64)]+[MASK-i for i in range(16)];counts={'states':len(stacks),'separated':0,'nonseparatedSkipped':0,'priorAlternateStopped':0,'reachedNext136':0}
    def memory(pair):
        origin,overlay=pair;return lambda addr:overlay.get(addr&MASK,origin(addr&MASK))
    def run(c,r,m,u=None):
        v=projection_values(c,r,m,unknowns=u);return v,{n:v[i] for n,i in c['registers'].items()},memory(v[c['currentMemory']])
    def word(m,a):return sum(m((a+i)&MASK)<<(8*i) for i in range(8))
    public=cores['public78-137']
    for S in stacks:
        assert time.monotonic()<deadline;L=(S-671)&MASK
        if ((L-0x140000000)&MASK)<1384448 or ((0x140000000-L)&MASK)<671:counts['nonseparatedSkipped']+=1;continue
        counts['separated']+=1;initial={n:rng.getrandbits(64) for n in GPRS};initial['rsp']=S;origin=total_byte(rng.getrandbits(64),facts);entry=replay['entry'];u={entry['dag']['nodes'][x['node']]['name']:rng.getrandbits(64) for x in entry['nondeterministicInputs']};v,r,m=run(entry,initial,origin,u);F=((S-648)&MASK)&(MASK-15);saved={x['slotByteOffset']:word(m,F+x['slotByteOffset']) for x in context['contextMap']};assert saved[144]==initial['rsi']
        v,r,m=run(replay['literal'],r,m)
        if not v[replay['literal']['pathGuard']]:counts['priorAlternateStopped']+=1;continue
        v,r,m=run(replay['137'],r,m);assert v[replay['137']['pathGuard']]==1
        c=replay['25078'];u={c['dag']['nodes'][x['node']]['name']:rng.getrandbits(64) for x in c['nondeterministicInputs']};v,r,m=run(c,r,m,u);assert v[c['pathGuard']]==1;saved[176]=word(m,F+176);saved[192]=0
        c=replay['2000'];v,r,m=run(c,r,m);assert v[c['pathGuard']]==1 and word(m,S-8)==initial['rbp'];saved[200]=S
        before=dict(r);prior=m;v,r,m=run(public,r,m);expected={**before,'rax':136,'r8':0x1400545b6,'rbp':(S-8)&MASK,'rsi':VIP+60,'rdi':initial['rbp'],'r10':208,'rbx':initial['rsi'],'rdx':144}
        assert r==expected and v[public['pathGuard']]==1 and v[public['control']['target']]==0x1400545b6;writes=[((F+208)&MASK,initial['rbp']),((F-8)&MASK,0x1400545e7),((S-8)&MASK,initial['rsi']),((F-8)&MASK,0x1400545b6)];overlay={}
        for s,(address,value) in zip(public['stores'],writes):assert v[s['address']]==address and v[s['value']]==value and v[s['guard']]==1;overlay.update({(address+i)&MASK:(value>>(8*i))&255 for i in range(8)})
        assert v[public['currentMemory']]==(prior,overlay) and all(v[e['guard']]==0 for e in public['sideExits']) and all(word(m,F+slot)==value for slot,value in saved.items()) and word(m,F+208)==initial['rbp'] and word(m,S-8)==initial['rsi'] and all(m(a)==b for a,b in facts.items());counts['reachedNext136']+=1
    return {**counts,'all16WholeMemoryFourWritesTwoComplementsAnd21WordsChecked':True,'independentEntry64And25059UnknownBitsVaried':True,'guardFalseNeverFedAsReachableNextState':True,'sameBatchAcrossDeploymentsNotAdditionalCoverage':True,'notIndependentCPUInterpreter':True,'notUniversalProof':True}

if __name__=='__main__':main()
