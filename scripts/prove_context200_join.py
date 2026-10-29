"""Full ordinary136/0 state and conditional context200 / next78 connection.

Owned3.11 bytes only. Whole component equations, public binding induction and
explicit byte-memory preservation; no target execution or whole-VM theorem.
"""
from pathlib import Path
from contextlib import ExitStack
import argparse,hashlib,json,random,sys,time
MAIN=Path(__file__).resolve().parents[1];sys.path[:0]=[str(MAIN/'worker'),str(MAIN/'scripts')]
from composition_domain_smt import ARRAY,GPRS,Queries,encode,validate,add,sub,bv,read,store,sha
from projection_numerical_oracle import MASK,projection_values,total_byte,context0_cases
from prove_context_write_join import ordinary as context_ordinary
from prove_handler208_semantics import ordinary as stack_ordinary,flag,different
TARGET='5f9c1b6fcb019366f835d8f02d9ec3b2957fe619e039410d07f288a9c73f63f0'
VIP=0x1400846c4;TABLE=0x140056098
AUXILIARY=('prove_context_write_join.py','prove_handler208_semantics.py','projection_numerical_oracle.py')

def ordinary(kind,r,m,tag):
    if kind=='136':
        lines,regs,after,target,writes=context_ordinary(136,True,r,m,tag);return lines,regs,after,[target],writes
    if kind in ('208','dispatch'):
        lines,regs,after,control,w=stack_ordinary('check' if kind=='208' else 'dispatch',r,m,tag);return lines,regs,after,control,[w]
    assert kind=='0';lines=[];out=dict(r)
    def define(name,bits,term):
        name=tag+'_'+name;lines.extend([f'(declare-const {name} {ARRAY if bits is None else f"(_ BitVec {bits})"})',f'(assert (= {name} {term}))']);return name
    index=define('index',64,f'((_ zero_extend 56) {read(m,r["rsi"],1)})');value=define('word',64,read(m,add(r['rsp'],index),8));address=define('address',64,sub(r['rbp'],bv(8)))
    after=define('memory',None,store(m,address,value,8));out.update(rdx=index,r9=value,rbp=address,rsi=add(r['rsi'],bv(1)),r8=add(r['rsp'],bv(384)))
    return lines,out,after,[flag(f'(bvugt {address} {out["r8"]})'),bv(0x140052124),bv(0x140052162)],[[address,value,m,after]]

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
        print(json.dumps({'passed':v['passed'],'queries':len(v['queries']),'statuses':{s:sum(r['status']==s for r in v['queries']) for s in ('unsat','sat','unknown')},'numeric':v['numeric'],'verifiedSha256':sha(out/'verified.json'),'process':proc}));return
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
        incoming=cert({'path':a.incoming_proof,'sha256':a.incoming_sha},'prove_handler208_semantics.py');prior=cert(incoming['incomingProof'],'prove_context_write_join.py')
        p250=cert(prior['incoming250Proof'],'prove_handler250_semantics.py');p137=cert(p250['incoming137Proof'],'prove_handler137_semantics.py');context=cert(p137['incomingContextProof'],'prove_context_mapping.py',False);domain=cert(context['incomingDomainProof'],'prove_entry_chain_domain.py');literal=cert(p137['incomingLiteralProof'],'prove_handler17_semantics.py',False)
        assert incoming['nextSelector']==136 and incoming['nextTarget']=='0x1400545b6' and len(incoming['initialImageByteFacts'])==76
        for key in ('offsetWidthBridgeLemma','preservationLemma','imageSeparationLemma'):assert domain['queries'][domain['window'][key]]['status']=='unsat'
        assert context['queries'][context['lemmas']['bytePreservation']]['status']=='unsat' and incoming['queries'][incoming['contextNonaliasQuery']]['status']=='unsat'
        receipt=load(a.receipt,a.receipt_sha);assert receipt['passed'] and receipt['activeRequests']==0;cores={};refs={}
        for case in receipt['cases']:
            assert not case['rejected'] and case['cleanupConfirmed'] and case['rootExitConfirmed'];ref=case['result'];cores[case['id']]=load(ref['reportPath'],ref['reportSha256'])['result'];refs[case['id']]={'path':ref['reportPath'],'sha256':ref['reportSha256']}
        from kernel_image import BinaryImage
        data=held.enter_context(locked_file(Path(receipt['cases'][0]['args']['target']),4*1024**2));assert hashlib.sha256(data).hexdigest()==TARGET;image=BinaryImage.from_bytes(data)
        for c in cores.values():
            validate(c);assert c['targetSha256']==TARGET and set(c['registers'])==set(GPRS) and all(c[k] is False for k in ('nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'))
            assert all(image.read(int(r['ea'],16),r['decoded']['size']).hex()==r['bytes'] for r in c['decodedPath'])
        for name in ('context136-prefix10','context136-full22'):
            assert cores[name]==load(prior['reports'][name]['path'],prior['reports'][name]['sha256'])['result']
        replay={}
        for name,ref in (('entry',prior['reports']['entry17-status']),('literal',literal['reports']['literal-fast-dispatch22']),('137',p137['reports']['context137-fast28']),('25078',prior['reports']['public250-136-78'])):replay[name]=load(ref['path'],ref['sha256'])['result']
        q=Queries(MAIN,out/'queries',deadline)
        try:prove(a,out,cores,refs,incoming,prior,context,domain,image,replay,q,deadline)
        finally:q.close()

def prove(a,out,cores,refs,incoming,prior,context,domain,image,replay,q,deadline):
    def query(name,case,roots,wanted=None,*,cuts=None,extra='',predicate=None,status='unsat'):
        cuts=cuts or {};lines,actual,meta=encode(cores[case],roots,cuts=cuts);meta.update(sourceCase=case,rootNodes=roots,cutNames={str(i):n for i,n in cuts.items()})
        decl=[l for l in lines if l.startswith('(declare-')];defs=[l for l in lines if not l.startswith('(declare-')]
        return q.expect(q.query(name,'\n'.join(decl)+'\n'+extra+'\n'+'\n'.join(defs)+'\n(assert '+(different(actual,wanted) if wanted is not None else predicate(actual))+')',status,meta))
    r={n:'I_'+n for n in GPRS};local=[]
    for case,kind in (('context136-prefix10','prefix136'),('context136-full22','136'),('context0-check14','0'),('context0-fast26','fast0')):
        c=cores[case]
        if kind=='prefix136':lines,regs,m,target,writes=context_ordinary(136,False,r,'M0','Local');control=[target]
        elif kind=='fast0':
            lines,checked,M1,cc,w0=ordinary('0',r,'M0','Check');more,regs,m,control,w1=ordinary('dispatch',checked,M1,'Dispatch');lines+=more;writes=w0+w1
        else:lines,regs,m,control,writes=ordinary(kind,r,'M0','Local')
        roots=[c['registers'][n] for n in GPRS]+[c['currentMemory']]+[c['control'][k] for k in (('condition','taken','fallthrough') if len(control)==3 else ('target',))]
        wanted=[regs[n] for n in GPRS]+[m]+control
        for j,(s,w) in enumerate(zip(c['stores'],writes)):
            roots += [s[k] for k in ('address','value','beforeMemory','afterMemory')];wanted += w
            if kind=='fast0':roots.append(s['guard']);wanted.append(bv(1,8) if j==0 else cc[0])
        if kind=='fast0':
            roots.append(c['pathGuard']);wanted.append(cc[0]);e=c['sideExits'][0];assert len(c['sideExits'])==1
            roots += [e['registers'][n] for n in GPRS]+[e[k] for k in ('currentMemory','guard','target')];wanted += [checked[n] for n in GPRS]+[M1,flag(f'(= {cc[0]} {bv(0,8)})'),bv(0x140052162)]
        local.append(query(case+'-all16-whole-memory-writes-control-complement',case,roots,wanted,extra='\n'.join(lines)))
    public=cores['public208-136-0'];assert len(public['layers'])==5 and len(public['stores'])==6 and len(public['sideExits'])==4;layer_queries=[];partition_queries=[];exit_cursor=0
    for step,kind in enumerate(('208','dispatch','136','0','dispatch')):
        layer=public['layers'][step];b=public['boundaries'][step];cuts={layer['inputRegisters'][n]:'Q_'+n for n in GPRS};cuts[layer['inputMemory']]='Q_memory';g=bv(1,8) if step==0 else 'Q_guard'
        if step:cuts[layer['entryGuard']]=g
        decl='\n'.join(f'(declare-const Q_{n} (_ BitVec 64))' for n in GPRS)+f'\n(declare-const Q_memory {ARRAY})'+('' if step==0 else '\n(declare-const Q_guard (_ BitVec 8))')
        eq,regs,m,control,writes=ordinary(kind,{n:'Q_'+n for n in GPRS},'Q_memory','Layer')
        roots=[b['registers'][n] for n in GPRS]+[b['currentMemory'],b['entryGuard']]+[b['control'][k] for k in (('condition','taken','fallthrough') if len(control)==3 else ('target',))]
        wanted=[regs[n] for n in GPRS]+[m,g]+control
        for s,w in zip([s for s in public['stores'] if s['stepIndex']==step],writes):roots += [s[k] for k in ('address','value','beforeMemory','afterMemory','guard')];wanted += w+[g]
        if step<4:
            target=0x1400545b6 if step==1 else 0x140052281 if step==2 else None
            cond=f'(= {control[0]} {bv(target)})' if target else f'(distinct {control[0]} {bv(0,8)})'
            continued=flag(f'(and (distinct {g} {bv(0,8)}) {cond})');complement=flag(f'(and (distinct {g} {bv(0,8)}) (not {cond}))')
            e=public['sideExits'][exit_cursor];exit_cursor+=1;assert e['stepIndex']==step
            if target is None:
                roots += [e['registers'][n] for n in GPRS]+[e[k] for k in ('currentMemory','guard','target')];wanted += [regs[n] for n in GPRS]+[m,complement,control[2]]
        else:continued=g
        if step not in (1,2):roots.append(b['continuedGuard']);wanted.append(continued)
        layer_queries.append(query('public-layer-'+str(step)+'-complete-state-and-partition','public208-136-0',roots,wanted,cuts=cuts,extra=decl+'\n'+'\n'.join(eq)))
        if step in (1,2):
            pcuts={b['control']['target']:'T',layer['entryGuard']:'G',**{b['registers'][n]:'Z_'+n for n in GPRS},b['currentMemory']:'Z_memory'}
            pdecl='\n'.join(f'(declare-const Z_{n} (_ BitVec 64))' for n in GPRS)+f'\n(declare-const Z_memory {ARRAY})\n(declare-const T (_ BitVec 64))\n(declare-const G (_ BitVec 8))'
            proots=[b['continuedGuard'],e['guard'],e['target'],*[e['registers'][n] for n in GPRS],e['currentMemory']]
            pwanted=[flag(f'(and (distinct G {bv(0,8)}) (= T {bv(target)}))'),flag(f'(and (distinct G {bv(0,8)}) (distinct T {bv(target)}))'),'T',*[f'Z_{n}' for n in GPRS],'Z_memory']
            partition_queries.append(query('public-layer-'+str(step)+'-complete-complementary-target-partition','public208-136-0',proots,pwanted,cuts=pcuts,extra=pdecl))
    init=f'(declare-const S (_ BitVec 64))\n(declare-const F (_ BitVec 64))\n(assert (= F (bvand {sub("S",bv(648))} {bv(MASK-15)})))'
    starts=[sub('S',bv(8)),sub('F',bv(8)),add('F',bv(200))]
    bounds=q.expect(q.query('all-new-write-classes-in-original671-window',init+'\n(assert (or '+' '.join(f'(bvugt {sub(x,sub("S",bv(671)))} {bv(663)})' for x in starts)+'))'))
    oldslots=incoming['contextPreservation']['slots'];assert len(set(oldslots))==19 and 200 not in oldslots
    nonalias=init+'\n(declare-const i (_ BitVec 3))\n(declare-const j (_ BitVec 3))\n(assert (or '+' '.join(f'(= {add(add("F",bv(slot)),"((_ zero_extend 61) i)")} {add(add("F",bv(200)),"((_ zero_extend 61) j)")})' for slot in oldslots)+'))'
    disjoint=q.expect(q.query('new-context200-disjoint-from-all-prior19-words',nonalias))
    mem=init+f'\n(declare-const Before {ARRAY})\n(declare-const EntryRBP (_ BitVec 64))';m='Before';memory_queries=[]
    vals=['S',bv(0x1400545b6),'S',bv(0x140052281),'EntryRBP',bv(0x14005242b)];classes=[0,1,2,1,0,1]
    for step,(cls,value) in enumerate(zip(classes,vals),1):
        after='After'+str(step);mem+=f'\n(define-fun {after} () {ARRAY} {store(m,starts[cls],value,8)})';m=after
        if step in (4,6):memory_queries.append(q.expect(q.query('after-'+str(step)+'-writes-context200-and-virtual-word',mem+'\n(assert '+different([read(m,starts[2],8),read(m,starts[0],8)],['S','S' if step==4 else 'EntryRBP'])+')')))
    facts={int(x,16):v for x,v in incoming['initialImageByteFacts']};stages=[];joins=[];word_queries=[];negative=[]
    for kind,offset,index,selector,target in ((136,52,200,0,0x140052281),(0,54,120,78,0x14005242b)):
        wa=TABLE+4*selector;current={VIP+offset:image.read(VIP+offset,1)[0],VIP+offset+1:image.read(VIP+offset+1,1)[0],**{wa+i:b for i,b in enumerate(image.read(wa,4))}}
        assert current[VIP+offset]==index and current[VIP+offset+1]==selector and TABLE+int.from_bytes(image.read(wa,4),'little',signed=True)==target
        added={x:v for x,v in current.items() if x not in facts};reused={x:v for x,v in current.items() if x in facts};assert all(facts[x]==v for x,v in reused.items());facts.update(added)
        assert (len(facts),len(added),len(reused))==((82,6,0) if kind==136 else (84,2,4));stages.append({'handler':kind,'total':len(facts),'added':[[hex(x),v] for x,v in sorted(added.items())],'reused':[[hex(x),v] for x,v in sorted(reused.items())]})
        pointers=init+'\n(declare-const EntryRBP (_ BitVec 64))'+f'\n(assert (= I_rsp F))\n(assert (= I_rbp {sub("S",bv(8)) if kind==136 else "S"}))\n(assert (= I_rsi {bv(VIP+offset)}))\n(assert (= I_r11 {bv(TABLE)}))'
        word='S' if kind==136 else 'EntryRBP';source=sub('S',bv(8)) if kind==136 else add('F',bv(120));loaded=f'(assert (= {read("M0",source,8)} {word}))';indexed=f'(assert (= {read("M0","I_rsi",1)} {bv(index,8)}))'
        case='context136-prefix10' if kind==136 else 'context0-check14';c=cores[case];s=c['stores'][0]
        word_queries.append(query('joined'+str(kind)+'-original-source-word-equation',case,[s['value']],[word],extra=pointers+'\n'+loaded+'\n'+indexed))
        changes={'rsp':'F','rbp':'S' if kind==136 else sub('S',bv(8)),'rsi':bv(VIP+offset+1),'r11':bv(TABLE),'rbx':'S'} if kind==136 else {'rsp':'F','rbp':sub('S',bv(8)),'rsi':bv(VIP+offset+1),'r11':bv(TABLE),'rdx':bv(index),'r9':word,'r8':add('F',bv(384))}
        if kind==136:changes['rax']=bv(200)
        roots=[c['registers'][n] for n in GPRS]+[c['currentMemory']];wanted=[changes.get(n,'I_'+n) for n in GPRS]+[store('M0',add('F',bv(200)) if kind==136 else sub('S',bv(8)),word,8)]
        joins.append(query('joined'+str(kind)+'-prefix-all16-and-entire-memory',case,roots,wanted,cuts={s['value']:word},extra=pointers+'\n'+loaded+'\n'+indexed))
        negative.append(query('negative'+str(kind)+'-missing-source-word-can-change-value',case,[s['value']],predicate=lambda xs,w=word:f'(distinct {xs[0]} {w})',extra=pointers+'\n'+indexed,status='sat'))
        if kind==136:negative.append(query('negative136-missing-index-can-change-context-address',case,[s['address']],predicate=lambda xs:f'(distinct {xs[0]} {add("F",bv(200))})',extra=pointers+'\n'+loaded,status='sat'))
        case='context136-full22' if kind==136 else 'context0-fast26';c=cores[case];cut=c['stores'][1]['beforeMemory'];known=f'(declare-const DispatchMemory {ARRAY})\n'+'\n'.join(f'(assert (= (select DispatchMemory {bv(x)}) {bv(v,8)}))' for x,v in current.items() if x!=VIP+offset)
        changes.update(rax=bv(selector),r8=bv(target),rsi=bv(VIP+offset+2));roots=[c['registers'][n] for n in GPRS]+[c['currentMemory'],c['control']['target']];wanted=[changes.get(n,'I_'+n) for n in GPRS]+[store('DispatchMemory',sub('F',bv(8)),bv(target),8),bv(target)]
        fast=f'(bvugt {sub("S",bv(8))} {add("F",bv(384))})'
        if kind==0:roots.append(c['pathGuard']);wanted.append(bv(1,8))
        joins.append(query('joined'+str(kind)+'-full-all16-target-and-dispatch-memory',case,roots,wanted,cuts={cut:'DispatchMemory',c['stores'][0]['value']:word},extra=pointers+'\n'+loaded+'\n'+indexed+'\n'+known+f'\n(assert {fast})'))
        restored=store('M0',add('F',bv(200)) if kind==136 else sub('S',bv(8)),word,8)
        negative.append(query('negative'+str(kind)+'-missing-dispatch-bytes-can-change-target',case,[c['control']['target']],predicate=lambda xs,t=target:f'(distinct {xs[0]} {bv(t)})',cuts={cut:'DispatchMemory'},extra=f'(declare-const DispatchMemory {ARRAY})\n'+pointers+'\n'+loaded+'\n'+indexed+f'\n(assert (= S {bv(0x100000)}))\n(assert (= DispatchMemory {restored}))',status='sat'))
    c=cores['context0-check14'];pointers=init+f'\n(assert (= I_rsp F))\n(assert (= I_rbp S))';false_range=f'(and (bvuge S {bv(8)}) (bvult S {bv(264)}))'
    guard=query('context0-guard-false-exactly8-through263','context0-check14',[c['control']['condition']],[flag(f'(not {false_range})')],extra=pointers)
    implication=q.expect(q.query('old-fast-edge-implies-context0-fast-edge',init+f'\n(assert (not {false_range}))\n(assert (not (bvugt {sub("S",bv(8))} {add("F",bv(384))})))'))
    alias=query('negative0-read-after-stack-write-changes-aliasing-source','context0-check14',[c['stores'][0]['value']],predicate=lambda xs:f'(distinct {xs[0]} {read("AliasAfter",add("I_rsp",f"((_ zero_extend 56) {read('M0','I_rsi',1)})"),8)})',cuts={c['stores'][0]['afterMemory']:'AliasAfter'},extra=f'(declare-const AliasAfter {ARRAY})\n(assert (= AliasAfter {store("M0",sub("I_rbp",bv(8)),read("M0",add("I_rsp",f"((_ zero_extend 56) {read('M0','I_rsi',1)})"),8),8)}))\n(assert (= {sub("I_rbp",bv(8))} {add(add("I_rsp",f"((_ zero_extend 56) {read('M0','I_rsi',1)})"),bv(1))}))',status='sat');negative.append(alias)
    premises=init+f'\n(declare-const M0 {ARRAY})\n(assert (bvuge {sub(sub("S",bv(671)),bv(image.imagebase))} {bv(domain["image"]["bytes"])}))\n(assert (bvuge {sub(bv(image.imagebase),sub("S",bv(671)))} {bv(671)}))\n(assert (not {false_range}))'+'\n'+'\n'.join(f'(assert (= (select M0 {bv(x)}) {bv(v,8)}))' for x,v in facts.items())
    consistent=q.expect(q.query('all84-image-and-prior-fast-premises-consistent',premises,'sat'))
    numeric=numeric_checks(cores,facts,context,replay,deadline)
    result={'schema':'ig5-context200-and-context0-conditional-join-v1','passed':True,'sourceReceipt':{'path':a.receipt,'sha256':a.receipt_sha},'reports':refs,'incoming208Proof':{'path':a.incoming_proof,'sha256':a.incoming_sha},'queries':q.rows,'localStateQueries':local,'publicLayerQueries':layer_queries,'publicTargetPartitionQueries':partition_queries,'newWriteWindowQuery':bounds,'context200NonaliasQuery':disjoint,'orderedMemoryWordQueries':memory_queries,'originalSourceWordQueries':word_queries,'joinedStateQueries':joins,'guardFalseRangeQuery':guard,'priorFastImpliesCurrentFastQuery':implication,'negativeControls':negative,'premisesSatisfiableQuery':consistent,'initialImageByteFacts':[[hex(x),v] for x,v in sorted(facts.items())],'factStages':stages,'newContextSlot':200,'newContextValue':'original initial RSP S','restoredContext120Value':'original entry RBP, not current VM RBP S','nextSelector':78,'nextTarget':'0x14005242b','joinedGuardFalseInitialRSPRange':[8,263],
        'contextPreservation':{'priorSlots':oldslots,'newSlot':200,'readByteOffsets':list(range(8)),'writeByteOffsets':list(range(8)),'priorAny256SlotStackWriteNonaliasQuery':incoming['contextNonaliasQuery'],'singleBytePreservationQuery':context['lemmas']['bytePreservation'],'newContextBytePairInstantiations':19*8*8,'orderedWriteClasses':['S-8','F-8','F+200','F-8','S-8','F-8'],'allPrior19AndNew200PreservedAfterFinalStackWrite':True},
        'imagePreservation':{'windowBytes':671,'wordStartMax':663,'offsetWidthBridgeLemma':domain['window']['offsetWidthBridgeLemma'],'preservationLemma':domain['window']['preservationLemma'],'imageSeparationLemma':domain['window']['imageSeparationLemma'],'everyPrefixOfSixWritesPreservesAll84Facts':True},'context120SourceCertificate':next(x for x in context['contextMap'] if x['slotByteOffset']==120),'numeric':numeric,'sourceProofScriptSha256':sha(__file__),'encoderSourceSha256':sha(MAIN/'scripts/composition_domain_smt.py'),'auxiliarySources':{x:sha(MAIN/'scripts'/x) for x in AUXILIARY},'solverDllSha256':q.dll_sha,'limits':incoming['limits'],'publicCrossReportJoinIntegrated':False,'wholeChainUncutQueryPerformed':False,
        'scope':'Complete local equations and exact5-layer/all18 binding summaries, plus prior208 certified state and671-window/image/context byte induction connect76->82->84. Dispatch-memory cuts are original post-write memory. No single uncut whole-chain, CPU/native/exact3.8 or complete-business theorem.','nativeTargetExecuted':False,'databaseModified':False,'architectureProved':False,'nativeReachabilityProved':False,'businessAccepted':False,'wholeBinaryVerified':False}
    raw=(json.dumps(result,indent=2)+'\n').encode('utf8');assert len(raw)<=4*1024**2 and time.monotonic()<deadline
    with (out/'verified.json').open('xb') as f:f.write(raw)

def numeric_checks(cores,facts,context,replay,deadline):
    # Ordinary free-state comparisons of context0 use the independently derived
    # oracle already covering selector/source/destination overlap and uint64 wrap.
    from projection_numerical_oracle import expected
    rows=list(context0_cases());local=0
    for _,r,seed,overrides in rows:
        assert time.monotonic()<deadline;origin=total_byte(seed,overrides);want=expected(r,origin);c=cores['context0-check14'];v=projection_values(c,r,origin)
        assert {n:v[x] for n,x in c['registers'].items()}==want['registers'] and v[c['currentMemory']]==(origin,want['memoryWrites'])
        assert [v[c['control'][k]] for k in ('condition','taken','fallthrough')]==[want['control'][k] for k in ('condition','taken','fallthrough')];local+=1
    rng=random.Random(0x323030303738);stacks=[rng.getrandbits(64) for _ in range(128)]+list(range(672))+[(VIP-256+i*8)&MASK for i in range(64)]+[MASK-i for i in range(16)]
    counts={'joinedStates':len(stacks),'separated':0,'nonseparatedSkipped':0,'priorAlternateStopped':0,'reachedNext78':0}
    def byte_memory(pair):
        base,overlay=pair;return lambda addr:overlay.get(addr&MASK,base(addr&MASK))
    def run(c,r,m,u=None):
        v=projection_values(c,r,m,unknowns=u);return v,{n:v[i] for n,i in c['registers'].items()},byte_memory(v[c['currentMemory']])
    def word(m,a):return sum(m((a+i)&MASK)<<(8*i) for i in range(8))
    public=cores['public208-136-0']
    for S in stacks:
        assert time.monotonic()<deadline;L=(S-671)&MASK
        if ((L-0x140000000)&MASK)<1384448 or ((0x140000000-L)&MASK)<671:counts['nonseparatedSkipped']+=1;continue
        counts['separated']+=1;initial={n:rng.getrandbits(64) for n in GPRS};initial['rsp']=S;origin=total_byte(rng.getrandbits(64),facts);entry=replay['entry'];u={entry['dag']['nodes'][x['node']]['name']:rng.getrandbits(64) for x in entry['nondeterministicInputs']};v,r,m=run(entry,initial,origin,u);F=((S-648)&MASK)&(MASK-15)
        saved={x['slotByteOffset']:word(m,F+x['slotByteOffset']) for x in context['contextMap']};assert saved[120]==initial['rbp']
        v,r,m=run(replay['literal'],r,m)
        if not v[replay['literal']['pathGuard']]:counts['priorAlternateStopped']+=1;continue
        v,r,m=run(replay['137'],r,m);assert v[replay['137']['pathGuard']]==1
        c=replay['25078'];u={c['dag']['nodes'][x['node']]['name']:rng.getrandbits(64) for x in c['nondeterministicInputs']};v,r,m=run(c,r,m,u);assert v[c['pathGuard']]==1
        saved[176]=word(m,F+176);saved[192]=0;before=dict(r);prior=m;v,r,m=run(public,r,m)
        expected_regs={**before,'rax':78,'rsp':F,'rbp':(S-8)&MASK,'rsi':VIP+56,'rbx':S,'r8':0x14005242b,'rdx':120,'r9':initial['rbp']}
        assert r==expected_regs and v[public['pathGuard']]==1 and v[public['control']['target']]==0x14005242b
        writes=[((S-8)&MASK,S),((F-8)&MASK,0x1400545b6),((F+200)&MASK,S),((F-8)&MASK,0x140052281),((S-8)&MASK,initial['rbp']),((F-8)&MASK,0x14005242b)];overlay={}
        for s,(address,value) in zip(public['stores'],writes):
            assert v[s['address']]==address and v[s['value']]==value and v[s['guard']]==1;overlay.update({(address+i)&MASK:(value>>(8*i))&255 for i in range(8)})
        assert v[public['currentMemory']]==(prior,overlay) and all(v[e['guard']]==0 for e in public['sideExits'])
        assert all(word(m,F+slot)==value for slot,value in saved.items()) and word(m,F+200)==S and word(m,S-8)==initial['rbp'] and all(m(a)==value for a,value in facts.items());counts['reachedNext78']+=1
    return {'freeContext0States':local,**counts,'all16WholeMemorySixOrderedWritesFourComplementsAndAll20ContextWordsChecked':True,'independentEntry64And25059UnknownBitsVaried':True,'guardFalseNeverFedAsReachableNextState':True,'sameBatchAcrossDeploymentsNotAdditionalCoverage':True,'notIndependentCPUInterpreter':True,'notUniversalProof':True}

if __name__=='__main__':main()
