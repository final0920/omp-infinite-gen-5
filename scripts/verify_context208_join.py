"""Independent source/query/certificate readback, no solver or CPU replay."""
from pathlib import Path
import argparse,hashlib,json,re,sys
MAIN=Path(__file__).resolve().parents[1];sys.path[:0]=[str(MAIN/'worker'),str(MAIN/'scripts')]
from lift_runtime import locked_file
from composition_domain_smt import validate,GPRS
from kernel_image import BinaryImage
from verify_context200_join import verify as verify_incoming

def load(path,pin=None,maximum=4*1024**2):
    path=Path(path);assert path.is_absolute() and '..' not in path.parts
    with locked_file(path,maximum) as raw:
        digest=hashlib.sha256(raw).hexdigest();assert pin is None or digest==pin;return json.loads(raw),digest

def verify(source):
    source=Path(source);v,digest=load(source);proc,_=load(source.parent/'process.json',maximum=65536)
    assert v['schema']=='ig5-context208-and137-conditional-join-v1' and v['passed'] and proc['exitCode']==0 and proc['childExitConfirmed'] and proc['jobAssignedAtCreation'] and proc['activeProcessLimit']==1 and proc['memoryLimitBytes']==2147483648
    for field,file in (('sourceProofScriptSha256','prove_context208_join.py'),('encoderSourceSha256','composition_domain_smt.py')):
        with locked_file(MAIN/'scripts'/file,1024**2) as raw:assert hashlib.sha256(raw).hexdigest()==v[field]
    assert set(v['auxiliarySources'])=={'prove_context_write_join.py','prove_context200_join.py','prove_handler208_semantics.py','projection_numerical_oracle.py'}
    for file,pin in v['auxiliarySources'].items():
        with locked_file(MAIN/'scripts'/file,1024**2) as raw:assert hashlib.sha256(raw).hexdigest()==pin
    incoming,_=load(v['incoming200Proof']['path'],v['incoming200Proof']['sha256']);ar=verify_incoming(v['incoming200Proof']['path']);assert ar['passed'] and ar['proofSha256']==v['incoming200Proof']['sha256']
    receipt,_=load(v['sourceReceipt']['path'],v['sourceReceipt']['sha256']);assert receipt['passed'] and receipt['activeRequests']==0
    with locked_file(Path(receipt['cases'][0]['args']['target']),4*1024**2) as raw:
        assert hashlib.sha256(raw).hexdigest()=='5f9c1b6fcb019366f835d8f02d9ec3b2957fe619e039410d07f288a9c73f63f0';image=BinaryImage.from_bytes(raw)
    cores={}
    for name,ref in v['reports'].items():
        c=next(c for c in receipt['cases'] if c['id']==name);assert not c['rejected'] and c['cleanupConfirmed'] and c['rootExitConfirmed'] and c['spawnedRoots']==1 and c['result']['reportSha256']==ref['sha256'] and Path(c['result']['reportPath']).resolve()==Path(ref['path']).resolve()
        record,_=load(ref['path'],ref['sha256']);core=record['result'];validate(core);cores[name]=core
        assert set(core['registers'])==set(GPRS) and core['targetSha256']=='5f9c1b6fcb019366f835d8f02d9ec3b2957fe619e039410d07f288a9c73f63f0'
        assert all(image.read(int(r['ea'],16),r['decoded']['size']).hex()==r['bytes'] for r in core['decodedPath']) and all(core[k] is False for k in ('nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'))
    assert len(cores)==5 and len(v['reusedFreeStateCertificates'])==4
    expected={'context78-prefix15':[2],'context78-full27':[3],'context137-check16':[0],'context137-fast28':[1,2,3]}
    reused=0
    for c in v['reusedFreeStateCertificates']:
        name=c['case'];assert c['queries']==expected[name] and c['entireFreshCoreEqual'] and c['notNewQueriesOrCoverage']
        p,_=load(c['priorProof']['path'],c['priorProof']['sha256']);audit,_=load(Path(c['priorProof']['path']).parent/'independent-audit.json');assert p['passed'] and audit['passed'] and audit['proofSha256']==c['priorProof']['sha256'] and p['reports'][name]==c['priorReport']
        rec,_=load(c['priorReport']['path'],c['priorReport']['sha256']);assert rec['result']==cores[name]
        if name.startswith('context78-'):assert any(r['case']==name and r['query']==c['queries'][0] for r in p['localStateCertificates'])
        else:assert [r['query'] for r in p['localSummaryCertificates']]==[0,1,2,3]
        for i in c['queries']:
            row=p['queries'][i];assert row['status']=='unsat' and not row['explicitCuts'] and row['wholeSourceDagValidated'] and row['timeoutMs']<=2000
            with locked_file(Path(row['path']),1024**2) as raw:assert hashlib.sha256(raw).hexdigest()==row['sha256']
            reused+=1
    assert reused==6
    prefix=cores['context78-prefix15'];full=cores['context78-full27'];check=cores['context137-check16'];fast=cores['context137-fast28'];public=cores['public78-137']
    assert len(prefix['projectionPath'])==15 and len(full['projectionPath'])==27 and prefix['projectionPath']==full['projectionPath'][:15] and len(check['projectionPath'])==16 and len(fast['projectionPath'])==28 and check['projectionPath']==fast['projectionPath'][:16] and full['projectionPath'][-12:]==fast['projectionPath'][-12:]
    assert len(public['layers'])==3 and public['dag']['bindingCount']==54 and len(public['stores'])==4 and len(public['sideExits'])==2 and public['compositionPlan']['paths']==[full['projectionPath'],check['projectionPath'],full['projectionPath'][-12:]]
    for step,(l,b) in enumerate(zip(public['layers'],public['boundaries'])):
        prev={'registers':public['initialRegisters'],'currentMemory':public['initialMemory'],'pathGuard':l['entryGuard']} if step==0 else public['layers'][step-1]
        assert l['inputRegisters']==prev['registers'] and l['inputMemory']==prev['currentMemory'] and l['entryGuard']==prev['pathGuard'] and l['registers']==b['registers'] and l['currentMemory']==b['currentMemory'] and l['pathGuard']==b['continuedGuard']
        assert all(public['dag']['nodes'][n]['op']=='state_binding' for n in [*l['registers'].values(),l['currentMemory'],l['pathGuard']])
    rows=v['queries'];assert len(rows)==22 and len({r['name'] for r in rows})==22 and sum(r['status']=='unsat' for r in rows)==16 and sum(r['status']=='sat' for r in rows)==6;texts={}
    for i,r in enumerate(rows):
        assert r['status']==r['expected'] and r['status'] in ('unsat','sat') and 0<r['timeoutMs']<=2000 and r['encodedDepth']<=128 and r['encodedSexpressions']<=2048 and r['encodedAtomTokens']<=8192
        assert Path(r['path']).parent==source.parent/'queries'
        with locked_file(Path(r['path']),1024**2) as raw:assert len(raw)==r['bytes'] and hashlib.sha256(raw).hexdigest()==r['sha256'];text=raw.decode('ascii')
        assert text.startswith(f'(set-option :timeout {r["timeoutMs"]})\n(set-option :memory_max_size 512)\n') and text.endswith('\n(check-sat)\n') and text.count('(')==r['encodedSexpressions'] and len(re.findall(r'[^\s()]+',text))==r['encodedAtomTokens'];texts[i]=text
        if 'sourceCase' in r:
            c=cores[r['sourceCase']];assert r['wholeSourceDagValidated'] and not r['weakenedLoadNodes'] and all(type(j) is int and 0<=j<len(c['dag']['nodes']) for j in r['rootNodes'])
    def unsat(i):assert rows[i]['status']=='unsat';return rows[i]
    assert len(v['publicLayerQueries'])==3
    for step,i in enumerate(v['publicLayerQueries']):
        r=unsat(i);l=public['layers'][step];b=public['boundaries'][step];cuts={str(l['inputRegisters'][n]):'Q_'+n for n in GPRS};cuts[str(l['inputMemory'])]='Q_memory'
        if step:cuts[str(l['entryGuard'])]='Q_guard'
        assert r['sourceCase']=='public78-137' and r['cutNames']==cuts and r['rootNodes'][:17]==[*[b['registers'][n] for n in GPRS],b['currentMemory']]
    assert len(v['publicTargetPartitionQueries'])==1;b=public['boundaries'][0];r=unsat(v['publicTargetPartitionQueries'][0]);assert r['cutNames']=={str(b['control']['target']):'T',**{str(b['registers'][n]):'Z_'+n for n in GPRS},str(b['currentMemory']):'Z_memory'}
    assert len(v['originalSourceWordQueries'])==2 and len(v['joinedStateQueries'])==4
    for i,name in zip(v['originalSourceWordQueries'],('context78-prefix15','context137-check16')):
        r=unsat(i);assert not r['explicitCuts'] and not r['cutNames'] and r['sourceCase']==name and r['rootNodes']==[cores[name]['stores'][0]['value']]
    for i,name,word in zip(v['joinedStateQueries'],('context78-prefix15','context78-full27','context137-check16','context137-fast28'),('EntryRBP','EntryRBP','EntryRSI','EntryRSI')):
        r=unsat(i);c=cores[name];cuts={str(c['stores'][0]['value']):word}
        if len(c['stores'])==2:assert c['stores'][1]['beforeMemory']==c['stores'][0]['afterMemory'];cuts[str(c['stores'][1]['beforeMemory'])]='DispatchMemory'
        assert r['sourceCase']==name and r['cutNames']==cuts
    for key in ('newWriteWindowQuery','newContext208NonaliasQuery','guardFalseRangeQuery','priorFastImpliesCurrentFastQuery'):unsat(v[key])
    assert len(v['orderedMemoryWordQueries'])==2
    for i in v['orderedMemoryWordQueries']:unsat(i)
    assert len(v['negativeControls'])==5
    for i in v['negativeControls']+[v['premisesSatisfiableQuery']]:assert rows[i]['status']=='sat'
    for i in v['negativeControls']:
        r=rows[i]
        if 'missing-dispatch-bytes' in r['name']:
            c=cores[r['sourceCase']];assert r['cutNames']=={str(c['stores'][1]['beforeMemory']):'DispatchMemory'} and '(assert (= DispatchMemory (store ' in texts[i] and '(assert (= S (_ bv1048576 64)))' in texts[i]
        else:assert not r['explicitCuts']
    facts={int(a,16):b for a,b in incoming['initialImageByteFacts']};assert len(facts)==84
    for stage,(kind,total) in zip(v['factStages'],((78,86),(137,88))):
        assert stage['handler']==kind and stage['total']==total and len(stage['added'])==2 and len(stage['reused'])==4
        for a,b in stage['reused']:assert facts[int(a,16)]==b
        for a,b in stage['added']:assert int(a,16) not in facts;facts[int(a,16)]=b
        assert len(facts)==total
    assert len(v['factStages'])==2 and facts=={int(a,16):b for a,b in v['initialImageByteFacts']} and all(image.read(a,1)[0]==b for a,b in facts.items())
    assert [facts[0x1400846c4+i] for i in range(56,60)]==[208,137,144,136] and v['nextSelector']==136 and v['nextTarget']=='0x1400545b6'
    cp=v['contextPreservation'];assert cp['priorSlots']==incoming['contextPreservation']['priorSlots']+[200] and len(set(cp['priorSlots']))==20 and 208 not in cp['priorSlots'] and cp['newSlot']==208 and cp['readByteOffsets']==cp['writeByteOffsets']==list(range(8)) and cp['bytePairInstances']==1280 and cp['all21WordsPreservedAfterFinalStackWrite']
    assert v['context144SourceCertificate']['slotByteOffset']==144 and v['context144SourceCertificate']['valueLabel']=='rsi' and v['newContextSlot']==208 and v['newContextValue']=='original entry RBP' and v['finalVirtualWord']=='original entry RSI' and v['joinedGuardFalseInitialRSPRange']==[8,263]
    assert v['imagePreservation']['windowBytes']==671 and v['imagePreservation']['wordStartMax']==663 and v['imagePreservation']['all88FactsPreservedAtEveryPrefix']
    for key in ('offsetWidthBridgeLemma','preservationLemma','imageSeparationLemma'):assert v['imagePreservation'][key]==incoming['imagePreservation'][key]
    n=v['numeric'];assert (n['states'],n['separated'],n['nonseparatedSkipped'],n['priorAlternateStopped'],n['reachedNext136'])==(880,816,64,256,560)
    assert all(v[k] is False for k in ('publicCrossReportJoinIntegrated','wholeChainUncutQueryPerformed','nativeTargetExecuted','databaseModified','architectureProved','nativeReachabilityProved','businessAccepted','wholeBinaryVerified'))
    return {'schema':'ig5-context208-conditional-independent-readback-v1','passed':True,'proofSha256':digest,'newQueries':22,'unsat':16,'sat':6,'unknown':0,'reusedUncutQueries':6,'reusedFourWholeCoresIdentical':True,'allQueryBytesBudgetsDagsRootsAndCertifiedCutsChecked':True,'all3Layers54Bindings4Writes2ComplementsChecked':True,'bothSATMemoryCutsRestored':True,'all88OriginalImageBytes84to86to88Checked':True,'context208EntryRBPAndContext144EntryRSIWith21WordInductionChecked':True,'scope':'Certificate/data readback only; reused equations not new coverage. No solver/CPU/native/fullbusiness theorem.','businessAccepted':False,'wholeBinaryVerified':False}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--proof',required=True);p.add_argument('--out',required=True);a=p.parse_args();result=verify(a.proof);out=Path(a.out);assert out.is_absolute()
    with out.open('x',encoding='utf8') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps(result))
