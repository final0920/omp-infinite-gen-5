"""Independent certificate/source readback; no solver or target replay."""
from pathlib import Path
import argparse,hashlib,json,re,sys
MAIN=Path(__file__).resolve().parents[1];sys.path[:0]=[str(MAIN/'worker'),str(MAIN/'scripts')]
from lift_runtime import locked_file
from composition_domain_smt import validate,GPRS
from kernel_image import BinaryImage
from verify_handler208_semantics import verify as verify_incoming

def load(path,pin=None,maximum=4*1024**2):
    path=Path(path);assert path.is_absolute() and '..' not in path.parts
    with locked_file(path,maximum) as raw:
        digest=hashlib.sha256(raw).hexdigest();assert pin is None or digest==pin;return json.loads(raw),digest

def verify(source):
    source=Path(source);v,digest=load(source);proc,_=load(source.parent/'process.json',maximum=65536)
    assert v['schema']=='ig5-context200-and-context0-conditional-join-v1' and v['passed']
    assert proc['exitCode']==0 and proc['childExitConfirmed'] and proc['jobAssignedAtCreation'] and proc['activeProcessLimit']==1 and proc['memoryLimitBytes']==2147483648
    for key,file in (('sourceProofScriptSha256','prove_context200_join.py'),('encoderSourceSha256','composition_domain_smt.py')):
        with locked_file(MAIN/'scripts'/file,1024**2) as raw:assert hashlib.sha256(raw).hexdigest()==v[key]
    assert set(v['auxiliarySources'])=={'prove_context_write_join.py','prove_handler208_semantics.py','projection_numerical_oracle.py'}
    for name,pin in v['auxiliarySources'].items():
        with locked_file(MAIN/'scripts'/name,1024**2) as raw:assert hashlib.sha256(raw).hexdigest()==pin
    incoming,_=load(v['incoming208Proof']['path'],v['incoming208Proof']['sha256']);ia=verify_incoming(v['incoming208Proof']['path']);assert ia['passed'] and ia['proofSha256']==v['incoming208Proof']['sha256']
    receipt,_=load(v['sourceReceipt']['path'],v['sourceReceipt']['sha256']);assert receipt['passed'] and receipt['activeRequests']==0;cores={}
    with locked_file(Path(receipt['cases'][0]['args']['target']),4*1024**2) as raw:
        assert hashlib.sha256(raw).hexdigest()=='5f9c1b6fcb019366f835d8f02d9ec3b2957fe619e039410d07f288a9c73f63f0';image=BinaryImage.from_bytes(raw)
    for name,ref in v['reports'].items():
        c=next(x for x in receipt['cases'] if x['id']==name);assert not c['rejected'] and c['cleanupConfirmed'] and c['rootExitConfirmed'] and c['spawnedRoots']==1
        assert Path(c['result']['reportPath']).resolve()==Path(ref['path']).resolve() and c['result']['reportSha256']==ref['sha256'];record,_=load(ref['path'],ref['sha256']);core=record['result'];validate(core);cores[name]=core
        assert set(core['registers'])==set(GPRS)
        assert core['targetSha256']=='5f9c1b6fcb019366f835d8f02d9ec3b2957fe619e039410d07f288a9c73f63f0'
        assert all(image.read(int(r['ea'],16),r['decoded']['size']).hex()==r['bytes'] for r in core['decodedPath']) and all(core[k] is False for k in ('nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'))
    assert len(cores)==5;prefix=cores['context136-prefix10'];full=cores['context136-full22'];check=cores['context0-check14'];fast=cores['context0-fast26'];public=cores['public208-136-0']
    assert len(prefix['projectionPath'])==10 and len(full['projectionPath'])==22 and prefix['projectionPath']==full['projectionPath'][:10]
    assert len(check['projectionPath'])==14 and len(fast['projectionPath'])==26 and fast['projectionPath'][:14]==check['projectionPath'] and fast['projectionPath'][-12:]==full['projectionPath'][-12:]
    assert check['projectionPath'][0]=='0x140052281' and check['decodedPath'][1]['decoded']['mnemonic']=='BSR' and check['stores'][0]['instructionIndex']==7
    assert len(public['layers'])==5 and public['dag']['bindingCount']==90 and len(public['stores'])==6 and len(public['sideExits'])==4
    assert public['compositionPlan']['paths'][2]==full['projectionPath'] and public['compositionPlan']['paths'][3]==check['projectionPath']
    for step,(layer,b) in enumerate(zip(public['layers'],public['boundaries'])):
        prev={'registers':public['initialRegisters'],'currentMemory':public['initialMemory'],'pathGuard':layer['entryGuard']} if step==0 else public['layers'][step-1]
        assert layer['inputRegisters']==prev['registers'] and layer['inputMemory']==prev['currentMemory'] and layer['entryGuard']==prev['pathGuard']
        assert layer['registers']==b['registers'] and layer['currentMemory']==b['currentMemory'] and layer['pathGuard']==b['continuedGuard']
        assert all(public['dag']['nodes'][n]['op']=='state_binding' for n in [*layer['registers'].values(),layer['currentMemory'],layer['pathGuard']])
    rows=v['queries'];assert len(rows)==30 and len({r['name'] for r in rows})==30 and sum(r['status']=='unsat' for r in rows)==23 and sum(r['status']=='sat' for r in rows)==7;texts={}
    for i,r in enumerate(rows):
        assert r['status']==r['expected'] and r['status'] in ('sat','unsat') and 0<r['timeoutMs']<=2000 and r['encodedDepth']<=128 and r['encodedSexpressions']<=2048 and r['encodedAtomTokens']<=8192
        path=Path(r['path']);assert path.parent==source.parent/'queries'
        with locked_file(path,1024**2) as raw:assert hashlib.sha256(raw).hexdigest()==r['sha256'] and len(raw)==r['bytes'];text=raw.decode('ascii')
        assert text.startswith(f'(set-option :timeout {r["timeoutMs"]})\n(set-option :memory_max_size 512)\n') and text.endswith('\n(check-sat)\n') and text.count('(')==r['encodedSexpressions'] and len(re.findall(r'[^\s()]+',text))==r['encodedAtomTokens'];texts[i]=text
        if 'sourceCase' in r:
            c=cores[r['sourceCase']];assert r['wholeSourceDagValidated'] and not r['weakenedLoadNodes'] and all(type(j) is int and 0<=j<len(c['dag']['nodes']) for j in r['rootNodes'])
    def unsat(i):assert rows[i]['status']=='unsat';return rows[i]
    assert len(v['localStateQueries'])==4
    for i in v['localStateQueries']:
        r=unsat(i);c=cores[r['sourceCase']];assert not r['explicitCuts'] and not r['cutNames'] and r['rootNodes'][:17]==[*[c['registers'][n] for n in GPRS],c['currentMemory']]
    assert len(v['publicLayerQueries'])==5
    for step,i in enumerate(v['publicLayerQueries']):
        r=unsat(i);l=public['layers'][step];b=public['boundaries'][step];cuts={str(l['inputRegisters'][n]):'Q_'+n for n in GPRS};cuts[str(l['inputMemory'])]='Q_memory'
        if step:cuts[str(l['entryGuard'])]='Q_guard'
        assert r['sourceCase']=='public208-136-0' and r['cutNames']==cuts and r['rootNodes'][:17]==[*[b['registers'][n] for n in GPRS],b['currentMemory']]
    assert len(v['publicTargetPartitionQueries'])==2
    for step,i in zip((1,2),v['publicTargetPartitionQueries']):
        r=unsat(i);l=public['layers'][step];b=public['boundaries'][step];cuts={str(b['control']['target']):'T',str(l['entryGuard']):'G',**{str(b['registers'][n]):'Z_'+n for n in GPRS},str(b['currentMemory']):'Z_memory'}
        assert r['cutNames']==cuts and r['sourceCase']=='public208-136-0'
    assert len(v['originalSourceWordQueries'])==2 and len(v['joinedStateQueries'])==4
    for index,case in zip(v['originalSourceWordQueries'],('context136-prefix10','context0-check14')):
        r=unsat(index);assert r['sourceCase']==case and not r['explicitCuts'] and r['rootNodes']==[cores[case]['stores'][0]['value']]
    for index,case,word in zip(v['joinedStateQueries'],('context136-prefix10','context136-full22','context0-check14','context0-fast26'),('S','S','EntryRBP','EntryRBP')):
        r=unsat(index);c=cores[case];cuts={str(c['stores'][0]['value']):word}
        if len(c['stores'])==2:
            assert c['stores'][1]['beforeMemory']==c['stores'][0]['afterMemory'];cuts[str(c['stores'][1]['beforeMemory'])]='DispatchMemory'
        assert r['sourceCase']==case and r['cutNames']==cuts
    for key in ('newWriteWindowQuery','context200NonaliasQuery','guardFalseRangeQuery','priorFastImpliesCurrentFastQuery'):unsat(v[key])
    assert len(v['orderedMemoryWordQueries'])==2
    for i in v['orderedMemoryWordQueries']:unsat(i)
    assert len(v['negativeControls'])==6
    for i in v['negativeControls']+[v['premisesSatisfiableQuery']]:assert rows[i]['status']=='sat'
    for i in v['negativeControls']:
        r=rows[i]
        if 'missing-dispatch-bytes' in r['name']:
            c=cores[r['sourceCase']];assert r['cutNames']=={str(c['stores'][1]['beforeMemory']):'DispatchMemory'} and '(assert (= DispatchMemory (store ' in texts[i] and '(assert (= S (_ bv1048576 64)))' in texts[i]
        else:assert not r['explicitCuts']
    priorfacts={int(a,16):b for a,b in incoming['initialImageByteFacts']};facts=dict(priorfacts);assert len(facts)==76 and len(v['factStages'])==2
    for stage,(kind,count,added,reused) in zip(v['factStages'],((136,82,6,0),(0,84,2,4))):
        assert (stage['handler'],stage['total'],len(stage['added']),len(stage['reused']))==(kind,count,added,reused)
        for a,b in stage['reused']:assert facts[int(a,16)]==b
        for a,b in stage['added']:assert int(a,16) not in facts;facts[int(a,16)]=b
        assert len(facts)==count
    assert facts=={int(a,16):b for a,b in v['initialImageByteFacts']} and all(image.read(a,1)[0]==b for a,b in facts.items())
    assert facts[0x1400846f8]==200 and facts[0x1400846f9]==0 and facts[0x1400846fa]==120 and facts[0x1400846fb]==78 and v['nextSelector']==78 and v['nextTarget']=='0x14005242b'
    cp=v['contextPreservation'];assert cp['priorSlots']==incoming['contextPreservation']['slots'] and len(set(cp['priorSlots']))==19 and 200 not in cp['priorSlots'] and cp['newSlot']==200 and cp['readByteOffsets']==cp['writeByteOffsets']==list(range(8)) and cp['newContextBytePairInstantiations']==1216
    assert cp['priorAny256SlotStackWriteNonaliasQuery']==incoming['contextNonaliasQuery'] and incoming['queries'][cp['priorAny256SlotStackWriteNonaliasQuery']]['status']=='unsat'
    assert cp['allPrior19AndNew200PreservedAfterFinalStackWrite'] and v['newContextSlot']==200 and v['context120SourceCertificate']['valueLabel']=='rbp' and v['context120SourceCertificate']['slotByteOffset']==120
    for key in ('offsetWidthBridgeLemma','preservationLemma','imageSeparationLemma'):assert v['imagePreservation'][key]==incoming['imagePreservation'][key]
    assert v['imagePreservation']['windowBytes']==671 and v['imagePreservation']['wordStartMax']==663 and v['imagePreservation']['everyPrefixOfSixWritesPreservesAll84Facts']
    n=v['numeric'];assert n['freeContext0States']==1004 and (n['joinedStates'],n['separated'],n['nonseparatedSkipped'],n['priorAlternateStopped'],n['reachedNext78'])==(880,816,64,256,560)
    assert all(v[k] is False for k in ('publicCrossReportJoinIntegrated','wholeChainUncutQueryPerformed','nativeTargetExecuted','databaseModified','architectureProved','nativeReachabilityProved','businessAccepted','wholeBinaryVerified'))
    return {'schema':'ig5-context200-conditional-independent-readback-v1','passed':True,'proofSha256':digest,'queries':30,'unsat':23,'sat':7,'unknown':0,'allQueryBytesBudgetsWholeDagsAndTypedCutsChecked':True,'all5ExactLayers90Bindings6Writes4ComplementsChecked':True,'originalSourceWordCutsSeparatelyCertified':True,'dispatchSATCutsRestoredToOriginalStore':True,'all84OriginalImageBytes76to82to84Checked':True,'context200AndEntryRBPContext120SourceAnd20WordInductionChecked':True,'scope':'Certificate and data readback only. No new solver/CPU/native reachability/fullbusiness proof.','businessAccepted':False,'wholeBinaryVerified':False}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--proof',required=True);p.add_argument('--out',required=True);a=p.parse_args();result=verify(a.proof);out=Path(a.out);assert out.is_absolute()
    with out.open('x',encoding='utf8') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps(result))
