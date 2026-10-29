"""Independent bounded source/certificate readback; no solver or CPU replay."""
from pathlib import Path
import argparse,hashlib,json,re,sys
MAIN=Path(__file__).resolve().parents[1];sys.path[:0]=[str(MAIN/'worker'),str(MAIN/'scripts')]
from lift_runtime import locked_file
from composition_domain_smt import validate,GPRS
from kernel_image import BinaryImage

def load(path,pin=None,maximum=4*1024**2):
    path=Path(path);assert path.is_absolute() and '..' not in path.parts
    with locked_file(path,maximum) as raw:
        digest=hashlib.sha256(raw).hexdigest();assert pin is None or digest==pin;return json.loads(raw),digest

def verify(source):
    source=Path(source);v,digest=load(source);proc,_=load(source.parent/'process.json',maximum=65536)
    assert v['schema']=='ig5-handler208-relocation-conditional-proof-v1' and v['passed']
    assert proc['exitCode']==0 and proc['childExitConfirmed'] and proc['jobAssignedAtCreation'] and proc['activeProcessLimit']==1 and proc['memoryLimitBytes']==2147483648
    for key,file in (('sourceProofScriptSha256','prove_handler208_semantics.py'),('encoderSourceSha256','composition_domain_smt.py')):
        with locked_file(MAIN/'scripts'/file,1024**2) as raw:assert hashlib.sha256(raw).hexdigest()==v[key]
    receipts=[];cases={};cores={}
    for key in ('sourceReceipt','alternateReceipt'):
        r,_=load(v[key]['path'],v[key]['sha256']);assert r['passed'] and r['activeRequests']==0;receipts.append(r)
        for c in r['cases']:assert not c['rejected'] and c['cleanupConfirmed'] and c['rootExitConfirmed'] and c['spawnedRoots']==1;cases[c['id']]=c
    with locked_file(Path(receipts[0]['cases'][0]['args']['target']),4*1024**2) as raw:
        assert hashlib.sha256(raw).hexdigest()=='5f9c1b6fcb019366f835d8f02d9ec3b2957fe619e039410d07f288a9c73f63f0';image=BinaryImage.from_bytes(raw)
    for name,ref in v['reports'].items():
        c=cases[name];assert Path(c['result']['reportPath']).resolve()==Path(ref['path']).resolve() and c['result']['reportSha256']==ref['sha256']
        record,_=load(ref['path'],ref['sha256']);core=record['result'];validate(core);cores[name]=core
        assert set(core['registers'])==set(GPRS) and core['targetSha256']=='5f9c1b6fcb019366f835d8f02d9ec3b2957fe619e039410d07f288a9c73f63f0'
        assert all(image.read(int(r['ea'],16),r['decoded']['size']).hex()==r['bytes'] for r in core['decodedPath'])
        assert all(core[k] is False for k in ('nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'))
    assert len(cores)==7
    check=cores['context208-check12'];fast=cores['context208-fast24'];rel=cores['relocation-prefix29'];body=cores['relocation-body13'];alternate=cores['context208-alternate41'];flat=cores['relocation-loop32'];public=cores['context208-relocation32']
    assert len(check['projectionPath'])==12 and len(fast['projectionPath'])==24 and fast['projectionPath'][:12]==check['projectionPath']
    assert len(rel['projectionPath'])==29 and body['projectionPath']==rel['projectionPath'][16:] and alternate['projectionPath']==check['projectionPath']+rel['projectionPath']
    assert len(flat['stores'])==33 and len(flat['boundaries'])==33 and len(flat['sideExits'])==32
    repeat=flat['inferredRepeat'];assert repeat['bodyApplicationsAfterPrefix']==31 and repeat['attempts']==32 and not repeat['observedValuesUsed']
    assert len(repeat['trace'])==32 and all(x['conditionValue']==('0x1' if i<31 else '0x0') and x['willRepeat']==(i<31) for i,x in enumerate(repeat['trace']))
    assert flat['compositionPlan']['prefix']==rel['projectionPath'] and flat['compositionPlan']['body']==body['projectionPath'] and flat['compositionPlan']['suffix']==[["0x1400521d5",*fast['projectionPath'][12:]]]
    assert flat['statistics']['logicalInstructions']==445 and flat['statistics']['expandedMemoryBytes']==533
    assert len(public['layers'])==len(public['boundaries'])==34 and len(public['stores'])==34 and len(public['sideExits'])==33 and public['dag']['bindingCount']==612
    plan=public['compositionPlan']['paths'];assert plan==[check['projectionPath'],rel['projectionPath'],*[body['projectionPath'] for _ in range(31)],flat['compositionPlan']['suffix'][0]]
    for i,(l,b) in enumerate(zip(public['layers'],public['boundaries'])):
        previous={'registers':public['initialRegisters'],'currentMemory':public['initialMemory'],'pathGuard':l['entryGuard']} if i==0 else public['layers'][i-1]
        assert l['inputRegisters']==previous['registers'] and l['inputMemory']==previous['currentMemory'] and l['entryGuard']==previous['pathGuard']
        assert l['registers']==b['registers'] and l['currentMemory']==b['currentMemory'] and l['pathGuard']==b['continuedGuard']
        assert all(public['dag']['nodes'][n]['op']=='state_binding' for n in [*l['registers'].values(),l['currentMemory'],l['pathGuard']])
    rows=v['queries'];assert len(rows)==84 and len({r['name'] for r in rows})==84
    assert sum(r['status']=='unsat' for r in rows)==79 and sum(r['status']=='sat' for r in rows)==5
    for r in rows:
        assert r['status']==r['expected'] and 0<r['timeoutMs']<=2000 and r['encodedDepth']<=128 and r['encodedSexpressions']<=2048 and r['encodedAtomTokens']<=8192
        path=Path(r['path']);assert path.parent==source.parent/'queries'
        with locked_file(path,1024**2) as raw:
            assert hashlib.sha256(raw).hexdigest()==r['sha256'] and len(raw)==r['bytes'];text=raw.decode('ascii')
        assert text.startswith(f'(set-option :timeout {r["timeoutMs"]})\n(set-option :memory_max_size 512)\n') and text.endswith('\n(check-sat)\n')
        assert text.count('(')==r['encodedSexpressions'] and len(re.findall(r'[^\s()]+',text))==r['encodedAtomTokens']
        if 'sourceCase' in r:
            c=cores[r['sourceCase']];assert r['wholeSourceDagValidated'] and not r['weakenedLoadNodes'] and all(type(i) is int and 0<=i<len(c['dag']['nodes']) for i in r['rootNodes'])
            assert all(str(i) in r['cutNames'] for i in r['explicitCuts'])
    def unsat(index):assert rows[index]['status']=='unsat';return rows[index]
    assert len(v['uncutLocalQueries'])==5
    for index in v['uncutLocalQueries']:
        r=unsat(index);assert not r['explicitCuts'] and not r['cutNames'];c=cores[r['sourceCase']];assert r['rootNodes'][:17]==[*[c['registers'][n] for n in GPRS],c['currentMemory']]
    assert len(v['public34LayerQueries'])==34
    for step,index in enumerate(v['public34LayerQueries']):
        r=unsat(index);l=public['layers'][step];b=public['boundaries'][step];expected={str(l['inputRegisters'][n]):'Q_'+n for n in GPRS};expected[str(l['inputMemory'])]='Q_memory'
        if step:expected[str(l['entryGuard'])]='Q_guard'
        assert r['sourceCase']=='context208-relocation32' and r['cutNames']==expected and r['rootNodes'][:17]==[*[b['registers'][n] for n in GPRS],b['currentMemory']]
    assert not unsat(v['flatDestinationQuery'])['explicitCuts'] and len(v['flat32CopyQueries'])==32
    destination=flat['stores'][0]['address']
    for i,index in enumerate(v['flat32CopyQueries']):
        r=unsat(index);s=flat['stores'][i];previous=flat['initialMemory'] if i==0 else flat['stores'][i-1]['afterMemory'];assert s['beforeMemory']==previous
        assert r['sourceCase']=='relocation-loop32' and r['cutNames']=={str(previous):'CopyBefore',str(destination):'CopyDestination'}
        assert r['rootNodes'][:5]==[s[k] for k in ('address','value','beforeMemory','afterMemory','guard')]
        node=flat['dag']['nodes'][s['afterMemory']];assert node['op']=='store_le' and node['size']==8 and node['args']==[previous,s['address'],s['value']]
    tail=unsat(v['flatDispatchQuery']);assert flat['stores'][32]['beforeMemory']==flat['stores'][31]['afterMemory']
    assert tail['cutNames']=={str(flat['stores'][32]['beforeMemory']):'CopyDone',str(flat['stores'][31]['value']):'LastWord',str(destination):'CopyDestination'}
    for key in ('joinedGuardQuery','previousFastImpliesCurrentFastQuery','newWriteWindowQuery','contextNonaliasQuery','virtualStackWordQuery','joinedStateQuery'):unsat(v[key])
    for i in v['negativeControls']+v['bothLocalGuardSATQueries']+[v['premisesSatisfiableQuery']]:assert rows[i]['status']=='sat'
    assert len(v['negativeControls'])==2 and not rows[v['negativeControls'][1]]['explicitCuts']
    joined=rows[v['joinedStateQuery']];assert joined['cutNames']=={str(fast['stores'][1]['beforeMemory']):'DispatchMemory'} and fast['stores'][1]['beforeMemory']==fast['stores'][0]['afterMemory']
    incoming,_=load(v['incomingProof']['path'],v['incomingProof']['sha256']);audit,_=load(Path(v['incomingProof']['path']).parent/'independent-audit.json');assert incoming['passed'] and audit['passed'] and audit['proofSha256']==v['incomingProof']['sha256']
    prior={int(a,16):b for a,b in incoming['initialImageByteFacts']};facts={int(a,16):b for a,b in v['initialImageByteFacts']}
    added={int(a,16):b for a,b in v['addedInitialFacts']};reused={int(a,16):b for a,b in v['reusedInitialFacts']}
    assert len(prior)==75 and len(facts)==76 and len(added)==1 and len(reused)==4 and not set(prior)&set(added) and facts=={**prior,**added} and all(prior[a]==b for a,b in reused.items())
    assert all(image.read(a,1)[0]==b for a,b in facts.items()) and added=={0x1400846f7:136} and set(reused)==set(range(0x1400562b8,0x1400562bc))
    assert v['nextSelector']==136 and v['nextTarget']=='0x1400545b6' and v['joinedGuardFalseInitialRSPRange']==[8,263]
    cp=v['contextPreservation'];assert len(set(cp['slots']))==19 and cp['slots'][-2:]==[176,192] and cp['readByteOffsets']==cp['writeByteOffsets']==list(range(8)) and cp['bytePairInstantiations']==2432 and cp['orderedWriteAddresses']==['S-8','F-8']
    assert cp['all19PriorWordsPreserved'] and cp['unknownEntry64And25059BitsRemainFree']
    assert v['imagePreservation']['originalWindowBytes']==671 and v['imagePreservation']['wordStartMax']==663 and v['imagePreservation']['all76FactsPreservedAtEveryPrefix']
    assert v['numeric']['states']==448 and v['numeric']['reportEvaluations']==3136 and v['numeric']['fast']==113 and v['numeric']['alternate']==v['numeric']['fullRelocationPathGuardTrue']==335
    assert all(v[k] is False for k in ('publicCrossReportJoinIntegrated','nativeTargetExecuted','databaseModified','architectureProved','nativeReachabilityProved','businessAccepted','wholeBinaryVerified'))
    return {'schema':'ig5-handler208-independent-readback-v1','passed':True,'proofSha256':digest,'queries':84,'unsat':79,'sat':5,'unknown':0,'allQueryBytesBudgetsDagsRootsAndTypedCutsChecked':True,'all34ExactPublicLayersAndComplementsChecked':True,'all32CopySteps33MemoryLinksDestinationAndLastWordCutsChecked':True,'all76OriginalImageBytesAndOneAddedFourReusedChecked':True,'all19ContextFiniteByteInductionIndicesChecked':True,'numericStatesReadBack':448,'scope':'Independent certificate/data readback only; no solver, CPU, native reachability or complete business claim.','businessAccepted':False,'wholeBinaryVerified':False}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--proof',required=True);p.add_argument('--out',required=True);a=p.parse_args();result=verify(a.proof);out=Path(a.out);assert out.is_absolute()
    with out.open('x',encoding='utf8') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps(result))
