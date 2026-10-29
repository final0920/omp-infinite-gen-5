"""Independent certificate/original-data readback; no solver or CPU rerun."""
from pathlib import Path
import argparse,hashlib,json,re,sys
MAIN=Path(__file__).resolve().parents[1];sys.path[:0]=[str(MAIN/'worker'),str(MAIN/'scripts')]
from composition_domain_smt import validate,GPRS
from lift_runtime import locked_file
from kernel_image import BinaryImage

def load(path,pin=None,maximum=4*1024**2):
    assert Path(path).is_absolute() and '..' not in Path(path).parts
    with locked_file(Path(path),maximum) as raw:
        digest=hashlib.sha256(raw).hexdigest();assert pin is None or digest==pin;return json.loads(raw),digest

def verify(source):
    source=Path(source);assert source.is_absolute();proof,digest=load(source);process,_=load(source.parent/'process.json',maximum=65536)
    assert proof['schema']=='ig5-status-chain-ordinary-certificates-v1' and proof['passed']
    assert process['exitCode']==0 and process['childExitConfirmed'] and process['jobAssignedAtCreation'] and process['activeProcessLimit']==1 and process['memoryLimitBytes']==2147483648
    for key,file in (('sourceProofScriptSha256','prove_status_chain_semantics.py'),('encoderSourceSha256','composition_domain_smt.py')):
        with locked_file(MAIN/'scripts'/file,1024**2) as raw:assert hashlib.sha256(raw).hexdigest()==proof[key]
    receipt,_=load(proof['sourceReceipt']['path'],proof['sourceReceipt']['sha256']);assert receipt['passed']
    cores={}
    for name,ref in proof['reports'].items():
        record,_=load(ref['path'],ref['sha256']);core=record['result'];validate(core);cores[name]=core
        assert all(core[k] is False for k in ('nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'))
        if name!='local136':
            case=next(c for c in receipt['cases'] if c['id']==name);assert not case['rejected'] and case['cleanupConfirmed'] and case['rootExitConfirmed']
            assert Path(case['result']['reportPath']).resolve()==Path(ref['path']).resolve() and case['result']['reportSha256']==ref['sha256']
            assert len(core['layers'])==len(case['args']['composition_plan']['paths'])
            assert all(t['initialFlagsSupplied'] is False and t['flagsExported'] is False for t in core['templates'])
            assert core['dag']['bindingCount']==len(core['layers'])*18
            previous=core['initialMemory']
            for i,layer in enumerate(core['layers']):
                assert layer['stepIndex']==i and layer['inputMemory']==previous
                if i:
                    assert layer['inputRegisters']==core['layers'][i-1]['registers'] and layer['entryGuard']==core['layers'][i-1]['pathGuard']
                memory=layer['inputMemory']
                for s in (s for s in core['stores'] if s['stepIndex']==i):
                    assert s['beforeMemory']==memory and s['guard']==layer['entryGuard']
                    n=core['dag']['nodes'][s['afterMemory']];assert n['op']=='store_le' and n['args']==[memory,s['address'],s['value']];memory=s['afterMemory']
                binding=core['dag']['nodes'][layer['currentMemory']];assert binding['op']=='state_binding' and binding['source']==memory;previous=layer['currentMemory']
                if core['templateMode']=='opaque-status':
                    for x in layer['flagImages']:
                        s=next(s for s in core['stores'] if s['stepIndex']==i and s['instructionIndex']==x['instructionIndex']);assert s['value']==x['valueNode'] and s['pcodeIndex']==56
    assert len(cores)==6 and len(cores['local136']['projectionPath'])==22 and len(cores['local136']['stores'])==2
    target=Path(receipt['cases'][0]['args']['target'])
    with locked_file(target,4*1024**2) as raw:
        assert hashlib.sha256(raw).hexdigest()=='5f9c1b6fcb019366f835d8f02d9ec3b2957fe619e039410d07f288a9c73f63f0';image=BinaryImage.from_bytes(raw)
    for c in cores.values():assert all(image.read(int(r['ea'],16),r['decoded']['size']).hex()==r['bytes'] for r in c['decodedPath'])
    c=cores['status250-136'];nodes=c['dag']['nodes'];loads=nodes[c['stores'][1]['value']]['args'];flag=c['layers'][0]['flagImages'][0]['valueNode'];noise=c['nondeterministicInputs'][0]['node'];target_node=c['boundaries'][0]['control']['target']
    allowed={loads[0]:'A',loads[1]:'B',flag:'F',noise:'U',target_node:'T',**{c['layers'][0]['registers'][n]:'Q_'+n for n in GPRS},c['layers'][0]['currentMemory']:'Q_memory',c['layers'][0]['pathGuard']:'Q_guard'}
    rows=proof['queries'];assert len(rows)==10 and len({r['name'] for r in rows})==10
    for row in rows:
        assert row['status']==row['expected'] and row['status'] in ('unsat','sat') and 0<row['timeoutMs']<=2000
        assert row['encodedDepth']<=128 and row['encodedSexpressions']<=2048 and row['encodedAtomTokens']<=8192 and not row['weakenedLoadNodes'] and row['wholeSourceDagValidated']
        with locked_file(Path(row['path']),1024**2) as raw:
            assert len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256'];text=raw.decode('ascii')
        assert f'(set-option :timeout {row["timeoutMs"]})' in text and '(set-option :memory_max_size 512)' in text and text.endswith('(check-sat)\n')
        core=cores[row['sourceCase']];cut_names={int(i):name for i,name in row['cutNames'].items()}
        assert set(row['explicitCuts'])<=set(cut_names)
        expected=allowed if row['sourceCase']=='status250-136' else {cores['legacy250-136']['stores'][0]['value']:'U'} if row['sourceCase']=='legacy250-136' else {}
        for i,name in cut_names.items():
            assert expected.get(i)==name;n=core['dag']['nodes'][i]
            assert (n['type'],n.get('bits'))==('memory',None) if name=='Q_memory' else (n['type'],n.get('bits'))==('bv',8 if name=='Q_guard' else 64)
        assert all(type(i) is int and 0<=i<len(core['dag']['nodes']) for i in row['rootNodes'])
    for key in ('operandAddressQuery','wholeFlagImageEquationQuery','fullLayer0Query','fullLocal136Query','fullLayer1Query','guardComplementQuery'):assert rows[proof[key]]['status']=='unsat'
    for i in [*proof['unmodeledAFQueries'],proof['legacyLossQuery'],proof['postWriteReadCounterexampleQuery']]:assert rows[i]['status']=='sat'
    cut_row=rows[proof['fullLayer1Query']];cuts=set(int(i) for i in cut_row['cutNames']);work=list(cut_row['rootNodes']);seen=set()
    while work:
        i=work.pop()
        if i in seen or i in cuts:continue
        seen.add(i);n=nodes[i];assert n['op'] not in ('input','initial_memory','nondeterministic');work.extend(n['args']+([n['source']] if n['op']=='state_binding' else []))
    counter=rows[proof['postWriteReadCounterexampleQuery']]
    with locked_file(Path(counter['path']),1024**2) as raw:text=raw.decode('ascii')
    assert all('(assert (= '+name+' ' in text for name in ('A','B','F'))
    numeric=proof['numeric'];assert numeric['states']==2560 and len(numeric['cases'])==5 and numeric['sameBatchesAcrossDeploymentsNotExtraCoverage']
    for r in numeric['cases']:assert r['states']==512 and r['guardTrue']==128 and r['guardFalse']==384 and r['aliasAndWrapStates']==256 and r['all16GPRsWholeMemoryStoresBoundariesAndSideExitsCompared']
    assert all(proof[k] is False for k in ('wholeTwoHandlerUncutQueryPerformed','nativeReachabilityProved','entry250To136InitialByteFactJoinProved','nativeTargetExecuted','databaseModified','architectureProved','businessAccepted','wholeBinaryVerified'))
    return {'schema':'ig5-status-chain-certificate-readback-v1','passed':True,'proofSha256':digest,'queries':10,'statuses':{s:sum(r['status']==s for r in rows) for s in ('unsat','sat','unknown')},
        'allOriginalBytesAndTypedSourceCaseCutsChecked':True,'allQueryBytesOptionsBudgetsAndExpectedStatusesChecked':True,'exactStateBindingMemoryAndFlagImageRootsChecked':True,
        'secondStageUsesOnlyExactPreviousBindingsAndConstants':True,'postWriteCounterexampleRestoresAllCutDefinitions':True,'numericStatesReadBack':2560,
        'scope':'Independent certificate/data readback only; no new SMT or CPU evaluation. Component UNSATs and exact binding induction, not one uncut whole-chain proof; no entry-byte conditional join or protected business claim.',
        'businessAccepted':False,'wholeBinaryVerified':False}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--proof',required=True);p.add_argument('--out',required=True);a=p.parse_args();out=Path(a.out);assert out.is_absolute();result=verify(a.proof)
    with out.open('x',encoding='utf8') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps(result))
