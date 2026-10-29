"""Independent certificate/data readback for the fixed owned VM ADD proof."""
from pathlib import Path
import argparse,hashlib,json,re,sys
MAIN=Path(__file__).resolve().parents[1];sys.path[:0]=[str(MAIN/'worker')]
from kernel_image import BinaryImage
from lift_runtime import locked_file


def load(path,pin=None,maximum=4*1024**2):
    with locked_file(Path(path),maximum) as raw:
        digest=hashlib.sha256(raw).hexdigest();assert pin is None or digest==pin
        return json.loads(raw),digest


def main():
    p=argparse.ArgumentParser();p.add_argument('--proof',required=True);p.add_argument('--out',required=True);a=p.parse_args();source=Path(a.proof);out=Path(a.out);assert source.is_absolute() and out.is_absolute()
    proof,digest=load(source);process,_=load(source.parent/'process.json',maximum=65536)
    assert proof['schema']=='ig5-handler250-status-conditional-proof-v1' and proof['passed']
    assert process['exitCode']==0 and process['childExitConfirmed'] and process['jobAssignedAtCreation'] and process['activeProcessLimit']==1 and process['memoryLimitBytes']==2147483648
    for key,file in (('sourceProofScriptSha256','prove_handler250_semantics.py'),('encoderSourceSha256','composition_domain_smt.py')):
        with locked_file(MAIN/'scripts'/file,1024**2) as raw:assert hashlib.sha256(raw).hexdigest()==proof[key]
    receipt,_=load(proof['sourceReceipt']['path'],proof['sourceReceipt']['sha256']);incoming,_=load(proof['incoming137Proof']['path'],proof['incoming137Proof']['sha256'])
    audit,_=load(Path(proof['incoming137Proof']['path']).parent/'independent-audit.json');assert audit['passed'] and audit['proofSha256']==proof['incoming137Proof']['sha256']
    assert incoming['passed'] and incoming['encoderSourceSha256']==proof['encoderSourceSha256'] and incoming['nextTarget']=='0x140055f66'
    cores={}
    for name,ref in proof['reports'].items():
        case=next(c for c in receipt['cases'] if c['id']==name);assert not case['rejected'] and case['cleanupConfirmed'] and case['rootExitConfirmed']
        assert case['result']['reportPath']==ref['path'] and case['result']['reportSha256']==ref['sha256']
        record,_=load(ref['path'],ref['sha256']);cores[name]=record['result']
    prefix=cores['status-prefix15'];full=cores['status-dispatch27'];old=cores['legacy-opaque27']
    assert len(prefix['projectionPath'])==15 and len(full['projectionPath'])==27 and prefix['projectionPath']==full['projectionPath'][:15]
    assert old['projectionPath']==full['projectionPath'] and full['projectionPath'][0]=='0x140055f66'
    target=Path(receipt['cases'][0]['args']['target'])
    with locked_file(target,4*1024**2) as raw:
        assert hashlib.sha256(raw).hexdigest()=='5f9c1b6fcb019366f835d8f02d9ec3b2957fe619e039410d07f288a9c73f63f0';image=BinaryImage.from_bytes(raw)
    cuts={};image_nodes={}
    for name,c in cores.items():
        assert len(c['registers'])==16 and all(c[k] is False for k in ('nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'))
        assert all(image.read(int(r['ea'],16),r['decoded']['size']).hex()==r['bytes'] for r in c['decodedPath'])
        nodes=c['dag']['nodes'];previous=c['initialMemory'];assert len(c['stores'])==(3 if name=='status-prefix15' else 4)
        for store in c['stores']:
            n=nodes[store['afterMemory']];assert store['size']==8 and store['beforeMemory']==previous and n['op']=='store_le' and n['size']==8
            assert n['args']==[previous,store['address'],store['value']];previous=store['afterMemory']
        assert previous==c['currentMemory']
        total=nodes[c['stores'][1]['value']];assert total['op']=='INT_ADD' and total['bits']==64
        for i in total['args']:
            n=nodes[i];assert n['op']=='load_le' and n['bits']==64 and n['size']==8 and n['args'][0]==c['initialMemory']
        noise=c['nondeterministicInputs'][0]['node'];assert len(c['nondeterministicInputs'])==1 and nodes[noise]['op']=='nondeterministic' and nodes[noise]['bits']==64
        e=c['opaqueEffects'][0];assert len(c['opaqueEffects'])==1 and e['source']=='0x140055f82' and e['instructionIndex']==7 and c['stores'][0]['pcodeIndex']==56
        assert e['conservativeSuperset'] and not e['architectureProved'] and not e['observedValuesUsed']
        allowed=set(total['args'])|{noise}
        if name!='legacy-opaque27':
            f=e['flagImageRefinement'];assert e['unknownBits']==f['effectiveUnknownBits']==59 and f['freshInputBits']==64
            assert f['knownMask']=='0x8c5' and f['unknownMask']=='0xfffffffffffff73a' and f['valueNode']==c['stores'][0]['value']==c['registers']['r10']
            assert f['knownFlags']==[{'name':n,'bit':b,'definitionInstructionIndex':4} for n,b in [('cf',0),('pf',2),('zf',6),('sf',7),('of',11)]]
            assert 'af' in c['flagPolicies'][4]['unmodeled'] and e['replacementOperationCount']==24 and c['stores'][0]['replacementPcodeIndex']==23
            allowed.add(f['valueNode']);image_nodes[name]=f['valueNode']
        else:assert e['unknownBits']==64 and 'flagImageRefinement' not in e and e['replacementOperationCount']==3
        if name=='status-dispatch27':allowed.add(c['stores'][-1]['beforeMemory'])
        cuts[name]=allowed
    rows=proof['queries'];assert len(rows)==22 and len({r['name'] for r in rows})==22
    for i,r in enumerate(rows):
        assert r['status']==r['expected'] and r['status'] in ('unsat','sat') or i==proof['wholeFlagImageEquationQuery'] and r['status']=='unknown'
        assert 0<r['timeoutMs']<=2000 and r['bytes']<=1024**2 and r['encodedDepth']<=128 and not r.get('weakenedLoadNodes')
        if r.get('sourceNodes'):
            assert r['wholeSourceDagValidated'] and r['sourceCase'] in cores
            c=cores[r['sourceCase']];assert set(r.get('explicitCuts',[]))<=cuts[r['sourceCase']]
            for index in r.get('explicitCuts',[]):
                node=c['dag']['nodes'][index]
                if r['sourceCase']=='status-dispatch27' and index==c['stores'][-1]['beforeMemory']:assert node['type']=='memory'
                else:assert node['type']=='bv' and node['bits']==64
        else:assert not r.get('explicitCuts')
        file=Path(r['path']);assert file.parent==source.parent/'queries'
        with locked_file(file,1024**2) as raw:
            assert len(raw)==r['bytes'] and hashlib.sha256(raw).hexdigest()==r['sha256'];text=raw.decode('ascii')
        assert text.count('(')==r['encodedSexpressions']<=2048 and len(re.findall(r'[^\s()]+',text))==r['encodedAtomTokens']<=8192
        assert text.startswith(f'(set-option :timeout {r["timeoutMs"]})\n(set-option :memory_max_size 512)\n') and text.endswith('\n(check-sat)\n')
    def unsat(i):assert rows[i]['status']=='unsat'
    assert list(proof['knownFlagBitQueries'])==['cf','pf','zf','sf','of']
    for i in proof['knownFlagBitQueries'].values():unsat(i)
    for k in ('originalOperandLoadAddressQuery','unknownRegionEqualityQuery','wholeImageMaskPartitionQuery','joinedKnownStatus44Query','newWriteWindowQuery','incomingVirtualOperandsZeroQuery','nextTargetQuery','joinedStateQuery'):unsat(proof[k])
    assert len(proof['localStateCertificates'])==2
    for c in proof['localStateCertificates']:
        unsat(c['query']);assert c['imageCutBoundToSeparateBitAndUnknownRegionProofs'] and c['all16GPRsEntireMemoryOrderedWritesAndControl']
    for i in proof['negativeControls']+proof['unmodeledAFBothSATQueries']+[proof['premisesSatisfiableQuery']]:assert rows[i]['status']=='sat'
    assert proof['nextTargetMemoryCut']==full['stores'][-1]['beforeMemory']==full['stores'][-2]['afterMemory']
    previous={int(a,16):v for a,v in incoming['initialImageByteFacts']};extra={int(a,16):v for a,v in proof['additionalInitialByteFacts']};reused={int(a,16):v for a,v in proof['reusedTargetTableByteFacts']}
    facts={int(a,16):v for a,v in proof['initialImageByteFacts']};assert len(previous)==66 and len(extra)==1 and len(reused)==4 and not set(previous)&set(extra)
    assert all(previous[a]==v for a,v in reused.items()) and facts==previous|extra and len(facts)==67
    assert all(image.read(a,1)[0]==v for a,v in facts.items())
    target_facts={int(a,16):v for a,v in proof['nextTargetCurrentImageByteFacts']};assert target_facts==extra|reused
    table=image.imagebase+0x56098;vip=image.imagebase+0x846c4;selector=facts[vip+46]
    next_target=(table+int.from_bytes(bytes(target_facts[table+4*selector+i] for i in range(4)),'little',signed=True))&((1<<64)-1)
    assert proof['nextSelector']==selector==136 and proof['nextTarget']==hex(next_target)=='0x1400545b6'
    assert proof['knownStatusMask']=='0x8c5' and proof['effectiveUnknownFlagBits']==59 and proof['unmodeledAFRemainsUnknown'] and not proof['publicCrossReportJoinIntegrated']
    assert all(proof[k] is False for k in ('nativeTargetExecuted','databaseModified','architectureProved','businessAccepted','wholeBinaryVerified'))
    result={'schema':'ig5-handler250-certificate-readback-v1','passed':True,'proofSha256':digest,'queries':22,'statuses':{s:sum(q['status']==s for q in rows) for s in ('unsat','sat','unknown')},
        'allQueryBytesLimitsStatusesAndTypedCutsChecked':True,'allOriginalOperandLoadsStoreChainsAndFreshNoiseChecked':True,'all16GPRAndWholeMemoryCertificateRootsChecked':True,
        'fiveBitPlusUnknownRegionAndPartitionCertificatesChecked':True,'all67InitialBytesReRead':True,'fourExistingTableFactsReusedWithoutDoubleCounting':True,
        'unmodeledAFFreeBothSAT':True,'legacyPrecisionLossSAT':True,'nextSelector':136,'nextTarget':hex(next_target),'effectiveUnknownFlagBits':59,
        'scope':'Independent certificate/original-data readback only; no new solver run, independent CPU interpreter or added numeric coverage.','businessAccepted':False,'wholeBinaryVerified':False}
    with out.open('x',encoding='utf8') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps(result))


if __name__=='__main__':main()
