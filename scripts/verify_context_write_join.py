"""Independent hash/type/binding/induction readback, without SMT or CPU rerun."""
from pathlib import Path
import argparse,hashlib,json,sys
MAIN=Path(__file__).resolve().parents[1];sys.path[:0]=[str(MAIN/'worker'),str(MAIN/'scripts')]
from composition_domain_smt import validate,GPRS
from lift_runtime import locked_file
from kernel_image import BinaryImage

def load(path,pin=None,maximum=4*1024**2):
    path=Path(path);assert path.is_absolute() and '..' not in path.parts
    with locked_file(path,maximum) as raw:
        digest=hashlib.sha256(raw).hexdigest();assert pin is None or pin==digest
        return json.loads(raw),digest

def check_queries(proof):
    for row in proof['queries']:
        assert row['status'] in ('unsat','sat','unknown') and 0<row['timeoutMs']<=2000
        assert row['encodedDepth']<=128 and row['encodedSexpressions']<=2048 and row['encodedAtomTokens']<=8192
        with locked_file(Path(row['path']),1024**2) as raw:
            assert len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256'];text=raw.decode('ascii')
        assert f'(set-option :timeout {row["timeoutMs"]})' in text and '(set-option :memory_max_size 512)' in text and text.endswith('(check-sat)\n')

def certificate(ref,audit=True):
    proof,_=load(ref['path'],ref['sha256']);process,_=load(Path(ref['path']).parent/'process.json',maximum=65536)
    assert proof['passed'] and process['exitCode']==0 and process['childExitConfirmed'] and process['jobAssignedAtCreation']
    assert process['activeProcessLimit']==1 and process['memoryLimitBytes']==2147483648
    if audit:
        reader,_=load(Path(ref['path']).parent/'independent-audit.json');assert reader['passed'] and reader['proofSha256']==ref['sha256']
    with locked_file(MAIN/'scripts/composition_domain_smt.py',1024**2) as raw:assert hashlib.sha256(raw).hexdigest()==proof['encoderSourceSha256']
    check_queries(proof);return proof

def verify(source):
    source=Path(source);proof,digest=load(source);process,_=load(source.parent/'process.json',maximum=65536)
    assert proof['schema']=='ig5-context-write-conditional-join-v1' and proof['passed']
    assert process['exitCode']==0 and process['childExitConfirmed'] and process['jobAssignedAtCreation'] and process['activeProcessLimit']==1 and process['memoryLimitBytes']==2147483648
    for key,file in (('sourceProofScriptSha256','prove_context_write_join.py'),('encoderSourceSha256','composition_domain_smt.py')):
        with locked_file(MAIN/'scripts'/file,1024**2) as raw:assert hashlib.sha256(raw).hexdigest()==proof[key]
    incoming=certificate(proof['incoming250Proof']);chain=certificate(proof['incomingChainProof']);prior137=certificate(incoming['incoming137Proof'])
    context=certificate(prior137['incomingContextProof'],False);literal=certificate(prior137['incomingLiteralProof'],False);domain=certificate(context['incomingDomainProof'])
    assert all(q['status']==q['expected'] for q in incoming['queries']+chain['queries']+context['queries']+literal['queries'])
    assert all(domain['queries'][domain['window'][k]]['status']=='unsat' for k in ('offsetWidthBridgeLemma','preservationLemma','imageSeparationLemma'))
    assert prior137['queries'][prior137['contextWordNonaliasQuery']]['status']=='unsat' and context['queries'][context['lemmas']['bytePreservation']]['status']=='unsat'
    receipt,_=load(proof['sourceReceipt']['path'],proof['sourceReceipt']['sha256']);assert receipt['passed'] and receipt['activeRequests']==0
    assert receipt['allStartedRootsExited'] and receipt['allStartedRootsCleanupACKs'];cores={}
    for name,ref in proof['reports'].items():
        case=next(c for c in receipt['cases'] if c['id']==name);assert not case['rejected'] and case['cleanupConfirmed'] and case['rootExitConfirmed'] and case['spawnedRoots']==1
        assert Path(case['result']['reportPath']).resolve()==Path(ref['path']).resolve() and case['result']['reportSha256']==ref['sha256']
        record,_=load(ref['path'],ref['sha256']);c=record['result'];validate(c);cores[name]=c
        assert all(c[k] is False for k in ('nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'))
        if case['args']['level']=='project':assert c['projectionPath']==case['args']['projection_path'];continue
        assert c['dag']['bindingCount']==len(c['layers'])*18 and all(t['initialFlagsSupplied'] is False and t['flagsExported'] is False for t in c['templates'])
        memory=c['initialMemory'];registers=c['initialRegisters']
        for i,layer in enumerate(c['layers']):
            assert layer['stepIndex']==i and layer['inputMemory']==memory and layer['inputRegisters']==registers
            if i:assert layer['entryGuard']==c['layers'][i-1]['pathGuard']
            for s in [s for s in c['stores'] if s['stepIndex']==i]:
                assert s['beforeMemory']==memory
                n=c['dag']['nodes'][s['afterMemory']];assert n['op']=='store_le' and n['args']==[memory,s['address'],s['value']];memory=s['afterMemory']
            n=c['dag']['nodes'][layer['currentMemory']];assert n['op']=='state_binding' and n['source']==memory
            memory=layer['currentMemory'];registers=layer['registers']
            for row in layer['flagImages']:
                s=next(s for s in c['stores'] if s['stepIndex']==i and s['instructionIndex']==row['instructionIndex']);assert s['value']==row['valueNode']
    assert len(cores)==7 and len(receipt['cases'])==8
    refused=next(c for c in receipt['cases'] if c['id']=='combined-entry-refused');assert refused['rejected'] and refused['spawnedRoots']==0 and '128' in refused['error']
    target=Path(receipt['cases'][0]['args']['target'])
    with locked_file(target,4*1024**2) as raw:
        assert hashlib.sha256(raw).hexdigest()=='5f9c1b6fcb019366f835d8f02d9ec3b2957fe619e039410d07f288a9c73f63f0';image=BinaryImage.from_bytes(raw)
    for c in cores.values():assert all(image.read(int(r['ea'],16),r['decoded']['size']).hex()==r['bytes'] for r in c['decodedPath'])
    eq=proof['entryOrdinaryEquivalence'];old,_=load(eq['sourceReport']['path'],eq['sourceReport']['sha256']);entry=cores[eq['newCase']]
    assert old['result']['dag']['nodes']==entry['dag']['nodes'] and all(old['result'][k]==entry[k] for k in eq['semanticFieldsEqual'])
    assert set(eq['semanticFieldsEqual'])=={'initialRegisters','initialMemory','registers','currentMemory','pathGuard','stores','sideExits','boundaries','control','steps','nondeterministicInputs'}
    refinement=entry['templates'][0]['opaqueEffects'][0]['flagImageRefinement'];assert refinement['knownMask']==eq['entryKnownMask']=='0x0' and refinement['effectiveUnknownBits']==eq['entryEffectiveUnknownBits']==64 and not refinement['knownFlags']
    prefix=proof['reused250Prefix'];old,_=load(chain['reports'][prefix['oldCase']]['path'],chain['reports'][prefix['oldCase']]['sha256']);c=cores[prefix['case']]
    assert prefix['nodeEndExclusive']==103 and c['dag']['nodes'][:103]==old['result']['dag']['nodes'][:103] and c['layers'][0]==old['result']['layers'][0] and c['boundaries'][0]==old['result']['boundaries'][0]
    for key in ('fullLayerQuery','wholeImageEquationQuery'):assert chain['queries'][prefix[key]]['status']=='unsat'
    rows=proof['queries'];assert len(rows)==22 and len({r['name'] for r in rows})==22;check_queries(proof)
    for row in rows:
        assert row['status']==row['expected'] and row['status'] in ('sat','unsat')
        if 'sourceCase' not in row:continue
        core=cores[row['sourceCase']];cuts={int(i):n for i,n in row['cutNames'].items()};allowed={}
        if row['name'].startswith('public'):
            if row['name']=='public136-complete-target-partition-and-complementary-state':
                b=c['boundaries'][1];allowed={b['control']['target']:'T',c['layers'][1]['entryGuard']:'G',**{b['registers'][n]:'Z_'+n for n in GPRS},b['currentMemory']:'Z_memory'}
            else:
                step=1 if row['name'].startswith('public136') else 2;l=c['layers'][step]
                allowed={l['inputRegisters'][n]:'Q_'+n for n in GPRS};allowed.update({l['inputMemory']:'Q_memory',l['entryGuard']:'Q_guard'})
        elif cuts:allowed={core['stores'][-1]['beforeMemory']:'M_dispatch'}
        assert cuts==allowed and set(row['explicitCuts'])<=set(cuts) and row['wholeSourceDagValidated'] and not row['weakenedLoadNodes']
        for i,name in cuts.items():
            node=core['dag']['nodes'][i];assert (node['type'],node.get('bits'))==(('memory',None) if name in ('M_dispatch','Q_memory','Z_memory') else ('bv',8 if name in ('G','Q_guard') else 64))
        assert all(type(i) is int and 0<=i<len(core['dag']['nodes']) for i in row['rootNodes'])
    for field in ('publicLayerQueries','orderedMemoryWordQueries','joinedStateQueries'):assert all(rows[i]['status']=='unsat' for i in proof[field])
    assert all(rows[x['query']]['status']=='unsat' for x in proof['localStateCertificates']) and len(proof['localStateCertificates'])==4
    assert all(rows[proof[k]]['status']=='unsat' for k in ('writeWindowQuery','newContextByteNonaliasQuery'))
    assert len(proof['negativeControls'])==5 and all(rows[i]['status']=='sat' for i in proof['negativeControls']) and rows[proof['premisesSatisfiableQuery']]['status']=='sat'
    for row in proof['localStateCertificates']:
        core=cores[row['case']];r=rows[row['query']];assert r['rootNodes'][:18]==[*[core['registers'][n] for n in GPRS],core['currentMemory'],core['control']['target']] and not r['cutNames']
    cert=proof['contextPreservationCertificate'];slots=[x['slotByteOffset'] for x in context['contextMap']]
    assert cert['slots']==slots and len(slots)==17 and 176 not in slots and 192 not in slots
    assert cert['readByteOffsets']==cert['writeByteOffsets']==list(range(8)) and cert['writeClasses']==['F-8','S-8','S-16','F+176','F+192'] and cert['orderedWriteClassIndices']==[0,1,2,0,3,0,4,0]
    assert cert['bytePairInstantiations']==8704 and cert['priorThreeClassNonaliasQuery']==prior137['contextWordNonaliasQuery'] and cert['singleBytePreservationQuery']==context['lemmas']['bytePreservation'] and cert['newTwoClassNonaliasQuery']==proof['newContextByteNonaliasQuery'] and cert['all17PriorWordsPreserved'] and cert['noNodeIdInequalityUsed']
    ip=proof['imagePreservationCertificate'];assert ip['windowBytes']==671 and ip['wordStartMax']==663 and ip['allFiveStartsQuery']==proof['writeWindowQuery']
    assert all(ip[k]==domain['window'][k] for k in ('offsetWidthBridgeLemma','preservationLemma','imageSeparationLemma'))
    facts={int(x,16):v for x,v in incoming['initialImageByteFacts']};assert len(facts)==67
    for stage,count,added,reused in zip(proof['factStages'],(69,75),(2,6),(4,0)):
        new={int(x,16):v for x,v in stage['added']};old={int(x,16):v for x,v in stage['reused']};current={int(x,16):v for x,v in stage['current']}
        assert len(new)==added and len(old)==reused and not set(new)&set(facts) and all(facts[x]==v for x,v in old.items()) and current=={**new,**old}
        facts.update(new);assert stage['total']==len(facts)==count
        assert all(image.read(x,1)[0]==v for x,v in current.items())
    assert proof['initialImageByteFacts']==[[hex(x),v] for x,v in sorted(facts.items())] and proof['nextSelector']==208 and proof['nextTarget']=='0x1400556d4'
    numeric=proof['numeric'];assert {k:numeric[k] for k in ('states','separatedEntry','nonseparatedSkipped','literalAlternate','reachedFullChain')}=={'states':1264,'separatedEntry':1200,'nonseparatedSkipped':64,'literalAlternate':256,'reachedFullChain':944}
    assert numeric['initialImageByteFacts']==75 and numeric['guardFalseNeverUsedAsNextInput'] and numeric['sameBatchesAcrossDeploymentsNotExtraCoverage']
    assert all(proof[k] is False for k in ('publicCrossReportJoinIntegrated','wholeChainUncutQueryPerformed','nativeTargetExecuted','databaseModified','architectureProved','nativeReachabilityProved','businessAccepted','wholeBinaryVerified'))
    return {'schema':'ig5-context-write-join-independent-readback-v1','passed':True,'proofSha256':digest,'queries':22,'statuses':{s:sum(r['status']==s for r in rows) for s in ('unsat','sat','unknown')},'typedCaseSpecificCutsAndCompleteSourceDagsChecked':True,'allQueryBytesOptionsAndProcessBudgetsChecked':True,'exact18StateBindingsAndOrderedMemoryLinksChecked':True,'entryAnd250PrefixSourceEquivalenceChecked':True,'all75InitialFactsAndFinite17WordInductionChecked':True,'priorUnknownQueriesNotUsedAsProof':True,'numericStatesReadBack':1264,'scope':'Certificate/data readback; no new SMT/CPU evaluation, no uncut whole-chain or protected-business theorem.','businessAccepted':False,'wholeBinaryVerified':False}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--proof',required=True);p.add_argument('--out',required=True);a=p.parse_args();out=Path(a.out);assert out.is_absolute();result=verify(a.proof)
    with out.open('x',encoding='utf8') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps(result))
