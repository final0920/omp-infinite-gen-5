"""Independent receipt/link checks and numeric controls using only25 byte facts.

Numeric checks supplement, and do not replace, the symbolic universal lemmas.
The numeric DAG evaluator is not an independent CPU interpreter.
"""
from pathlib import Path
import argparse,hashlib,json,random,re,sys
MAIN=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(MAIN/'worker'),str(MAIN/'scripts')]
from kernel_image import BinaryImage
from lift_runtime import locked_file
from projection_numerical_oracle import MASK,NAMES,projection_values,total_byte

def sha(path):
    with locked_file(Path(path),4*1024**2) as raw:return hashlib.sha256(raw).hexdigest()
def load(path,pin=None):
    with locked_file(Path(path),4*1024**2) as raw:
        digest=hashlib.sha256(raw).hexdigest();assert pin is None or digest==pin
        return json.loads(raw),digest

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--proof',required=True);parser.add_argument('--out',required=True);args=parser.parse_args()
    proof_path=Path(args.proof);out=Path(args.out);assert proof_path.is_absolute() and out.is_absolute()
    proof,digest=load(proof_path);process,_=load(proof_path.parent/'process.json')
    assert proof['passed'] and process['exitCode']==0 and process['childExitConfirmed'] and process['jobAssignedAtCreation']
    assert process['activeProcessLimit']==1 and process['memoryLimitBytes']==2*1024**3
    assert sha(MAIN/'scripts/prove_entry_chain_domain.py')==proof['sourceProofScriptSha256']
    assert sha(MAIN/'scripts/composition_domain_smt.py')==proof['encoderSourceSha256']
    receipt,_=load(proof['sourceReceipt']['path'],proof['sourceReceipt']['sha256'])
    assert proof['schema']=='ig5-entry-chain-conditional-domain-proof-v2' and proof['caseId'] in ('entry-plus16','entry-plus17')
    applications=17 if proof['caseId']=='entry-plus16' else 18;writes=21+2*(applications-1)
    assert proof['applications']==applications and proof['passedContinuations']==applications-1 and proof['orderedStoreCount']==writes
    case=next(c for c in receipt['cases'] if c['id']==proof['caseId']);record,_=load(proof['sourceReport']['path'],proof['sourceReport']['sha256'])
    assert proof['sourceReport']['sha256']==case['result']['reportSha256'];core=record['result'];nodes=core['dag']['nodes']
    target=Path(case['args']['target']);assert sha(target)==proof['targetSha256']==core['targetSha256']
    image=BinaryImage.from_file(target);base=image.imagebase;size=proof['image']['bytes'];assert base==int(proof['image']['base'],16)
    rows=proof['queries'];assert len(rows)<=128 and len({r['name'] for r in rows})==len(rows)
    for row in rows:
        assert row['status']==row['expected'] and row['status'] in ('sat','unsat') or row['name']==f'all{writes}-write-starts-in671-window' and row['status']=='unknown'
        assert 0<row['timeoutMs']<=2000 and row['bytes']<=1024**2 and row['encodedDepth']<=128
        file=Path(row['path']);assert file.parent==proof_path.parent/'queries'
        with locked_file(file,1024**2) as raw:
            assert len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256'];text=raw.decode('ascii')
        assert text.count('(')==row['encodedSexpressions']<=2048
        assert len(re.findall(r'[^\s()]+',text))==row['encodedAtomTokens']<=8192
        assert f'(set-option :timeout {row["timeoutMs"]})' in text and '(set-option :memory_max_size 512)' in text
    def unsat(i,name=None):
        assert rows[i]['status']=='unsat' and (name is None or rows[i]['name']==name)
        return i
    for certificate in proof['certificates']:
        for i in certificate.get('queries',[certificate.get('query')]):unsat(i)
    window=proof['window'];bridge=unsat(window['offsetWidthBridgeLemma'],'bounded64-offset-equals-zero-extended10-bit-offset')
    preserve=unsat(window['preservationLemma'],'any-outside-byte-survives-any-window-word-byte')
    separate=unsat(window['imageSeparationLemma'],'image-region-outside-circular-stack-window')
    assert (window['bytes'],window['wordStartMax'])==(671,663)
    links=proof['allOrderedMemoryLinks'];assert len(links)==len(core['stores'])==writes and len(core['layers'])==applications
    previous=core['initialMemory'];link_index=0;prior_counts=[]
    for step,layer in enumerate(core['layers']):
        assert layer['inputMemory']==previous
        layer_stores=[s for s in core['stores'] if s['stepIndex']==step];assert len(layer_stores)==(21 if step==0 else 2)
        for s in layer_stores:
            assert links[link_index]=={k:s[k] for k in links[link_index]} and s['guard']==layer['entryGuard']
            n=nodes[s['afterMemory']];assert n['op']=='store_le' and n['size']==s['size']==8 and n['args']==[previous,s['address'],s['value']]
            previous=s['afterMemory'];link_index+=1
        prior_counts.append(link_index-1)
        b=nodes[layer['currentMemory']];assert b['op']=='state_binding' and b['source']==previous
        previous=layer['currentMemory']
    assert link_index==writes and previous==core['currentMemory'] and len(core['sideExits'])==applications-1
    facts={int(a,16):v for a,v in proof['initialImageByteFacts']};assert len(facts)==len(proof['initialImageByteFacts'])==(25 if applications==17 else 30)
    assert all(base<=a<base+size and image.read(a,1)[0]==v for a,v in facts.items())
    all_targets=[];derived_facts={}
    assert len(proof['targetCertificates'])==applications
    for step,c in enumerate(proof['targetCertificates']):
        s=[s for s in core['stores'] if s['stepIndex']==step][-1]
        assert c['stepIndex']==step and c['targetNode']==core['boundaries'][step]['control']['target']
        assert c['currentMemoryNode']==s['beforeMemory'] and c['priorStoreCount']==prior_counts[step]==20+2*step
        assert c['derivedImageBytesFrom']==[bridge,preserve,separate] and c['allPriorMemoryLinksPreserveBytes']
        cuts=[s['beforeMemory']]
        for key in ('identityQuery','conditionalQuery'):
            i=unsat(c[key]);assert rows[i]['explicitCuts']==cuts and not rows[i]['weakenedLoadNodes']
        vip=base+0x846c4;table=base+0x56098;selector_address=vip+2*step;opcode=facts[selector_address]
        addresses=[selector_address]+[table+opcode*4+i for i in range(4)]
        known=[[hex(a),facts[a]] for a in addresses];assert c['imageByteFacts']==known
        derived_facts.update({int(a,16):v for a,v in known})
        word=bytes(facts[a] for a in addresses[1:]);target_value=(table+int.from_bytes(word,'little',signed=True))&MASK
        assert int(c['target'],16)==target_value
        if step<applications-1:assert target_value==int(case['args']['composition_plan']['paths'][step+1][0],16)
        all_targets.append(target_value)
    assert derived_facts==facts
    i=unsat(proof['allContinuationSelectionsAndComplementaryExitGuardsQuery'],'all-selected-path-and-complementary-exit-guards')
    assert rows[i]['explicitCuts']==sorted(c['targetNode'] for c in proof['targetCertificates'][:-1]) and not rows[i]['weakenedLoadNodes']
    assert rows[proof['premisesSatisfiableQuery']]['status']=='sat'
    assert len(proof['negativeControls'])==2 and all(rows[i]['status']=='sat' for i in proof['negativeControls'])
    # Only these25 bytes are fixed. Other data memory, GPRs and live opaque
    # values vary. Test seeds/addresses never become universal proof premises.
    rng=random.Random(0x636861696e646f6d)
    stack_values=[rng.getrandbits(64) for _ in range(1024)]
    for edge in (0,base,base+size,base+0x846c4,base+0x56098,MASK):
        stack_values += [(edge+d)&MASK for d in range(-680,681,16)]
    stack_values += [base+0x846c4+8+d for d in range(16)]
    stack_values=list(dict.fromkeys(stack_values));counts={'separatedTrueGuard':0,'overlapTrueGuard':0,'overlapFalseGuard':0};examples={}
    for index,S in enumerate(stack_values):
        initial={n:rng.getrandbits(64) for n in NAMES};initial['rsp']=S;L=(S-671)&MASK;frame=((S-648)&MASK)&(MASK-15)
        origin=total_byte(rng.getrandbits(64),facts)
        unknowns={nodes[x['node']]['name']:rng.getrandbits(64) for x in core['nondeterministicInputs']}
        v=projection_values(core,initial,origin,unknowns=unknowns)
        region=((L-base)&MASK)>=size and ((base-L)&MASK)>=671
        for s in core['stores']:assert ((v[s['address']]-L)&MASK)<=663
        for step,layer in enumerate(core['layers']):
            assert v[layer['registers']['rsp']]==frame and v[layer['registers']['rbp']]==(S-136+8*step)&MASK
            assert v[layer['registers']['rsi']]==base+0x846c4+1+2*step and v[layer['registers']['r11']]==base+0x56098
        guard=v[core['pathGuard']];assert guard in (0,1)
        label='separatedTrueGuard' if region else 'overlapTrueGuard' if guard else 'overlapFalseGuard';counts[label]+=1
        if region:
            assert guard==1 and all(v[e['guard']]==0 for e in core['sideExits'])
            assert all(v[b['control']['target']]==wanted for b,wanted in zip(core['boundaries'],all_targets))
            # Check every prefix, not only final memory. No written address can
            # hit any image byte, irrespective of whether its value coincides.
            for s in core['stores']:
                original,overlay=v[s['afterMemory']];assert original is origin
                assert all(not base<=a<base+size for a in overlay)
        elif label not in examples:examples[label]={'initialRSP':hex(S),'finalGuard':guard}
    assert counts['separatedTrueGuard']>=1024 and counts['overlapTrueGuard']>0 and counts['overlapFalseGuard']>0
    result={'schema':'ig5-entry-chain-domain-independent-audit-v2','passed':True,'caseId':proof['caseId'],'applications':applications,'writes':writes,'initialByteFacts':len(facts),'proofPath':str(proof_path),'proofSha256':digest,
        'sourceReportSha256':proof['sourceReport']['sha256'],'allQueryHashesLimitsAndExpectedStatusesChecked':True,
        'allStoreLinksAndMemoryBindingsChecked':True,'targetCutsLinkedToPriorConditionalCertificates':True,
        'onlyStatedInitialBytesFixed':True,'otherMemoryArbitraryDeterministicTotalForTests':True,'numericStates':len(stack_values),
        'numericResults':counts,'overlapExamples':examples,'numericAllWriteBoundsAndPointerStatesChecked':True,
        'separatedCasesAllTargetsExitsAndEveryPrefixImagePreservationChecked':True,
        'verifierSourceSha256':sha(__file__),'numericEvaluatorSha256':sha(MAIN/'scripts/projection_numerical_oracle.py'),
        'numericChecksAreNotUniversalProof':True,'notIndependentCPUInterpreter':True,
        'nativeTargetExecuted':False,'businessAccepted':False,'wholeBinaryVerified':False}
    with out.open('x',encoding='utf8') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    print(json.dumps(result))
if __name__=='__main__':main()
