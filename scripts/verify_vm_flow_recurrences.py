"""Independent raw-parser/numerical audit of accepted recorded recurrences.

No JavaScript evaluator, native DLL, PE read, target execution or missing-byte
fill. Entire typed DAGs are validated first. STORE prefixes are numerically
evaluated only through their existing afterMemory definition, without cutting
dependencies; final evaluation uses the complete original DAG. Unknown inputs
or unsupported recorded store sidecars refuse this audit rather than pass.
"""
import argparse,hashlib,json,sys
from pathlib import Path
MAIN=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(MAIN/'worker'),str(MAIN/'scripts')]
from trace_analysis import parse_trace,GPRS
from projection_numerical_oracle import projection_values,MASK
from composition_domain_smt import validate
from lift_runtime import locked_file

def load(path,digest=None,maximum=4*1024**2):
    with locked_file(Path(path),maximum) as raw:
        if digest is not None:assert hashlib.sha256(raw).hexdigest()==digest
        return json.loads(raw.decode('utf-8-sig'))

def signatures(core):
    result=[]
    for n in core['dag']['nodes']:
        meaning={k:v for k,v in n.items() if k not in ('id','args')};meaning['args']=[result[i] for i in n['args']]
        result.append(hashlib.sha256(json.dumps(meaning,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf8')).hexdigest())
    return result

def verify(report_path,digest,recording_root):
    result=load(report_path,digest)['result'];assert result['schema']=='ig5-flow-recurrences-v1'
    flow=load(result['sourceFlow']['path'],result['sourceFlow']['sha256'])['result'];assert flow['targetSha256']==result['targetSha256']
    full=load(result['sourceProjections']['full']['path'],result['sourceProjections']['full']['sha256'])['result']
    prefix=load(result['sourceProjections']['prefix']['path'],result['sourceProjections']['prefix']['sha256'])['result']
    for core in (prefix,full):
        validate(core);assert not any(n['op']=='state_binding' for n in core['dag']['nodes'])
        assert core['targetSha256']==result['targetSha256'] and core['nativeTargetExecuted'] is False
    loads=[n for n in prefix['dag']['nodes'] if n['op']=='load_le' and n['size'] in (1,2)];assert len(loads)==1
    signature=signatures(prefix)[loads[0]['id']];fs=signatures(full)
    source=next(n['id'] for n in full['dag']['nodes'] if n['op']=='load_le' and fs[n['id']]==signature)
    assert flow['sourceLoad']['signature']==signature and flow['sourceLoad']['matchedFullNodes'][0]==source
    allgroups=[];raw_bytes=0;instructions=0;previous=None
    for ref in result['source']['windows']:
        record=load(recording_root/'records'/(ref['reportId']+'.json'),ref['reportSha256']);body=record['result']
        assert 'storeEvents' not in body,'Optional native store sidecars need a separate independent audit'
        assert body['targetSha256']==result['targetSha256'] and body['sha256']==ref['traceSha256']
        with locked_file(recording_root/'blobs'/(body['sha256']+'.bin'),1024**2) as raw:
            assert hashlib.sha256(raw).hexdigest()==body['sha256'] and len(raw)==body['bytes'];raw_bytes+=len(raw);assert raw_bytes<=16*1024**2
            trace=parse_trace(raw,100000)
        instructions+=len(trace);assert instructions<=100000;groups=[]
        for i,(pc,code,regs,memory) in enumerate(trace):
            if regs is None:groups[-1]['instructions'].append((pc,code));continue
            groups.append({'instructions':[(pc,code)],'before':dict(zip(GPRS,regs)),'flags':trace.flag_snapshots[i],'reads':memory,'recordingId':ref['reportId']})
        assert len(groups)==body['endStopSeq']-body['startStopSeq'] and len(trace)==body['instructionCount']
        for i,g in enumerate(groups):
            g['pause']=body['startStopSeq']+i
            after=groups[i+1] if i+1<len(groups) else None
            g['after']=after['before'] if after else dict(zip(GPRS,trace.final_registers[:16]));g['afterRip']=after['instructions'][0][0] if after else trace.final_registers[16]
        if previous:
            before,old=previous
            assert body['runId']==old['runId'] and body['threadId']==old['threadId'] and body['runtimeBase']==old['runtimeBase'] and body['startStopSeq']==old['endStopSeq']
            assert groups[0]['before']==before['after'] and groups[0]['instructions'][0][0]==before['afterRip']
        previous=(groups[-1],body);allgroups.extend(groups)
    descriptor=[(int(d['runtimePc'],16),bytes.fromhex(d['bytes'])) for d in result['descriptor']]
    assert len(descriptor)==len(full['projectionPath']) and len({pc for pc,_ in descriptor})==len(descriptor)
    assert [code.hex() for _,code in descriptor]==[d['bytes'] for d in full['decodedPath']]
    starts=complete=mismatches=coalesced=changed=0;pending=None;completed=[]
    for i,g in enumerate(allgroups):
        one=len(g['instructions'])==1
        for item in g['instructions']:
            if item[0]==descriptor[0][0]:
                if item[1]!=descriptor[0][1]:changed+=1
                else:starts+=1;coalesced+=int(not one)
        if pending is not None:
            start,position=pending
            if one and g['instructions'][0]==descriptor[position]:
                position+=1
                if position==len(descriptor):complete+=1;completed.append(start);pending=None
                else:pending=(start,position)
                continue
            mismatches+=1;pending=None
        if one and g['instructions'][0]==descriptor[0]:
            if len(descriptor)==1:complete+=1;completed.append(i)
            else:pending=(i,1)
    expected={'sourceByteEvents':starts,'completeDescriptorPaths':complete,'pathMismatches':mismatches,'coalescedSourceEvents':coalesced,'changedBytesAtSourcePc':changed}
    for key,value in expected.items():assert result['counts'][key]==value
    inventory_audit=None
    if result['sampling']['strategy']=='first-per-observed-source-target-pair-page':
        source_node=full['dag']['nodes'][source];assert source_node['args'][0]==full['initialMemory'];address_node=source_node['args'][1]
        needed=set();todo=[address_node]
        while todo:
            i=todo.pop()
            if i in needed:continue
            needed.add(i);assert full['dag']['nodes'][i]['op'] not in ('load_le','store_le','initial_memory','nondeterministic');todo.extend(full['dag']['nodes'][i]['args'])
        ids=sorted(needed);mapping={old:new for new,old in enumerate(ids)}
        view={'dag':{'nodes':[{**full['dag']['nodes'][i],'id':mapping[i],'args':[mapping[j] for j in full['dag']['nodes'][i]['args']]} for i in ids]}}
        pairs={};unobserved=unindexed=0
        def no_ram(_):raise AssertionError('Pure source address unexpectedly reads RAM')
        for start in completed:
            g=allgroups[start];address=projection_values(view,g['before'],no_ram)[mapping[address_node]]
            candidates=[v for a,n,v in g['reads'] if a==address and n==source_node['size']]
            if not candidates or len(set(candidates))!=1:unobserved+=1;continue
            value=candidates[0];target=allgroups[start+len(descriptor)-1]['afterRip'];key=(value,target)
            if key not in pairs:
                if len(pairs)==256:unindexed+=1;continue
                pairs[key]={'ordinal':len(pairs),'observedValue':hex(value),'target':hex(target),'completePaths':0,
                    'firstOccurrence':{'startGroup':start,'endGroup':start+len(descriptor)-1,'recordingId':g['recordingId'],'pause':g['pause'],
                        'sourceRead':{'status':'observed','address':hex(address),'bytes':source_node['size'],'value':hex(value)}}}
            pairs[key]['completePaths']+=1
        inv=result['observedSourceTargetInventory'];assert inv['pairs']==list(pairs.values()) and inv['sourceReadUnobservedCompletePaths']==unobserved and inv['unindexedCompletePaths']==unindexed
        assert inv['trackingComplete']==(unindexed==0 and unobserved==0) and inv['countsAreLowerBounds']==(unindexed>0 or unobserved>0)
        assert inv['inventoryIsOrdinaryStateReplay'] is False and inv['sourceValuesAreOpcodeLabels'] is False
        offset=result['sampling']['pairOffset'];selected=[p['firstOccurrence']['startGroup'] for p in list(pairs.values())[offset:offset+8]]
        assert inv['selectedPairOrdinals']==[p['ordinal'] for p in list(pairs.values())[offset:offset+8]]
        assert inv['nextPairOffset']==(offset+8 if offset+8<len(pairs) else None)
        inventory_audit={'trackedPairs':len(pairs),'unobservedSourcePaths':unobserved,'unindexedPaths':unindexed,'pairOffset':offset,'sourceAddressDependenciesCut':False,'sourceBytesFromExactRawRead':True}
    else:
        assert result['sampling']['strategy']=='first4-last4-complete-descriptor-paths' and 'observedSourceTargetInventory' not in result
        selected=list(dict.fromkeys(completed[:4]+completed[-4:]))
    assert selected==[o['startGroup'] for o in result['occurrences']]
    partial=[] if pending is None else [{'startGroup':pending[0],'capturedGroups':pending[1],'requiredGroups':len(descriptor),'reason':'supplied-recording-end'}]
    assert result['partialCapturedPaths']==partial;rows=[]
    for occurrence in result['occurrences']:
        assert occurrence['status']=='consistent-recorded-ordinary-state' and occurrence['snapshotCaptureComplete'] is True
        start=occurrence['startGroup'];groups=allgroups[start:start+len(descriptor)];initial=groups[0]['before'];seed={};overlay={};stores=[];post=0
        def byte(address):
            assert address in seed,'Missing observed initial RAM; no invented fill'
            return seed[address]
        for step,g in enumerate(groups):
            for address,size,value in g['reads']:
                for n in range(size):
                    a=(address+n)&MASK;b=(value>>(8*n))&255
                    if a in overlay:assert overlay[a]==b;post+=1
                    elif a in seed:assert seed[a]==b
                    else:seed[a]=b
            for s in full['stores']:
                if s['instructionIndex']!=step:continue
                # Existing topological definitions through this STORE retain
                # all of its dependencies; full source validated above.
                view={'dag':{'nodes':full['dag']['nodes'][:s['afterMemory']+1]}}
                v=projection_values(view,initial,byte);address=v[s['address']];value=v[s['value']]
                stores.append({'instructionIndex':step,'pcodeIndex':s['pcodeIndex'],'address':hex(address),'value':hex(value),'bytes':s['size']})
                for n in range(s['size']):overlay[(address+n)&MASK]=(value>>(8*n))&255
        v=projection_values(full,initial,byte)
        assert {k:v[i] for k,i in full['registers'].items()}==groups[-1]['after']=={k:int(x,16) for k,x in occurrence['finalGprs'].items()}
        assert v[full['control']['target']]==groups[-1]['afterRip']==int(occurrence['target'],16)
        assert v[full['currentMemory']][1]==overlay and stores==occurrence['orderedStores']
        assert {int(r['address'],16):r['value'] for r in occurrence['finiteInitialMemoryBytes']}==seed and post==occurrence['postStoreReadBytesNotSeededAsInitial']
        assert hex(v[source])==occurrence['sourceValue'] and hex(v[full['dag']['nodes'][source]['args'][1]])==occurrence['sourceAddress']
        for index in occurrence['indexedReads']:
            assert index['address']==hex(v[full['dag']['nodes'][index['node']]['args'][1]]) and index['value']==hex(v[index['node']])
        for update in occurrence['sourceAddressInputUpdates']:
            g=update['name'];assert update['before']==hex(initial[g]) and update['deltaModulo64']==hex((groups[-1]['after'][g]-initial[g])&MASK)
        rows.append({'startGroup':start,'all16FinalGprsMatched':True,'targetMatched':True,'orderedStores':len(stores),'finiteInitialBytes':len(seed),'postStoreBytesExcluded':post})
    return {'schema':'ig5-flow-recurrence-independent-audit-v1','passed':True,'rawWindows':len(result['source']['windows']),'rawInstructions':instructions,'pairInventoryAudit':inventory_audit,
        'descriptorCounts':expected,'selectedCompletePathsVerified':rows,'partialCapturedPaths':partial,'missingRamFilled':False,
        'entireTypedSourceDagValidated':True,'storePrefixEvaluationCutsDependencies':False,'finalEvaluationUsesCompleteSourceDag':True,
        'independentNativeStoreSidecarAudit':'not-present','nativeTargetExecuted':False,'peFileRead':False,'instructionSemanticsProved':False,'intermediateGprSemanticsVerified':False,
        'vmRoleProved':False,'independentInputCoverageProved':False,'businessAccepted':False,'scope':'Independent raw parser and numerical final-state/ordered-STORE audit; no CPU/VM/cross-input or business proof'}

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    for key in ('report','sha256','recording-root','out'):parser.add_argument('--'+key,required=True)
    a=parser.parse_args();result=verify(Path(a.report),a.sha256,Path(a.recording_root))
    with Path(a.out).open('x',encoding='utf8') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    print(json.dumps(result))
