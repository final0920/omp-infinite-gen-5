"""Independent raw-recording and finite numerical body audit; no PE execution.

Full typed source DAGs are checked before dependency-closed numerical views.
Unknown inputs are never assigned; unknown writes taint later read bytes.
"""
import argparse,copy,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'worker'),str(ROOT/'scripts')]
from verify_vm_flow_recurrences import load
from trace_analysis import parse_trace,GPRS
from projection_numerical_oracle import projection_values,MASK
from composition_domain_smt import validate
from lift_runtime import locked_file

def typed(core):
    # The unchanged old validator has no INT_NEGATE. Expand only this exact
    # equal-width ones-complement identity in an independent validation view.
    # The original source, roots and numerical interpreter remain unchanged.
    mapping={};nodes=[];extensions=[]
    for n in core['dag']['nodes']:
        assert n['id']==len(mapping) and all(type(i) is int and 0<=i<n['id'] for i in n['args'])
        x=copy.deepcopy(n);x['args']=[mapping[i] for i in n['args']]
        if n['op']=='INT_NEGATE':
            assert n['type']=='bv' and len(n['args'])==1 and type(n['bits']) is int and 1<=n['bits']<=128
            assert core['dag']['nodes'][n['args'][0]]['type']=='bv' and core['dag']['nodes'][n['args'][0]]['bits']==n['bits']
            c=len(nodes);nodes.append({'id':c,'op':'const','type':'bv','bits':n['bits'],'value':hex((1<<n['bits'])-1),'args':[]})
            x['op']='INT_XOR';x['args'].append(c);extensions.append(n['id'])
        x['id']=len(nodes);mapping[n['id']]=x['id'];nodes.append(x)
    ds=[]
    for n in nodes:ds.append(1+max([0]+[ds[i] for i in n['args']]))
    validate({'dag':{'nodes':nodes,'depth':max(ds),'references':sum(len(n['args']) for n in nodes)}})
    return extensions

def raw_groups(result,recording_root):
    recurrence=load(result['sourceRecurrencePath'],result['sourceRecurrence']['sha256'])['result'];groups=[];used=0;previous=None
    for ref in recurrence['source']['windows']:
        r=load(recording_root/'records'/(ref['reportId']+'.json'),ref['reportSha256'])['result']
        assert r['targetSha256']==result['targetSha256'] and 'storeEvents' not in r and r['sha256']==ref['traceSha256']
        assert r['runId']==recurrence['source']['identity']['runId'] and r['threadId']==recurrence['source']['identity']['threadId']
        with locked_file(recording_root/'blobs'/(r['sha256']+'.bin'),1024**2) as b:
            assert hashlib.sha256(b).hexdigest()==r['sha256'] and len(b)==r['bytes'];used+=len(b);assert used<=16*1024**2
            trace=parse_trace(b,100000)
        rows=[]
        for pc,code,regs,reads in trace:
            if regs is None:rows[-1]['instructions'].append((pc,code));continue
            rows.append({'instructions':[(pc,code)],'before':dict(zip(GPRS,regs)),'reads':reads})
        for i,g in enumerate(rows):
            g['after']=rows[i+1]['before'] if i+1<len(rows) else dict(zip(GPRS,trace.final_registers[:16]))
            g['afterRip']=rows[i+1]['instructions'][0][0] if i+1<len(rows) else trace.final_registers[16]
            g.update(groupIndex=len(groups)+i,recordingId=ref['reportId'],pauseBefore=r['startStopSeq']+i,pauseAfter=r['startStopSeq']+i+1)
        if previous:
            g,old=previous;assert r['runId']==old['runId'] and r['threadId']==old['threadId'] and r['startStopSeq']==old['endStopSeq']
            assert rows[0]['before']==g['after'] and rows[0]['instructions'][0][0]==g['afterRip']
        previous=(rows[-1],r);groups.extend(rows)
    return recurrence,groups

def verify(report,digest,recording_root,recurrence_path):
    result=load(report,digest)['result'];assert result['schema']=='ig5-recorded-handlers-v1'
    result['sourceRecurrencePath']=str(recurrence_path);recurrence,allgroups=raw_groups(result,recording_root)
    selection=load(result['sourceSelection']['path'],result['sourceSelection']['sha256'])['result'];rows=[];unverified=[]
    head=recurrence['descriptor'][0];head=(int(head['runtimePc'],16),bytes.fromhex(head['bytes']))
    for body,selected,occurrence in zip(result['bodies'],selection['bodies'],recurrence['occurrences'],strict=True):
        assert body['sourceOccurrence']==selected['sourceOccurrence']==occurrence['startGroup']
        start=occurrence['endGroup']+1;end=next(i for i in range(start,len(allgroups)) if allgroups[i]['instructions']==[head])
        assert end==selected['nextFetchGroup']==body['nextFetchGroup'];groups=allgroups[start:end]
        assert len(groups)==body['groupCount']==len(selected['groups']) and groups[0]['instructions'][0][0]==int(occurrence['target'],16)
        for raw,stored in zip(groups,selected['groups'],strict=True):
            assert raw['instructions']==[(int(i['pc'],16),bytes.fromhex(i['bytes'])) for i in stored['instructions']]
            assert raw['before']=={k:int(v,16) for k,v in stored['before']['gprs'].items()}
            assert raw['after']=={k:int(v,16) for k,v in stored['after']['gprs'].items()} and raw['afterRip']==int(stored['after']['rip'],16)
            assert raw['reads']==[(int(r['address'],16),r['bytes'],int.from_bytes(bytes.fromhex(r['littleEndianHex']),'little')) for r in stored['memoryReads']]
        if body['status']=='unverified':
            assert isinstance(body.get('reason'),str) and body['reason'];unverified.append({'sourceValue':body['sourceValue'],'status':'unverified','reason':body['reason']});continue
        projection_record=load(body['projection']['path'],body['projection']['sha256']);core=projection_record['result'];extensions=typed(core);nodes=core['dag']['nodes'];a=body['assessment']
        assert core['targetSha256']==result['targetSha256'] and len(core['decodedPath'])==len(groups)
        runtime=core.get('recordedCoordinates')
        if runtime is not None:
            assert projection_record['action']=='project-recorded' and body['projectionCoordinates']=='recorded-runtime-v1'
            assert runtime['schema']=='ig5-recorded-runtime-code-binding-v1' and runtime['ordinaryDataRelocated'] is False and runtime['globalCodeEpochProved'] is False
            coordinate_ref=projection_record['recordedCoordinatesInput'];assert coordinate_ref['sha256']==runtime['inputSha256']
            coordinate_file=Path(body['projection']['path']).parent.parent/'blobs'/(coordinate_ref['sha256']+'.bin')
            with locked_file(coordinate_file,65536) as b:
                assert len(b)==coordinate_ref['bytes'] and hashlib.sha256(b).hexdigest()==coordinate_ref['sha256'];assert json.loads(b)==runtime['input']
            x=runtime['input'];assert x['schema']=='ig5-recorded-runtime-code-input-v1' and x['targetSha256']==result['targetSha256']
            assert x['source']['recurrencesRef']==result['sourceRecurrence']
            assert x['source']['selectionRef']=={k:result['sourceSelection'][k] for k in ('id','sha256')}
            assert x['source']['runId']==recurrence['source']['identity']['runId'] and x['source']['threadId']==recurrence['source']['identity']['threadId']
            assert x['runtimeBase']==recurrence['source']['identity']['runtimeBase']==body['mapping']['runtimeBase']
            assert x['preferredBase']==body['mapping']['preferredBase'] and len(x['rows'])==len(groups)
            source_windows={w['reportId']:w for w in recurrence['source']['windows']}
            assert {w['reportId'] for w in x['source']['windows']}=={g['recordingId'] for g in groups}
            for w in x['source']['windows']:assert w=={k:source_windows[w['reportId']][k] for k in ('reportId','reportSha256','traceSha256')}
            for r,g,m,d in zip(x['rows'],groups,body['mapping']['mapping'],core['decodedPath'],strict=True):
                pc,code=g['instructions'][0];assert r['groupIndex']==g['groupIndex']==m['groupIndex'] and r['recordingId']==g['recordingId']==m['recordingId']
                assert int(r['runtimePc'],16)==pc and r['bytes']==code.hex()==m['bytes'] and r['preferred']==m['preferred'] and r['fileOffset']==m['fileOffset']
                assert r['pauseBefore']==g['pauseBefore'] and r['pauseAfter']==g['pauseAfter']
                assert int(r['preferred'],16)-int(x['preferredBase'],16)==pc-int(x['runtimeBase'],16)
                assert d['ea']==d['decoded']['ea']==hex(pc) and d['decoded']['size']==len(code)
            assert core['originalPreferredPath']==[r['preferred'] for r in x['rows']] and core['projectionPath']==[r['runtimePc'] for r in x['rows']]
        else:assert 'projectionCoordinates' not in body
        opaque=[]
        for n in nodes:opaque.append(set(([n['id']] if n['op']=='nondeterministic' else [])+list(set().union(*(opaque[i] for i in n['args'])))))
        seed={};overlay={};post_unknown=post_known=0;initial=groups[0]['before']
        def byte(address):assert address in seed,'missing finite initial RAM';return seed[address]
        def at(root):
            if opaque[root]:return None
            needed=set();todo=[root]
            while todo:
                i=todo.pop()
                if i in needed:continue
                needed.add(i);todo.extend(nodes[i]['args'])
            ids=sorted(needed);m={old:new for new,old in enumerate(ids)}
            view={'dag':{'nodes':[{**nodes[i],'id':m[i],'args':[m[j] for j in nodes[i]['args']]} for i in ids]}}
            return projection_values(view,initial,byte)[m[root]]
        stores=[]
        for step,g in enumerate(groups):
            assert core['decodedPath'][step]['bytes']==g['instructions'][0][1].hex()
            for address,size,value in g['reads']:
                for j in range(size):
                    address_byte=(address+j)&MASK;b=(value>>(8*j))&255
                    if address_byte in overlay:
                        if overlay[address_byte] is None:post_unknown+=1
                        else:assert overlay[address_byte]==b;post_known+=1
                    elif address_byte in seed:assert seed[address_byte]==b
                    else:seed[address_byte]=b
            for s in core['stores']:
                if s['instructionIndex']!=step:continue
                address,value=at(s['address']),at(s['value']);assert address is not None
                stores.append((address,value,s['size']))
                for j in range(s['size']):overlay[(address+j)&MASK]=None if value is None else (value>>(8*j))&255
        known=0
        for expected in a['gprs']:
            name=expected['name'];v=at(core['registers'][name])
            if v is None:assert expected['status']=='unknown-preserved' and expected['computed'] is None
            else:assert v==groups[-1]['after'][name]==int(expected['computed'],16);known+=1
        assert stores==[(int(s['address'],16),None if s['value'] is None else int(s['value'],16),s['bytes']) for s in a['orderedStores']]
        assert seed=={int(r['address'],16):r['value'] for r in a['finiteInitialMemoryBytes']}
        assert post_known==a['postStoreKnownReadBytesNotSeededAsInitial'] and post_unknown==a['postStoreUnknownReadBytesNotSeededAsInitial']
        code=groups[-1]['instructions'][0][1];pc=groups[-1]['instructions'][0][0];next_pc=(pc+len(code))&MASK
        if core['control']['kind']=='fallthrough':
            assert runtime is not None and a['control']['selectedSuccessor']=='fallthrough'
            assert a['control']['taken'] is None and a['control']['fallthrough']==hex(next_pc)
            assert at(core['control']['target'])==next_pc and core['control']['source']==hex(pc)
            target=next_pc
        else:
            assert code[0]==0xe9 or code[:2] in [bytes((0x0f,n)) for n in range(0x80,0x90)]
            target=(next_pc+int.from_bytes(code[-4:],'little',signed=True))&MASK
        if core['control']['kind']=='conditional':
            condition=at(core['control']['condition']);assert condition is not None;target=target if condition else next_pc
            assert a['control']['fallthrough']==hex(next_pc) and a['control']['unselectedContinuationAnalyzed'] is False
        assert target==groups[-1]['afterRip']==int(a['control']['target'],16)
        exact=known==16 and all(v is not None for _,v,_ in stores) and post_unknown==0
        assert exact==(body['status']=='consistent-recorded-ordinary-state')
        if exact:assert at(core['currentMemory'])[1]==overlay
        rows.append({'sourceValue':body['sourceValue'],'groups':len(groups),'matchedGprs':known,'orderedStores':len(stores),'unknownStores':sum(v is None for _,v,_ in stores),
            'postStoreUnknownBytesExcluded':post_unknown,'complementNodesIndependentlyValidated':extensions,'status':body['status'],
            'recordedRuntimeCoordinatesVerifiedAgainstRaw':runtime is not None,'originalFileMappingIndependentlyRechecked':False})
    assert len(rows)+len(unverified)==result['counts']['selectedBodies'] and len(unverified)==result['counts']['unverified']
    assert sum(r['status']=='consistent-recorded-ordinary-state' for r in rows)==result['counts']['ordinaryConsistent']
    assert sum(r['status']=='partially-consistent-unknown-preserved' for r in rows)==result['counts']['partialUnknownPreserved']
    return{'schema':'ig5-recorded-handlers-independent-audit-v1','passed':True,'rawGroups':len(allgroups),'bodies':rows,'unverifiedBodiesRetained':unverified,
        'allSelectedBodiesNumericallyAssessed':len(unverified)==0,'auditAcceptsUnverifiedAsOrdinarySuccess':False,
        'entireTypedDagCheckedBeforeDependencyClosedEvaluation':True,'opaqueValuesAssigned':False,'missingRamFilled':False,'nativeTargetExecuted':False,'peFileRead':False,
        'vmRoleProved':False,'businessAccepted':False,'scope':'Independent raw parser, complete typed source and known ordinary root/STORE/control comparison; unknowns preserved, no CPU/VM/business proof'}

if __name__=='__main__':
    p=argparse.ArgumentParser()
    for key in('report','sha256','recording-root','recurrence','out'):p.add_argument('--'+key,required=True)
    a=p.parse_args();r=verify(Path(a.report),a.sha256,Path(a.recording_root),Path(a.recurrence))
    with Path(a.out).open('x',encoding='utf8') as f:json.dump(r,f,indent=2);f.write('\n')
    print(json.dumps(r))
