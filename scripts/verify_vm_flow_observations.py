"""Independent raw observation and numerical checks. No native decoder/PE execution.
These checks do not prove CPU semantics, nonconstancy, VM roles or path coverage.
"""
import argparse, hashlib, json, sys
from pathlib import Path
MAIN=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(MAIN/'worker'),str(MAIN/'scripts')]
from trace_analysis import parse_trace, GPRS
from projection_numerical_oracle import projection_values, MASK
from lift_runtime import locked_file

def load(path,digest=None,maximum=4*1024**2):
    with locked_file(Path(path),maximum) as raw:
        if digest is not None:assert hashlib.sha256(raw).hexdigest()==digest
        return json.loads(raw.decode('utf-8-sig'))

def verify(report_path,digest,recording_root):
    result=load(report_path,digest)['result']
    assert result['schema'] in ('ig5-fetch-control-dependency-v1','ig5-fetch-control-assessed-v1')
    full=load(result['evidence']['fullProjection']['path'],result['evidence']['fullProjection']['sha256'])['result']
    window=load(result['sourceWindow']['path'],result['sourceWindow']['sha256'])['result']
    assert not full['nondeterministicInputs'],'Opaque-input numerical coordination is outside this verifier'
    originals={};starts={};raw_bytes=0;instructions=0
    for ref in window['source']['windows']:
        record=load(recording_root/'records'/(ref['reportId']+'.json'),ref['reportSha256'])
        body=record['result'];assert body['targetSha256']==result['targetSha256'] and body['sha256']==ref['traceSha256']
        with locked_file(recording_root/'blobs'/(body['sha256']+'.bin'),1024**2) as raw:
            assert hashlib.sha256(raw).hexdigest()==body['sha256'];raw_bytes+=len(raw);assert raw_bytes<=16*1024**2
            trace=parse_trace(raw,100000)
        groups=[];instructions+=len(trace);assert instructions<=100000
        for i,(pc,code,regs,memory) in enumerate(trace):
            if regs is None:groups[-1]['instructions'].append((pc,code));continue
            groups.append({'pc':pc,'instructions':[(pc,code)],'gprs':dict(zip(GPRS,regs)),'flags':trace.flag_snapshots[i],'memory':memory})
        for i,g in enumerate(groups):
            nxt=groups[i+1] if i+1<len(groups) else None
            g['after']=nxt['gprs'] if nxt else dict(zip(GPRS,trace.final_registers[:16]))
            g['afterRip']=nxt['pc'] if nxt else trace.final_registers[16]
            g['afterFlags']=nxt['flags'] if nxt else trace.final_registers[17]
        originals[ref['reportId']]=groups;starts[ref['reportId']]=ref['startStopSeq']
    for g in window['groups']:
        old=originals[g['recordingId']][g['pauseSequence']['before']-starts[g['recordingId']]]
        assert {k:int(v,16) for k,v in g['before']['gprs'].items()}==old['gprs']
        assert {k:int(v,16) for k,v in g['after']['gprs'].items()}==old['after']
        assert int(g['before']['flags'],16)==old['flags'] and int(g['after']['flags'],16)==old['afterFlags']
        assert int(g['after']['rip'],16)==old['afterRip']
        assert [(int(i['pc'],16),bytes.fromhex(i['bytes'])) for i in g['instructions']]==old['instructions']
        assert [(int(m['address'],16),m['bytes'],int.from_bytes(bytes.fromhex(m['littleEndianHex']),'little')) for m in g['memoryReads']]==old['memory']
    groups=window['groups'][:result['completeSelectedWindow']['groups']]
    assert len(groups)==result['instructionCount']==len(full['projectionPath'])
    with locked_file(Path(load(result['evidence']['fullProjection']['path'])['target']),64*1024**2) as raw:
        assert hashlib.sha256(raw).hexdigest()==result['targetSha256']
        for m,g,d in zip(result['mapping']['mapping'],groups,full['decodedPath'],strict=True):
            assert m['bytes']==g['instructions'][0]['bytes']==d['bytes']
            assert raw[m['fileOffset']:m['fileOffset']+len(bytes.fromhex(m['bytes']))].hex()==m['bytes']
            assert int(m['runtimePc'],16)-int(result['mapping']['runtimeBase'],16)==int(m['preferred'],16)-int(result['mapping']['preferredBase'],16)
    initial={k:int(v,16) for k,v in groups[0]['before']['gprs'].items()};all_reads={}
    for g in groups:
        for m in g['memoryReads']:
            for n,b in enumerate(bytes.fromhex(m['littleEndianHex'])):all_reads.setdefault((int(m['address'],16)+n)&MASK,b)
    preliminary=projection_values(full,initial,lambda a:all_reads.get(a,0))
    stores=[(s['instructionIndex'],preliminary[s['address']],preliminary[s['value']],s['size']) for s in full['stores']]
    seed_bytes={};overlay={};post_store_reads=0
    for i,g in enumerate(groups):
        for m in g['memoryReads']:
            for n,b in enumerate(bytes.fromhex(m['littleEndianHex'])):
                a=(int(m['address'],16)+n)&MASK
                if a in overlay:assert overlay[a]==b;post_store_reads+=1
                elif a in seed_bytes:assert seed_bytes[a]==b
                else:seed_bytes[a]=b
        for at,a,value,size in stores:
            if at==i:
                for n in range(size):overlay[(a+n)&MASK]=(value>>(8*n))&255
    wanted={k:int(v,16) for k,v in groups[-1]['after']['gprs'].items()}
    for pattern in (0,255,0x5a):
        values=projection_values(full,initial,lambda a:seed_bytes.get(a,(pattern^(a>>5))&255))
        assert {k:values[v] for k,v in full['registers'].items()}==wanted
        assert values[full['control']['target']]==int(groups[-1]['after']['rip'],16)
        assert [(s['instructionIndex'],values[s['address']],values[s['value']],s['size']) for s in full['stores']]==stores
        assert values[full['currentMemory']][1]==overlay
    return {'passed':True,'rawWindowsVerified':len(originals),'rawInstructionsValidated':instructions,
        'contiguousObservationGroupsVerified':len(window['groups']),'projectedInstructionGroups':len(groups),
        'all16FinalGprsMatched':True,'indirectTargetMatched':True,'orderedDecodedStores':len(stores),
        'seededInitialObservedBytes':len(seed_bytes),'postStoreReadBytesNotSeededAsInitial':post_store_reads,
        'unobservedInitialBytePatterns':3,'nativeTargetExecuted':False,'instructionSemanticsProved':False,
        'vmRoleProved':False,'businessAccepted':False,'scope':'Independent raw parser and observed ordinary-state numerical consistency; no CPU/coverage/VM proof'}

if __name__=='__main__':
    p=argparse.ArgumentParser()
    for key in ('report','sha256','recording-root','out'):p.add_argument('--'+key,required=True)
    a=p.parse_args();r=verify(Path(a.report),a.sha256,Path(a.recording_root))
    with Path(a.out).open('x',encoding='utf8') as f:json.dump(r,f,indent=2);f.write('\n')
    print(json.dumps(r))
