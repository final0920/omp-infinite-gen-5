"""Independent raw parser/arithmetic checks; no native decoder or target execution."""
import hashlib, json, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'worker'))
from trace_analysis import parse_trace, GPRS
def read(path,digest=None):
    raw=Path(path).read_bytes()
    if digest is not None:assert hashlib.sha256(raw).hexdigest()==digest
    return json.loads(raw.decode('utf-8-sig'))
def verify(result_path):
    run=read(result_path);catalog=read(run['catalog']['path'],run['catalog']['sha256'])
    cases={c['name']:c for c in catalog};counts={'cases':0,'samples':0,'memoryAccesses':0,'loadConsistencies':0}
    for case in run['results']:
        assert case['status']=='completed-offline-only'
        meta=case['preview'];report=read(meta['reportPath'],meta['reportSha256'])['result']
        ref=report['evidence']['sampleReport'];sample=read(ref['path'],ref['sha256'])['result']
        original={};root=Path(cases[case['name']]['artifactDir'])/'debug-traces'
        for ref in case['input']['recordings']:
            body=read(root/'records'/(ref['id']+'.json'),ref['sha256'])['result']
            raw=(root/'blobs'/(body['sha256']+'.bin')).read_bytes()
            assert hashlib.sha256(raw).hexdigest()==body['sha256']
            trace=parse_trace(raw,100000);groups=[]
            for index,(pc,code,regs,memory) in enumerate(trace):
                if regs is None:groups[-1]['instructions'].append((pc,code));continue
                groups.append({'pc':pc,'instructions':[(pc,code)],'gprs':dict(zip(GPRS,regs)),'flags':trace.flag_snapshots[index],'memory':memory})
            for index,g in enumerate(groups):
                nxt=groups[index+1] if index+1<len(groups) else None
                g['after']=nxt['gprs'] if nxt else dict(zip(GPRS,trace.final_registers[:16]))
                g['afterRip']=nxt['pc'] if nxt else trace.final_registers[16]
            original[ref['id']]=groups
        starts={w['reportId']:w['startStopSeq'] for w in sample['observation']['windows']}
        for site,analyzed in zip(sample['sites'],report['sites'],strict=True):
            assert (site['pc'],site['bytes'])==(analyzed['pc'],analyzed['bytes'])
            if analyzed['decoder']['status']=='decode-rejected':continue
            for g,a in zip(site['groups'],analyzed['observations'],strict=True):
                old=original[g['recordingId']][g['pauseSequence']['before']-starts[g['recordingId']]]
                assert {k:int(v,16) for k,v in g['before']['gprs'].items()}==old['gprs']
                assert {k:int(v,16) for k,v in g['after']['gprs'].items()}==old['after']
                assert int(g['after']['rip'],16)==old['afterRip']
                assert [(int(i['pc'],16),bytes.fromhex(i['bytes'])) for i in g['instructions']]==old['instructions']
                assert [(int(m['address'],16),m['bytes'],int.from_bytes(bytes.fromhex(m['littleEndianHex']),'little')) for m in g['memoryReads']]==old['memory']
                counts['samples']+=1
                for access in a.get('accesses',[]):
                    if access['read']['status']!='matched-recorded-read':continue
                    ea=access['effectiveAddress'];op=access['expression'];bits=ea['addressBits'];value=int(op['displacement'],16)
                    for r,scale in ((op['base'],1),(op['index'],op['scale'])):
                        if r:
                            n=old['pc']+len(old['instructions'][0][1]) if r['parent']=='rip' else old['gprs'][r['parent']]
                            value+=((n>>r['low'])&((1<<r['bits'])-1))*scale
                    value=((value&((1<<bits)-1))+int(ea['segmentBase'],16))&((1<<64)-1)
                    assert value==int(ea['address'],16)
                    assert any(addr==value and size==op['bytes'] and n==int.from_bytes(bytes.fromhex(access['read']['littleEndianHex']),'little') for addr,size,n in old['memory'])
                    counts['memoryAccesses']+=1
                if a.get('load',{}).get('status')=='observed-consistent':
                    load=a['load'];assert int(load['observedParentValue'],16)==old['after'][load['destination']['parent']]
                    counts['loadConsistencies']+=1
        assert report['vmModelProved'] is False and report['businessAccepted'] is False
        counts['cases']+=1
    return counts
if __name__=='__main__':print(json.dumps({'passed':True,**verify(sys.argv[1]),'nativeTargetExecuted':False,'scope':'source observations and arithmetic, not independent CPU/VM semantics'}))
