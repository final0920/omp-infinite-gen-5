"""Independent formula and complete ordinary roots for saved Java projections."""
from pathlib import Path
import hashlib,json,random,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from projection_numerical_oracle import projection_values,total_byte,MASK


def main():
    source=Path(sys.argv[1]);receipt=json.loads(source.read_text(encoding='utf8'));rows=[]
    assert receipt['syntheticFixturesOnly'] and not receipt['nativeRecordingImported']
    gprs='rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split()
    for row in receipt['cases']:
        assert row['rootExited'] and row['rootClosed'] and row['cleanupConfirmed']
        if not row['accepted']:
            failure=row['analysisFailure'];b=Path(failure['reportPath']).read_bytes();assert hashlib.sha256(b).hexdigest()==failure['reportSha256'];r=json.loads(b)['result'];assert r['method']=='project-recorded' and r['cleanupConfirmed'] and r['status']=='failed-unverified';assert r['recordedCoordinatesSha256']==hashlib.sha256(json.dumps(row['coordinateInput'],separators=(',',':')).encode()).hexdigest();continue
        ref=row['result'];raw=Path(ref['reportPath']).read_bytes();assert hashlib.sha256(raw).hexdigest()==ref['reportSha256'];core=json.loads(raw)['result'];x=row['coordinateInput'];base=int(x['runtimeBase'],16);value=base+0x1027
        assert core['projectionPath']==[r['runtimePc'] for r in x['rows']] and core['originalPreferredPath']==[r['preferred'] for r in x['rows']]
        assert core['recordedCoordinates']['input']==x and not core['recordedCoordinates']['ordinaryDataRelocated']
        assert len(core['stores'])==1 and len(core['initialRegisters'])==len(core['registers'])==16
        for r,decoded in zip(x['rows'],core['decodedPath']):assert decoded['ea']==r['runtimePc'] and decoded['bytes']==r['bytes'] and decoded['decoded']['size']==len(r['bytes'])//2
        # Direct inspection of the complete first decoded operation: its PC-
        # derived COPY constant must equal next runtime PC + signed disp32.
        first=core['decodedPath'][0]['decoded']['pcode'];assert len(first)==1 and first[0]['opcode']=='COPY';assert int(first[0]['inputs'][0]['offset'],16)==value
        rng=random.Random(0x525043);states=0
        for i in range(64):
            initial={g:rng.getrandbits(64) for g in gprs};initial['rbp']=[0,0x8000,0x140001027,base+0x1027,MASK-3][i%5]
            values=projection_values(core,initial,total_byte(i));expected={**initial,'rax':value,'rcx':value,'rdx':0x140001027}
            for g,n in core['registers'].items():assert values[n]==expected[g]
            store=core['stores'][0];assert values[store['address']]==initial['rbp'] and values[store['value']]==value and store['size']==8
            overlay={(initial['rbp']+j)&MASK:(value>>(8*j))&255 for j in range(8)};assert values[core['currentMemory']][1]==overlay
            assert core['control']['kind']=='fallthrough' and values[core['control']['target']]==base+0x1019
            states+=1
        rows.append({'runtimeBase':x['runtimeBase'],'states':states,'all16GprsAndWholeOrderedMemoryChecked':True,'absoluteDataImmediateNotRebased':True,'runtimePcLeaConstantChecked':True})
    assert len(rows)==3
    result={'schema':'ig5-recorded-coordinates-independent-audit-v1','passed':True,'cases':rows,'numericStates':192,'syntheticFixturesOnly':True,'nativeTargetExecuted':False,'independentCpuArchitectureProved':False,'businessAccepted':False}
    with (source.parent/'independent-audit.json').open('x',encoding='utf8') as f:json.dump(result,f,indent=2)
    print(json.dumps(result))


if __name__=='__main__':main()
