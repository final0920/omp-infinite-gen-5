"""Independent native instruction formulas; no decoder/product imports."""
from pathlib import Path
import hashlib,json,random,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from projection_numerical_oracle import MASK,NAMES,projection_values,total_byte
data=json.loads(Path(sys.argv[1]).read_bytes());assert len(data['cases'])==11
assert sum(not c['rejected'] for c in data['cases'])==9
rng=random.Random(0x4d46524e);rows=[];count=0
for case in data['cases']:
    if case['rejected']:continue
    response=case['result'];raw=Path(response['reportPath']).read_bytes();assert hashlib.sha256(raw).hexdigest()==response['reportSha256']
    result=json.loads(raw)['result'];kind=case['id'];n=0
    for index in range(64):
        state={name:rng.getrandbits(64) for name in NAMES}
        state['rdi']=[0,1,MASK-3,MASK,state['rdi']][index%5]
        state['rsp']=[0,1,MASK-3,MASK,state['rsp']][index%5]
        if kind=='unknown-alias-barrier':state['rsi']=(state['rdi']+index%19-9)&MASK
        if kind=='push-ret-guarded-reentry' and index%2==0:state['rax']=0x140001100
        memory=total_byte(rng.getrandbits(64));writes={};wanted=dict(state);guard=1;alternate=None
        def write(address,value,size):
            for offset in range(size):writes[(address+offset)&MASK]=(value>>(offset*8))&255
        def read(address,size):return sum((writes[(address+offset)&MASK] if (address+offset)&MASK in writes else memory((address+offset)&MASK))<<(offset*8) for offset in range(size))
        if kind.startswith('push-ret'):
            write((state['rsp']-8)&MASK,state['rax'],8);assert result['control']['kind'] in ('return','fallthrough')
            if kind=='push-ret-guarded-reentry':alternate=dict(wanted);guard=int(state['rax']==0x140001100);wanted['rcx']=state['rax']
        elif kind=='latest-narrow-store':
            write(state['rdi'],state['rax'],8);write((state['rdi']+3)&MASK,state['rbx'],1);wanted['rcx']=read(state['rdi'],8)
        elif kind=='partial-before-store':write(state['rdi'],state['rax'],8);wanted['rcx']=read((state['rdi']-3)&MASK,8)
        elif kind=='known-disjoint-store':
            write(state['rdi'],state['rax'],8);write((state['rdi']+16)&MASK,state['rbx'],8);wanted['rcx']=state['rax']
        elif kind=='unknown-alias-barrier':
            write(state['rdi'],state['rax'],8);write(state['rsi'],state['rbx'],8);wanted['rcx']=read(state['rdi'],8)
        elif kind=='memory-controlled-loop':
            write(state['rdi'],0,1);wanted['rax']=0;assert result['inferredRepeat']['bodyApplicationsAfterPrefix']==2
            assert len(result['stores'])==4 and result['statistics']['expandedMemoryBytes']==8
        elif kind=='affine-address-identity':
            wanted.update(rdx=state['rdi'],rsi=state['rdi'],rcx=state['rax']);write(state['rdi'],state['rax'],8)
        else:raise AssertionError(kind)
        values=projection_values(result,state,memory)
        assert {name:values[ref] for name,ref in result['registers'].items()}==wanted,kind
        assert values[result['currentMemory']]==(memory,writes),kind
        assert values[result['pathGuard']]==guard,kind
        if kind in ('push-ret-one-template','push-ret-across-templates'):assert values[result['control']['target']]==state['rax']
        if alternate is not None:
            exit_=result['sideExits'][-1];assert values[exit_['guard']]==1-guard and values[exit_['target']]==state['rax']
            assert {name:values[ref] for name,ref in exit_['registers'].items()}==alternate
            assert values[exit_['currentMemory']]==(memory,writes)
        assert all(values[s['guard']]==1 for s in result['stores'])
        n+=1;count+=1
    rows.append({'case':kind,'numericStates':n})
assert count==576
print(json.dumps({'status':'passed-independent-native-memory-formulas','numericStates':count,'reports':9,'cases':rows,
 'targetExecuted':False,'architectureProved':False,'businessAccepted':False,'wholeBinaryVerified':False}))
