"""Independent arithmetic/ordered-byte memory checks of real compose reports."""
from pathlib import Path
import hashlib,json,random,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from projection_numerical_oracle import MASK,NAMES,projection_values,total_byte
data=json.loads(Path(sys.argv[1]).read_bytes());cases=data['cases'];assert len(cases)==13
assert sum(not c['rejected'] for c in cases)==6
rng=random.Random(0x434f4d50);checked=0;rows=[]
for case in cases:
    if case['rejected']:continue
    public=case['result'];raw=Path(public['reportPath']).read_bytes();assert hashlib.sha256(raw).hexdigest()==public['reportSha256']
    report=json.loads(raw)['result'];assert report['schema']=='ig5-pcode-composition-v1' and report['publicToolRouteExposed'] is True
    assert set(report['registers'])==set(NAMES) and report['businessAccepted'] is False
    count=0
    for i in range(64):
        initial={n:rng.getrandbits(64) for n in NAMES};overrides={};kind=case['id']
        if kind=='guarded-indirect':initial['rax']=0x140001100 if i%2==0 else rng.getrandbits(64)
        if kind=='guarded-return':
            initial['rsp']=(MASK-3) if i%3==0 else rng.getrandbits(64)
            target=0x140001100 if i%2==0 else rng.getrandbits(64)
            overrides={(initial['rsp']+n)&MASK:(target>>(8*n))&255 for n in range(8)}
        if kind in ('guarded-stores','memory-limit-exact'):
            initial.update(rdi=MASK-3,rsi=(MASK-3+(i%15)-7)&MASK)
            if kind=='guarded-stores':initial['rdx']=0x140001180 if i%2==0 else rng.getrandbits(64)
        memory=total_byte(rng.getrandbits(64),overrides);wanted=dict(initial);writes={};guard=1;exit_state=None;exit_target=None
        def load(address):return sum((writes[(address+n)&MASK] if (address+n)&MASK in writes else memory((address+n)&MASK))<<(8*n) for n in range(8))
        def store(address,value):
            for n in range(8):writes[(address+n)&MASK]=(value>>(8*n))&255
        if kind=='sequence':wanted.update(rax=42,rcx=42)
        elif kind=='constant-loop':wanted.update(rax=0,rbx=0);assert report['inferredRepeat']['bodyApplicationsAfterPrefix']==2
        elif kind in ('guarded-indirect','guarded-return'):
            if kind=='guarded-return':wanted['rsp']=(initial['rsp']+8)&MASK;exit_target=load(initial['rsp'])
            else:exit_target=initial['rax']
            exit_state=dict(wanted);guard=int(exit_target==0x140001100);wanted['rcx']=wanted['rax']
        elif kind=='guarded-stores':
            store(initial['rdi'],initial['rax']);exit_state=dict(wanted);exit_target=initial['rdx'];guard=int(exit_target==0x140001180)
            before=dict(writes);store(initial['rsi'],initial['rbx'])
        elif kind=='memory-limit-exact':
            wanted['rax']=load(initial['rdi']);wanted['rbx']=load(initial['rsi'])
            assert report['statistics']['expandedMemoryBytes']==1024
        else:raise AssertionError(kind)
        values=projection_values(report,initial,memory)
        assert {n:values[node] for n,node in report['registers'].items()}==wanted,kind
        assert values[report['currentMemory']]==(memory,writes),kind
        assert values[report['pathGuard']]==guard,kind
        if exit_state is not None:
            side=report['sideExits'][-1]
            assert {n:values[node] for n,node in side['registers'].items()}==exit_state
            assert values[side['target']]==exit_target and values[side['guard']]==1-guard
            assert values[side['currentMemory']]==(memory,before if kind=='guarded-stores' else {})
        if kind=='guarded-stores':assert [values[s['guard']] for s in report['stores']]==[1,guard]
        if kind=='constant-loop':assert all(values[e['guard']]==0 for e in report['sideExits'])
        count+=1;checked+=1
    rows.append({'case':case['id'],'numericStates':count})
assert checked==384
print(json.dumps({'status':'passed-independent-numerical-state-memory-guard-comparison','numericStates':checked,'reports':6,'cases':rows,
    'nativeTargetExecuted':False,'architectureProved':False,'businessAccepted':False,'wholeBinaryVerified':False}))
