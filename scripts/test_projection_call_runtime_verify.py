"""Independent CALL/RET instruction formulas for real decoded public reports."""
from pathlib import Path
import hashlib,json,random,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from projection_numerical_oracle import MASK,NAMES,projection_values,total_byte
data=json.loads(Path(sys.argv[1]).read_bytes());actual=data.get('actualRequest') is not None
assert len(data['cases'])==(15 if actual else 9) and sum(not c['rejected'] for c in data['cases'])==(8 if actual else 6)
rng=random.Random(0x43414c4e);rows=[];count=0
for c in data['cases']:
    if c['rejected']:continue
    response=c['result'];raw=Path(response['reportPath']).read_bytes();assert hashlib.sha256(raw).hexdigest()==response['reportSha256'];r=json.loads(raw)['result']
    kind=c['id'];n=0
    for index in range(64):
        initial={name:rng.getrandbits(64) for name in NAMES};initial['rsp']=[0,1,MASK-7,MASK,initial['rsp']][index%5]
        memory=total_byte(rng.getrandbits(64));wanted=dict(initial);writes={};selected=c['args'].get('projection_registers',NAMES)
        def store(address,value):
            for i in range(8):writes[(address+i)&MASK]=(value>>(8*i))&255
        if kind=='actual-ultra-local-table-base-definition':wanted['r11']=0x140056098;destination=0x14005211e
        else:
            ea=int(c['args'].get('projection_path',['0x140001000'])[0],16)
            return_address=0x1400141b4 if kind=='actual-ultra-same-entry-call-request' else ea+5
            if kind=='actual-ultra-same-entry-call-request':store(initial['rsp']-8,0xfffffffff2e7defb);wanted['rsp']=(initial['rsp']-16)&MASK
            else:wanted['rsp']=(initial['rsp']-8)&MASK
            store(wanted['rsp'],return_address)
            destination=0x140001020
            if kind=='rel32-positive-limit':destination=(ea+5+0x7fffffff)&MASK
            elif kind=='rel32-negative-limit':destination=(ea+5-0x80000000)&MASK
            elif kind=='actual-ultra-same-entry-call-request':destination=0x140052000
            if kind in ('project-call-callee-return','compose-call-callee-return'):
                wanted['rsp']=initial['rsp'];wanted['rax']=initial['rcx'];destination=return_address
        v=projection_values(r,initial,memory)
        assert {name:v[identity] for name,identity in r['registers'].items()}=={name:wanted[name] for name in selected},kind
        assert v[r['currentMemory']]==(memory,writes),kind
        assert v[r['control']['target']]==destination,kind
        if r['control'].get('transfer')=='call':assert r['control']['returnAddress']==hex(return_address)
        n+=1;count+=1
    rows.append({'case':kind,'numericStates':n})
assert count==(512 if actual else 384)
print(json.dumps({'status':'passed-independent-direct-call-stack-control-formulas','numericStates':count,'reports':8 if actual else 6,'cases':rows,
 'nativeTargetExecuted':False,'architectureProved':False,'businessAccepted':False,'wholeBinaryVerified':False}))
