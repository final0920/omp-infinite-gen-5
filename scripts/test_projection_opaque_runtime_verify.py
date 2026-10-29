"""Full saved public reports vs independent unsliced raw/opaque formulas."""
from pathlib import Path
import hashlib,json,random,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from projection_raw_oracle import run_raw,opaque_values
from projection_numerical_oracle import total_byte,NAMES,MASK
data=json.loads(Path(sys.argv[1]).read_bytes());actual=data['actualGraph'] is not None
assert len(data['cases'])==(29 if actual else 27) and sum(not c['rejected'] for c in data['cases'])==(22 if actual else 21)
rng=random.Random(0x6f706171);rows=[];total=0
for case in data['cases']:
    if case['rejected']:continue
    response=case['result'];b=Path(response['reportPath']).read_bytes();assert hashlib.sha256(b).hexdigest()==response['reportSha256'];r=json.loads(b)['result']
    assert r['schema']=='ig5-pcode-opaque-projection-v1';raw=[{**v['decoded'],'codeBytes':v['bytes']} for v in r['decodedPath']]
    assert len(r['stores'])==response['storeCount'] and r['statistics']['pcodeOperations']==sum(len(v['pcode']) for v in raw)
    for index in range(64):
        initial={n:rng.getrandbits(64) for n in NAMES};initial['rsp']=[0,1,7,8,MASK,MASK-7,initial['rsp']][index%7]
        if case['id']=='actual-ultra-full98-opaque' and index%4==0:initial['rsp']=[0x1400846c4+136,0x140056098+136,0x1400846c4+8,0x140056098+8][(index//4)%4]
        if case['id']=='unknown-alias-read':initial['rcx']=(initial['rsp']+[-8,-7,-4,0,8192][index%5])&MASK
        memory=total_byte(rng.getrandbits(64));unknowns={e['instructionIndex']:rng.getrandbits(64) for e in r['opaqueEffects']}
        wanted=run_raw(raw,initial,memory,unknowns,rng.getrandbits(6));v=opaque_values(r,initial,memory,unknowns)
        assert {n:v[i] for n,i in r['registers'].items()}==wanted['registers'],(case['id'],index,'GPRs')
        assert v[r['currentMemory']]==(memory,wanted['memoryWrites']),(case['id'],index,'full memory')
        stores=[{'instructionIndex':s['instructionIndex'],'pcodeIndex':s['pcodeIndex'],'address':v[s['address']],'value':v[s['value']],'size':s['size']} for s in r['stores']]
        assert stores==wanted['stores'],(case['id'],index,'all ordered stores')
        assert r['control']['kind']==wanted['control']['kind'] and v[r['control']['target']]==wanted['control']['target'],(case['id'],index,'control')
        total+=1
    rows.append({'case':case['id'],'numericStates':64,'orderedStores':len(r['stores'])})
assert total==(1408 if actual else 1344)
print(json.dumps({'status':'passed-unsliced-raw-and-independent-opaque-data-formulas','numericStates':total,'acceptedReports':len(rows),'cases':rows,
 'scope':'Complete selected16GPRs, ordered STORE effects, coherent total wrapping memory and final control; boundary/random/alias states. Local fixed-path data abstraction only, no CPU/SMT/native reachability/all-input/business proof.',
 'nativeTargetExecuted':False,'architectureProved':False,'businessAccepted':False,'wholeBinaryVerified':False}))
