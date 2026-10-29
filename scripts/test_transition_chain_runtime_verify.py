"""Independent formula check of actual Ultra78/136 public chain reports.

Only existing hash-bound reports and the owned raw PE are read. No PE executes.
All file bytes below are test memory inputs, never premises injected by IG5.
"""
from pathlib import Path
import hashlib, json, random, sys
sys.path[:0]=[str(Path(__file__).resolve().parent),str(Path(__file__).resolve().parents[1]/'worker')]
from projection_numerical_oracle import total_byte,projection_values,NAMES,MASK
from kernel_image import BinaryImage
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
receipt=Path(sys.argv[sys.argv.index('--receipt')+1]);observed=json.loads(receipt.read_bytes())
assert observed['passed'] and len(observed['cases'])==5
accepted=[c for c in observed['cases'] if c['representation']=='transition-chain']
image=BinaryImage.from_file(accepted[0]['args']['target']);vip=image.imagebase+0x846c4;table=image.imagebase+0x56098
overrides={vip+i:v for i,v in enumerate(image.read(vip,40))};overrides.update({table+i:v for i,v in enumerate(image.read(table,1024))})
previous=Path(r'C:\Users\IG5User\Desktop\无限五代\_research\entry-context-invariants-20261016-v1\init-composition-verified.json')
old={c['applications']:c for c in json.loads(previous.read_bytes())['cases'] if not c['rejected']}
rng=random.Random(0x7472616e736974);rows=[]
for case in accepted:
    file=Path(case['result']['reportPath']);assert sha(file)==case['result']['reportSha256'];core=json.loads(file.read_bytes())['result']
    oldcore=None
    if case['applications'] in old:
        previous_case=old[case['applications']];assert sha(previous_case['result']['reportPath'])==previous_case['result']['reportSha256']
        oldcore=json.loads(Path(previous_case['result']['reportPath']).read_bytes())['result']
    positive=negative=0
    for sample in range(128):
        initial={n:rng.getrandbits(64) for n in NAMES};initial.update(rsp=0x100000,rbp=0x101000,rsi=vip+1,r11=table)
        if sample%2:initial['rsp']=(vip+2-overrides[vip+1])&MASK
        # Raw table entries are all distinct. The first stack write deliberately
        # puts opcode78 where the selected next handler requires136.
        initialbytes={**overrides,**({initial['rbp']:78} if sample%2 else {})}
        origin=total_byte(rng.getrandbits(64),initialbytes);state=dict(initial);memory={};stores=[];exits=[];boundaries=[];guard=1
        def load(a,n):return sum((memory[(a+j)&MASK] if (a+j)&MASK in memory else origin((a+j)&MASK))<<(8*j) for j in range(n))
        def put(a,value):
            a&=MASK;before=dict(memory)
            for j in range(8):memory[(a+j)&MASK]=(value>>(8*j))&255
            stores.append((a,value,guard,before,dict(memory)))
        for step in range(case['applications']):
            before=dict(state);value=load(state['rbp'],8);index=load(state['rsi'],1);put(state['rsp']+index,value)
            state.update(rbp=(before['rbp']+8)&MASK,rsi=(before['rsi']+1)&MASK)
            if step%2==0:state.update(rdi=value,r10=index)
            else:state.update(rbx=value,rax=index)
            selector=load(before['rsi']+1,1);word=load(before['r11']+4*selector,4)
            destination=(before['r11']+(word if word<1<<31 else word-(1<<32)))&MASK
            state.update(rax=selector,r8=destination,rsi=(before['rsi']+2)&MASK);put(before['rsp']-8,destination)
            entry=guard
            if step+1<case['applications']:
                selected=int(destination==int(case['args']['composition_plan']['paths'][step+1][0],16))
                exits.append((int(bool(guard) and not selected),destination,dict(state),dict(memory)))
                guard=int(bool(guard) and selected)
            boundaries.append((entry,guard,dict(state),dict(memory),destination))
        values=projection_values(core,initial,origin)
        assert {n:values[i] for n,i in core['registers'].items()}==state
        assert values[core['currentMemory']]==(origin,memory) and values[core['pathGuard']]==guard
        assert values[core['control']['target']]==destination
        assert len(stores)==len(core['stores']) and len(exits)==len(core['sideExits'])
        for s,(address,value,entry,before,after) in zip(core['stores'],stores):
            assert s['size']==8 and (values[s['address']],values[s['value']],values[s['guard']])==(address,value,entry)
            assert values[s['beforeMemory']]==(origin,before) and values[s['afterMemory']]==(origin,after)
        for e,(g,t,regs,mem) in zip(core['sideExits'],exits):
            assert (values[e['guard']],values[e['target']])==(g,t) and values[e['currentMemory']]==(origin,mem)
            assert {n:values[i] for n,i in e['registers'].items()}==regs
        for b,(entry,g,regs,mem,t) in zip(core['boundaries'],boundaries):
            assert (values[b['entryGuard']],values[b['continuedGuard']],values[b['control']['target']])==(entry,g,t)
            assert values[b['currentMemory']]==(origin,mem) and {n:values[i] for n,i in b['registers'].items()}==regs
        if oldcore:
            oldvalues=projection_values(oldcore,initial,origin)
            assert {n:oldvalues[i] for n,i in oldcore['registers'].items()}==state
            assert oldvalues[oldcore['currentMemory']]==(origin,memory) and oldvalues[oldcore['pathGuard']]==guard
        if sample%2:assert guard==0;negative+=1
        else:positive+=guard
    rows.append({'applications':case['applications'],'states':128,'unalteredTestFileMemoryFinalGuardTrue':positive,
        'deliberateNextOpcodeClobberGuardFalse':negative,'comparedPreviousFlatFinalState':bool(oldcore),
        'all16GPRsFullMemoryOrderedStoresEntryGuardsComplementaryExitsAndBoundariesCompared':True,
        'retainedDepth':core['dag']['depth'],'expandedDependencyDepth':core['dag']['expandedDependencyDepth'],
        'nodes':len(core['dag']['nodes']),'references':core['dag']['references'],'reportSha256':sha(file)})
failure=observed['cases'][-1];assert failure['representation']=='flat' and failure['rejected'] and 'DAG depth budget exceeded' in failure['error']
output={'passed':True,'receipt':str(receipt),'receiptSha256':sha(receipt),'cases':rows,'totalStates':sum(r['states'] for r in rows),
    'verifierSourceSha256':sha(__file__),'defaultFlat16RefusalRetained':True,'nativeTargetExecuted':False,'businessAccepted':False,'wholeBinaryVerified':False,
    'scope':'Independent ordinary GPR/memory/control formula and finite inputs. A false guard makes later hypothetical state invalid as an executed continuation. File-memory fixtures are not native reachability/ASLR/CPU/full-business proof.'}
destination=receipt.parent/'independent-reference.json';destination.write_text(json.dumps(output,indent=2)+'\n',encoding='utf8')
print(json.dumps(output))
