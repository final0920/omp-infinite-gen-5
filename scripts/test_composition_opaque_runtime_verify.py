"""Whole-chain consistency and an independent ordinary handler reference.

The entry oracle is the earlier immutable, independently cross-checked entry
projection, NOT an independent CPU interpreter. Handler equations are separately
derived. No observed register/data values become product-analysis premises.
"""
from pathlib import Path
import hashlib,json,random,sys
sys.path[:0]=[str(Path(__file__).resolve().parent),str(Path(__file__).resolve().parents[1]/'worker')]
from projection_numerical_oracle import projection_values,total_byte,NAMES,MASK
from kernel_image import BinaryImage
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
receipt=Path(sys.argv[sys.argv.index('--receipt')+1]);record=json.loads(receipt.read_bytes());assert record['passed']
reference=record['entryReference'];assert sha(reference['path'])==reference['sha256']
entry=json.loads(Path(reference['path']).read_bytes())['result'];assert len(entry['stores'])==21 and len(entry['nondeterministicInputs'])==1
accepted=[c for c in record['cases'] if not c['rejected']];assert len(accepted)==4
image=BinaryImage.from_file(accepted[0]['args']['target']);vip=image.imagebase+0x846c4;table=image.imagebase+0x56098
overrides={vip+i:v for i,v in enumerate(image.read(vip,64))};overrides.update({table+i:v for i,v in enumerate(image.read(table,1024))})
rng=random.Random(0x656e747279636861);rows=[]
for case in accepted:
    report=case['result'];assert sha(report['reportPath'])==report['reportSha256'];core=json.loads(Path(report['reportPath']).read_bytes())['result']
    guard_true=alias_false=all_false=0
    for sample in range(128):
        initial={n:rng.getrandbits(64) for n in NAMES}
        initial['rsp']=(0x100000+sample*16 if sample<64 else [0,1,7,MASK-7,MASK][sample%5] if sample<96 else vip-192+(sample-96)*16)
        origin=total_byte(rng.getrandbits(64),overrides);state=dict(initial);memory={};guard=1;stores=[];exits=[];boundaries=[]
        unknowns={core['dag']['nodes'][x['node']]['name']:rng.getrandbits(64) for x in core['nondeterministicInputs']}
        def read(a,n):return sum((memory[(a+j)&MASK] if (a+j)&MASK in memory else origin((a+j)&MASK))<<(8*j) for j in range(n))
        def put(a,value,size,step,instruction,pcode):
            a&=MASK;before=dict(memory)
            for j in range(size):memory[(a+j)&MASK]=(value>>(8*j))&255
            stores.append({'address':a,'value':value,'size':size,'guard':guard,'before':before,'after':dict(memory),
                'stepIndex':step,'instructionIndex':instruction,'pcodeIndex':pcode})
        for step,path in enumerate(case['args']['composition_plan']['paths']):
            if path[0]==entry['decodedPath'][0]['ea']:
                before=dict(memory)
                def stage_origin(a,previous=before):return previous.get(a&MASK,origin(a&MASK))
                entry_unknowns={entry['dag']['nodes'][x['node']]['name']:unknowns[f"step_{step}_opaque_{x['instructionIndex']}"] for x in entry['nondeterministicInputs']}
                v=projection_values(entry,state,stage_origin,unknowns=entry_unknowns)
                for s in entry['stores']:put(v[s['address']],v[s['value']],s['size'],step,s['instructionIndex'],s['pcodeIndex'])
                state={n:v[i] for n,i in entry['registers'].items()};destination=v[entry['control']['target']]
                assert v[entry['currentMemory']][0] is stage_origin
                assert memory=={**before,**v[entry['currentMemory']][1]}
            else:
                before=dict(state);value=read(state['rbp'],8);index=read(state['rsi'],1)
                template=core['templates'][core['steps'][step]];native_stores=[s for s in core['stores'] if s['stepIndex']==step]
                assert len(native_stores)==2
                # Operand/value equations are independent of the product DAG.
                put(state['rsp']+index,value,8,step,native_stores[0]['instructionIndex'],native_stores[0]['pcodeIndex'])
                state.update(rbp=(before['rbp']+8)&MASK,rsi=(before['rsi']+1)&MASK)
                if int(path[0],16)==image.imagebase+0x5242b:state.update(rdi=value,r10=index)
                else:assert int(path[0],16)==image.imagebase+0x545b6;state.update(rbx=value,rax=index)
                selector=read(before['rsi']+1,1);word=read(before['r11']+4*selector,4)
                destination=(before['r11']+(word if word<1<<31 else word-(1<<32)))&MASK
                state.update(rax=selector,r8=destination,rsi=(before['rsi']+2)&MASK)
                put(before['rsp']-8,destination,8,step,native_stores[1]['instructionIndex'],native_stores[1]['pcodeIndex'])
            entry_guard=guard
            if step+1<len(case['args']['composition_plan']['paths']):
                selected=int(destination==int(case['args']['composition_plan']['paths'][step+1][0],16))
                exits.append((int(bool(guard) and not selected),destination,dict(state),dict(memory)))
                guard=int(bool(guard) and selected)
            boundaries.append((entry_guard,guard,dict(state),dict(memory),destination))
        actual=projection_values(core,initial,origin,unknowns=unknowns)
        assert {n:actual[i] for n,i in core['registers'].items()}==state
        assert actual[core['currentMemory']]==(origin,memory) and actual[core['control']['target']]==destination and actual[core['pathGuard']]==guard
        assert len(core['stores'])==len(stores) and len(core['sideExits'])==len(exits)
        for s,w in zip(core['stores'],stores):
            assert (actual[s['address']],actual[s['value']],s['size'],actual[s['guard']])==(w['address'],w['value'],w['size'],w['guard'])
            assert actual[s['beforeMemory']]==(origin,w['before']) and actual[s['afterMemory']]==(origin,w['after'])
            assert all(s[k]==w[k] for k in ('stepIndex','instructionIndex','pcodeIndex'))
        for b,(before,g,regs,mem,target) in zip(core['boundaries'],boundaries):
            assert (actual[b['entryGuard']],actual[b['continuedGuard']],actual[b['control']['target']])==(before,g,target)
            assert {n:actual[i] for n,i in b['registers'].items()}==regs and actual[b['currentMemory']]==(origin,mem)
        for e,(g,target,regs,mem) in zip(core['sideExits'],exits):
            assert (actual[e['guard']],actual[e['target']])==(g,target)
            assert {n:actual[i] for n,i in e['registers'].items()}==regs and actual[e['currentMemory']]==(origin,mem)
        guard_true+=guard;all_false+=not guard;alias_false+=int(sample>=96 and not guard)
    rows.append({'id':case['id'],'states':128,'finalGuardTrue':guard_true,'finalGuardFalse':all_false,'imageOverlapStatesWithFalseContinuation':alias_false,
        'all16GPRsEntireMemoryEveryStoreEntryGuardBoundaryAndSideExitCompared':True,'liveUnknowns':len(core['nondeterministicInputs']),
        'reportSha256':report['reportSha256']})
assert all(c['rejected'] and c['analysisFailure'] for c in record['cases'] if c['id'].endswith('refused'))
out={'passed':True,'receipt':str(receipt),'receiptSha256':sha(receipt),'cases':rows,'states':sum(r['states'] for r in rows),
    'entryOracle':reference,'verifierSourceSha256':sha(__file__),'entryOracleIsPriorProjectionNotIndependentCPUInterpreter':True,
    'handlerEquationsDerivedIndependently':True,'nativeTargetExecuted':False,'businessAccepted':False,'wholeBinaryVerified':False,
    'scope':'Conditional ordinary state consistency, including wrapped/overlapping memory and fresh opaque values. File-memory test inputs and low/disjoint test stacks are not native relocation/stack-allocation/reachability certificates. Guard-false later states are hypothetical only.'}
(receipt.parent/'reference-verified.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf8');print(json.dumps(out))
