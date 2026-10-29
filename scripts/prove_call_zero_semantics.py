"""Full ordinary-state certificate for byte-bound E8 rel0, never CPU execution."""
from pathlib import Path
from contextlib import ExitStack
import argparse,hashlib,json,random,sys,time
MAIN=Path(__file__).resolve().parents[1];sys.path[:0]=[str(MAIN/'worker'),str(MAIN/'scripts')]
from composition_domain_smt import GPRS,Queries,encode,bv,sub,store,sha
from projection_numerical_oracle import MASK,projection_values,total_byte
TARGET='ef19e116449f152151b6f1a3a63d56da78acd2e4a0e98cbcca6486aa038d756b'

def main():
    p=argparse.ArgumentParser()
    for key in ('receipt','receipt-sha','out'):p.add_argument('--'+key,required=True)
    p.add_argument('--child',action='store_true');a=p.parse_args();out=Path(a.out)
    assert Path(a.receipt).is_absolute() and out.is_absolute()
    from lift_runtime import locked_file
    if not a.child:
        from lift_process import run_owned
        out.mkdir(exist_ok=False);job=out/'job';job.mkdir()
        process=run_owned(str(MAIN/'runtimes/ghidra/python/python.exe'),['-I','-B','-X','utf8',str(Path(__file__)),*sys.argv[1:],'--child'],job,budget_ms=50000)
        (out/'process.json').write_text(json.dumps(process,indent=2)+'\n',encoding='utf8');assert process['childExitConfirmed'] and process['jobAssignedAtCreation']
        if process['exitCode']!=0:
            with locked_file(job/'stderr.log',4*1024**2) as raw:error=raw.decode('utf8')
            with locked_file(job/'stdout.log',4*1024**2) as raw:error+='\n'+raw.decode('utf8')[-8192:]
            raise AssertionError(error)
        with locked_file(out/'verified.json',4*1024**2) as raw:v=json.loads(raw)
        print(json.dumps({'passed':v['passed'],'queries':len(v['queries']),'statuses':{s:sum(r['status']==s for r in v['queries']) for s in ('unsat','sat','unknown')},'numeric':v['numeric'],'verifiedSha256':sha(out/'verified.json'),'process':process}));return
    deadline=time.monotonic()+45
    with ExitStack() as held:
        def load(path,pin):
            raw=held.enter_context(locked_file(Path(path),4*1024**2));assert hashlib.sha256(raw).hexdigest()==pin;return json.loads(raw)
        receipt=load(a.receipt,a.receipt_sha);assert receipt['passed'] and len(receipt['cases'])==3 and receipt['activeRequests']==0
        cores={};refs={}
        for case in receipt['cases']:
            assert not case['rejected'] and case['cleanupConfirmed'] and case['rootExitConfirmed']
            ref=case['result'];cores[case['id']]=load(ref['reportPath'],ref['reportSha256'])['result'];refs[case['id']]={'path':ref['reportPath'],'sha256':ref['reportSha256']}
        from kernel_image import BinaryImage
        data=held.enter_context(locked_file(Path(receipt['cases'][0]['args']['target']),4*1024**2));assert hashlib.sha256(data).hexdigest()==TARGET;image=BinaryImage.from_bytes(data)
        assert image.read(0x140001000,6).hex()=='e800000000c3'
        q=Queries(MAIN,out/'queries',deadline)
        try:
            equations=[]
            for name,c in cores.items():
                assert c['targetSha256']==TARGET and all(c[k] is False for k in ('nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'))
                assert all(image.read(int(r['ea'],16),r['decoded']['size']).hex()==r['bytes'] for r in c['decodedPath'])
                original=c['decodedPath'][0]['decoded'];assert original['mnemonic']=='CALL' and original['pcode'][-1]['opcode']=='BRANCH' and len(original['pcode'])==3
                root=[c['registers'][n] for n in GPRS]+[c['currentMemory'],c['control']['target']]+[s[k] for s in c['stores'] for k in ('address','value','beforeMemory','afterMemory')]
                address=sub('I_rsp',bv(8));memory=store('M0',address,bv(0x140001005),8)
                want=[address if n=='rsp' and name=='zero-terminal' else 'I_'+n for n in GPRS]+[memory,bv(0x140001005),address,bv(0x140001005),'M0',memory]
                lines,actual,meta=encode(c,root);meta.update(sourceCase=name,rootNodes=root,cutNames={})
                pred='(or '+' '.join(f'(distinct {x} {y})' for x,y in zip(actual,want))+')';assert len(actual)==len(want) and len(c['stores'])==1
                i=q.expect(q.query(name+'-all16-entire-memory-ordered-store-and-control','\n'.join(lines)+'\n(assert '+pred+')',metadata=meta));equations.append(i)
            c=cores['zero-ret'];lines,actual,meta=encode(c,[c['currentMemory']]);meta.update(sourceCase='zero-ret',rootNodes=[c['currentMemory']],cutNames={})
            negative=q.expect(q.query('negative-call-ret-does-not-erase-return-address-memory-effect','\n'.join(lines)+f'\n(assert (distinct {actual[0]} M0))','sat',meta))
            rng=random.Random(0x72656c3073746163);stacks=[0,1,7,8,MASK-7,MASK,(1<<63)-1,1<<63]+[rng.getrandbits(64) for _ in range(256)]
            for stack in stacks:
                assert time.monotonic()<deadline;initial={n:rng.getrandbits(64) for n in GPRS};initial['rsp']=stack;origin=total_byte(rng.getrandbits(64));writes={((stack-8+i)&MASK):(0x140001005>>(8*i))&255 for i in range(8)}
                for name,c in cores.items():
                    v=projection_values(c,initial,origin);expected={**initial,**({'rsp':(stack-8)&MASK} if name=='zero-terminal' else {})}
                    assert {n:v[i] for n,i in c['registers'].items()}==expected and v[c['currentMemory']]==(origin,writes) and v[c['control']['target']]==0x140001005
                    s=c['stores'][0];assert v[s['address']]==(stack-8)&MASK and v[s['value']]==0x140001005 and v[s['beforeMemory']]==(origin,{}) and v[s['afterMemory']]==(origin,writes)
                    if 'pathGuard' in c:assert v[c['pathGuard']]==1 and not c['sideExits']
            result={'schema':'ig5-call-zero-ordinary-proof-v1','passed':True,'sourceReceipt':{'path':a.receipt,'sha256':a.receipt_sha},'reports':refs,'queries':q.rows,'completeStateQueries':equations,'memoryEffectNegativeQuery':negative,
                'numeric':{'uniqueStates':264,'reportEvaluations':792,'all16WholeMemoryOrderedStoreControlChecked':True,'includesStackWraparound':True,'sameBatchesAcrossDeploymentsNotExtraCoverage':True,'notIndependentCPUInterpreter':True},
                'sourceProofScriptSha256':sha(__file__),'encoderSourceSha256':sha(MAIN/'scripts/composition_domain_smt.py'),'solverDllSha256':q.dll_sha,
                'limits':{'queries':128,'queryTimeoutMs':2000,'queryMemoryMiB':512,'sharedSeconds':45,'ownedJobSeconds':50,'ownedJobMemoryBytes':2147483648},
                'scope':'Uncut all16/whole-byte-memory equations for terminal CALLrel0, explicit CALLrel0->RET and exact-binding public composition. Full original3-op BRANCH shape preserved. No ABI/CET/OS/fault/native reachability/CPU/VM-business theorem.',
                'nativeTargetExecuted':False,'databaseModified':False,'architectureProved':False,'businessAccepted':False,'wholeBinaryVerified':False}
            raw=(json.dumps(result,indent=2)+'\n').encode('utf8');assert len(raw)<=4*1024**2 and time.monotonic()<deadline
            with (out/'verified.json').open('xb') as f:f.write(raw)
        finally:q.close()

if __name__=='__main__':main()
