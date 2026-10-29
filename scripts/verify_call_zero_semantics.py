"""Independent source/data/typed-query readback. No solver or CPU rerun."""
from pathlib import Path
import argparse,hashlib,json,sys
MAIN=Path(__file__).resolve().parents[1];sys.path[:0]=[str(MAIN/'worker'),str(MAIN/'scripts')]
from lift_runtime import locked_file
from composition_domain_smt import validate,GPRS
from kernel_image import BinaryImage

def load(path,pin=None,maximum=4*1024**2):
    path=Path(path);assert path.is_absolute() and '..' not in path.parts
    with locked_file(path,maximum) as raw:
        digest=hashlib.sha256(raw).hexdigest();assert pin is None or digest==pin;return json.loads(raw),digest

def verify(source):
    proof,digest=load(source);process,_=load(Path(source).parent/'process.json',maximum=65536)
    assert proof['schema']=='ig5-call-zero-ordinary-proof-v1' and proof['passed']
    assert process['exitCode']==0 and process['childExitConfirmed'] and process['jobAssignedAtCreation'] and process['activeProcessLimit']==1 and process['memoryLimitBytes']==2147483648
    for field,name in [('sourceProofScriptSha256','prove_call_zero_semantics.py'),('encoderSourceSha256','composition_domain_smt.py')]:
        with locked_file(MAIN/'scripts'/name,1024**2) as raw:assert hashlib.sha256(raw).hexdigest()==proof[field]
    receipt,_=load(proof['sourceReceipt']['path'],proof['sourceReceipt']['sha256']);assert receipt['passed'] and len(receipt['cases'])==3 and receipt['activeRequests']==0;cores={}
    with locked_file(Path(receipt['cases'][0]['args']['target']),4*1024**2) as raw:
        assert hashlib.sha256(raw).hexdigest()=='ef19e116449f152151b6f1a3a63d56da78acd2e4a0e98cbcca6486aa038d756b';image=BinaryImage.from_bytes(raw)
    for name,ref in proof['reports'].items():
        case=next(x for x in receipt['cases'] if x['id']==name);assert not case['rejected'] and case['cleanupConfirmed'] and case['rootExitConfirmed']
        assert Path(case['result']['reportPath']).resolve()==Path(ref['path']).resolve() and case['result']['reportSha256']==ref['sha256']
        record,_=load(ref['path'],ref['sha256']);c=record['result'];nodes=validate(c);cores[name]=c
        assert all(image.read(int(r['ea'],16),r['decoded']['size']).hex()==r['bytes'] for r in c['decodedPath'])
        original=c['decodedPath'][0];assert original['bytes']=='e800000000' and len(original['decoded']['pcode'])==3 and original['decoded']['pcode'][-1]['opcode']=='BRANCH'
        if name=='zero-compose-ret':
            assert c['dag']['bindingCount']==36 and len(c['layers'])==2 and c['layers'][1]['inputRegisters']==c['layers'][0]['registers'] and c['layers'][1]['inputMemory']==c['layers'][0]['currentMemory']
            assert c['boundaries'][0]['control']['transfer']=='call' and c['boundaries'][0]['control']['returnAddress']=='0x140001005'
        else:
            d=c['path'][0]['directCall'];assert d['decoderControlOpcode']=='BRANCH' and d['decoderForm']=='canonical-e8-rel0-branch-next-v1' and d['calleeSummaryUsed'] is False
            rsp={'space':'register','size':8,'offset':0x20};constant=lambda n:{'space':'const','size':8,'offset':n}
            normalized=[{'opcode':'INT_SUB','output':rsp,'inputs':[rsp,constant(8)]},{'opcode':'STORE','output':None,'inputs':[rsp,constant(0x140001005)]},{'opcode':'BRANCH','output':None,'inputs':[{'space':'ram','size':8,'offset':0x140001005}]}]
            assert d['rawPcodeSemanticSha256']==hashlib.sha256(json.dumps(normalized,sort_keys=True,separators=(',',':')).encode('ascii')).hexdigest()
        assert len(c['stores'])==1 and c['stores'][0]['pcodeIndex']==1 and c['stores'][0]['size']==8
        assert all(c[k] is False for k in ('nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'))
    rows=proof['queries'];assert len(rows)==4 and len({r['name'] for r in rows})==4
    for i,row in enumerate(rows):
        assert row['status']==row['expected']==('sat' if i==3 else 'unsat') and 0<row['timeoutMs']<=2000
        assert row['wholeSourceDagValidated'] and not row['explicitCuts'] and not row['cutNames'] and not row['weakenedLoadNodes']
        assert row['encodedDepth']<=128 and row['encodedSexpressions']<=2048 and row['encodedAtomTokens']<=8192
        c=cores[row['sourceCase']];assert all(type(n) is int and 0<=n<len(c['dag']['nodes']) for n in row['rootNodes'])
        if i<3:assert row['rootNodes'][:18]==[*[c['registers'][n] for n in GPRS],c['currentMemory'],c['control']['target']]
        else:assert row['sourceCase']=='zero-ret' and row['rootNodes']==[c['currentMemory']]
        with locked_file(Path(row['path']),1024**2) as raw:
            assert len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256'];text=raw.decode('ascii')
        assert f'(set-option :timeout {row["timeoutMs"]})' in text and '(set-option :memory_max_size 512)' in text and text.endswith('(check-sat)\n')
    assert proof['completeStateQueries']==[0,1,2] and proof['memoryEffectNegativeQuery']==3 and proof['numeric']['uniqueStates']==264 and proof['numeric']['reportEvaluations']==792
    assert all(proof[k] is False for k in ('nativeTargetExecuted','databaseModified','architectureProved','businessAccepted','wholeBinaryVerified'))
    return {'schema':'ig5-call-zero-independent-readback-v1','passed':True,'proofSha256':digest,'queries':4,'unsat':3,'sat':1,'unknown':0,'allOriginalBytesTypedCompleteDagsUncutRootsAndQueryBudgetsChecked':True,'exactCompositionBindingsChecked':True,'numericStatesReadBack':264,'scope':'Independent certificate readback only; no solver/CPU rerun. No ABI/native reachability or complete VM business claim.','businessAccepted':False,'wholeBinaryVerified':False}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--proof',required=True);p.add_argument('--out',required=True);a=p.parse_args();result=verify(a.proof);out=Path(a.out);assert out.is_absolute()
    with out.open('x',encoding='utf8') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps(result))
