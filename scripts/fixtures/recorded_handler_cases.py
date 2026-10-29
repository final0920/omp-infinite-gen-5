"""Synthetic byte/pcode declarations only; no decoder, target or CPU executes."""
import copy,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'worker'),str(ROOT/'scripts')]
from pcode_projection import GPRS,project
from test_pcode_projection import ins,op,reg,tmp,const,target,RAM,append_path
from test_pcode_status import ADD,PUSH,POP

def finish(rows,conditional=False):
    rows=append_path(*rows)
    ea=int(rows[-1]['ea'],16)+rows[-1]['size'];size=6 if conditional else 5
    code=('0f83' if conditional else 'e9')+((0x2000-ea-size)&0xffffffff).to_bytes(4,'little').hex()
    tail=ins(*([op('BOOL_NEGATE',tmp(900,1),{'space':'register','offset':'0x200','size':1}),op('CBRANCH',None,target(0x2000),tmp(900,1))] if conditional else [op('BRANCH',None,target(0x2000))]),ea=ea,mnemonic='JAE' if conditional else 'JMP',code=code)
    rows.append(tail);r=project(rows,list(GPRS),mode='opaque-status')
    r.update(targetSha256='a'*64,nativeTargetExecuted=False,databaseModified=False,businessAccepted=False,wholeBinaryVerified=False)
    r['decodedPath']=[{'ea':i['ea'],'bytes':i['codeBytes'],'decoded':i} for i in rows]
    r['projectionPath']=[i['ea'] for i in rows]
    return r

simple=finish([ins(op('LOAD',reg('rax'),RAM,reg('rbx')),mnemonic='MOV',code='488b03'),
    ins(op('INT_NEGATE',reg('rax'),reg('rax')),mnemonic='NOT',code='48f7d0'),
    ins(op('STORE',None,RAM,reg('rcx'),reg('rax')),mnemonic='MOV',code='488901')])
conditional=finish([copy.deepcopy(ADD)],True)
opaque=finish([copy.deepcopy(ADD),copy.deepcopy(PUSH),copy.deepcopy(POP)])
print(json.dumps([simple,conditional,opaque]))
