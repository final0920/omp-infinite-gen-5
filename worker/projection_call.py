"""Exact fixed-decoder AMD64 E8 rel32 near CALL structure.

This recognizes a transfer plus its eight-byte return-address store, never an
ABI/callee summary. Prefixes, indirect/far calls and other p-code forms reject.
"""
import hashlib,json

class CallRejected(ValueError):pass

def match_direct_call(instruction,operations):
    raw=instruction.get('codeBytes');named=instruction.get('mnemonic')=='CALL'
    present=any(op.get('opcode')=='CALL' for op in operations)
    encoded=type(raw) is str and len(raw)==10 and raw[:2].lower()=='e8'
    if not (named or present or encoded):return None
    def require(condition,message):
        if not condition:raise CallRejected(message)
    require(named and encoded and instruction.get('size')==5,'direct CALL requires unprefixed5-byte E8 rel32 and complete matching decode')
    try:code=bytes.fromhex(raw);ea=int(instruction['ea'],16)
    except (TypeError,ValueError,KeyError):raise CallRejected('invalid direct CALL byte/address binding')
    require(0<=ea<=(1<<64)-6,'direct CALL return address exceeds uint64')
    return_address=ea+5;destination=(return_address+int.from_bytes(code[1:],'little',signed=True))&((1<<64)-1)
    # Fixed SLEIGH uses BRANCH for E8 rel0's transfer to the next instruction.
    # The complete stack/store/control shape below is still required. Keep the
    # original BRANCH and its hash; never rewrite raw pcode into a fabricated CALL.
    rel0_branch=(code==b'\xe8\0\0\0\0' and not present and bool(operations) and operations[-1].get('opcode')=='BRANCH')
    require(present or rel0_branch,'direct CALL requires unprefixed5-byte E8 rel32 and complete matching decode')
    reg={'space':'register','size':8,'offset':0x20}
    constant=lambda value:{'space':'const','size':8,'offset':value}
    target={'space':'ram','size':8,'offset':destination}
    expected=[{'opcode':'INT_SUB','output':reg,'inputs':[reg,constant(8)]},
              {'opcode':'STORE','output':None,'inputs':[reg,constant(return_address)]},
              {'opcode':'BRANCH' if rel0_branch else 'CALL','output':None,'inputs':[target]}]
    require(operations==expected,'direct CALL requires exact RSP-8/store-return-address/control p-code structure')
    return {'kind':'amd64-e8-rel32-fixed-stack-transfer-v1','codeBytes':code.hex(),
            'target':hex(destination),'returnAddress':hex(return_address),'stackDelta':-8,'stackWriteBytes':8,
            'rawPcodeSemanticSha256':hashlib.sha256(json.dumps(operations,sort_keys=True,separators=(',',':')).encode('ascii')).hexdigest(),
            'calleeSummaryUsed':False,
            **({'decoderControlOpcode':'BRANCH','decoderForm':'canonical-e8-rel0-branch-next-v1'} if rel0_branch else {})}
