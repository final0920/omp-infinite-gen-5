"""Byte-bound conservative replacements, never observations or exact semantics.

Only the pinned decoder's complete PUSHFQ, RDTSC and canonical16-bit BSWAP
shapes are recognized. Default strict project/compose never use replacements;
explicit opaque projection and opaque transition-chain templates may use them.
An arbitrary flag image deliberately loses its relation to status/control flags;
an arbitrary whole GPR deliberately loses even potentially preserved high bits.
This is a superset of ordinary fault-free data results, not a CPU model.
"""
import copy
import hashlib
import json
from projection_flags import FLAG_OFFSETS

FLAG_BITS={'cf':0,'pf':2,'af':4,'zf':6,'sf':7,'of':11}

REGISTERS = dict(zip('rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15'.split(),
                     [0,8,16,24,32,40,48,56,128,136,144,152,160,168,176,184]))
PUSHFQ_RAW_SHA = 'b716d890dc722444a6cf52e3952e04226c48692030b1ca45b8f4f4fffe0fe539'
RDTSC_RAW_SHA = 'c169e67f4e1028f5c1ee5f6440bd50b32a59486ae2b28d734fedb5d309d8c599'
BSWAP32_RAX_RAW_SHA = 'b850ce16167269126f00e2e292f71d5d1fe16b3db75293d863977d34ea2bc964'


class OpaqueRejected(ValueError):
    pass


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode('ascii')).hexdigest()


def _v(space, offset, size):
    return {'space':space, 'offset':hex(offset), 'size':size}


def _op(kind, output, *inputs):
    return {'opcode':kind, 'output':output, 'inputs':list(inputs)}


def advance_known_flags(known,policy,operations,ordinal,*,allow_defined=True):
    """Conservative forward provenance, never caller values or initial flags."""
    if policy['status']!='classified':return {}
    written=set();needed=set()
    for op in operations:
        for v in op['inputs']:
            if v['space']=='register':
                needed.update(n for n,a in FLAG_OFFSETS.items() if v['offset']<=a<v['offset']+v['size'] and n not in written)
        v=op['output']
        if v and v['space']=='register':written.update(n for n,a in FLAG_OFFSETS.items() if v['offset']<=a<v['offset']+v['size'])
    result={n:i for n,i in known.items() if n in policy['preserved']}
    if allow_defined and needed<=set(known):result.update({n:ordinal for n in policy['defined']})
    return result


def match_effect(instruction,known_flags=None):
    """Return internally generated replacement+descriptor or fail closed.

    The unknown pseudo-op cannot be supplied as raw p-code: the normal opcode
    validator rejects it; only the freshly generated replacement is authorized.
    Complete raw semantic fingerprints include every operation and operand.
    """
    mnemonic, raw = instruction.get('mnemonic'), instruction.get('pcode')
    encoded, size = instruction.get('codeBytes'), instruction.get('size')
    bound = (type(encoded) is str and type(size) is int and len(encoded)==size*2
             and all(c in '0123456789abcdefABCDEF' for c in encoded))
    code=bytes.fromhex(encoded) if bound else b''
    kind, destination, operations, required = None, None, None, None
    if mnemonic=='PUSHFQ':
        if code!=b'\x9c':raise OpaqueRejected('Only unprefixed64-bit PUSHFQ is abstracted')
        kind,required='unknown-pushed-flag-image',PUSHFQ_RAW_SHA
        u,rsp=_v('unique',0,8),_v('register',32,8)
        operations=[_op('IG5_OPAQUE',u)];image=u
        if known_flags is not None:
            assert type(known_flags) is dict and all(n in FLAG_BITS and type(i) is int and i>=0 for n,i in known_flags.items())
            mask=sum(1<<FLAG_BITS[n] for n in known_flags)
            if mask:
                image=_v('unique',8,8);operations.append(_op('INT_AND',image,u,_v('const',((1<<64)-1)^mask,8)))
                for j,name in enumerate(sorted(known_flags,key=FLAG_BITS.get)):
                    boolean=_v('unique',16+32*j,1);wide=_v('unique',24+32*j,8);placed=_v('unique',32+32*j,8);joined=_v('unique',40+32*j,8)
                    operations.extend([_op('INT_NOTEQUAL',boolean,_v('register',FLAG_OFFSETS[name],1),_v('const',0,1)),
                        _op('INT_ZEXT',wide,boolean),_op('INT_MULT',placed,wide,_v('const',1<<FLAG_BITS[name],8)),_op('INT_OR',joined,image,placed)])
                    image=joined
        operations.extend([_op('INT_SUB',rsp,rsp,_v('const',8,8)),
                    _op('STORE',None,{'kind':'address-space','space':'ram','spaceId':3},rsp,image)])
    elif mnemonic=='RDTSC':
        if code!=b'\x0f\x31':raise OpaqueRejected('Only unprefixed RDTSC is abstracted')
        kind,required='fresh-timestamp64',RDTSC_RAW_SHA
        u=_v('unique',0,8)
        operations=[_op('IG5_OPAQUE',u)]
        for register,offset in [(16,4),(0,0)]:
            low=_v('register',register,4)
            operations.extend([_op('SUBPIECE',low,u,_v('const',offset,4)),
                               _op('INT_ZEXT',_v('register',register,8),low)])
    elif mnemonic=='BSWAP' and bound and code[:1]==b'\x66':
        index,rex=1,0
        if index<len(code) and 0x40<=code[index]<=0x4f:rex=code[index];index+=1
        # Effective REX.W makes this a supported64-bit instruction, not an
        # undefined16-bit case. Its ordinary strict validation remains active.
        if rex&8:return None
        if not (index+2==len(code) and code[index]==0x0f and 0xc8<=code[index+1]<=0xcf):
            raise OpaqueRejected('Noncanonical16-bit BSWAP cannot be abstracted')
        number=(code[index+1]-0xc8)+(8 if rex&1 else 0)
        destination=list(REGISTERS)[number];base=REGISTERS[destination]
        kind='undefined-bswap16-full-gpr';required=BSWAP32_RAX_RAW_SHA
        operations=[_op('IG5_OPAQUE',_v('register',base,8))]
        raw=copy.deepcopy(raw)
        for operation in raw:
            for value in [operation.get('output'),*operation.get('inputs',[])]:
                if type(value) is dict and value.get('space')=='register':
                    if value.get('offset')!=hex(base):raise OpaqueRejected('BSWAP destination differs from bytes')
                    value['offset']='0x0'
    else:
        return None
    try:
        if fingerprint(raw)!=required:raise OpaqueRejected('Complete fixed-decoder opaque-effect shape mismatch')
    except (TypeError,ValueError,RecursionError) as error:
        if isinstance(error,OpaqueRejected):raise
        raise OpaqueRejected('Malformed opaque-effect shape') from error
    descriptor={'kind':kind,'codeBytes':code.hex(),'rawPcodeSemanticSha256':fingerprint(instruction['pcode']),
                'rawOperationCount':len(instruction['pcode']),'replacementOperationCount':len(operations),
                'unknownBits':64,'conservativeSuperset':True,'observedValuesUsed':False,
                'architectureProved':False,'flagsPreserved':True}
    if destination is not None:descriptor['destination']=destination
    if kind=='unknown-pushed-flag-image':descriptor['rawStorePcodeIndex']=56
    if kind=='unknown-pushed-flag-image' and known_flags is not None:
        descriptor['unknownBits']=64-len(known_flags)
        descriptor['flagImageRefinement']={'method':'defined-status-pcode-overlay-v1','knownMask':hex(mask),'unknownMask':hex(((1<<64)-1)^mask),
            'knownFlags':[{'name':n,'bit':FLAG_BITS[n],'definitionInstructionIndex':known_flags[n]} for n in sorted(known_flags,key=FLAG_BITS.get)],
            'freshInputBits':64,'effectiveUnknownBits':64-len(known_flags),'initialFlagValuesSupplied':False,'unmodeledBitsRemainUnknown':True}
    return operations,descriptor


def make_dag(check):
    # Delayed imports avoid a cycle with the unchanged strict engine. All memory
    # forwarding uses the same exact alias relations/budget as composition.
    from projection_composition import CompositionDag
    class OpaqueDag(CompositionDag):
        def make(self, op, args=(), bits=None, **data):
            nodes=[self.nodes[n] for n in args]
            if bits is not None and nodes and all(n['op']=='const' for n in nodes):
                values=[int(n['value'],16) for n in nodes];x=values[0]
                y=values[1] if len(values)>1 else None
                width=nodes[0]['bits'];value=None
                if op=='INT_2COMP':value=-x
                elif op=='INT_NEGATE':value=~x
                elif op=='INT_LEFT':value=0 if y>=width else x<<y
                elif op=='INT_RIGHT':value=0 if y>=width else x>>y
                elif op=='INT_SRIGHT':
                    signed=x-(1<<width) if x&(1<<(width-1)) else x
                    value=(-1 if signed<0 else 0) if y>=width else signed>>y
                elif op=='INT_REM' and y:value=x%y
                if value is not None:return self.const(value,bits)
            return super().make(op,args,bits,**data)
    return OpaqueDag(check)
