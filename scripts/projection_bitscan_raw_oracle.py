"""Numerical fixed-raw BSF CFG checker; not a CPU architecture certificate.

No product imports or pattern matcher. Expected nonzero results use the
independent least-set-bit integer formula. Zero checks only decoder termination
and its explicit writes; the architectural destination stays undefined.
"""
import random


def check_bsf_raw(instruction,bits,source_offset,destination_offset):
    raw=instruction['pcode'];width=bits//8;mask=(1<<bits)-1
    rng=random.Random(0x425346+bits)
    inputs=range(1<<16) if bits==16 else [0]+[1<<i for i in range(bits)]+[rng.getrandbits(bits) for _ in range(128)]
    maximum=0;cases=0;largest_counter=-1
    for source in inputs:
        regs={};unique={}
        def write(space,offset,size,value):
            data=regs if space=='register' else unique
            for i in range(size):data[offset+i]=(value>>(8*i))&255
        def read(v):
            offset,size=int(v['offset'],16),v['size']
            if v['space']=='const':return offset&((1<<(8*size))-1)
            data=regs if v['space']=='register' else unique
            assert all(offset+i in data for i in range(size))
            return sum(data[offset+i]<<(8*i) for i in range(size))
        # Full destination/source frames may alias. BSF reads its source before
        # the final destination write; seeded upper bytes must survive r16.
        sentinel=0xd3c2b1a098765432
        write('register',destination_offset,8,sentinel)
        write('register',source_offset,8,(sentinel&~mask)|source)
        original_destination=sum(regs[destination_offset+i]<<(8*i) for i in range(8))
        pc,steps=0,0
        while pc<len(raw):
            steps+=1;assert steps<={16:99,32:196,64:387}[bits]
            op=raw[pc];kind=op['opcode'];values=[read(v) for v in op['inputs']]
            if kind in ('BRANCH','CBRANCH'):
                if kind=='CBRANCH' and not values[1]:pc+=1;continue
                v=op['inputs'][0];delta=values[0]
                if delta&(1<<(8*v['size']-1)):delta-=1<<(8*v['size'])
                pc+=delta;assert 0<=pc<=len(raw);continue
            x=values[0];y=values[1] if len(values)>1 else None
            if kind in ('COPY','INT_ZEXT'):value=x
            elif kind=='INT_EQUAL':value=int(x==y)
            elif kind=='INT_NOTEQUAL':value=int(x!=y)
            elif kind=='INT_RIGHT':value=x>>y
            elif kind=='INT_AND':value=x&y
            elif kind=='INT_ADD':value=x+y
            else:raise AssertionError('Unexpected raw BSF operation '+kind)
            out=op['output'];write(out['space'],int(out['offset'],16),out['size'],value);pc+=1
        zf=regs[0x206];assert zf==int(source==0)
        index=(source&-source).bit_length()-1 if source else 0
        actual=sum(regs[destination_offset+i]<<(8*i) for i in range(8))
        expected=((original_destination&~mask)|index) if bits==16 else index
        assert actual==expected
        if source:largest_counter=max(largest_counter,index)
        maximum=max(maximum,steps);cases+=1
    assert maximum=={16:99,32:196,64:387}[bits] and largest_counter==bits-1
    return {'operandBits':bits,'numericInputs':cases,'maximumPcodeStepsObserved':maximum,
            'maximumCounterObserved':largest_counter,'all16BitSourcesEnumerated':bits==16,
            'architecturalZeroDestinationCertified':False,'architectureProved':False}
