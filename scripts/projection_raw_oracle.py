"""Test-only unsliced raw-pcode interpreter; no product/decoder imports.

The three explicit opaque instruction classes use independent architectural
data formulas and supplied free values. Other pure operations use the existing
independent numerical oracle. This checks slicing, memory order, normalization
and new unknown propagation, not full CPU correctness of SLEIGH.
"""
from projection_numerical_oracle import NAMES,MASK,projection_values

OFFSETS=dict(zip(NAMES,[0,8,16,24,32,40,48,56,128,136,144,152,160,168,176,184]))
FLAGS=[0x200,0x202,0x204,0x206,0x207,0x20b]


def run_raw(instructions,initial,initial_byte,unknowns,flags=0):
    registers={};writes={};stores=[];reads=[];control=None;raw_steps=0
    def put(v,value,temporary):
        storage=registers if v['space']=='register' else temporary
        for i in range(v['size']):storage[int(v['offset'],16)+i]=(value>>(8*i))&255
    for name,base in OFFSETS.items():put({'space':'register','offset':hex(base),'size':8},initial[name],{})
    for i,offset in enumerate(FLAGS):registers[offset]=(flags>>i)&1
    def read_memory(address,size):
        address&=MASK;reads.append({'address':address,'size':size})
        return sum((writes[(address+i)&MASK] if (address+i)&MASK in writes else initial_byte((address+i)&MASK))<<(8*i) for i in range(size))
    def store(address,size,value,ordinal,index):
        address&=MASK;value&=(1<<(size*8))-1;stores.append({'instructionIndex':ordinal,'pcodeIndex':index,'address':address,'size':size,'value':value})
        for i in range(size):writes[(address+i)&MASK]=(value>>(8*i))&255
    def read(v,temporary):
        if v['space'] in ['const','ram']:return int(v['offset'],16)
        storage=registers if v['space']=='register' else temporary;offset=int(v['offset'],16)
        return sum(storage[offset+i]<<(8*i) for i in range(v['size']))
    def gpr(name):return read({'space':'register','offset':hex(OFFSETS[name]),'size':8},{})
    for ordinal,ins in enumerate(instructions):
        code=bytes.fromhex(ins['codeBytes']);ea=int(ins['ea'],16);following=ea+ins['size'];temporary={};instruction_control=None
        if code==b'\x9c':
            sp=(gpr('rsp')-8)&MASK;put({'space':'register','offset':'0x20','size':8},sp,{})
            store(sp,8,unknowns[ordinal],ordinal,len(ins['pcode'])-1)
        elif code==b'\x0f\x31':
            value=unknowns[ordinal];put({'space':'register','offset':'0x0','size':8},value&0xffffffff,{})
            put({'space':'register','offset':'0x10','size':8},value>>32,{})
        elif len(code) in [3,4] and code[0]==0x66 and code[-2]==0x0f and 0xc8<=code[-1]<=0xcf and (len(code)==3 or not code[1]&8):
            rex=code[1] if len(code)==4 else 0;assert rex&8==0
            name=NAMES[code[-1]-0xc8+(8 if rex&1 else 0)];put({'space':'register','offset':hex(OFFSETS[name]),'size':8},unknowns[ordinal],{})
        else:
            pc=steps=0
            while pc<len(ins['pcode']):
                operation=ins['pcode'][pc];kind=operation['opcode'];out=operation['output'];inputs=operation['inputs'];steps+=1;raw_steps+=1
                assert steps<=512 and raw_steps<=65536,'Reference interpreter work budget'
                if kind in ['BRANCH','CBRANCH','CALL','BRANCHIND','RETURN']:
                    take=kind!='CBRANCH' or read(inputs[1],temporary)!=0
                    if inputs[0]['space']=='const':
                        offset=read(inputs[0],temporary);bits=inputs[0]['size']*8
                        if offset&(1<<(bits-1)):offset-=1<<bits
                        pc=pc+offset if take else pc+1;assert 0<=pc<=len(ins['pcode']);continue
                    if take:following=read(inputs[0],temporary)
                    instruction_control={'kind':'return' if kind=='RETURN' else 'indirect' if kind=='BRANCHIND' else 'direct','target':following}
                    assert pc==len(ins['pcode'])-1;break
                if kind in ['LOAD','STORE']:
                    address=read(inputs[1],temporary)
                    if kind=='STORE':store(address,inputs[2]['size'],read(inputs[2],temporary),ordinal,pc)
                    else:put(out,read_memory(address,out['size']),temporary)
                else:
                    values=[read(v,temporary) for v in inputs];bits=out['size']*8
                    if kind=='COPY':value=values[0]
                    elif kind=='PIECE':value=(values[0]<<(inputs[1]['size']*8))|values[1]
                    elif kind=='SUBPIECE':value=values[0]>>(values[1]*8)
                    else:
                        nodes=[{'id':i,'op':'const','bits':v['size']*8,'args':[],'value':hex(number)} for i,(v,number) in enumerate(zip(inputs,values))]
                        nodes.append({'id':len(nodes),'op':kind,'bits':bits,'args':list(range(len(nodes)))})
                        value=projection_values({'dag':{'nodes':nodes}},initial,initial_byte)[-1]
                    put(out,value,temporary)
                pc+=1
        if ordinal+1<len(instructions):assert following==int(instructions[ordinal+1]['ea'],16),'Reference path/control mismatch'
        control=instruction_control or {'kind':'fallthrough','target':following}
    return {'registers':{name:gpr(name) for name in NAMES},'memoryWrites':writes,'stores':stores,'control':control,'reads':reads,'rawExecutedOperations':raw_steps}


def opaque_values(report,initial,initial_byte,unknowns):
    import copy
    converted=copy.deepcopy(report);inputs=dict(initial)
    for n in converted['dag']['nodes']:
        if n['op']=='nondeterministic':
            ordinal=int(n['name'].removeprefix('opaque_'));inputs[n['name']]=unknowns[ordinal];n['op']='input'
    return projection_values(converted,inputs,initial_byte)
