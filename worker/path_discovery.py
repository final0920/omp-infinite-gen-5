"""Bounded raw-file candidate walking, not CPU execution or CFG recovery."""
MASK=(1<<64)-1
PIN='65bf673f1c4304cc2c09076e3b96e368da9e0df72aa0badeba0c2a5cae392934'
SYSTEM={'syscall','sysenter','sysexit','sysret','sysretq','int','int1','int3','into','iret','iretd','iretq','hlt','ud0','ud1','ud2','xabort','xbegin','xend','rsm','vmcall','vmmcall','vmlaunch','vmresume','encls','enclu'}

def control(code,ea,text,flow,branch):
    """Only canonical byte-bound direct JMP is followed. No operand-text EA."""
    following=(ea+len(code))&MASK;mnemonic=text.split()[0].lower()
    result={'kind':'fallthrough','successors':[hex(following)]}
    if mnemonic in SYSTEM:return {'kind':'system','successors':[]}
    if flow:
        if code[:1]==b'\xe9' and len(code)==5 or code[:1]==b'\xeb' and len(code)==2:
            if mnemonic!='jmp' or not branch:raise ValueError('Discovery direct-JMP metadata disagrees with bytes')
            displacement=int.from_bytes(code[1:],'little',signed=True)
            return {'kind':'direct-jump','successors':[hex((following+displacement)&MASK)]}
        if mnemonic.startswith('ret'):return {'kind':'return','successors':[]}
        if mnemonic in ('call','lcall'):
            if mnemonic=='call' and code[:1]==b'\xe8' and len(code)==5:
                return {'kind':'call','successors':[hex((following+int.from_bytes(code[1:],'little',signed=True))&MASK)],'returnAddress':hex(following)}
            return {'kind':'call','successors':[]}
        if mnemonic!='jmp' and branch:
            target=None
            if len(code)==2 and (0x70<=code[0]<=0x7f or 0xe0<=code[0]<=0xe3):target=(following+int.from_bytes(code[1:],'little',signed=True))&MASK
            elif len(code)==6 and code[0]==0x0f and 0x80<=code[1]<=0x8f:target=(following+int.from_bytes(code[2:],'little',signed=True))&MASK
            return {'kind':'conditional','successors':[] if target is None else [hex(target),hex(following)]}
        return {'kind':'unresolved-control','successors':[]}
    if branch or mnemonic in ('jmp','ljmp','call','lcall') or mnemonic.startswith('ret'):
        raise ValueError('Discovery control-flow metadata inconsistent')
    return result

def walk(image,entry,maximum,decode,check=lambda:None,*,follow_direct_calls=False):
    if type(entry) is not int or not 1<=entry<=MASK or type(maximum) is not int or not 1<=maximum<=128:
        raise ValueError('Discovery needs nonzero uint64 entry and1..128 instructions')
    if type(follow_direct_calls) is not bool:raise ValueError('Discovery direct-call option must be Boolean')
    rows=[];visited=set();intervals=[];ea=entry;stop=None
    while True:
        check()
        if ea in visited:stop={'reason':'cycle','next':hex(ea)};break
        if any(a<ea<a+n for a,n in intervals):stop={'reason':'overlap','next':hex(ea)};break
        mappings=[r for r in image.regions if r.start<=ea<r.start+len(r.data)]
        if len(mappings)!=1 or not mappings[0].permissions&4:
            if not rows:raise ValueError('Discovery entry must map uniquely to executable file bytes')
            stop={'reason':'unmapped-or-nonexecutable','next':hex(ea)};break
        r=mappings[0];code=r.data[ea-r.start:ea-r.start+15];decoded=decode(ea,code)
        size=decoded['size'];text=decoded['text'];flow=decoded['controlFlow'];branch=decoded['branch']
        if type(size) is not int or not 1<=size<=len(code) or size>15 or type(text) is not str or not text or len(text)>2048 or type(flow) is not bool or type(branch) is not bool:
            raise ValueError('Discovery decode shape mismatch')
        code=code[:size]
        if ea+size>1<<64:raise ValueError('Discovery instruction crosses uint64 boundary')
        if any(ea<a+n and a<ea+size for a,n in intervals):stop={'reason':'overlap','next':hex(ea),'nextSize':size};break
        edge=control(code,ea,text,flow,branch)
        rows.append({'ea':hex(ea),'size':size,'bytes':code.hex(),'text':text,'controlFlow':flow,'branch':branch,'control':edge})
        visited.add(ea);intervals.append((ea,size))
        if edge['kind'] not in ('fallthrough','direct-jump') and not (follow_direct_calls and edge['kind']=='call' and edge['successors']):stop={'reason':edge['kind'],'next':None};break
        ea=int(edge['successors'][0],16)
        if len(rows)==maximum:stop={'reason':'instruction-budget','next':hex(ea)};break
    return {'schema':'ig5-path-discovery-v1','status':'partial','recoveryStatus':'unverified','entry':hex(entry),'maxInstructions':maximum,'followDirectCalls':follow_direct_calls,
        'candidatePath':[r['ea'] for r in rows],'instructions':rows,'stop':stop,'decoder':'pinned-triton-disassembly-only','decoderManifestPin':PIN,
        'candidateOnly':True,'pathSemanticsValidated':False,'nativeReachabilityProved':False,'databaseModified':False,'nativeTargetExecuted':False,'businessAccepted':False,'wholeBinaryVerified':False,
        'scope':'Raw-file AMD64 candidate only. Optional canonical E8 rel32 follows the callee entry; RET always stops, no call-return/ABI summary. No processing(), memory/register initialization, branch-condition choice or indirect-target inference. Submit candidatePath to explicit Java project; original semantic/flags refusals remain.'}
