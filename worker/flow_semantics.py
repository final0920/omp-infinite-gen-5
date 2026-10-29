"""Paired coherent ordinary IR states. Never executes a target or changes a DAG.

The second state differs only by an exact initial-RAM store at the source LOAD.
All initial GPRs and independent opaque inputs are coupled. Existing immutable
encoder/solver inventory helpers are reused without changing their contracts.
"""
from pathlib import Path
import ctypes as C
import hashlib, json, os, re, sys, time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from composition_domain_smt import ARRAY,GPRS,Queries,encode,validate,bv,store

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)
def signatures(core):
    rows=[]
    for node in core['dag']['nodes']:
        meaning={k:v for k,v in node.items() if k not in ('id','args')}
        meaning['args']=[rows[i] for i in node['args']]
        rows.append(hashlib.sha256(canonical(meaning).encode('utf8')).hexdigest())
    return rows
def closure(nodes,root):
    todo=[root];seen=set()
    while todo:
        i=todo.pop()
        if i in seen:continue
        seen.add(i);todo.extend(nodes[i]['args'])
    return seen
def source(core):
    if (type(core) is not dict or core.get('schema')!='ig5-pcode-opaque-status-projection-v1' or core.get('projectionMode')!='opaque-status' or
        any(core.get(k) is not False for k in ('nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified')) or
        set(core.get('initialRegisters',{}))!=set(GPRS) or set(core.get('registers',{}))!=set(GPRS) or
        not isinstance(core.get('projectionPath'),list) or not 1<=len(core['projectionPath'])<=128):raise ValueError('Unsupported full ordinary-state source')
    nodes=validate(core)  # Every node, including unused definitions; no cuts.
    if any(n['op']=='state_binding' for n in nodes):raise ValueError('State-composed reports are not accepted')
    if ([n['id'] for n in nodes if n['op']=='initial_memory']!=[core['initialMemory']] or
        sorted((n['name'],n['id']) for n in nodes if n['op']=='input')!=sorted(core['initialRegisters'].items())):
        raise ValueError('Initial state identities differ')
    return nodes

def prepare(prefix,full):
    pnodes,nodes=source(prefix),source(full)
    if (len(prefix['projectionPath'])!=1 or prefix['projectionPath'][0]!=full['projectionPath'][0] or prefix['targetSha256']!=full['targetSha256'] or
        prefix['decodedPath'][0]!=full['decodedPath'][0] or prefix['stores'] or full['control']['kind'] not in ('return','indirect')):
        raise ValueError('Source instruction or indirect control binding differs')
    loads=[n for n in pnodes if n['op']=='load_le' and n['size'] in (1,2)]
    if len(loads)!=1:raise ValueError('One source narrow LOAD required')
    ps,fs=signatures(prefix),signatures(full);signature=ps[loads[0]['id']]
    matches=[n['id'] for n in nodes if n['op']=='load_le' and fs[n['id']]==signature]
    if not matches:raise ValueError('Source LOAD absent from full state representation')
    seed=matches[0];memory,address=nodes[seed]['args']
    if memory!=full['initialMemory'] or nodes[memory]['op']!='initial_memory':raise ValueError('Source is not an initial-RAM LOAD')
    if any(nodes[i]['op'] in ('load_le','initial_memory','store_le','nondeterministic') for i in closure(nodes,address)):
        raise ValueError('Source address is not independent of initial RAM/opaque outputs')
    target=full['control']['target'];target_closure=closure(nodes,target)
    indexed=[n['id'] for n in nodes if n['op']=='load_le' and n['id'] not in matches and n['id'] in target_closure and any(i in closure(nodes,n['args'][1]) for i in matches)]
    if not indexed:raise ValueError('No source-dependent indexed read reaches the indirect target')
    roots=list(full['registers'].values())+[full['initialMemory'],full['currentMemory'],target,seed,address]
    for s in full['stores']:roots.extend(s[k] for k in ('address','value','beforeMemory','afterMemory'))
    roots.extend(nodes[i]['args'][1] for i in indexed)
    roots=list(dict.fromkeys(roots));lines,values,metadata=encode(full,roots)
    if metadata['explicitCuts'] or metadata['weakenedLoadNodes']:raise ValueError('Semantic assessment cannot cut LOADs or source definitions')
    rename=lambda s:re.sub(r'\bn(\d+)\b',r'changed_n\1',re.sub(r'\bM0\b','M_seed_changed',s))
    changed=[];shared=set(line for line in lines if line.startswith('(declare-const '));removed=0
    for line in lines:
        if line==f'(declare-const M0 {ARRAY})':removed+=1;continue
        if line.startswith('(declare-const ') and re.match(r'\(declare-const (?:I_[a-z0-9]+|M_dispatch|opaque_\d+) ',line):continue
        changed.append(rename(line))
    if removed!=1:raise ValueError('Initial memory declaration differs')
    seed_bits=nodes[seed]['bits'];new=f'(declare-const seed_changed (_ BitVec {seed_bits}))'
    memory_definition=f'(define-fun M_seed_changed () {ARRAY} {store("M0",f"n{address}","seed_changed",nodes[seed]["size"])})'
    common='\n'.join(lines+[new,memory_definition]+changed)
    needed=set()
    for root in roots:needed.update(closure(nodes,root))
    # Finite M0 observations cover every needed LOAD in both worlds. STORE
    # overlays are replayed independently; no array is replaced by free LOADs.
    cells=[]
    for i in sorted(needed):
        n=nodes[i]
        if n['op']=='load_le':
            for world in ('original','changed'):
                term=f'n{n["args"][1]}' if world=='original' else f'changed_n{n["args"][1]}'
                for at in range(n['size']):cells.append((world,i,at,term))
    if len(cells)>256:raise ValueError('Finite semantic witness exceeds 256 initial-RAM byte observations')
    opaque=[i for i in sorted(needed) if nodes[i]['op']=='nondeterministic']
    names=[(f'I_{g}',64) for g in GPRS]+[('seed_changed',seed_bits)]+[(f'opaque_{i}',64) for i in opaque]
    cell_defs=[]
    for n,(world,node,at,term) in enumerate(cells):
        a=f'witness_a{n}';v=f'witness_b{n}'
        cell_defs += [f'(define-fun {a} () (_ BitVec 64) (bvadd {term} {bv(at)}))',f'(define-fun {v} () (_ BitVec 8) (select M0 {a}))']
        names.extend(((a,64),(v,8)))
    witness_base=common+'\n'+'\n'.join(cell_defs)
    return {'full':full,'nodes':nodes,'seed':seed,'seedAddress':address,'seedBits':seed_bits,'signature':signature,'matches':matches,
        'indexed':indexed,'roots':roots,'needed':sorted(needed),'opaque':opaque,'base':witness_base,'witnessNames':names,'cells':cells,
        'metadata':metadata,'sourceChange':f'(distinct n{seed} changed_n{seed})','target':target}

def forms(text):
    if type(text) is not str or len(text.encode('utf8'))>65536:raise ValueError('Solver model byte budget')
    tokens=re.findall(r'\(|\)|[^\s()]+',text)
    if len(tokens)>8192:raise ValueError('Solver model token budget')
    stack=[];result=[]
    for token in tokens:
        if token=='(':
            if len(stack)>=128:raise ValueError('Solver model depth budget')
            item=[]
            (stack[-1] if stack else result).append(item);stack.append(item)
        elif token==')':
            if not stack:raise ValueError('Solver model framing')
            stack.pop()
        else:(stack[-1] if stack else result).append(token)
    if stack:raise ValueError('Solver model framing')
    return result
def model_values(text,names):
    parsed=forms(text)
    if len(parsed)!=1 or not isinstance(parsed[0],list) or len(parsed[0])!=len(names):raise ValueError('Solver model shape differs')
    result={}
    for pair,(name,bits) in zip(parsed[0],names):
        if not isinstance(pair,list) or len(pair)!=2 or pair[0]!=name:raise ValueError('Solver model identity differs')
        v=pair[1]
        if isinstance(v,str) and re.fullmatch(r'#x[0-9a-fA-F]+',v) and 4*(len(v)-2)==bits:value=int(v[2:],16)
        elif isinstance(v,str) and re.fullmatch(r'#b[01]+',v) and len(v)-2==bits:value=int(v[2:],2)
        elif isinstance(v,list) and len(v)==3 and v[0]=='_' and type(v[1]) is str and re.fullmatch(r'bv[0-9]+',v[1]) and v[2]==str(bits):value=int(v[1][2:])
        else:raise ValueError('Unsupported finite solver value')
        if not 0<=value<1<<bits or name in result:raise ValueError('Solver value width or duplicate differs')
        result[name]=value
    return result

class SemanticSolver(Queries):
    def __init__(self,main,out,deadline):
        super().__init__(main,out,deadline);self.output_bytes=0;self.errors=[]
        self.handler_type=C.CFUNCTYPE(None,C.c_void_p,C.c_uint)
        self.handler=self.handler_type(lambda _ctx,code:self.errors.append(code))
        self.lib.Z3_set_error_handler.argtypes=[C.c_void_p,self.handler_type];self.lib.Z3_set_error_handler.restype=None
        if os.name=='nt':
            kernel=C.WinDLL('kernel32',use_last_error=True)
            kernel.GetModuleFileNameW.argtypes=[C.c_void_p,C.c_wchar_p,C.c_uint];kernel.GetModuleFileNameW.restype=C.c_uint
            buffer=C.create_unicode_buffer(32768);size=kernel.GetModuleFileNameW(self.lib._handle,buffer,len(buffer))
            if not 0<size<len(buffer) or Path(buffer.value).resolve()!=self.dll.resolve():raise ValueError('Loaded solver module path differs')
    def check(self,name,base,conditions,witness_names):
        if len(self.rows)>=128:raise ValueError('Semantic solver query budget')
        remaining=int((self.deadline-time.monotonic())*1000)
        if remaining<1:raise ValueError('Semantic assessment deadline')
        timeout=min(2000,remaining);body='\n'.join([base,*[f'(assert {c})' for c in conditions]])
        checked=f'(set-option :timeout {timeout})\n(set-option :memory_max_size 512)\n{body}\n(check-sat)\n'
        model_command='(get-value ('+' '.join(n for n,_ in witness_names)+'))\n'
        candidate=(checked+model_command).encode('ascii');depth=0;maximum=0
        for c in candidate:
            if c==40:depth+=1;maximum=max(depth,maximum)
            elif c==41:depth-=1
            if depth<0:raise ValueError('Semantic SMT framing')
        if depth or maximum>128 or candidate.count(b'(')>2048 or len(re.findall(rb'[^\s()]+',candidate))>8192 or len(candidate)>1024**2:
            raise ValueError('Semantic encoded-query budget')
        if self.output_bytes+len(candidate)>3*1024**2:raise ValueError('Combined semantic query output budget')
        file=f'q{len(self.rows):03d}.smt2';raw=checked.encode('ascii')
        # Persist the exact attempted query before entering native code. An
        # unknown/error never erases the query which produced it.
        with (self.out/file).open('xb') as stream:stream.write(raw)
        self.output_bytes+=len(raw)
        config=self.lib.Z3_mk_config();ctx=self.lib.Z3_mk_context(config);self.lib.Z3_del_config(config)
        self.errors=[];self.lib.Z3_set_error_handler(ctx,self.handler);start=time.monotonic();model_text=None;values=None;problem=None;solver_status=None;model_reads=0
        try:
            status=self.lib.Z3_eval_smtlib2_string(ctx,checked.encode('ascii')).decode('utf8').strip();solver_status=status
            if self.errors or status not in ('sat','unsat','unknown'):raise ValueError('Solver returned an invalid status')
            if status=='sat':
                with (self.out/file).open('ab') as stream:stream.write(model_command.encode('ascii'))
                self.output_bytes+=len(model_command);raw=candidate
                model_reads=1
                model_text=self.lib.Z3_eval_smtlib2_string(ctx,model_command.encode('ascii')).decode('utf8').strip()
                if self.errors or len(model_text.encode('utf8'))>65536:raise ValueError('Solver witness output budget or error')
                values=model_values(model_text,witness_names)
        except (ValueError,RuntimeError,UnicodeError) as error:
            problem=str(error)[:512];status='unverified';values=None
        finally:self.lib.Z3_del_context(ctx)
        model_ref=None
        if model_text is not None:
            model_file=f'q{len(self.rows):03d}.model.txt';model_raw=(model_text+'\n').encode('utf8')[:65536]
            with (self.out/model_file).open('xb') as stream:stream.write(model_raw)
            model_ref={'name':model_file,'bytes':len(model_raw),'sha256':hashlib.sha256(model_raw).hexdigest()};self.output_bytes+=len(model_raw)
        row={'name':name,'status':status,'timeoutMs':timeout,'elapsedMs':round((time.monotonic()-start)*1000),
            'checkSatCalls':1,'modelReadCalls':model_reads,'query':{'name':file,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()},
            'model':model_ref,'encodedSexpressions':candidate.count(b'('),'encodedAtomTokens':len(re.findall(rb'[^\s()]+',candidate)),'encodedDepth':maximum,
            'modelCommandConditionalOnSat':True,**({'solverStatus':solver_status,'error':problem} if problem else {})}
        self.rows.append(row);return len(self.rows)-1,values

def witness(pair,values,index):
    if values is None:return None
    cells={}
    for n in range(len(pair['cells'])):
        address=values[f'witness_a{n}'];byte=values[f'witness_b{n}']
        if address in cells and cells[address]!=byte:raise ValueError('Incoherent finite initial memory witness')
        cells[address]=byte
    return {'initialRegisters':{g:hex(values[f'I_{g}']) for g in GPRS},'changedSourceValue':hex(values['seed_changed']),
        'opaqueInputs':[{'node':i,'value':hex(values[f'opaque_{i}'])} for i in pair['opaque']],
        'initialMemoryBytes':[{'address':hex(a),'value':v} for a,v in sorted(cells.items())],
        'indexReadNode':index,'sourceNode':pair['seed'],'sourceAddressNode':pair['seedAddress'],
        'nativeReachabilityProved':False,'recordedEnvironmentUsed':False}

def assess(prefix,full,solver):
    pair=prepare(prefix,full);nodes=pair['nodes'];target_loads={i for i in closure(nodes,pair['target']) if nodes[i]['op']=='load_le'}
    rows=[]
    for index in pair['indexed'][:4]:
        address=nodes[index]['args'][1];other_index=sorted(i for i in closure(nodes,address) if nodes[i]['op']=='load_le' and i not in pair['matches'])
        other_target=sorted(target_loads-set(pair['matches'])-set(pair['indexed']))
        same=lambda ids:[f'(= n{i} changed_n{i})' for i in ids]
        premise=[pair['sourceChange'],*same(other_index)]
        p,pw=solver.check(f'index-{index}-source-premises',pair['base'],premise,pair['witnessNames'])
        row={'indexReadNode':index,'addressNode':address,'coupledIndexLoads':other_index,'coupledOtherTargetLoads':other_target,'queries':[p],
            'indexMayChange':False,'targetMayChangeWithIndex':False,'witnesses':[]}
        if solver.rows[p]['status']!='sat':row['status']='source-variation-unavailable-or-unknown';rows.append(row);continue
        row['witnesses'].append({'query':p,'kind':'source-premises','state':witness(pair,pw,index)})
        q,qw=solver.check(f'index-{index}-address-change',pair['base'],premise+[f'(distinct n{address} changed_n{address})'],pair['witnessNames']);row['queries'].append(q)
        if solver.rows[q]['status']!='sat':row['status']='index-invariant-under-coupled-loads' if solver.rows[q]['status']=='unsat' else 'index-variation-unknown';rows.append(row);continue
        row['indexMayChange']=True;row['witnesses'].append({'query':q,'kind':'index-change','state':witness(pair,qw,index)})
        terminal_premise=[*premise,*same(other_target),f'(distinct n{address} changed_n{address})']
        t,tw=solver.check(f'index-{index}-target-premises',pair['base'],terminal_premise,pair['witnessNames']);row['queries'].append(t)
        if solver.rows[t]['status']!='sat':row['status']='target-variation-premises-unavailable-or-unknown';rows.append(row);continue
        row['witnesses'].append({'query':t,'kind':'target-premises','state':witness(pair,tw,index)})
        z,zw=solver.check(f'index-{index}-target-change',pair['base'],terminal_premise+[f'(distinct n{pair["target"]} changed_n{pair["target"]})'],pair['witnessNames']);row['queries'].append(z)
        if solver.rows[z]['status']=='sat':row['targetMayChangeWithIndex']=True;row['status']='ordinary-model-source-index-target-influence';row['witnesses'].append({'query':z,'kind':'target-change','state':witness(pair,zw,index)})
        else:row['status']='target-invariant-under-isolated-index-change' if solver.rows[z]['status']=='unsat' else 'target-variation-unknown'
        rows.append(row)
    return {'schema':'ig5-flow-semantic-assessment-v1','assessmentComplete':True,'targetSha256':full['targetSha256'],'sourceLoadSignature':pair['signature'],
        'sourceLoadNode':pair['seed'],'sourceAddressNode':pair['seedAddress'],'sourceBytes':pair['seedBits']//8,
        'assessments':rows,'indexedReadsTotal':len(pair['indexed']),'indexedReadsAssessed':len(rows),'indexedReadCoverageComplete':len(rows)==len(pair['indexed']),
        'queries':solver.rows,'solverManifestPin':'65bf673f1c4304cc2c09076e3b96e368da9e0df72aa0badeba0c2a5cae392934','solverDllSha256':solver.dll_sha,
        'sourceValidation':pair['metadata'],'neededNodes':pair['needed'],'roots':pair['roots'],
        'initialMemoryRelationship':'changed RAM is exact little-endian store(M0, sourceAddress, changedSourceValue); all16 initial GPRs and opaque inputs are shared',
        'scope':'Existential paired ordinary-IR states; listed other LOAD values coupled. Index and target co-variation is not exclusive mediation or CPU/fault/code-coherence/native-reachability/VM/business proof',
        'nativeTargetExecuted':False,'databaseModified':False,'businessAccepted':False,'wholeBinaryVerified':False,'vmRoleProved':False,'instructionSemanticsProved':False,
        'hostWitnessReplayVerified':False}
