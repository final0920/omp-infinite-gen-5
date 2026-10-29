"""Fixed JSON BV-to-SMT translation; no candidate evaluation or target execution."""
from pathlib import Path
from contextlib import ExitStack
import ctypes as C
import hashlib,json,re,sys,time
sys.path.insert(0,str(Path(__file__).resolve().parent))
from lift_runtime import locked_file
from flow_semantics import SemanticSolver

def integer(v,a,b):return type(v) is int and a<=v<=b
def strict(raw):
    def pairs(rows):
        value={}
        for key,item in rows:
            if key in value:raise ValueError('Duplicate candidate JSON field')
            value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('Nonfinite candidate JSON')))
def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
def check_ast(ast,variables):
    if type(ast) is not dict or set(ast)!={'nodes','root'} or type(ast['nodes']) is not list or not 1<=len(ast['nodes'])<=128 or not integer(ast['root'],0,len(ast['nodes'])-1):raise ValueError('Bounded AST required')
    rows=ast['nodes'];depths=[]
    for i,n in enumerate(rows):
        if type(n) is not dict or n.get('id')!=i or not integer(n.get('id'),0,127) or not integer(n.get('bits'),1,64) or type(n.get('args')) is not list or len(n['args'])>6 or any(not integer(a,0,i-1) for a in n['args']):raise ValueError('AST shape/topology')
        op=n.get('op');extra={'value'} if op=='const' else {'name'} if op=='var' else {'offset'} if op=='extract' else set()
        if set(n)!={'id','op','bits','args'}|extra:raise ValueError('Unknown AST fields')
        args=[rows[a] for a in n['args']];bits=n['bits']
        if op=='const':
            if args or type(n['value']) is not str or not re.fullmatch(r'0x(?:0|[1-9a-f][a-f0-9]{0,15})',n['value']) or int(n['value'],16)>=1<<bits:raise ValueError('Constant width')
        elif op=='var':
            if args or variables.get(n['name'])!=bits:raise ValueError('Variable identity/width')
        elif op in ('add','sub','mul','and','or','xor','shl','lshr','ashr','eq','ult','slt'):
            if len(args)!=2 or args[0]['bits']!=args[1]['bits'] or bits!=(1 if op in ('eq','ult','slt') else args[0]['bits']):raise ValueError('Binary widths')
        elif op in ('not','neg'):
            if len(args)!=1 or bits!=args[0]['bits']:raise ValueError('Unary widths')
        elif op in ('zext','sext'):
            if len(args)!=1 or bits<=args[0]['bits']:raise ValueError('Extension widths')
        elif op=='extract':
            if len(args)!=1 or not integer(n['offset'],0,63) or n['offset']+bits>args[0]['bits']:raise ValueError('Extraction widths')
        elif op=='concat':
            if len(args)<2 or bits!=sum(a['bits'] for a in args):raise ValueError('Concat widths')
        elif op=='ite':
            if len(args)!=3 or args[0]['bits']!=1 or args[1]['bits']!=bits or args[2]['bits']!=bits:raise ValueError('ITE widths')
        else:raise ValueError('Unsupported AST operator')
        depths.append(1+max([depths[a] for a in n['args']]+[0]))
        if depths[-1]>32:raise ValueError('AST depth')
    seen=set()
    def visit(i):
        if i in seen:return
        seen.add(i)
        for a in rows[i]['args']:visit(a)
    visit(ast['root'])
    if len(seen)!=len(rows):raise ValueError('Disconnected AST')
    return rows[ast['root']]['bits']

def encode(ast,prefix,names):
    lines=[];rows=ast['nodes']
    binary={'add':'bvadd','sub':'bvsub','mul':'bvmul','and':'bvand','or':'bvor','xor':'bvxor','shl':'bvshl','lshr':'bvlshr','ashr':'bvashr'}
    for n in rows:
        op=n['op'];args=[prefix+str(i) for i in n['args']];bits=n['bits']
        if op=='const':body=f'(_ bv{int(n["value"],16)} {bits})'
        elif op=='var':body=names[n['name']]
        elif op in binary:body='('+binary[op]+' '+' '.join(args)+')'
        elif op in ('not','neg'):body='('+('bvnot' if op=='not' else 'bvneg')+' '+args[0]+')'
        elif op in ('eq','ult','slt'):body='(ite ('+{'eq':'=','ult':'bvult','slt':'bvslt'}[op]+' '+' '.join(args)+') #b1 #b0)'
        elif op in ('zext','sext'):body=f'((_ {"zero_extend" if op=="zext" else "sign_extend"} {bits-rows[n["args"][0]]["bits"]}) {args[0]})'
        elif op=='extract':body=f'((_ extract {n["offset"]+bits-1} {n["offset"]}) {args[0]})'
        elif op=='concat':
            body=args[0]
            for a in args[1:]:body=f'(concat {body} {a})'
        elif op=='ite':body=f'(ite (= {args[0]} #b1) {args[1]} {args[2]})'
        else:raise ValueError('Unsupported encoder operation')
        lines.append(f'(define-fun {prefix}{n["id"]} () (_ BitVec {bits}) {body})')
    return lines,prefix+str(ast['root'])

def assess(contract,candidate,solver):
    if contract.get('schema')!='ig5-bitvector-contract-v1' or contract.get('version')!='20261024-bv-contract-1':raise ValueError('Candidate contract schema/version')
    variables=contract['variables']
    if type(variables) is not list or len(variables)>6 or len({v['name'] for v in variables})!=len(variables):raise ValueError('Bounded SSA variables')
    for v in variables:
        if set(v)!={'name','bits','sourceNode','sourceName'} or not integer(v['bits'],1,64) or not integer(v['sourceNode'],0,2047) or v['name']!='ssa_'+str(v['sourceNode']):raise ValueError('SSA identity')
    widths={v['name']:v['bits'] for v in variables}
    bits=check_ast(contract['original'],widths)
    if check_ast(candidate,widths)!=bits or check_ast(contract['premise'],widths)!=1 or len(contract['original']['nodes'])+len(contract['premise']['nodes'])>128:raise ValueError('Contract width or size')
    if digest(contract['original'])!=contract['originalDigest'] or digest(contract['premise'])!=contract['premiseDigest']:raise ValueError('Contract AST digest')
    names={v['name']:'v'+str(i) for i,v in enumerate(variables)}
    witnesses=[(names[v['name']],v['bits']) for v in variables]+[('f07_dummy',1)]
    declarations=[f'(declare-fun {name} () (_ BitVec {width}))' for name,width in witnesses]
    premise,p=encode(contract['premise'],'P',names)
    base='\n'.join(['(set-logic QF_BV)',*declarations,*premise])
    out={'schema':'ig5-bitvector-solver-v1','status':'unknown','premiseStatus':'not-run','differenceStatus':'not-run','premiseWitness':None,'counterexample':None,'queries':solver.rows,
         'originalDigest':contract['originalDigest'],'candidateDigest':digest(candidate),'premiseDigest':contract['premiseDigest'],
         'nativeTargetExecuted':False,'databaseModified':False,'businessAccepted':False,'wholeBinaryVerified':False}
    q,pv=solver.check('candidate-premise',base,[f'(= {p} #b1)'],witnesses);out['premiseStatus']=solver.rows[q]['status']
    def values(v):return None if v is None else {k:'0x'+format(n,'x') for k,n in v.items()}
    out['premiseWitness']=values(pv)
    if out['premiseStatus']!='sat':return out
    original,o=encode(contract['original'],'O',names);changed,c=encode(candidate,'C',names)
    q,cv=solver.check('candidate-difference',base+'\n'+'\n'.join(original+changed),[f'(= {p} #b1)',f'(distinct {o} {c})'],witnesses)
    out['differenceStatus']=solver.rows[q]['status'];out['counterexample']=values(cv)
    return out

def main():
    if len(sys.argv)!=2:raise ValueError('One private candidate request required')
    with ExitStack() as held:
        p=strict(held.enter_context(locked_file(Path(sys.argv[1]),65536)))
        if type(p) is not dict or set(p)!={'sha256','target','budget_ms'} or not integer(p['budget_ms'],1,50000) or not re.fullmatch('[a-f0-9]{64}',p['sha256']):raise ValueError('Private candidate worker scope')
        raw=held.enter_context(locked_file(Path(p['target']),65536))
        if hashlib.sha256(raw).hexdigest()!=p['sha256']:raise ValueError('Candidate input SHA')
        request=strict(raw)
        if set(request)!={'schema','contract','candidate'} or request['schema']!='ig5-bitvector-solver-input-v1':raise ValueError('Candidate input schema')
        solver=SemanticSolver(Path(__file__).resolve().parents[1],Path(sys.argv[1]).parent/'semantic-queries',time.monotonic()+p['budget_ms']/1000)
        try:
            try:result=assess(request['contract'],request['candidate'],solver)
            except (ValueError,AssertionError,KeyError,TypeError,IndexError,RuntimeError) as error:
                result={'schema':'ig5-bitvector-solver-v1','status':'unknown','premiseStatus':'unknown','differenceStatus':'not-run','premiseWitness':None,'counterexample':None,'queries':solver.rows,'reason':str(error)[:512],
                        'originalDigest':request['contract']['originalDigest'],'candidateDigest':digest(request['candidate']),'premiseDigest':request['contract']['premiseDigest'],
                        'nativeTargetExecuted':False,'databaseModified':False,'businessAccepted':False,'wholeBinaryVerified':False}
        finally:solver.close()
        version=[C.c_uint() for _ in range(4)];solver.lib.Z3_get_version.argtypes=[C.POINTER(C.c_uint)]*4;solver.lib.Z3_get_version.restype=None
        solver.lib.Z3_get_version(*[C.byref(v) for v in version])
        result.update(inputSha256=p['sha256'],solverManifestPin='65bf673f1c4304cc2c09076e3b96e368da9e0df72aa0badeba0c2a5cae392934',solverDllSha256=solver.dll_sha,solverVersion='.'.join(str(v.value) for v in version),pythonVersion=sys.version.split()[0])
        output=(json.dumps(result,ensure_ascii=True,allow_nan=False,separators=(',',':'))+'\n').encode('ascii')
        if len(output)>1024**2 or solver.output_bytes+len(output)>4*1024**2:raise ValueError('Candidate result/query/model output budget')
        sys.stdout.buffer.write(output)

if __name__=='__main__':main()
