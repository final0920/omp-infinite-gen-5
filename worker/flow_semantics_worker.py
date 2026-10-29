"""Owned paired-state SMT analysis of internally produced projection JSON.

No caller SMT, target execution, PE parsing, or runtime decoder is accepted.
"""
from contextlib import ExitStack
from pathlib import Path
import hashlib, json, re, sys, time
sys.path.insert(0,str(Path(__file__).resolve().parent))
from lift_runtime import locked_file
from flow_semantics import SemanticSolver, assess


def strict(raw):
    def pairs(rows):
        value={}
        for key,item in rows:
            if key in value:raise ValueError('Duplicate semantic input property')
            value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('Invalid semantic number')))


def main():
    if len(sys.argv)!=2:raise ValueError('One private semantic request required')
    with ExitStack() as held:
        p=strict(held.enter_context(locked_file(Path(sys.argv[1]),65536)))
        if (type(p) is not dict or set(p)!={'target','sha256','budget_ms'} or type(p['budget_ms']) is not int or not 1<=p['budget_ms']<=50000
            or type(p['sha256']) is not str or not re.fullmatch(r'[a-f0-9]{64}',p['sha256'])):raise ValueError('Invalid semantic child request')
        deadline=time.monotonic()+p['budget_ms']/1000
        raw=held.enter_context(locked_file(Path(p['target']),4*1024**2))
        if hashlib.sha256(raw).hexdigest()!=p['sha256']:raise ValueError('Semantic input digest differs')
        request=strict(raw)
        if (type(request) is not dict or set(request)!={'schema','prefix','full'} or request['schema']!='ig5-flow-semantic-input-v1'
            or type(request['full']) is not dict or type(request['full'].get('targetSha256')) is not str
            or not re.fullmatch(r'[a-f0-9]{64}',request['full']['targetSha256'])):raise ValueError('Invalid internal semantic input schema')
        solver=SemanticSolver(Path(__file__).resolve().parents[1],Path(sys.argv[1]).parent/'semantic-queries',deadline)
        try:
            try:result=assess(request['prefix'],request['full'],solver)
            except (ValueError,AssertionError,KeyError,TypeError,IndexError,RuntimeError) as error:
                result={'schema':'ig5-flow-semantic-assessment-v1','assessmentComplete':False,'targetSha256':request['full']['targetSha256'],
                    'status':'semantic-assessment-unverified','reason':str(error)[:512] or type(error).__name__,'queries':solver.rows,'assessments':[],
                    'solverManifestPin':'65bf673f1c4304cc2c09076e3b96e368da9e0df72aa0badeba0c2a5cae392934','solverDllSha256':solver.dll_sha,
                    'nativeTargetExecuted':False,'databaseModified':False,'businessAccepted':False,'wholeBinaryVerified':False,
                    'vmRoleProved':False,'instructionSemanticsProved':False,'hostWitnessReplayVerified':False}
        finally:solver.close()
        result['inputSha256']=p['sha256']
        output=(json.dumps(result,ensure_ascii=True,allow_nan=False,separators=(',',':'))+'\n').encode('ascii')
        if len(output)>1024**2 or solver.output_bytes+len(output)>4*1024**2:raise ValueError('Combined semantic result/query/model output exceeds 4 MiB')
        sys.stdout.buffer.write(output)


if __name__=='__main__':main()
