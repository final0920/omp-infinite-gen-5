"""Bounded universal width checks for the status encoder additions."""
from pathlib import Path
import argparse,json,sys,time
MAIN=Path(__file__).resolve().parents[1];sys.path[:0]=[str(MAIN/'worker'),str(MAIN/'scripts')]
from composition_domain_smt import Queries,encode,bv,add,sha


def main():
    p=argparse.ArgumentParser();p.add_argument('--out',required=True);p.add_argument('--child',action='store_true');args=p.parse_args();out=Path(args.out);assert out.is_absolute()
    if not args.child:
        from lift_process import run_owned
        from lift_runtime import locked_file
        out.mkdir(exist_ok=False);job=out/'job';job.mkdir();r=run_owned(str(MAIN/'runtimes/ghidra/python/python.exe'),['-I','-B','-X','utf8',str(Path(__file__)),*sys.argv[1:],'--child'],job,budget_ms=50000)
        (out/'process.json').write_text(json.dumps(r,indent=2)+'\n',encoding='utf8');assert r['childExitConfirmed'] and r['jobAssignedAtCreation']
        if r['exitCode']!=0:
            with locked_file(job/'stderr.log',4*1024**2) as raw:error=raw.decode('utf8')
            with locked_file(job/'stdout.log',4*1024**2) as raw:error+='\n'+raw.decode('utf8')[-4096:]
            raise AssertionError(error)
        with locked_file(out/'verified.json',4*1024**2) as raw:proof=json.loads(raw)
        print(json.dumps({'passed':proof['passed'],'queries':len(proof['queries']),'statuses':{s:sum(q['status']==s for q in proof['queries']) for s in ('unsat','sat','unknown')},'verifiedSha256':sha(out/'verified.json'),'process':r}));return
    deadline=time.monotonic()+45;q=Queries(MAIN,out/'queries',deadline)
    try:
        for width in (1,8,16,32,64,128):
            nodes=[]
            def n(op,bits,args=(),**data):
                i=len(nodes);nodes.append({'id':i,'op':op,'type':'bv','bits':bits,'args':list(args),**data});return i
            inputs=[n('input',64,name=s) for s in ('rax','rbx','rcx','rdx')]
            if width<64:a,b=[n('extract',width,[i],offset=0) for i in inputs[:2]]
            elif width==64:a,b=inputs[:2]
            else:a,b=n('concat',128,[inputs[0],inputs[2]]),n('concat',128,[inputs[1],inputs[3]])
            roots=[n(op,8,[a,b]) for op in ('INT_CARRY','INT_SCARRY','INT_SLESS')]
            depths=[]
            for node in nodes:depths.append(1+max([0]+[depths[i] for i in node['args']]))
            core={'dag':{'nodes':nodes,'depth':max(depths),'references':sum(len(x['args']) for x in nodes)+len(roots)}}
            lines,actual,meta=encode(core,roots);pa=('((_ extract '+str(width-1)+' 0) I_rax)' if width<64 else 'I_rax' if width==64 else '(concat I_rax I_rcx)')
            pb=('((_ extract '+str(width-1)+' 0) I_rbx)' if width<64 else 'I_rbx' if width==64 else '(concat I_rbx I_rdx)')
            unsigned=add(f'((_ zero_extend 1) {pa})',f'((_ zero_extend 1) {pb})');signed=add(f'((_ sign_extend 1) {pa})',f'((_ sign_extend 1) {pb})')
            sa=f'((_ extract {width-1} {width-1}) {pa})';sb=f'((_ extract {width-1} {width-1}) {pb})'
            conditions=[f'(bvuge {unsigned} {bv(1<<width,width+1)})',f'(distinct ((_ extract {width} {width}) {signed}) ((_ extract {width-1} {width-1}) {signed}))',
                f'(or (and (= {sa} {bv(1,1)}) (= {sb} {bv(0,1)})) (and (= {sa} {sb}) (bvult {pa} {pb})))']
            predicate='(or '+' '.join(f'(distinct {v} (ite {c} {bv(1,8)} {bv(0,8)}))' for v,c in zip(actual,conditions))+')'
            q.expect(q.query('carry-overflow-signed-less-width'+str(width),'\n'.join(lines)+'\n(assert '+predicate+')','unsat',meta))
            # Constants cover empty/full/alternating population at every width;
            # expected counts come from Python integers, not SMT expansion.
            nodes=[]
            roots=[]
            values=[0,(1<<width)-1,sum(1<<i for i in range(0,width,2))]
            for value in values:
                c=n('const',width,value=hex(value));roots.append(n('POPCOUNT',8,[c]))
            core={'dag':{'nodes':nodes,'depth':2,'references':sum(len(x['args']) for x in nodes)+len(roots)}}
            lines,actual,meta=encode(core,roots)
            predicate='(or '+' '.join(f'(distinct {v} {bv(x.bit_count(),8)})' for v,x in zip(actual,values))+')'
            q.expect(q.query('popcount-boundaries-width'+str(width),'\n'.join(lines)+'\n(assert '+predicate+')','unsat',meta))
        nodes=[{'id':0,'op':'input','name':'rax','type':'bv','bits':64,'args':[]},{'id':1,'op':'input','name':'rbx','type':'bv','bits':64,'args':[]},
            {'id':2,'op':'INT_CARRY','type':'bv','bits':8,'args':[0,1]}]
        lines,actual,meta=encode({'dag':{'nodes':nodes,'depth':2,'references':3}},[2])
        q.expect(q.query('negative-off-by-one-carry-threshold-is-not-equivalent','\n'.join(lines)+f'\n(assert (distinct {actual[0]} (ite (bvuge {add("((_ zero_extend 1) I_rax)","((_ zero_extend 1) I_rbx)")} {bv((1<<64)-1,65)}) {bv(1,8)} {bv(0,8)})))','sat',meta))
        result={'passed':True,'queries':q.rows,'widths':[1,8,16,32,64,128],'signedUnsignedCarryAndOrderingUniversal':True,'popcountThreeIntegerBoundaryPatternsEachWidth':True,
            'negativeOffByOneCounterexampleSAT':True,'encoderSourceSha256':sha(MAIN/'scripts/composition_domain_smt.py'),'sourceTestSha256':sha(__file__),
            'solverDllSha256':q.dll_sha,'nativeTargetExecuted':False,'businessAccepted':False,'wholeBinaryVerified':False}
        with (out/'verified.json').open('x',encoding='utf8') as f:json.dump(result,f,indent=2);f.write('\n')
    finally:q.close()


if __name__=='__main__':main()
