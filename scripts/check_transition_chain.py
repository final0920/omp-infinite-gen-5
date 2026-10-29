"""Maintenance checks; logs to an explicit fresh evidence directory."""
from pathlib import Path
import hashlib,json,os,re,subprocess,sys
MAIN=Path(__file__).resolve().parents[1];OUT=Path(sys.argv[1]);OUT.mkdir(exist_ok=False)
NODE=Path(r'C:\Users\IG5User\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe')
PY=MAIN/'runtimes/ghidra/python/python.exe';skip={'runtimes','third_party','node_modules','.git','__pycache__'}
syntax={'javascript':0,'python':0,'errors':[]}
for directory,dirs,files in os.walk(MAIN):
    dirs[:]=[d for d in dirs if d not in skip]
    for name in files:
        p=Path(directory)/name
        try:
            if p.suffix in ('.js','.mjs','.cjs'):
                r=subprocess.run([str(NODE),'--check',str(p)],capture_output=True,creationflags=0x08000000,timeout=15)
                assert r.returncode==0,r.stderr.decode('utf8',errors='replace');syntax['javascript']+=1
            elif p.suffix=='.py':compile(p.read_bytes(),str(p),'exec');syntax['python']+=1
        except Exception as error:syntax['errors'].append({'path':str(p),'message':str(error)})
(OUT/'syntax.json').write_text(json.dumps(syntax,indent=2)+'\n',encoding='utf8');print(json.dumps(syntax),flush=True);assert not syntax['errors']
names=['test_analysis_failure','test_projection_decoder','test_projection_jobs','test_composition_jobs','test_projection_guarded_host',
       'test_projection_opaque_host','test_projection_calls_host','test_lift_jobs','test_transition_chain_host','test_composition_opaque_host','test_dashboard_projection','test_client']
commands=[('node-owned-analysis',[str(NODE),'--test',*[str(MAIN/'scripts'/f'{n}.mjs') for n in names]])]
commands += [(n,[str(PY),'-I','-B','-X','utf8',str(MAIN/'scripts'/f'{n}.py')]) for n in
    ['test_analysis_failure','test_java_projection','test_pcode_projection','test_pcode_bsf','test_pcode_guarded','test_pcode_opaque',
     'test_pcode_calls','test_projection_composition','test_composition_memory','test_composition_selection','test_lift_process','test_transition_chain','test_composition_opaque']]
commands += [(n,[str(NODE),str(MAIN/'scripts'/f'{n}.mjs')]) for n in
    ['test_host_sdk','test_workflow','test_approval_gate','test_worker_transport','test_attachment_leases']]
# The broad native public catalog includes the already application-control
# blocked decoder. Never retry it here; retain its original4551 failure receipt.
rows=[]
for name,args in commands:
    r=subprocess.run(args,cwd=MAIN,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120,creationflags=0x08000000)
    log=OUT/(name+'.log');log.write_bytes(r.stdout);text=r.stdout.decode('utf8',errors='replace')
    py=re.search(r'Ran (\d+) tests?',text);node=re.search(r'tests (\d+)',text)
    rows.append({'name':name,'exitCode':r.returncode,'log':str(log),'sha256':hashlib.sha256(r.stdout).hexdigest(),
        'pythonTests':int(py.group(1)) if py else None,'nodeTests':int(node.group(1)) if node else None})
    (OUT/'progress.json').write_text(json.dumps(rows,indent=2)+'\n',encoding='utf8');print(json.dumps(rows[-1]),flush=True)
    assert r.returncode==0,text[-3000:]
(OUT/'checks.json').write_text(json.dumps({'passed':True,'syntax':syntax,'suites':rows,'businessAccepted':False,'wholeBinaryVerified':False},indent=2)+'\n',encoding='utf8')
