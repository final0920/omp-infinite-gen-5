"""One read-only Mergen lift. The target is parsed as data and never executed."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from kernel_image import BinaryImage
from lift_process import run_owned, OwnedProcessError
from lift_runtime import runtime, locked_file, MANIFEST_SHA256, LIFTER_SHA256

PROTOCOL = os.fdopen(os.dup(sys.stdout.fileno()), 'w', encoding='utf8', buffering=1)
os.dup2(sys.stderr.fileno(), sys.stdout.fileno()); sys.stdout = sys.stderr
HEX = re.compile(r'0x[0-9a-fA-F]{1,16}\Z')
UUID = re.compile(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\Z')
OUTPUTS = ('output.ll','output_no_opts.ll','output_diagnostics.json','stdout.log','stderr.log','mergen-crash.txt')


def emit(value):
    PROTOCOL.write(json.dumps(value,ensure_ascii=False,allow_nan=False,separators=(',',':'))+'\n')


def strict_json(raw):
    def pairs(values):
        out = {}
        for key,value in values:
            if key in out: raise ValueError('Duplicate JSON property')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON number')))


def address(value):
    if not isinstance(value,str) or not HEX.fullmatch(value): raise ValueError('Explicit 64-bit hexadecimal address required')
    return int(value,16)


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--artifacts-root',required=True)
    root = Path(parser.parse_args().artifacts_root)
    if not root.is_absolute() or root.resolve(strict=True) != root: raise ValueError('Physical lifter artifact root required')
    emit({'ig5':'ready','engine':'Mergen','capabilities':['lift']})
    request = {}; nonce = None; cleanup = True
    cancel = threading.Event(); started = time.monotonic()
    try:
        line = sys.stdin.buffer.readline(64*1024+1)
        if len(line)>64*1024 or not line.endswith(b'\n'): raise ValueError('Lifter request framing limit')
        request = strict_json(line)
        if not isinstance(request,dict) or request.get('method') != 'lift' or request.get('id') != 1:
            raise ValueError('Unsupported lifter request')
        p = request['params']; nonce = p.get('nonce')
        required = {'job_id','nonce','sha256','ea','initial_flags','lift_inline','max_blocks','budget_ms'}
        if not isinstance(p,dict) or set(p)!=required or not UUID.fullmatch(p.get('job_id','')) or not UUID.fullmatch(nonce or ''):
            raise ValueError('Invalid lifter request scope')
        if not re.fullmatch('[a-f0-9]{64}',p['sha256']): raise ValueError('Invalid target digest')
        ea, flags = address(p['ea']), address(p['initial_flags'])
        if not ea or flags>0xfff: raise ValueError('Lifter requires nonzero preferred VA and explicit low12 modeled flags')
        inline = p['lift_inline']
        if not isinstance(inline,list) or len(inline)>16: raise ValueError('At most sixteen explicit inline addresses')
        inline = [address(value) for value in inline]
        if 0 in inline or len(set(inline))!=len(inline): raise ValueError('Duplicate/zero inline address')
        blocks, budget = p['max_blocks'], p['budget_ms']
        if type(blocks) is not int or not 1<=blocks<=4096 or type(budget) is not int or not 1<=budget<=50000:
            raise ValueError('Invalid lifter budget')
        directory = root/'jobs'/p['job_id']
        if directory.resolve(strict=True)!=directory or not directory.is_dir() or any(directory.iterdir()):
            raise ValueError('Lifter output directory is not a fresh physical job')

        def controls():
            try:
                while True:
                    raw=sys.stdin.buffer.readline(4097)
                    if not raw: cancel.set(); return
                    if len(raw)>4096 or not raw.endswith(b'\n'): cancel.set(); return
                    message=strict_json(raw)
                    if message == {'id':0,'method':'cancel','params':{'requestId':1,'nonce':nonce}}:
                        cancel.set(); return
                    cancel.set(); return
            except Exception: cancel.set()
        threading.Thread(target=controls,daemon=True).start()
        # Held file handles deny writes/deletes while both PE parsers consume the
        # same immutable snapshot. No recorded-memory reconstruction occurs.
        with locked_file(root/'blobs'/(p['sha256']+'.bin'),64*1024**2) as data:
            if hashlib.sha256(data).hexdigest()!=p['sha256']: raise ValueError('Target snapshot digest mismatch')
            image=BinaryImage.from_bytes(data)
            if image.format!='PE' or image.bits!=64 or image.machine!=0x8664:
                raise ValueError('Mergen lift currently requires AMD64 PE32+')
            for value in [ea,*inline]:
                if sum(r.start<=value<r.start+len(r.data) for r in image.regions)!=1:
                    raise ValueError('Lifter addresses must map uniquely to file-backed preferred main-image bytes')
            with runtime() as executable:
                remaining = min(budget,50000-int((time.monotonic()-started)*1000))
                if remaining<1: raise ValueError('Lifter preflight deadline exceeded')
                argv=[str(root/'blobs'/(p['sha256']+'.bin')),hex(ea),'--initial-flags',hex(flags)]
                if inline: argv += ['--inline',','.join(hex(value) for value in inline)]
                cleanup=False
                process=run_owned(executable,argv,directory,budget_ms=remaining,cancel=cancel,
                    env={'MERGEN_MAX_BLOCK_BUDGET':str(blocks),'MERGEN_CRASH_REPORT':str(directory/'mergen-crash.txt')})
                cleanup=process['childExitConfirmed']
        outputs=[]
        for name in OUTPUTS:
            filename=directory/name
            if filename.exists():
                # Oversized output is retained on disk and identified, never
                # silently truncated or promoted into a successful lift.
                size=filename.stat().st_size
                outputs.append({'name':name,'bytes':size,'withinBudget':size<=4*1024**2})
        result={'backend':'Mergen','status':'partial','recoveryStatus':'unverified',
            'targetSha256':p['sha256'],'entry':hex(ea),'initialFlags':hex(flags),
            'initialStateScope':'Explicit modeled low12 flags; GPR arguments remain symbolic. Not bound to a native capture; full architectural flag semantics not verified.',
            'inputScope':'Raw-file preferred addresses; no relocations, captured memory or runtime patches applied.',
            'nativeTargetExecuted':False,'databaseModified':False,'wholeBinaryVerified':False,'businessAccepted':False,
            'backendPin':LIFTER_SHA256,'runtimeManifestPin':MANIFEST_SHA256,'process':process,'outputs':outputs,
            'inlineTargets':[hex(value) for value in inline],'maxBlocks':blocks,
            'limitations':['IR generation is not a proof of business semantics, complete paths or function return.',
                'Opaque __ig5_unresolved_control_* and __ig5_unlifted_block_* calls preserve unmodeled transfers/results; they do not recover them. Block identity arguments are not native addresses.',
                           'Missing memory, unresolved indirect flow and unsupported instructions remain unresolved.']}
        emit({'id':1,'nonce':nonce,'cleanupConfirmed':cleanup,'result':result})
    except Exception as error:
        if isinstance(error,OwnedProcessError): cleanup=error.child_exit_confirmed
        emit({'id':request.get('id') if isinstance(request,dict) else None,'nonce':nonce,
              'cleanupConfirmed':cleanup,'error':{'code':'LIFT_FAILED','message':str(error)[:1024]}})


if __name__=='__main__': main()
