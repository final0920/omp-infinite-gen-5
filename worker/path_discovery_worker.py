"""Single owned native decoder job; candidate bytes are never executed."""
from pathlib import Path
from contextlib import ExitStack
import hashlib,json,sys,time
sys.path.insert(0,str(Path(__file__).resolve().parent))
from lift_runtime import locked_file
from kernel_image import BinaryImage
from path_discovery import walk,PIN

def main():
    if len(sys.argv)!=2:raise ValueError('One private discovery request required')
    with ExitStack() as held:
        raw=held.enter_context(locked_file(Path(sys.argv[1]),65536));p=json.loads(raw)
        if set(p)!={'target','sha256','ea','max_instructions','follow_direct_calls','budget_ms'} or type(p['budget_ms']) is not int or not 1<=p['budget_ms']<=50000 or type(p['follow_direct_calls']) is not bool:raise ValueError('Invalid discovery child request')
        deadline=time.monotonic()+p['budget_ms']/1000
        def check():
            if time.monotonic()>=deadline:raise ValueError('Discovery deadline exhausted')
        data=held.enter_context(locked_file(Path(p['target']),64*1024**2))
        if hashlib.sha256(data).hexdigest()!=p['sha256']:raise ValueError('Discovery target digest mismatch')
        image=BinaryImage.from_bytes(data)
        if image.format!='PE' or image.bits!=64 or image.machine!=0x8664:raise ValueError('Discovery requires raw AMD64 PE32+ file bytes')
        vendor=Path(__file__).resolve().parent/'trace_vendor';raw=held.enter_context(locked_file(vendor/'ig5-manifest.json',4*1024**2))
        if hashlib.sha256(raw).hexdigest()!=PIN:raise ValueError('Discovery dependency inventory mismatch')
        for row in json.loads(raw)['files']:
            check();path=vendor/row['path']
            if not path.resolve().is_relative_to(vendor.resolve()):raise ValueError('Discovery dependency outside fixed vendor')
            content=held.enter_context(locked_file(path,128*1024**2))
            if len(content)!=row['bytes'] or hashlib.sha256(content).hexdigest()!=row['sha256']:raise ValueError('Discovery dependency pin mismatch')
        from trace_analysis import load_triton
        tt=load_triton();ctx=tt.TritonContext(tt.ARCH.X86_64)
        def decode(ea,code):
            check();inst=tt.Instruction(ea,code);ctx.disassembly(inst)
            if inst.getType()==0:raise ValueError('Discovery invalid instruction')
            return {'size':inst.getSize(),'text':inst.getDisassembly(),'controlFlow':inst.isControlFlow(),'branch':inst.isBranch()}
        result=walk(image,int(p['ea'],16),p['max_instructions'],decode,check,follow_direct_calls=p['follow_direct_calls']);result['targetSha256']=p['sha256'];result['runtimeManifestPin']='8fc4ae42f775f0139aa5f184c912db71f77e68d661c14564ab6f4820d434abea'
        raw=(json.dumps(result,ensure_ascii=True,allow_nan=False,separators=(',',':'))+'\n').encode('ascii')
        if len(raw)>4*1024**2:raise ValueError('Discovery output budget')
        sys.stdout.buffer.write(raw)

if __name__=='__main__':main()
