"""Pinned official Java SLEIGH decoding for the owned projection supervisor.

The public request supplies addresses, never raw pcode. Runtime file handles
deny writes/deletes across both sequential compute stages; hashing is streamed
so the supervisor does not retain hundreds of megabytes of JAR/JVM byte data.
"""
from contextlib import contextmanager, ExitStack
import ctypes as C
from ctypes import wintypes as W
import hashlib,json,re
from pathlib import Path
from kernel_image import BinaryImage
from lift_runtime import locked_file

JAVA_RUNTIME_PIN='a2d70b018865c39e2d176c0997b4bc91b60942ee8944ed63069c2b6456d5dda0'
UPSTREAM_PIN='8fc4ae42f775f0139aa5f184c912db71f77e68d661c14564ab6f4820d434abea'
PREFIX=b'IG5_JAVA_JSON:'
HEX=re.compile(r'0x[0-9a-f]{1,16}\Z')
def digest(data):return hashlib.sha256(data).hexdigest()
def strict_json(raw):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise ValueError('Duplicate Java decoder JSON property')
            result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid Java decoder number')))

def prepare_input(data,sha256,addresses):
    if digest(data)!=sha256 or not 1<=len(addresses)<=128 or len(set(addresses))!=len(addresses):raise ValueError('Java decoder target/selection mismatch')
    image=BinaryImage.from_bytes(data)
    if image.format!='PE' or image.bits!=64 or image.machine!=0x8664:raise ValueError('Java projection requires raw AMD64 PE32+ bytes')
    rows=[]
    for ea in addresses:
        if type(ea) is not int or not 1<=ea<1<<64:raise ValueError('Java decoder address scope')
        mappings=[r for r in image.regions if r.start<=ea<r.start+len(r.data)]
        if len(mappings)!=1 or not mappings[0].permissions&4:raise ValueError('Java decoder address must map uniquely to executable file bytes')
        region=mappings[0];offset=ea-region.start
        rows.append({'ea':hex(ea),'codeBytes':region.data[offset:offset+15].hex()})
    raw=json.dumps({'schema':'ig5-java-projection-input-v1','targetSha256':sha256,'instructions':rows},ensure_ascii=True,separators=(',',':')).encode('ascii')
    if len(raw)>65536:raise ValueError('Java decoder input exceeds64KiB')
    return raw

@contextmanager
def locked_asset(path,pin,check):
    """Stream a pinned regular file, retaining only its read/share-read handle."""
    path=Path(path)
    if (not path.is_absolute() or str(path.resolve(strict=True)).casefold()!=str(path).casefold() or not path.is_file() or path.is_symlink()):raise ValueError('Java runtime asset must be a physical regular file')
    if type(pin['bytes']) is not int or not 0<=pin['bytes']<=256*1024**2:raise ValueError('Java runtime asset byte budget')
    k=C.WinDLL('kernel32',use_last_error=True)
    for name,args,result in [('CreateFileW',[W.LPCWSTR,W.DWORD,W.DWORD,C.c_void_p,W.DWORD,W.DWORD,W.HANDLE],W.HANDLE),('CloseHandle',[W.HANDLE],W.BOOL),('GetFileSizeEx',[W.HANDLE,C.POINTER(C.c_longlong)],W.BOOL),('ReadFile',[W.HANDLE,C.c_void_p,W.DWORD,C.POINTER(W.DWORD),C.c_void_p],W.BOOL)]:
        function=getattr(k,name);function.argtypes=args;function.restype=result
    handle=k.CreateFileW(str(path),0x80000000,1,None,3,0x00200000,None)
    if handle==C.c_void_p(-1).value:raise C.WinError(C.get_last_error())
    try:
        size=C.c_longlong()
        if not k.GetFileSizeEx(handle,C.byref(size)):raise C.WinError(C.get_last_error())
        if size.value!=pin['bytes']:raise ValueError('Java runtime asset size mismatch')
        hashed=hashlib.sha256();buffer=C.create_string_buffer(1024**2);read=W.DWORD();total=0
        while True:
            check()
            if not k.ReadFile(handle,buffer,len(buffer),C.byref(read),None):raise C.WinError(C.get_last_error())
            if read.value==0:break
            total+=read.value
            if total>pin['bytes']:raise ValueError('Java runtime asset grew during hashing')
            hashed.update(buffer.raw[:read.value])
        if total!=pin['bytes'] or hashed.hexdigest()!=pin['sha256']:raise ValueError('Java runtime asset digest mismatch')
        yield pin
    finally:k.CloseHandle(handle)

def load_manifest(raw):
    if digest(raw)!=JAVA_RUNTIME_PIN:raise ValueError('Java projection runtime manifest pin mismatch')
    manifest=strict_json(raw)
    if (manifest.get('schema')!='ig5-official-java-projection-runtime-v1' or manifest.get('upstreamManifestPin')!=UPSTREAM_PIN or
        manifest.get('language')!='x86:LE:64:default' or manifest.get('mainClass')!='IG5JavaProjectionDecode' or
        manifest.get('helper',{}).get('path')!='ig5-java-decode.jar'):raise ValueError('Java projection runtime scope mismatch')
    assets=manifest['upstreamAssets'];jars=manifest['classpath']
    if (not isinstance(assets,list) or not 1<=len(assets)<=1024 or assets!=sorted(set(assets)) or
        any(not isinstance(n,str) or ':' in n or '\\' in n or n.startswith('/') or '..' in n.split('/') for n in assets) or
        not isinstance(jars,list) or not 1<=len(jars)<=256 or jars!=sorted(set(jars)) or not set(jars)<=set(assets)):
        raise ValueError('Java projection runtime asset scope mismatch')
    return manifest

@contextmanager
def held_runtime(package,inventory,config,check):
    runtime=package/'runtimes';sidecar=package/'adapters/ghidra/projection-java'
    with ExitStack() as held:
        raw=held.enter_context(locked_file(sidecar/'manifest.json',128*1024));manifest=load_manifest(raw)
        if manifest['ghidraHome']!=config['ghidraHome'] or manifest['javaHome']!=config['javaHome']:raise ValueError('Java projection runtime configuration mismatch')
        if any(n not in inventory for n in manifest['upstreamAssets']) or sum(inventory[n]['bytes'] for n in manifest['upstreamAssets'])>1024**3:raise ValueError('Java runtime upstream inventory scope mismatch')
        for name in manifest['upstreamAssets']:held.enter_context(locked_asset(runtime/name,inventory[name],check))
        helper=manifest['helper'];held.enter_context(locked_asset(sidecar/helper['path'],helper,check))
        yield manifest

def arguments(package,manifest,input_path,input_sha256,job):
    runtime=package/'runtimes';helper=package/'adapters/ghidra/projection-java'/manifest['helper']['path']
    # The pinned helper JAR manifest lists the exact relative upstream JARs.
    classpath=str(helper)
    args=['-Xmx512m','-Dfile.encoding=UTF-8','-Duser.language=en','-Djava.awt.headless=true','-Duser.home='+str(job/'home')]
    args+=['-Dapplication.'+name+'dir='+str(job/name) for name in ('temp','cache','settings')]
    args+=['-cp',classpath,manifest['mainClass'],str(runtime/'ghidra'/manifest['ghidraHome']),str(input_path),input_sha256]
    executable=runtime/'ghidra'/manifest['javaHome']/'bin/java.exe'
    if sum(len(a)+3 for a in args)+len(str(executable))>=30000:raise ValueError('Java decoder command-line byte budget')
    return executable,args

def validate_output(raw,prepared):
    if len(raw)>4*1024**2 or not raw.startswith(PREFIX) or not raw.endswith(b'\n'):raise ValueError('Java decoder output framing/byte budget')
    result=strict_json(raw[len(PREFIX):]);expected=strict_json(prepared)
    if (not isinstance(result,dict) or set(result)!={'schema','language','targetSha256','inputSha256','nativeTargetExecuted','databaseModified','addressSpaces','instructions'} or
        result['schema']!='ig5-java-projection-decode-v1' or result['language']!='x86:LE:64:default' or result['targetSha256']!=expected['targetSha256'] or
        result['inputSha256']!=digest(prepared) or result['nativeTargetExecuted'] is not False or result['databaseModified'] is not False or
        not isinstance(result['instructions'],list) or len(result['instructions'])!=len(expected['instructions'])):raise ValueError('Java decoder output provenance mismatch')
    spaces=result['addressSpaces']
    if spaces!=[{'space':'ram','javaSpaceId':433,'uniqueIndex':3}] or any(type(spaces[0][key]) is not int for key in ('javaSpaceId','uniqueIndex')):raise ValueError('Java decoder fixed address-space binding mismatch')
    operations=0
    def varnode(v):
        return (isinstance(v,dict) and set(v)=={'space','offset','size'} and v['space'] in ('ram','register','unique','const') and
            isinstance(v['offset'],str) and HEX.fullmatch(v['offset']) and type(v['size']) is int and 1<=v['size']<=64)
    for row,input_row in zip(result['instructions'],expected['instructions']):
        if (not isinstance(row,dict) or set(row)!={'ea','size','codeBytes','mnemonic','operands','pcode'} or row['ea']!=input_row['ea'] or
            type(row['size']) is not int or not 1<=row['size']<=len(input_row['codeBytes'])//2 or row['size']>15 or
            row['codeBytes']!=input_row['codeBytes'][:row['size']*2] or not isinstance(row['mnemonic'],str) or not 1<=len(row['mnemonic'])<=64 or
            not isinstance(row['operands'],str) or len(row['operands'])>2048 or not isinstance(row['pcode'],list) or len(row['pcode'])>4096):raise ValueError('Java decoder instruction byte/boundary mismatch')
        operations+=len(row['pcode'])
        if operations>65536:raise ValueError('Java decoder raw pcode budget')
        for op in row['pcode']:
            if (not isinstance(op,dict) or set(op)!={'opcode','output','inputs'} or not isinstance(op['opcode'],str) or not re.fullmatch('[A-Z][A-Z0-9_]{0,40}',op['opcode']) or
                op['output'] is not None and not varnode(op['output']) or not isinstance(op['inputs'],list) or len(op['inputs'])>64):raise ValueError('Java decoder pcode shape mismatch')
            for index,v in enumerate(op['inputs']):
                if index==0 and op['opcode'] in ('LOAD','STORE'):
                    if v!={'kind':'address-space','space':'ram','spaceId':3} or type(v['spaceId']) is not int:raise ValueError('Java decoder memory-space operand mismatch')
                elif not varnode(v):raise ValueError('Java decoder varnode mismatch')
    return result
