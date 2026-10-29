"""Build the IG5-only Java wrapper using the existing pinned local JDK/jars.

Writes a NEW absolute output directory. No target execution/download, and no
change to the original runtime inventory or upstream artifacts/licenses.
"""
from contextlib import ExitStack
from pathlib import Path
import hashlib,json,sys,zipfile
from urllib.parse import quote
MAIN=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(MAIN/'worker'))
from lift_process import run_owned
from lift_runtime import locked_file
PIN='8fc4ae42f775f0139aa5f184c912db71f77e68d661c14564ab6f4820d434abea'
def sha(raw):return hashlib.sha256(raw).hexdigest()
if len(sys.argv)!=2:raise SystemExit('Usage: build_java_projection.py NEW-ABSOLUTE-DIRECTORY')
OUT=Path(sys.argv[1]);assert OUT.is_absolute() and not OUT.exists();OUT.mkdir(parents=True)
runtime=MAIN/'runtimes';source=MAIN/'adapters/ghidra/projection-java/IG5JavaProjectionDecode.java'
with ExitStack() as held:
    manifest_raw=held.enter_context(locked_file(runtime/'manifest.json',2*1024**2));assert sha(manifest_raw)==PIN
    inventory={r['path']:r for r in json.loads(manifest_raw)['files']}
    config_raw=held.enter_context(locked_file(runtime/'ghidra/runtime.json',65536));assert sha(config_raw)==inventory['ghidra/runtime.json']['sha256']
    config=json.loads(config_raw);home='ghidra/'+config['ghidraHome']+'/';jdk='ghidra/'+config['javaHome']+'/'
    jars=sorted(n for n in inventory if n.startswith(home+'Ghidra/') and '/lib/' in n and n.endswith('.jar'))
    assert 10<len(jars)<256
    # Compiler/JVM/JAR inputs are held during the owned local compilation.
    for name in jars+[jdk+'bin/javac.exe',jdk+'bin/java.exe',jdk+'bin/server/jvm.dll']:
        raw=held.enter_context(locked_file(runtime/name,256*1024**2));assert sha(raw)==inventory[name]['sha256']
    source_raw=held.enter_context(locked_file(source,65536))
    classes=OUT/'classes';classes.mkdir()
    job=OUT/'compile';job.mkdir()
    args=['-J-Xmx512m','-J-Duser.language=en','-proc:none','-encoding','UTF-8','-cp',';'.join(str(runtime/n) for n in jars),'-d',str(classes),str(source)]
    assert sum(len(a)+3 for a in args)<30000
    process=run_owned(str(runtime/(jdk+'bin/javac.exe')),args,job,budget_ms=50000)
    (OUT/'compile-process.json').write_text(json.dumps(process,indent=2)+'\n',encoding='utf-8')
    assert process['exitCode']==0 and process['childExitConfirmed'] and process['jobAssignedAtCreation'],(job/'stderr.log').read_text(encoding='utf-8',errors='replace')
    class_bytes=(classes/'IG5JavaProjectionDecode.class').read_bytes()
    jar=OUT/'ig5-java-decode.jar'
    with zipfile.ZipFile(jar,'x',compression=zipfile.ZIP_DEFLATED) as archive:
        # Standard manifest-relative JAR dependencies avoid Windows command-line
        # limits and launcher argfile encodings for non-ASCII installation paths.
        line=('Class-Path: '+' '.join('../../../runtimes/'+quote(n,safe='/') for n in jars)).encode('ascii')
        folded=[]
        while line:
            width=70 if not folded else 69
            folded.append((b'' if not folded else b' ')+line[:width]);line=line[width:]
        jar_manifest=b'Manifest-Version: 1.0\r\n'+b'\r\n'.join(folded)+b'\r\n\r\n'
        manifest_info=zipfile.ZipInfo('META-INF/MANIFEST.MF',(1980,1,1,0,0,0));manifest_info.compress_type=zipfile.ZIP_DEFLATED
        archive.writestr(manifest_info,jar_manifest)
        info=zipfile.ZipInfo('IG5JavaProjectionDecode.class',(1980,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
        archive.writestr(info,class_bytes)
    assets=set(jars)
    for name in inventory:
        relative=name[len(home):] if name.startswith(home) else ''
        if (name.startswith(jdk) and name[len(jdk):].split('/')[0] in ('bin','lib','conf') or name==jdk+'release' or
            relative=='Ghidra/application.properties' or relative.endswith('/Module.manifest') or
            relative.endswith('/data/ExtensionPoint.manifest') or relative.endswith(('.ldefs','.xsd','.rng','.dtd')) or
            relative.startswith('Ghidra/Processors/x86/data/languages/')):assets.add(name)
    assets=sorted(assets);assert len(assets)<=1024 and sum(inventory[n]['bytes'] for n in assets)<1024**3
    result={'schema':'ig5-official-java-projection-runtime-v1','upstreamManifestPin':PIN,'ghidraHome':config['ghidraHome'],'javaHome':config['javaHome'],'language':'x86:LE:64:default','mainClass':'IG5JavaProjectionDecode','classpath':jars,'upstreamAssets':assets,'helper':{'path':'ig5-java-decode.jar','bytes':jar.stat().st_size,'sha256':sha(jar.read_bytes())},'source':{'path':str(source.relative_to(MAIN)).replace('\\','/'),'sha256':sha(source_raw)},'targetExecuted':False}
    encoded=(json.dumps(result,indent=2)+'\n').encode('utf-8');assert len(encoded)<=128*1024
    (OUT/'manifest.json').write_bytes(encoded)
    (OUT/'build-proof.json').write_text(json.dumps({'sourceSHA256':sha(source_raw),'classSHA256':sha(class_bytes),'jarSHA256':sha(jar.read_bytes()),'manifestSHA256':sha(encoded),'upstreamJarCount':len(jars),'runtimeAssetCount':len(assets),'runtimeAssetBytes':sum(inventory[n]['bytes'] for n in assets),'process':process},indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'manifestSHA256':sha(encoded),'helperSHA256':sha(jar.read_bytes()),'runtimeAssetCount':len(assets),'runtimeAssetBytes':sum(inventory[n]['bytes'] for n in assets),'process':process}))
