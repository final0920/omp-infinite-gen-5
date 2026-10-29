"""Independent finite x64 reference over owned native captures, not general ISA proof."""
import hashlib,json,re,struct,sys
from pathlib import Path
ROOT=Path(sys.argv[1]).resolve()
NAMES='rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split()
MASK=(1<<64)-1
FAULT=sys.argv[2] if len(sys.argv)>2 else None
assert FAULT in [None,'registers','phase','code-version','store-reference','initialization-label']
def sha(b):return hashlib.sha256(b).hexdigest()
def enc(v):return json.dumps(v,separators=(',',':'),ensure_ascii=False).encode()
def load(p,digest=None):
 b=Path(p).read_bytes()
 if digest:assert sha(b)==digest,str(p)
 value=json.loads(b)
 if FAULT and value.get('kind')=='vm-native-observations':
  result=value['result'];model=result['phaseModel']
  if FAULT=='registers':result['stopGroups'][0]['after']['gprs']['rax']=hex(int(result['stopGroups'][0]['after']['gprs']['rax'],16)^1)
  if FAULT=='phase':model['phaseVerified']=True
  if FAULT=='code-version':model['groups'][0]['versions'][0]['version']['binding']['reportSha256']='0'*64
  if FAULT=='initialization-label':model['groups'][0]['initialization']='verified'
  if FAULT=='store-reference':
   result['stopGroups'][0]['memoryWrites']['sourceBlobSha256']='0'*64
   for row in model['groups']:
    for point in row['versions']:
     for link in point['relation']['storeObservations']:link['source']['storeBlobSha256']='0'*64
 return value
def parse(raw):
 groups=[];regs=None;flags=None;reads=[];final=None
 for line,text in enumerate(raw.decode('ascii').splitlines(),1):
  f=text.split(':');tag=f[0]
  if tag=='r':assert len(f)==17;regs=dict(zip(NAMES,map(lambda x:int(x,16),f[1:])))
  elif tag=='d':
   bits=int(f[1],16);positions=[i for i in range(16) if bits>>i&1];assert len(positions)==len(f)-2
   regs=dict(regs)
   for i,v in zip(positions,f[2:]):regs[NAMES[i]]=int(v,16)
  elif tag=='e':flags=int(f[1],16)
  elif tag=='mr':reads.append((int(f[1],16),int(f[2]),int(f[3],16)))
  elif tag=='i':
   assert regs is not None and flags is not None and len(f)==4
   groups.append(dict(pc=int(f[1],16),code=bytes.fromhex(f[3]),line=line,regs=dict(regs),flags=flags,reads=reads));reads=[]
  elif tag=='f':assert len(f)==19;final=dict(regs=dict(zip(NAMES,map(lambda x:int(x,16),f[1:17]))),pc=int(f[17],16),flags=int(f[18],16))
  else:assert tag in ['h','s'],tag
 assert final and not reads
 for i,g in enumerate(groups):g['after']=groups[i+1] if i+1<len(groups) else final
 return groups
def flags_calc(a,b,bits,sub=False,logic=False):
 mask=(1<<bits)-1;sign=1<<(bits-1);a&=mask;b&=mask;r=(a-b if sub else a^b if logic else a+b)&mask
 value=(4 if (r&255).bit_count()%2==0 else 0)|(64 if r==0 else 0)|(128 if r&sign else 0)
 if not logic:
  value|=(1 if (a<b if sub else a+b>mask) else 0)|(16 if (a^b^r)&16 else 0)
  value|=2048 if ((a^b)&(a^r)&sign if sub else (~(a^b)&(a^r)&sign)) else 0
 return r,value
freeze=load(ROOT/'fixture-freeze.json');assert freeze['schema']=='ig5-owned-branch-native-freeze-v1';assert len(freeze['targets'])==1;assert freeze['targets'][0]['sha256']=='d9bf31e34c5e95307f88fcc7ce544101bd61e566c284a4622afc9700f29da61c';summaries=[];total=0
for target in freeze['targets']:
 binary=Path(target['path']).read_bytes();assert sha(binary)==target['sha256']
 cr=next(c for c in freeze['contracts'] if c['id']==target['id']);contract=load(cr['path'],cr['sha256'])
 run_paths=sorted(ROOT.glob(target['id']+'-native-*/acceptance.json'));assert run_paths
 for run_path in run_paths:
  run=load(run_path)
  if not run['ok']:continue # Preserve failed attempts; never count them as passing.
  assert run['nativeTargetExecuted'] and not run['generalVmPhaseProved']
  for capture in run['captures']:
   tr=load(capture['traceReportPath'],capture['traceReportSha256']);body=tr['result'];base=int(body['runtimeBase'],16)
   blobs=Path(capture['traceReportPath']).parent.parent/'blobs';raw=(blobs/(body['sha256']+'.bin')).read_bytes();assert sha(raw)==body['sha256']
   event_raw=(blobs/(body['storeEvents']['sha256']+'.bin')).read_bytes();assert sha(event_raw)==body['storeEvents']['sha256']
   events=json.loads(event_raw)['events'];groups=parse(raw);assert len(groups)==len(events)==capture['nativeSteps']
   assert body['targetSha256']==target['sha256'] and body['nativeTargetExecuted'] is True and body['stopReason']=='returned'
   assert body['executionLocation']['profileSha256']==run['profileSha256'] and body['executionLocation']['bundleSha256']==run['bundleSha256']
   assert body['storeEvents']['actualWriteCausalityProved'] is False
   pages=capture['observationPages'];assert 1<=len(pages)<=4
   results=[];offset=0
   for page in pages:
    part=load(page['path'],page['sha256'])['result']
    assert part['pagination']['offset']==offset==page['offset']
    assert part['pagination']['returned']==len(part['stopGroups'])==page['returned']<=64
    assert part['pagination']['entireInputValidated'] is True
    assert part['targetSha256']==target['sha256'] and part['identity']['runId']==body['runId']
    assert len(part['phaseModel']['groups'])==len(part['stopGroups'])
    offset+=len(part['stopGroups']);assert part['pagination']['nextOffset']==(offset if offset<len(groups) else None)
    results.append(part)
   assert offset==len(groups)
   result=results[0];model=result['phaseModel']
   result['stopGroups']=[g for p in results for g in p['stopGroups']]
   model['groups']=[g for p in results for g in p['phaseModel']['groups']]
   assert len(result['stopGroups'])==len(groups)
   for i,(g,published,event) in enumerate(zip(groups,result['stopGroups'],events,strict=True)):
    assert published['groupIndex']==i and published['recordingId']==tr['id']
    for key,state in [('before',g),('after',g['after'])]:
     assert published[key]['gprs']=={n:hex(v) for n,v in state['regs'].items()}
     assert published[key]['rip']==hex(state['pc']) and published[key]['flags']==hex(state['flags'])
    assert published['memoryWrites']['stores']==event['stores']
    assert published['memoryWrites']['sourceBlobSha256']==body['storeEvents']['sha256']
   memory={};pe=struct.unpack_from('<I',binary,0x3c)[0];count=struct.unpack_from('<H',binary,pe+6)[0];opt=struct.unpack_from('<H',binary,pe+20)[0]
   for n in range(count):
    h=pe+24+opt+40*n;size,rva,raw_size,offset=struct.unpack_from('<IIII',binary,h+8)
    for k,v in enumerate(binary[offset:offset+raw_size]):memory[base+rva+k]=v
   regs=dict(groups[0]['regs']);assert regs['rcx']==int(capture['input'],16);stack=regs['rsp'];pc=base+contract['entryRva']
   seen_code={};versions={};changed_count=0;fetches=[];regions=[];unknown_flags=[];code_stores=[];store_count=0
   location=body['executionLocation'];location={k:location[k] for k in ['kind','profileSha256','guestCID','bundleSha256','serverInstanceId','sessionId'] if k in location}
   def read(address,width,observed=None):
    if any(address+k not in memory for k in range(width)):
     assert stack-8<=address and address+width<=stack+8 and observed is not None,'Unknown memory outside bounded entry stack precondition'
     memory.update({address+k:(observed>>(8*k))&255 for k in range(width)})
    value=sum(memory[address+k]<<(8*k) for k in range(width))
    if observed is not None:assert value==observed
    return value
   for i,(g,event,row) in enumerate(zip(groups,events,model['groups'],strict=True)):
    assert g['pc']==pc and g['regs']==regs
    code=g['code'];size=len(code);next_pc=pc+size;stores=[];expected_reads=[];flag_mask=0x8d5;next_flags=g['flags']
    desc=next(t for t in contract['instructions'] if t['rva']==pc-base);regions.append(desc['phase'])
    assert bytes(read(pc+k,1) for k in range(size))==code
    binding=dict(targetSha256=target['sha256'],runId=body['runId'],threadId=body['threadId'],runtimeBase=body['runtimeBase'],
     locationFingerprint=sha(enc(location)),reportId=tr['id'],reportSha256=capture['traceReportSha256'],traceSha256=body['sha256'],
     groupIndex=i,beforeStopSeq=body['startStopSeq']+i,afterStopSeq=body['startStopSeq']+i+1,sourceLine=g['line'],pc=hex(pc),bytes=code.hex(),beforeStateAvailable=True)
    version_id=sha(enc(binding));assert row['versions'][0]['version']['id']==version_id
    assert row['versions'][0]['version']['binding']==binding
    assert row['versions'][0]['version']['contentSha256']==sha(code)
    assert row['versions'][0]['version']['validBetweenObservations'] is False
    assert row['versions'][0]['relation']['intervalStable']=='unknown'
    for k,b in enumerate(code):
     if pc+k in seen_code and seen_code[pc+k]!=b:changed_count+=1
     seen_code[pc+k]=b
    versions[i]=version_id
    def write(address,width,value):
     old=next((s for s in event['stores'] if int(s['address'],16)==address and s['bytes']==width),None);assert old is not None
     prior=read(address,width,int.from_bytes(bytes.fromhex(old['beforeHex']),'little'));after=value&((1<<(8*width))-1)
     assert old['afterHex']==after.to_bytes(width,'little').hex() and old['changed']==(prior!=after) and old['status']=='observed'
     stores.append((address,width));memory.update({address+k:(after>>(8*k))&255 for k in range(width)})
     if base+0x1000<=address<base+0x1400:code_stores.append((i,address,prior,after))
    if code[:3] in [bytes.fromhex('4c8d0d'),bytes.fromhex('4c8d15'),bytes.fromhex('4c8d1d')]:regs[{0x0d:'r9',0x15:'r10',0x1d:'r11'}[code[2]]]=(next_pc+int.from_bytes(code[3:],'little',signed=True))&MASK
    elif code==bytes.fromhex('4d89da'):regs['r10']=regs['r11']
    elif code==bytes.fromhex('4d8d1413'):regs['r10']=(regs['r11']+regs['rdx'])&MASK
    elif code==bytes.fromhex('498b01'):
     value=read(regs['r9'],8);expected_reads.append((regs['r9'],8,value));regs['rax']=value
    elif code==bytes.fromhex('a801'):
     _,f=flags_calc(regs['rax']&1,0,8,logic=True);flag_mask&=~16;unknown_flags.append({'group':i,'flag':'AF','reason':'architecturally undefined TEST AL immediate'});next_flags=(g['flags']&~flag_mask)|f
    elif code==bytes.fromhex('4801d0'):
     regs['rax'],f=flags_calc(regs['rax'],regs['rdx'],64);next_flags=(g['flags']&~0x8d5)|f
    elif code==bytes.fromhex('4831d0'):
     regs['rax'],f=flags_calc(regs['rax'],regs['rdx'],64,logic=True);flag_mask&=~16;unknown_flags.append({'group':i,'flag':'AF','reason':'architecturally undefined XOR register'});next_flags=(g['flags']&~flag_mask)|f
    elif code==bytes.fromhex('498909'):write(regs['r9'],8,regs['rcx'])
    elif code==bytes.fromhex('498901'):write(regs['r9'],8,regs['rax'])
    elif code==bytes.fromhex('4889c8'):regs['rax']=regs['rcx']
    elif code==bytes.fromhex('4989c8'):regs['r8']=regs['rcx']
    elif code==bytes.fromhex('410fb612'):
     value=read(regs['r10'],1);expected_reads.append((regs['r10'],1,value));fetches.append(value);regs['rdx']=value
    elif code==bytes.fromhex('49ffc2'):
     regs['r10'],f=flags_calc(regs['r10'],1,64);next_flags=(g['flags']&~0x8d4)|(f&0x8d4)
    elif code==bytes.fromhex('84d2'):
     _,f=flags_calc(regs['rdx']&255,0,8,logic=True);flag_mask&=~16;unknown_flags.append({'group':i,'flag':'AF','reason':'architecturally undefined TEST'});next_flags=(g['flags']&~flag_mask)|f
    elif code[:2]==bytes.fromhex('80fa'):
     _,f=flags_calc(regs['rdx']&255,code[2],8,sub=True);next_flags=(g['flags']&~0x8d5)|f
    elif code[:2]==bytes.fromhex('0f84'):
     if g['flags']&64:next_pc+=int.from_bytes(code[2:],'little',signed=True)
    elif code[:2]==bytes.fromhex('0f85'):
     if not g['flags']&64:next_pc+=int.from_bytes(code[2:],'little',signed=True)
    elif code[0]==0xe9:next_pc+=int.from_bytes(code[1:],'little',signed=True)
    elif code==bytes.fromhex('4883c007'):
     regs['rax'],f=flags_calc(regs['rax'],7,64);next_flags=(g['flags']&~0x8d5)|f
    elif code==bytes.fromhex('4883f055'):
     regs['rax'],f=flags_calc(regs['rax'],0x55,64,logic=True);flag_mask&=~16;unknown_flags.append({'group':i,'flag':'AF','reason':'architecturally undefined XOR'});next_flags=(g['flags']&~flag_mask)|f
    elif code==bytes.fromhex('4983f800'):
     _,f=flags_calc(regs['r8'],0,64,sub=True);next_flags=(g['flags']&~0x8d5)|f
    elif code[:2]==bytes.fromhex('c605'):write(next_pc+int.from_bytes(code[2:6],'little',signed=True),1,code[6])
    elif code[:2]==bytes.fromhex('49b8'):regs['r8']=int.from_bytes(code[2:],'little')
    elif code==bytes.fromhex('488d4107'):regs['rax']=(regs['rcx']+7)&MASK
    elif code==bytes.fromhex('48894c24f8'):write(regs['rsp']-8,8,regs['rcx'])
    elif code==bytes.fromhex('488b4424f8'):
     address=regs['rsp']-8;value=read(address,8);expected_reads.append((address,8,value));regs['rax']=value
    elif code==b'\x90':pass
    elif code==b'\xf8':next_flags&=~1
    elif code==b'\xc3':
     address=regs['rsp'];observed=next(v for a,w,v in g['reads'] if a==address and w==8);next_pc=read(address,8,observed);expected_reads.append((address,8,next_pc));regs['rsp']+=8;assert i==len(groups)-1
    else:raise AssertionError('Outside fixed instruction reference: '+code.hex())
    assert g['reads']==expected_reads,(i,g['reads'],expected_reads)
    assert len(event['stores'])==len(stores) and event['completeDecodedStoreSet'] and not event['actualWriteCausalityProved']
    assert event['beforeStopSeq']==body['startStopSeq']+i and event['afterStopSeq']==body['startStopSeq']+i+1
    assert g['after']['regs']==regs,(i,'GPR mismatch')
    assert g['after']['pc']==next_pc,(i,'control mismatch')
    assert (g['after']['flags']^next_flags)&flag_mask==0,(i,'defined flags mismatch',hex(g['after']['flags']),hex(next_flags))
    assert row['phase']=='unknown' and row['verifiedPhase'] is None and all(row[k]=='unknown' for k in ['initialization','dispatch','business'])
    assert all(row[k]=='unknown' for k in ['initialization','dispatch','business'])
    store_count+=len(stores);pc=next_pc
   expected=int(capture['expected'],16);assert regs['rax']==expected
   if contract['outputMemoryRva'] is not None:assert read(base+contract['outputMemoryRva'],8)==expected
   assert contract['kind']=='branch-bytecode-vm'
   saved=(int(capture['input'],16)+7)&MASK
   assert expected==(saved if saved%2==0 else saved^85)
   assert fetches==([7,7,3,5,9,1,4,0] if saved%2==0 else [7,7,3,5,9,8,85,6,11,0])
   assert store_count==3 and {'initialization','dispatch','handler-store','output-store','return'}<=set(regions)
   assert ('handler-load' in regions)==(saved%2==0)
   expected_changes=1 if contract['kind']=='self-modifying-control' and int(capture['input'],16)!=0 else 0
   assert changed_count==expected_changes==model['codeEpochs']['observedChangedBytes']
   if expected_changes:
    assert len(code_stores)==1;index,address,old,new=code_stores[0];assert(old,new)==(0x90,0xf8)
    links=[l for row in model['groups'] for point in row['versions'] for l in point['relation']['storeObservations']]
    assert len(links)==1;link=links[0];assert link['source']['groupIndex']==index and int(link['address'],16)==address
    assert link['source']['storeBlobSha256']==body['storeEvents']['sha256']
    assert link['source']['recordingId']==tr['id'] and link['source']['reportSha256']==capture['traceReportSha256'] and link['source']['traceSha256']==body['sha256']
    assert link['beforeMatches'] and link['afterMatches'] and not link['actualWriteCausalityProved'] and link['intervalStable']=='unknown'
   assert model['phaseVerified'] is False and model['businessAccepted'] is False
   total+=len(groups);summaries.append(dict(target=target['id'],input=capture['input'],groups=len(groups),stores=store_count,fetchBytes=fetches,observedCodeChanges=changed_count,
    fixedFixtureStageSemanticsVerified=contract['kind']=='branch-bytecode-vm',generalVmPhaseProved=False,unknownFlags=unknown_flags,
    scope='Finite native path in frozen owned fixture; six arithmetic flags checked where defined, reserved flags/TF outside proof; initial stack return is an observed precondition'))
  evidence=run.get('lastCleanupEvidence');assert evidence and evidence['entries']
  for e in evidence['entries']:
   receipt=load(e['receiptPath'],e['receiptSha256']);assert e['nativeCleanupProved'] and all(n['rootExitConfirmed'] and n['jobClosed'] for n in e['nativeRoots'])
assert len(summaries)==3,'Three explicitly registered native captures required'
assert len({int(c['input'],16) for c in summaries})==3
assert {'0x0','0x1','0xffffffffffffffff'}=={c['input'] for c in summaries}
report=dict(schema='ig5-pr10-native-independent-audit-v1',ok=True,captures=summaries,totalGroups=total,nativeTargetExecuted=True,
 newStoreCollectionVerifiedInGuest=True,fixedFixturePhaseContractVerified=True,generalVmPhaseProved=False,smcCoverageComplete=False,
 auditorSha256=sha(Path(__file__).read_bytes()),fixtureFreezeSha256=sha((ROOT/'fixture-freeze.json').read_bytes()),
 scope='Finite owned branch/write-read bytecode VM; not arbitrary VM, CPU completeness or input-domain proof')
assert not FAULT,'Negative audit must reject the injected false observation'
with (ROOT/'independent-branch-native-audit.json').open('x',encoding='utf-8') as output:output.write(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
