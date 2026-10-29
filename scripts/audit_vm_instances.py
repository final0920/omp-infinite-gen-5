"""Independent bounded reader/interpreter for declared small-VM receipts. No JS imports/native execution."""
import sys,json,hashlib,pathlib
def digest(v): return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
def raw(p,maximum=4*1024*1024):
 p=pathlib.Path(p);assert p.is_file() and not p.is_symlink();b=p.read_bytes();assert len(b)<=maximum;return b
def execute(m,x,initial):
 if any(m[k] is None for k in ('decode','table','roles')):return {'status':'unknown','returnValue':None,'accumulator':None}
 d=m['decode'];code=bytes.fromhex(m['bytecodeHex']);key=d['seed'];pos=0;value=x;result=initial;mod=1<<d['bits']
 for _ in range(256):
  if pos>=len(code):break
  opcode=m['table'][code[pos]^key];pos+=1;key=(key+1)%256
  if opcode is None:break
  if opcode==0:return {'status':'halt','returnValue':hex(result),'accumulator':hex(value)}
  if opcode==1:value=x;continue
  if opcode==5:result=value;continue
  if pos>=len(code):break
  operand=code[pos];pos+=1
  if opcode==2:value=(value+operand)%mod
  elif opcode==3:
   for _ in range(d['rotate']):value=((value*2)%mod)+(value>>(d['bits']-1))
  elif opcode==4:value=(value-operand if d['subtract']=='acc-minus-operand' else operand-value)%mod
 return {'status':'unknown','returnValue':None,'accumulator':None}
def main():
 filename=pathlib.Path(sys.argv[1]);payload=raw(filename);assert hashlib.sha256(payload).hexdigest()==sys.argv[2];record=json.loads(payload);assert record['kind']=='vm-instance-check' and record['action']=='instance_check';r=record['result'];assert r['schema']=='ig5-small-vm-check-v1' and r['businessAccepted'] is False and r['nativeTargetExecuted'] is False and r['assistEnabled'] is False and r['dataWorkerCleanupConfirmed'] is True
 reference=r['comparisonRef'];b=raw(filename.parent/(reference['id']+'.json'));assert hashlib.sha256(b).hexdigest()==reference['sha256'];comparison=json.loads(b)['result'];assert len(comparison['sources'])<=8
 cases=0;identities=[]
 for index,s in enumerate(comparison['sources']):
  blob=raw(filename.parent.parent/'blobs'/(s['blob']['ref'][7:]+'.bin'),65536);assert hashlib.sha256(blob).hexdigest()==s['sha256']==s['blob']['sha256'];m=json.loads(blob);assert m==s['model'];c=m['contract'];transcript=[]
  for x in range(int(c['minimum'],16),int(c['maximum'],16)+1):
   for initial in c['initialResults']:transcript.append({'input':hex(x),'initialResult':initial,**execute(m,x,int(initial,16))})
  fields={'codeSha256':m['codeSha256'],'bytecodeSha256':hashlib.sha256(bytes.fromhex(m['bytecodeHex'])).hexdigest(),'tableSha256':None if m['table'] is None else digest(m['table']),'decode':m['decode'],'runId':m['runId'],'memoryEpoch':m['memoryEpoch'],'roles':m['roles']};missing=[k for k in ('codeSha256','runId','memoryEpoch','table','decode','roles') if m[k] is None];identity={'fields':fields,'complete':not missing,'missing':missing,'id':None if missing else digest(fields),'assurance':'declared-small-VM-model; not native instance identification'};assert r['identities'][index]==identity==comparison['identities'][index];identities.append(identity)
  v=r['checks'][index];assert v['transcript']==transcript and v['transcriptDigest']==digest(transcript) and v['cases']==len(transcript);assert v['nativeEquivalenceProved'] is False;unknown=sum(t['status']!='halt' for t in transcript);assert v['unknown']==unknown and v['status']==('unknown' if unknown else 'pass-in-finite-model');cases+=len(transcript)
 pairs=[]
 for a,x in enumerate(identities):
  for b,y in enumerate(identities[a+1:],a+1):
   differences=[k for k in x['fields'] if x['fields'][k]!=y['fields'][k]];complete=x['complete'] and y['complete'];pairs.append({'a':a,'b':b,'status':'unknown' if not complete else 'distinct' if differences else 'same-declared-identity','differences':differences,'mergeAllowed':complete and not differences,'nativeMergeAllowed':False})
 assert pairs==r['pairs']==comparison['pairs']
 assert cases<=1024
 print(json.dumps({'ok':True,'models':len(comparison['sources']),'cases':cases,'scope':'independent finite virtual model only','native':False}))
if __name__=='__main__':main()
