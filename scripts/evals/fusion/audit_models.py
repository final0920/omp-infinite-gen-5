"""Independent replay of actual Harness model events and costs. No JS judge import."""
import json,pathlib,hashlib,sys
def data(p,maxbytes=16*1024*1024):
 p=pathlib.Path(p);assert p.is_file() and not p.is_symlink();b=p.read_bytes();assert len(b)<=maxbytes;return b
def load(p):return json.loads(data(p))
def sha(b):return hashlib.sha256(b).hexdigest()
def encoded(v):return json.dumps(v,ensure_ascii=False,separators=(',',':')).encode()
def main():
 root=pathlib.Path(sys.argv[1]);plan=load(root/'plan.json');runs=load(root/'runs.json');assert len(runs)<=30;f=plan['frozen'];assert sha(encoded(f['manifest']))==f['sha256'];assert plan['answerBoundary']=='exposed';budget=f['manifest']['controls']['budget'];assert budget=={'toolCalls':20,'tokens':16000,'elapsedMs':120000,'returnedBytes':65536};seen=set();certs=[]
 for source in plan['sources']:assert sha(data(root/(source['name']+'.snapshot')))==source['sha256']
 for row in runs:
  key=(row['taskId'],row['group'],row['repetition']);assert key not in seen;seen.add(key);assert any(all(spec[k]==row[k] for k in ('taskId','group','repetition')) for spec in plan['schedule']);folder=root/('-'.join(map(str,key)));events=load(folder/'events.json');logs=[json.loads(line) for line in data(folder/'tools.jsonl').decode().splitlines() if line.strip()];assert load(folder/'result.json')==row
  last=None;usage=[];calls={};payloads=[];toolcalls=0;returned=0;invalid=0;boundary=any(l.get('boundary')=='only-ig5_fusion_eval' for l in logs);allowed=['task','raw']+(['documents'] if row['group']>='B' else [])+(['conditions'] if row['group']>='C' else [])+(['history','proposal'] if row['group']>='D' else [])+(['verify'] if row['group']>='E' else [])
  for e in events:
   if e['type']=='assistant/message':last=e['data'];usage.append(last.get('usage'))
   if e['type']=='tool/call':
    c=e['data'];calls[c['callId']]=c;toolcalls+=1
   if e['type']=='tool/result':
    message=e['data'].get('message',{});call=calls.get(message.get('toolCallId',message.get('source',{}).get('callId')))
    if not call:continue
    args=json.loads(call['arguments']);valid=call['name']=='ig5_fusion_eval' and list(args)==['action'] and args['action'] in allowed
    if not valid:invalid+=1
    try:value=json.loads(''.join(b['text'] for b in message.get('content',[]) if b['type']=='text'))
    except (ValueError,KeyError):continue
    if 'sourceSha256' not in value:continue
    assert valid,'Denied action returned a source payload'
    digest=sha(encoded(value['payload']));assert digest==value['sourceSha256'];assert any(l.get('phase')=='result' and l['sourceSha256']==digest and l['action']==args['action'] for l in logs);payloads.append(digest);returned+=len(encoded(value))
  # Current transport counts the pre-execute dispatch, including invalid attempts.
  dispatched=sum(l.get('phase')=='dispatch' for l in logs);assert dispatched==row['cost']['toolCalls'];assert returned==row['cost']['returnedBytes'];assert toolcalls>=dispatched
  actual=None
  if last:
   content=last.get('message',{}).get('content',last.get('content',[]));text='\n'.join(b['text'] for b in content if b['type']=='text')
   try:actual=json.loads(text)
   except ValueError:pass
  expected=['0x0','0x1','0xff'] if row['taskId']=='owned-bv-add-zero' else [hex(initial) for x in (0,7,255) for initial in (0,57)]
  answerok=bool(actual and actual.get('returns')==expected and actual.get('wholeFunctionRecovered') is False and actual.get('nativeProved') is False);citations=bool(actual and actual.get('sourceRefs') and all(s in payloads for s in actual['sourceRefs']));known=bool(usage and all(u and isinstance(u.get('inputTokens'),int) and isinstance(u.get('outputTokens'),int) for u in usage));tokens=sum(u['inputTokens']+u.get('cacheReadTokens',0)+u['outputTokens'] for u in usage) if known else None;assert tokens==row['cost']['tokens'];within=known and tokens<=budget['tokens'] and dispatched<=budget['toolCalls'] and returned<=budget['returnedBytes'] and row['cost']['elapsedMs']<=budget['elapsedMs'];assert within==row['withinBudget'];accepted=row['status']=='completed' and answerok and citations and boundary and row['cleanupConfirmed'] and within;assert bool(accepted)==row['accepted'];assert actual==row.get('answer')
  numeric=False
  try:numeric=bool(actual and isinstance(actual['returns'],list) and len(actual['returns'])==len(expected) and all(isinstance(v,str) and v.startswith('0x') and len(v)<=18 and int(v,16)==int(e,16) for v,e in zip(actual['returns'],expected)) and actual.get('wholeFunctionRecovered') is False and actual.get('nativeProved') is False)
  except (ValueError,KeyError,TypeError):pass
  certs.append({'task':row['taskId'],'group':row['group'],'repetition':row['repetition'],'answerCorrect':answerok,'numericValuesAndBoundariesCorrect':numeric,'strictHexFormatOnlyFailure':numeric and not answerok,'algorithmInvoked':any(l.get('phase')=='result' and l.get('action')=='verify' for l in logs),'citationsBound':citations,'accepted':bool(accepted),'withinBudget':bool(within),'invalidAttempts':invalid,'cost':row['cost'],'eventSha256':sha(data(folder/'events.json')),'toolLogSha256':sha(data(folder/'tools.jsonl')),'cleanupReported':row['cleanupConfirmed']})
 pergroup={g:{'registered':6,'attempted':sum(c['group']==g for c in certs),'accepted':sum(c['group']==g and c['accepted'] for c in certs)} for g in 'ABCDE'}
 paired=[]
 for task in ('owned-bv-add-zero','owned-vm-halt-state'):
  for rep in (1,2,3):
   rows={c['group']:c for c in certs if c['task']==task and c['repetition']==rep}
   if 'A' in rows and 'E' in rows:paired.append({'task':task,'repetition':rep,'successDeltaEminusA':int(rows['E']['accepted'])-int(rows['A']['accepted']),'toolCallsDeltaEminusA':rows['E']['cost']['toolCalls']-rows['A']['cost']['toolCalls'],'tokensDeltaEminusA':None if rows['E']['cost']['tokens'] is None or rows['A']['cost']['tokens'] is None else rows['E']['cost']['tokens']-rows['A']['cost']['tokens'],'elapsedMsDeltaEminusA':rows['E']['cost']['elapsedMs']-rows['A']['cost']['elapsedMs']})
 report={'schema':'ig5-fusion-independent-model-audit-v1','registeredRuns':30,'attemptedRuns':len(certs),'unrun':30-len(certs),'perGroup':pergroup,'pairedEminusA':paired,'certificates':certs,'answerBoundary':'exposed','isolatedCreditAllowed':False,'nativeRecoveryProved':False,'assistAllowed':False,'netBenefitEstablished':False,'scope':'actual model finite-value workflow; two owned families, declared holdout, no OS isolation or protected target'};(root/'independent-audit.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf8');print(json.dumps({'attempted':len(certs),'accepted':sum(c['accepted'] for c in certs),'unrun':30-len(certs),'groups':pergroup,'native':False,'assist':False}))
if __name__=='__main__':main()
