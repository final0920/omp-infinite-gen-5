"""Independent bounded certificate/data readback, not a CPU or solver replay."""
from pathlib import Path
import argparse,hashlib,json,re,sys
MAIN=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(MAIN/'worker'),str(MAIN/'scripts')]
from kernel_image import BinaryImage
from lift_runtime import locked_file


def load(path,pin=None,maximum=4*1024**2):
    with locked_file(Path(path),maximum) as raw:
        digest=hashlib.sha256(raw).hexdigest();assert pin is None or digest==pin
        return json.loads(raw),digest


def same_source_receipt(left,right):
    """Bind physical source identity and digest, allowing Windows spellings."""
    if not all(type(r) is dict and type(r.get('path')) is str and re.fullmatch(r'[0-9a-f]{64}',str(r.get('sha256',''))) for r in (left,right)):return False
    if left['sha256']!=right['sha256']:return False
    paths=[]
    for ref in (left,right):
        p=Path(ref['path'])
        if not p.is_absolute() or p.is_symlink():return False
        try:physical=p.resolve(strict=True)
        except OSError:return False
        if str(physical).casefold()!=str(p).casefold():return False
        paths.append(physical)
    return paths[0]==paths[1]


def main():
    p=argparse.ArgumentParser();p.add_argument('--proof',required=True);p.add_argument('--out',required=True);args=p.parse_args()
    source=Path(args.proof);out=Path(args.out);assert source.is_absolute() and out.is_absolute()
    proof,digest=load(source);process,_=load(source.parent/'process.json',maximum=65536)
    assert proof['schema']=='ig5-handler137-conditional-semantics-proof-v1' and proof['passed']
    assert process['exitCode']==0 and process['childExitConfirmed'] and process['jobAssignedAtCreation'] and process['activeProcessLimit']==1 and process['memoryLimitBytes']==2147483648
    for key,file in (('sourceProofScriptSha256','prove_handler137_semantics.py'),('encoderSourceSha256','composition_domain_smt.py')):
        with locked_file(MAIN/'scripts'/file,1024**2) as raw:assert hashlib.sha256(raw).hexdigest()==proof[key]
    receipt,_=load(proof['sourceReceipt']['path'],proof['sourceReceipt']['sha256'])
    incoming={}
    for key in ('incomingContextProof','incomingLiteralProof','incomingDomainProof'):
        incoming[key],_=load(proof[key]['path'],proof[key]['sha256']);assert incoming[key]['passed'] and same_source_receipt(incoming[key]['sourceReceipt'],proof['sourceReceipt'])
    context=incoming['incomingContextProof'];literal=incoming['incomingLiteralProof'];domain=incoming['incomingDomainProof']
    assert context['incomingDomainProof']==literal['incomingDomainProof']==proof['incomingDomainProof']
    cores={}
    for name,ref in proof['reports'].items():
        case=next(c for c in receipt['cases'] if c['id']==name);assert not case['rejected'] and case['cleanupConfirmed'] and case['rootExitConfirmed']
        assert case['result']['reportPath']==ref['path'] and case['result']['reportSha256']==ref['sha256']
        record,_=load(ref['path'],ref['sha256']);cores[name]=record['result']
    entry=cores['entry-plus17'];check=cores['context137-check16'];fast=cores['context137-fast28'];s0,s1=fast['stores']
    assert len(check['projectionPath'])==16 and len(fast['projectionPath'])==28 and check['projectionPath']==fast['projectionPath'][:16]
    assert len(set(fast['projectionPath']))==28 and fast['projectionPath'][-12:]==cores['literal-fast-dispatch22']['projectionPath'][-12:]
    case=next(c for c in receipt['cases'] if c['id']=='entry-plus17');image_path=Path(case['args']['target'])
    with locked_file(image_path,4*1024**2) as raw:
        assert hashlib.sha256(raw).hexdigest()==entry['targetSha256']=='5f9c1b6fcb019366f835d8f02d9ec3b2957fe619e039410d07f288a9c73f63f0';image=BinaryImage.from_bytes(raw)
    for core in cores.values():
        assert core['targetSha256']==entry['targetSha256'] and all(core[k] is False for k in ('nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'))
        assert len(core['registers'])==16 and all(image.read(int(r['ea'],16),r['decoded']['size']).hex()==r['bytes'] for r in core['decodedPath'])
    rows=proof['queries'];assert len(rows)==19 and len({r['name'] for r in rows})==19
    whole=proof['wholeContextPreservationQuery'];assert rows[whole]['name']=='all17-context-words-preserved-by-literal-dispatch-and-next-stack-write'
    for i,row in enumerate(rows):
        assert row['status']==row['expected'] and row['status'] in ('sat','unsat') or i==whole and row['status']=='unknown'
        assert 0<row['timeoutMs']<=2000 and row['encodedDepth']<=128 and row['bytes']<=1024**2
        file=Path(row['path']);assert file.parent==source.parent/'queries'
        with locked_file(file,1024**2) as raw:
            assert len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256'];text=raw.decode('ascii')
        assert text.count('(')==row['encodedSexpressions']<=2048 and len(re.findall(r'[^\s()]+',text))==row['encodedAtomTokens']<=8192
        assert text.startswith(f'(set-option :timeout {row["timeoutMs"]})\n(set-option :memory_max_size 512)\n') and text.endswith('\n(check-sat)\n')
        assert not row.get('weakenedLoadNodes')
        if row.get('explicitCuts'):assert row['explicitCuts']==[s1['beforeMemory']] and row['wholeSourceDagValidated']
    def unsat(i,name=None):assert rows[i]['status']=='unsat' and (name is None or rows[i]['name']==name)
    assert len(proof['localSummaryCertificates'])==4
    for c in proof['localSummaryCertificates']:
        unsat(c['query']);assert not rows[c['query']]['explicitCuts'] and rows[c['query']]['wholeSourceDagValidated']
    for key in ('joinedGuardFalseRangeQuery','previousFastImpliesCurrentFastQuery','newWriteWindowQuery','contextWordNonaliasQuery','contextZeroReadQuery','nextTargetQuery','joinedAll16StateAndFinalDispatchMemoryQuery'):unsat(proof[key])
    for i in proof['negativeControls']+proof['bothLocalGuardDirectionsSATQueries']+[proof['premisesSatisfiableQuery']]:assert rows[i]['status']=='sat'
    assert proof['joinedGuardFalseInitialRSPRange']==[16,263] and proof['contextOperand']==48 and proof['contextLoadedValue']=='0x0'
    c=proof['contextPreservationCertificate'];slots=[x['slotByteOffset'] for x in context['contextMap']]
    assert c['slots']==slots and len(set(slots))==17 and all(0<=x<=255 for x in slots)
    assert c['readByteOffsets']==c['writeByteOffsets']==list(range(8)) and c['newOrderedWriteAddresses']==['S-8','F-8','S-16','F-8']
    assert c['allBytePairNonaliasQuery']==proof['contextWordNonaliasQuery'] and c['all17ContextWordsPreserved'] and c['noNodeIdInequalityUsed'] and c['wholeQueryUnknownNotUsedAsProof']
    assert c['incomingSingleBytePreservationQuery']==context['lemmas']['bytePreservation'] and context['queries'][c['incomingSingleBytePreservationQuery']]['status']=='unsat'
    zero=next(x for x in context['contextMap'] if x['slotByteOffset']==48)
    assert zero==proof['contextSlot48SourceCertificate'] and zero['valueLabel']=='zero' and zero['latestEntryStoreIndex']==17
    assert entry['dag']['nodes'][entry['stores'][17]['value']]['value']=='0x0'
    cut=s1['beforeMemory'];assert cut==s0['afterMemory']==proof['nextTargetCurrentMemoryCut']
    node=fast['dag']['nodes'][cut];assert node['op']=='store_le' and node['size']==8 and node['args']==[s0['beforeMemory'],s0['address'],s0['value']]
    assert s0['beforeMemory']==fast['initialMemory'] and fast['currentMemory']==s1['afterMemory'] and len(fast['sideExits'])==1
    facts={int(a,16):v for a,v in proof['initialImageByteFacts']};expected={int(a,16):v for a,v in context['initialImageByteFacts']}
    for a,v in literal['extraInitialImageByteFacts']+proof['additionalInitialByteFacts']:
        a=int(a,16);assert a not in expected or expected[a]==v;expected[a]=v
    assert facts==expected and len(facts)==66 and len(proof['additionalInitialByteFacts'])==6
    assert all(image.read(a,1)[0]==v for a,v in facts.items())
    vip=image.imagebase+0x846c4;table=image.imagebase+0x56098;opcode=facts[vip+45]
    target=table+int.from_bytes(bytes(facts[table+4*opcode+i] for i in range(4)),'little',signed=True)
    assert facts[vip+44]==48 and proof['nextSelector']==opcode==250 and proof['nextTarget']==hex(target)=='0x140055f66'
    d=proof['memoryFactDerivation'];assert d['originalOrderedWrites']==len(entry['stores'])==55 and d['originalBindings']==len(entry['layers'])==18
    for field,source_field in (('originalImagePreservationLemma','preservationLemma'),('originalImageSeparationLemma','imageSeparationLemma')):
        assert d[field]==domain['window'][source_field] and domain['queries'][d[field]]['status']=='unsat'
    assert proof['limits']==domain['limits'] and not proof['publicCrossReportJoinIntegrated']
    assert all(proof[k] is False for k in ('nativeTargetExecuted','databaseModified','architectureProved','businessAccepted','wholeBinaryVerified'))
    result={'schema':'ig5-handler137-certificate-readback-v1','passed':True,'proofSha256':digest,'queries':len(rows),'statuses':{s:sum(r['status']==s for r in rows) for s in ('unsat','sat','unknown')},
        'allQueryBytesLimitsAndStatusesChecked':True,'allFourUncutFullStateCertificatesChecked':True,'cutBoundToOriginalFirstStorePostMemory':True,
        'all17ContextFiniteBytePreservationIndicesAndIncomingLemmaChecked':True,'unknownNotUsedAsUnsat':True,'all66SourceImageBytesReRead':True,
        'contextZeroBoundToLaterEntryStore17':True,'full28InstructionPathAnd16PrefixByteBindingChecked':True,'nextSelector':250,'nextTarget':hex(target),
        'scope':'Independent certificate and original-data readback only. No new SMT solve, numeric coverage or CPU equivalence is claimed.','businessAccepted':False,'wholeBinaryVerified':False}
    with out.open('x',encoding='utf8') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps(result))


if __name__=='__main__':main()
