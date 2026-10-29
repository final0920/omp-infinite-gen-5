"""Independent finite reference and interval audit of the JS profile's output.

Intervals are enumerated from code-byte observation lists, rather than using the
JS pending-byte tracker. Does not execute code or certify native collection.
"""
import copy
import importlib.util
import json
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location('fixed_phase_reference', Path(__file__).parent / 'fixtures' / 'phase_reference.py')
ref = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ref)


def checked(path, sha):
    raw = Path(path).read_bytes()
    assert ref.digest(raw) == sha, f'Changed evidence: {path}'
    return json.loads(raw)


def audit_case(root, entry, case):
    original, trace, sidecar, summary, oracle = ref.reference(entry['patch'], entry['mode'])
    for name, expected in [('program.bin', original), ('trace.bin', trace), ('stores.json', sidecar),
                           ('summary.json', ref.encode(summary)), ('oracle.json', ref.encode(oracle))]:
        raw = (root / entry['name'] / name).read_bytes()
        assert raw == expected and ref.digest(raw) == entry['files'][name]
    record = checked(case['recording']['path'], case['recording']['sha256'])
    body = record['result']
    blob_root = Path(case['recording']['path']).parent.parent / 'blobs'
    assert (blob_root / (ref.digest(trace)+'.bin')).read_bytes() == trace
    assert (blob_root / (ref.digest(sidecar)+'.bin')).read_bytes() == sidecar
    assert body['fixtureMode'] == 'offline-reference-no-native-execution'
    assert all(body[k] == v for k, v in summary.items())
    events = json.loads(sidecar)['events']
    points, addresses = [], {}
    for i, step in enumerate(oracle):
        binding = dict(targetSha256=summary['targetSha256'], runId=summary['runId'], threadId=7, runtimeBase='0x1000',
                       locationFingerprint=ref.digest(b'null'), reportId=case['recording']['id'],
                       reportSha256=case['recording']['sha256'], traceSha256=summary['sha256'], groupIndex=i,
                       beforeStopSeq=i+1, afterStopSeq=i+2, sourceLine=4+3*i, pc=step['pc'], bytes=step['code'], beforeStateAvailable=True)
        point = dict(id=ref.digest(ref.encode(binding)), binding=binding)
        points.append(point)
        for offset, byte in enumerate(bytes.fromhex(step['code'])):
            addresses.setdefault(int(step['pc'],16)+offset, []).append((i, byte, point['id']))
    # Enumerate every interval independently. The first recorded changed snapshot
    # inside it is referenced; overlapping observations remain explicitly ambiguous.
    links, changes, epoch_at = {}, {}, {}
    overlap_count = ambiguous_count = 0
    for address, observations in addresses.items():
        for previous, following in zip(observations, observations[1:]):
            a, before, old_id = previous
            b, after, new_id = following
            if before != after:
                changes.setdefault(b, []).append(dict(address=hex(address), before=f'{before:02x}', after=f'{after:02x}', priorVersionId=old_id))
            candidates = [(e, index, s) for e in events[a:b] for index, s in enumerate(e['stores'])
                          if s['changed'] is True and int(s['address'],16) <= address < int(s['address'],16)+s['bytes']]
            if candidates:
                event, index, store = candidates[0]
                offset = address - int(store['address'],16)
                store_before, store_after = store['beforeHex'][2*offset:2*offset+2], store['afterHex'][2*offset:2*offset+2]
                link = dict(address=hex(address), source=dict(recordingId=record['id'], reportSha256=case['recording']['sha256'],
                            traceSha256=summary['sha256'], storeBlobSha256=ref.digest(sidecar), groupIndex=event['groupIndex'], storeIndex=index,
                            beforeStopSeq=event['beforeStopSeq'], afterStopSeq=event['afterStopSeq']), byteOffset=offset,
                            priorCodeVersionId=old_id, nextCodeVersionId=new_id, priorCodeByte=f'{before:02x}', storeBeforeByte=store_before,
                            storeAfterByte=store_after, nextCodeByte=f'{after:02x}', beforeMatches=store_before == f'{before:02x}',
                            afterMatches=store_after == f'{after:02x}', observationCount=len(candidates), ambiguous=len(candidates) > 1,
                            scope='first-store-snapshot-to-next-code-observation; intervening writes and causes unknown',
                            actualWriteCausalityProved=False, intervalStable='unknown')
                links.setdefault(b, []).append(link)
                overlap_count += len(candidates)
                ambiguous_count += len(candidates)-1
    epoch = 0
    for i in range(19):
        if changes.get(i): epoch += 1
        epoch_at[i] = epoch

    def verify(result, phase):
        assert len(result['stopGroups']) == (1 if result['pagination']['offset'] else 19)
        for group in result['stopGroups']:
            i = group['groupIndex']; truth = oracle[i]
            assert group['before']['gprs'] == truth['beforeGprs'] and group['after']['gprs'] == truth['afterGprs']
            assert group['before']['flags'] == truth['beforeFlags'] and group['after']['flags'] == truth['afterFlags']
            assert group['before']['rip'] == truth['pc'] and group['after']['rip'] == truth['afterPc']
            assert group['instructions'][0]['bytes'] == truth['code']
            assert group['memoryWrites']['stores'] == events[i]['stores']
        if not phase:
            assert 'phaseModel' not in result
            return
        model = result['phaseModel']
        assert model['phaseVerified'] is False and model['writesAttributedToInstructions'] is False
        assert model['smcCoverageComplete'] is False and model['businessAccepted'] is False
        assert model['counts']['codeChangeGroups'] == len(changes)
        assert model['counts']['groups'] == 19 and model['counts']['firstVisits'] == 9
        assert model['counts']['revisits'] == 10 and model['counts']['unindexedVisits'] == 0
        assert model['counts']['memoryChangeGroups'] == sum(any(s['changed'] is True for s in e['stores']) for e in events)
        assert model['counts']['missingStoreGroups'] == 0
        assert model['codeEpochs']['observedChangedBytes'] == sum(map(len, changes.values()))
        assert model['codeEpochs']['observationEpoch'] == epoch
        timeline = model['codeEpochs']['storeTimeline']
        assert timeline['changedObservations'] == sum(s['changed'] is True for e in events for s in e['stores'])
        assert timeline['overlappingBytes'] == overlap_count and timeline['ambiguousBytes'] == ambiguous_count
        assert timeline['reobservedBytes'] == sum(map(len, links.values()))
        assert timeline['matchingBytes'] == sum(l['beforeMatches'] and l['afterMatches'] for ls in links.values() for l in ls)
        assert timeline['conflictingBytes'] == 0 and timeline['pendingBytes'] == 0
        assert timeline['actualWriteCausalityProved'] is False
        for row in model['groups']:
            i = row['groupIndex']; point = points[i]
            assert row['phase'] == 'unknown' and row['verifiedPhase'] is None
            assert all(row[k] == 'unknown' for k in ['initialization','dispatch','business'])
            observed = row['versions'][0]
            assert observed['version']['id'] == point['id'] and observed['version']['binding'] == point['binding']
            assert observed['version']['validBetweenObservations'] is False
            assert observed['relation']['storeObservations'] == sorted(links.get(i, []), key=lambda l:int(l['address'],16))
            assert observed['relation']['changedBytes'] == sorted(changes.get(i, []), key=lambda c:int(c['address'],16))
            assert observed['relation']['observationEpoch'] == epoch_at[i]
            assert observed['relation']['intervalStable'] == 'unknown'
            assert row['events']['unchangedBytesProveNoWrite'] is False
            assert row['events']['unknownStores'] == sum(s['changed'] is None for s in events[i]['stores'])
            assert row['events']['unchangedByteObservations'] == sum(s['changed'] is False for s in events[i]['stores'])
    results = [checked(r['path'],r['sha256'])['result'] for r in case['reports']]
    for index, result in enumerate(results): verify(result, index < 2)
    assert results[0]['phaseModel']['groups'][9] == results[1]['phaseModel']['groups'][0]
    # Self-consistent output changes must still fail this independent oracle.
    corruptions = [lambda r:r['stopGroups'][0]['after']['gprs'].__setitem__('rax','0x0'),
                   lambda r:r['phaseModel']['counts'].__setitem__('codeChangeGroups',99),
                   lambda r:r['phaseModel'].__setitem__('phaseVerified',True)]
    if entry['name'] == 'clc':
        corruptions += [lambda r:r['phaseModel']['groups'][9]['versions'][0]['relation']['storeObservations'][0].__setitem__('afterMatches',False)]
    for change in corruptions:
        wrong = copy.deepcopy(results[0]); change(wrong)
        try: verify(wrong, True)
        except AssertionError: pass
        else: raise AssertionError('Independent oracle accepted a deliberately false result')
    return dict(name=entry['name'], groups=19, referenceRegions=sorted({s['fixtureRegion'] for s in oracle}),
                linkedBytes=sum(map(len,links.values())), changedCodeGroups=len(changes), independentNegativeChecks=len(corruptions))


root, output = map(lambda p:Path(p).resolve(), sys.argv[1:3])
receipt = json.loads((output/'acceptance.json').read_text(encoding='utf-8'))
manifest = checked(root/'reference-fixtures.json',receipt['fixtureManifestSha256'])
assert manifest['referenceSha256'] == ref.digest(Path(ref.__file__).read_bytes())
assert receipt['cleanupConfirmed'] and receipt['sourceInputsUnchanged'] and not receipt['nativeTargetExecuted']
assert [c['name'] for c in receipt['cases']] == [c['name'] for c in manifest['cases']]
cases = [audit_case(root,entry,case) for entry,case in zip(manifest['cases'],receipt['cases'],strict=True)]
report = dict(schema='ig5-phase-reference-independent-audit-v1',ok=True,cases=cases,
              referenceSha256=manifest['referenceSha256'],auditorSha256=ref.digest(Path(__file__).read_bytes()),
              negativeChecks=sum(c['independentNegativeChecks'] for c in cases),nativeTargetExecuted=False,
              phaseClassificationProved=False,scope='Finite independent instruction reference, raw snapshots and STORE/code intervals; not native CPU or general VM stage proof')
(output/'independent-audit.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps(report))
