"""Independent candidate audit + exact raw recording correlation. No phase/CPU proof."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
manifest = json.loads((root / 'phase-context-replay.json').read_text(encoding='utf-8'))
digest = lambda data: hashlib.sha256(data).hexdigest()
compact = lambda value: json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
for ref in manifest['inputRefs']:
    assert digest(Path(ref['path']).read_bytes()) == ref['sha256']
context_path = Path(manifest['inputRefs'][0]['path'])
model = json.loads(context_path.read_text(encoding='utf-8'))['result']
independent = Path(__file__).with_name('verify_vm_context_model.py')
audit = subprocess.run([sys.executable, '-I', '-B', str(independent), str(context_path), manifest['contextRef']['sha256']], capture_output=True, text=True, check=True)
assert json.loads(audit.stdout)['passed'] is True
parents = []
for refs in model['sourceReports']:
    loaded = {k: json.loads(Path(refs[k]['path']).read_text(encoding='utf-8'))['result'] for k in ['selection', 'recurrence']}
    parents.append((refs, loaded))
windows = parents[0][1]['selection']['source']['windows']
expected_bodies, fetches, heads, cycles = {}, {}, {}, []
for refs, loaded in parents:
    assert loaded['selection']['source']['windows'] == windows
    assert loaded['recurrence']['source']['windows'] == windows
    for occurrence, body in zip(loaded['recurrence']['occurrences'], loaded['selection']['bodies'], strict=True):
        cycle = {'occurrence': occurrence, 'body': body, 'refs': refs}
        ordinal = len(cycles)
        cycles.append(cycle)
        assert body['groups'][0]['groupIndex'] == occurrence['endGroup'] + 1
        assert body['nextFetchGroup'] == body['groups'][-1]['groupIndex'] + 1
        for index, descriptor in enumerate(loaded['recurrence']['descriptor']):
            point = occurrence['startGroup'] + index
            assert point not in fetches
            fetches[point] = (ordinal, descriptor, index)
        for group in body['groups']:
            assert group['groupIndex'] not in expected_bodies
            expected_bodies[group['groupIndex']] = group
        heads[body['nextFetchGroup']] = loaded['recurrence']['descriptor'][0]
names = 'rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split()
all_needed = set(fetches) | set(expected_bodies) | set(heads)
actual, versions = {}, {}
global_group = 0
artifact_root = context_path.parent.parent.parent

def snapshot(regs, flags, pc, line):
    return {'gprs': {name: hex(value) for name, value in zip(names, regs, strict=True)}, 'rip': hex(pc), 'flags': hex(flags),
            'sourceLine': line, 'assurance': 'recorded-observation-not-predicted-state'}


for window in windows:
    source_path = artifact_root / 'debug-traces' / 'records' / (window['reportId'] + '.json')
    source_bytes = source_path.read_bytes()
    assert digest(source_bytes) == window['reportSha256']
    record = json.loads(source_bytes)['result']
    assert not record.get('storeEvents'), 'Independent audit currently requires legacy no-STORE recordings'
    raw = (artifact_root / 'debug-traces' / 'blobs' / (record['sha256'] + '.bin')).read_bytes()
    assert digest(raw) == window['traceSha256'] == record['sha256']
    previous, pending, pending_line, flags, reads, active, local = None, None, None, None, [], None, 0
    location = record.get('executionLocation')
    location = {k: location[k] for k in ['kind', 'profileSha256', 'guestCID', 'bundleSha256', 'serverInstanceId', 'sessionId'] if k in location} if location else None
    fingerprint = digest(compact(location))

    def finish(regs, flags_value, pc, line):
        if active is None:
            return
        active['after'] = snapshot(regs, flags_value, pc, line)
        if active['groupIndex'] in all_needed:
            actual[active['groupIndex']] = active.copy()

    def instruction(fields, line, first):
        index = global_group + local - 1
        pc, code = hex(int(fields[1], 16)), fields[3].lower()
        insn = {'pc': pc, 'bytes': code, 'sourceLine': line, 'codeObservationSha256': digest((pc + ':' + code).encode('ascii')), 'beforeStateAvailable': first}
        if not first:
            insn.update(continuationSemanticsValidated=False, reason='No intermediate GPR/flags snapshot was recorded')
        binding = {'targetSha256': record['targetSha256'], 'runId': record['runId'], 'threadId': record['threadId'],
                   'runtimeBase': record['runtimeBase'], 'locationFingerprint': fingerprint, 'reportId': window['reportId'],
                   'reportSha256': window['reportSha256'], 'traceSha256': record['sha256'], 'groupIndex': index,
                   'beforeStopSeq': record['startStopSeq'] + local - 1, 'afterStopSeq': record['startStopSeq'] + local,
                   'sourceLine': line, 'pc': pc, 'bytes': code, 'beforeStateAvailable': first}
        entry = versions.setdefault(index, {'first': digest(compact(binding))})
        entry['last'] = digest(compact(binding))
        return insn

    for line, text in enumerate(raw.decode('ascii').splitlines(), 1):
        fields = text.split(':')
        if fields[0] == 'r':
            pending = [int(value, 16) for value in fields[1:]]
            pending_line = line
        elif fields[0] == 'd':
            mask = int(fields[1], 16)
            pending = previous.copy()
            cursor = iter(fields[2:])
            for bit in range(16):
                if mask & (1 << bit):
                    pending[bit] = int(next(cursor), 16)
            pending_line = line
        elif fields[0] == 'e':
            flags = int(fields[1], 16)
        elif fields[0] == 'mr':
            size = int(fields[2])
            reads.append({'address': hex(int(fields[1], 16)), 'bytes': size, 'littleEndianHex': int(fields[3], 16).to_bytes(size, 'little').hex(),
                          'sourceLine': line, 'meaning': 'observed-memory-read-not-bytecode-or-input-classification'})
        elif fields[0] == 'i':
            pc = int(fields[1], 16)
            finish(pending, flags, pc, pending_line)
            local += 1
            active = {'groupIndex': global_group + local - 1, 'recordingId': window['reportId'], 'phase': 'unclassified',
                      'pauseSequence': {'before': record['startStopSeq'] + local - 1, 'after': record['startStopSeq'] + local,
                                        'source': 'derived-from-recorded-window-order-and-confirmed-step-count', 'individuallyAttested': False},
                      'before': snapshot(pending, flags, pc, pending_line), 'instructions': [instruction(fields, line, True)],
                      'memoryReads': reads, 'intermediateStateAvailable': True,
                      'memoryWrites': {'status': 'not-recorded-by-this-format', 'effectsNotInferredFromReads': True}}
            previous, pending, flags, reads = pending.copy(), None, None, []
        elif fields[0] == 'c':
            active['instructions'].append(instruction(fields, line, False))
            active['intermediateStateAvailable'] = False
        elif fields[0] == 'f':
            values = [int(value, 16) for value in fields[1:]]
            finish(values[:16], values[17], values[16], line)
    assert local == window['confirmedStopGroups']
    global_group += local

assert set(actual) == all_needed
for point, expected in expected_bodies.items():
    assert actual[point] == expected, ('body', point)
source_reads = set()
for point, (ordinal, descriptor, offset) in fetches.items():
    group, occurrence = actual[point], cycles[ordinal]['occurrence']
    assert len(group['instructions']) == 1 and group['instructions'][0]['pc'] == descriptor['runtimePc'] and group['instructions'][0]['bytes'] == descriptor['bytes']
    if point == occurrence['startGroup']:
        assert group['before']['gprs'] == occurrence['initialGprs'] and group['pauseSequence']['before'] == occurrence['firstPause']
    if point == occurrence['endGroup']:
        assert group['after']['gprs'] == occurrence['finalGprs'] and group['after']['rip'] == occurrence['target'] and group['pauseSequence']['after'] == occurrence['lastPause']
    if any(r['address'] == occurrence['sourceAddress'] and r['bytes'] == occurrence['sourceBytes'] and int.from_bytes(bytes.fromhex(r['littleEndianHex']), 'little') == int(occurrence['sourceValue'], 16) for r in group['memoryReads']):
        source_reads.add(ordinal)
assert len(source_reads) == len(cycles)
for point, descriptor in heads.items():
    assert actual[point]['instructions'][0]['pc'] == descriptor['runtimePc'] and actual[point]['instructions'][0]['bytes'] == descriptor['bytes']
expected_segments = []
for cycle in cycles:
    o, b, refs = cycle['occurrence'], cycle['body'], cycle['refs']
    for kind, start, end in [('fetch-dispatch-candidate', o['startGroup'], o['endGroup']), ('handler-body-candidate', b['groups'][0]['groupIndex'], b['groups'][-1]['groupIndex'])]:
        expected_segments.append({'kind': kind, 'occurrence': o['startGroup'], 'startGroup': start, 'endGroup': end,
                                  'firstVersionId': versions[start]['first'], 'lastVersionId': versions[end]['last'],
                                  'sourceRecurrence': {k: refs['recurrence'][k] for k in ['id', 'sha256']},
                                  'sourceSelection': {k: refs['selection'][k] for k in ['id', 'sha256']},
                                  'status': 'observed-candidate', 'intervalStable': 'unknown'})
for page in manifest['pages']:
    data = Path(page['reportPath']).read_bytes()
    assert digest(data) == page['reportSha256']
    model = json.loads(data)['result']['phaseModel']
    assert model['contextAnnotation']['segments'] == expected_segments
    assert model['contextAnnotation']['phaseClassificationProved'] is False
    for row in model['groups']:
        point = row['groupIndex']
        kind = 'fetch-dispatch-candidate' if point in fetches else 'handler-body-candidate' if point in expected_bodies else 'unclassified-prefix' if point < min(fetches) else 'unclassified-context-gap'
        assert row['contextPhase']['kind'] == kind
        assert row['phase'] == 'unknown' and row['verifiedPhase'] is None
report = {'schema': 'ig5-phase-context-raw-audit-v1', 'ok': True, 'windows': len(windows), 'rawGroups': global_group,
          'cycles': len(cycles), 'selectedGroupsMatched': len(set(fetches) | set(expected_bodies)), 'nextFetchHeads': len(heads),
          'segments': len(expected_segments), 'auditorSha256': digest(Path(__file__).read_bytes()),
          'contextAuditorSha256': digest(independent.read_bytes()), 'phaseClassificationProved': False,
          'scope': 'Independent candidate derivation, selected raw snapshots, fetch read/state/boundary correlation and endpoint identities; no CPU/VM stage/business proof'}
(root / 'raw-context-audit.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
print(json.dumps(report))
