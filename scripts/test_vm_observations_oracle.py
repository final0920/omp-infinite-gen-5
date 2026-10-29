"""Data-only differential check using the existing independent Python parser.
Input JSON: {cases:[{name, windows:[{dataBase64}], result}]}.
Never loads Triton, decodes a PE, attaches a debugger or executes a target.
"""
import base64
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'worker'))
from trace_analysis import parse_trace

def verify(case):
    result = case['result']
    groups, instruction_count, read_count = [], 0, 0
    for window in case['windows']:
        parsed = parse_trace(base64.b64decode(window['dataBase64'], validate=True), 100000)
        assert parsed.final_registers is not None
        start = len(groups)
        for index, (ea, code, registers, memory) in enumerate(parsed):
            instruction_count += 1
            read_count += len(memory)
            if registers is None:
                groups[-1]['instructions'].append((ea, code))
            else:
                groups.append({'instructions': [(ea, code)], 'registers': registers, 'flags': parsed.flag_snapshots[index], 'memory': memory})
        for index in range(start, len(groups)):
            nxt = groups[index + 1] if index + 1 < len(groups) else None
            groups[index]['after'] = (nxt['registers'], nxt['instructions'][0][0], nxt['flags']) if nxt else (parsed.final_registers[:16], parsed.final_registers[16], parsed.final_registers[17])
    assert result['totals']['instructions'] == instruction_count
    assert result['totals']['stopGroups'] == len(groups)
    assert result['totals']['memoryReads'] == read_count
    names = 'rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split()
    for group in result['stopGroups']:
        expected = groups[group['groupIndex']]
        assert [int(group['before']['gprs'][name], 16) for name in names] == expected['registers']
        assert int(group['before']['flags'], 16) == expected['flags']
        assert [(int(item['pc'], 16), bytes.fromhex(item['bytes'])) for item in group['instructions']] == expected['instructions']
        assert [(int(item['address'], 16), item['bytes'], int.from_bytes(bytes.fromhex(item['littleEndianHex']), 'little')) for item in group['memoryReads']] == expected['memory']
        after, rip, flags = expected['after']
        assert [int(group['after']['gprs'][name], 16) for name in names] == after
        assert int(group['after']['rip'], 16) == rip and int(group['after']['flags'], 16) == flags
        assert group['intermediateStateAvailable'] == (len(expected['instructions']) == 1)

if __name__ == '__main__':
    dataset = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8-sig'))
    assert 1 <= len(dataset['cases']) <= 256
    for item in dataset['cases']:
        verify(item)
    assert 'triton' not in sys.modules
    print(json.dumps({'passed': True, 'cases': len(dataset['cases']), 'nativeTargetExecuted': False, 'tritonLoaded': False}))
