"""Read local PE exports to label saved owned debugger addresses; no execution."""
import json
from pathlib import Path
import struct
import sys

folder = Path(sys.argv[1])
receipt = json.loads((folder / 'receipt.json').read_text(encoding='utf-8'))
diagnostics = receipt['diagnostics']
modules = diagnostics['modules']['modules']
def exports(filename):
    data = Path(filename).read_bytes()
    if len(data) > 64 * 1024 * 1024: raise ValueError('Local PE budget exceeded')
    u16 = lambda off: struct.unpack_from('<H', data, off)[0]
    u32 = lambda off: struct.unpack_from('<I', data, off)[0]
    pe = u32(0x3c); optional = pe + 24; sections = optional + u16(pe + 20)
    def raw(rva):
        for i in range(u16(pe + 6)):
            header = sections + i * 40
            start, size = u32(header + 12), u32(header + 16)
            if start <= rva < start + size: return u32(header + 20) + rva - start
        raise ValueError('Unbacked export RVA')
    directory_rva = u32(optional + (112 if u16(optional) == 0x20b else 96))
    if not directory_rva: return []
    directory = raw(directory_rva)
    functions, names, ordinals = [raw(u32(directory + n)) for n in (28, 32, 36)]
    count = u32(directory + 24)
    if count > 65536: raise ValueError('Export budget exceeded')
    rows = []
    for i in range(count):
        offset = raw(u32(names + i * 4))
        name = data[offset:data.index(0, offset, min(len(data), offset + 4096))].decode('ascii')
        rows.append((u32(functions + 4 * u16(ordinals + i * 2)), name))
    return sorted(rows)
loaded = {}
def describe(value):
    ea = int(value, 16)
    for module in modules:
        base = int(module['base'], 16)
        if base <= ea < base + module['size']:
            if module['path'] not in loaded: loaded[module['path']] = exports(module['path'])
            rows = [row for row in loaded[module['path']] if row[0] <= ea - base]
            if not rows: return {'ea': value, 'module': module['name'], 'rva': hex(ea - base)}
            nearest = rows[-1][0]
            return {'ea': value, 'module': module['name'], 'nearestExports': [name for rva, name in rows if rva == nearest], 'offset': hex(ea - base - nearest), 'exactFunctionBoundaryNotProved': True}
    return {'ea': value, 'mappedModule': False}
result = {'mainThread': describe(diagnostics['mainThread']['selectedThreadRegs']['rip']), 'stackCandidates': []}
if 'mainStack' in diagnostics:
    stack = bytes.fromhex(diagnostics['mainStack']['hex'])
    for value in struct.unpack('<' + 'Q' * (len(stack) // 8), stack):
        label = describe(hex(value))
        if 'module' in label: result['stackCandidates'].append(label)
(folder / 'thread-address-labels.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
print(json.dumps(result))
