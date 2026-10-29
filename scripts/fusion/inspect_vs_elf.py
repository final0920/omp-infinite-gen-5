"""Read-only original ELF byte check. Does not import or run VS1.5 code."""
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'adapters' / 'ghidra'))
from elf_addresses import parse_loads, convert


def main():
    source, output = map(Path, sys.argv[1:])
    if not source.is_absolute() or not output.is_absolute():
        raise ValueError('Explicit absolute input and new output required')
    source = source.resolve(strict=True)
    parent = output.parent.resolve(strict=True)
    if parent == source.parent or source.parent in parent.parents:
        raise ValueError('Output must be outside source directory')
    data = source.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != 'f18037fdf042ab0b4628546dbcc81f4f9db50000391381c3922ae99257e55de0':
        raise ValueError('Original ELF identity mismatch')
    if data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 183:
        raise ValueError('Expected little-endian ARM64 ELF64')
    loads = parse_loads(lambda offset, count: data[offset:offset+count], len(data))
    checks = []
    for address, expected, register in [(0x50434, 0x2A1F03F3, 'w19'), (0x50438, 0x2A1F03F9, 'w25')]:
        offset = int(convert(hex(address), 'elf_vaddr', 'file_offset', loads, []), 16)
        raw = data[offset:offset+4]
        word = int.from_bytes(raw, 'little')
        checks.append(dict(elfVaddr=hex(address), fileOffset=hex(offset), rawHex=raw.hex(), word=hex(word),
                           exactExpectedEncoding=word == expected, expectedInstruction='ORR '+register+', wzr, wzr (MOV alias)'))
    result = dict(schema='ig5-vs-original-static-bytes-v1', sourceSha256=digest, ptLoads=loads, checks=checks,
                  byteChecksPassed=all(row['exactExpectedEncoding'] for row in checks), nativeExecuted=False,
                  originalScriptsImported=False, cpuProof=False, haltDispatchTargetProved=False,
                  conclusion='Two adjacent clears have distinct destinations; which entry HALT reaches remains an independent control-flow obligation.')
    with output.open('x', encoding='utf8') as target:
        json.dump(result, target, indent=2)
    if not result['byteChecksPassed']:
        raise ValueError('Original bytes disagree with historical instruction locators; preserve conflict')
    print(json.dumps(dict(byteChecksPassed=True, haltDispatchTargetProved=False)))


if __name__ == '__main__':
    main()
