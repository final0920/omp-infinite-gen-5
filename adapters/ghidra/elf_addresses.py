"""Bounded ELF PT_LOAD and exact source mapping; never infer a global rebase."""
import struct
import re

MAX = (1 << 64) - 1


def uint(value):
    if not isinstance(value, str) or not re.fullmatch(r'0[xX][0-9a-fA-F]+', value):
        raise ValueError('ADDRESS_SPACE_REQUIRED: address must be an explicit hex string')
    if len(value) > 18:
        raise ValueError('ADDRESS_OVERFLOW: address is outside uint64')
    number = int(value, 16)
    if not 0 <= number <= MAX:
        raise ValueError('ADDRESS_OVERFLOW: address is outside uint64')
    return number


def parse_loads(read, size):
    header = read(0, min(size, 64))
    if len(header) < 52 or header[:4] != b'\x7fELF' or header[4] not in (1, 2) or header[5] not in (1, 2):
        raise ValueError('ELF_MAPPING_UNAVAILABLE: source is not a supported ELF')
    wide, endian = header[4] == 2, '<' if header[5] == 1 else '>'
    if wide and len(header) < 64:
        raise ValueError('ELF_MAPPING_INVALID: short ELF64 header')
    fields = struct.unpack_from(endian + ('HHIQQQIHHHHHH' if wide else 'HHIIIIIHHHHHH'), header, 16)
    phoff, entsize, count = fields[4], fields[8], fields[9]
    expected = 56 if wide else 32
    if entsize != expected or not 1 <= count <= 1024 or phoff + count * entsize > size:
        raise ValueError('ELF_MAPPING_INVALID: program header table exceeds bounds')
    table = read(phoff, count * entsize)
    loads = []
    for index in range(count):
        row = struct.unpack_from(endian + ('IIQQQQQQ' if wide else 'IIIIIIII'), table, index * entsize)
        if row[0] != 1:
            continue
        offset, vaddr, filesz, memsz = (row[2], row[3], row[5], row[6]) if wide else (row[1], row[2], row[4], row[5])
        if filesz > memsz or offset + filesz > size or vaddr + memsz > MAX + 1:
            raise ValueError('ELF_MAPPING_INVALID: invalid PT_LOAD range')
        if memsz:
            loads.append(dict(offset=offset, vaddr=vaddr, filesz=filesz, memsz=memsz))
    if not loads:
        raise ValueError('ELF_MAPPING_INVALID: no PT_LOAD')
    return loads


def unique(rows):
    if len(rows) != 1:
        raise ValueError('AMBIGUOUS_MAPPING' if rows else 'UNMAPPED_ADDRESS')
    return rows[0]


def convert(value, space, destination, loads, sources):
    number = uint(value)
    if space not in ('elf_vaddr', 'ghidra_va', 'file_offset', 'module_offset') or destination not in ('elf_vaddr', 'ghidra_va', 'file_offset', 'module_offset'):
        raise ValueError('RUNTIME_MAPPING_UNAVAILABLE: runtime_va requires a separately observed run/module/load epoch')
    minimum = min(s['vaddr'] for s in loads)
    if space == 'ghidra_va':
        source = unique([s for s in sources if s['start'] <= number < s['start'] + s['size']])
        number = source['offset'] + number - source['start']
        unique([s for s in sources if s['offset'] <= number < s['offset'] + s['size']])
        space = 'file_offset'
    if space == 'file_offset':
        segment = unique([s for s in loads if s['offset'] <= number < s['offset'] + s['filesz']])
        number = segment['vaddr'] + number - segment['offset']
    elif space == 'module_offset':
        number += minimum
        if number > MAX:
            raise ValueError('ADDRESS_OVERFLOW')
    segment = unique([s for s in loads if s['vaddr'] <= number < s['vaddr'] + s['memsz']])
    elf_vaddr = number
    if destination == 'elf_vaddr':
        return hex(number)
    if destination == 'module_offset':
        return hex(number - minimum)
    delta = number - segment['vaddr']
    if delta >= segment['filesz']:
        raise ValueError('NOT_FILE_BACKED: BSS has no source file bytes')
    offset = segment['offset'] + delta
    # Both source and destination mappings must be unique.
    unique([s for s in loads if s['offset'] <= offset < s['offset'] + s['filesz']])
    if destination == 'file_offset':
        return hex(offset)
    source = unique([s for s in sources if s['offset'] <= offset < s['offset'] + s['size']])
    address = source['start'] + offset - source['offset']
    if address > MAX:
        raise ValueError('ADDRESS_OVERFLOW')
    unique([s for s in sources if s['start'] <= address < s['start'] + s['size']])
    return hex(address)


def program_mapping(worker):
    memory = worker.program.getMemory()
    files = list(memory.getAllFileBytes())
    file = unique([f for f in files if int(f.getFileOffset()) == 0])
    def read(offset, size):
        data = worker.jpype.JArray(worker.jpype.JByte)(size)
        if int(file.getOriginalBytes(offset, data)) != size:
            raise ValueError('ELF_MAPPING_INVALID: incomplete original file snapshot')
        return bytes(data)
    loads = parse_loads(read, int(file.getSize()))
    sources = []
    blocks = memory.getBlocks()
    if len(blocks) > 1024:
        raise ValueError('ELF_MAPPING_LIMIT: too many memory blocks')
    for block in blocks:
        if block.isOverlay():
            continue
        for source in block.getSourceInfos():
            if len(sources) >= 4096:
                raise ValueError('ELF_MAPPING_LIMIT: too many source ranges')
            original = source.getFileBytes()
            offset = int(source.getFileBytesOffset())
            if original.isPresent() and original.get() == file and offset >= 0 and not source.getByteMappingScheme().isPresent():
                sources.append(dict(start=uint('0x' + str(source.getMinAddress())), size=int(source.getLength()), offset=offset))
    return loads, sources
