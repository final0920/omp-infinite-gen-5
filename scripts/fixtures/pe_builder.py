"""Generated PE / ELF images for the packing tests: headers and sections laid out from the published formats.

Nothing here is executable code; section contents are inert bytes chosen for their statistics (low-entropy "code",
random "compressed" data, zero pages). ``build_pe`` places an import table and a TLS callback table inside a chosen
section, the way real packers hide them, so the analyzer has to find them through the data directories.
"""
import os
import random
import struct

SCN_CODE, SCN_INIT, SCN_UNINIT, SCN_EXEC, SCN_READ, SCN_WRITE = 0x20, 0x40, 0x80, 0x20000000, 0x40000000, 0x80000000
TEXT = SCN_CODE | SCN_EXEC | SCN_READ
RDATA = SCN_INIT | SCN_READ
DATA = SCN_INIT | SCN_READ | SCN_WRITE
RWX = SCN_CODE | SCN_EXEC | SCN_READ | SCN_WRITE | SCN_INIT


def pseudo_code(size, seed=1):
    """Bytes with the statistics of compiled code: skewed towards a few opcodes, entropy about 5-6 bits."""
    rng = random.Random(seed)
    common = bytes([0x48, 0x89, 0x8b, 0xe8, 0xff, 0x00, 0x24, 0x0f, 0x83, 0xc0, 0x45, 0x31])
    return bytes(rng.choice(common) if rng.random() < 0.8 else rng.randrange(256) for _ in range(size))


def random_bytes(size, seed=2):
    return random.Random(seed).randbytes(size)


def align(value, to):
    return (value + to - 1) // to * to


def _imports_blob(imports, rva, plus):
    """Import directory + thunks + names laid out contiguously from ``rva``; returns (bytes, directory_size)."""
    width = 8 if plus else 4
    descriptors = (len(imports) + 1) * 20
    cursor = descriptors
    plan = []
    for dll, names in imports:
        ilt, iat = cursor, cursor + (len(names) + 1) * width
        cursor = iat + (len(names) + 1) * width
        name_rvas = []
        strings = b''
        for api in names:
            name_rvas.append(cursor + len(strings))
            entry = struct.pack('<H', 0) + api.encode() + b'\0'
            strings += entry + (b'\0' if len(entry) % 2 else b'')
        cursor += len(strings)
        dll_at = cursor
        cursor += len(dll) + 1
        plan.append((dll, names, ilt, iat, name_rvas, strings, dll_at))
    blob = bytearray(cursor)
    for index, (dll, names, ilt, iat, name_rvas, strings, dll_at) in enumerate(plan):
        struct.pack_into('<IIIII', blob, index * 20, rva + ilt, 0, 0, rva + dll_at, rva + iat)
        for slot, name_rva in enumerate(name_rvas):
            for table in (ilt, iat):
                blob[table + slot * width: table + (slot + 1) * width] = (rva + name_rva).to_bytes(width, 'little')
        start = name_rvas[0] if name_rvas else 0
        blob[start: start + len(strings)] = strings if name_rvas else b''
        blob[dll_at: dll_at + len(dll) + 1] = dll.encode() + b'\0'
    return bytes(blob), descriptors


def build_pe(sections, *, entry=0, entry_offset=0, plus=True, imports=None, imports_in=0, tls_callbacks=0, tls_in=0, subsystem=3, dll=False, managed=False, overlay=b'',
             file_align=0x200, section_align=0x1000, entry_rva=None, image_size_delta=0):
    """sections: [{'name', 'data', 'vsize', 'chars', 'raw': override raw size}] -> bytes of a PE32+ (or PE32) file."""
    optional_size = 240 if plus else 224
    header_size = align(0x80 + 24 + optional_size + 40 * len(sections), file_align)
    image_base = 0x140000000 if plus else 0x400000
    rows, va = [], align(header_size, section_align)
    directories = [(0, 0)] * 16
    width = 8 if plus else 4
    for index, spec in enumerate(sections):
        data = bytes(spec.get('data', b''))
        row = {**spec, 'data': data, 'va': spec.get('va', va)}
        rows.append(row)
        appended = False

        def reserve(blob):
            offset = align(len(row['data']), 8)
            row['data'] = row['data'].ljust(offset, b'\0') + blob
            return row['va'] + offset
        if imports and index == imports_in:
            blob, size = _imports_blob(imports, row['va'] + align(len(row['data']), 8), plus)
            directories[1] = (reserve(blob), size)
            appended = True
        if tls_callbacks and index == tls_in:
            directory_rva = row['va'] + align(len(row['data']), 8)
            directory = bytearray(40 if plus else 24)
            directory[(24 if plus else 12): (24 if plus else 12) + width] = (image_base + directory_rva + len(directory)).to_bytes(width, 'little')
            table = b''.join((image_base + rows[0]['va'] + i * 16).to_bytes(width, 'little') for i in range(tls_callbacks)) + bytes(width)
            directories[9] = (reserve(bytes(directory) + table), len(directory))
            appended = True
        row['vsize'] = max(spec.get('vsize', 0), len(row['data'])) if appended else spec.get('vsize', len(data))
        va += align(max(row['vsize'], 1), section_align)
    if managed:
        directories[14] = (rows[0]['va'], 0x48)
    out = bytearray(header_size)
    out[0:2] = b'MZ'
    struct.pack_into('<I', out, 0x3c, 0x80)
    out[0x80:0x84] = b'PE\0\0'
    characteristics = 0x0022 | (0x2000 if dll else 0) | (0 if plus else 0x0100)
    struct.pack_into('<HHIIIHH', out, 0x84, 0x8664 if plus else 0x14c, len(rows), 0, 0, 0, optional_size, characteristics)
    opt = 0x80 + 24
    first_exec = rows[entry]
    ep = entry_rva if entry_rva is not None else first_exec['va'] + entry_offset
    struct.pack_into('<HBBIII', out, opt, 0x20b if plus else 0x10b, 14, 0, 0, 0, 0)
    struct.pack_into('<I', out, opt + 16, ep)
    if plus:
        struct.pack_into('<Q', out, opt + 24, image_base)
    else:
        struct.pack_into('<I', out, opt + 28, image_base)
    struct.pack_into('<IIHHHHHHIIIIHH', out, opt + 32, section_align, file_align, 6, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0)       # section/file alignment and version fields (values unused by the analyzer)
    struct.pack_into('<II', out, opt + 56, va + image_size_delta, header_size)
    struct.pack_into('<H', out, opt + 68, subsystem)
    struct.pack_into('<I', out, opt + (108 if plus else 92), 16)
    for i, (rva, size) in enumerate(directories):
        struct.pack_into('<II', out, opt + (112 if plus else 96) + i * 8, rva, size)
    table_at = opt + optional_size
    body = bytearray()
    for index, spec in enumerate(rows):
        data = spec['data']
        raw_size = spec['raw'] if 'raw' in spec else align(len(data), file_align) if data else 0
        pointer = header_size + len(body) if raw_size else 0
        name = spec['name'] if isinstance(spec['name'], bytes) else spec['name'].encode('latin1')
        struct.pack_into('<8sIIIIIIHHI', out, table_at + index * 40, name.ljust(8, b'\0')[:8], spec.get('vsize', len(data)), spec['va'], raw_size, pointer, 0, 0, 0, 0, spec['chars'])
        if raw_size:
            body += data.ljust(raw_size, b'\0')[:raw_size]
    return bytes(out) + bytes(body) + overlay


def build_elf(segments, *, entry_segment=0, entry_offset=0, sections=True, interp=False, dynamic=False, marker=b'', is64=True, e_type=2):
    """segments: [{'flags': 'rx', 'data': bytes, 'memsz': int}] -> a little-endian ELF with PT_LOAD per segment."""
    flags = {'r': 4, 'w': 2, 'x': 1}
    extra = ([(3, 4, b'/lib/ld.so\0')] if interp else []) + ([(2, 6, bytes(16))] if dynamic else [])
    count = len(segments) + len(extra)
    ehsize, phentsize = (64, 56) if is64 else (52, 32)
    cursor = align(ehsize + phentsize * count, 0x1000)
    placed, body = [], bytearray()
    for spec in segments:
        data = bytes(spec['data'])
        placed.append((cursor + len(body), data, spec))
        body += data.ljust(align(max(len(data), 1), 0x1000), b'\0')
    out = bytearray(ehsize + phentsize * count)
    base = 0x400000
    entry_va = base + placed[entry_segment][0] + entry_offset
    if is64:
        out[0:16] = b'\x7fELF\x02\x01\x01' + bytes(9)
        struct.pack_into('<HHIQQQIHHHHHH', out, 16, e_type, 0x3e, 1, entry_va, ehsize, 0, 0, ehsize, phentsize, count, 64, 0, 0)
    else:
        out[0:16] = b'\x7fELF\x01\x01\x01' + bytes(9)
        struct.pack_into('<HHIIIIIHHHHHH', out, 16, e_type, 0x3, 1, entry_va, ehsize, 0, 0, ehsize, phentsize, count, 40, 0, 0)
    for index, (offset, data, spec) in enumerate(placed):
        f = sum(flags[c] for c in spec['flags'])
        memsz = max(spec.get('memsz', len(data)), len(data))
        if is64:
            struct.pack_into('<IIQQQQQQ', out, ehsize + index * phentsize, 1, f, offset, base + offset, base + offset, len(data), memsz, 0x1000)
        else:
            struct.pack_into('<IIIIIIII', out, ehsize + index * phentsize, 1, offset, base + offset, base + offset, len(data), memsz, f, 0x1000)
    for index, (kind, f, data) in enumerate(extra):
        at = ehsize + (len(segments) + index) * phentsize
        if is64:
            struct.pack_into('<IIQQQQQQ', out, at, kind, f, 0, 0, 0, len(data), len(data), 8)
        else:
            struct.pack_into('<IIIIIIII', out, at, kind, 0, 0, 0, len(data), len(data), f, 8)
    file = bytes(out).ljust(cursor, b'\0') + bytes(body)
    if marker:
        at = ehsize + phentsize * count       # in the padding right after the program headers, where UPX keeps its header
        file = file[:at] + marker + file[at + len(marker):]
    if sections:
        # one non-null section header after the data so e_shnum/e_shoff are populated
        shoff = len(file)
        file += bytes(64 if is64 else 40) * 2
        patch = struct.pack('<Q', shoff) if is64 else struct.pack('<I', shoff)
        file = file[:40 if is64 else 32] + patch + file[(48 if is64 else 36):]
        shnum_at = 60 if is64 else 48
        file = file[:shnum_at] + struct.pack('<H', 2) + file[shnum_at + 2:]
    return file
