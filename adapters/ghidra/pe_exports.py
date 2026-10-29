"""Bounded PE export directory reader; never substitutes analysis entrypoints."""
import struct


def pe_exports(read, imagebase):
    """read(rva, size) returns exact mapped bytes from the current database."""
    budget = [0]

    def take(rva, size):
        if size == 0:
            return b''
        if rva < 0 or size < 0 or rva + size > 0x100000000:
            raise ValueError('Invalid PE export RVA range')
        budget[0] += size
        if budget[0] > 4 * 1024 * 1024:
            raise ValueError('PE export read budget exceeded')
        value = bytes(read(rva, size))
        if len(value) != size:
            raise ValueError('Incomplete PE export bytes')
        return value

    def u32(rva):
        return struct.unpack('<I', take(rva, 4))[0]

    def text(rva, ceiling=256):
        data = bytearray()
        for i in range(ceiling):
            value = take(rva + i, 1)[0]
            if not value:
                if not data or any(c < 32 or c > 126 for c in data):
                    raise ValueError('Invalid/non-ASCII PE export text')
                return data.decode('ascii')
            data.append(value)
        raise ValueError('Unterminated PE export text within 256-byte limit')

    if take(0, 2) != b'MZ':
        return {'supported': False, 'source': 'pe-export-directory', 'reason': 'Not a PE image', 'rows': []}
    nt = u32(0x3c)
    if nt > 1024 * 1024 or take(nt, 4) != b'PE\0\0':
        raise ValueError('Invalid PE header')
    optional_size = struct.unpack('<H', take(nt + 20, 2))[0]
    opt = nt + 24
    magic = struct.unpack('<H', take(opt, 2))[0]
    directory = {0x10b: 96, 0x20b: 112}.get(magic)
    if directory is None or optional_size < directory:
        raise ValueError('Unsupported or truncated PE optional header')
    if u32(opt + directory - 4) < 1:
        return {'supported': True, 'source': 'pe-export-directory', 'rows': [], 'partial': False}
    if optional_size < directory + 8:
        raise ValueError('Truncated PE export directory header')
    rva, size = struct.unpack('<II', take(opt + directory, 8))
    if not rva and not size:
        return {'supported': True, 'source': 'pe-export-directory', 'rows': [], 'partial': False}
    if not rva or size < 40 or rva + size > 0x100000000:
        raise ValueError('Invalid PE export directory size')
    values = struct.unpack('<10I', take(rva, 40))
    base, count, names, addresses, strings, ordinals = values[4:10]
    if count > 8192 or names > 8192 or base + count > 0x100000000:
        raise ValueError('PE export table exceeds 8192-entry budget')
    funcs = struct.unpack('<' + 'I' * count, take(addresses, 4 * count))
    name_rvas = struct.unpack('<' + 'I' * names, take(strings, 4 * names))
    indices = struct.unpack('<' + 'H' * names, take(ordinals, 2 * names))
    aliases, diagnostics = {}, []
    for name_rva, index in zip(name_rvas, indices):
        if index >= count:
            diagnostics.append({'kind': 'invalid-name-ordinal', 'index': index})
            continue
        try:
            name = text(name_rva)
        except ValueError as error:
            name = None
            diagnostics.append({'kind': 'invalid-export-name', 'ordinal': base + index, 'reason': str(error)})
        aliases.setdefault(index, []).append(name)
    rows = []
    for i, target in enumerate(funcs):
        if not target:
            continue  # An unused EAT slot is not an exported address.
        for name in aliases.get(i, [None]):
            row = {'ordinal': base + i, 'name': name, 'rva': hex(target),
                   'entryKind': 'pe-export', 'source': 'pe-export-directory'}
            if rva <= target < rva + size:
                row['entryKind'] = 'pe-forwarder'
                try:
                    row['forwarder'] = text(target, min(256, rva + size - target))
                except ValueError as error:
                    row['forwarder'] = None
                    diagnostics.append({'kind': 'invalid-forwarder', 'ordinal': base + i, 'reason': str(error)})
            else:
                row['ea'] = hex(imagebase + target)
            rows.append(row)
    return {'supported': True, 'source': 'pe-export-directory', 'rows': rows,
            'declaredFunctions': count, 'declaredNames': names, 'partial': bool(diagnostics),
            'diagnostics': diagnostics,
            'limitations': ['Current database PE directory bytes; not a loader validation or runtime reachability proof.',
                            'Entrypoints and TLS callbacks are not substituted for exports.']}
