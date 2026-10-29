"""Boot-image style containers: U-Boot legacy images, flattened device trees / FIT images, Android boot and sparse images, TRX.

Each ``probe_*`` validates the header (sizes against the available bytes, checksums where the format defines them) and returns a
dict describing the component, or ``None``. ``*_children`` return the payloads inside as (name, offset, size, meta) tuples with
offsets relative to the component start, so the scanner can recurse into them.
"""
import hashlib
import struct
import zlib

import firmware_rules as rules


def _text(raw):
    return raw.split(b'\0', 1)[0].decode('utf-8', 'replace')


# ---- U-Boot legacy image ----------------------------------------------------------------------------------------------

def probe_uimage(src, offset):
    head = src.read(offset, 64)
    if len(head) < 64 or head[:4] != b'\x27\x05\x19\x56':
        return None
    magic, hcrc, timestamp, size, load, entry, dcrc, os_code, arch, kind, comp, name = struct.unpack('>IIIIIIIBBBB32s', head)
    zeroed = head[:4] + b'\0\0\0\0' + head[8:]
    header_ok = (zlib.crc32(zeroed) & 0xffffffff) == hcrc
    available = src.size - offset - 64
    if kind not in rules.UIMAGE_TYPES or comp not in rules.UIMAGE_COMPRESSION or size > (1 << 31):
        return None
    if not header_ok and size > available:
        return None
    data_ok = None
    if size <= available and size <= 256 * 1024 * 1024:
        crc = 0
        for at in range(0, size, 1 << 20):
            crc = zlib.crc32(src.read(offset + 64 + at, min(1 << 20, size - at)), crc)
        data_ok = (crc & 0xffffffff) == dcrc
    return {'size': 64 + min(size, max(available, 0)) if size > available else 64 + size, 'truncated': size > available, 'name': _text(name), 'imageType': rules.UIMAGE_TYPES[kind], 'compression': rules.UIMAGE_COMPRESSION[comp],
            'arch': rules.UIMAGE_ARCH.get(arch, f'arch {arch}'), 'os': {5: 'Linux', 17: 'U-Boot', 2: 'OpenBSD', 9: 'VxWorks'}.get(os_code, f'os {os_code}'), 'loadAddress': f'{load:#x}', 'entryPoint': f'{entry:#x}',
            'timestamp': timestamp, 'payloadSize': size, 'checks': {'headerCrc': header_ok, 'dataCrc': data_ok}, 'valid': header_ok and data_ok is not False}


def uimage_children(src, offset, info):
    base, size = offset + 64, info['payloadSize']
    if info['imageType'] == 'multi-file' and info['compression'] == 'none':
        sizes, at = [], 0
        while at < 256:
            raw = src.read(base + at, 4)
            if len(raw) < 4:
                return []
            (value,) = struct.unpack('>I', raw)
            at += 4
            if value == 0:
                break
            sizes.append(value)
        position, out = at, []
        for index, length in enumerate(sizes):
            out.append((f'multi-file image {index}', 64 + position, length, {}))
            position += (length + 3) & ~3
        return out
    return [(info['imageType'] + ' payload', 64, min(size, src.size - offset - 64), {'compression': info['compression']})]


# ---- flattened device tree / FIT ---------------------------------------------------------------------------------------

def probe_fdt(src, offset):
    head = src.read(offset, 40)
    if len(head) < 40:
        return None
    magic, total, off_struct, off_strings, off_rsv, version, last_comp, boot_cpu, size_strings, size_struct = struct.unpack('>10I', head)
    if magic != 0xd00dfeed or total < 40 or total > 1 << 28 or version < 16 or last_comp > version or off_struct + size_struct > total or off_strings + size_strings > total or off_struct % 4:
        return None
    return {'size': min(total, src.size - offset), 'declaredSize': total, 'version': version, 'truncated': total > src.size - offset,
            'offsets': {'struct': off_struct, 'strings': off_strings, 'structSize': size_struct, 'stringsSize': size_strings}}


def parse_fdt(src, offset, info, max_nodes=5000):
    """Parse the structure block into nested dicts: {'props': {name: (data_offset, bytes)}, 'nodes': {name: {...}}}."""
    o = info['offsets']
    blob = src.read(offset + o['struct'], o['structSize'])
    strings = src.read(offset + o['strings'], o['stringsSize'])
    root = {'props': {}, 'nodes': {}}
    stack, i, nodes = [], 0, 0
    notes = []
    while i + 4 <= len(blob):
        (token,) = struct.unpack_from('>I', blob, i)
        i += 4
        if token == 1:
            end = blob.find(b'\0', i)
            if end < 0:
                notes.append('unterminated node name')
                break
            name = blob[i:end].decode('utf-8', 'replace')
            i = (end + 1 + 3) & ~3
            nodes += 1
            if nodes > max_nodes or len(stack) > 32:
                notes.append('device tree too large or too deep; parse stopped')
                break
            if not stack:
                node = root
            else:
                node = {'props': {}, 'nodes': {}}
                stack[-1]['nodes'][name] = node
            stack.append(node)
        elif token == 2:
            if stack:
                stack.pop()
        elif token == 3:
            if i + 8 > len(blob) or not stack:
                break
            length, name_off = struct.unpack_from('>II', blob, i)
            i += 8
            data = blob[i:i + length]
            name = strings[name_off:strings.find(b'\0', name_off)].decode('utf-8', 'replace') if name_off < len(strings) else '?'
            stack[-1]['props'][name] = (offset + o['struct'] + i, data)
            i = (i + length + 3) & ~3
        elif token == 4:
            continue
        elif token == 9:
            break
        else:
            notes.append(f'unknown token {token:#x}')
            break
    return root, notes


def _str(prop):
    return _text(prop[1]) if prop else None


def _cells(prop):
    if not prop or len(prop[1]) not in (4, 8):
        return None
    return int.from_bytes(prop[1], 'big')


def fit_images(src, offset, info):
    """If the tree is a FIT image, return its image nodes with verified hashes; else None."""
    tree, notes = parse_fdt(src, offset, info)
    images = tree['nodes'].get('images')
    if images is None:
        return None, notes, tree
    out = []
    for name, node in images['nodes'].items():
        props = node['props']
        data_prop = props.get('data')
        external = None
        if data_prop is None and 'data-size' in props and ('data-position' in props or 'data-offset' in props):
            where = _cells(props['data-position']) if 'data-position' in props else ((info['size'] + 3) & ~3) + _cells(props['data-offset'])
            external = (where, _cells(props['data-size']))
        row = {'name': name, 'description': _str(props.get('description')), 'type': _str(props.get('type')), 'arch': _str(props.get('arch')), 'os': _str(props.get('os')),
               'compression': _str(props.get('compression')) or 'none', 'load': _cells(props.get('load')), 'entry': _cells(props.get('entry')), 'hashes': []}
        if data_prop is not None:
            row['dataOffset'], row['dataSize'] = data_prop[0] - offset, len(data_prop[1])
            payload = data_prop[1]
        elif external and None not in external:
            position, length = external
            row['dataOffset'], row['dataSize'], row['external'] = position, length, True
            payload = src.read(offset + position, length) if length <= 256 * 1024 * 1024 else b''
        else:
            payload = b''
        for hash_name, hash_node in node['nodes'].items():
            algo, value = _str(hash_node['props'].get('algo')), hash_node['props'].get('value')
            if not algo or not value or not payload:
                continue
            if algo in ('sha256', 'sha1', 'md5', 'sha384', 'sha512'):
                good = hashlib.new(algo, payload).digest() == value[1]
            elif algo == 'crc32':
                good = (zlib.crc32(payload) & 0xffffffff).to_bytes(4, 'big') == value[1]
            else:
                good = None
            row['hashes'].append({'node': hash_name, 'algo': algo, 'verified': good})
        out.append(row)
    configs = tree['nodes'].get('configurations')
    return {'images': out, 'default': _str(configs['props'].get('default')) if configs else None, 'description': _str(tree['props'].get('description')),
            'configurations': sorted(configs['nodes']) if configs else []}, notes, tree


# ---- Android -----------------------------------------------------------------------------------------------------------

def probe_android_boot(src, offset):
    head = src.read(offset, 1664 + 128)
    if len(head) < 48 or head[:8] != b'ANDROID!':
        return None
    version = struct.unpack_from('<I', head, 40)[0]
    if version >= 3 and version <= 4:
        kernel, ramdisk, os_version, header_size, _, _, _, _, hv = struct.unpack_from('<IIIIIIIII', head, 8)[:9]
        header_version = struct.unpack_from('<I', head, 40)[0]
        page = 4096
        cmdline = _text(head[44:44 + 1536])
        second = 0
    else:
        if len(head) < 608:
            return None
        kernel, kaddr, ramdisk, raddr, second, saddr, tags, page, header_version, os_version = struct.unpack_from('<10I', head, 8)
        cmdline = _text(head[64:64 + 512] if len(head) >= 576 else b'')
        if header_version > 4 or page not in (2048, 4096, 8192, 16384, 32768, 65536) or header_version >= 3:
            return None
    align = lambda n: (n + page - 1) // page * page
    layout = {'header': page}
    position = page
    for key, size in (('kernel', kernel), ('ramdisk', ramdisk), ('second', second)):
        layout[key] = (position, size)
        position += align(size)
    total = position
    if kernel == 0 or kernel > 1 << 29 or ramdisk > 1 << 29 or total > src.size - offset + page:
        return None
    a, b, c = os_version >> 25, (os_version >> 18) & 0x7f, (os_version >> 11) & 0x7f
    y, m = ((os_version >> 4) & 0x7f) + 2000, os_version & 0xf
    return {'size': min(total, src.size - offset), 'pageSize': page, 'headerVersion': header_version, 'kernelSize': kernel, 'ramdiskSize': ramdisk, 'secondSize': second, 'cmdline': cmdline,
            'osVersion': f'{a}.{b}.{c}' if os_version else None, 'securityPatch': f'{y}-{m:02d}' if os_version and 1 <= m <= 12 else None, 'layout': layout, 'truncated': total > src.size - offset}


def android_boot_children(info):
    out = []
    for key, label in (('kernel', 'kernel'), ('ramdisk', 'ramdisk'), ('second', 'second-stage')):
        start, size = info['layout'][key]
        if size:
            out.append((label, start, size, {}))
    return out


def probe_android_sparse(src, offset):
    head = src.read(offset, 28)
    if len(head) < 28:
        return None
    magic, major, minor, file_hdr, chunk_hdr, block_size, blocks, chunks, checksum = struct.unpack('<IHHHHIIII', head)
    if magic != 0xED26FF3A or major != 1 or file_hdr < 28 or chunk_hdr < 12 or block_size % 4 or not 512 <= block_size <= 1 << 20 or chunks == 0 or chunks > 1 << 22:
        return None
    return {'blockSize': block_size, 'blocks': blocks, 'chunks': chunks, 'rawSize': blocks * block_size, 'fileHeader': file_hdr, 'chunkHeader': chunk_hdr}


def sparse_size(src, offset, info):
    """Walk the chunk headers to find where the image ends; also validates the chunk table."""
    position = offset + info['fileHeader']
    for _ in range(info['chunks']):
        head = src.read(position, 12)
        if len(head) < 12:
            return None
        kind, _, count, total = struct.unpack('<HHII', head)
        if kind not in (0xCAC1, 0xCAC2, 0xCAC3, 0xCAC4) or total < 12:
            return None
        position += total
    return position - offset


def unsparse(src, offset, info, write, limit):
    """Reconstruct the raw image through ``write(bytes)``; holes become zeros. Refuses images larger than ``limit``."""
    if info['rawSize'] > limit:
        return False
    position = offset + info['fileHeader']
    for _ in range(info['chunks']):
        kind, _, count, total = struct.unpack('<HHII', src.read(position, 12))
        data = position + info['chunkHeader']
        size = count * info['blockSize']
        if kind == 0xCAC1:
            for at in range(0, size, 1 << 20):
                write(src.read(data + at, min(1 << 20, size - at)))
        elif kind == 0xCAC2:
            pattern = src.read(data, 4)
            for at in range(0, size, 1 << 20):
                write((pattern * ((min(1 << 20, size - at) + 3) // 4))[:min(1 << 20, size - at)])
        elif kind == 0xCAC3:
            for at in range(0, size, 1 << 20):
                write(bytes(min(1 << 20, size - at)))
        position += total
    return True


# ---- TRX ---------------------------------------------------------------------------------------------------------------

def probe_trx(src, offset):
    head = src.read(offset, 28)
    if len(head) < 28 or head[:4] != b'HDR0':
        return None
    magic, length, crc, flags_version, o0, o1, o2 = struct.unpack('<4sIIIIII', head)
    version = flags_version >> 16
    offsets = [x for x in (o0, o1, o2) if x]
    if length < 28 or length > src.size - offset + 1 or version not in (1, 2) or offsets != sorted(offsets) or any(x < 28 or x >= length for x in offsets):
        return None
    return {'size': min(length, src.size - offset), 'version': version, 'partitions': offsets, 'crc32': f'{crc:#010x}'}


def trx_children(info):
    points = [28] + info['partitions'] if info['partitions'] and info['partitions'][0] != 28 else info['partitions'] or [28]
    ends = points[1:] + [info['size']]
    return [(f'TRX partition {i}', start, end - start, {}) for i, (start, end) in enumerate(zip(points, ends)) if end > start]
