"""Generated firmware images for the tests: SquashFS 4, ext2/ext4, cpio, U-Boot images, FIT/FDT, Android boot and sparse images.

Written from the published layouts (kernel documentation and format specs), independently of the readers under test. 7-Zip is
used by the tests as a third opinion on the file systems. Nothing here is executable; file contents are inert bytes.
"""
import hashlib
import lzma
import struct
import zlib

# ---- common ------------------------------------------------------------------------------------------------------------


def pad(data, to, fill=b'\0'):
    return data + fill * (-len(data) % to)


def tree_from(files):
    """files: [{'path', 'data'|'symlink'|'device'|'fifo', 'mode'}] -> root node dict with explicit directories."""
    root = {'name': '', 'kind': 'dir', 'mode': 0o755, 'children': {}}
    for spec in files:
        parts = [p for p in spec['path'].split('/') if p]
        node = root
        for part in parts[:-1]:
            node = node['children'].setdefault(part, {'name': part, 'kind': 'dir', 'mode': 0o755, 'children': {}})
        leaf = parts[-1]
        if 'symlink' in spec:
            node['children'][leaf] = {'name': leaf, 'kind': 'symlink', 'mode': spec.get('mode', 0o777), 'target': spec['symlink']}
        elif 'device' in spec:
            node['children'][leaf] = {'name': leaf, 'kind': 'device', 'mode': spec.get('mode', 0o600), 'rdev': spec['device']}
        elif spec.get('dir'):
            node['children'].setdefault(leaf, {'name': leaf, 'kind': 'dir', 'mode': spec.get('mode', 0o755), 'children': {}})
        else:
            node['children'][leaf] = {'name': leaf, 'kind': 'file', 'mode': spec.get('mode', 0o644), 'data': spec['data']}
    return root


def walk(node, path=''):
    yield path, node
    if node['kind'] == 'dir':
        for name in sorted(node['children']):
            yield from walk(node['children'][name], f'{path}/{name}' if path else name)


# ---- SquashFS 4.0 ------------------------------------------------------------------------------------------------------

def build_squashfs(files, *, compression='zlib', block_size=4096, compress_metadata=True, big_endian=False, mkfs_time=1700000000):
    e = '>' if big_endian else '<'
    comp_id = {'zlib': 1, 'lzma': 2, 'xz': 4, 'none': 1}[compression]

    def squeeze(raw):
        if compression == 'none':
            return None
        out = {'zlib': lambda: zlib.compress(raw, 9), 'xz': lambda: lzma.compress(raw, format=lzma.FORMAT_XZ), 'lzma': lambda: lzma.compress(raw, format=lzma.FORMAT_ALONE)}[compression]()
        return out if len(out) < len(raw) else None

    root = tree_from(files)
    nodes = list(walk(root))
    number = {path: i + 1 for i, (path, _) in enumerate(nodes)}
    parent_of = {path: path.rpartition('/')[0] for path, _ in nodes}
    body, fragments, fragment_buffer = bytearray(), [], bytearray()

    def flush_fragment():
        nonlocal fragment_buffer
        if not fragment_buffer:
            return
        packed = squeeze(bytes(fragment_buffer))
        raw = packed if packed is not None else bytes(fragment_buffer)
        fragments.append((96 + len(body), len(raw) | (0 if packed is not None else 1 << 24)))
        body.extend(raw)
        fragment_buffer = bytearray()

    placement = {}
    for path, node in nodes:
        if node['kind'] != 'file':
            continue
        data, sizes, start = node['data'], [], 96 + len(body)
        for i in range(len(data) // block_size):
            chunk = data[i * block_size:(i + 1) * block_size]
            if not any(chunk):
                sizes.append(0)
                continue
            packed = squeeze(chunk)
            raw = packed if packed is not None else chunk
            body.extend(raw)
            sizes.append(len(raw) | (0 if packed is not None else 1 << 24))
        tail = data[(len(data) // block_size) * block_size:]
        fragment, offset = 0xffffffff, 0
        if tail:
            if len(fragment_buffer) + len(tail) > block_size:
                flush_fragment()
            fragment, offset = len(fragments), len(fragment_buffer)
            fragment_buffer.extend(tail)
        placement[path] = (start, sizes, fragment, offset)
    flush_fragment()

    def chunked(stream):
        blocks, starts, position = [], [], 0
        for i in range(0, max(len(stream), 1), 8192):
            chunk = bytes(stream[i:i + 8192])
            packed = squeeze(chunk) if compress_metadata else None
            raw = packed if packed is not None else chunk
            blocks.append(struct.pack(e + 'H', len(raw) | (0 if packed is not None else 0x8000)) + raw)
            starts.append(position)
            position += 2 + len(raw)
        return b''.join(blocks), starts

    kind_code = {'dir': 1, 'file': 2, 'symlink': 3, 'device': 4}

    def inode_bytes(path, node, dir_ref):
        mode = node['mode']
        head = struct.pack(e + 'HHHHII', kind_code[node['kind']] if node['kind'] != 'device' else 5, mode, 0, 0, 1700000000, number[path])
        if node['kind'] == 'dir':
            block, offset, listing_size = dir_ref
            return head + struct.pack(e + 'IIHHI', block, 1 + len([1 for c in node['children'].values() if c['kind'] == 'dir']), listing_size + 3, offset, number[parent_of[path]] if path else len(nodes) + 1)
        if node['kind'] == 'file':
            start, sizes, fragment, offset = placement[path]
            return head + struct.pack(e + 'IIII', start, fragment, offset, len(node['data'])) + struct.pack(e + f'{len(sizes)}I', *sizes)
        if node['kind'] == 'symlink':
            target = node['target'].encode()
            return head + struct.pack(e + 'II', 1, len(target)) + target
        return head + struct.pack(e + 'II', 1, (node['rdev'][1] << 8) | node['rdev'][2])

    inode_blocks, inode_starts = b'', [0] * 64
    dir_blocks, dir_starts = b'', [0] * 64
    for _ in range(16):                                   # block offsets depend on compressed sizes; iterate to a fixed point
        # 1) directory listings need the inode references, which need the inode stream layout (sizes are fixed per node)
        inode_pos, cursor = {}, 0
        order = [p for p, _ in nodes]
        sizes_by_path = {}
        for path, node in nodes:
            sizes_by_path[path] = len(inode_bytes(path, node, (0, 0, 0)))
        for path in order:
            inode_pos[path] = cursor
            cursor += sizes_by_path[path]
        dir_stream, dir_ref = bytearray(), {}
        for path, node in nodes:
            if node['kind'] != 'dir':
                continue
            listing = bytearray()
            children = sorted(node['children'].items())
            i = 0
            while i < len(children):
                first_path = f'{path}/{children[i][0]}' if path else children[i][0]
                block = inode_starts[inode_pos[first_path] // 8192]
                run = []
                while i < len(children) and len(run) < 256:
                    child_path = f'{path}/{children[i][0]}' if path else children[i][0]
                    if inode_starts[inode_pos[child_path] // 8192] != block:
                        break
                    run.append((children[i][0], child_path, children[i][1]))
                    i += 1
                listing += struct.pack(e + 'III', len(run) - 1, block, number[run[0][1]])
                for name, child_path, child in run:
                    code = {'dir': 1, 'file': 2, 'symlink': 3, 'device': 5}[child['kind']]
                    listing += struct.pack(e + 'HhHH', inode_pos[child_path] % 8192, number[child_path] - number[run[0][1]], code, len(name) - 1) + name.encode()
            position = len(dir_stream)
            dir_ref[path] = (dir_starts[position // 8192], position % 8192, len(listing))
            dir_stream += listing
        inode_stream = bytearray()
        for path, node in nodes:
            data = inode_bytes(path, node, dir_ref.get(path, (0, 0, 0)))
            assert len(data) == sizes_by_path[path]
            inode_stream += data
        new_inode_blocks, new_inode_starts = chunked(inode_stream)
        new_dir_blocks, new_dir_starts = chunked(dir_stream)
        new_inode_starts += [0] * (64 - len(new_inode_starts))
        new_dir_starts += [0] * (64 - len(new_dir_starts))
        if new_inode_starts == inode_starts and new_dir_starts == dir_starts:
            inode_blocks, dir_blocks = new_inode_blocks, new_dir_blocks
            break
        inode_starts, dir_starts = new_inode_starts, new_dir_starts
    else:
        raise RuntimeError('metadata layout did not converge')

    inode_table = 96 + len(body)
    out = bytearray(body)
    out += inode_blocks
    directory_table = 96 + len(out)
    out += dir_blocks
    # fragment table: metadata blocks of 16-byte entries, then the pointer array
    fragment_table = 0xffffffffffffffff
    if fragments:
        entries = b''.join(struct.pack(e + 'QII', start, size, 0) for start, size in fragments)
        pointers = []
        for i in range(0, len(entries), 8192):
            chunk = entries[i:i + 8192]
            packed = squeeze(chunk) if compress_metadata else None
            raw = packed if packed is not None else chunk
            pointers.append(96 + len(out))
            out += struct.pack(e + 'H', len(raw) | (0 if packed is not None else 0x8000)) + raw
        fragment_table = 96 + len(out)
        out += struct.pack(e + f'{len(pointers)}Q', *pointers)
    id_block = struct.pack(e + 'H', 4 | 0x8000) + struct.pack(e + 'I', 0)
    id_pointer = 96 + len(out)
    out += id_block
    id_table = 96 + len(out)
    out += struct.pack(e + 'Q', id_pointer)
    used = 96 + len(out)
    root_ref = (inode_starts[inode_pos[''] // 8192] << 16) | (inode_pos[''] % 8192)
    flags = 0x0200 | 0x0010 if True else 0              # NO_XATTRS | DUPLICATES_CHECK-ish flags; informational only
    sb = struct.pack(e + '4sIIIIHHHHHHQQQQQQQQ', b'sqsh' if big_endian else b'hsqs', len(nodes), mkfs_time, block_size, len(fragments), comp_id, block_size.bit_length() - 1, flags, 1, 4, 0,
                     root_ref, used, id_table, 0xffffffffffffffff, inode_table, directory_table, fragment_table, 0xffffffffffffffff)
    image = sb + bytes(out)
    return pad(image, 4096)


def ext_directory(entries, block_size):
    """Linear directory blocks: each record is padded to 4 bytes and the last record of a block runs to the block end."""
    blocks, current, last = [], bytearray(), None
    for ino, name, ftype in entries:
        encoded = name.encode()
        record = (8 + len(encoded) + 3) & ~3
        if len(current) + record > block_size:
            struct.pack_into('<H', current, last + 4, struct.unpack_from('<H', current, last + 4)[0] + block_size - len(current))
            current.extend(bytes(block_size - len(current)))
            blocks.append(bytes(current))
            current, last = bytearray(), None
        last = len(current)
        current += struct.pack('<IHBB', ino, record, len(encoded), ftype) + encoded.ljust(record - 8, b'\0')
    struct.pack_into('<H', current, last + 4, struct.unpack_from('<H', current, last + 4)[0] + block_size - len(current))
    current.extend(bytes(block_size - len(current)))
    blocks.append(bytes(current))
    return b''.join(blocks)


# ---- ext2 / ext4 -------------------------------------------------------------------------------------------------------

def build_ext(files, *, extents=False, block_size=1024, total_blocks=2048, volume='IG5TEST'):
    """A single-group ext2 (or extent-mapped ext4) image holding ``files``. Files may use direct, single- and double-indirect blocks."""
    root = tree_from(files)
    nodes = list(walk(root))
    inodes_count = max(32, ((len(nodes) + 12) // 8 + 1) * 8)
    inode_size = 128 if not extents else 256
    inode_table_blocks = (inodes_count * inode_size + block_size - 1) // block_size
    first_data_block = 1 if block_size == 1024 else 0
    gd_block, bb_block, ib_block, it_block = first_data_block + 1, first_data_block + 2, first_data_block + 3, first_data_block + 4
    next_block = it_block + inode_table_blocks
    image = bytearray(total_blocks * block_size)
    used_blocks = set(range(first_data_block, next_block))
    per = block_size // 4

    def allocate(count=1):
        nonlocal next_block
        start = next_block
        next_block += count
        if next_block > total_blocks:
            raise RuntimeError('test image too small')
        used_blocks.update(range(start, start + count))
        return start

    number = {path: (2 if path == '' else i + 2 + (1 if i + 2 >= 2 else 0)) for i, (path, _) in enumerate(nodes)}
    # simple numbering: root = 2, others sequentially from 11 (below 11 is reserved)
    number = {'': 2}
    for i, (path, _) in enumerate(p for p in nodes if p[0] != ''):
        number[path] = 11 + i
    inode_rows = {}

    def put_block(index, data):
        image[index * block_size:index * block_size + len(data)] = data

    def block_map(blocks):
        direct = blocks[:12]
        rest = blocks[12:]
        pointers = list(direct) + [0] * (12 - len(direct))
        if rest:
            single = rest[:per]
            rest = rest[per:]
            block = allocate()
            put_block(block, struct.pack(f'<{len(single)}I', *single))
            pointers.append(block)
        else:
            pointers.append(0)
        if rest:
            double = []
            while rest:
                chunk = rest[:per]
                rest = rest[per:]
                inner = allocate()
                put_block(inner, struct.pack(f'<{len(chunk)}I', *chunk))
                double.append(inner)
            block = allocate()
            put_block(block, struct.pack(f'<{len(double)}I', *double))
            pointers.append(block)
        else:
            pointers.append(0)
        pointers.append(0)
        return struct.pack('<15I', *pointers[:15])

    def data_blocks(data):
        count = (len(data) + block_size - 1) // block_size
        start = allocate(count) if count else 0
        for i in range(count):
            put_block(start + i, data[i * block_size:(i + 1) * block_size])
        return start, count

    for path, node in nodes:
        mode_type = {'dir': 0o040000, 'file': 0o100000, 'symlink': 0o120000, 'device': 0o020000}[node['kind']]
        flags, block_field, size = 0, bytes(60), 0
        if node['kind'] == 'file':
            size = len(node['data'])
            start, count = data_blocks(node['data'])
            if extents:
                flags = 0x80000
                header = struct.pack('<HHHHI', 0xF30A, 1 if count else 0, 4, 0, 0)
                block_field = (header + (struct.pack('<IHHI', 0, count, 0, start) if count else b'')).ljust(60, b'\0')
            else:
                block_field = block_map(list(range(start, start + count)))
        elif node['kind'] == 'symlink':
            target = node['target'].encode()
            size = len(target)
            if len(target) < 60:
                block_field = target.ljust(60, b'\0')
            else:
                start, count = data_blocks(target)
                block_field = block_map(list(range(start, start + count))) if not extents else (struct.pack('<HHHHI', 0xF30A, 1, 4, 0, 0) + struct.pack('<IHHI', 0, count, 0, start)).ljust(60, b'\0')
                flags = 0x80000 if extents else 0
        elif node['kind'] == 'device':
            block_field = struct.pack('<I', (node['rdev'][1] << 8) | node['rdev'][2]).ljust(60, b'\0')
        elif node['kind'] == 'dir':
            entries = [(number[path] if path else 2, '.', 2), (number[path.rpartition('/')[0]] if path.rpartition('/')[0] else 2, '..', 2)]
            for name, child in sorted(node['children'].items()):
                child_path = f'{path}/{name}' if path else name
                entries.append((number[child_path], name, {'dir': 2, 'file': 1, 'symlink': 7, 'device': 3}[child['kind']]))
            raw = ext_directory(entries, block_size)
            size = len(raw)
            start, count = data_blocks(raw)
            if extents:
                flags = 0x80000
                block_field = (struct.pack('<HHHHI', 0xF30A, 1, 4, 0, 0) + struct.pack('<IHHI', 0, count, 0, start)).ljust(60, b'\0')
            else:
                block_field = block_map(list(range(start, start + count)))
        row = bytearray(inode_size)
        struct.pack_into('<HHIIIIIHH', row, 0, mode_type | node['mode'], 0, size & 0xffffffff, 0, 1700000000, 1700000000, 0, 0, 1)
        struct.pack_into('<II', row, 28, 0, flags)
        row[40:100] = block_field
        if node['kind'] == 'file' or node['kind'] == 'dir':
            struct.pack_into('<I', row, 108, size >> 32)
        inode_rows[number[path]] = bytes(row)
    for ino, row in inode_rows.items():
        at = it_block * block_size + (ino - 1) * inode_size
        image[at:at + inode_size] = row
    # bitmaps
    bitmap = bytearray(block_size)
    for b in used_blocks:
        index = b - first_data_block
        bitmap[index // 8] |= 1 << (index % 8)
    put_block(bb_block, bytes(bitmap))
    inode_bitmap = bytearray(block_size)
    for ino in inode_rows:
        inode_bitmap[(ino - 1) // 8] |= 1 << ((ino - 1) % 8)
    for ino in range(1, 11):
        inode_bitmap[(ino - 1) // 8] |= 1 << ((ino - 1) % 8)
    put_block(ib_block, bytes(inode_bitmap))
    gd = struct.pack('<IIIHHHH', bb_block, ib_block, it_block, total_blocks - next_block, inodes_count - len(inode_rows) - 10, sum(1 for _, n in nodes if n['kind'] == 'dir'), 0)
    put_block(gd_block, gd)
    incompat = 0x2 | (0x40 if extents else 0)
    ro_compat = 0x1 | (0x40 if extents else 0)
    sb = bytearray(1024)
    log = block_size.bit_length() - 11
    struct.pack_into('<IIIIIIIIIII', sb, 0, inodes_count, total_blocks, 0, total_blocks - next_block, inodes_count - len(inode_rows) - 10, first_data_block, log, log, total_blocks, total_blocks, inodes_count)
    struct.pack_into('<HHHH', sb, 52, 0, 0xffff, 0xEF53, 1)
    struct.pack_into('<I', sb, 76, 1)                                    # revision 1: dynamic inode size
    struct.pack_into('<IHH', sb, 84, 11, inode_size, 0)
    struct.pack_into('<III', sb, 92, 0, incompat, ro_compat)
    sb[120:136] = volume.encode().ljust(16, b'\0')
    image[1024:2048] = sb
    return bytes(image)


# ---- cpio, U-Boot, FDT/FIT, Android --------------------------------------------------------------------------------------

def build_cpio(files):
    out = bytearray()
    for i, spec in enumerate(files):
        name = spec['path'].encode() + b'\0'
        if 'symlink' in spec:
            data, mode = spec['symlink'].encode(), 0o120777
        elif spec.get('dir'):
            data, mode = b'', 0o040755
        elif 'device' in spec:
            data, mode = b'', 0o020600
        else:
            data, mode = spec['data'], 0o100000 | spec.get('mode', 0o644)
        fields = [i + 1, mode, 0, 0, 1, 1700000000, len(data), 0, 0, 0, 0, len(name), 0]
        header = b'070701' + b''.join(b'%08X' % f for f in fields)
        out += pad(header + name, 4) + pad(data, 4)
    trailer_name = b'TRAILER!!!\0'
    out += pad(b'070701' + b''.join(b'%08X' % f for f in [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(trailer_name), 0]) + trailer_name, 4)
    return pad(bytes(out), 512)


def build_uimage(payload, *, name='IG5 test kernel', os_code=5, arch=2, kind=2, comp=0, load=0x80008000, entry=0x80008000, bad_header_crc=False, bad_data_crc=False):
    dcrc = zlib.crc32(payload) & 0xffffffff
    if bad_data_crc:
        dcrc ^= 1
    header = struct.pack('>IIIIIIIBBBB32s', 0x27051956, 0, 1700000000, len(payload), load, entry, dcrc, os_code, arch, kind, comp, name.encode()[:31])
    hcrc = zlib.crc32(header) & 0xffffffff
    if bad_header_crc:
        hcrc ^= 1
    return struct.pack('>I', 0x27051956) + struct.pack('>I', hcrc) + header[8:] + payload


def fdt_blob(root, *, boot_cpu=0):
    """root: nested {'props': {name: bytes|str|int}, 'nodes': {name: {...}}} -> flattened device tree bytes (version 17)."""
    strings, struct_block = bytearray(), bytearray()

    def string_offset(name):
        data = name.encode() + b'\0'
        at = bytes(strings).find(data)
        if at < 0:
            at = len(strings)
            strings.extend(data)
        return at

    def emit(name, node):
        struct_block.extend(struct.pack('>I', 1) + pad(name.encode() + b'\0', 4))
        for key, value in node.get('props', {}).items():
            raw = value if isinstance(value, bytes) else struct.pack('>I', value) if isinstance(value, int) else value.encode() + b'\0'
            struct_block.extend(struct.pack('>III', 3, len(raw), string_offset(key)) + pad(raw, 4))
        for child, content in node.get('nodes', {}).items():
            emit(child, content)
        struct_block.extend(struct.pack('>I', 2))
    emit('', root)
    struct_block.extend(struct.pack('>I', 9))
    reserve = bytes(16)
    off_reserve = 40
    off_struct = off_reserve + len(reserve)
    off_strings = off_struct + len(struct_block)
    total = off_strings + len(strings)
    header = struct.pack('>IIIIIIIIII', 0xd00dfeed, total, off_struct, off_strings, off_reserve, 17, 16, boot_cpu, len(strings), len(struct_block))
    return header + reserve + bytes(struct_block) + bytes(strings)


def build_fit(images, *, bad_hash=False):
    """images: {name: {'data': bytes, 'type': 'kernel', 'arch': 'arm', 'os': 'linux', 'compression': 'none', 'load': int}} -> FIT image."""
    nodes = {}
    for name, spec in images.items():
        digest = hashlib.sha256(spec['data']).digest()
        if bad_hash:
            digest = bytes([digest[0] ^ 1]) + digest[1:]
        nodes[name] = {'props': {'description': f'{name} image', 'data': spec['data'], 'type': spec.get('type', 'kernel'), 'arch': spec.get('arch', 'arm'), 'os': spec.get('os', 'linux'),
                                 'compression': spec.get('compression', 'none'), 'load': spec.get('load', 0x80008000), 'entry': spec.get('load', 0x80008000)},
                       'nodes': {'hash-1': {'props': {'algo': 'sha256', 'value': digest}}, 'hash-2': {'props': {'algo': 'crc32', 'value': struct.pack('>I', zlib.crc32(spec['data']) & 0xffffffff)}}}}
    root = {'props': {'description': 'IG5 FIT test', 'timestamp': 1700000000}, 'nodes': {'images': {'nodes': nodes}, 'configurations': {'props': {'default': 'conf-1'}, 'nodes': {'conf-1': {'props': {'kernel': next(iter(images))}}}}}}
    return fdt_blob(root)


def build_android_boot(kernel, ramdisk, *, second=b'', page_size=2048, version=0, cmdline='console=ttyS0 root=/dev/ram0', name='ig5', os_version=(11, 0, 0, 2023, 5)):
    a, b, c, year, month = os_version
    packed_os = (((a << 14) | (b << 7) | c) << 11) | (((year - 2000) << 4) | month)
    if version >= 3:
        header = struct.pack('<8sIIII16xI1536s', b'ANDROID!', len(kernel), len(ramdisk), packed_os, 4096, version, cmdline.encode()[:1535])
        header = pad(header, 4096)
        return header + pad(kernel, 4096) + pad(ramdisk, 4096)
    header = struct.pack('<8s10I16s512s32s1024s', b'ANDROID!', len(kernel), 0x10008000, len(ramdisk), 0x11000000, len(second), 0x10f00000, 0x10000100, page_size, version, packed_os,
                         name.encode(), cmdline.encode()[:511], bytes(32), b'')
    return pad(header, page_size) + pad(kernel, page_size) + pad(ramdisk, page_size) + (pad(second, page_size) if second else b'')


def build_sparse(chunks, *, block_size=4096):
    """chunks: [('raw', bytes) | ('fill', int, blocks) | ('skip', blocks)] -> Android sparse image."""
    body, blocks = bytearray(), 0
    for chunk in chunks:
        if chunk[0] == 'raw':
            data = pad(chunk[1], block_size)
            count = len(data) // block_size
            body += struct.pack('<HHII', 0xCAC1, 0, count, 12 + len(data)) + data
        elif chunk[0] == 'fill':
            count = chunk[2]
            body += struct.pack('<HHII', 0xCAC2, 0, count, 16) + struct.pack('<I', chunk[1])
        else:
            count = chunk[1]
            body += struct.pack('<HHII', 0xCAC3, 0, count, 12)
        blocks += count
    return struct.pack('<IHHHHIIII', 0xED26FF3A, 1, 0, 28, 12, block_size, blocks, len(chunks), 0) + bytes(body)
