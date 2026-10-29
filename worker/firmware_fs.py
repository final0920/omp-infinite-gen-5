"""Read-only file system and archive readers: SquashFS 4, ext2/3/4, cpio (newc), tar, zip.

Each reader validates its own headers, lists entries lazily and reads file data on demand under a byte ceiling. Nothing
here writes to disk or follows a link: a symlink is reported with its target text, a device node as a device, and the
caller decides what to extract. Hostile structures (loops, huge counts, out-of-range offsets) end the walk with a
note rather than an exception whenever the part read so far is still meaningful.
"""
import io
import lzma
import struct
import tarfile
import zipfile
import zlib

import firmware_rules as rules
from firmware_io import FirmwareError, inflate


class Entry:
    """One name inside a file system or archive. ``read(limit)`` returns up to ``limit`` bytes of a regular file."""

    def __init__(self, path, kind, size=0, mode=0, target=None, reader=None, extra=None):
        self.path, self.kind, self.size, self.mode, self.target, self._reader, self.extra = path, kind, size, mode, target, reader, extra or {}

    def read(self, limit):
        if self._reader is None:
            raise FirmwareError('NO_DATA', f'{self.path} has no readable content')
        return self._reader(limit)

    def summary(self):
        row = {'path': self.path, 'kind': self.kind, 'size': self.size, 'mode': f'{self.mode & 0o7777:o}'}
        if self.target is not None:
            row['target'] = self.target
        row.update(self.extra)
        return row


class SourceFile(io.RawIOBase):
    """File-like view of a Source, for the standard-library archive readers."""

    def __init__(self, src):
        self.src, self.position = src, 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=io.SEEK_SET):
        self.position = offset if whence == io.SEEK_SET else self.position + offset if whence == io.SEEK_CUR else self.src.size + offset
        self.position = max(0, self.position)
        return self.position

    def readinto(self, buffer):
        data = self.src.read(self.position, len(buffer))
        buffer[:len(data)] = data
        self.position += len(data)
        return len(data)


MODE_KIND = {0o140000: 'socket', 0o120000: 'symlink', 0o100000: 'file', 0o060000: 'device', 0o040000: 'dir', 0o020000: 'device', 0o010000: 'fifo'}


# ---- SquashFS 4 --------------------------------------------------------------------------------------------------------

class SquashFS:
    """Superblock probe (``probe``) and reader (``SquashFS(src)``) for SquashFS 4.0 images, either byte order."""
    HEADER = 96

    @staticmethod
    def probe(src, offset=0, available=None):
        head = src.read(offset, SquashFS.HEADER)
        if len(head) < SquashFS.HEADER or head[:4] not in (b'hsqs', b'sqsh'):
            return None
        e = '<' if head[:4] == b'hsqs' else '>'
        (_, inodes, mkfs_time, block_size, fragments, compression, block_log, flags, ids, major, minor, root, used, id_table, xattr_table, inode_table, dir_table, frag_table, lookup_table) = \
            struct.unpack(e + '4sIIIIHHHHHHQQQQQQQQ', head)
        if (major, minor) != (4, 0) or block_size & (block_size - 1) or not 4096 <= block_size <= 1 << 20 or 1 << block_log != block_size or compression not in rules.SQUASHFS_COMPRESSORS:
            return None
        total = (src.size - offset) if available is None else available
        if used < SquashFS.HEADER or inodes == 0 or inode_table < SquashFS.HEADER or not inode_table < dir_table <= used or id_table >= used + 1 or ids == 0:
            return None
        return {'endian': 'little' if e == '<' else 'big', 'inodes': inodes, 'mkfsTime': mkfs_time, 'blockSize': block_size, 'fragments': fragments, 'compressor': rules.SQUASHFS_COMPRESSORS[compression],
                'compressorId': compression, 'flags': flags, 'bytesUsed': used, 'truncated': used > total, 'size': used, 'rootInode': root, 'tables': {'inode': inode_table, 'directory': dir_table, 'fragment': frag_table, 'id': id_table}}

    def __init__(self, src, offset=0, budget=None):
        info = self.probe(src, offset)
        if info is None:
            raise FirmwareError('BAD_SQUASHFS', 'not a SquashFS 4.0 superblock')
        self.src, self.base, self.info, self.notes, self.e = src, offset, info, [], '<' if info['endian'] == 'little' else '>'
        self.bs, self.comp = info['blockSize'], info['compressorId']
        if self.comp not in rules.SQUASHFS_SUPPORTED:
            raise FirmwareError('UNSUPPORTED_COMPRESSOR', f'SquashFS compressor {info["compressor"]} has no decoder here')
        t = info['tables']
        self.inodes = self._metadata(t['inode'], t['directory'])
        end_of_dirs = min(f for f in (t['fragment'], t['id'], info['bytesUsed']) if f > t['directory']) if any(f > t['directory'] for f in (t['fragment'], t['id'], info['bytesUsed'])) else info['bytesUsed']
        self.dirs = self._metadata(t['directory'], end_of_dirs)
        self.fragments = self._fragment_table(t['fragment'], info['fragments'])

    # -- compression --
    def _decompress(self, raw, limit):
        try:
            if self.comp == 1:
                data = zlib.decompressobj().decompress(raw, limit + 1)
            elif self.comp == 4:
                data = lzma.LZMADecompressor(format=lzma.FORMAT_XZ).decompress(raw, limit + 1)
            else:
                data = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(raw, limit + 1)
        except (zlib.error, lzma.LZMAError) as error:
            raise FirmwareError('CORRUPT_BLOCK', f'SquashFS block does not decompress: {error}')
        if len(data) > limit:
            raise FirmwareError('CORRUPT_BLOCK', 'SquashFS block is larger than its declared size')
        return data

    # -- metadata streams: sequences of <= 8 KiB blocks, each with a 2-byte header --
    def _metadata(self, start, end):
        blocks, order, position = {}, [], start
        while position + 2 <= end and len(order) < 100000:
            head = self.src.read(self.base + position, 2)
            if len(head) < 2:
                self.notes.append(f'metadata block at {position} is past the end of the image')
                break
            header = struct.unpack(self.e + 'H', head)[0]
            size, stored = header & 0x7fff, bool(header & 0x8000)
            raw = self.src.read(self.base + position + 2, size)
            if len(raw) != size or size == 0 or size > 8192 + 64:
                self.notes.append(f'metadata block at {position} is unreadable')
                break
            blocks[position - start] = raw if stored else self._decompress(raw, 8192)
            order.append(position - start)
            position += 2 + size
        return {'blocks': blocks, 'order': order}

    def _meta_read(self, stream, block, offset, length):
        order, blocks = stream['order'], stream['blocks']
        if block not in blocks:
            raise FirmwareError('BAD_REFERENCE', f'metadata block {block} does not exist')
        index, out = order.index(block), b''
        while len(out) < length:
            if index >= len(order):
                raise FirmwareError('BAD_REFERENCE', 'metadata read runs past the table')
            data = blocks[order[index]]
            out += data[offset:offset + length - len(out)]
            index, offset = index + 1, 0
        return out

    def _fragment_table(self, start, count):
        if not count or start >= self.info['bytesUsed']:
            return []
        pointers = struct.unpack(self.e + f'{(count + 511) // 512}Q', self.src.read(self.base + start, 8 * ((count + 511) // 512)))
        entries = []
        for pointer in pointers:
            header = struct.unpack(self.e + 'H', self.src.read(self.base + pointer, 2))[0]
            size, stored = header & 0x7fff, bool(header & 0x8000)
            raw = self.src.read(self.base + pointer + 2, size)
            data = raw if stored else self._decompress(raw, 8192)
            for i in range(0, len(data) - 15, 16):
                entries.append(struct.unpack(self.e + 'QII', data[i:i + 16])[:2])
        return entries[:count]

    # -- inodes --
    def _inode(self, reference):
        block, offset = reference >> 16, reference & 0xffff
        e = self.e
        head = self._meta_read(self.inodes, block, offset, 16)
        kind, mode, uid, gid, mtime, number = struct.unpack(e + 'HHHHII', head)
        node = {'type': kind, 'mode': mode, 'mtime': mtime, 'inode': number}
        body = lambda size: self._meta_read(self.inodes, block, offset + 16, size)
        if kind == 1:
            start, links, size, off, parent = struct.unpack(e + 'IIHHI', body(16)); node.update(dirBlock=start, fileSize=size, dirOffset=off)
        elif kind == 8:
            links, size, start, parent, index_count, off, xattr = struct.unpack(e + 'IIIIHHI', body(24)); node.update(dirBlock=start, fileSize=size, dirOffset=off)
        elif kind == 2:
            start, fragment, off, size = struct.unpack(e + 'IIII', body(16)); node.update(start=start, fragment=fragment, fragOffset=off, fileSize=size)
            node['blocks'] = self._block_list(block, offset + 32, size, fragment)
        elif kind == 9:
            start, size, sparse, links, fragment, off, xattr = struct.unpack(e + 'QQQIIII', body(40)); node.update(start=start, fragment=fragment, fragOffset=off, fileSize=size)
            node['blocks'] = self._block_list(block, offset + 16 + 40, size, fragment)
        elif kind in (3, 10):
            links, length = struct.unpack(e + 'II', body(8)); node['target'] = self._meta_read(self.inodes, block, offset + 24, min(length, 4096)).decode('utf-8', 'replace')
        elif kind in (4, 5, 11, 12):
            links, rdev = struct.unpack(e + 'II', body(8)); node['rdev'] = rdev
        return node

    def _block_list(self, block, offset, size, fragment):
        count = size // self.bs if fragment != 0xffffffff else (size + self.bs - 1) // self.bs
        if count > 1 << 22:
            raise FirmwareError('BAD_INODE', 'file claims an absurd number of blocks')
        return list(struct.unpack(self.e + f'{count}I', self._meta_read(self.inodes, block, offset, 4 * count))) if count else []

    # -- file data --
    def _read_file(self, node, limit):
        size = node['fileSize']
        if size > limit:
            raise FirmwareError('FILE_TOO_LARGE', f'file of {size} bytes exceeds the read limit {limit}')
        out, position = bytearray(), node['start']
        for index, word in enumerate(node['blocks']):
            length, stored = word & 0xffffff, bool(word & (1 << 24))
            want = min(self.bs, size - index * self.bs)
            if length == 0:
                out += bytes(want)
                continue
            raw = self.src.read(self.base + position, length)
            if len(raw) != length:
                raise FirmwareError('TRUNCATED', 'SquashFS data block lies past the end of the image')
            out += raw if stored else self._decompress(raw, self.bs)
            position += length
        if node['fragment'] != 0xffffffff and len(out) < size:
            if node['fragment'] >= len(self.fragments):
                raise FirmwareError('BAD_INODE', 'fragment index out of range')
            start, word = self.fragments[node['fragment']]
            length, stored = word & 0xffffff, bool(word & (1 << 24))
            raw = self.src.read(self.base + start, length)
            block = raw if stored else self._decompress(raw, self.bs)
            out += block[node['fragOffset']:node['fragOffset'] + size - len(out)]
        if len(out) != size:
            raise FirmwareError('CORRUPT_BLOCK', f'file read {len(out)} of {size} bytes')
        return bytes(out)

    # -- directory walk --
    def _children(self, node):
        size = node['fileSize']
        if size < 3:
            return []
        data = self._meta_read(self.dirs, node['dirBlock'], node['dirOffset'], size - 3)
        out, i, e = [], 0, self.e
        while i + 12 <= len(data) and len(out) < 100000:
            count, start, number = struct.unpack(e + 'III', data[i:i + 12])
            i += 12
            for _ in range(count + 1):
                if i + 8 > len(data):
                    return out
                offset, delta, kind, name_size = struct.unpack(e + 'HhHH', data[i:i + 8])
                name = data[i + 8:i + 8 + name_size + 1]
                i += 8 + name_size + 1
                out.append((name.decode('utf-8', 'replace'), (start << 16) | offset, kind))
        return out

    def entries(self, max_entries=None):
        max_entries = max_entries or rules.LIMITS['max_files']
        stack, seen, produced = [(self.info['rootInode'], '')], set(), 0
        while stack:
            reference, path = stack.pop()
            try:
                node = self._inode(reference)
            except (FirmwareError, struct.error) as error:
                self.notes.append(f'{path or "/"}: {error}')
                continue
            kind = node['type']
            mode = node['mode']
            if kind in (1, 8):
                if reference in seen:
                    self.notes.append(f'{path or "/"}: directory loop')
                    continue
                seen.add(reference)
                if path:
                    yield Entry(path, 'dir', 0, mode)
                try:
                    children = self._children(node)
                except (FirmwareError, struct.error) as error:
                    self.notes.append(f'{path or "/"}: {error}')
                    continue
                for name, child_ref, _ in sorted(children, reverse=True):
                    if len(path.split('/')) > 64:
                        self.notes.append('directories nested deeper than 64 levels were not followed')
                        continue
                    stack.append((child_ref, f'{path}/{name}' if path else name))
                continue
            produced += 1
            if produced > max_entries:
                self.notes.append(f'listing stopped after {max_entries} entries')
                return
            if kind in (2, 9):
                yield Entry(path, 'file', node['fileSize'], mode, reader=lambda limit, n=node: self._read_file(n, limit), extra={'mtime': node['mtime']})
            elif kind in (3, 10):
                yield Entry(path, 'symlink', 0, mode, target=node['target'])
            elif kind in (4, 5, 11, 12):
                yield Entry(path, 'device', 0, mode, extra={'rdev': node['rdev']})
            else:
                yield Entry(path, 'fifo' if kind in (6, 13) else 'socket', 0, mode)


# ---- ext2 / ext3 / ext4 ------------------------------------------------------------------------------------------------

class Ext:
    """ext2/3/4 reader: block-mapped and extent files, linear directory scan, fast and block symlinks."""
    SB = 1024

    @staticmethod
    def probe(src, offset=0):
        sb = src.read(offset + Ext.SB, 264)
        if len(sb) < 264 or struct.unpack_from('<H', sb, 56)[0] != 0xEF53:
            return None
        inodes, blocks_lo, _, _, _, first_data, log_bs, _, per_group, _, inodes_per_group = struct.unpack_from('<IIIIIIIIIII', sb, 0)[:11]
        state, rev = struct.unpack_from('<HH', sb, 58)[0], struct.unpack_from('<I', sb, 76)[0]
        compat, incompat, ro = struct.unpack_from('<III', sb, 92)
        if log_bs > 6 or per_group == 0 or inodes_per_group == 0 or inodes == 0 or blocks_lo == 0:
            return None
        block_size = 1024 << log_bs
        blocks = blocks_lo | (struct.unpack_from('<I', sb, 336)[0] << 32 if incompat & 0x80 else 0)
        inode_size = struct.unpack_from('<H', sb, 88)[0] if rev >= 1 else 128
        if inode_size < 128 or inode_size > block_size or inode_size & (inode_size - 1) or blocks * block_size < block_size * 2:
            return None
        version = 4 if incompat & 0x40 or ro & 0x40 else 3 if compat & 0x4 else 2
        return {'blockSize': block_size, 'blocks': blocks, 'inodes': inodes, 'inodeSize': inode_size, 'version': f'ext{version}', 'volume': sb[120:136].split(b'\0')[0].decode('latin1'),
                'lastMounted': sb[136:200].split(b'\0')[0].decode('latin1'), 'size': blocks * block_size, 'features': {'compat': compat, 'incompat': incompat, 'roCompat': ro}, 'firstDataBlock': first_data,
                'blocksPerGroup': per_group, 'inodesPerGroup': inodes_per_group, 'descSize': struct.unpack_from('<H', sb, 254)[0] if incompat & 0x80 else 32}

    def __init__(self, src, offset=0):
        info = self.probe(src, offset)
        if info is None:
            raise FirmwareError('BAD_EXT', 'not an ext2/3/4 superblock')
        self.src, self.base, self.info, self.notes = src, offset, info, []
        self.bs = info['blockSize']
        if info['features']['incompat'] & 0x2000 or info['features']['incompat'] & 0x8000:
            self.notes.append('encrypted or large-xattr incompat feature present; names or data may be unreadable')
        self.group_blocks = (info['inodes'] + info['inodesPerGroup'] - 1) // info['inodesPerGroup']
        table_block = info['firstDataBlock'] + 1
        desc = src.read(self.base + table_block * self.bs, self.group_blocks * info['descSize'])
        self.inode_tables = []
        for g in range(self.group_blocks):
            row = desc[g * info['descSize']:(g + 1) * info['descSize']]
            if len(row) < 12:
                break
            low = struct.unpack_from('<I', row, 8)[0]
            high = struct.unpack_from('<I', row, 40)[0] if info['descSize'] >= 64 and len(row) >= 44 else 0
            self.inode_tables.append(low | (high << 32))

    def _inode(self, number):
        info = self.info
        if number < 1 or number > info['inodes']:
            raise FirmwareError('BAD_INODE', f'inode {number} out of range')
        group, index = divmod(number - 1, info['inodesPerGroup'])
        if group >= len(self.inode_tables):
            raise FirmwareError('BAD_INODE', 'inode group out of range')
        raw = self.src.read(self.base + self.inode_tables[group] * self.bs + index * info['inodeSize'], max(128, min(info['inodeSize'], 256)))
        if len(raw) < 128:
            raise FirmwareError('TRUNCATED', f'inode {number} lies past the end of the image')
        mode, uid, size_lo = struct.unpack_from('<HHI', raw, 0)
        mtime = struct.unpack_from('<I', raw, 16)[0]
        flags, = struct.unpack_from('<I', raw, 32)
        size = size_lo | (struct.unpack_from('<I', raw, 108)[0] << 32 if (mode & 0o170000) in (0o100000, 0o040000) else 0)
        return {'mode': mode, 'size': size, 'flags': flags, 'block': raw[40:100], 'mtime': mtime, 'number': number}

    def _extents(self, node_bytes, depth_left=6):
        magic, entries, _, depth = struct.unpack_from('<HHHH', node_bytes, 0)
        if magic != 0xF30A or entries > 340:
            raise FirmwareError('BAD_EXTENTS', 'invalid extent header')
        out = []
        for i in range(entries):
            row = node_bytes[12 + i * 12:24 + i * 12]
            if len(row) < 12:
                break
            if depth == 0:
                logical, length, hi, lo = struct.unpack('<IHHI', row)
                out.append((logical, length - 32768 if length > 32768 else length, (hi << 32) | lo, length > 32768))
            else:
                logical, lo, hi, _ = struct.unpack('<IIHH', row)
                if depth_left <= 0:
                    raise FirmwareError('BAD_EXTENTS', 'extent tree too deep')
                child = self.src.read(self.base + ((hi << 32) | lo) * self.bs, self.bs)
                out += self._extents(child, depth_left - 1)
        return out

    def _block_numbers(self, node, count):
        """Physical block numbers for the first ``count`` logical blocks (0 = hole)."""
        if node['flags'] & 0x80000:
            blocks = [0] * count
            for logical, length, physical, unwritten in self._extents(node['block']):
                for i in range(min(length, max(0, count - logical))):
                    blocks[logical + i] = 0 if unwritten else physical + i
            return blocks
        words = struct.unpack('<15I', node['block'])
        blocks = list(words[:12])
        per = self.bs // 4

        def indirect(pointer, level):
            if pointer == 0:
                return [0] * (per ** level)
            data = self.src.read(self.base + pointer * self.bs, self.bs)
            pointers = struct.unpack(f'<{len(data) // 4}I', data)
            if level == 1:
                return list(pointers)
            out = []
            for p in pointers:
                if len(out) >= count:
                    break
                out += indirect(p, level - 1)
            return out
        for pointer, level in zip(words[12:], (1, 2, 3)):
            if len(blocks) >= count:
                break
            blocks += indirect(pointer, level)
        return blocks[:count] + [0] * max(0, count - len(blocks))

    def _read(self, node, limit):
        size = node['size']
        if size > limit:
            raise FirmwareError('FILE_TOO_LARGE', f'file of {size} bytes exceeds the read limit {limit}')
        if node['flags'] & 0x10000000:
            return node['block'][:size]                               # inline data stored in i_block (small files only)
        count = (size + self.bs - 1) // self.bs
        out = bytearray()
        for number in self._block_numbers(node, count):
            out += self.src.read(self.base + number * self.bs, self.bs) if number else bytes(self.bs)
        return bytes(out[:size])

    def entries(self, max_entries=None):
        max_entries = max_entries or rules.LIMITS['max_files']
        stack, seen, produced = [(2, '')], set(), 0
        while stack:
            number, path = stack.pop()
            try:
                node = self._inode(number)
            except (FirmwareError, struct.error) as error:
                self.notes.append(f'{path or "/"}: {error}')
                continue
            kind = MODE_KIND.get(node['mode'] & 0o170000, 'other')
            if kind == 'dir':
                if number in seen:
                    self.notes.append(f'{path or "/"}: directory loop')
                    continue
                seen.add(number)
                if path:
                    yield Entry(path, 'dir', 0, node['mode'])
                try:
                    data = self._read(node, 64 * 1024 * 1024)
                except (FirmwareError, struct.error) as error:
                    self.notes.append(f'{path or "/"}: {error}')
                    continue
                children, i = [], 0
                while i + 8 <= len(data):
                    child, record, name_len, _ = struct.unpack_from('<IHBB', data, i)
                    if record < 8 or record % 4 or i + record > len(data):
                        break
                    name = data[i + 8:i + 8 + name_len].decode('utf-8', 'replace')
                    if child and name not in ('.', '..'):
                        children.append((name, child))
                    i += record
                for name, child in sorted(children, reverse=True):
                    if len(path.split('/')) > 64:
                        continue
                    stack.append((child, f'{path}/{name}' if path else name))
                continue
            produced += 1
            if produced > max_entries:
                self.notes.append(f'listing stopped after {max_entries} entries')
                return
            if kind == 'file':
                yield Entry(path, 'file', node['size'], node['mode'], reader=lambda limit, n=node: self._read(n, limit), extra={'mtime': node['mtime']})
            elif kind == 'symlink':
                try:
                    target = node['block'][:node['size']] if node['size'] < 60 and not node['flags'] & 0x80000 else self._read(node, 4096)
                    yield Entry(path, 'symlink', 0, node['mode'], target=target.decode('utf-8', 'replace'))
                except (FirmwareError, struct.error) as error:
                    self.notes.append(f'{path}: {error}')
            else:
                yield Entry(path, kind, 0, node['mode'])


# ---- cpio (newc) -------------------------------------------------------------------------------------------------------

class Cpio:
    @staticmethod
    def probe(src, offset=0):
        """Walk headers until the TRAILER; returns size and entry count, or None if the first header is not plausible."""
        position, count = offset, 0
        while count < 200000:
            head = src.read(position, 110)
            if len(head) < 110 or head[:6] not in (b'070701', b'070702'):
                return None if count == 0 else {'size': position - offset, 'entries': count, 'complete': False}
            try:
                fields = [int(head[6 + 8 * i:14 + 8 * i], 16) for i in range(13)]
            except ValueError:
                return None if count == 0 else {'size': position - offset, 'entries': count, 'complete': False}
            size, name_size = fields[6], fields[11]
            if name_size == 0 or name_size > 4096:
                return None if count == 0 else {'size': position - offset, 'entries': count, 'complete': False}
            name = src.read(position + 110, name_size)
            nxt = position + ((110 + name_size + 3) & ~3) + ((size + 3) & ~3)
            if name.rstrip(b'\0') == b'TRAILER!!!':
                return {'size': nxt - offset, 'entries': count, 'complete': True}
            count += 1
            position = nxt
        return None

    def __init__(self, src, offset=0):
        self.src, self.base, self.notes = src, offset, []

    def entries(self, max_entries=None):
        max_entries = max_entries or rules.LIMITS['max_files']
        position, produced = self.base, 0
        while produced < max_entries:
            head = self.src.read(position, 110)
            if len(head) < 110 or head[:6] not in (b'070701', b'070702'):
                self.notes.append('archive ends without a TRAILER entry')
                return
            fields = [int(head[6 + 8 * i:14 + 8 * i], 16) for i in range(13)]
            mode, size, name_size = fields[1], fields[6], fields[11]
            name = self.src.read(position + 110, name_size).rstrip(b'\0').decode('utf-8', 'replace')
            data_at = position + ((110 + name_size + 3) & ~3)
            position = data_at + ((size + 3) & ~3)
            if name == 'TRAILER!!!':
                return
            path = name[2:] if name.startswith('./') else name
            if path in ('', '.'):
                continue
            produced += 1
            kind = MODE_KIND.get(mode & 0o170000, 'other')
            if kind == 'file':
                yield Entry(path, 'file', size, mode, reader=lambda limit, a=data_at, s=size: self._file(a, s, limit), extra={'mtime': fields[5]})
            elif kind == 'symlink':
                yield Entry(path, 'symlink', 0, mode, target=self.src.read(data_at, size).decode('utf-8', 'replace'))
            else:
                yield Entry(path, kind, 0, mode)

    def _file(self, at, size, limit):
        if size > limit:
            raise FirmwareError('FILE_TOO_LARGE', f'file of {size} bytes exceeds the read limit {limit}')
        return self.src.read(at, size)


# ---- tar / zip (standard library, bounded) -------------------------------------------------------------------------------

def tar_entries(src, offset=0):
    stream = SourceFile(src.window(offset))
    try:
        archive = tarfile.open(fileobj=stream, mode='r:')
    except tarfile.TarError as error:
        raise FirmwareError('BAD_TAR', str(error))
    produced = 0
    for member in archive:
        produced += 1
        if produced > rules.LIMITS['max_files']:
            return
        path = member.name[2:] if member.name.startswith('./') else member.name
        if member.isfile():
            yield Entry(path, 'file', member.size, member.mode, reader=lambda limit, m=member: _tar_read(archive, m, limit), extra={'mtime': int(member.mtime)})
        elif member.isdir():
            yield Entry(path, 'dir', 0, member.mode)
        elif member.issym() or member.islnk():
            yield Entry(path, 'symlink' if member.issym() else 'hardlink', 0, member.mode, target=member.linkname)
        else:
            yield Entry(path, 'device' if member.isdev() else 'other', 0, member.mode)


def _tar_read(archive, member, limit):
    if member.size > limit:
        raise FirmwareError('FILE_TOO_LARGE', f'file of {member.size} bytes exceeds the read limit {limit}')
    handle = archive.extractfile(member)
    return handle.read() if handle else b''


def tar_size(src, offset=0):
    """Size of a tar archive up to its terminating zero blocks; None when the first header fails its checksum."""
    position, count = offset, 0
    while count < 500000:
        block = src.read(position, 512)
        if len(block) < 512:
            return None if count == 0 else position - offset
        if block == bytes(512):
            return (position - offset) + 1024 if count else None
        stored = block[148:156].split(b'\0')[0].strip()
        try:
            expected = int(stored or b'0', 8)
        except ValueError:
            return None if count == 0 else position - offset
        actual = sum(block[:148]) + 8 * 32 + sum(block[156:])
        if actual != expected and (sum(bytes(b if b < 128 else b - 256 for b in block[:148])) + 256 + sum(block[156:])) != expected:
            return None if count == 0 else position - offset
        try:
            size = int(block[124:136].split(b'\0')[0].strip() or b'0', 8)
        except ValueError:
            return None if count == 0 else position - offset
        position += 512 + ((size + 511) & ~511)
        count += 1
    return position - offset


def zip_entries(src, offset=0, end=None):
    try:
        archive = zipfile.ZipFile(SourceFile(src.window(offset, None if end is None else end - offset)))
    except (zipfile.BadZipFile, OSError) as error:
        raise FirmwareError('BAD_ZIP', str(error))
    produced = 0
    for info in archive.infolist():
        produced += 1
        if produced > rules.LIMITS['max_files']:
            return
        if info.is_dir():
            yield Entry(info.filename.rstrip('/'), 'dir', 0, 0o755)
        else:
            mode = (info.external_attr >> 16) & 0xffff
            kind = MODE_KIND.get(mode & 0o170000, 'file') if mode else 'file'
            yield Entry(info.filename, kind, info.file_size, mode or 0o644, reader=lambda limit, i=info: _zip_read(archive, i, limit))


def _zip_read(archive, info, limit):
    if info.file_size > limit:
        raise FirmwareError('FILE_TOO_LARGE', f'file of {info.file_size} bytes exceeds the read limit {limit}')
    if info.flag_bits & 1:
        raise FirmwareError('ENCRYPTED', 'entry is encrypted')
    with archive.open(info) as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise FirmwareError('FILE_TOO_LARGE', 'entry expands past the read limit')
    return data
