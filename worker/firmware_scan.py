"""Firmware scanner and extractor: find validated containers at every offset, describe them, and optionally unpack them.

``scan_firmware(path, ...)`` walks a blob the way binwalk does (signature hits), but every hit must pass its format's own
validation before it counts, and recognised containers are opened: compressed streams are decompressed (bounded) and scanned
again, file systems and archives are listed, boot images are split into their payloads. With ``extract_to`` the contents are
written under that directory using sanitized names; nothing is executed and links are never created.
"""
import os
import re
import struct
import time
import zlib

import firmware_fs as fs
import firmware_images as images
import firmware_rules as rules
from firmware_io import Budget, FirmwareError, Source, inflate, safe_relative, sha256_bytes, unique_path

SCHEMA = 'ig5.firmware.v1'
CODECS = {'gzip': 'gzip', 'bzip2': 'bzip2', 'xz': 'xz', 'lzma': 'lzma', 'zlib': 'zlib'}
PRIORITY = {'fdt': 0, 'uimage': 0, 'android-boot': 0, 'android-sparse': 0, 'trx': 0, 'squashfs': 1, 'ext': 1, 'cpio': 2, 'tar': 2, 'zip': 2, 'cramfs': 2, 'romfs': 2, 'ubi': 2, 'ubifs': 2, 'jffs2': 3,
            'xz': 3, 'gzip': 3, 'bzip2': 3, 'zstd': 3, 'lz4': 3, 'lzma': 4, 'zlib': 5, 'elf': 6, 'pe': 6, 'ihex': 7, 'srec': 7}


class Context:
    def __init__(self, budget, deadline, out_root, scan_decompress):
        self.budget, self.deadline, self.out_root, self.scan_decompress = budget, deadline, out_root, scan_decompress
        self.next_id, self.limits_hit, self.written, self.taken, self.skipped = 0, set(), [], {}, []
        self.banners, self.probe_bytes = {'kernel': None, 'busybox': None}, 0

    def check(self):
        if time.monotonic() > self.deadline:
            self.limits_hit.add('deadline')
            raise FirmwareError('DEADLINE', 'the time budget for this firmware ran out')

    def new_id(self):
        self.next_id += 1
        return self.next_id


# ---- per-format validators ---------------------------------------------------------------------------------------------

def _stream(kind, src, start, ctx, name):
    out, used, status = inflate(src, start, CODECS[kind], rules.LIMITS['validate_bytes'], max_in=64 * 1024 * 1024)
    minimum = 16 if kind in ('gzip', 'xz', 'bzip2') else 48
    if status == 'error' and len(out) < minimum or status == 'bomb' or (status == 'truncated' and len(out) < minimum) or not out:
        return None
    return {'meta': {'status': status, 'validatedOutputBytes': len(out)}, 'size': used if status == 'complete' else None, 'truncated': status == 'truncated', 'sizeKnown': status == 'complete'}


def validate(sig, src, start, hit, ctx):
    fid = sig['id']
    head = src.read(start, 64)
    if fid == 'gzip':
        if len(head) < 10 or head[3] & 0xe0 or head[8] not in (0, 2, 4) or (head[9] > 13 and head[9] != 255):
            return None
        return _stream('gzip', src, start, ctx, 'gzip')
    if fid == 'bzip2':
        if len(head) < 10 or not 0x31 <= head[3] <= 0x39 or head[4:10] != b'\x31\x41\x59\x26\x53\x59':
            return None
        return _stream('bzip2', src, start, ctx, 'bzip2')
    if fid == 'xz':
        if len(head) < 12 or (zlib.crc32(head[6:8]) & 0xffffffff) != struct.unpack('<I', head[8:12])[0]:
            return None
        return _stream('xz', src, start, ctx, 'xz')
    if fid == 'lzma':
        if len(head) < 13:
            return None
        dict_size, usize = struct.unpack('<IQ', head[1:13])
        if dict_size < 4096 or dict_size > 1 << 30 or (dict_size & (dict_size - 1) and (dict_size & (dict_size >> 1) == 0 or (dict_size - (dict_size & -dict_size)) & ((dict_size - (dict_size & -dict_size)) - 1))) or not (usize == 0xffffffffffffffff or usize < 1 << 38):
            return None
        return _stream('lzma', src, start, ctx, 'lzma')
    if fid == 'zlib':
        if len(head) < 2 or ((head[0] << 8) | head[1]) % 31 or head[0] != 0x78:
            return None
        return _stream('zlib', src, start, ctx, 'zlib')
    if fid == 'squashfs':
        info = fs.SquashFS.probe(src, start)
        if info is None or (hit[1].get('variant') == 'be') != (info['endian'] == 'big'):
            return None
        padded = (info['size'] + 4095) & ~4095
        size = padded if start + padded <= src.size else min(info['size'], src.size - start)
        return {'meta': {k: v for k, v in info.items() if k not in ('tables', 'rootInode', 'size')}, 'size': size, 'truncated': info['truncated'], 'sizeKnown': True, 'exact': info['size']}
    if fid == 'ext':
        if start < 0:
            return None
        info = fs.Ext.probe(src, start)
        if info is None:
            return None
        return {'meta': {k: v for k, v in info.items() if k not in ('features', 'firstDataBlock', 'blocksPerGroup', 'inodesPerGroup', 'descSize')}, 'size': min(info['size'], src.size - start), 'truncated': info['size'] > src.size - start, 'sizeKnown': True}
    if fid == 'cpio':
        info = fs.Cpio.probe(src, start)
        if info is None or info['entries'] == 0 and not info['complete']:
            return None
        return {'meta': {'entries': info['entries'], 'complete': info['complete']}, 'size': info['size'], 'sizeKnown': info['complete'], 'truncated': not info['complete']}
    if fid == 'tar':
        size = fs.tar_size(src, start)
        return {'meta': {}, 'size': size, 'sizeKnown': True, 'truncated': False} if size else None
    if fid == 'zip':
        return _validate_zip(src, start)
    if fid == 'uimage':
        info = images.probe_uimage(src, start)
        if info is None:
            return None
        return {'meta': {k: v for k, v in info.items() if k not in ('size', 'truncated', 'valid')}, 'size': info['size'], 'sizeKnown': not info['truncated'], 'truncated': info['truncated'], 'checks': info['checks'], 'valid': info['valid']}
    if fid == 'fdt':
        info = images.probe_fdt(src, start)
        if info is None:
            return None
        return {'meta': {'version': info['version']}, 'size': info['size'], 'sizeKnown': True, 'truncated': info['truncated'], '_info': info}
    if fid == 'android-boot':
        info = images.probe_android_boot(src, start)
        if info is None:
            return None
        return {'meta': {k: v for k, v in info.items() if k not in ('layout', 'size', 'truncated')}, 'size': info['size'], 'sizeKnown': True, 'truncated': info['truncated'], '_info': info}
    if fid == 'android-sparse':
        info = images.probe_android_sparse(src, start)
        if info is None:
            return None
        size = images.sparse_size(src, start, info)
        if size is None:
            return None
        available = src.size - start
        return {'meta': {'blockSize': info['blockSize'], 'rawSize': info['rawSize'], 'chunks': info['chunks']}, 'size': min(size, available), 'sizeKnown': True, 'truncated': size > available, '_info': info}
    if fid == 'trx':
        info = images.probe_trx(src, start)
        return {'meta': {k: v for k, v in info.items() if k != 'size'}, 'size': info['size'], 'sizeKnown': True, 'truncated': False, '_info': info} if info else None
    if fid == 'cramfs':
        return _validate_cramfs(src, start)
    if fid == 'romfs':
        return _validate_romfs(src, start)
    if fid == 'jffs2':
        return _validate_jffs2(src, start)
    if fid == 'ubi':
        return _validate_ubi(src, start)
    if fid == 'ubifs':
        return _validate_ubifs(src, start)
    if fid == 'elf':
        return _validate_elf(src, start)
    if fid == 'pe':
        return _validate_pe(src, start)
    if fid in ('zstd', 'lz4'):
        if fid == 'zstd' and len(head) >= 5 and head[4] & 0x08:
            return None
        return {'meta': {}, 'size': None, 'sizeKnown': False, 'truncated': False}
    if fid == 'android-payload':
        if len(head) < 12 or struct.unpack('>Q', head[4:12])[0] not in (1, 2):
            return None
        return {'meta': {'payloadVersion': struct.unpack('>Q', head[4:12])[0]}, 'size': None, 'sizeKnown': False, 'truncated': False}
    if fid == 'ihex':
        return _validate_text(src, start, re.compile(rb'^:[0-9A-Fa-f]{10,}\r?\n'))
    if fid == 'srec':
        return _validate_text(src, start, re.compile(rb'^S0[0-9A-Fa-f]{6,}\r?\n'))
    return None


def _validate_zip(src, start):
    head = src.read(start, 30)
    if len(head) < 30 or struct.unpack('<H', head[4:6])[0] > 63 or struct.unpack('<H', head[26:28])[0] == 0:
        return None
    position, tries = start + 30, 0
    while tries < 6:
        at = src.find(b'PK\x05\x06', position)
        if at < 0:
            return None
        tries += 1
        record = src.read(at, 22)
        if len(record) == 22:
            end = at + 22 + struct.unpack('<H', record[20:22])[0]
            try:
                names = [e.path for e in fs.zip_entries(src, start, end)]
            except (FirmwareError, Exception):
                names = None
            if names:
                return {'meta': {'entries': len(names)}, 'size': end - start, 'sizeKnown': True, 'truncated': end > src.size}
        position = at + 4
    return None


def _validate_cramfs(src, start):
    head = src.read(start, 76)
    if len(head) < 76 or head[16:32] != b'Compressed ROMFS':
        return None
    size, flags = struct.unpack('<II', head[4:12])
    return {'meta': {'name': head[48:64].split(b'\0')[0].decode('latin1'), 'files': struct.unpack('<I', head[44:48])[0]}, 'size': min(size, src.size - start), 'sizeKnown': True, 'truncated': size > src.size - start} if size >= 76 else None


def _validate_romfs(src, start):
    head = src.read(start, 16)
    if len(head) < 16:
        return None
    size = struct.unpack('>I', head[8:12])[0]
    if size < 32 or size > 1 << 31:
        return None
    check = src.read(start, min(size, 512))
    total = sum(struct.unpack('>%dI' % (len(check) // 4), check[:len(check) // 4 * 4])) & 0xffffffff
    return {'meta': {'checksumOk': total == 0}, 'size': min(size, src.size - start), 'sizeKnown': True, 'truncated': size > src.size - start} if total == 0 else None


def _validate_jffs2(src, start):
    position, nodes = start, 0
    while nodes < 3:
        head = src.read(position, 12)
        if len(head) < 12:
            return None
        magic, kind, total = struct.unpack('<HHI', head[:8])
        if magic != 0x1985 or kind not in (0xE001, 0xE002, 0x2003, 0x2004, 0x2006, 0xE003) or total < 12 or total > 1 << 20:
            return None
        position += (total + 3) & ~3
        nodes += 1
    return {'meta': {'validated': 'three consecutive node headers; CRCs not checked'}, 'size': None, 'sizeKnown': False, 'truncated': False}


def _ubi_crc(data):
    return (zlib.crc32(data) ^ 0xffffffff) & 0xffffffff


def _validate_ubi(src, start):
    head = src.read(start, 64)
    if len(head) < 64 or head[4] != 1:
        return None
    crc = struct.unpack('>I', head[60:64])[0]
    if _ubi_crc(head[:60]) != crc:
        return None
    vid, data = struct.unpack('>II', head[16:24])
    return {'meta': {'vidHeaderOffset': vid, 'dataOffset': data, 'eraseCounter': struct.unpack('>Q', head[8:16])[0], 'headerCrcOk': True}, 'size': None, 'sizeKnown': False, 'truncated': False}


def _validate_ubifs(src, start):
    head = src.read(start, 24)
    if len(head) < 24:
        return None
    crc, seq, length = struct.unpack('<IQI', head[4:20])
    if length < 24 or length > 1 << 20:
        return None
    body = src.read(start + 8, length - 8)
    if len(body) != length - 8 or _ubi_crc(body) != crc:
        return None
    return {'meta': {'nodeType': head[20], 'headerCrcOk': True}, 'size': None, 'sizeKnown': False, 'truncated': False}


def _validate_elf(src, start):
    head = src.read(start, 64)
    if len(head) < 52 or head[4] not in (1, 2) or head[5] not in (1, 2) or head[6] != 1:
        return None
    e = '<' if head[5] == 1 else '>'
    is64 = head[4] == 2
    if is64 and len(head) < 64:
        return None
    if is64:
        e_type, machine, _, entry, phoff, shoff, _, _, phentsize, phnum, shentsize, shnum = struct.unpack(e + 'HHIQQQIHHHHH', head[16:62])
    else:
        e_type, machine, _, entry, phoff, shoff, _, _, phentsize, phnum, shentsize, shnum = struct.unpack(e + 'HHIIIIIHHHHH', head[16:50])
    if e_type > 4 and e_type < 0xfe00 or machine == 0 or (phnum and phentsize != (56 if is64 else 32)) or phnum > 256 or shnum > 4096:
        return None
    end = max([phoff + phnum * phentsize if phnum else 0, shoff + shnum * shentsize if shnum else 0, 64])
    for i in range(min(phnum, 64)):
        row = src.read(start + phoff + i * phentsize, phentsize)
        if len(row) < phentsize:
            return None
        if is64:
            offset, filesz = struct.unpack(e + 'QQ', row[8:16] + row[32:40])
        else:
            offset, filesz = struct.unpack(e + 'II', row[4:8] + row[16:20])
        end = max(end, offset + filesz)
    return {'meta': {'bits': 64 if is64 else 32, 'endian': 'little' if e == '<' else 'big', 'machine': rules.MACHINES.get(machine, f'machine {machine:#x}'), 'type': {1: 'relocatable', 2: 'executable', 3: 'shared object/PIE', 4: 'core'}.get(e_type, 'other'),
                     'entry': f'{entry:#x}'}, 'size': end if end <= src.size - start else None, 'sizeKnown': end <= src.size - start, 'truncated': end > src.size - start}


def _validate_pe(src, start):
    head = src.read(start, 64)
    if len(head) < 64 or head[:2] != b'MZ':
        return None
    lfanew = struct.unpack('<I', head[60:64])[0]
    if lfanew < 64 or lfanew > 1 << 20:
        return None
    nt = src.read(start + lfanew, 24)
    if len(nt) < 24 or nt[:4] != b'PE\0\0':
        return None
    machine, sections, _, _, _, optional, characteristics = struct.unpack('<HHIIIHH', nt[4:24])
    table = src.read(start + lfanew + 24 + optional, min(sections, 96) * 40)
    end = 0
    for i in range(len(table) // 40):
        raw, ptr = struct.unpack('<II', table[i * 40 + 16:i * 40 + 24])
        end = max(end, ptr + raw)
    magic = struct.unpack('<H', src.read(start + lfanew + 24, 2).ljust(2, b'\0'))[0]
    return {'meta': {'bits': 64 if magic == 0x20b else 32, 'machine': {0x14c: 'x86', 0x8664: 'x86-64', 0x1c0: 'ARM', 0xaa64: 'AArch64', 0x1c4: 'ARM Thumb-2'}.get(machine, f'{machine:#x}'), 'dll': bool(characteristics & 0x2000), 'sections': sections},
            'size': end if 0 < end <= src.size - start else None, 'sizeKnown': 0 < end <= src.size - start, 'truncated': False}


def _validate_text(src, start, pattern):
    if start != 0:
        return None
    head = src.read(0, 200)
    return {'meta': {}, 'size': src.size, 'sizeKnown': True, 'truncated': False} if pattern.match(head) else None


# ---- the walk -------------------------------------------------------------------------------------------------------

def find_candidates(src, ctx):
    found = []
    for sig in rules.SIGNATURES:
        position, count = 0, 0
        while count < rules.LIMITS['max_matches_per_signature']:
            ctx.check()
            hit = src.find(sig['magic'], position)
            if hit < 0:
                break
            position = hit + 1
            start = hit - sig['offset']
            if sig.get('start_only') and hit != 0 or start < 0:
                if sig.get('start_only'):
                    break
                continue
            found.append((start, PRIORITY.get(sig['id'], 9), sig, hit))
            count += 1
        if count >= rules.LIMITS['max_matches_per_signature']:
            ctx.limits_hit.add(f'signature-matches:{sig["id"]}')
    found.sort(key=lambda row: (row[0], row[1]))
    return found


def identify_head(data):
    """Cheap format guess from the first bytes of a blob, used to decide whether an extracted file deserves a recursive scan."""
    for sig in rules.SIGNATURES:
        if sig['offset'] == 0 and data[:len(sig['magic'])] == sig['magic'] and sig['id'] not in ('pe', 'elf', 'ihex', 'srec', 'lzma', 'zlib', 'jffs2', 'ubi', 'ubifs'):
            return sig['id']
    if data[257:262] == b'ustar':
        return 'tar'
    if data[1080:1082] == b'\x53\xef':
        return 'ext'
    return None


def scan_blob(src, ctx, depth, label, parent_dir):
    """Components found in ``src``; ``parent_dir`` is the extraction directory for this level (or None)."""
    components, covered = [], 0
    for start, _, sig, hit in find_candidates(src, ctx):
        ctx.check()
        if start < covered:
            continue
        found = validate(sig, src, start, (hit, sig), ctx)
        if found is None:
            continue
        ctx.budget.take_component()
        size = found.get('size')
        component = {'id': ctx.new_id(), 'format': sig['id'], 'name': sig['name'], 'category': sig['category'], 'offset': start, 'size': size, 'sizeKnown': found.get('sizeKnown', False),
                     'truncated': found.get('truncated', False), 'meta': found.get('meta', {}), 'capabilities': list(rules.CAPABILITIES.get(sig['id'], ())), 'children': [], 'notes': []}
        for key in ('checks', 'valid'):
            if key in found:
                component[key] = found[key]
        if size and sig['category'] in ('compression', 'filesystem', 'image', 'archive'):
            covered = start + size
        elif sig['category'] == 'executable' and size:
            covered = start + size
        elif sig['id'] in ('jffs2', 'ubi', 'ubifs'):
            covered = src.size                                   # extent unknown: treat the rest as part of it
        elif not size and sig['category'] in ('compression',):
            covered = src.size
        elif sig['id'] in ('zstd', 'lz4', 'android-payload'):
            covered = src.size
        elif sig['category'] == 'text':
            covered = src.size
        try:
            open_component(component, found, src, start, ctx, depth, label, parent_dir)
        except FirmwareError as error:
            if error.code in ('DEADLINE',):
                raise
            component['notes'].append(f'{error.code}: {error}')
        except (struct.error, ValueError, IndexError, OSError, OverflowError, KeyError, TypeError, UnicodeError, zlib.error) as error:
            component['notes'].append(f'damaged structure: {type(error).__name__}')
        components.append(component)
    return components


def _slug(component):
    return f'{component["id"]:03d}_{component["format"]}'


def open_component(component, found, src, start, ctx, depth, label, parent_dir):
    fid, size = component['format'], component['size']
    here = os.path.join(parent_dir, _slug(component)) if parent_dir else None
    window = src.window(start, size) if size else src.window(start)
    if fid in CODECS:
        limit = rules.LIMITS['max_file_bytes'] if ctx.out_root else ctx.scan_decompress
        out, used, status = inflate(window, 0, CODECS[fid], limit)
        component['decompressed'] = {'size': len(out), 'status': status, 'sha256': sha256_bytes(out)}
        if status == 'limit':
            component['notes'].append(f'output stopped at {limit} bytes')
            ctx.limits_hit.add('decompress-limit')
        if status == 'bomb':
            component['notes'].append('decompression ratio too high; treated as a bomb')
            return
        if component.get('sizeKnown') is False and status == 'complete':
            component['size'] = used
            component['sizeKnown'] = True
        _payload(component, out, 'decompressed', ctx, depth, label, here, f'{_slug(component)}.bin')
    elif fid == 'squashfs':
        try:
            reader = fs.SquashFS(window.window(0, found.get('exact')) if found.get('exact') else window)
        except FirmwareError as error:
            component['notes'].append(f'{error.code}: {error}')
            return
        _filesystem(component, reader, ctx, depth, label, here)
    elif fid == 'ext':
        _filesystem(component, fs.Ext(window), ctx, depth, label, here)
    elif fid == 'cpio':
        _filesystem(component, fs.Cpio(window), ctx, depth, label, here)
    elif fid == 'tar':
        _filesystem(component, _Iter(lambda: fs.tar_entries(window)), ctx, depth, label, here)
    elif fid == 'zip':
        _filesystem(component, _Iter(lambda: fs.zip_entries(window)), ctx, depth, label, here)
    elif fid == 'uimage':
        info = images.probe_uimage(src, start)
        for name, offset, length, meta in images.uimage_children(src, start, info):
            _child(component, window, name, offset, length, meta, ctx, depth, label, here)
    elif fid == 'trx':
        for name, offset, length, meta in images.trx_children(found['_info']):
            _child(component, window, name, offset, length, meta, ctx, depth, label, here)
    elif fid == 'android-boot':
        for name, offset, length, meta in images.android_boot_children(found['_info']):
            _child(component, window, name, offset, length, meta, ctx, depth, label, here)
    elif fid == 'android-sparse':
        info = found['_info']
        limit = rules.LIMITS['max_file_bytes'] if ctx.out_root else ctx.scan_decompress
        buffer = bytearray()
        if images.unsparse(window, 0, info, buffer.extend, limit):
            _payload(component, bytes(buffer), 'unsparsed', ctx, depth, label, here, f'{_slug(component)}.raw')
        else:
            component['notes'].append(f'raw image is {info["rawSize"]} bytes, over the {limit} byte budget; not expanded')
            ctx.limits_hit.add('sparse-too-large')
    elif fid == 'fdt':
        _fit(component, found['_info'], window, ctx, depth, label, here)
    elif fid in ('elf',):
        _banners(window.read(0, rules.PROBE_BYTES), ctx)


def _child(component, window, name, offset, length, meta, ctx, depth, label, here):
    if length <= 0 or offset >= window.size:
        return
    sub = window.window(offset, length)
    entry = {'name': name, 'offset': offset, 'size': sub.size, 'meta': meta, 'components': []}
    component['children'].append(entry)
    if depth < ctx.budget.limits['max_depth']:
        entry['components'] = scan_blob(sub, ctx, depth + 1, f'{label}/{name}', os.path.join(here, safe_relative(name)[0]) if here else None)
    if here:
        data = sub.read(0, min(sub.size, rules.LIMITS['max_file_bytes']))
        _write(ctx, os.path.join(here, safe_relative(name)[0] + '.bin'), data, f'{label}/{name}', entry)
    _banners(sub.read(0, rules.PROBE_BYTES), ctx)


def _payload(component, data, kind, ctx, depth, label, here, filename):
    """Scan (and optionally write) data that a container produced."""
    blob = Source(data=data)
    component['payload'] = {'kind': kind, 'size': len(data), 'sha256': sha256_bytes(data)}
    _banners(data[:rules.PROBE_BYTES], ctx)
    if here:
        _write(ctx, os.path.join(here, filename), data, f'{label}/{filename}', component['payload'])
    if depth < ctx.budget.limits['max_depth']:
        component['children'] = [{'name': kind, 'offset': 0, 'size': len(data), 'meta': {}, 'components': scan_blob(blob, ctx, depth + 1, label + '/' + kind, here)}]
    blob.close()


def _banners(data, ctx):
    if ctx.banners['kernel'] is None:
        match = rules.KERNEL_BANNER.search(data)
        if match:
            printable = re.match(rb'Linux version [\x20-\x7e]{1,160}', data[match.start():match.start() + 200])
            ctx.banners['kernel'] = printable.group(0).decode('ascii') if printable else match.group(0).decode('ascii')
    if ctx.banners['busybox'] is None:
        match = rules.BUSYBOX_BANNER.search(data)
        if match:
            ctx.banners['busybox'] = match.group(1).decode('latin1')


def _fit(component, info, window, ctx, depth, label, here):
    result, notes, tree = images.fit_images(window, 0, info)
    component['notes'].extend(notes)
    if result is None:
        component['meta']['kind'] = 'device tree'
        model = tree['props'].get('model')
        component['meta']['model'] = images._str(model) if model else None
        return
    component['meta']['kind'] = 'FIT image'
    component['meta'].update(default=result['default'], description=result['description'], configurations=result['configurations'])
    component['fit'] = []
    for row in result['images']:
        row = dict(row)
        component['fit'].append(row)
        if 'dataOffset' in row and row['dataSize'] and row['dataSize'] <= rules.LIMITS['max_file_bytes']:
            data = window.read(row['dataOffset'], row['dataSize'])
            if len(data) != row['dataSize']:
                row['note'] = 'image data lies beyond the end of the file'
                continue
            row['sha256'] = sha256_bytes(data)
            child = {'name': row['name'], 'offset': row['dataOffset'], 'size': len(data), 'meta': {'type': row['type'], 'compression': row['compression']}, 'components': []}
            component['children'].append(child)
            if depth < ctx.budget.limits['max_depth'] and row['type'] != 'flat_dt':
                child['components'] = scan_blob(Source(data=data), ctx, depth + 1, f'{label}/{row["name"]}', os.path.join(here, safe_relative(row['name'])[0]) if here else None)
            if here:
                _write(ctx, os.path.join(here, safe_relative(row['name'])[0] + '.bin'), data, f'{label}/{row["name"]}', child)
            _banners(data[:rules.PROBE_BYTES], ctx)


class _Iter:
    def __init__(self, factory):
        self.factory, self.notes = factory, []

    def entries(self, max_entries=None):
        yield from self.factory()


# ---- file systems ------------------------------------------------------------------------------------------------------

def _write(ctx, path, data, origin, record=None):
    ctx.budget.take_file(len(data))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as handle:
        handle.write(data)
    row = {'path': os.path.relpath(path, ctx.out_root).replace('\\', '/'), 'size': len(data), 'sha256': sha256_bytes(data), 'origin': origin}
    ctx.written.append(row)
    if record is not None:
        record['extractedTo'] = row['path']


def _filesystem(component, reader, ctx, depth, label, here):
    counts = {'file': 0, 'dir': 0, 'symlink': 0, 'device': 0, 'other': 0}
    total, listing, interesting, executables, nested = 0, [], {}, [], []
    taken = set()
    root = os.path.join(here, 'files') if here else None
    unreadable = 0
    for entry in reader.entries():
        ctx.check()
        kind = entry.kind if entry.kind in counts else 'other'
        counts[kind] += 1
        if len(listing) < rules.LIMITS['max_listing']:
            listing.append(entry.summary())
        for name, pattern in rules.INTERESTING:
            if pattern.search(entry.path):
                interesting.setdefault(name, [])
                if len(interesting[name]) < 25:
                    interesting[name].append(entry.path)
        if entry.kind != 'file':
            continue
        total += entry.size
        data = None
        wants_data = bool(root) or entry.size <= 4 * 1024 * 1024
        if wants_data and entry.size <= rules.LIMITS['max_file_bytes']:
            try:
                data = entry.read(rules.LIMITS['max_file_bytes'])
            except FirmwareError as error:
                unreadable += 1
                ctx.skipped.append({'path': f'{label}:{entry.path}', 'reason': f'{error.code}: {error}'})
        if data is not None:
            if data[:4] == b'\x7fELF' and len(executables) < 100:
                probe = _validate_elf(Source(data=data), 0)
                if probe:
                    executables.append({'path': entry.path, 'size': len(data), **{k: probe['meta'][k] for k in ('bits', 'machine', 'type')}})
            if ctx.banners['busybox'] is None or ctx.banners['kernel'] is None:
                if re.search(r'(^|/)(busybox|vmlinu[xz]|zimage|uimage|kernel[^/]*)$', entry.path, re.I) or entry.size > 512 * 1024 and 'bin' in entry.path:
                    _banners(data[:rules.PROBE_BYTES], ctx)
            if rules.PRIVATE_KEY.search(data[:1 << 20]):
                interesting.setdefault('private-key-material', [])
                if len(interesting['private-key-material']) < 25:
                    interesting['private-key-material'].append(entry.path)
            guess = identify_head(data[:2048]) if len(data) > 16 else None
            if guess and guess not in ('tar',) and depth < ctx.budget.limits['max_depth'] and len(nested) < 50:
                nested.append((entry.path, data))
        if root and data is not None:
            relative, _ = safe_relative(entry.path)
            if relative:
                try:
                    target, shown = unique_path(root, relative, taken)
                    _write(ctx, target, data, f'{label}:{entry.path}', None)
                    ctx.written[-1]['archivePath'] = entry.path
                except FirmwareError as error:
                    ctx.skipped.append({'path': f'{label}:{entry.path}', 'reason': f'{error.code}: {error}'})
    component['filesystem'] = {'files': counts['file'], 'directories': counts['dir'], 'symlinks': counts['symlink'], 'devices': counts['device'], 'other': counts['other'], 'totalFileBytes': total,
                               'listing': listing, 'listingTruncated': sum(counts.values()) > len(listing), 'interesting': interesting, 'executables': executables[:100], 'unreadable': unreadable}
    component['notes'].extend(reader.notes[:20])
    for path, data in nested:
        blob = Source(data=data)
        found = scan_blob(blob, ctx, depth + 1, f'{label}:{path}', os.path.join(here, 'nested', safe_relative(path)[0]) if here else None)
        blob.close()
        if found:
            component['children'].append({'name': path, 'offset': None, 'size': len(data), 'meta': {}, 'components': found})


# ---- driver ------------------------------------------------------------------------------------------------------------

def summarize(components, ctx):
    formats, filesystems, interesting, executables = {}, [], {}, []

    def visit(items):
        for c in items:
            formats[c['format']] = formats.get(c['format'], 0) + 1
            if 'filesystem' in c:
                f = c['filesystem']
                filesystems.append({'format': c['format'], 'files': f['files'], 'bytes': f['totalFileBytes']})
                for key, paths in f['interesting'].items():
                    interesting.setdefault(key, [])
                    interesting[key].extend(paths[: max(0, 25 - len(interesting[key]))])
                executables.extend(f['executables'][: max(0, 100 - len(executables))])
            for child in c['children']:
                visit(child['components'])
    visit(components)
    arch = {}
    for e in executables:
        arch[f"{e['machine']} {e['bits']}-bit"] = arch.get(f"{e['machine']} {e['bits']}-bit", 0) + 1
    return {'formats': formats, 'filesystems': filesystems, 'interesting': interesting, 'executableArchitectures': arch, 'kernelBanner': ctx.banners['kernel'], 'busyboxVersion': ctx.banners['busybox']}


def scan_firmware(path, *, extract_to=None, limits=None, deadline_seconds=300, scan_decompress_bytes=64 * 1024 * 1024):
    """Scan (and with ``extract_to`` unpack) the file at ``path``. Raises FirmwareError for inputs that cannot be processed at all."""
    budget = Budget(limits)
    if not os.path.isfile(path) or os.path.islink(path):
        raise FirmwareError('INPUT', 'the input must be a regular file')
    size = os.path.getsize(path)
    if size == 0 or size > budget.limits['max_input_bytes']:
        raise FirmwareError('INPUT', f'input size {size} is outside 1..{budget.limits["max_input_bytes"]}')
    if extract_to is not None:
        os.makedirs(extract_to, exist_ok=True)
        if os.listdir(extract_to):
            raise FirmwareError('OUTPUT_NOT_EMPTY', 'the extraction directory must be empty')
    ctx = Context(budget, time.monotonic() + deadline_seconds, extract_to, scan_decompress_bytes)
    src = Source(path=path)
    try:
        digest = src.sha256()
        try:
            components = scan_blob(src, ctx, 0, '', extract_to)
        except FirmwareError as error:
            if error.code != 'DEADLINE':
                raise
            components = []
            ctx.limits_hit.add('deadline')
        report = {'schema': SCHEMA, 'file': {'path': os.path.abspath(path), 'size': size, 'sha256': digest}, 'components': components, 'summary': summarize(components, ctx),
                  'extraction': None if extract_to is None else {'root': os.path.abspath(extract_to), 'files': len(ctx.written), 'bytes': ctx.budget.bytes, 'items': ctx.written[:2000], 'itemsTruncated': len(ctx.written) > 2000, 'skipped': ctx.skipped[:200]},
                  'limitsHit': sorted(ctx.limits_hit), 'components_total': ctx.budget.components,
                  'notRun': ['execution of any extracted content', 'JFFS2 / UBIFS / CramFS / ROMFS content extraction (identified only)', 'zstd / LZ4 / LZO decompression (no decoder available)', 'signature or secure-boot verification',
                             'recovery of deleted or unreferenced data'],
                  'note': 'Components are validated by their own headers; a component may still be a coincidence. Extraction writes sanitized names only: no links, devices or absolute paths are created.'}
        return report
    finally:
        src.close()
