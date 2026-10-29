"""Shared plumbing for the firmware front end: bounded readers, bounded decompression, safe output names, budgets.

Nothing here executes content. Decompression is incremental with an output ceiling and a ratio ceiling, so a small
stream cannot expand into memory; output names are reduced to single safe path components so an archive entry cannot
write outside the extraction directory.
"""
import bz2
import hashlib
import lzma
import mmap
import os
import re
import zlib

import firmware_rules as rules


class FirmwareError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class Budget:
    """Counts what extraction has produced so far; raises when a ceiling is crossed."""

    def __init__(self, limits=None):
        self.limits = {**rules.LIMITS, **(limits or {})}
        self.bytes = self.files = self.components = 0
        self.notes = []

    def take_file(self, size):
        if size > self.limits['max_file_bytes']:
            raise FirmwareError('FILE_TOO_LARGE', f'a file of {size} bytes exceeds the {self.limits["max_file_bytes"]} byte limit')
        if self.files + 1 > self.limits['max_files']:
            raise FirmwareError('TOO_MANY_FILES', f'more than {self.limits["max_files"]} files')
        if self.bytes + size > self.limits['max_total_extract_bytes']:
            raise FirmwareError('EXTRACT_LIMIT', f'extraction would exceed {self.limits["max_total_extract_bytes"]} bytes')
        self.files += 1
        self.bytes += size

    def take_component(self):
        if self.components + 1 > self.limits['max_components']:
            raise FirmwareError('TOO_MANY_COMPONENTS', f'more than {self.limits["max_components"]} components')
        self.components += 1


class Source:
    """Random-access read-only view of bytes, a file, or a window onto another Source."""

    def __init__(self, data=None, path=None, parent=None, start=0, length=None):
        self._map = self._handle = self._data = None
        self.parent, self.start = parent, start
        if parent is not None:
            self.size = parent.size - start if length is None else min(length, parent.size - start)
        elif path is not None:
            self._handle = open(path, 'rb')
            self.size = os.fstat(self._handle.fileno()).st_size
            if self.size:
                self._map = mmap.mmap(self._handle.fileno(), 0, access=mmap.ACCESS_READ)
        else:
            self._data = bytes(data)
            self.size = len(self._data)

    def read(self, offset, length):
        if offset < 0 or length <= 0 or offset >= self.size:
            return b''
        length = min(length, self.size - offset)
        if self.parent is not None:
            return self.parent.read(self.start + offset, length)
        if self._map is not None:
            return self._map[offset:offset + length]
        return self._data[offset:offset + length]

    def find(self, needle, start=0, end=None):
        end = self.size if end is None else min(end, self.size)
        if start >= end:
            return -1
        if self.parent is not None:
            found = self.parent.find(needle, self.start + start, self.start + end)
            return found - self.start if found >= 0 else -1
        if self._map is not None:
            return self._map.find(needle, start, end)
        return self._data.find(needle, start, end)

    def window(self, start, length=None):
        return Source(parent=self, start=start, length=length)

    def sha256(self, start=0, length=None):
        hasher = hashlib.sha256()
        end = self.size if length is None else min(self.size, start + length)
        for offset in range(start, end, 1 << 20):
            hasher.update(self.read(offset, min(1 << 20, end - offset)))
        return hasher.hexdigest()

    def close(self):
        if self._map is not None:
            self._map.close()
        if self._handle is not None:
            self._handle.close()


# ---- bounded decompression --------------------------------------------------------------------------------------------

def _decompressor(kind):
    if kind == 'gzip':
        return zlib.decompressobj(wbits=31)
    if kind == 'zlib':
        return zlib.decompressobj(wbits=15)
    if kind == 'raw-deflate':
        return zlib.decompressobj(wbits=-15)
    if kind == 'bzip2':
        return bz2.BZ2Decompressor()
    if kind == 'xz':
        return lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
    if kind == 'lzma':
        return lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
    raise FirmwareError('UNSUPPORTED_CODEC', f'no decoder for {kind}')


def inflate(src, offset, kind, max_out, max_ratio=None, max_in=None):
    """Decompress ``kind`` data starting at ``offset``. Returns (bytes, consumed, status).

    status: ``complete`` (stream ended), ``truncated`` (valid so far, input ran out), ``limit`` (output ceiling hit),
    ``bomb`` (ratio ceiling hit), ``error`` (invalid data; whatever decoded before the error is still returned).
    """
    max_ratio = max_ratio or rules.LIMITS['max_ratio']
    engine = _decompressor(kind)
    zlib_like = kind in ('gzip', 'zlib', 'raw-deflate')
    end = src.size if max_in is None else min(src.size, offset + max_in)
    out, produced, fed, cursor, pending = [], 0, 0, offset, b''
    try:
        while True:
            data = engine.decompress(pending, max_out - produced + 1)
            pending = engine.unconsumed_tail if zlib_like else b''
            if data:
                out.append(data)
                produced += len(data)
            if produced > max_out:
                return b''.join(out)[:max_out], fed, 'limit'
            if engine.eof:
                return b''.join(out), fed - len(engine.unused_data), 'complete'
            if produced > max_ratio * max(fed, 1) + (1 << 20):
                return b''.join(out), fed, 'bomb'
            if pending or (not zlib_like and engine.needs_input is False):
                continue                                     # output ceiling of this round was hit; drain what is buffered
            if cursor >= end:
                return b''.join(out), fed, 'truncated'
            pending = src.read(cursor, min(1 << 16, end - cursor))
            if not pending:
                return b''.join(out), fed, 'truncated'
            cursor += len(pending)
            fed += len(pending)
    except (zlib.error, OSError, EOFError, lzma.LZMAError, ValueError):
        return b''.join(out), fed, 'error'


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


# ---- output names ------------------------------------------------------------------------------------------------------

_RESERVED = re.compile(r'^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$', re.I)
_UNSAFE = re.compile(r'[\x00-\x1f<>:"|?*\\]')


def safe_component(name):
    """One archive path element reduced to a name that is safe on Windows and POSIX; '' means "skip this element"."""
    name = _UNSAFE.sub('_', name).strip(' .')
    if name in ('', '.', '..'):
        return ''
    if _RESERVED.match(name):
        name = '_' + name
    if len(name) > 120:
        name = name[:105] + '~' + hashlib.sha256(name.encode('utf-8', 'surrogatepass')).hexdigest()[:10]
    return name


def safe_relative(path):
    """Archive path -> (relative path of safe elements joined with '/', changed flag). Never absolute, never escaping."""
    parts = [safe_component(p) for p in re.split(r'[/\\]+', path.replace('\x00', ''))]
    kept = [p for p in parts if p]
    result = '/'.join(kept)
    limit = rules.LIMITS['max_path_chars']
    if len(result) > limit:
        digest = hashlib.sha256(result.encode('utf-8', 'surrogatepass')).hexdigest()[:12]
        result = result[:limit - 14] + '~' + digest
    return result, result != path.lstrip('/')


def unique_path(root, relative, taken):
    """Return a path under ``root`` for ``relative`` that no earlier entry used (case-insensitively), recording it in ``taken``."""
    candidate, n = relative, 0
    while candidate.lower() in taken:
        n += 1
        stem, dot, ext = relative.rpartition('.')
        candidate = f'{stem}~{n}.{ext}' if dot and stem else f'{relative}~{n}'
    taken.add(candidate.lower())
    full = os.path.normpath(os.path.join(root, *candidate.split('/')))
    root_norm = os.path.normpath(root)
    if os.path.commonpath([full, root_norm]) != root_norm:
        raise FirmwareError('PATH_ESCAPE', 'a computed output path left the extraction directory')
    return full, candidate
