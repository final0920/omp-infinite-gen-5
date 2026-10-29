"""Verify and hold read-only capabilities to the local pinned analysis runtime."""
import ctypes as C
from ctypes import wintypes as W
from contextlib import contextmanager, ExitStack
import hashlib
import json
import os
from pathlib import Path

MANIFEST_SHA256 = '1d63bc53c0a0f49e99163768d716727a4ea02056b4617165c18db20e21b28485'
LIFTER_SHA256 = '32806e249c5fdfa64d673c8fb403d6c3dd4ad6a51b5f19c9154b8d6f236fa0c6'


@contextmanager
def locked_file(path, maximum):
    """Deny concurrent writes/deletes until the native reader has exited."""
    import msvcrt
    path = Path(path)
    if (not path.is_absolute() or str(path.resolve(strict=True)).casefold() != str(path).casefold()
            or not path.is_file() or path.is_symlink()):
        raise ValueError('Lifter input must be a physical regular file')
    k = C.WinDLL('kernel32', use_last_error=True)
    k.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, C.c_void_p, W.DWORD, W.DWORD, W.HANDLE]
    k.CreateFileW.restype = W.HANDLE
    k.CloseHandle.argtypes = [W.HANDLE]; k.CloseHandle.restype = W.BOOL
    handle = k.CreateFileW(str(path), 0x80000000, 1, None, 3, 0x00200000, None)
    if handle == C.c_void_p(-1).value:
        raise C.WinError(C.get_last_error())
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except Exception:
        k.CloseHandle(handle); raise
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if before.st_size > maximum: raise ValueError('Lifter input exceeds byte budget')
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno()); current = path.stat()
        keys = ('st_dev','st_ino','st_size','st_mtime_ns')
        if (len(data) != before.st_size or any(getattr(before,key) != getattr(after,key) or
                getattr(before,key) != getattr(current,key) for key in keys)):
            raise ValueError('Lifter input changed during verification')
        yield data


@contextmanager
def runtime():
    root = Path(__file__).resolve().parents[1] / 'runtimes' / 'mergen'
    with ExitStack() as held:
        raw = held.enter_context(locked_file(root/'manifest.json', 64*1024))
        if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256: raise ValueError('Mergen runtime manifest pin mismatch')
        manifest = json.loads(raw)
        rows = manifest.get('files')
        if not isinstance(rows,list) or not 4 <= len(rows) <= 32: raise ValueError('Invalid Mergen runtime inventory')
        names = set()
        for row in rows:
            name = row['path']
            if (not isinstance(name,str) or name in names or '/' in name or '\\' in name or
                    name in ('.','..') or not name or ':' in name): raise ValueError('Invalid Mergen runtime file')
            names.add(name)
            data = held.enter_context(locked_file(root/name, 32*1024**2))
            if len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256']:
                raise ValueError('Mergen runtime file pin mismatch: '+name)
            if name == 'lifter.exe' and row['sha256'] != LIFTER_SHA256: raise ValueError('Mergen executable pin mismatch')
        if {p.name for p in root.iterdir()} != names | {'manifest.json'}:
            raise ValueError('Unexpected file in pinned Mergen runtime')
        yield root/'lifter.exe'
