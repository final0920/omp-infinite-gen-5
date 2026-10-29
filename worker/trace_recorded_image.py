"""Sparse recorded native bytes for OFFLINE semantics; never rebuilds a PE file."""
import hashlib
import os
from pathlib import Path
import re
import struct


class NativeSnapshot:
    def __init__(self, snapshot, target_sha256, runtime_base):
        if not isinstance(snapshot, dict) or snapshot.get('schema') != 'ig5.native-main-image.v1' or snapshot.get('targetSha256') != target_sha256:
            raise ValueError('Native loaded-image identity differs')
        if not isinstance(snapshot.get('runtimeBase'), str) or not re.fullmatch(r'0x[0-9a-fA-F]{1,16}', snapshot['runtimeBase']) or int(snapshot['runtimeBase'], 16) != runtime_base:
            raise ValueError('Native loaded-image identity/runtime base differs')
        if not isinstance(snapshot.get('sha256'), str) or not re.fullmatch(r'[0-9a-f]{64}', snapshot['sha256']):
            raise ValueError('Native loaded-image digest differs')
        filename = Path(snapshot['path'])
        if filename.is_symlink() or not filename.is_file() or filename.stat().st_size > 8 * 1024 * 1024:
            raise ValueError('Native image blob is linked/oversized')
        with filename.open('rb') as stream:
            self.data = stream.read(8 * 1024 * 1024 + 1)
        if isinstance(snapshot.get('bytes'), bool) or not isinstance(snapshot.get('bytes'), int) or not 1 <= snapshot['bytes'] <= 8 * 1024 * 1024 or len(self.data) != snapshot['bytes'] or hashlib.sha256(self.data).hexdigest() != snapshot['sha256']:
            raise ValueError('Native loaded-image digest differs')
        regions, module_size = snapshot.get('regions'), snapshot.get('moduleSize')
        if not isinstance(regions, list) or not 1 <= len(regions) <= 2048 or isinstance(module_size, bool) or not isinstance(module_size, int) or not 1 <= module_size <= 8 * 1024 * 1024 or runtime_base + module_size > 1 << 64:
            raise ValueError('Native image mapping budget differs')
        prior, consumed = 0, 0
        self.regions = []
        for region in regions:
            if not isinstance(region, dict) or not isinstance(region.get('rva'), str) or not re.fullmatch(r'0x[0-9a-fA-F]{1,16}', region['rva']):
                raise ValueError('Native image regions require explicit bounded hexadecimal RVAs')
            offset, size, blob_offset = int(region['rva'], 16), region.get('bytes'), region.get('blobOffset')
            if isinstance(size, bool) or not isinstance(size, int) or size < 1 or isinstance(blob_offset, bool) or not isinstance(blob_offset, int) or offset < prior or offset + size > module_size or blob_offset != consumed:
                raise ValueError('Native image regions overlap/escape or have missing blob bytes')
            self.regions.append((offset, size, blob_offset)); prior = offset + size; consumed += size
        if consumed != len(self.data): raise ValueError('Native image mapping does not cover its blob')
        self.module_size = module_size

    def read_rva(self, offset, size):
        if not isinstance(offset, int) or not isinstance(size, int) or offset < 0 or size < 1 or offset + size > self.module_size:
            raise ValueError('Recorded instruction falls outside captured native image bytes')
        parts, cursor, remaining = [], offset, size
        for start, count, blob_offset in self.regions:
            if start <= cursor < start + count:
                take = min(remaining, start + count - cursor)
                at = blob_offset + cursor - start
                parts.append(self.data[at:at + take]); cursor += take; remaining -= take
                if not remaining: return b''.join(parts)
            elif start > cursor: break
        raise ValueError('Recorded instruction falls outside captured native image bytes')

    def pe64_header(self):
        dos = self.read_rva(0, 64)
        if dos[:2] != b'MZ': raise ValueError('Recorded image lacks a readable PE64 header')
        offset = struct.unpack_from('<I', dos, 0x3c)[0]
        if not 64 <= offset <= min(self.module_size - 136, 1024 * 1024):
            raise ValueError('Recorded PE header offset is outside its budget')
        header = self.read_rva(offset, 136)
        machine, sections, optional_size = struct.unpack_from('<HH12xH', header, 4)
        if header[:4] != b'PE\0\0' or machine != 0x8664 or not 1 <= sections <= 256 or optional_size < 112 or struct.unpack_from('<H', header, 24)[0] != 0x20b:
            raise ValueError('Recorded image requires a readable AMD64 PE32+ header')
        image_base = struct.unpack_from('<Q', header, 48)[0]
        if struct.unpack_from('<I', header, 80)[0] != self.module_size:
            raise ValueError('Recorded PE SizeOfImage differs from captured module')
        return {'imageBase': hex(image_base), 'machine': 'AMD64', 'format': 'PE32+'}


class RecordedImageIdentity:
    """Only a captured target identity and RVA coordinate origin, not a file."""
    format, architecture, bits = 'PE', 'x86', 64
    imagebase = 0  # RVA coordinate origin; never reported as a preferred PE base.
    original_file_available = False

    def __init__(self, snapshot, target_sha256, target):
        if not isinstance(target_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', target_sha256):
            raise ValueError('Recorded target requires an explicit SHA-256')
        self.recorded_target_path = target
        self.validate_snapshot_target(snapshot)
        self.sha256 = target_sha256
        self.snapshot = NativeSnapshot(snapshot, target_sha256, int(snapshot['runtimeBase'], 16))
        self.recorded_header = self.snapshot.pe64_header()

    def validate_snapshot_target(self, snapshot):
        target = self.recorded_target_path
        recorded = snapshot.get('recordedTargetPath') if isinstance(snapshot, dict) else None
        if not isinstance(target, str) or not os.path.isabs(target) or not isinstance(recorded, str) or not os.path.isabs(recorded) or os.path.normcase(os.path.normpath(recorded)) != os.path.normcase(os.path.normpath(target)):
            raise ValueError('Recorded target path identity differs')

    def read(self, address, size):
        raise ValueError('Original PE file is not read in explicit recorded-image-only mode')
