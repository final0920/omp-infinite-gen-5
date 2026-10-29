"""Pinned-file -> declared PE loaded image byte binding; never patches a file.

Only documented ABSOLUTE padding and AMD64 DIR64 relocations are modeled.
Unknown types, overlapping fixups, malformed blocks and unbacked targets reject.
The ordinary BinaryImage loader remains an unrelocated preferred-address view.
"""
import struct
from trace_recorded_image import NativeSnapshot


class TraceByteBinding:
    def __init__(self, image, runtime_base, snapshot=None):
        self.image, self.patches, self.evidence = image, {}, []
        self.snapshot = snapshot
        if snapshot is not None:
            if image.format != 'PE' or image.bits != 64:
                raise ValueError('Native loaded-image identity differs')
            if not getattr(image, 'original_file_available', True): image.validate_snapshot_target(snapshot)
            self.snapshot_view = NativeSnapshot(snapshot, image.sha256, runtime_base)
            self.snapshot_data, self.snapshot_regions = self.snapshot_view.data, self.snapshot_view.regions
            self.recorded_header = self.snapshot_view.pe64_header() if not getattr(image, 'original_file_available', True) else None
            return
        if not getattr(image, 'original_file_available', True):
            raise ValueError('Recorded-image-only semantics require an image for every path')
        self.delta = runtime_base - image.imagebase
        if image.format != 'PE' or image.bits != 64 or not self.delta: return
        directory = next((row for row in image.data_directories if row['index'] == 5), None)
        if not directory or not directory['size']: return
        if directory['size'] > 1024 * 1024: raise ValueError('PE trace relocation directory exceeds 1 MiB')
        data = image.read(image.imagebase + int(directory['pointer'], 16), directory['size'])
        offset, entries = 0, 0
        while offset < len(data):
            if offset + 8 > len(data): raise ValueError('Incomplete PE relocation block')
            page, size = struct.unpack_from('<II', data, offset)
            if page % 4096 or size < 8 or size % 4 or size > len(data) - offset: raise ValueError('Malformed PE relocation block')
            for at in range(offset + 8, offset + size, 2):
                entry = struct.unpack_from('<H', data, at)[0]; kind, within = entry >> 12, entry & 0xfff
                if kind == 0: continue
                if kind != 10: raise ValueError('Unsupported AMD64 trace relocation type ' + str(kind))
                entries += 1
                if entries > 65536: raise ValueError('PE trace relocation count exceeds budget')
                address = image.imagebase + page + within
                original = image.read(address, 8)
                relocated = ((int.from_bytes(original, 'little') + self.delta) & ((1 << 64) - 1)).to_bytes(8, 'little')
                if any(address + n in self.patches for n in range(8)): raise ValueError('Overlapping PE relocation fixups')
                self.patches.update((address + n, value) for n, value in enumerate(relocated))
                self.evidence.append({'rva': hex(page + within), 'type': 'IMAGE_REL_BASED_DIR64', 'original': original.hex(), 'relocated': relocated.hex()})
            offset += size

    def read(self, address, size):
        if self.snapshot is not None:
            try: original = self.image.read(address, size)
            except ValueError: original = None
            return original, self.snapshot_view.read_rva(address - self.image.imagebase, size)
        original = self.image.read(address, size)
        expected = bytes(self.patches.get(address + n, value) for n, value in enumerate(original))
        return original, expected

    def fixups_at(self, address, size):
        if self.snapshot is not None: return []
        return [row for row in self.evidence if self.image.imagebase + int(row['rva'], 16) < address + size and self.image.imagebase + int(row['rva'], 16) + 8 > address]
