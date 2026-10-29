"""Bounded PE import-table reader for API tracing.

This reads static bytes only. It never launches the target, resolves an export, or
writes a database. A parsed import is a *file* fact: the runtime IAT slot may still
be zero, forwarded, hooked or otherwise different, so the caller must read the IAT
at the current debugger pause and keep unresolved slots explicitly unknown.
"""
from __future__ import annotations

import struct
from pathlib import Path

MAX_HEADER = 0x10000
MAX_SECTIONS = 96
MAX_DESCRIPTORS = 4096
MAX_IMPORTS = 16384
MAX_IMPORTS_PER_DLL = 4096
MAX_DLL_NAME = 256
MAX_API_NAME = 512
MAX_TABLE_BYTES = 256 * 1024


class ImportParseError(ValueError):
    """The file is not a usable PE image or an import table is out of bounds."""


class _Reader:
    def __init__(self, path):
        self.path = Path(path).expanduser().resolve(strict=True)
        self.size = self.path.stat().st_size
        if self.size < 0x40 or self.size > 512 * 1024 * 1024:
            raise ImportParseError("PE import scan requires a regular file of 64 bytes..512 MiB")
        self.file = self.path.open("rb")

    def close(self):
        self.file.close()

    def read(self, offset, count):
        if offset < 0 or count < 0 or offset + count > self.size:
            raise ImportParseError("PE read is outside the file")
        self.file.seek(offset)
        data = self.file.read(count)
        if len(data) != count:
            raise ImportParseError("PE read was incomplete")
        return data

    def u16(self, offset):
        return struct.unpack_from("<H", self.read(offset, 2))[0]

    def u32(self, offset):
        return struct.unpack_from("<I", self.read(offset, 4))[0]

    def u64(self, offset):
        return struct.unpack_from("<Q", self.read(offset, 8))[0]


def _decode_name(data):
    end = data.find(b"\x00")
    if end < 0:
        raise ImportParseError("import name is not NUL terminated")
    name = data[:end]
    if not name or len(name) > MAX_API_NAME:
        raise ImportParseError("import name is empty or too long")
    try:
        return name.decode("ascii")
    except UnicodeDecodeError as error:
        raise ImportParseError("import name is not ASCII") from error


def _sections(reader, file_header, optional_size, count):
    if count < 1 or count > MAX_SECTIONS:
        raise ImportParseError("PE section count is outside 1..%d" % MAX_SECTIONS)
    # ``file_header`` is the PE-signature offset; the optional header follows the
    # 4-byte signature plus the 20-byte COFF header.
    table = file_header + 24 + optional_size
    reader.read(table, count * 40)
    rows = []
    for index in range(count):
        offset = table + index * 40
        raw = reader.read(offset, 40)
        name = raw[:8].split(b"\x00", 1)[0].decode("ascii", "replace")
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<IIII", raw, 8)
        rows.append({"name": name, "virtualSize": virtual_size, "virtualAddress": virtual_address,
                     "rawSize": raw_size, "rawPointer": raw_pointer})
    return rows


def _rva_offset(rva, sections):
    for section in sections:
        span = max(section["virtualSize"], section["rawSize"])
        if section["virtualAddress"] <= rva < section["virtualAddress"] + span:
            delta = rva - section["virtualAddress"]
            if delta >= section["rawSize"]:
                raise ImportParseError("RVA points into an unbacked part of a section")
            return section["rawPointer"] + delta
    raise ImportParseError("RVA is not inside a raw-backed section")


def _read_at_rva(reader, rva, count, sections, limits):
    offset = _rva_offset(rva, sections)
    limits[0] += count
    if limits[0] > MAX_TABLE_BYTES:
        raise ImportParseError("PE import tables exceed the 256 KiB parse budget")
    return reader.read(offset, count)


def _descriptor(reader, offset):
    raw = reader.read(offset, 20)
    original, stamp, chain, name_rva, first_thunk = struct.unpack("<IIIII", raw)
    return {"originalFirstThunk": original, "timeDateStamp": stamp, "forwarderChain": chain,
            "nameRva": name_rva, "firstThunk": first_thunk}


def _read_thunk(reader, rva, bits, sections, limits):
    width = 8 if bits == 64 else 4
    raw = _read_at_rva(reader, rva, width, sections, limits)
    return struct.unpack("<Q" if bits == 64 else "<I", raw)[0]


def parse_imports(path):
    """Return a bounded description of the PE import table.

    ``imports`` entries contain ``module``, ``name`` (or ``ordinal`` as ``#N``),
    ``byOrdinal``, ``iatRva`` and ``originalThunkRva``. Ordinals are kept so a
    caller can request them; they have no taxonomy category by themselves.
    """
    reader = _Reader(path)
    try:
        if reader.read(0, 2) != b"MZ":
            raise ImportParseError("target is not a PE executable (missing MZ)")
        pe_offset = reader.u32(0x3C)
        if pe_offset < 0x40 or pe_offset > MAX_HEADER or pe_offset + 24 > reader.size:
            raise ImportParseError("PE header offset is outside the bounded header window")
        if reader.read(pe_offset, 4) != b"PE\x00\x00":
            raise ImportParseError("target is not a PE executable (missing PE signature)")
        machine, section_count, _, _, _, optional_size, characteristics = struct.unpack(
            "<HHIIIHH", reader.read(pe_offset + 4, 20))
        if machine not in (0x14c, 0x8664):
            raise ImportParseError("only x86 and x64 PE images are supported")
        if optional_size < 0xE0 or optional_size > 0xF0:
            raise ImportParseError("unexpected PE optional header size")
        optional = pe_offset + 24
        magic = reader.u16(optional)
        bits = 64 if machine == 0x8664 and magic == 0x20B else 32 if machine == 0x14C and magic == 0x10B else 0
        if not bits:
            raise ImportParseError("PE machine/optional-header magic disagree")
        if bits == 64:
            image_base = reader.u64(optional + 24)
            size_of_image = reader.u32(optional + 56)
            data_dir = optional + 112
        else:
            image_base = reader.u32(optional + 28)
            size_of_image = reader.u32(optional + 56)
            data_dir = optional + 96
        if size_of_image < 0x1000 or size_of_image > 1 << 31:
            raise ImportParseError("PE SizeOfImage is outside the supported range")
        directory_count = reader.u32(data_dir - 4)
        if directory_count < 2:
            raise ImportParseError("PE has no import data directory")
        import_rva, import_size = struct.unpack_from("<II", reader.read(data_dir + 8, 8))
        delay_rva, delay_size = (struct.unpack_from("<II", reader.read(data_dir + 8 * 13, 8))
                                 if directory_count > 13 else (0, 0))
        sections = _sections(reader, pe_offset, optional_size, section_count)
        limits = [0]
        imports, modules, truncated, warnings = [], [], False, []
        if not import_rva:
            return {"schema": "ig5.pe-imports.v1", "path": str(reader.path), "bits": bits, "machine": machine,
                    "imageBase": image_base, "sizeOfImage": size_of_image, "sections": sections,
                    "imports": [], "modules": [], "importDirectoryRva": 0, "importDirectorySize": import_size,
                    "delayImportDirectoryRva": delay_rva, "delayImportDirectorySize": delay_size,
                    "truncated": False, "warnings": (["no import directory"] if import_size else []),
                    "scope": "static PE import-table bytes; runtime IAT resolution is not implied"}
        descriptor_bytes = min(import_size or MAX_DESCRIPTORS * 20, MAX_DESCRIPTORS * 20)
        descriptor_bytes = max(20, descriptor_bytes - descriptor_bytes % 20)
        descriptors = []
        for index in range(descriptor_bytes // 20):
            row = _descriptor(reader, _rva_offset(import_rva + index * 20, sections))
            if not any(row.values()):
                break
            descriptors.append(row)
        else:
            truncated = True
            warnings.append("import descriptor table reached its %d-entry cap" % MAX_DESCRIPTORS)
        if len(descriptors) > MAX_DESCRIPTORS:
            raise ImportParseError("too many import descriptors")
        total = 0
        for descriptor in descriptors:
            name_offset = _rva_offset(descriptor["nameRva"], sections)
            module = _decode_name(reader.read(name_offset, MAX_DLL_NAME + 1))
            if len(module) > MAX_DLL_NAME or not module.isprintable():
                raise ImportParseError("import DLL name is invalid")
            modules.append(module)
            original = descriptor["originalFirstThunk"] or descriptor["firstThunk"]
            width = 8 if bits == 64 else 4
            ordinal_flag = 1 << (bits - 1)
            count = 0
            while count < MAX_IMPORTS_PER_DLL:
                thunk = _read_thunk(reader, original + count * width, bits, sections, limits)
                if not thunk:
                    break
                iat_rva = descriptor["firstThunk"] + count * width
                if thunk & ordinal_flag:
                    imports.append({"module": module, "name": "#%d" % (thunk & 0xFFFF), "ordinal": thunk & 0xFFFF,
                                    "byOrdinal": True, "iatRva": iat_rva, "originalThunkRva": original + count * width})
                else:
                    hint_name = _read_at_rva(reader, thunk, 2, sections, limits)
                    hint = struct.unpack("<H", hint_name)[0]
                    name_bytes = reader.read(_rva_offset(thunk + 2, sections), MAX_API_NAME + 1)
                    imports.append({"module": module, "name": _decode_name(name_bytes), "ordinal": None,
                                    "hint": hint, "byOrdinal": False, "iatRva": iat_rva,
                                    "originalThunkRva": original + count * width})
                total += 1
                count += 1
                if total >= MAX_IMPORTS:
                    truncated = True
                    warnings.append("import table reached its %d-entry cap" % MAX_IMPORTS)
                    break
            else:
                truncated = True
                warnings.append("DLL %s reached its %d-entry thunk cap" % (module, MAX_IMPORTS_PER_DLL))
            if total >= MAX_IMPORTS:
                break
        return {"schema": "ig5.pe-imports.v1", "path": str(reader.path), "bits": bits, "machine": machine,
                "imageBase": image_base, "sizeOfImage": size_of_image, "sections": sections,
                "imports": imports, "modules": modules, "importDirectoryRva": import_rva,
                "importDirectorySize": import_size, "delayImportDirectoryRva": delay_rva,
                "delayImportDirectorySize": delay_size, "truncated": truncated, "warnings": warnings,
                "scope": "static PE import-table bytes; runtime IAT resolution is not implied"}
    finally:
        reader.close()
