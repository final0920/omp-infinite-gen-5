"""Firmware container knowledge as data: signatures, budgets, and the file names worth listing.

A signature is only a place to LOOK. Every candidate is validated by a parser in ``firmware_formats`` (header fields,
sizes, checksums where the format has them) before it becomes a component, so random data that happens to contain
``1f 8b 08`` does not turn into a "gzip stream". ``validate()`` runs at import and fails the first test run on a typo.
"""
import re

# ---- budgets ---------------------------------------------------------------------------------------------------------
LIMITS = {
    'max_input_bytes': 1024 * 1024 * 1024,      # larger images are refused rather than half-read
    'max_matches_per_signature': 4000,          # random data produces short-magic hits; stop collecting
    'max_components': 5000,                     # per scan, all levels
    'max_depth': 4,                             # container -> payload -> filesystem -> archive ...
    'max_total_extract_bytes': 1024 * 1024 * 1024,
    'max_file_bytes': 256 * 1024 * 1024,
    'max_files': 50000,
    'max_ratio': 1500,                          # decompressed / compressed; above this a stream is treated as a bomb
    'max_path_chars': 240,
    'max_listing': 2000,                        # file entries kept per filesystem in the report (extraction is not limited by this)
    'validate_bytes': 1024 * 1024,              # how much a weak signature may decompress to prove itself
}

# ---- signatures ------------------------------------------------------------------------------------------------------
# magic: bytes found in the file; offset: where the magic sits inside its component (component start = hit - offset)
# category: compression | filesystem | image | archive | executable | table | text
SIGNATURES = [
    {'id': 'gzip', 'name': 'gzip stream', 'magic': b'\x1f\x8b\x08', 'offset': 0, 'category': 'compression'},
    {'id': 'bzip2', 'name': 'bzip2 stream', 'magic': b'BZh', 'offset': 0, 'category': 'compression'},
    {'id': 'xz', 'name': 'xz stream', 'magic': b'\xfd7zXZ\x00', 'offset': 0, 'category': 'compression'},
    {'id': 'lzma', 'name': 'LZMA (alone) stream', 'magic': b'\x5d\x00\x00', 'offset': 0, 'category': 'compression'},
    {'id': 'zlib', 'name': 'zlib stream', 'magic': b'\x78\x9c', 'offset': 0, 'category': 'compression'},
    {'id': 'zlib', 'name': 'zlib stream', 'magic': b'\x78\xda', 'offset': 0, 'category': 'compression'},
    {'id': 'zlib', 'name': 'zlib stream', 'magic': b'\x78\x01', 'offset': 0, 'category': 'compression'},
    {'id': 'zstd', 'name': 'Zstandard frame', 'magic': b'\x28\xb5\x2f\xfd', 'offset': 0, 'category': 'compression'},
    {'id': 'lz4', 'name': 'LZ4 frame', 'magic': b'\x04\x22\x4d\x18', 'offset': 0, 'category': 'compression'},
    {'id': 'zip', 'name': 'ZIP archive', 'magic': b'PK\x03\x04', 'offset': 0, 'category': 'archive'},
    {'id': 'tar', 'name': 'tar archive', 'magic': b'ustar', 'offset': 257, 'category': 'archive'},
    {'id': 'cpio', 'name': 'cpio archive (newc)', 'magic': b'070701', 'offset': 0, 'category': 'archive'},
    {'id': 'cpio', 'name': 'cpio archive (newc, CRC)', 'magic': b'070702', 'offset': 0, 'category': 'archive'},
    {'id': 'squashfs', 'name': 'SquashFS (little endian)', 'magic': b'hsqs', 'offset': 0, 'category': 'filesystem'},
    {'id': 'squashfs', 'name': 'SquashFS (big endian)', 'magic': b'sqsh', 'offset': 0, 'category': 'filesystem', 'variant': 'be'},
    {'id': 'ext', 'name': 'ext2/3/4 filesystem', 'magic': b'\x53\xef', 'offset': 1080, 'category': 'filesystem'},
    {'id': 'cramfs', 'name': 'CramFS', 'magic': b'\x45\x3d\xcd\x28', 'offset': 0, 'category': 'filesystem'},
    {'id': 'romfs', 'name': 'ROMFS', 'magic': b'-rom1fs-', 'offset': 0, 'category': 'filesystem'},
    {'id': 'jffs2', 'name': 'JFFS2 filesystem', 'magic': b'\x85\x19', 'offset': 0, 'category': 'filesystem'},
    {'id': 'ubi', 'name': 'UBI volume image', 'magic': b'UBI#', 'offset': 0, 'category': 'filesystem'},
    {'id': 'ubifs', 'name': 'UBIFS', 'magic': b'\x31\x18\x10\x06', 'offset': 0, 'category': 'filesystem'},
    {'id': 'uimage', 'name': 'U-Boot legacy image', 'magic': b'\x27\x05\x19\x56', 'offset': 0, 'category': 'image'},
    {'id': 'fdt', 'name': 'Flattened device tree / FIT image', 'magic': b'\xd0\x0d\xfe\xed', 'offset': 0, 'category': 'image'},
    {'id': 'android-boot', 'name': 'Android boot image', 'magic': b'ANDROID!', 'offset': 0, 'category': 'image'},
    {'id': 'android-sparse', 'name': 'Android sparse image', 'magic': b'\x3a\xff\x26\xed', 'offset': 0, 'category': 'image'},
    {'id': 'android-payload', 'name': 'Android OTA payload', 'magic': b'CrAU', 'offset': 0, 'category': 'image'},
    {'id': 'trx', 'name': 'Broadcom TRX image', 'magic': b'HDR0', 'offset': 0, 'category': 'image'},
    {'id': 'elf', 'name': 'ELF executable or library', 'magic': b'\x7fELF', 'offset': 0, 'category': 'executable'},
    {'id': 'pe', 'name': 'Windows PE image', 'magic': b'MZ', 'offset': 0, 'category': 'executable'},
    {'id': 'ihex', 'name': 'Intel HEX', 'magic': b':', 'offset': 0, 'category': 'text', 'start_only': True},
    {'id': 'srec', 'name': 'Motorola S-record', 'magic': b'S0', 'offset': 0, 'category': 'text', 'start_only': True},
]

# Formats this tool can open, and what it does with them.  list: report the file table; extract: write the contents out.
CAPABILITIES = {
    'gzip': ('extract',), 'bzip2': ('extract',), 'xz': ('extract',), 'lzma': ('extract',), 'zlib': ('extract',), 'zip': ('list', 'extract'), 'tar': ('list', 'extract'),
    'cpio': ('list', 'extract'), 'squashfs': ('list', 'extract'), 'ext': ('list', 'extract'), 'uimage': ('extract',), 'fdt': ('list', 'extract'), 'android-boot': ('extract',),
    'android-sparse': ('extract',), 'cramfs': ('identify',), 'romfs': ('identify',), 'jffs2': ('identify',), 'ubi': ('identify',), 'ubifs': ('identify',), 'zstd': ('identify',), 'lz4': ('identify',),
    'android-payload': ('identify',), 'trx': ('identify', 'extract'), 'elf': ('identify',), 'pe': ('identify',), 'ihex': ('identify',), 'srec': ('identify',),
}
SQUASHFS_COMPRESSORS = {1: 'gzip', 2: 'lzma', 3: 'lzo', 4: 'xz', 5: 'lz4', 6: 'zstd'}
SQUASHFS_SUPPORTED = frozenset({1, 2, 4})
UIMAGE_COMPRESSION = {0: 'none', 1: 'gzip', 2: 'bzip2', 3: 'lzma', 4: 'lzo', 5: 'lz4', 6: 'zstd'}
UIMAGE_TYPES = {1: 'standalone', 2: 'kernel', 3: 'ramdisk', 4: 'multi-file', 5: 'firmware', 6: 'script', 7: 'filesystem', 8: 'flat device tree', 9: 'kernel (any load address)'}
UIMAGE_ARCH = {2: 'ARM', 3: 'x86', 4: 'MIPS', 5: 'MIPS64', 6: 'PowerPC', 7: 'PowerPC', 8: 'SuperH', 9: 'SPARC', 22: 'ARM64', 24: 'RISC-V'}
MACHINES = {0x03: 'x86', 0x08: 'MIPS', 0x14: 'PowerPC', 0x28: 'ARM', 0x2a: 'SuperH', 0x3e: 'x86-64', 0xb7: 'AArch64', 0xf3: 'RISC-V', 0x5: 'M88K', 0x15: 'PowerPC64'}

# ---- what to list from a file system -----------------------------------------------------------------------------
INTERESTING = [
    ('credentials-file', re.compile(r'(^|/)etc/(passwd|shadow|group|gshadow|security/passwd)$|(^|/)(\.htpasswd|htpasswd|\.netrc)$')),
    ('startup-script', re.compile(r'(^|/)etc/(inittab|rc\.local|init\.d/[^/]+|rc\.d/[^/]+|rcS|profile|xinetd\.conf|inetd\.conf)$|(^|/)(init|linuxrc|rcS)$|(^|/)etc/.*\.sh$')),
    ('web-root', re.compile(r'(^|/)(www|htdocs|webroot|web|cgi-bin|usr/www|var/www)(/|$)')),
    ('crypto-material', re.compile(r'\.(pem|key|crt|cer|der|p12|pfx|jks|keystore)$|(^|/)id_(rsa|dsa|ecdsa|ed25519)$|(^|/)authorized_keys$|(^|/)dropbear/.*key')),
    ('config', re.compile(r'(^|/)etc/.*\.(conf|cfg|ini|json|xml)$|(^|/)(nvram|config|default)\.(bin|cfg|conf)$')),
    ('package-database', re.compile(r'(^|/)(opkg|dpkg|rpm|ipkg)/(status|info|lists)|(^|/)usr/lib/opkg')),
    ('kernel-module', re.compile(r'\.ko$')),
    ('boot-or-update', re.compile(r'(^|/)(boot|u-boot|uboot|bootloader|recovery|update|upgrade)[^/]*$', re.I)),
]
KERNEL_BANNER = re.compile(rb'Linux version (\d+\.\d+[\w.\-+]*)')
BUSYBOX_BANNER = re.compile(rb'BusyBox v(\d+\.\d+(?:\.\d+)?[\w.\-]*)')
PRIVATE_KEY = re.compile(rb'-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED |)PRIVATE KEY-----')
PROBE_BYTES = 8 * 1024 * 1024         # how much of a file is searched for banners


def validate():
    problems, ids = [], set()
    for sig in SIGNATURES:
        if not sig['magic'] or not isinstance(sig['magic'], bytes) or sig['offset'] < 0:
            problems.append(f"signature {sig['id']} magic/offset")
        if sig['category'] not in ('compression', 'filesystem', 'image', 'archive', 'executable', 'table', 'text'):
            problems.append(f"signature {sig['id']} category")
        if sig['id'] not in CAPABILITIES:
            problems.append(f"signature {sig['id']} has no capability entry")
        ids.add(sig['id'])
    for key, value in CAPABILITIES.items():
        if key not in ids:
            problems.append(f'capability {key} has no signature')
        if not value or any(v not in ('identify', 'list', 'extract') for v in value):
            problems.append(f'capability {key} values')
    for key, value in LIMITS.items():
        if not isinstance(value, int) or value <= 0:
            problems.append(f'limit {key}')
    if not set(SQUASHFS_SUPPORTED) <= set(SQUASHFS_COMPRESSORS):
        problems.append('squashfs compressors')
    for name, pattern in INTERESTING:
        if not name or not hasattr(pattern, 'search'):
            problems.append(f'interesting {name}')
    problems = [p for p in problems if p]
    if problems:
        raise ValueError('firmware_rules is inconsistent: ' + '; '.join(problems))


validate()
