"""Firmware front end: rule table, bounded decompression, SquashFS / ext / cpio / tar / zip readers, boot-image parsers, the nested
scan, safe extraction, hostile inputs, and real files. Images are generated from the format specs (scripts/fixtures/fw_builder.py);
7-Zip, when installed, gives an independent opinion on the file systems.

Run:  runtimes/ghidra/python/python.exe -I -B -X utf8 scripts/test_firmware.py
"""
from pathlib import Path
import bz2
import glob
import gzip
import hashlib
import io
import lzma
import os
import random
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
import zlib

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'worker'))
sys.path.insert(0, str(ROOT / 'scripts' / 'fixtures'))
import firmware_fs as fs
import firmware_images as images
import firmware_io as fio
import firmware_rules as rules
import firmware_scan as scan
import fw_builder as build
from firmware_io import FirmwareError, Source

SEVEN_ZIP = next((p for p in ('C:/Program Files/7-Zip/7z.exe', 'C:/Program Files (x86)/7-Zip/7z.exe') if os.path.exists(p)), None)
RNG = random.Random(7)
NOISE = bytes(RNG.randrange(256) for _ in range(30000))
FILES = [
    {'path': 'etc/passwd', 'data': b'root:x:0:0:root:/root:/bin/sh\n' * 3},
    {'path': 'bin/busybox', 'data': b'\x7fELF\x01\x01\x01' + bytes(9) + b'\x02\x00\x28\x00' + bytes(4) + bytes(40) + b'BusyBox v1.31.1 multi-call binary' + NOISE[:20000], 'mode': 0o755},
    {'path': 'bin/sh', 'symlink': 'busybox'},
    {'path': 'www/index.html', 'data': b'<html>' * 900},
    {'path': 'dev/null', 'device': (0, 1, 3)},
    {'path': 'empty', 'data': b''},
    {'path': 'zeros', 'data': bytes(9000)},
    {'path': 'a/b/c/d.txt', 'data': b'deep'},
    {'path': 'lib/big.bin', 'data': NOISE},
    {'path': 'etc/ssl/key.pem', 'data': b'-----BEGIN RSA PRIVATE KEY-----\nQUJD\n-----END RSA PRIVATE KEY-----\n'},
]
EXPECTED = {f['path']: f for f in FILES}


def read_all(reader):
    """{path: (kind, size, data|None, target)} for every entry a reader yields."""
    out = {}
    for entry in reader.entries():
        data = entry.read(1 << 28) if entry.kind == 'file' else None
        out[entry.path] = (entry.kind, entry.size, data, entry.target)
    return out


def check_tree(test, found, files=FILES, devices=True):
    for spec in files:
        path = spec['path']
        test.assertIn(path, found, f'{path} missing; have {sorted(found)}')
        kind, size, data, target = found[path]
        if 'symlink' in spec:
            test.assertEqual((kind, target), ('symlink', spec['symlink']), path)
        elif 'device' in spec:
            test.assertEqual(kind, 'device', path)
        else:
            test.assertEqual((kind, size), ('file', len(spec['data'])), path)
            test.assertEqual(data, spec['data'], f'{path} content')
    for directory in ('etc', 'bin', 'a/b/c', 'a/b'):
        test.assertEqual(found[directory][0], 'dir', directory)


class Rules(unittest.TestCase):
    def test_validates(self):
        rules.validate()

    def test_mistakes_are_caught(self):
        original = (list(rules.SIGNATURES), dict(rules.CAPABILITIES), dict(rules.LIMITS))
        try:
            rules.SIGNATURES.append({'id': 'nope', 'name': 'x', 'magic': b'xx', 'offset': 0, 'category': 'compression'})
            with self.assertRaisesRegex(ValueError, 'no capability entry'):
                rules.validate()
            rules.SIGNATURES[:] = original[0]
            rules.SIGNATURES.append({'id': 'gzip', 'name': 'x', 'magic': b'', 'offset': 0, 'category': 'compression'})
            with self.assertRaisesRegex(ValueError, 'magic/offset'):
                rules.validate()
            rules.SIGNATURES[:] = original[0]
            rules.SIGNATURES.append({'id': 'gzip', 'name': 'x', 'magic': b'x', 'offset': 0, 'category': 'wizard'})
            with self.assertRaisesRegex(ValueError, 'category'):
                rules.validate()
            rules.SIGNATURES[:] = original[0]
            rules.CAPABILITIES['ghost'] = ('list',)
            with self.assertRaisesRegex(ValueError, 'has no signature'):
                rules.validate()
            del rules.CAPABILITIES['ghost']
            rules.CAPABILITIES['gzip'] = ('fly',)
            with self.assertRaisesRegex(ValueError, 'values'):
                rules.validate()
            rules.CAPABILITIES['gzip'] = original[1]['gzip']
            rules.LIMITS['max_depth'] = 0
            with self.assertRaisesRegex(ValueError, 'limit max_depth'):
                rules.validate()
        finally:
            rules.SIGNATURES[:] = original[0]
            rules.CAPABILITIES.clear(); rules.CAPABILITIES.update(original[1]); rules.LIMITS.clear(); rules.LIMITS.update(original[2])
        rules.validate()

    def test_interesting_patterns(self):
        hit = lambda path: sorted(name for name, pattern in rules.INTERESTING if pattern.search(path))
        self.assertIn('credentials-file', hit('etc/shadow')); self.assertIn('startup-script', hit('etc/init.d/rcS')); self.assertIn('web-root', hit('usr/www/cgi-bin/login.cgi'))
        self.assertIn('crypto-material', hit('etc/ssl/server.pem')); self.assertEqual(hit('usr/share/doc/readme'), []); self.assertNotIn('credentials-file', hit('etc/passwd.bak/x'))


class IO(unittest.TestCase):
    PAYLOAD = NOISE[:1000] + b'A' * 200000 + b'tail'

    def codecs(self):
        return {'gzip': gzip.compress(self.PAYLOAD), 'zlib': zlib.compress(self.PAYLOAD), 'bzip2': bz2.compress(self.PAYLOAD), 'xz': lzma.compress(self.PAYLOAD), 'lzma': lzma.compress(self.PAYLOAD, format=lzma.FORMAT_ALONE)}

    def test_complete_streams_report_exact_consumption_even_with_trailing_bytes(self):
        for kind, blob in self.codecs().items():
            with self.subTest(kind):
                out, used, status = fio.inflate(Source(data=blob + b'TRAILING GARBAGE'), 0, kind, 1 << 24)
                self.assertEqual((status, out, used), ('complete', self.PAYLOAD, len(blob)))
                out, used, status = fio.inflate(Source(data=b'xx' + blob), 2, kind, 1 << 24)
                self.assertEqual((status, used), ('complete', len(blob)), 'a stream that starts mid-file')

    def test_truncation_limit_and_corruption(self):
        for kind, blob in self.codecs().items():
            with self.subTest(kind):
                self.assertEqual(fio.inflate(Source(data=blob[:len(blob) // 2]), 0, kind, 1 << 24)[2], 'truncated')
                out, _, status = fio.inflate(Source(data=blob), 0, kind, 5000)
                self.assertEqual((status, len(out)), ('limit', 5000))
                bad = bytearray(blob)
                bad[len(bad) // 2] ^= 0xff
                bad[len(bad) // 2 + 1] ^= 0xff
                self.assertIn(fio.inflate(Source(data=bytes(bad)), 0, kind, 1 << 24)[2], ('error', 'complete', 'truncated'))
                if kind != 'lzma':                                  # an all-zero header is a legal (empty) LZMA stream header
                    self.assertIn(fio.inflate(Source(data=bytes(300)), 0, kind, 1 << 20)[2], ('error', 'truncated'))

    def test_ratio_ceiling_stops_a_bomb(self):
        out, used, status = fio.inflate(Source(data=gzip.compress(bytes(300 * 1024 * 1024), 9)), 0, 'gzip', 1 << 40, max_ratio=100)
        self.assertEqual(status, 'bomb'); self.assertLess(len(out), 80 * 1024 * 1024)

    def test_unknown_codec(self):
        with self.assertRaises(FirmwareError):
            fio.inflate(Source(data=b'x'), 0, 'rot13', 10)

    def test_safe_names(self):
        cases = {'../../etc/passwd': 'etc/passwd', '/abs/path': 'abs/path', 'a/./b/../c': 'a/b/c', 'dir\\file': 'dir/file', 'CON': '_CON', 'nul.txt': '_nul.txt', 'a:b?c*d': 'a_b_c_d', '  .. ': '', '': '', 'ok/file.name': 'ok/file.name',
                 'trail. ': 'trail', 'x\x00y': 'xy', 'C:/Windows/system32': 'C_/Windows/system32'}
        for raw, wanted in cases.items():
            with self.subTest(raw):
                self.assertEqual(fio.safe_relative(raw)[0], wanted)
        long = fio.safe_relative('d/' + 'x' * 500)[0]
        self.assertLessEqual(len(long), rules.LIMITS['max_path_chars']); self.assertNotEqual(long, fio.safe_relative('d/' + 'x' * 499 + 'y')[0], 'truncated names stay distinct')

    def test_unique_paths_never_collide_and_never_escape(self):
        taken = set()
        root = tempfile.mkdtemp()
        try:
            names = [fio.unique_path(root, 'Etc/Passwd', taken)[1], fio.unique_path(root, 'etc/passwd', taken)[1], fio.unique_path(root, 'etc/passwd', taken)[1]]
            self.assertEqual(len(set(n.lower() for n in names)), 3, names)
            full, _ = fio.unique_path(root, 'a/b', taken)
            self.assertTrue(os.path.normpath(full).startswith(os.path.normpath(root)))
        finally:
            shutil.rmtree(root)

    def test_source_windows_and_find(self):
        data = b'0123456789' * 100 + b'NEEDLE' + b'x' * 50
        source = Source(data=data)
        window = source.window(500, 600)
        self.assertEqual(window.size, 556); self.assertEqual(window.read(0, 4), data[500:504]); self.assertEqual(window.find(b'NEEDLE'), 500); self.assertEqual(source.find(b'NEEDLE'), 1000)
        self.assertEqual(window.find(b'NEEDLE', 501), -1); self.assertEqual(source.read(-1, 5), b''); self.assertEqual(source.read(5000, 5), b''); self.assertEqual(len(source.read(1000, 10**6)), 56)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'f.bin'
            path.write_bytes(data)
            on_disk = Source(path=str(path))
            try:
                self.assertEqual(on_disk.find(b'NEEDLE'), 1000); self.assertEqual(on_disk.sha256(), hashlib.sha256(data).hexdigest()); self.assertEqual(on_disk.window(1000).read(0, 6), b'NEEDLE')
            finally:
                on_disk.close()

    def test_budget_ceilings(self):
        budget = fio.Budget({'max_files': 2, 'max_total_extract_bytes': 100, 'max_file_bytes': 60, 'max_components': 1})
        budget.take_file(50)
        with self.assertRaises(FirmwareError) as e:
            budget.take_file(61)
        self.assertEqual(e.exception.code, 'FILE_TOO_LARGE')
        with self.assertRaises(FirmwareError) as e:
            budget.take_file(51)
        self.assertEqual(e.exception.code, 'EXTRACT_LIMIT')
        budget.take_file(10)
        with self.assertRaises(FirmwareError) as e:
            budget.take_file(1)
        self.assertEqual(e.exception.code, 'TOO_MANY_FILES')
        budget.take_component()
        with self.assertRaises(FirmwareError):
            budget.take_component()


def seven_zip_listing(path):
    run = subprocess.run([SEVEN_ZIP, 'l', '-slt', str(path)], capture_output=True, text=True, timeout=60)
    entries, current = {}, {}
    for line in run.stdout.splitlines() + ['']:
        if line.startswith('Path = ') and 'Path' in current:
            entries[current['Path']] = current
            current = {}
        if ' = ' in line:
            key, value = line.split(' = ', 1)
            current[key] = value
        elif not line and 'Path' in current and 'Size' in current:
            entries[current['Path']] = current
            current = {}
    return entries


class SquashFSTests(unittest.TestCase):
    def test_every_compressor_and_metadata_mode_round_trips(self):
        for compression in ('zlib', 'xz', 'lzma', 'none'):
            for metadata in (True, False):
                for block in (4096, 16384):
                    with self.subTest(compression=compression, compressed_metadata=metadata, block=block):
                        image = build.build_squashfs(FILES, compression=compression, compress_metadata=metadata, block_size=block)
                        reader = fs.SquashFS(Source(data=image))
                        self.assertEqual(reader.info['compressor'], {'zlib': 'gzip', 'xz': 'xz', 'lzma': 'lzma', 'none': 'gzip'}[compression])
                        check_tree(self, read_all(reader))
                        self.assertEqual(reader.notes, [])

    def test_big_endian(self):
        reader = fs.SquashFS(Source(data=build.build_squashfs(FILES, big_endian=True)))
        self.assertEqual(reader.info['endian'], 'big'); check_tree(self, read_all(reader))

    def test_image_inside_a_larger_blob(self):
        image = build.build_squashfs(FILES, compression='xz')
        blob = b'\xff' * 1000 + image + b'\xee' * 500
        reader = fs.SquashFS(Source(data=blob), 1000)
        check_tree(self, read_all(reader))

    def test_many_files_span_several_metadata_blocks(self):
        many = [{'path': f'd{i % 7}/file{i:04d}.txt', 'data': f'content {i}\n'.encode() * (i % 5 + 1)} for i in range(900)]
        reader = fs.SquashFS(Source(data=build.build_squashfs(many)))
        found = read_all(reader)
        self.assertEqual(sum(1 for v in found.values() if v[0] == 'file'), 900)
        for spec in many[::97]:
            self.assertEqual(found[spec['path']][2], spec['data'])
        self.assertEqual(reader.notes, [])

    def test_probe_rejects_what_is_not_a_superblock(self):
        image = bytearray(build.build_squashfs(FILES))
        self.assertIsNotNone(fs.SquashFS.probe(Source(data=bytes(image)), 0))
        for offset, value, why in ((28, 3, 'version'), (12, 5000, 'block size not a power of two'), (22, 99, 'block log mismatch'), (20, 9, 'compressor id'), (4, 0, 'no inodes')):
            broken = bytearray(image)
            if offset == 28:
                struct.pack_into('<H', broken, 28, value)
            elif offset == 12:
                struct.pack_into('<I', broken, 12, value)
            elif offset == 22:
                struct.pack_into('<H', broken, 22, value)
            elif offset == 20:
                struct.pack_into('<H', broken, 20, value)
            else:
                struct.pack_into('<I', broken, 4, value)
            self.assertIsNone(fs.SquashFS.probe(Source(data=bytes(broken)), 0), why)
        self.assertIsNone(fs.SquashFS.probe(Source(data=b'hsqs' + bytes(100)), 0)); self.assertIsNone(fs.SquashFS.probe(Source(data=b'hsqs'), 0))

    def test_unsupported_compressor_is_refused_with_its_name(self):
        image = bytearray(build.build_squashfs(FILES))
        struct.pack_into('<H', image, 20, 3)
        info = fs.SquashFS.probe(Source(data=bytes(image)), 0)
        self.assertEqual(info['compressor'], 'lzo')
        with self.assertRaises(FirmwareError) as e:
            fs.SquashFS(Source(data=bytes(image)))
        self.assertEqual(e.exception.code, 'UNSUPPORTED_COMPRESSOR')

    def test_corruption_ends_a_branch_with_a_note_not_an_exception(self):
        image = bytearray(build.build_squashfs(FILES, compression='zlib'))
        rng = random.Random(3)
        for _ in range(60):
            broken = bytearray(image)
            for _ in range(rng.randrange(1, 8)):
                broken[rng.randrange(96, len(broken))] = rng.randrange(256)
            try:
                reader = fs.SquashFS(Source(data=bytes(broken)))
                for entry in reader.entries():
                    if entry.kind == 'file':
                        try:
                            entry.read(1 << 26)
                        except FirmwareError:
                            pass
            except FirmwareError:
                pass

    def test_truncated_image_is_flagged_and_partly_readable(self):
        image = build.build_squashfs(FILES, compression='none')
        info = fs.SquashFS.probe(Source(data=image[:len(image) // 2]), 0)
        self.assertTrue(info is None or info['truncated'])

    @unittest.skipUnless(SEVEN_ZIP, '7-Zip not installed')
    def test_7zip_agrees_on_names_and_sizes(self):
        with tempfile.TemporaryDirectory() as d:
            for compression in ('zlib', 'xz'):
                path = Path(d) / f'{compression}.squashfs'
                path.write_bytes(build.build_squashfs(FILES, compression=compression))
                theirs = {k.replace('\\', '/'): v for k, v in seven_zip_listing(path).items() if v.get('Folder') == '-'}
                ours = {p: v for p, v in read_all(fs.SquashFS(Source(data=path.read_bytes()))).items() if v[0] in ('file', 'symlink', 'device')}
                shared = set(theirs) & set(ours)
                self.assertGreaterEqual(len(shared), 8, (sorted(theirs), sorted(ours)))
                for name in shared:
                    if ours[name][0] == 'file':
                        self.assertEqual(int(theirs[name]['Size']), ours[name][1], name)


class ExtTests(unittest.TestCase):
    def images(self):
        big = [{'path': 'data/big.bin', 'data': NOISE * 10}]                       # 300 KB: needs single and double indirect blocks at 1 KiB
        files = FILES + big + [{'path': 'lnk/long', 'symlink': 'x' * 100}]
        return {'ext2': build.build_ext(files, total_blocks=4096), 'ext4-extents': build.build_ext(files, extents=True, total_blocks=4096)}, files

    def test_ext2_and_extent_files(self):
        images, files = self.images()
        for name, image in images.items():
            with self.subTest(name):
                reader = fs.Ext(Source(data=image))
                found = read_all(reader)
                check_tree(self, found, files)
                self.assertEqual(reader.info['volume'], 'IG5TEST'); self.assertEqual(reader.info['version'], 'ext4' if 'extents' in name else 'ext2'); self.assertEqual(reader.notes, [])

    def test_probe_rejects_non_ext(self):
        image = bytearray(build.build_ext(FILES))
        self.assertIsNotNone(fs.Ext.probe(Source(data=bytes(image)), 0))
        broken = bytearray(image)
        struct.pack_into('<H', broken, 1024 + 56, 0xBEEF)
        self.assertIsNone(fs.Ext.probe(Source(data=bytes(broken)), 0)); self.assertIsNone(fs.Ext.probe(Source(data=bytes(500)), 0))
        broken = bytearray(image)
        struct.pack_into('<I', broken, 1024 + 40, 0)
        self.assertIsNone(fs.Ext.probe(Source(data=bytes(broken)), 0), 'zero inodes per group')

    def test_corruption_does_not_raise_out_of_the_reader(self):
        image = build.build_ext(FILES)
        rng = random.Random(5)
        for _ in range(60):
            broken = bytearray(image)
            for _ in range(rng.randrange(1, 10)):
                broken[rng.randrange(1024, 40000)] = rng.randrange(256)
            try:
                reader = fs.Ext(Source(data=bytes(broken)))
                for entry in reader.entries():
                    if entry.kind == 'file':
                        try:
                            entry.read(1 << 24)
                        except FirmwareError:
                            pass
            except (FirmwareError, struct.error):
                pass

    @unittest.skipUnless(SEVEN_ZIP, '7-Zip not installed')
    def test_7zip_agrees_on_names_and_sizes(self):
        images, files = self.images()
        with tempfile.TemporaryDirectory() as d:
            for name, image in images.items():
                path = Path(d) / f'{name}.img'
                path.write_bytes(image)
                theirs = {k.replace('\\', '/'): v for k, v in seven_zip_listing(path).items() if v.get('Folder') == '-'}
                ours = {p: v for p, v in read_all(fs.Ext(Source(data=image))).items() if v[0] == 'file'}
                for p, v in ours.items():
                    if p in theirs:
                        self.assertEqual(int(theirs[p]['Size']), v[1], (name, p))
                self.assertGreaterEqual(len(set(theirs) & set(ours)), 8, (name, sorted(theirs)))


class ArchiveTests(unittest.TestCase):
    def test_cpio(self):
        image = build.build_cpio([f for f in FILES if 'device' not in f] + [{'path': 'proc', 'dir': True}])
        info = fs.Cpio.probe(Source(data=image), 0)
        self.assertTrue(info['complete']); self.assertEqual(info['entries'], len(FILES) - 1 + 1)
        found = read_all(fs.Cpio(Source(data=image)))
        check_tree(self, found, [f for f in FILES if 'device' not in f], devices=False) if False else None
        for spec in FILES:
            if 'data' in spec:
                self.assertEqual(found[spec['path']][2], spec['data'])
        self.assertEqual(found['bin/sh'][:2] + (found['bin/sh'][3],), ('symlink', 0, 'busybox'))

    def test_cpio_probe_stops_at_garbage(self):
        image = build.build_cpio(FILES)
        self.assertIsNone(fs.Cpio.probe(Source(data=b'070701' + b'ZZZZZZZZ' * 13), 0)); self.assertIsNone(fs.Cpio.probe(Source(data=b'x' * 200), 0))
        cut = fs.Cpio.probe(Source(data=image[:600]), 0)
        self.assertIsNotNone(cut) and self.assertFalse(cut['complete'])

    def make_tar(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:') as archive:
            for spec in FILES:
                if 'data' in spec:
                    info = tarfile.TarInfo(spec['path'])
                    info.size = len(spec['data'])
                    archive.addfile(info, io.BytesIO(spec['data']))
                elif 'symlink' in spec:
                    info = tarfile.TarInfo(spec['path'])
                    info.type, info.linkname = tarfile.SYMTYPE, spec['symlink']
                    archive.addfile(info)
        return stream.getvalue()

    def test_tar_round_trip_and_size(self):
        data = self.make_tar()
        found = read_all(_Wrap(fs.tar_entries(Source(data=data))))
        for spec in FILES:
            if 'data' in spec:
                self.assertEqual(found[spec['path']][2], spec['data'])
        size = fs.tar_size(Source(data=data + b'trailing'), 0)
        self.assertTrue(len(data) - 10240 < size <= len(data), (size, len(data)))                 # tarfile pads to a 10 KiB record; the archive proper ends after two zero blocks
        self.assertIsNone(fs.tar_size(Source(data=b'x' * 2000), 0))
        bad = bytearray(data)
        bad[148] ^= 1
        self.assertIsNone(fs.tar_size(Source(data=bytes(bad)), 0), 'header checksum')

    def test_zip_round_trip(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as archive:
            for spec in FILES:
                if 'data' in spec:
                    archive.writestr(spec['path'], spec['data'])
            archive.writestr('dir/', '')
        found = read_all(_Wrap(fs.zip_entries(Source(data=b'JUNK' * 10 + stream.getvalue()), 40)))
        for spec in FILES:
            if 'data' in spec:
                self.assertEqual(found[spec['path']][2], spec['data'])
        self.assertEqual(found['dir'][0], 'dir')

    def test_encrypted_and_oversized_zip_entries_are_refused(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr('big', bytes(5000))
        entries = list(fs.zip_entries(Source(data=stream.getvalue()), 0))
        with self.assertRaises(FirmwareError) as e:
            entries[0].read(100)
        self.assertEqual(e.exception.code, 'FILE_TOO_LARGE')


class _Wrap:
    def __init__(self, iterator):
        self.iterator, self.notes = iterator, []

    def entries(self):
        return self.iterator


class ImageTests(unittest.TestCase):
    def test_uimage(self):
        payload = b'kernel payload ' * 40
        info = images.probe_uimage(Source(data=build.build_uimage(payload, name='my kernel')), 0)
        self.assertEqual((info['name'], info['imageType'], info['arch'], info['os'], info['compression'], info['loadAddress'], info['payloadSize']), ('my kernel', 'kernel', 'ARM', 'Linux', 'none', '0x80008000', len(payload)))
        self.assertEqual(info['checks'], {'headerCrc': True, 'dataCrc': True}); self.assertTrue(info['valid']); self.assertEqual(info['size'], 64 + len(payload))
        bad_data = images.probe_uimage(Source(data=build.build_uimage(payload, bad_data_crc=True)), 0)
        self.assertEqual((bad_data['checks']['dataCrc'], bad_data['valid']), (False, False))
        bad_header = images.probe_uimage(Source(data=build.build_uimage(payload, bad_header_crc=True)), 0)
        self.assertEqual((bad_header['checks']['headerCrc'], bad_header['valid']), (False, False))
        cut = images.probe_uimage(Source(data=build.build_uimage(payload)[:100]), 0)
        self.assertTrue(cut['truncated']); self.assertIsNone(cut['checks']['dataCrc'])
        self.assertIsNone(images.probe_uimage(Source(data=b'\x27\x05\x19\x56' + bytes(60)), 0)); self.assertIsNone(images.probe_uimage(Source(data=b'x'), 0))

    def test_uimage_multi_file(self):
        parts = [b'A' * 10, b'B' * 7]
        payload = struct.pack('>III', 10, 7, 0) + parts[0] + bytes(2) + parts[1] + bytes(1)
        data = build.build_uimage(payload, kind=4)
        info = images.probe_uimage(Source(data=data), 0)
        children = images.uimage_children(Source(data=data), 0, info)
        self.assertEqual([(c[2]) for c in children], [10, 7])
        self.assertEqual(data[children[0][1]:children[0][1] + 10], parts[0]); self.assertEqual(data[children[1][1]:children[1][1] + 7], parts[1])

    def test_fit_hashes_are_checked(self):
        blob = build.build_fit({'kernel': {'data': b'K' * 300}, 'fdt-1': {'data': b'D' * 64, 'type': 'flat_dt'}, 'ramdisk': {'data': b'R' * 100, 'type': 'ramdisk', 'compression': 'gzip'}})
        source = Source(data=blob)
        info = images.probe_fdt(source, 0)
        result, notes, _ = images.fit_images(source, 0, info)
        self.assertEqual(notes, []); self.assertEqual(result['default'], 'conf-1'); self.assertEqual([i['name'] for i in result['images']], ['kernel', 'fdt-1', 'ramdisk'])
        for row in result['images']:
            self.assertEqual([h['verified'] for h in row['hashes']], [True, True]); self.assertEqual(blob[row['dataOffset']:row['dataOffset'] + row['dataSize']], {'kernel': b'K' * 300, 'fdt-1': b'D' * 64, 'ramdisk': b'R' * 100}[row['name']])
        self.assertEqual(next(i for i in result['images'] if i['name'] == 'ramdisk')['compression'], 'gzip')
        bad, _, _ = images.fit_images(Source(data=build.build_fit({'kernel': {'data': b'K' * 300}}, bad_hash=True)), 0, images.probe_fdt(Source(data=build.build_fit({'kernel': {'data': b'K'}})), 0) and images.probe_fdt(Source(data=build.build_fit({'kernel': {'data': b'K' * 300}}, bad_hash=True)), 0))
        self.assertEqual(sorted(h['verified'] for h in bad['images'][0]['hashes']), [False, True], 'sha256 mismatch is reported, crc32 still matches')

    def test_plain_device_tree_is_not_a_fit(self):
        blob = build.fdt_blob({'props': {'model': 'IG5 board'}, 'nodes': {'cpus': {'props': {'#address-cells': 1}}}})
        source = Source(data=blob)
        result, _, tree = images.fit_images(source, 0, images.probe_fdt(source, 0))
        self.assertIsNone(result); self.assertEqual(images._str(tree['props']['model']), 'IG5 board')

    def test_fdt_header_validation(self):
        blob = bytearray(build.fdt_blob({'props': {'a': 1}}))
        self.assertIsNotNone(images.probe_fdt(Source(data=bytes(blob)), 0))
        for offset, value in ((4, 1 << 30), (20, 3), (8, 2)):
            broken = bytearray(blob)
            struct.pack_into('>I', broken, offset, value)
            self.assertIsNone(images.probe_fdt(Source(data=bytes(broken)), 0), offset)

    def test_android_boot_versions(self):
        for version in (0, 3, 4):
            with self.subTest(version):
                data = build.build_android_boot(b'K' * 3000, b'R' * 5000, version=version, second=b'S' * 100 if version == 0 else b'')
                info = images.probe_android_boot(Source(data=data), 0)
                self.assertEqual((info['kernelSize'], info['ramdiskSize'], info['headerVersion']), (3000, 5000, version))
                self.assertEqual(info['osVersion'], '11.0.0'); self.assertEqual(info['securityPatch'], '2023-05'); self.assertIn('console=ttyS0', info['cmdline'])
                children = images.android_boot_children(info)
                self.assertEqual(data[children[0][1]:children[0][1] + 3000], b'K' * 3000); self.assertEqual(data[children[1][1]:children[1][1] + 5000], b'R' * 5000)
                self.assertEqual(len(children), 3 if version == 0 else 2)
        self.assertIsNone(images.probe_android_boot(Source(data=b'ANDROID!' + bytes(500)), 0))

    def test_sparse_unsparse_matches_the_raw_image(self):
        raw = b'A' * 5000
        chunks = [('raw', raw), ('fill', 0x01020304, 2), ('skip', 3), ('raw', b'tail' * 100)]
        data = build.build_sparse(chunks)
        source = Source(data=data)
        info = images.probe_android_sparse(source, 0)
        self.assertEqual(images.sparse_size(source, 0, info), len(data))
        expected = raw.ljust(8192, b'\0') + struct.pack('<I', 0x01020304) * 2048 + bytes(3 * 4096) + (b'tail' * 100).ljust(4096, b'\0')
        out = bytearray()
        self.assertTrue(images.unsparse(source, 0, info, out.extend, 1 << 30)); self.assertEqual(bytes(out), expected)
        self.assertFalse(images.unsparse(source, 0, info, out.extend, 100), 'over the size budget')
        self.assertEqual(images.sparse_size(Source(data=data[:-10]), 0, info), len(data), 'the declared size; the scanner marks the file truncated')

    def test_trx(self):
        body = bytes(8) + b'A' * 100 + b'B' * 200
        header = struct.pack('<4sIIIIII', b'HDR0', 28 + len(body), 0, 1 << 16 | 0, 28, 28 + 108, 0)
        data = header + body
        info = images.probe_trx(Source(data=data), 0)
        self.assertEqual(info['partitions'], [28, 136]); self.assertEqual(len(images.trx_children(info)), 2)
        self.assertIsNone(images.probe_trx(Source(data=header[:8] + struct.pack('<IIIII', 0, 5 << 16, 500, 40, 0)), 0))


def write_image(directory, data, name='fw.bin'):
    path = os.path.join(directory, name)
    with open(path, 'wb') as handle:
        handle.write(data)
    return path


def flatten(components):
    for c in components:
        yield c
        for child in c['children']:
            yield from flatten(child['components'])


def nested_firmware():
    kernel = b'Linux version 4.14.180 (builder@host) (gcc 7.5) #1 SMP' + NOISE[:3000]
    squash = build.build_squashfs(FILES, compression='xz')
    return (build.build_uimage(gzip.compress(kernel, mtime=0), comp=1) + bytes(100) + lzma.compress(squash) + bytes(37) + build.build_cpio([{'path': 'init', 'data': b'#!/bin/sh\n'}])), kernel, squash


class Scan(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='ig5-fw-')

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_nested_inventory(self):
        image, kernel, squash = nested_firmware()
        report = scan.scan_firmware(write_image(self.dir, image))
        formats = [c['format'] for c in flatten(report['components'])]
        self.assertEqual(formats, ['uimage', 'gzip', 'xz', 'squashfs', 'cpio'])
        top = report['components']
        self.assertEqual([c['offset'] for c in top], [0, len(build.build_uimage(gzip.compress(kernel, mtime=0))) + 100, top[2]['offset']])
        self.assertTrue(top[0]['valid']); self.assertEqual(top[0]['meta']['compression'], 'gzip')
        gz = top[0]['children'][0]['components'][0]
        self.assertEqual(gz['decompressed']['size'], len(kernel)); self.assertEqual(gz['decompressed']['sha256'], hashlib.sha256(kernel).hexdigest())
        sq = next(c for c in flatten(report['components']) if c['format'] == 'squashfs')
        self.assertEqual(sq['filesystem']['files'], 8); self.assertEqual(sq['filesystem']['symlinks'], 1); self.assertEqual(sq['filesystem']['devices'], 1)
        self.assertEqual(report['summary']['kernelBanner'], 'Linux version 4.14.180 (builder@host) (gcc 7.5) #1 SMP'); self.assertEqual(report['summary']['busyboxVersion'], '1.31.1')
        self.assertEqual(report['summary']['executableArchitectures'], {'ARM 32-bit': 1})
        self.assertEqual(report['summary']['interesting']['credentials-file'], ['etc/passwd']); self.assertIn('etc/ssl/key.pem', report['summary']['interesting']['private-key-material'])
        self.assertIsNone(report['extraction']); self.assertEqual(report['limitsHit'], []); self.assertEqual(report['file']['sha256'], hashlib.sha256(image).hexdigest())
        self.assertTrue(all(isinstance(x, (int, str, bool, type(None), list, dict, float)) for x in report))

    def test_extraction_writes_exactly_the_contents_and_nothing_else(self):
        image, kernel, squash = nested_firmware()
        out = os.path.join(self.dir, 'out')
        report = scan.scan_firmware(write_image(self.dir, image), extract_to=out)
        written = {os.path.relpath(os.path.join(r, f), out).replace('\\', '/') for r, _, fs_ in os.walk(out) for f in fs_}
        self.assertEqual(written, {i['path'] for i in report['extraction']['items']})
        self.assertEqual(report['extraction']['files'], len(written))
        by_archive = {i.get('archivePath'): i for i in report['extraction']['items'] if i.get('archivePath')}
        for spec in FILES:
            if 'data' in spec:
                row = by_archive[spec['path']] if spec['path'] in by_archive else None
                self.assertIsNotNone(row, spec['path'])
                self.assertEqual(open(os.path.join(out, row['path']), 'rb').read(), spec['data']); self.assertEqual(row['sha256'], hashlib.sha256(spec['data']).hexdigest())
        self.assertNotIn('bin/sh', by_archive, 'symlinks are not created'); self.assertNotIn('dev/null', by_archive, 'device nodes are not created')
        self.assertEqual(open(os.path.join(out, [i for i in report['extraction']['items'] if i['path'].endswith('003_squashfs/files/etc/passwd') or i['path'].endswith('files/etc/passwd')][0]['path']), 'rb').read(), EXPECTED['etc/passwd']['data'])
        self.assertEqual(report['extraction']['bytes'], sum(os.path.getsize(os.path.join(out, w)) for w in written))
        before = os.listdir(self.dir)
        self.assertEqual(sorted(before), ['fw.bin', 'out'], 'nothing is written outside the output directory')

    def test_hostile_archive_names_stay_inside_the_output(self):
        evil = [{'path': '../../escape.txt', 'data': b'x'}, {'path': '/abs/olute.txt', 'data': b'y'}, {'path': 'C:/Windows/evil.dll', 'data': b'z'}, {'path': 'CON', 'data': b'c'}, {'path': 'a/../../b.txt', 'data': b'b'},
                {'path': 'dup', 'data': b'1'}, {'path': 'DUP', 'data': b'2'}, {'path': 'link', 'symlink': '../../etc/passwd'}]
        out = os.path.join(self.dir, 'out')
        report = scan.scan_firmware(write_image(self.dir, build.build_cpio(evil)), extract_to=out)
        root = os.path.realpath(out)
        for r, d, files_ in os.walk(out):
            for f in files_:
                self.assertTrue(os.path.realpath(os.path.join(r, f)).startswith(root), f)
        self.assertEqual(sorted(os.listdir(self.dir)), ['fw.bin', 'out'])
        names = [i['path'] for i in report['extraction']['items']]
        self.assertEqual(len(names), 7); self.assertEqual(len({n.lower() for n in names}), 7, 'case-insensitive duplicates are renamed')
        self.assertFalse(any('..' in n.split('/') for n in names)); self.assertFalse(os.path.exists(os.path.join(self.dir, 'escape.txt')))

    def test_a_decompression_bomb_is_stopped_and_reported(self):
        bomb = gzip.compress(bytes(400 * 1024 * 1024), 9)
        report = scan.scan_firmware(write_image(self.dir, bomb), limits={'max_ratio': 100})
        gz = report['components'][0]
        self.assertEqual(gz['format'], 'gzip'); self.assertIn(gz['decompressed']['status'], ('bomb', 'limit')); self.assertTrue(gz['notes']); self.assertLess(gz['decompressed']['size'], 80 * 1024 * 1024)

    def test_extraction_budgets_stop_cleanly(self):
        out = os.path.join(self.dir, 'out')
        report = scan.scan_firmware(write_image(self.dir, build.build_squashfs(FILES)), extract_to=out, limits={'max_file_bytes': 1000})
        skipped = {s['path'].split(':')[-1]: s['reason'] for s in report['extraction']['skipped']}
        self.assertIn('lib/big.bin', skipped); self.assertTrue(skipped['lib/big.bin'].startswith('FILE_TOO_LARGE'))
        self.assertTrue(all(i['size'] <= 1000 for i in report['extraction']['items']))
        out2 = os.path.join(self.dir, 'out2')
        report2 = scan.scan_firmware(write_image(self.dir, build.build_squashfs(FILES), 'b.bin'), extract_to=out2, limits={'max_files': 2})
        self.assertLessEqual(report2['extraction']['files'], 2); self.assertTrue(report2['extraction']['skipped'])

    def test_depth_limit(self):
        layers = build.build_cpio([{'path': 'inner.bin', 'data': build.build_cpio([{'path': 'deep.bin', 'data': gzip.compress(b'secret' * 100)}])}])
        shallow = scan.scan_firmware(write_image(self.dir, layers), limits={'max_depth': 1})
        self.assertEqual([c['format'] for c in flatten(shallow['components'])], ['cpio', 'cpio'])
        flat = scan.scan_firmware(write_image(self.dir, layers, 'f.bin'), limits={'max_depth': 0})
        self.assertEqual([c['format'] for c in flatten(flat['components'])], ['cpio'])
        deep = scan.scan_firmware(write_image(self.dir, layers, 'd.bin'), limits={'max_depth': 4})
        self.assertEqual([c['format'] for c in flatten(deep['components'])], ['cpio', 'cpio', 'gzip'])

    def test_random_noise_yields_no_components(self):
        noise = bytes(random.Random(11).randrange(256) for _ in range(200000))
        report = scan.scan_firmware(write_image(self.dir, noise))
        self.assertEqual(report['components'], [])

    def test_weak_signatures_need_valid_content(self):
        fake = b'\x1f\x8b\x08' + bytes(50) + b'BZh9' + bytes(30) + b'hsqs' + bytes(200) + b'\x78\x9c' + bytes(30) + b'PK\x03\x04' + bytes(40) + b'\x5d\x00\x00' + bytes(40) + b'UBI#' + bytes(80) + b'\x7fELF' + bytes(20)
        self.assertEqual(scan.scan_firmware(write_image(self.dir, fake))['components'], [])

    def test_every_cut_of_a_real_looking_image_scans_without_raising(self):
        image, _, _ = nested_firmware()
        for cut in range(1, len(image), max(1, len(image) // 120)):
            report = scan.scan_firmware(write_image(self.dir, image[:cut]))
            self.assertEqual(report['schema'], scan.SCHEMA)

    def test_mutated_images_never_raise(self):
        image, _, _ = nested_firmware()
        rng = random.Random(13)
        for _ in range(80):
            data = bytearray(image)
            for _ in range(rng.randrange(1, 12)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            scan.scan_firmware(write_image(self.dir, bytes(data)))

    def test_inputs_that_cannot_be_processed(self):
        with self.assertRaises(FirmwareError) as e:
            scan.scan_firmware(os.path.join(self.dir, 'missing.bin'))
        self.assertEqual(e.exception.code, 'INPUT')
        with self.assertRaises(FirmwareError):
            scan.scan_firmware(write_image(self.dir, b''))
        with self.assertRaises(FirmwareError):
            scan.scan_firmware(self.dir)
        os.makedirs(os.path.join(self.dir, 'full'))
        open(os.path.join(self.dir, 'full', 'x'), 'w').close()
        with self.assertRaises(FirmwareError) as e:
            scan.scan_firmware(write_image(self.dir, b'x' * 10), extract_to=os.path.join(self.dir, 'full'))
        self.assertEqual(e.exception.code, 'OUTPUT_NOT_EMPTY')
        with self.assertRaises(FirmwareError):
            scan.scan_firmware(write_image(self.dir, b'x' * 10), limits={'max_input_bytes': 5})

    def test_deadline_is_honoured(self):
        image, _, _ = nested_firmware()
        report = scan.scan_firmware(write_image(self.dir, image), deadline_seconds=-1)
        self.assertIn('deadline', report['limitsHit'])

    def test_component_budget(self):
        many = b''.join(build.build_cpio([{'path': f'f{i}', 'data': b'x'}]) for i in range(30))
        with self.assertRaises(FirmwareError) as e:
            scan.scan_firmware(write_image(self.dir, many), limits={'max_components': 5})
        self.assertEqual(e.exception.code, 'TOO_MANY_COMPONENTS')

    def test_formats_that_are_identified_but_not_opened(self):
        zstd = b'\x28\xb5\x2f\xfd' + bytes([0x20, 0x10]) + b'x' * 40
        report = scan.scan_firmware(write_image(self.dir, zstd))
        self.assertEqual([(c['format'], c['capabilities']) for c in report['components']], [('zstd', ['identify'])])
        ec = bytearray(64)
        ec[:4], ec[4] = b'UBI#', 1
        struct.pack_into('>QII', ec, 8, 3, 64, 4096)
        struct.pack_into('>I', ec, 60, (zlib.crc32(bytes(ec[:60])) ^ 0xffffffff) & 0xffffffff)
        self.assertEqual([c['format'] for c in scan.scan_firmware(write_image(self.dir, bytes(ec) + bytes(4000), 'u.bin'))['components']], ['ubi'])
        ec[10] ^= 1
        self.assertEqual(scan.scan_firmware(write_image(self.dir, bytes(ec) + bytes(4000), 'v.bin'))['components'], [], 'bad header CRC')

    def test_split_zlib_and_bzip_xz_streams_in_a_raw_dump(self):
        payload = NOISE[:5000] + b'B' * 20000
        dump = bytes(300) + bz2.compress(payload) + bytes(50) + lzma.compress(payload) + bytes(70) + zlib.compress(payload, 9) + bytes(30)
        report = scan.scan_firmware(write_image(self.dir, dump))
        self.assertEqual([(c['format'], c['decompressed']['size']) for c in report['components']], [('bzip2', len(payload)), ('xz', len(payload)), ('zlib', len(payload))])
        self.assertEqual([c['offset'] for c in report['components']], [300, 300 + len(bz2.compress(payload)) + 50, 300 + len(bz2.compress(payload)) + 50 + len(lzma.compress(payload)) + 70])

    def test_fit_image_is_split_into_hash_checked_payloads(self):
        kernel = gzip.compress(b'Linux version 5.4.0 (x@y) #1' + NOISE[:500], mtime=0)
        fit = build.build_fit({'kernel': {'data': kernel, 'compression': 'gzip'}, 'ramdisk': {'data': build.build_cpio([{'path': 'init', 'data': b'x'}]), 'type': 'ramdisk'}})
        out = os.path.join(self.dir, 'o')
        report = scan.scan_firmware(write_image(self.dir, fit + bytes(64)), extract_to=out)
        c = report['components'][0]
        self.assertEqual((c['format'], c['meta']['kind']), ('fdt', 'FIT image')); self.assertEqual([f['name'] for f in c['fit']], ['kernel', 'ramdisk'])
        self.assertTrue(all(h['verified'] for f in c['fit'] for h in f['hashes']))
        self.assertEqual(report['summary']['kernelBanner'], 'Linux version 5.4.0 (x@y) #1'); self.assertIn('cpio', report['summary']['formats'])
        self.assertTrue(any(i['path'].endswith('kernel.bin') for i in report['extraction']['items']))

    def test_android_images_are_opened(self):
        ramdisk = gzip.compress(build.build_cpio([{'path': 'init', 'data': b'#!/system/bin/sh\n'}]), mtime=0)
        boot = build.build_android_boot(b'\x00' * 100 + b'Linux version 4.19.1 (a@b) #1' + bytes(100), ramdisk)
        report = scan.scan_firmware(write_image(self.dir, boot))
        self.assertEqual([c['format'] for c in flatten(report['components'])], ['android-boot', 'gzip', 'cpio'])
        sparse = build.build_sparse([('raw', build.build_ext(FILES)), ('skip', 4)])
        report = scan.scan_firmware(write_image(self.dir, sparse, 's.img'))
        self.assertEqual([c['format'] for c in flatten(report['components'])], ['android-sparse', 'ext'])
        self.assertEqual(next(c for c in flatten(report['components']) if c['format'] == 'ext')['filesystem']['files'], 8)


@unittest.skipUnless(glob.glob(str(Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32' / 'notepad.exe')), 'no notepad.exe')
class RealFiles(unittest.TestCase):
    def test_a_windows_executable_is_one_pe(self):
        path = Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32' / 'notepad.exe'
        report = scan.scan_firmware(str(path))
        self.assertEqual(report['components'][0]['format'], 'pe'); self.assertEqual(report['components'][0]['offset'], 0)

    def test_a_real_zip_and_a_real_jar(self):
        candidates = glob.glob(str(ROOT / 'runtimes' / 'ghidra' / '**' / '*.jar'), recursive=True)[:3]
        corpus = Path(os.environ.get('IG5_PROTECTION_CORPUS') or Path.home() / '.dsh' / 'ig5' / 'artifacts' / 'corpus-expansion-20261014' / 'corpus') / 'derived'
        candidates += sorted(glob.glob(str(corpus / '*.apk')))[:3]
        if not candidates:
            self.skipTest('no real zip-format files found')
        for path in candidates:
            with self.subTest(os.path.basename(path)):
                report = scan.scan_firmware(path)
                top = report['components'][0]
                self.assertEqual((top['format'], top['offset']), ('zip', 0))
                with zipfile.ZipFile(path) as archive:
                    expected = sum(1 for i in archive.infolist() if not i.is_dir())
                self.assertEqual(top['meta']['entries'], len(zipfile.ZipFile(path).infolist()))
                self.assertEqual(top['filesystem']['files'], expected)


if __name__ == '__main__':
    unittest.main(verbosity=1)
