"""Packing detection: rule-table integrity, generated PE/ELF cases for every indicator and exemption, hostile headers,
and checks against REAL files when they exist on this machine (the protection corpus and the Windows system directory).

Run:  runtimes/ghidra/python/python.exe -I -B -X utf8 scripts/test_packer_analysis.py [--runtime ghidra]
The real-file checks skip loudly when their inputs are missing; ``--runtime ghidra`` also runs the ig5_scan acceptance
through a real Ghidra session (the generated image is analysed, never executed).
"""
from pathlib import Path
import argparse
import glob
import importlib
import json
import os
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'worker'))
sys.path.insert(0, str(ROOT / 'scripts' / 'fixtures'))
import packer_rules as rules
from packer_analysis import analyze_packing, entropy
from pe_builder import (DATA, RDATA, RWX, SCN_EXEC, SCN_READ, SCN_UNINIT, SCN_WRITE, TEXT, build_elf, build_pe, pseudo_code, random_bytes)

KERNEL32 = ['CreateFileW', 'ReadFile', 'WriteFile', 'CloseHandle', 'GetLastError', 'HeapAlloc', 'HeapFree', 'GetProcessHeap', 'ExitProcess', 'GetCommandLineW', 'Sleep', 'GetTickCount',
            'LoadLibraryA', 'GetProcAddress', 'VirtualAlloc', 'VirtualProtect', 'GetModuleHandleA', 'lstrlenA']
USER32 = ['MessageBoxW', 'GetMessageW', 'DispatchMessageW', 'CreateWindowExW', 'RegisterClassW']
LOADER_ONLY = [('kernel32.dll', ['LoadLibraryA', 'GetProcAddress', 'VirtualProtect', 'ExitProcess'])]


def plain_pe(**overrides):
    """A compiler-shaped executable: code, read-only data, data, exceptions, resources, relocations; 23 imports."""
    sections = [{'name': '.text', 'data': pseudo_code(0x6000), 'chars': TEXT}, {'name': '.rdata', 'data': pseudo_code(0x2000, 3), 'chars': RDATA},
                {'name': '.data', 'data': bytes(0x400), 'vsize': 0x1000, 'chars': DATA}, {'name': '.pdata', 'data': pseudo_code(0x400, 4), 'chars': RDATA},
                {'name': '.rsrc', 'data': pseudo_code(0x400, 5), 'chars': RDATA}, {'name': '.reloc', 'data': pseudo_code(0x200, 6), 'chars': RDATA}]
    options = dict(imports=[('kernel32.dll', KERNEL32), ('user32.dll', USER32)], imports_in=1)
    options.update(overrides)
    return build_pe(options.pop('sections', sections), **options)


def upx_pe(names=('UPX0', 'UPX1', '.rsrc'), marker=b'UPX!', imports=LOADER_ONLY):
    stub = random_bytes(0x3000, 7)
    stub = stub[:0x40] + marker + stub[0x40 + len(marker):] if marker else stub
    return build_pe([{'name': names[0], 'data': b'', 'vsize': 0x20000, 'chars': RWX | SCN_UNINIT, 'raw': 0}, {'name': names[1], 'data': stub, 'chars': RWX},
                     {'name': names[2], 'data': pseudo_code(0x400, 5), 'chars': DATA}], entry=1, entry_offset=0x1000, imports=imports, imports_in=1)


def vmp_pe(random_names=True):
    names = ['.Tc!', '.B%h', '.u_{'] if random_names else ['.vmp0', '.vmp1', '.vmp2']
    return build_pe([{'name': '.text', 'data': b'', 'vsize': 0xf3c, 'chars': TEXT, 'raw': 0}, {'name': '.rdata', 'data': b'', 'vsize': 0xfea, 'chars': RDATA, 'raw': 0},
                     {'name': '.data', 'data': b'', 'vsize': 0x658, 'chars': DATA, 'raw': 0}, {'name': names[0], 'data': b'', 'vsize': 0xe9000, 'chars': TEXT, 'raw': 0},
                     {'name': names[1], 'data': pseudo_code(0x800, 8), 'chars': DATA}, {'name': names[2], 'data': random_bytes(0x20000, 9), 'chars': RWX},
                     {'name': '.rsrc', 'data': pseudo_code(0x200, 5), 'chars': RDATA}], entry=5, imports=[('kernel32.dll', KERNEL32[:12])], imports_in=4)


def ids(report):
    return [f['id'] for f in report['indicators']]


def analyze(data, **limits):
    return analyze_packing(data=data, limits=limits or None)


class Rules(unittest.TestCase):
    def test_shipped_table_validates(self):
        rules.validate()

    def test_validation_catches_each_kind_of_mistake(self):
        def broken(mutate):
            saved = (dict(rules.INDICATORS), dict(rules.SECTION_NAMES), rules.MARKERS, set(rules.STANDARD_NAMES), rules.STATUS_PACKED)
            try:
                mutate()
                with self.assertRaises(ValueError) as caught:
                    rules.validate()
                return str(caught.exception)
            finally:
                rules.INDICATORS.clear(); rules.INDICATORS.update(saved[0]); rules.SECTION_NAMES.clear(); rules.SECTION_NAMES.update(saved[1])
                rules.MARKERS = saved[2]; rules.STANDARD_NAMES = frozenset(saved[3]); rules.STATUS_PACKED = saved[4]
        self.assertIn('indicator x', broken(lambda: rules.INDICATORS.update(x=(0, ''))))
        self.assertIn('indicator y', broken(lambda: rules.INDICATORS.update(y=(500, 'too heavy'))))
        self.assertIn("section name 'Toolongname'", broken(lambda: rules.SECTION_NAMES.update(Toolongname=('X', 'compressor'))))
        self.assertIn("section name '.x'", broken(lambda: rules.SECTION_NAMES.update({'.x': ('X', 'wizard')})))
        self.assertIn('marker', broken(lambda: setattr(rules, 'MARKERS', ((b'', 'X', 'compressor'),))))
        self.assertIn('lower-case', broken(lambda: setattr(rules, 'STANDARD_NAMES', rules.STANDARD_NAMES | {'.Text'})))
        self.assertIn('also listed as standard', broken(lambda: setattr(rules, 'STANDARD_NAMES', rules.STANDARD_NAMES | {'upx0'})))
        self.assertIn('thresholds', broken(lambda: setattr(rules, 'STATUS_PACKED', 10)))

    def test_every_packer_has_a_name_a_kind_and_no_name_is_a_compiler_name(self):
        self.assertGreaterEqual(len(rules.SECTION_NAMES), 20)
        self.assertEqual({kind for _, kind in rules.SECTION_NAMES.values()}, {'compressor', 'protector'})


class Statistics(unittest.TestCase):
    def test_entropy_values(self):
        self.assertEqual(entropy(b''), 0.0)
        self.assertEqual(entropy(bytes(1000)), 0.0)
        self.assertAlmostEqual(entropy(bytes(range(256)) * 16), 8.0, places=9)
        self.assertAlmostEqual(entropy(b'ab' * 500), 1.0, places=9)
        self.assertGreater(entropy(random_bytes(1 << 16)), 7.99)
        self.assertTrue(5.0 < entropy(pseudo_code(1 << 16)) < 6.9, 'generated code must look like compiled code, or the thresholds are tested against the wrong thing')


class PlainPE(unittest.TestCase):
    def test_compiler_shaped_executable_is_plain(self):
        report = analyze(plain_pe())
        self.assertEqual((report['format'], report['status'], report['score'], report['bits']), ('pe', 'plain', 0, 64))
        self.assertEqual(report['indicators'], []); self.assertEqual(report['identified'], [])
        self.assertEqual(report['unpack'], {'attempted': False, 'status': 'not-applicable', 'reason': 'This analysis detects packing; it does not unpack.', 'next': []})
        self.assertEqual(report['imports']['functions'], 23); self.assertEqual(report['imports']['libraries'], ['kernel32.dll', 'user32.dll'])
        self.assertTrue(report['entry']['intact']); self.assertEqual(report['entry']['section'], '.text')
        self.assertEqual([s['name'] for s in report['sections']], ['.text', '.rdata', '.data', '.pdata', '.rsrc', '.reloc'])
        text = report['sections'][0]
        self.assertTrue(text['entry'] and text['executable'] and text['flags'] == 'rx' and 5.0 < text['entropy'] < 6.9)

    def test_pe32_is_read_too(self):
        report = analyze(plain_pe(plus=False))
        self.assertEqual((report['bits'], report['status'], report['imports']['functions']), (32, 'plain', 23))

    def test_exact_values_do_not_depend_on_the_sampling_budget(self):
        small = analyze(plain_pe(), max_bytes=2048)
        self.assertEqual(small['status'], 'plain'); self.assertLessEqual(small['coverage']['sampledBytes'], 2048)

    def test_compiler_conventions_are_not_suspicious(self):
        cases = {
            'textbss': lambda: plain_pe(sections=[{'name': '.text', 'data': pseudo_code(0x3000), 'chars': TEXT}, {'name': '.textbss', 'data': b'', 'vsize': 0x20000, 'chars': TEXT | SCN_UNINIT, 'raw': 0},
                                                  {'name': '.rdata', 'data': pseudo_code(0x800, 3), 'chars': RDATA}], imports_in=2),
            'bss': lambda: plain_pe(sections=[{'name': '.text', 'data': pseudo_code(0x3000), 'chars': TEXT}, {'name': '.rdata', 'data': pseudo_code(0x800, 3), 'chars': RDATA},
                                              {'name': '.bss', 'data': b'', 'vsize': 0x40000, 'chars': DATA | SCN_UNINIT, 'raw': 0}], imports_in=1),
            'mingw-debug-names': lambda: plain_pe(sections=[{'name': '.text', 'data': pseudo_code(0x3000), 'chars': TEXT}, {'name': '.rdata', 'data': pseudo_code(0x800, 3), 'chars': RDATA},
                                                            {'name': '/4', 'data': random_bytes(0x2000, 3), 'chars': RDATA}, {'name': '/19', 'data': random_bytes(0x20000, 4), 'chars': RDATA},
                                                            {'name': '.debug_info', 'data': random_bytes(0x2000, 5), 'chars': RDATA}], imports_in=1),
            'msvc-rdata': lambda: plain_pe(sections=[{'name': '.text', 'data': pseudo_code(0x3000), 'chars': TEXT}, {'name': '_RDATA', 'data': pseudo_code(0x800, 3), 'chars': RDATA},
                                                     {'name': '.rdata', 'data': pseudo_code(0x800, 3), 'chars': RDATA}], imports_in=2),
            'padding': lambda: plain_pe(sections=[{'name': '.text', 'data': pseudo_code(0x3000), 'chars': TEXT}, {'name': 'Pad1', 'data': b'', 'vsize': 0x50000, 'chars': TEXT, 'raw': 0},
                                                  {'name': '.rdata', 'data': pseudo_code(0x800, 3), 'chars': RDATA}], imports_in=2),
            'compressed-debug-and-resources-not-executable': lambda: plain_pe(sections=[{'name': '.text', 'data': pseudo_code(0x3000), 'chars': TEXT}, {'name': '.rdata', 'data': pseudo_code(0x800, 3), 'chars': RDATA},
                                                                                       {'name': '.rsrc', 'data': random_bytes(0x8000, 6), 'chars': RDATA}], imports_in=1),
            'library-without-entry': lambda: plain_pe(dll=True, entry_rva=0, imports=[('kernel32.dll', ['Sleep'])]),
        }
        for name, build in cases.items():
            with self.subTest(name):
                report = analyze(build())
                self.assertEqual((report['status'], ids(report)), ('plain', []), (name, report['score']))

    def test_dotnet_executables_import_almost_nothing_and_are_not_flagged(self):
        report = analyze(plain_pe(imports=[('mscoree.dll', ['_CorExeMain'])], managed=True))
        self.assertTrue(report['managed']); self.assertEqual(ids(report), [])
        self.assertEqual(ids(analyze(plain_pe(imports=[('mscoree.dll', ['_CorExeMain'])]))), [], 'the runtime DLL alone is enough, even without the COM descriptor')
        self.assertEqual(ids(analyze(plain_pe(imports=[('kernel32.dll', ['Sleep'])], managed=True))), [], 'a managed image is judged by its metadata, not its import table')
        self.assertIn('few-imports', ids(analyze(plain_pe(imports=[('kernel32.dll', ['Sleep'])]))))

    def test_kernel_images_keep_discardable_sections_by_design(self):
        sections = [{'name': '.text', 'data': pseudo_code(0x3000), 'chars': TEXT}, {'name': 'PAGE', 'data': pseudo_code(0x1000, 3), 'chars': TEXT}, {'name': 'Pad2', 'data': b'', 'vsize': 0x80000, 'chars': TEXT, 'raw': 0},
                    {'name': 'INIT', 'data': pseudo_code(0x800, 4), 'chars': TEXT}, {'name': 'POOLCODE', 'data': pseudo_code(0x400, 5), 'chars': TEXT}, {'name': '.rdata', 'data': pseudo_code(0x800, 3), 'chars': RDATA}]
        driver = analyze(build_pe(sections, entry=3, subsystem=1, imports=[('ntoskrnl.exe', ['IoCreateDevice'])], imports_in=5))
        self.assertEqual(ids(driver), [], 'discardable sections, padding and an INIT entry are normal in kernel-mode images')
        user_mode = analyze(build_pe(sections, entry=3, subsystem=3, imports=[('ntoskrnl.exe', ['IoCreateDevice'])], imports_in=5))
        self.assertIn('entry-nonstandard-section', ids(user_mode), 'the same layout in a user-mode image is odd')


class Packed(unittest.TestCase):
    def test_upx_with_its_own_section_names(self):
        report = analyze(upx_pe())
        self.assertEqual((report['status'], report['score']), ('packed', 100))
        self.assertEqual([(i['name'], i['confidence']) for i in report['identified']], [('UPX', 'name-only'), ('UPX', 'marker')])
        for wanted in ('signature-name', 'signature-marker', 'upx-like-layout', 'encrypted-exec', 'virtual-only-exec', 'entry-in-writable', 'loader-imports', 'few-imports', 'rwx-section'):
            self.assertIn(wanted, ids(report))
        self.assertEqual(report['kind'], 'compressor'); self.assertEqual(report['unpack']['status'], 'not-unpacked')
        self.assertTrue(any('upx -d' in step for step in report['unpack']['next'])); self.assertTrue(any('ig5_dbg' in step for step in report['unpack']['next']))

    def test_renamed_upx_is_still_found_by_structure(self):
        report = analyze(upx_pe(names=('.a', '.b', '.c'), marker=b''))
        self.assertEqual(report['status'], 'packed')
        self.assertEqual([(i['name'], i['confidence']) for i in report['identified']], [('UPX-style stub', 'structural')])
        self.assertNotIn('signature-name', ids(report)); self.assertIn('upx-like-layout', ids(report))
        self.assertGreaterEqual(report['score'], rules.STATUS_PACKED)

    def test_protector_layout_with_random_names_and_emptied_sections(self):
        report = analyze(vmp_pe())
        self.assertEqual(report['status'], 'packed')
        for wanted in ('emptied-code-section', 'random-section-names', 'entry-nonstandard-section', 'virtual-only-exec', 'protector-layout'):
            self.assertIn(wanted, ids(report))
        self.assertEqual([(i['name'], i['kind'], i['confidence']) for i in report['identified']], [('Unidentified protector', 'protector', 'structural')])

    def test_known_name_with_entry_still_in_ordinary_code_is_protected_not_packed(self):
        sections = [{'name': '.text', 'data': pseudo_code(0x3000), 'chars': TEXT}, {'name': '.rdata', 'data': pseudo_code(0x800, 3), 'chars': RDATA}, {'name': '.vmp0', 'data': random_bytes(0x8000, 6), 'chars': TEXT | SCN_WRITE}]
        report = analyze(build_pe(sections, entry=0, imports=[('kernel32.dll', KERNEL32[:8])], imports_in=1))
        self.assertEqual(report['status'], 'protected', (ids(report), report['score']))
        self.assertEqual(report['identified'][0]['name'], 'VMProtect'); self.assertTrue(report['entry']['intact'])
        self.assertTrue(report['unpack']['next'][0].startswith('The entry point is still in ordinary code'))

    def test_a_name_alone_is_only_a_lead(self):
        sections = [{'name': '.text', 'data': pseudo_code(0x3000), 'chars': TEXT}, {'name': '.themida', 'data': pseudo_code(0x200, 3), 'chars': RDATA}]
        report = analyze(build_pe(sections, imports=[('kernel32.dll', KERNEL32)], imports_in=1))
        self.assertEqual(report['status'], 'suspected' if report['score'] >= rules.STATUS_SUSPECTED else 'plain')
        self.assertEqual(report['identified'][0]['confidence'], 'name-only')
        self.assertEqual(report['score'], rules.INDICATORS['signature-name'][0], 'nothing structural backs the name, so the name is the whole score')

    def test_encrypted_entry_section_without_any_name(self):
        sections = [{'name': '.text', 'data': random_bytes(0x6000, 3), 'chars': TEXT}, {'name': '.rdata', 'data': pseudo_code(0x800, 3), 'chars': RDATA}]
        report = analyze(build_pe(sections, imports=[('kernel32.dll', KERNEL32)], imports_in=1))
        self.assertIn('encrypted-exec', ids(report)); self.assertEqual(report['status'], 'suspected')
        high = analyze(build_pe([{**sections[0], 'data': (pseudo_code(0x3000, 1) + random_bytes(0x3000, 5))}, sections[1]], imports=[('kernel32.dll', KERNEL32)], imports_in=1))
        self.assertIn(ids(high)[0], ('high-entropy-exec', 'encrypted-exec'))

    def test_entry_outside_every_section_and_before_the_code(self):
        self.assertIn('entry-outside-sections', ids(analyze(plain_pe(entry_rva=0x900000))))
        self.assertNotIn('entry-outside-sections', ids(analyze(plain_pe(entry_rva=0x200))), 'an entry inside the headers is odd but not "outside"')

    def test_few_imports_and_loader_only_imports(self):
        sections = [{'name': '.text', 'data': pseudo_code(0x6000), 'chars': TEXT}, {'name': '.rdata', 'data': pseudo_code(0x2000, 3), 'chars': RDATA}]
        few = analyze(build_pe(sections, imports=[('kernel32.dll', ['ExitProcess', 'Sleep'])], imports_in=1))
        self.assertIn('few-imports', ids(few)); self.assertNotIn('loader-imports', ids(few))
        loader = analyze(build_pe(sections, imports=LOADER_ONLY, imports_in=1))
        self.assertIn('loader-imports', ids(loader))
        rich = analyze(build_pe(sections, imports=[('kernel32.dll', KERNEL32)], imports_in=1))
        self.assertNotIn('few-imports', ids(rich)); self.assertNotIn('loader-imports', ids(rich), 'LoadLibrary among eighteen other imports is ordinary')
        self.assertIn('few-imports', ids(analyze(build_pe(sections))), 'no import table at all')

    def test_tls_callbacks_and_big_encrypted_overlay(self):
        sections = [{'name': '.text', 'data': pseudo_code(0x6000), 'chars': TEXT}, {'name': '.rdata', 'data': pseudo_code(0x2000, 3), 'chars': RDATA}]
        tls = analyze(build_pe(sections, imports=[('kernel32.dll', KERNEL32)], imports_in=1, tls_callbacks=2, tls_in=1))
        self.assertIn('tls-callbacks', ids(tls)); self.assertIn('2 callback', next(f for f in tls['indicators'] if f['id'] == 'tls-callbacks')['detail'])
        sfx = analyze(build_pe(sections, imports=[('kernel32.dll', KERNEL32)], imports_in=1, overlay=random_bytes(0x40000, 8)))
        self.assertIn('overlay-encrypted', ids(sfx)); self.assertEqual(sfx['status'], 'plain', 'an installer-style overlay alone proves nothing')
        small = analyze(build_pe(sections, imports=[('kernel32.dll', KERNEL32)], imports_in=1, overlay=random_bytes(0x1000, 8)))
        self.assertNotIn('overlay-encrypted', ids(small))

    def test_random_section_names_need_company(self):
        sections = lambda names: [{'name': names[0], 'data': pseudo_code(0x3000), 'chars': TEXT}, {'name': names[1], 'data': pseudo_code(0x800, 3), 'chars': RDATA}, {'name': names[2], 'data': pseudo_code(0x800, 4), 'chars': DATA}]
        one = analyze(build_pe(sections(['.text', '.rdata', b'.\x01\x02x']), imports=[('kernel32.dll', KERNEL32)], imports_in=1))
        self.assertNotIn('random-section-names', ids(one))
        two = analyze(build_pe(sections([b'.\x01a', b'.\x02b', '.data']), imports=[('kernel32.dll', KERNEL32)], imports_in=1))
        self.assertIn('random-section-names', ids(two))
        custom = analyze(build_pe(sections(['.text', 'RT_CODE', 'RT_DATA']), imports=[('kernel32.dll', KERNEL32)], imports_in=1))
        self.assertEqual(custom['status'], 'plain'); self.assertEqual(custom['score'], 6, 'two custom names, three points each')
        capped = analyze(build_pe([{'name': f'.c{i}', 'data': pseudo_code(0x400, i), 'chars': RDATA} for i in range(1, 8)] + [{'name': '.text', 'data': pseudo_code(0x3000), 'chars': TEXT}], entry=7, imports=[('kernel32.dll', KERNEL32)], imports_in=0))
        self.assertEqual(next(f for f in capped['indicators'] if f['id'] == 'nonstandard-section-names')['weight'], 9)


class Markers(unittest.TestCase):
    def test_marker_must_sit_in_executable_data(self):
        sections = [{'name': '.text', 'data': pseudo_code(0x3000), 'chars': TEXT}, {'name': '.rdata', 'data': pseudo_code(0x800, 3) + b'signatures: UPX! MPRESS' + bytes(100), 'chars': RDATA}]
        scanner = analyze(build_pe(sections, imports=[('kernel32.dll', KERNEL32)], imports_in=1))
        self.assertEqual((scanner['status'], scanner['identified']), ('plain', []), 'a scanner that merely lists the UPX string is not packed')
        inside = [{'name': '.text', 'data': pseudo_code(0x40) + b'UPX!' + pseudo_code(0x3000), 'chars': TEXT}, sections[1]]
        found = analyze(build_pe(inside, imports=[('kernel32.dll', KERNEL32)], imports_in=1))
        self.assertEqual([i['confidence'] for i in found['identified']], ['marker']); self.assertIn('signature-marker', ids(found))

    def test_marker_straddling_a_read_chunk_is_found(self):
        text = bytes(1 << 20) [:(1 << 20) - 2] + b'UPX!' + bytes(100)
        sections = [{'name': '.text', 'data': text, 'chars': TEXT}, {'name': '.rdata', 'data': pseudo_code(0x800, 3), 'chars': RDATA}]
        self.assertEqual([i['name'] for i in analyze(build_pe(sections, imports=[('kernel32.dll', KERNEL32)], imports_in=1))['identified']], ['UPX'])


class Hostile(unittest.TestCase):
    def test_unknown_formats(self):
        for data in (b'', b'MZ', b'hello world' * 10, bytes(64), b'\x7fELF'):
            report = analyze(data)
            self.assertIn(report['format'], ('unknown', 'pe')); self.assertIn(report['status'], ('unknown',))

    def test_every_truncation_point_returns_a_report(self):
        for original in (plain_pe(), upx_pe(), build_elf([{'flags': 'rx', 'data': pseudo_code(0x2000)}, {'flags': 'rw', 'data': bytes(0x100)}])):
            for cut in range(0, len(original), max(1, len(original) // 150)):
                report = analyze(original[:cut])
                self.assertIn(report['status'], ('plain', 'suspected', 'protected', 'packed', 'unknown'), cut)
                self.assertEqual(report['schema'], 'ig5.packing.v1')

    def test_corrupted_headers_do_not_raise(self):
        base = bytearray(plain_pe())
        rng = __import__('random').Random(5)
        for _ in range(400):
            data = bytearray(base)
            for _ in range(rng.randrange(1, 12)):
                data[rng.randrange(0, 0x400)] = rng.randrange(256)
            report = analyze(bytes(data))
            self.assertIn('status', report)

    def test_header_inconsistencies_are_reported(self):
        shorter = analyze(plain_pe()[:-0x600])
        self.assertIn('header-anomaly', ids(shorter)); self.assertIn('extends past the end', next(f for f in shorter['indicators'] if f['id'] == 'header-anomaly')['detail'])
        small_image = analyze(plain_pe(image_size_delta=-0x4000))
        self.assertIn('SizeOfImage', next(f for f in small_image['indicators'] if f['id'] == 'header-anomaly')['detail'])
        data = bytearray(plain_pe())
        struct.pack_into('<H', data, 0x80 + 6, 50)                    # claims fifty sections, the table only holds six plus data
        self.assertIn('header-anomaly', ids(analyze(bytes(data))))

    def test_unreadable_import_table_is_not_fatal(self):
        data = bytearray(plain_pe())
        directory = 0x80 + 24 + 112 + 8
        struct.pack_into('<II', data, directory, 0x7fff0000, 100)
        report = analyze(bytes(data))
        self.assertEqual(report['imports']['functions'], 0)

    def test_budget_is_respected(self):
        big = plain_pe(sections=[{'name': '.text', 'data': pseudo_code(1 << 20), 'chars': TEXT}, {'name': '.rdata', 'data': pseudo_code(0x800, 3), 'chars': RDATA}], imports_in=1)
        report = analyze(big, max_bytes=100000)
        self.assertLessEqual(report['coverage']['sampledBytes'], 100000)             # headers, import tables and the marker scan are bounded separately
        self.assertGreater(report['coverage']['sampledBytes'], 0); self.assertEqual(report['coverage']['markerScanBytes'], len(big))
        self.assertEqual(analyze(big)['status'], analyze(big, max_bytes=100000)['status'])

    def test_result_is_deterministic_and_json_serialisable(self):
        first, second = analyze(upx_pe()), analyze(upx_pe())
        self.assertEqual(first, second); json.dumps(first)

    def test_file_and_bytes_agree(self):
        data = upx_pe()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sample.exe'
            path.write_bytes(data)
            self.assertEqual(analyze_packing(str(path)), analyze_packing(data=data))
        self.assertFalse((Path(directory) / 'sample.exe').exists())


class ELF(unittest.TestCase):
    def plain(self, **overrides):
        options = dict(segments=[{'flags': 'r', 'data': pseudo_code(0x200)}, {'flags': 'rx', 'data': pseudo_code(0x4000)}, {'flags': 'rw', 'data': bytes(0x200)}], entry_segment=1, interp=True, dynamic=True)
        options.update(overrides)
        return build_elf(options.pop('segments'), **options)

    def test_ordinary_dynamic_executable(self):
        report = analyze(self.plain())
        self.assertEqual((report['format'], report['bits'], report['status'], report['score']), ('elf', 64, 'plain', 0), ids(report))
        self.assertTrue(report['hasSectionHeaders'])

    def test_elf32(self):
        self.assertEqual(analyze(self.plain(is64=False))['bits'], 32)
        self.assertEqual(analyze(self.plain(is64=False))['status'], 'plain')

    def test_upx_style_elf(self):
        data = build_elf([{'flags': 'rwx', 'data': random_bytes(0x4000, 3) , 'memsz': 0x20000}, {'flags': 'rw', 'data': bytes(0x100)}], entry_segment=0, sections=False, marker=b'UPX!')
        report = analyze(data)
        self.assertEqual(report['status'], 'packed', ids(report))
        for wanted in ('elf-no-sections', 'elf-rwx-segment', 'elf-high-entropy-load', 'elf-entry-in-writable', 'signature-marker', 'elf-few-loads'):
            self.assertIn(wanted, ids(report))
        self.assertEqual([(i['name'], i['confidence']) for i in report['identified']], [('UPX', 'marker')])

    def test_each_elf_indicator_alone(self):
        self.assertIn('elf-no-sections', ids(analyze(self.plain(sections=False))))
        rwx = analyze(self.plain(segments=[{'flags': 'r', 'data': pseudo_code(0x200)}, {'flags': 'rwx', 'data': pseudo_code(0x4000)}], entry_segment=1))
        self.assertIn('elf-rwx-segment', ids(rwx)); self.assertIn('elf-entry-in-writable', ids(rwx))
        late = analyze(self.plain(segments=[{'flags': 'rx', 'data': pseudo_code(0x1000)}, {'flags': 'rx', 'data': pseudo_code(0x4000)}, {'flags': 'rw', 'data': bytes(0x200)}], entry_segment=1))
        self.assertIn('elf-entry-not-first-code', ids(late))
        hot = analyze(self.plain(segments=[{'flags': 'r', 'data': pseudo_code(0x200)}, {'flags': 'rx', 'data': random_bytes(0x4000, 4)}, {'flags': 'rw', 'data': bytes(0x200)}]))
        self.assertIn('elf-high-entropy-load', ids(hot))
        static = analyze(build_elf([{'flags': 'rx', 'data': pseudo_code(0x4000)}, {'flags': 'rw', 'data': bytes(0x200)}]))
        self.assertIn('elf-few-loads', ids(static)); self.assertEqual(static['status'], 'plain')

    def test_marker_must_be_near_the_start(self):
        data = bytearray(self.plain())
        far = len(data) + 5
        data += bytes(0x20000) + b'UPX!'
        self.assertEqual(analyze(bytes(data))['identified'], [])
        self.assertEqual([i['name'] for i in analyze(self.plain(marker=b'UPX!'))['identified']], ['UPX'])




class Boundaries(unittest.TestCase):
    """Each case sits just either side of a threshold or exemption; found by mutating the analyzer and seeing what no test noticed."""

    def pe(self, extra=None, **kw):
        sections = [{'name': '.text', 'data': pseudo_code(0x6000), 'chars': TEXT}, {'name': '.rdata', 'data': pseudo_code(0x2000, 3), 'chars': RDATA}] + (extra or [])
        kw.setdefault('imports', [('kernel32.dll', KERNEL32)]); kw.setdefault('imports_in', 1)
        return build_pe(sections, **kw)

    def test_verdict_thresholds_are_inclusive(self):
        from packer_analysis import _verdict
        row = lambda weight: [{'id': 'x', 'weight': weight}]
        self.assertEqual([_verdict(row(w), [], False)[1] for w in (29, 30, 59, 60)], ['plain', 'suspected', 'suspected', 'packed'])
        self.assertEqual(_verdict(row(60), [{'name': 'X'}], True)[1], 'protected'); self.assertEqual(_verdict(row(60), [], True)[1], 'packed', 'no identification, no "protected"')
        self.assertEqual(_verdict(row(150), [], False)[0], 100)

    def test_empty_sections_must_be_big_enough_to_matter(self):
        small_target = analyze(self.pe([{'name': '.zz', 'data': b'', 'vsize': 0x3000, 'chars': RWX | SCN_UNINIT, 'raw': 0}]))
        self.assertNotIn('virtual-only-exec', ids(small_target))
        big = analyze(self.pe([{'name': '.zz', 'data': b'', 'vsize': 0x4000, 'chars': RWX | SCN_UNINIT, 'raw': 0}]))
        self.assertIn('virtual-only-exec', ids(big))
        tiny_empty_code = analyze(self.pe([{'name': '.zz', 'data': b'', 'vsize': 0xff, 'chars': TEXT, 'raw': 0}]))
        self.assertNotIn('emptied-code-section', ids(tiny_empty_code))
        self.assertIn('emptied-code-section', ids(analyze(self.pe([{'name': '.zz', 'data': b'', 'vsize': 0x100, 'chars': TEXT, 'raw': 0}]))))

    def test_rwx_needs_all_three_permissions(self):
        write_exec_only = analyze(self.pe([{'name': '.zz', 'data': pseudo_code(0x400, 9), 'chars': SCN_EXEC | SCN_WRITE}]))
        self.assertNotIn('rwx-section', ids(write_exec_only))
        self.assertIn('rwx-section', ids(analyze(self.pe([{'name': '.zz', 'data': pseudo_code(0x400, 9), 'chars': SCN_EXEC | SCN_WRITE | SCN_READ}]))))

    def test_entropy_needs_enough_bytes_and_the_right_section(self):
        tiny = analyze(self.pe([{'name': '.zz', 'data': random_bytes(0x800, 4), 'chars': TEXT}]))
        self.assertNotIn('encrypted-exec', ids(tiny)); self.assertNotIn('high-entropy-exec', ids(tiny), 'two kilobytes of random bytes say nothing about the section')
        enough = analyze(self.pe([{'name': '.zz', 'data': random_bytes(0x1000, 4), 'chars': TEXT}]))
        self.assertIn('encrypted-exec', ids(enough))
        small_resources = analyze(self.pe([{'name': '.rsrc', 'data': random_bytes(0x8000, 4), 'chars': RDATA}]))
        self.assertNotIn('high-entropy-resources', ids(small_resources))
        self.assertIn('high-entropy-resources', ids(analyze(self.pe([{'name': '.rsrc', 'data': random_bytes(0x10000, 4), 'chars': RDATA}]))))

    def test_encrypted_and_merely_high_entropy_are_told_apart(self):
        from packer_analysis import entropy
        between = pseudo_code(0x1000, 1) + random_bytes(0x1800, 2)
        value = entropy(between)
        self.assertTrue(rules.ENTROPY_PACKED <= value < rules.ENTROPY_ENCRYPTED, f'fixture must sit between the thresholds, got {value:.2f}')
        result = analyze(self.pe([{'name': '.zz', 'data': between, 'chars': TEXT}]))
        self.assertIn('high-entropy-exec', ids(result)); self.assertNotIn('encrypted-exec', ids(result))

    def test_import_count_boundaries(self):
        names = lambda n: [('kernel32.dll', [f'Fn{i}' for i in range(n)])]
        self.assertIn('few-imports', ids(analyze(self.pe(imports=names(rules.FEW_IMPORTS)))))
        self.assertNotIn('few-imports', ids(analyze(self.pe(imports=names(rules.FEW_IMPORTS + 1)))))
        tiny = build_pe([{'name': '.text', 'data': pseudo_code(0x800), 'chars': TEXT}, {'name': '.rdata', 'data': pseudo_code(0x400, 3), 'chars': RDATA}], imports=names(3), imports_in=1)
        self.assertNotIn('few-imports', ids(analyze(tiny)), 'a tiny program with a few imports is just a tiny program')
        no_getproc = analyze(self.pe(imports=[('kernel32.dll', ['LoadLibraryA', 'ExitProcess', 'VirtualAlloc'])]))
        self.assertNotIn('loader-imports', ids(no_getproc))
        extra = analyze(self.pe(imports=[('kernel32.dll', ['LoadLibraryA', 'GetProcAddress'] + [f'Other{i}' for i in range(8)])]))
        self.assertNotIn('loader-imports', ids(extra), 'a loader pair plus eight unrelated imports is an ordinary program')

    def test_overlay_must_be_large_and_random(self):
        quiet = analyze(self.pe(overlay=bytes(0x40000)))
        self.assertNotIn('overlay-encrypted', ids(quiet)); self.assertEqual(quiet['overlay']['entropy'], 0.0)
        big = analyze(self.pe(overlay=random_bytes(0x40000, 8)))
        self.assertIn('overlay-encrypted', ids(big))

    def test_memory_overlap_and_declared_section_count(self):
        overlapping = analyze(build_pe([{'name': '.text', 'data': pseudo_code(0x2000), 'chars': TEXT, 'va': 0x1000}, {'name': '.data', 'data': pseudo_code(0x400, 3), 'chars': DATA, 'va': 0x1800}],
                                       imports=[('kernel32.dll', KERNEL32)], imports_in=0))
        self.assertIn('overlap in memory', next(f for f in overlapping['indicators'] if f['id'] == 'header-anomaly')['detail'])
        cut = self.pe()[:0x80 + 24 + 240 + 40]                            # the table ends after one of the two declared sections
        detail = next(f for f in analyze(cut)['indicators'] if f['id'] == 'header-anomaly')['detail']
        self.assertIn('2 sections declared, 1 readable', detail)

    def upx_variant(self, entry=1, stub=None, first_raw=0, first_virtual=0x20000):
        stub = random_bytes(0x3000, 7) if stub is None else stub
        data = build_pe([{'name': '.a', 'data': bytes(first_raw), 'vsize': first_virtual, 'chars': RWX | SCN_UNINIT, 'raw': first_raw}, {'name': '.b', 'data': stub, 'chars': RWX},
                         {'name': '.c', 'data': pseudo_code(0x400, 5), 'chars': DATA}], entry=entry, imports=LOADER_ONLY, imports_in=2)
        return 'upx-like-layout' in ids(analyze(data))

    def test_upx_like_layout_needs_every_part(self):
        self.assertIn('upx-like-layout', ids(analyze(upx_pe(names=('.a', '.b', '.c'), marker=b''))))
        self.assertEqual(self.upx_variant(entry=0), False, 'entry in the empty first section')
        self.assertEqual(self.upx_variant(entry=2), False, 'entry in the third section')
        self.assertEqual(self.upx_variant(stub=pseudo_code(0x3000, 4)), False, 'a low-entropy second section is not compressed data')
        self.assertEqual(self.upx_variant(first_raw=0x200), False, 'the first section has file content')
        self.assertEqual(self.upx_variant(first_virtual=0x2000), False, 'the empty section is too small to unpack into')
        self.assertEqual(self.upx_variant(first_virtual=0x4000, stub=random_bytes(0x6000, 3)), False, 'it must also be at least as large as the packed data')
        self.assertEqual(self.upx_variant(), True)

    def test_unidentified_protector_needs_the_whole_layout(self):
        self.assertIn('protector-layout', ids(analyze(vmp_pe())))
        self.assertNotIn('protector-layout', ids(analyze(vmp_pe(random_names=False))), 'named sections are identified by name instead')
        sections = [{'name': '.text', 'data': b'', 'vsize': 0xf3c, 'chars': TEXT, 'raw': 0}, {'name': '.data', 'data': pseudo_code(0x400, 5), 'chars': DATA}, {'name': '.rsrc', 'data': pseudo_code(0x400, 5), 'chars': RDATA}]
        self.assertNotIn('protector-layout', ids(analyze(build_pe(sections, entry=1, imports=[('kernel32.dll', KERNEL32)], imports_in=1))), 'emptied code alone, ordinary names and a plain entry section')

    def test_protector_layout_is_not_claimed_when_a_name_already_identifies_it_or_nothing_was_emptied(self):
        named = [{'name': '.text', 'data': b'', 'vsize': 0xf3c, 'chars': TEXT, 'raw': 0}, {'name': '.themida', 'data': pseudo_code(0x400, 5), 'chars': DATA}, {'name': b'.a', 'data': pseudo_code(0x400, 5), 'chars': DATA},
                 {'name': b'.b', 'data': random_bytes(0x8000, 9), 'chars': RWX}]
        report = analyze(build_pe(named, entry=3, imports=[('kernel32.dll', KERNEL32)], imports_in=1))
        self.assertNotIn('protector-layout', ids(report)); self.assertEqual([i['name'] for i in report['identified']], ['Themida/WinLicense'])
        nothing_emptied = [{'name': '.text', 'data': pseudo_code(0x800, 3), 'chars': TEXT}, {'name': b'.a', 'data': pseudo_code(0x400, 5), 'chars': DATA}, {'name': b'.b', 'data': random_bytes(0x8000, 9), 'chars': RWX}]
        self.assertNotIn('protector-layout', ids(analyze(build_pe(nothing_emptied, entry=2, imports=[('kernel32.dll', KERNEL32)], imports_in=1))))

    def test_protected_requires_an_intact_entry(self):
        standard = [{'name': '.text', 'data': pseudo_code(0x3000), 'chars': TEXT}, {'name': '.rdata', 'data': pseudo_code(0x800, 3), 'chars': RDATA}, {'name': '.vmp0', 'data': random_bytes(0x8000, 6), 'chars': TEXT | SCN_WRITE}]
        build = lambda sections, entry: analyze(build_pe(sections, entry=entry, imports=[('kernel32.dll', KERNEL32[:8])], imports_in=1))['status']
        self.assertEqual(build(standard, 0), 'protected')
        self.assertEqual(build([{**standard[0], 'name': 'CODEX'}] + standard[1:], 0), 'packed', 'the entry section name is not an ordinary code section')
        self.assertEqual(build([{**standard[0], 'data': random_bytes(0x3000, 1)}] + standard[1:], 0), 'packed', 'compressed entry code is not intact')
        self.assertEqual(build(standard, 2), 'packed')

    def test_marker_straddling_a_read_boundary_is_found(self):
        raw = analyze(self.pe())['sections'][0]['rawPointer']
        offset = (1 << 20) - 2 - raw                                  # the four marker bytes cover file offsets 2^20-2 .. 2^20+1
        sections = [{'name': '.text', 'data': bytes(offset) + b'UPX!' + bytes(100), 'chars': TEXT}, {'name': '.rdata', 'data': pseudo_code(0x800, 3), 'chars': RDATA}]
        found = analyze(build_pe(sections, imports=[('kernel32.dll', KERNEL32)], imports_in=1))
        self.assertEqual([i['name'] for i in found['identified']], ['UPX'])

    def test_every_sampled_chunk_counts(self):
        from packer_analysis import _Source, _sample_entropy, DEFAULT_LIMITS
        data = bytes(0x100000 - 0x10000) + random_bytes(0x10000, 3)       # silent except for the last 64 KiB
        value, used = _sample_entropy(_Source(data=data), 0, len(data), DEFAULT_LIMITS, [DEFAULT_LIMITS['max_bytes']])
        self.assertGreater(value, 1.5); self.assertEqual(used, 4 * 64 * 1024)

    def test_elf_dynamic_and_interpreter_flags_each_count(self):
        segments = [{'flags': 'rx', 'data': pseudo_code(0x4000)}, {'flags': 'rw', 'data': bytes(0x200)}]
        self.assertNotIn('elf-few-loads', ids(analyze(build_elf(segments, dynamic=True))))
        self.assertNotIn('elf-few-loads', ids(analyze(build_elf(segments, interp=True))))
        self.assertIn('elf-few-loads', ids(analyze(build_elf(segments))))


# ---- real files --------------------------------------------------------------------------------------------------------

CORPUS = Path(os.environ.get('IG5_PROTECTION_CORPUS') or Path.home() / '.dsh' / 'ig5' / 'artifacts' / 'corpus-expansion-20261014' / 'corpus')
# Labels come from how the corpus describes its files (protection tool or original name), not from this detector:
#   derived/no_protections_packed_vmp*.exe = VMProtect 3.6 "packed" variants, vmp-lab and vmp-research *.vmp.exe = VMProtect, salwan *.vmp.bin = VMProtect (ELF),
#   plain counterparts test.exe / sample*.bin and the Tigress samples are the unprotected originals or source-level obfuscations (normal ELF structure).
PROTECTED_FILES = ['derived/no_protections_packed_vmp%d.exe' % i for i in range(1, 8)] + ['vmp-lab/Challenge/(Lv01)-chall-x64.vmp.exe', 'vmp-lab/Challenge/(Lv01)-chall-x86.vmp.exe',
                   'vmp-research/test1/test.vmp.exe', 'salwan-vmp/vmp_binaries/binaries/sample1.vmp.bin', 'salwan-vmp/vmp_binaries/binaries/sample5.vmp.bin', 'salwan-vmp/vmp_binaries/binaries/sample6.vmp.bin']
PLAIN_FILES = ['vmp-research/test1/test.exe', 'salwan-vmp/vmp_binaries/binaries/sample1.bin', 'salwan-vmp/vmp_binaries/binaries/sample5.bin', 'salwan-vmp/vmp_binaries/binaries/sample6.bin']
# derived/ files identified by their section tables (UPX0/UPX1, .themida, renamed UPX stubs); the SHA-256 prefix is the file name.
PACKED_BY_PREFIX = {'5677a1d4': 'UPX', 'e116d143': 'UPX', 'fe3d0b7a': 'UPX', '31de7bde': 'Themida/WinLicense', '8ebb3580': 'ASPack', '8d2e867b': 'UPX-style stub', 'a94b3bce': 'UPX-style stub', 'e2f3f85e': 'UPX-style stub'}


@unittest.skipUnless((CORPUS / 'derived').is_dir(), f'real protection corpus not found at {CORPUS}')
class RealCorpus(unittest.TestCase):
    def test_protected_files_are_flagged_and_unprotected_originals_are_not(self):
        for relative in PROTECTED_FILES:
            with self.subTest(relative):
                report = analyze_packing(str(CORPUS / relative))
                self.assertIn(report['status'], ('packed', 'protected'), (relative, report['status'], ids(report)))
        for relative in PLAIN_FILES:
            with self.subTest(relative):
                self.assertEqual(analyze_packing(str(CORPUS / relative))['status'], 'plain', relative)

    def test_known_packers_are_named_even_when_sections_are_renamed(self):
        for prefix, name in PACKED_BY_PREFIX.items():
            path = next(iter(glob.glob(str(CORPUS / 'derived' / (prefix + '*')))), None)
            with self.subTest(prefix):
                self.assertIsNotNone(path)
                report = analyze_packing(path)
                self.assertEqual(report['status'], 'packed', (prefix, ids(report)))
                self.assertIn(name, [i['name'] for i in report['identified']])

    @staticmethod
    def magic(path):
        with open(path, 'rb') as stream:
            return stream.read(4)

    def test_tigress_source_level_obfuscation_is_not_called_packed(self):
        files = sorted(glob.glob(str(CORPUS / 'tigress' / '**' / '*'), recursive=True))
        elfs = [f for f in files if os.path.isfile(f) and self.magic(f) == b'\x7fELF']
        self.assertGreaterEqual(len(elfs), 20)
        self.assertEqual([f for f in elfs if analyze_packing(f)['status'] != 'plain'], [])

    def test_no_clean_corpus_executable_is_called_packed(self):
        clean = ['17d59691', '26461a60', '2abf0aab', '31bb7af8', '37875703', '6296cbd8', '72106d93', '895664c5', '94fb3e3d', '97fc1b5a', '986acccb', '9c7b713a', 'ad32240b', 'b53bf960', 'c2a2ab5c', 'd3283413', 'f8d5d7e9']
        for prefix in clean:
            path = next(iter(glob.glob(str(CORPUS / 'derived' / (prefix + '*')))), None)
            if path:
                with self.subTest(prefix):
                    self.assertEqual(analyze_packing(path)['status'], 'plain', (prefix, ids(analyze_packing(path))))


WINDOWS = Path(os.environ.get('SystemRoot', r'C:\Windows'))


@unittest.skipUnless((WINDOWS / 'System32').is_dir(), 'Windows system directory not found')
class RealSystemFiles(unittest.TestCase):
    def test_system_binaries_are_almost_never_flagged_and_never_called_packed(self):
        files = []
        for directory in ('System32', 'SysWOW64'):
            for pattern in ('*.exe', '*.dll', '*.sys'):
                files += sorted(glob.glob(str(WINDOWS / directory / pattern)))
        files = files[::5] or files                    # a deterministic fifth keeps the run short; the full sweep was done by hand
        self.assertGreaterEqual(len(files), 300)
        counts, flagged = {}, []
        for path in files:
            report = analyze_packing(path)
            counts[report['status']] = counts.get(report['status'], 0) + 1
            if report['status'] in ('packed', 'protected'):
                flagged.append((path, ids(report)))
        self.assertEqual(flagged, [], 'a clean Windows file was called packed or protected')
        self.assertGreaterEqual(counts.get('plain', 0) / len(files), 0.97, counts)


# ---- real Ghidra acceptance -------------------------------------------------------------------------------------------

class GhidraAcceptance(unittest.TestCase):
    runtime = False

    def test_scan_reports_packing_for_the_generated_images(self):
        if not self.runtime:
            self.skipTest('run with --runtime ghidra')
        from ghidra_session import GhidraSession
        results = {}
        for label, image in (('plain', plain_pe()), ('upx', upx_pe())):
            with GhidraSession(image, filename=label + '.exe', timeout=240) as session:
                results[label] = session.rpc('scan')
        self.assertEqual(results['plain']['packing']['status'], 'plain'); self.assertEqual(results['upx']['packing']['status'], 'packed')
        self.assertIn('UPX', [i['name'] for i in results['upx']['packing']['identified']])
        print(json.dumps({'engine': 'ghidra', 'plain': results['plain']['packing']['status'], 'upx': results['upx']['packing']['status'], 'identified': [i['name'] for i in results['upx']['packing']['identified']]}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', choices=['none', 'ghidra'], default='none')
    options, rest = parser.parse_known_args()
    GhidraAcceptance.runtime = options.runtime == 'ghidra'
    unittest.main(argv=[sys.argv[0], *rest], verbosity=1)
