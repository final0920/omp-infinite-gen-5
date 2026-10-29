"""String decoding: scoring, argument planning, text extraction, orchestration, and a real-Unicorn end-to-end run.

The end-to-end part emulates hand-assembled x86-64 routines over a synthetic memory image (no engine, no target).
Run: runtimes/ghidra/python/python.exe -I -B -X utf8 scripts/test_string_decoding.py
"""
from pathlib import Path
import copy
import json
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'worker'))
import string_decoding as sd
from cpu_emulator import emulate_image
from memory_image import MemoryImage, MemoryRegion, PERM_EXEC, PERM_READ, PERM_WRITE

GOOD = {'fanIn': 4, 'hasLoop': True, 'arithmetic': 1, 'memoryWrites': True, 'externalCalls': 0, 'calls': 0}


def write(ea, before, after):
    return {'ea': hex(ea), 'size': len(after), 'before': before.hex(), 'after': after.hex()}


def result(writes=(), reason='returned', fault=None):
    return {'reason': reason, 'fault': fault, 'writes': list(writes)}


def decoder(ea='0x1000', features=None, sites=2, size=20, **extra):
    return {'ea': ea, 'name': 'dec_' + ea, 'size': size, 'bits': 64, 'features': dict(GOOD, **(features or {})),
            'sites': [{'ea': hex(0x2000 + 0x10 * i), 'caller': {'ea': '0x2000', 'name': 'main'},
                       'args': [{'kind': 'const', 'value': 0x3000 + i}, {'kind': 'const', 'value': 5}]} for i in range(sites)], **extra}


class ScoringTests(unittest.TestCase):
    def test_structure_decides_candidacy(self):
        score, reasons = sd.score_decoder(GOOD)
        self.assertGreaterEqual(score, sd.SCORE_THRESHOLD); self.assertTrue(any('loop' in r for r in reasons))
        for missing in ('hasLoop', 'arithmetic', 'memoryWrites'):
            self.assertIsNone(sd.score_decoder(dict(GOOD, **{missing: False if missing != 'arithmetic' else 0})), missing)

    def test_penalties_and_bonus_cap(self):
        base = sd.score_decoder(GOOD)[0]
        self.assertLess(sd.score_decoder(dict(GOOD, externalCalls=2))[0], base - 2)
        self.assertLess(sd.score_decoder(dict(GOOD, calls=1))[0], base)
        self.assertLess(sd.score_decoder(dict(GOOD, size=400))[0], base)
        self.assertEqual(sd.score_decoder(dict(GOOD, fanIn=500))[0], sd.score_decoder(dict(GOOD, fanIn=50))[0])


class ArgumentTests(unittest.TestCase):
    def test_constants_stack_and_unknown(self):
        args, scratch, unresolved = sd.plan_arguments([{'kind': 'stack', 'offset': 0x20}, {'kind': 'const', 'value': 0x1_0000_0000_0000_0001},
                                                      {'kind': 'unknown'}, {'kind': 'stack', 'offset': 8}], 64)
        self.assertEqual(args[1], 1, 'values are masked to the target width'); self.assertEqual(args[2], 0); self.assertEqual(unresolved, 1)
        self.assertEqual(len(scratch), 2); self.assertNotEqual(args[0], args[3], 'each stack buffer gets its own scratch area')
        self.assertEqual(scratch[0]['hex'], '00' * sd.SCRATCH_SIZE)
        self.assertEqual(sd.plan_arguments([{'kind': 'stack'}], 32)[0][0], sd.SCRATCH_BASE[32])

    def test_trailing_unknown_arguments_are_not_counted_as_unresolved(self):
        unknown = {'kind': 'unknown'}
        self.assertEqual(sd.plan_arguments([{'kind': 'const', 'value': 1}, {'kind': 'const', 'value': 2}, unknown, unknown], 64)[2], 0)
        self.assertEqual(sd.plan_arguments([unknown, {'kind': 'const', 'value': 2}, unknown, unknown], 64)[2], 1)
        self.assertEqual(sd.plan_arguments([unknown, unknown], 64)[2], 0, 'nothing is known, so nothing can be called unresolved')


class ExtractionTests(unittest.TestCase):
    def test_only_changed_text_is_reported(self):
        before = b'KEEP-THIS-TEXT\0' + b'\0' * 12 + b'\0'
        after = b'KEEP-THIS-TEXT\0' + b'http://x.invalid/' + b'\0'
        found = sd.extract_texts([write(0x100, before, after)], 4)
        self.assertEqual([item['text'] for item in found], ['http://x.invalid/'])
        self.assertEqual(found[0]['ea'], hex(0x100 + 15))
        self.assertEqual(sd.extract_texts([write(0x100, after, after)], 4), [], 'unchanged bytes are never reported')

    def test_utf16_and_filters(self):
        wide = 'Software\\Example'.encode('utf-16le')
        found = sd.extract_texts([write(0x200, b'\0' * len(wide), wide)], 4)
        self.assertEqual((found[0]['text'], found[0]['encoding']), ('Software\\Example', 'utf-16le'))
        for noise in (b'abc\0', b'AAAAAAAA', b'\x01\x02\x03\x04\x05\x06', b'   \x01'):
            self.assertEqual(sd.extract_texts([write(0x300, b'\0' * len(noise), noise)], 4), [], noise)


class OrchestrationTests(unittest.TestCase):
    def run_with(self, candidates, fake, **params):
        calls = []
        def run(entry, args, scratch):
            calls.append((entry, tuple(args), len(scratch)))
            return fake(entry, args, scratch, len(calls))
        return sd.decode_strings(candidates, run, params, considered=len(candidates)), calls

    def text_run(self, text=b'config.example.invalid'):
        return result([write(0x4000, b'\0' * len(text), text)])

    def test_decoded_string_carries_full_provenance(self):
        report, _ = self.run_with([decoder(sites=1)], lambda *a: self.text_run())
        item = report['strings'][0]
        self.assertEqual(item['text'], 'config.example.invalid'); self.assertEqual(item['callSite'], '0x2000')
        self.assertEqual((item['decoder'], item['verificationLevel'], item['basis'], item['reproduced']), ('0x1000', 'E1', 'unicorn-emulation', True))
        self.assertEqual(item['args'], ['0x3000', '0x5']); self.assertEqual(report['decoders'][0]['status'], 'decoded')
        self.assertEqual(report['coverage']['stringsFound'], 1); self.assertIn('Level E1', report['interpretation'])

    def test_every_hit_is_run_twice_and_unstable_ones_are_dropped(self):
        report, calls = self.run_with([decoder(sites=1)], lambda e, a, s, n: self.text_run(b'first-run-text' if n == 1 else b'other-run-text'))
        self.assertEqual(len(calls), 2); self.assertEqual(report['strings'], [])
        self.assertEqual(report['decoders'][0]['unstableRuns'], 1); self.assertEqual(report['decoders'][0]['status'], 'no-output')

    def test_failures_are_reported_as_unsupported_not_as_empty(self):
        fault = {'accessType': 'execute', 'kind': 'unmapped', 'ea': '0x500000000000'}
        report, _ = self.run_with([decoder(sites=3)], lambda *a: result(reason='unmapped-memory', fault=fault))
        row = report['decoders'][0]
        self.assertEqual((row['status'], row['unsupported']), ('unsupported', {'calls-outside-image': 3}))
        mixed, _ = self.run_with([decoder(sites=2)], lambda e, a, s, n: result(reason='timeout') if n == 1 else result())
        self.assertEqual(mixed['decoders'][0]['status'], 'no-output', 'a partly working decoder is not "unsupported"')

    def test_non_candidates_are_never_emulated(self):
        weak = decoder('0x50', features={'externalCalls': 2}, size=400)       # loop + arithmetic + writes, but imports and large: score below threshold
        report, calls = self.run_with([decoder('0x10', features={'fanIn': 2}), decoder('0x20', features={'hasLoop': False}),
                                       decoder('0x30', size=5000), decoder('0x40', features={'memoryWrites': False}), weak], lambda *a: self.text_run())
        self.assertEqual(calls, []); self.assertEqual(report['decoders'], []); self.assertEqual(report['coverage']['candidates'], 0)

    def test_a_function_named_by_the_caller_is_tried_whatever_its_structure(self):
        forced = decoder('0x70', features={'hasLoop': False, 'arithmetic': 0, 'memoryWrites': False, 'fanIn': 1}, sites=1, forced=True)
        report, calls = self.run_with([forced], lambda *a: self.text_run())
        self.assertEqual(len(calls), 2); self.assertEqual(report['decoders'][0]['status'], 'decoded')
        self.assertIn('selected explicitly by the caller', report['decoders'][0]['reasons'])
        self.assertEqual(report['decoders'][0]['score'], 0, 'the real structural score is still reported')

    def test_budgets_truncate_visibly(self):
        report, calls = self.run_with([decoder(sites=10)], lambda *a: result(), max_runs=3)
        self.assertEqual(len(calls), 3); self.assertTrue(report['truncation']['runs'])
        ticks = iter(range(0, 10**6, 600))
        report = sd.decode_strings([decoder(sites=10)], lambda e, a, s: result(), {'time_budget_ms': 1000}, clock=lambda: next(ticks))
        self.assertTrue(report['truncation']['time']); self.assertLess(report['coverage']['runs'], 10)
        many = [decoder(hex(0x100 * i), sites=1) for i in range(1, 6)]
        self.assertTrue(self.run_with(many, lambda *a: result(), max_decoders=2)[0]['truncation']['decoders'])
        strings, _ = self.run_with([decoder(sites=1)], lambda *a: result([write(0x4000, b'\0' * 40, b'aaa-bbb ccc-ddd eee-fff ggg-hhh iii-jjj')]), max_strings=1)
        self.assertEqual(len(strings['strings']), 1)

    def test_duplicates_unresolved_arguments_and_purity(self):
        cand = decoder(sites=1)
        cand['sites'][0]['args'] = [{'kind': 'unknown'}, {'kind': 'const', 'value': 5}]
        before = copy.deepcopy(cand)
        two = self.text_run(b'dup-text-here ' + b'x-y-z dup-text-here')
        report, _ = self.run_with([cand], lambda *a: two)
        self.assertEqual(cand, before, 'the candidates must not be modified')
        self.assertEqual(report['decoders'][0]['unresolvedArguments'], 1); self.assertEqual(report['coverage']['unresolvedArguments'], 1)

    def test_limits_are_validated(self):
        for key, value in (('min_calls', 0), ('max_runs', 100000), ('time_budget_ms', True), ('min_text', 'x'), ('max_size', 1)):
            with self.assertRaises(ValueError):
                sd.limits_from({key: value})


# ---------------------------------------------------------------------------------- real Unicorn, hand-assembled code
CODE_BASE, DATA_BASE = 0x140001000, 0x140003000
XOR_IN_PLACE = bytes.fromhex('85d2740a80315a48ffc1ffca75f6c3')                 # rcx=ptr, edx=len: xor byte [rcx], 0x5a
COPY_DECODE = bytes.fromhex('4585c07412' '8a02' '4430c8' '8801' '48ffc1' '48ffc2' '41ffc8' '75ee' 'c3')   # rcx=dst, rdx=src, r8d=len, r9b=key
COUNTER = bytes.fromhex('85d27409fe0148ffc1ffca75f7c3')                         # rcx=ptr, edx=len: inc byte [rcx]  (loop + arithmetic, not a decoder)
CALLS_OUT = bytes.fromhex('48b8000000000050' '0000' 'ffd0c3')                   # mov rax, 0x500000000000 ; call rax ; ret
OFFSETS = {'xor': 0x000, 'copy': 0x040, 'counter': 0x080, 'out': 0x0c0}


def xor(data, key):
    return bytes(b ^ key for b in data)


class EmulatorEndToEnd(unittest.TestCase):
    PLAIN = [b'config.example.invalid:8443', b'Software\\Example\\Run', b'GET /status HTTP/1.1']

    def build(self):
        code = bytearray(0x1000)
        for name, blob in (('xor', XOR_IN_PLACE), ('copy', COPY_DECODE), ('counter', COUNTER), ('out', CALLS_OUT)):
            code[OFFSETS[name]:OFFSETS[name] + len(blob)] = blob
        data, self.blobs, cursor = bytearray(0x1000), [], 0
        for index, plain in enumerate(self.PLAIN):
            cipher = xor(plain, 0x5A if index < 2 else 0x37)
            data[cursor:cursor + len(cipher)] = cipher
            self.blobs.append((DATA_BASE + cursor, len(cipher))); cursor += 0x40
        self.zeros = DATA_BASE + 0x400
        self.code, self.data = bytes(code), bytes(data)
        regions = [MemoryRegion(CODE_BASE, 0x1000, lambda o, s: self.code[o:o + s], name='.text', permissions=PERM_READ | PERM_EXEC),
                   MemoryRegion(DATA_BASE, 0x1000, lambda o, s: self.data[o:o + s], name='.data', permissions=PERM_READ | PERM_WRITE)]
        return MemoryImage('x86', 64, CODE_BASE, regions, source='test').snapshot()

    def candidates(self):
        const = lambda value: {'kind': 'const', 'value': value}
        site = lambda ea, args: {'ea': hex(ea), 'caller': {'ea': '0x140001800', 'name': 'main'}, 'args': args}
        def feature(**kw): return dict(GOOD, **kw)
        return [
            {'ea': hex(CODE_BASE + OFFSETS['xor']), 'name': 'decode_xor', 'size': len(XOR_IN_PLACE), 'bits': 64, 'features': feature(),
             'sites': [site(0x140001810 + 16 * i, [const(blob[0]), const(blob[1])]) for i, blob in enumerate(self.blobs[:2])] + [site(0x140001850, [{'kind': 'unknown'}, const(3)])]},
            {'ea': hex(CODE_BASE + OFFSETS['copy']), 'name': 'decode_copy', 'size': len(COPY_DECODE), 'bits': 64, 'features': feature(),
             'sites': [site(0x140001860, [{'kind': 'stack', 'offset': 0x20}, const(self.blobs[2][0]), const(self.blobs[2][1]), const(0x37)])]},
            {'ea': hex(CODE_BASE + OFFSETS['counter']), 'name': 'count_up', 'size': len(COUNTER), 'bits': 64, 'features': feature(),
             'sites': [site(0x140001870 + 16 * i, [const(self.zeros), const(24)]) for i in range(3)]},
            {'ea': hex(CODE_BASE + OFFSETS['out']), 'name': 'calls_out', 'size': len(CALLS_OUT), 'bits': 64, 'features': feature(),
             'sites': [site(0x140001890 + 16 * i, [const(self.zeros), const(4)]) for i in range(3)]},
        ]

    def decode(self, image):
        def run(entry, args, scratch):
            return emulate_image(image.with_entry(entry), {'abi': 'win64', 'args': [hex(a) for a in args], 'memory': scratch,
                                                           'trace_writes': True, 'max_instructions': 200000, 'timeout_ms': 2000})
        return sd.decode_strings(self.candidates(), run, {})

    def test_decodes_in_place_and_buffer_decoders_and_reports_the_rest_honestly(self):
        image = self.build()
        report = self.decode(image)
        texts = {item['text'] for item in report['strings']}
        self.assertEqual(texts, {p.decode() for p in self.PLAIN}, report['strings'])
        by_name = {row['name']: row for row in report['decoders']}
        self.assertEqual(by_name['decode_xor']['status'], 'decoded'); self.assertEqual(by_name['decode_xor']['strings'], 2)
        self.assertEqual(by_name['decode_xor']['unresolvedArguments'], 1)
        self.assertEqual(by_name['decode_copy']['status'], 'decoded')
        stack_item = next(item for item in report['strings'] if item['decoder'] == by_name['decode_copy']['ea'])
        self.assertEqual(stack_item['stackArguments'], 1)
        self.assertEqual(by_name['count_up']['status'], 'no-output', 'a loop that changes memory without producing text decodes nothing')
        self.assertEqual((by_name['calls_out']['status'], by_name['calls_out']['unsupported']), ('unsupported', {'calls-outside-image': 3}))

    def test_runs_are_isolated_from_each_other_and_from_the_image(self):
        image = self.build()
        first, second = self.decode(image), self.decode(image)
        self.assertEqual(first['strings'], second['strings'])
        self.assertEqual(b''.join(image.regions[1].read(0, 0x1000) for _ in [0]), self.data, 'the snapshot is never modified by emulation')

    def test_write_trace_is_optional_and_does_not_change_default_results(self):
        image = self.build().with_entry(CODE_BASE + OFFSETS['xor'])
        params = {'abi': 'win64', 'args': [hex(self.blobs[0][0]), hex(self.blobs[0][1])]}
        plain = emulate_image(image, params)
        traced = emulate_image(image, dict(params, trace_writes=True))
        self.assertNotIn('writes', plain); self.assertEqual(traced['writes'][0]['size'], self.blobs[0][1])
        for key in ('reason', 'return_value', 'instructions'):
            self.assertEqual(plain[key], traced[key])
        with self.assertRaises(ValueError):
            emulate_image(image, dict(params, trace_writes='yes'))


    def test_write_trace_marks_a_clipped_contiguous_range(self):
        # mov ecx,count; mov edi,0x3000; mov al,0x41; rep stosb; ret
        for count, expected_truncated in ((4096, False), (4097, True), (5000, True)):
            with self.subTest(count=count):
                code = b'\xb9' + count.to_bytes(4, 'little') + bytes.fromhex('bf00300000b041f3aac3')
                data = bytes(8192)
                image = MemoryImage('x86', 64, 0x1000, [
                    MemoryRegion(0x1000, len(code), lambda o, s: code[o:o+s], permissions=PERM_READ | PERM_EXEC),
                    MemoryRegion(0x3000, len(data), lambda o, s: data[o:o+s], permissions=PERM_READ | PERM_WRITE),
                ], source='test').snapshot()
                report = emulate_image(image, {'trace_writes': True, 'capture': [{'ea': '0x3000', 'size': count}]})
                self.assertEqual(report['reason'], 'returned')
                self.assertEqual(bytes.fromhex(report['memory'][0]['hex']), b'A' * count)
                self.assertEqual(report['writes'][0]['size'], min(count, 4096))
                self.assertEqual(report['writesTruncated'], expected_truncated)


# ---------------------------------------------------------------------------------- real Ghidra on a generated PE
import struct

PLAIN = {'c0': b'config.example.invalid:8443', 'c1': b'Software\\Example\\Run', 'c3': b'Mozilla/5.0 (compatible)',   # xor 0x5a
         'c2': b'GET /status HTTP/1.1', 'c4': b'User-Agent: example-agent/1.0'}                                    # copy-decode, key 0x37
DATA_RVA = {'c0': 0x2000, 'c1': 0x2040, 'c2': 0x2080, 'c3': 0x20c0, 'dst': 0x2100, 'c4': 0x2180, 'zeros': 0x2200}
CODE_RVA, SLOT = 0x1000, {'xor': 0x1180, 'copy': 0x11c0, 'counter': 0x1200, 'logger': 0x1240}


def pe_with_decoders():
    image = bytearray(0xa00)
    def u16(o, v): struct.pack_into('<H', image, o, v)
    def u32(o, v): struct.pack_into('<I', image, o, v)
    def u64(o, v): struct.pack_into('<Q', image, o, v)
    def raw(rva): return rva - 0x1000 + 0x200 if rva < 0x2000 else rva - 0x2000 + 0x600
    def put(o, v): image[o:o + len(v)] = v
    put(0, b'MZ'); u32(0x3c, 0x80); put(0x80, b'PE\0\0')
    u16(0x84, 0x8664); u16(0x86, 2); u16(0x94, 0xf0); u16(0x96, 0x22)
    o = 0x98
    u16(o, 0x20b); u32(o + 4, 0x400); u32(o + 8, 0x400); u32(o + 16, CODE_RVA); u32(o + 20, 0x1000); u64(o + 24, 0x140000000)
    u32(o + 32, 0x1000); u32(o + 36, 0x200); u16(o + 40, 6); u16(o + 48, 6); u32(o + 56, 0x3000); u32(o + 60, 0x200); u16(o + 68, 3)
    u64(o + 72, 0x100000); u64(o + 80, 0x1000); u64(o + 88, 0x100000); u64(o + 96, 0x1000); u32(o + 108, 16)
    for index, name, rva, offset, perm in [(0, b'.text', 0x1000, 0x200, 0x60000020), (1, b'.data', 0x2000, 0x600, 0xc0000040)]:
        s = o + 0xf0 + 40 * index
        put(s, name); u32(s + 8, 0x400); u32(s + 12, rva); u32(s + 16, 0x400); u32(s + 20, offset); u32(s + 36, perm)
    for key, plain in PLAIN.items():
        put(raw(DATA_RVA[key]), xor(plain, 0x5a if key in ('c0', 'c1', 'c3') else 0x37))

    def assemble(base, parts):
        code = bytearray()
        for part in parts:
            code += part(base + len(code)) if callable(part) else part
        return bytes(code)
    rel = lambda opcode, target: (lambda at: opcode + struct.pack('<i', target - (at + len(opcode) + 4)))
    lea_rcx = lambda rva: rel(b'\x48\x8d\x0d', rva)
    lea_rdx = lambda rva: rel(b'\x48\x8d\x15', rva)
    lea_rax = lambda rva: rel(b'\x48\x8d\x05', rva)
    call = lambda target: rel(b'\xe8', target)
    mov_edx = lambda v: b'\xba' + struct.pack('<I', v)
    mov_r8d = lambda v: b'\x41\xb8' + struct.pack('<I', v)
    mov_r9d = lambda v: b'\x41\xb9' + struct.pack('<I', v)
    lea_rcx_stack = b'\x48\x8d\x4c\x24\x20'
    xor_site = lambda key: [lea_rcx(DATA_RVA[key]), mov_edx(len(PLAIN[key])), call(SLOT['xor'])]
    copy_site = lambda dst, key: [dst, lea_rdx(DATA_RVA[key]), mov_r8d(len(PLAIN[key])), mov_r9d(0x37), call(SLOT['copy'])]
    counter_site = [lea_rcx(DATA_RVA['zeros']), mov_edx(24), call(SLOT['counter'])]
    main = assemble(CODE_RVA, [b'\x48\x83\xec\x48', *xor_site('c0'), *xor_site('c1'), *xor_site('c3'),
                               b'\x48\x89\xc1', mov_edx(5), call(SLOT['xor']),                     # rcx comes from "mov rcx, rax" after a call: unresolvable
                               *copy_site(lea_rcx(DATA_RVA['dst']), 'c2'), *copy_site(lea_rcx_stack, 'c2'), *copy_site(lea_rcx_stack, 'c4'),
                               *counter_site, *counter_site, *counter_site,
                               # edx is set, then a call clobbers it, then only rcx is set again: edx is unknown at the decoder call
                               mov_edx(0x99), call(SLOT['logger']), lea_rcx(DATA_RVA['c0']), call(SLOT['xor']),
                               lea_rax(SLOT['xor']),            # lea rax,[decoder]: takes the address, is NOT a call
                               *[call(SLOT['logger'])] * 5, b'\x48\x83\xc4\x48\xc3'])
    assert len(main) <= SLOT['xor'] - CODE_RVA, len(main)
    for name, blob in (('xor', XOR_IN_PLACE), ('copy', COPY_DECODE), ('counter', COUNTER), ('logger', bytes.fromhex('b801000000c3'))):
        put(raw(SLOT[name]), blob)
    put(raw(CODE_RVA), main)
    return bytes(image)


def runtime_test():
    from fixtures.ghidra_session import GhidraSession
    image = pe_with_decoders()
    ea = lambda rva: hex(0x140000000 + rva)
    with GhidraSession(image, 'decoder-fixture.exe', prefix='ig5-decode-') as ghidra:
        print('evidence directory:', ghidra.scratch)
        before = ghidra.rpc('stats')
        report = ghidra.rpc('emulate', {'mode': 'decode_strings'})
        (ghidra.scratch / 'observed.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
        texts = sorted(item['text'] for item in report['strings'])
        expected = sorted(p.decode() for k, p in PLAIN.items() if k != 'c2') + [PLAIN['c2'].decode()] * 2
        assert texts == sorted(expected), (texts, expected)
        rows = {row['ea']: row for row in report['decoders']}
        assert set(rows) == {ea(SLOT['xor']), ea(SLOT['copy']), ea(SLOT['counter'])}, 'only structurally plausible decoders are tried (not main, not the logger): ' + str(sorted(rows))
        xor_row, copy_row, counter_row = rows[ea(SLOT['xor'])], rows[ea(SLOT['copy'])], rows[ea(SLOT['counter'])]
        assert (xor_row['status'], xor_row['strings'], xor_row['callSites']) == ('decoded', 3, 5), 'address-taken references are not call sites: ' + str(xor_row)
        assert xor_row['unsupported'] == {'unmapped-memory': 1} and xor_row['unresolvedArguments'] == 1, 'the one unresolvable call site is reported, not hidden: ' + str(xor_row)
        assert (copy_row['status'], copy_row['strings'], copy_row['callSites']) == ('decoded', 3, 3), copy_row
        assert (counter_row['status'], counter_row['strings']) == ('no-output', 0), 'a loop that changes memory but yields no text decodes nothing: ' + str(counter_row)
        stack_strings = [item for item in report['strings'] if item['stackArguments']]
        assert len(stack_strings) == 2 and all(item['decoder'] == ea(SLOT['copy']) for item in stack_strings), stack_strings
        assert all(item['caller']['ea'] == ea(CODE_RVA) and item['verificationLevel'] == 'E1' and item['reproduced'] for item in report['strings'])
        assert report['sourceEngine'] == 'ghidra' and report['abi'] == 'win64' and report['idb_modified'] is False
        # a function named by the caller is tried even below the call-count threshold
        forced = ghidra.rpc('emulate', {'mode': 'decode_strings', 'ea': ea(SLOT['xor']), 'min_calls': 50})
        assert [row['ea'] for row in forced['decoders']] == [ea(SLOT['xor'])] and len(forced['strings']) == 3, forced['decoders']
        assert 'selected explicitly by the caller' in forced['decoders'][0]['reasons']
        # the classic single-function emulation still works after the refactor
        classic = ghidra.rpc('emulate', {'ea': ea(SLOT['xor']), 'args': [ea(DATA_RVA['c0']), hex(len(PLAIN['c0']))],
                                         'capture': [{'ea': ea(DATA_RVA['c0']), 'size': len(PLAIN['c0'])}]})
        assert classic['reason'] == 'returned' and bytes.fromhex(classic['memory'][0]['hex']) == PLAIN['c0'], classic
        assert ghidra.rpc('stats')['revision'] == before['revision'], 'decoding must not modify the database'
        assert ghidra.source_unchanged()
        print(json.dumps({'ok': True, 'engine': 'ghidra', 'strings': len(report['strings']), 'decoders': len(report['decoders']),
                          'artifacts': str(ghidra.scratch)}))


if __name__ == '__main__':
    import argparse
    sys.path.insert(0, str(ROOT / 'scripts'))
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', choices=('ghidra',))
    args, rest = parser.parse_known_args()
    if not unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])).wasSuccessful():
        sys.exit(1)
    if args.runtime:
        runtime_test()
