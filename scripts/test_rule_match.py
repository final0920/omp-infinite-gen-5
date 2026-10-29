"""Signature rule matching: restricted-subset compiler, matcher semantics, scan integration
and checks against REAL files when they exist on this machine (the protection corpus and the
Windows system directory).

Run:  runtimes/ghidra/python/python.exe -I -B -X utf8 scripts/test_rule_match.py [--runtime ghidra]

The real-file checks skip loudly when their inputs are missing.  ``--runtime ghidra`` also runs
the ig5_scan acceptance through the real Ghidra worker (built-in table, caller-supplied rules,
a rejected construct and the read-only guarantees).  Generated PE bytes are analyzed only,
never executed.
"""
from pathlib import Path
import argparse
import glob
import hashlib
import json
import os
import random
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'worker'))
sys.path.insert(0, str(ROOT / 'scripts' / 'fixtures'))

import feature_rules
import rule_match
from rule_match import RuleError, compile_rules
from scan_analysis import CHUNK_SIZE, scan_image


def segment(data, base=0x1000, name='.data'):
    return {'name': name, 'start': base, 'size': len(data), 'read': lambda offset, size: data[offset:offset + size]}


def rule_source(body, identifiers=('$a', '$b', '$c')):
    """A one-rule source; ``body`` is the text after ``condition:``."""
    words = {'$a': 'AAA', '$b': 'BBB', '$c': 'CCC'}
    strings = ''.join('    %s = "%s"\n' % (name, words[name]) for name in identifiers)
    return 'rule scan_fixture : probe {\n  strings:\n%s  condition:\n    %s\n}\n' % (strings, body)


def scan_scoped(data, body, **params):
    options = {'rules': rule_source(body)}
    options.update(params)
    return scan_image([segment(data)], source_engine='test', params=options)['ruleMatches']


def scan_rules(source, data, base=0x1000, **params):
    options = {'rules': source}
    options.update(params)
    return scan_image([segment(data, base=base)], source_engine='test', params=options)['ruleMatches']


def matched(report):
    return [row['rule'] for row in report['matches']]


class BuiltinTable(unittest.TestCase):
    def test_table_compiles_and_every_rule_is_reviewable(self):
        feature_rules.validate()
        ruleset = compile_rules(feature_rules.RULES_SOURCE, origin='builtin', version=feature_rules.RULES_VERSION)
        identifiers = [rule['id'] for rule in ruleset.rules]
        self.assertGreaterEqual(len(identifiers), 16)
        self.assertEqual(len(identifiers), len(set(identifiers)))
        required = {'upx_stub', 'themida_winlicense', 'vmprotect', 'enigma_protector', 'aspack', 'mpress',
                    'pecompact', 'petite', 'nspack', 'rlpack', 'yoda_protector', 'pyinstaller_bundle',
                    'nsis_installer', 'inno_setup_installer', 'dotnet_managed', 'autoit_compiled'}
        self.assertEqual(required - set(identifiers), set())
        for rule in ruleset.rules:
            with self.subTest(rule['id']):
                self.assertTrue(str(rule['meta'].get('description', '')).strip())
                self.assertTrue(rule['tags'])
                self.assertLessEqual(set(rule['tags']), feature_rules.TAG_VOCABULARY)
                self.assertTrue(rule['strings'])

    def test_validate_rejects_each_kind_of_mistake(self):
        original = feature_rules.RULES_SOURCE
        cases = {
            'missing description': 'rule x : probe { strings: $a = "A" condition: $a }',
            'missing tags': 'rule x { meta: description = "d" strings: $a = "A" condition: $a }',
            'unknown tag': 'rule x : weird { meta: description = "d" strings: $a = "A" condition: $a }',
            'no strings': 'rule x : probe { meta: description = "d" condition: true }',
        }
        try:
            for label, source in cases.items():
                with self.subTest(label):
                    feature_rules.RULES_SOURCE = source
                    with self.assertRaises(ValueError):
                        feature_rules.validate()
        finally:
            feature_rules.RULES_SOURCE = original
        feature_rules.validate()

    def test_every_shipped_rule_fires_on_its_own_marker(self):
        markers = {
            'upx_stub': b'UPX!',
            'themida_winlicense': b'.themida',
            'vmprotect': b'.vmp0',
            'enigma_protector': b'.enigma1',
            'aspack': b'.aspack',
            'mpress': b'.MPRESS1',
            'pecompact': b'pec2to',
            'petite': b'.petite',
            'nspack': b'nsp0',
            'rlpack': b'.RLPack',
            'yoda_protector': b'.y0da',
            'pyinstaller_bundle': b'PYZ-00.pyz',
            'nsis_installer': b'Nullsoft Install System',
            'inno_setup_installer': b'Inno Setup Setup Data',
            'dotnet_managed': b'BSJB' + b'\x00' * 12 + b'#Strings',
            'autoit_compiled': b'AU3!EA',
        }
        for name, marker in markers.items():
            with self.subTest(name):
                result = scan_image([segment(b'\x00' * 32 + marker + b'\x00' * 32)], source_engine='test')
                self.assertEqual(matched(result['ruleMatches']), [name])

    def test_benign_and_near_miss_bytes_do_not_match(self):
        samples = [
            bytes(range(256)) * 8,
            b'hello world\n' * 100,
            b'This program cannot be run in DOS mode.\r\n' * 20,
            b'MZ' + b'\x00' * 128,
            b'BSJB' + b'\x00' * 64,                       # CLR signature without the #Strings heap
            b'_CorExeMain _CorDllMain mscoree.dll',       # native COM activation shim strings
            b'UPX ', b'.vmp', b'.aspac', b'.MPRESS', b'NullsoftInst', b'.yp', b'.petit',
        ]
        for index, data in enumerate(samples):
            with self.subTest(index):
                result = scan_image([segment(data)], source_engine='test')
                self.assertEqual(result['ruleMatches']['matches'], [], data[:40])

    def test_metadata_and_addresses_are_reported(self):
        data = b'\x00' * 16 + b'UPX!' + b'\x00' * 16
        result = scan_image([segment(data, base=0x401000)], source_engine='test')['ruleMatches']
        self.assertEqual(result['schema'], 'ig5.ruleMatches.v1')
        self.assertEqual(result['evidenceLevel'], 'E0')
        self.assertEqual(result['ruleSet']['origin'], 'builtin')
        self.assertEqual(result['ruleSet']['version'], feature_rules.RULES_VERSION)
        row = result['matches'][0]
        self.assertEqual(row['rule'], 'upx_stub')
        self.assertIn('packer', row['tags'])
        self.assertTrue(row['description'])
        self.assertEqual(row['evidence'][0]['ea'], '0x401010')
        self.assertEqual(row['evidence'][0]['segment'], '.data')
        self.assertEqual(row['occurrences'], 1)
        self.assertIn('not proof', result['note'])


class Compiler(unittest.TestCase):
    def rejected(self, source, *fragments):
        with self.assertRaises(RuleError) as caught:
            compile_rules(source)
        message = str(caught.exception).lower()
        for fragment in fragments:
            self.assertIn(fragment.lower(), message)

    def test_regex_jumps_alternatives_and_unsupported_modifiers(self):
        cases = [
            ('rule x { strings: $a = /MZ/ condition: $a }', 'unexpected character'),
            ('rule x { strings: $a = { 4D 5A [2-4] 00 } condition: $a }', 'hex jumps'),
            ('rule x { strings: $a = { 4D (5A|00) } condition: $a }', 'alternatives'),
            ('rule x { strings: $a = "MZ" fullword condition: $a }', 'unsupported string modifier'),
            ('rule x { strings: $a = "MZ" xor condition: $a }', 'unsupported string modifier'),
            ('rule x { strings: $a = "MZ" condition: #a > 0 }', 'unexpected character'),
            ('rule x { strings: $a = "MZ" condition: $a at 0 }', "expected '}'"),
            ('rule x { strings: $a = "MZ" condition: for any i in (1..2) : ( $a ) }', 'unsupported condition'),
            ('rule x { strings: $a = "MZ" condition: any of ($a*) }', "expected 'them'"),
        ]
        for source, fragment in cases:
            with self.subTest(source):
                self.rejected(source, fragment)

    def test_condition_names_are_validated(self):
        self.rejected('rule x { strings: $a = "A" condition: $b }', 'undefined string')
        self.rejected('rule x { strings: $a = "A" $b = "B" condition: 3 of them }', '3 of 2')
        self.rejected('rule x { condition: any of them }', 'needs at least one string')
        self.rejected('rule x { strings: $a = "A" condition: 0 of them }', '0 of 1')

    def test_identifier_and_size_limits(self):
        self.rejected('rule a { condition: true }\nrule a { condition: true }', 'unique')
        self.rejected('\n'.join('rule r%d { condition: true }' % index for index in range(65)), 'more than 64 rules')
        strings = '\n'.join('    $s%d = "A"' % index for index in range(33))
        self.rejected('rule x { strings:\n%s\n  condition: $s0 }' % strings, 'more than 32 strings')
        block = 'rule x%d { strings: %s condition: all of them }\n'
        source = ''.join(block % (index, ' '.join('$s%d = "A"' % part for part in range(32))) for index in range(9))
        self.rejected(source, 'more than 256 strings in total')
        self.rejected('', 'empty')
        self.rejected('   \n\t', 'empty')
        with self.assertRaises(RuleError):
            compile_rules(123)
        self.rejected(' ' * 65536 + 'rule a { condition: true }', 'longer than 65536')

    def test_string_bodies_are_validated(self):
        cases = [
            ('rule x { strings: $a = "" condition: $a }', 'empty text string'),
            ('rule x { strings: $a = "%s" condition: $a }' % ('A' * 257), 'longer than 256 bytes'),
            ('rule x { strings: $a = "%s" ascii wide condition: $a }' % ('A' * 129), 'wide text string longer than'),
            ('rule x { strings: $a = "\\xc3\\xa9" wide condition: $a }', 'wide text strings must be ASCII'),
            ('rule x { strings: $a = { } condition: $a }', 'empty hex string'),
            ('rule x { strings: $a = { ?? ?? } condition: $a }', 'at least one fixed byte'),
            ('rule x { strings: $a = { %s } condition: $a }' % ('4D ' * 257), 'longer than 256 bytes'),
            ('rule x { strings: $a = { 4 } condition: $a }', 'two digits'),
            ('rule x { strings: $a = { ?? ? } condition: $a }', 'malformed wildcard'),
            ('rule x { strings: $a = { 4D 5A', 'unterminated hex string'),
            ('rule x { strings: $a = "MZ condition: $a }', 'unterminated string literal'),
            ('rule x { strings: $a = "MZ\\x4" condition: $a }', 'two hex digits'),
            ('rule x { strings: $a = "MZ\\q" condition: $a }', 'unsupported escape'),
            ('rule x { strings: $a = "MZ" ascii ascii condition: $a }', 'duplicate modifier'),
        ]
        for source, fragment in cases:
            with self.subTest(fragment):
                self.rejected(source, fragment)

    def test_rule_and_meta_syntax(self):
        cases = [
            ('rule x : Packer { condition: true }', 'invalid tag'),
            ('rule x : meta { condition: true }', 'collides with a section keyword'),
            ('rule x : probe probe { condition: true }', 'duplicate tag'),
            ('rule x : %s { condition: true }' % ' '.join('t%d' % index for index in range(9)), 'more than 8 tags'),
            ('rule 9x { condition: true }', 'rule name'),
            ('foo x { condition: true }', "expected 'rule'"),
            ('rule x { }', 'expected condition'),
            ('rule x { strings: $a = "A" condition: $a } trailing', "expected 'rule'"),
            ('rule x { meta: confidence = $a condition: true }', 'quoted string or integer'),
            ('rule x { meta: description = "a" description = "b" condition: true }', 'duplicate meta'),
            ('rule x { meta: %s condition: true }' % ' '.join('k%d = 1' % index for index in range(17)), 'more than 16 meta'),
            ('rule x { meta: description = "%s" condition: true }' % ('d' * 513), 'longer than 512'),
            ('rule x { strings: $a = "A" condition: %s }' % ' or '.join(['$a'] * 130), 'more than 128'),
        ]
        for source, fragment in cases:
            with self.subTest(fragment):
                self.rejected(source, fragment)

    def test_supported_constructs_compile_and_keep_their_fields(self):
        source = '''
// leading comment
rule multi : packer anti-analysis {
  meta:
    description = "fixture rule"
    confidence = 42
  strings:
    $text = "MZ" ascii nocase
    $hex = { 4D 5A ?? 00 ?A 4? }
  condition:
    $text and (all of them)
}
'''
        ruleset = compile_rules(source, origin='custom', version=7, max_locations=9)
        self.assertEqual(ruleset.origin, 'custom')
        self.assertEqual(ruleset.version, 7)
        self.assertEqual(len(ruleset.rules), 1)
        rule = ruleset.rules[0]
        self.assertEqual(rule['id'], 'multi')
        self.assertEqual(rule['tags'], ['packer', 'anti-analysis'])
        self.assertEqual(rule['meta'], {'description': 'fixture rule', 'confidence': 42})
        self.assertEqual([row['id'] for row in rule['strings']], ['$text', '$hex'])
        self.assertEqual(ruleset.overlap, 5)          # longest fixed-width hex pattern minus one
        self.assertEqual(matched(scan_rules(source, b'MZ' + b'\x4d\x5a\x00\x00\x0a\x40')), ['multi'])
        self.assertEqual(scan_rules(source, b'xxxxx')['matches'], [])


class TextAndHex(unittest.TestCase):
    def fires(self, declaration, data):
        source = 'rule t { strings: $a = %s condition: $a }\n' % declaration
        return bool(scan_rules(source, data)['matches'])

    def test_text_case_and_width(self):
        self.assertTrue(self.fires('"MZ"', b'MZ'))
        self.assertFalse(self.fires('"MZ"', b'mz'))
        self.assertFalse(self.fires('"MZ"', b'M\x00Z\x00'))
        self.assertTrue(self.fires('"MZ" ascii nocase', b'mz'))
        self.assertTrue(self.fires('"MZ" ascii nocase', b'Mz'))
        self.assertFalse(self.fires('"MZ" ascii nocase', b'zz'))
        self.assertTrue(self.fires('"MZ" wide', b'M\x00Z\x00'))
        self.assertFalse(self.fires('"MZ" wide', b'MZ'))
        self.assertTrue(self.fires('"MZ" wide ascii', b'MZ'))
        self.assertTrue(self.fires('"MZ" wide ascii', b'M\x00Z\x00'))
        self.assertFalse(self.fires('"MZ" nocase', b'm\x00z\x00'))

    def test_text_escapes_and_non_ascii(self):
        self.assertTrue(self.fires('"line\\nbreak"', b'line\nbreak'))
        self.assertTrue(self.fires('"A\\x00B"', b'A\x00B'))
        self.assertTrue(self.fires('"\\t\\r\\0\\\\\\""', b'\t\r\x00\\"'))
        self.assertTrue(self.fires('"é"', 'é'.encode('utf-8')))
        source = 'rule t { strings: $a = "é" wide condition: $a }\n'
        with self.assertRaises(RuleError):
            compile_rules(source)

    def test_hex_bytes_and_wildcards(self):
        self.assertTrue(self.fires('{ 4D 5A }', b'MZ'))
        self.assertFalse(self.fires('{ 4D 5A }', b'Mz'))
        self.assertTrue(self.fires('{ 4d 5a }', b'MZ'))
        self.assertTrue(self.fires('{ 4D ?? 00 }', b'MZ\x00'))
        self.assertTrue(self.fires('{ 4D ?? 00 }', b'M\x00\x00'))
        self.assertFalse(self.fires('{ 4D ?? 00 }', b'MZ\x01'))
        # ``?A`` fixes the low nibble; ``4?`` fixes the high nibble.
        self.assertTrue(self.fires('{ ?A }', b'\x0a'))
        self.assertTrue(self.fires('{ ?A }', b'\xfa'))
        self.assertFalse(self.fires('{ ?A }', b'\x0b'))
        for high in range(16):
            declaration = '{ %X? }' % high
            for byte in range(256):
                with self.subTest(high=high, byte=byte):
                    self.assertEqual(self.fires(declaration, bytes([byte])), byte >> 4 == high)

    def test_wide_modifier_doubles_the_pattern_length(self):
        result = scan_rules('rule t { strings: $a = "AB" wide ascii condition: $a }\n', b'ABxAB\x00')
        self.assertEqual(result['ruleSet']['strings'], 2)
        self.assertEqual(result['matches'][0]['occurrences'], 2)
        self.assertEqual(result['matches'][0]['evidence'][0]['length'], 2)
        self.assertEqual(result['matches'][0]['evidence'][1]['length'], 2)

    def test_hex_matches_a_brute_force_reference(self):
        items = [('byte', 0x4D, 0), ('wild', 0, 0), ('nibble', 0x0A, 'low'),
                 ('nibble', 0x4, 'high'), ('byte', 0x5A, 0)]
        declaration = '{ 4D ?? ?A 4? 5A }'
        source = 'rule t { strings: $a = %s condition: $a }\n' % declaration
        rng = random.Random(20261025)
        block = b'\x4d\x00\x1a\x40\x5a' + bytes(rng.randrange(256) for _ in range(11))
        data = block * 40

        def accepts(byte, kind, value, side):
            if kind == 'byte':
                return byte == value
            if kind == 'wild':
                return True
            return byte & 0x0F == value if side == 'low' else byte & 0xF0 == value << 4

        expected = [start for start in range(len(data))
                    if start + len(items) <= len(data)
                    and all(accepts(data[start + index], *item) for index, item in enumerate(items))]
        report = scan_rules(source, data, max_rule_matches=4096)
        row = report['matches'][0]
        self.assertEqual(row['occurrences'], len(expected))
        self.assertEqual([int(entry['ea'], 16) for entry in row['evidence']],
                         [0x1000 + start for start in expected[:16]])

    def test_text_nocase_matches_a_brute_force_reference(self):
        source = 'rule t { strings: $a = "ab" nocase condition: $a }\n'
        rng = random.Random(7)
        data = bytes(rng.choice(b'aAbBcC') for _ in range(600))
        expected = [start for start in range(len(data) - 1) if data[start:start + 2].lower() == b'ab']
        report = scan_rules(source, data, max_rule_matches=4096)
        row = report['matches'][0]
        self.assertEqual(row['occurrences'], len(expected))
        self.assertEqual([int(entry['ea'], 16) for entry in row['evidence']],
                         [0x1000 + start for start in expected[:16]])


class Conditions(unittest.TestCase):
    def test_boolean_operators_and_precedence(self):
        cases = [
            ('$a', b'AAA', True), ('$a', b'zzz', False),
            ('any of them', b'BBB', True), ('any of them', b'zzz', False),
            ('all of them', b'AAABBBCCC', True), ('all of them', b'AAABBB', False),
            ('2 of them', b'AAABBB', True), ('2 of them', b'AAA', False),
            ('2 of them', b'BBBBBB', False),
            ('3 of them', b'AAABBBCCC', True), ('3 of them', b'AAABBB', False),
            ('not $a', b'BBB', True), ('not $a', b'AAA', False),
            ('not $a and $b', b'BBB', True), ('not $a and $b', b'AAA', False),
            ('not ($a and $b)', b'AAA', True), ('not ($a and $b)', b'AAABBB', False),
            ('$a or $b and $c', b'AAA', True),
            ('($a or $b) and $c', b'AAA', False),
            ('($a or $b) and $c', b'AAACCC', True),
        ]
        for condition, data, expected in cases:
            with self.subTest(condition=condition, data=data):
                self.assertEqual(bool(scan_scoped(data, condition)['matches']), expected)

    def test_constant_conditions_and_stringless_rules(self):
        yes = scan_rules('rule t { condition: true }\n', b'anything')
        no = scan_rules('rule t { condition: false }\n', b'anything')
        self.assertEqual(matched(yes), ['t'])
        self.assertEqual(yes['matches'][0]['stringsMatched'], 0)
        self.assertEqual(yes['matches'][0]['strings'], 0)
        self.assertEqual(no['matches'], [])

    def test_hits_count_strings_not_variants(self):
        source = 'rule t { strings: $a = "AB" wide ascii condition: all of them }\n'
        self.assertEqual(matched(scan_rules(source, b'AB')), ['t'])
        self.assertEqual(matched(scan_rules(source, b'A\x00B\x00')), ['t'])
        self.assertEqual(scan_rules(source, b'AB')['matches'][0]['stringsMatched'], 1)
        self.assertEqual(scan_rules(source, b'AB')['matches'][0]['strings'], 1)

    def test_overlapping_occurrences_are_all_counted(self):
        row = scan_rules('rule t { strings: $a = "AA" condition: $a }\n', b'AAA')['matches'][0]
        self.assertEqual(row['occurrences'], 2)
        self.assertEqual([entry['ea'] for entry in row['evidence']], ['0x1000', '0x1001'])


class Budgets(unittest.TestCase):
    def test_evidence_and_occurrence_caps_are_reported(self):
        source = 'rule t { strings: $a = "AA" condition: $a }\n'
        capped = scan_rules(source, b'AA-' * 10, max_rule_matches=3)
        row = capped['matches'][0]
        self.assertEqual(row['occurrences'], 10)
        self.assertEqual(len(row['evidence']), 3)
        self.assertTrue(capped['coverage']['matchesTruncated'])
        self.assertTrue(capped['coverage']['truncated'])
        exact = scan_rules(source, b'AA-' * 3, max_rule_matches=3)
        self.assertEqual(len(exact['matches'][0]['evidence']), 3)
        self.assertFalse(exact['coverage']['matchesTruncated'])
        self.assertFalse(exact['coverage']['truncated'])

    def test_occurrence_cap_bounds_a_one_byte_pattern(self):
        # The cap is part of the documented contract, so pin the literal too;
        # comparing against the module constant alone would let a change to the
        # constant slip through.
        self.assertEqual(rule_match.MAX_OCCURRENCES_PER_PATTERN, 1024)
        source = 'rule t { strings: $a = "A" condition: $a }\n'
        report = scan_rules(source, b'A' * 2000, max_rule_matches=4096)
        row = report['matches'][0]
        self.assertEqual(row['occurrences'], 1024)
        self.assertTrue(report['coverage']['occurrencesTruncated'])
        self.assertTrue(report['coverage']['truncated'])
        self.assertFalse(report['coverage']['matchesTruncated'])
        boundary = scan_rules(source, b'A' * 1023, max_rule_matches=4096)
        self.assertEqual(boundary['matches'][0]['occurrences'], 1023)
        self.assertFalse(boundary['coverage']['occurrencesTruncated'])
        # Reaching the cap is reported as truncated: with the counter stopped at
        # 1024 the scanner cannot tell "exactly 1024" from "more than 1024".
        at_cap = scan_rules(source, b'A' * 1024, max_rule_matches=4096)
        self.assertEqual(at_cap['matches'][0]['occurrences'], 1024)
        self.assertTrue(at_cap['coverage']['occurrencesTruncated'])

    def test_scan_truncation_flag_mirrors_the_report(self):
        source = 'rule t { strings: $a = "AA" condition: $a }\n'
        result = scan_image([segment(b'AA-' * 10)], source_engine='test',
                            params={'rules': source, 'max_rule_matches': 2})
        self.assertTrue(result['truncation']['rule_matches'])
        self.assertTrue(result['truncated'])
        self.assertEqual(result['ruleMatches']['coverage']['bytesScanned'], result['coverage']['bytesRead'])

    def test_rule_budget_validation(self):
        for value in (0, -1, True, '10', 1.5, 4097):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    scan_rules('rule t { condition: true }\n', b'!', max_rule_matches=value)


class Chunks(unittest.TestCase):
    def marker(self, body):
        return 'rule t { strings: $a = %s condition: $a }\n' % body

    def test_every_split_of_a_marker_across_a_chunk_boundary_matches_once(self):
        cases = [
            (b'ABCDEFGH', '"ABCDEFGH"'),
            (b'A\x00B\x00C\x00D\x00', '"ABCD" wide'),
            (b'MZ\xee\x00\x11\x22', '{ 4D 5A ?? 00 11 22 }'),
        ]
        for marker, declaration in cases:
            source = self.marker(declaration)
            for split in range(1, len(marker) + 1):
                with self.subTest(marker=marker, split=split):
                    data = b'\x00' * (CHUNK_SIZE - split) + marker + b'\x00' * CHUNK_SIZE
                    report = scan_rules(source, data)
                    self.assertEqual(matched(report), ['t'])
                    self.assertEqual(report['matches'][0]['occurrences'], 1)
                    self.assertEqual(report['matches'][0]['evidence'][0]['ea'],
                                     hex(0x1000 + CHUNK_SIZE - split))

    def test_repeated_markers_across_chunks_are_not_lost_or_duplicated(self):
        source = self.marker('"XY"')
        data = (b'XY' + b'\x00' * 98) * 100
        report = scan_rules(source, data, max_rule_matches=4096)
        row = report['matches'][0]
        self.assertEqual(row['occurrences'], 100)
        self.assertEqual(int(row['evidence'][0]['ea'], 16), 0x1000)
        self.assertEqual(len(row['evidence']), 16)      # the per-rule evidence listing is bounded

    def test_short_pattern_inside_the_overlap_tail_is_not_counted_twice(self):
        # The tail length comes from the *longest* pattern, so a shorter pattern
        # can sit wholly inside the tail and would be re-counted on the next
        # buffer without the fresh_from filter.
        source = ('rule t { strings:\n'
                  '  $long = "AAAA"\n'
                  '  $short = "BB"\n'
                  '  condition: $short\n'
                  '}\n')
        data = b'\x00' * (CHUNK_SIZE - 2) + b'BB' + b'\x00' * CHUNK_SIZE
        report = scan_rules(source, data)
        self.assertEqual(report['matches'][0]['occurrences'], 1)
        self.assertEqual(len(report['matches'][0]['evidence']), 1)
        self.assertEqual(int(report['matches'][0]['evidence'][0]['ea'], 16),
                         0x1000 + CHUNK_SIZE - 2)

    def test_a_marker_split_across_non_contiguous_segments_does_not_match(self):
        source = self.marker('"ABCD"')
        segments = [segment(b'AB', base=0x1000), segment(b'CD', base=0x2000)]
        report = scan_image(segments, source_engine='test', params={'rules': source})['ruleMatches']
        self.assertEqual(report['matches'], [])

    def test_no_match_is_invented_across_an_unread_gap(self):
        source = self.marker('"ABCD"')
        data = bytearray(1000)
        data[200:204] = b'ABCD'
        report = scan_image([segment(data)], source_engine='test',
                            params={'rules': source, 'max_bytes': 120, 'max_segment_bytes': 120})['ruleMatches']
        self.assertEqual(report['matches'], [])
        self.assertEqual(report['coverage']['bytesScanned'], 120)

    def test_non_memory_address_spaces_are_not_scanned(self):
        overlay = segment(b'UPX!')
        overlay.update(addressSpace='overlay', sourceAddress='overlay:00000000')
        result = scan_image([overlay], source_engine='test')
        self.assertEqual(result['ruleMatches']['matches'], [])
        self.assertEqual(result['ruleMatches']['coverage']['bytesScanned'], 0)


class ScanIntegration(unittest.TestCase):
    def test_custom_rules_replace_the_builtin_table(self):
        source = 'rule custom_only { condition: true }\n'
        result = scan_image([segment(b'UPX!')], source_engine='test', params={'rules': source})['ruleMatches']
        self.assertEqual(result['ruleSet'], {'origin': 'custom', 'version': rule_match.SUBSET_VERSION,
                                             'rules': 1, 'strings': 0})
        self.assertEqual(matched(result), ['custom_only'])

    def test_missing_rules_uses_the_builtin_table(self):
        result = scan_image([segment(b'UPX!')], source_engine='test')['ruleMatches']
        self.assertEqual(result['ruleSet']['origin'], 'builtin')
        self.assertEqual(matched(result), ['upx_stub'])

    def test_rule_source_parameter_is_validated(self):
        for value in (0, [], {}, b'rule t { condition: true }'):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(ValueError):
                    scan_image([segment(b'!')], source_engine='test', params={'rules': value})
        with self.assertRaises(ValueError):
            scan_image([segment(b'!')], source_engine='test', params={'rules': '   \n'})
        with self.assertRaises(ValueError):
            scan_image([segment(b'!')], source_engine='test', params={'rules': 'x' * 65537})
        with self.assertRaises(RuleError):
            scan_image([segment(b'!')], source_engine='test',
                       params={'rules': 'rule t { strings: $a = /MZ/ condition: $a }'})

    def test_empty_inputs_and_serialisation(self):
        report = scan_image([segment(b'')], source_engine='test')['ruleMatches']
        self.assertEqual(report['matches'], [])
        self.assertEqual(report['coverage']['bytesScanned'], 0)
        data = b'\x00' * 8 + b'.vmp0' + b'\x00' * 40 + b'UPX!'
        first = scan_image([segment(data)], source_engine='test')['ruleMatches']
        second = scan_image([segment(data)], source_engine='test')['ruleMatches']
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))
        self.assertEqual(matched(first), ['upx_stub', 'vmprotect'])
        json.loads(json.dumps(first))


CORPUS = Path(os.environ.get('IG5_PROTECTION_CORPUS')
              or Path.home() / '.dsh' / 'ig5' / 'artifacts' / 'corpus-expansion-20261014' / 'corpus')
# Labels come from the corpus' own file names / protection tools, not from this matcher:
#   derived/<sha prefix>  = files whose section tables name the tool (see test_packer_analysis.py)
#   vmp-research/test1    = VMProtect research sample
PREFIX_RULES = {'5677a1d4': 'upx_stub', 'e116d143': 'upx_stub', 'fe3d0b7a': 'upx_stub',
                '31de7bde': 'themida_winlicense', '8ebb3580': 'aspack', '31bb7af8': 'pyinstaller_bundle'}
FILE_RULES = {'vmp-research/test1/test.vmp.exe': 'vmprotect'}
CLEAN_PREFIXES = ['17d59691', '26461a60', '2abf0aab', '37875703', '6296cbd8', '72106d93', '895664c5',
                  '94fb3e3d', '97fc1b5a', '986acccb', '9c7b713a', 'ad32240b', 'b53bf960', 'c2a2ab5c',
                  'd3283413', 'f8d5d7e9']
PLAIN_FILES = ['vmp-research/test1/test.exe', 'salwan-vmp/vmp_binaries/binaries/sample1.bin',
               'salwan-vmp/vmp_binaries/binaries/sample5.bin', 'salwan-vmp/vmp_binaries/binaries/sample6.bin']


def scan_file(path, **params):
    data = Path(path).read_bytes()
    options = {'max_bytes': 64 * 1024 * 1024, 'max_segment_bytes': 16 * 1024 * 1024}
    options.update(params)
    result = scan_image([segment(data, base=0x1000, name='.file')], source_engine='test', params=options)
    return data, result['ruleMatches']


@unittest.skipUnless((CORPUS / 'derived').is_dir(), 'real protection corpus not found at %s' % CORPUS)
class RealCorpus(unittest.TestCase):
    def test_files_whose_tool_is_known_match_that_rule(self):
        expected = {}
        for prefix, rule in PREFIX_RULES.items():
            path = next(iter(glob.glob(str(CORPUS / 'derived' / (prefix + '*')))), None)
            self.assertIsNotNone(path, prefix)
            expected[path] = rule
        for relative, rule in FILE_RULES.items():
            path = CORPUS / relative
            self.assertTrue(path.is_file(), relative)
            expected[str(path)] = rule
        for path, rule in expected.items():
            with self.subTest(os.path.basename(path)):
                _, report = scan_file(path)
                self.assertIn(rule, matched(report))

    def test_plain_originals_and_clean_corpus_files_match_nothing(self):
        paths = []
        for prefix in CLEAN_PREFIXES:
            path = next(iter(glob.glob(str(CORPUS / 'derived' / (prefix + '*')))), None)
            self.assertIsNotNone(path, prefix)
            paths.append(path)
        for relative in PLAIN_FILES:
            path = CORPUS / relative
            self.assertTrue(path.is_file(), relative)
            paths.append(str(path))
        for path in paths:
            with self.subTest(os.path.basename(path)):
                _, report = scan_file(path)
                self.assertEqual(report['matches'], [], path)


WINDOWS = Path(os.environ.get('SystemRoot', r'C:\Windows'))
# Native binaries that carry .NET hosting strings (the mscoree.dll COM activation shim) but no
# CLR metadata; the built-in dotnet_managed rule must stay quiet on them.
NATIVE_CONTROLS = ['kernel32.dll', 'advapi32.dll', 'user32.dll', 'notepad.exe', 'shell32.dll',
                   'combase.dll', 'mscoree.dll', 'msvcrt.dll', 'ucrtbase.dll', 'atl100.dll',
                   'sxs.dll', 'catsrv.dll']


@unittest.skipUnless((WINDOWS / 'System32').is_dir(), 'Windows system directory not found')
class RealWindowsFiles(unittest.TestCase):
    def test_native_controls_match_no_rule(self):
        for name in NATIVE_CONTROLS:
            path = WINDOWS / 'System32' / name
            if not path.is_file():
                continue
            with self.subTest(name):
                _, report = scan_file(path)
                self.assertEqual(report['matches'], [], name)

    def test_system_sample_has_few_managed_hits_and_no_packer_hits(self):
        files = [path for path in sorted(glob.glob(str(WINDOWS / 'System32' / '*')))
                 if os.path.isfile(path) and os.path.getsize(path) > 4096]
        step = max(1, len(files) // 300)
        sample = files[::step][:300]
        self.assertGreaterEqual(len(sample), 300)
        managed, other = [], []
        for path in sample:
            data, report = scan_file(path, max_bytes=8 * 1024 * 1024, max_segment_bytes=1024 * 1024)
            for row in report['matches']:
                if row['rule'] == 'dotnet_managed':
                    managed.append((path, data))
                else:
                    other.append((path, row['rule']))
        self.assertEqual(other, [], 'a clean Windows file matched a packer/installer rule')
        self.assertLessEqual(len(managed), 10, [os.path.basename(path) for path, _ in managed])
        for path, data in managed:
            self.assertIn(b'BSJB', data, path)
            self.assertIn(b'#Strings', data, path)

    def test_real_managed_assemblies_are_detected(self):
        directories = [WINDOWS / 'Microsoft.NET' / 'Framework64' / 'v4.0.30319',
                       WINDOWS / 'Microsoft.NET' / 'Framework' / 'v4.0.30319']
        names = ['mscorlib.dll', 'System.dll', 'System.Core.dll', 'Microsoft.CSharp.dll']
        found = 0
        for directory in directories:
            for name in names:
                path = directory / name
                if not path.is_file():
                    continue
                found += 1
                with self.subTest(name=name):
                    _, report = scan_file(path)
                    self.assertIn('dotnet_managed', matched(report), str(path))
        if not found:
            self.skipTest('no .NET framework assemblies on this machine')


# ---- real Ghidra acceptance -------------------------------------------------------------------------------------------

CUSTOM_SOURCE = '''
rule ig5_custom_marker : probe acceptance {
  meta:
    description = "generated acceptance marker"
  strings:
    $marker = "IG5-CUSTOM-MARK"
  condition:
    $marker
}
'''


def pe_with_text(payload):
    """A minimal one-section PE64 whose .text starts at RVA 0x1000 with ``payload``."""
    raw, span = 0x200, 0x200
    image = bytearray(raw + span)
    def u16(offset, value): struct.pack_into('<H', image, offset, value)
    def u32(offset, value): struct.pack_into('<I', image, offset, value)
    def u64(offset, value): struct.pack_into('<Q', image, offset, value)
    image[0:2] = b'MZ'
    u32(0x3C, 0x80)
    image[0x80:0x84] = b'PE\0\0'
    u16(0x84, 0x8664); u16(0x86, 1); u16(0x94, 0xF0); u16(0x96, 0x22)
    optional = 0x98
    u16(optional, 0x20B)
    u32(optional + 4, span)                 # SizeOfCode
    u32(optional + 16, 0x1000)              # AddressOfEntryPoint
    u32(optional + 20, 0x1000)              # BaseOfCode
    u64(optional + 24, 0x140000000)         # ImageBase
    u32(optional + 32, 0x1000)              # SectionAlignment
    u32(optional + 36, 0x200)               # FileAlignment
    u16(optional + 40, 6); u16(optional + 48, 6)
    u32(optional + 56, 0x2000)              # SizeOfImage
    u32(optional + 60, raw)                 # SizeOfHeaders
    u16(optional + 68, 3)                   # Subsystem: console
    u64(optional + 72, 0x100000); u64(optional + 80, 0x1000)
    u64(optional + 88, 0x100000); u64(optional + 96, 0x1000)
    u32(optional + 108, 16)                 # NumberOfRvaAndSizes
    section = optional + 0xF0
    image[section:section + 8] = b'.text\0\0\0'
    u32(section + 8, span); u32(section + 12, 0x1000)
    u32(section + 16, span); u32(section + 20, raw)
    u32(section + 36, 0x60000020)
    image[raw:raw + span] = b'\xcc' * span
    image[raw:raw + len(payload)] = payload
    return bytes(image)


def rpc_error(session, method, params):
    import time
    session.counter += 1
    mark = session.counter
    session.process.stdin.write(json.dumps({'id': mark, 'method': method, 'params': params}) + '\n')
    session.process.stdin.flush()
    deadline = time.monotonic() + session.timeout
    while time.monotonic() < deadline:
        line = session.messages.get(timeout=max(0.1, deadline - time.monotonic()))
        if line is None:
            raise AssertionError('Ghidra worker exited; see ' + str(session.scratch / 'stderr.log'))
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if message.get('id') == mark and ('result' in message or 'error' in message):
            return message.get('error'), message.get('result')
    raise AssertionError('Ghidra RPC timeout')


class GhidraAcceptance(unittest.TestCase):
    runtime = False

    def test_scan_accepts_caller_rules_and_rejects_unsupported_syntax(self):
        if not self.runtime:
            self.skipTest('run with --runtime ghidra')
        from ghidra_session import GhidraSession
        marker = b'IG5-CUSTOM-MARK'
        payload = b'UPX!' + b'\x00' * 4 + (marker + b'\x00') * 3
        image = pe_with_text(payload)
        with GhidraSession(image, filename='rule_fixture.exe', timeout=240) as session:
            builtin = session.rpc('scan')
            builtin_rules = {row['rule'] for row in builtin['ruleMatches']['matches']}
            self.assertEqual(builtin['ruleMatches']['ruleSet']['origin'], 'builtin')
            self.assertIn('upx_stub', builtin_rules)
            self.assertNotIn('ig5_custom_marker', builtin_rules)

            custom = session.rpc('scan', {'rules': CUSTOM_SOURCE})
            self.assertEqual(custom['ruleMatches']['ruleSet']['origin'], 'custom')
            self.assertEqual(custom['ruleMatches']['ruleSet']['version'], rule_match.SUBSET_VERSION)
            self.assertEqual([row['rule'] for row in custom['ruleMatches']['matches']], ['ig5_custom_marker'])
            self.assertEqual(custom['ruleMatches']['matches'][0]['evidence'][0]['ea'], '0x140001008')

            limited = session.rpc('scan', {'rules': CUSTOM_SOURCE, 'max_rule_matches': 1})
            self.assertEqual(len(limited['ruleMatches']['matches'][0]['evidence']), 1)
            self.assertTrue(limited['ruleMatches']['coverage']['matchesTruncated'])
            self.assertTrue(limited['truncation']['rule_matches'])

            error, result = rpc_error(session, 'scan', {'rules': 'rule t { strings: $a = /MZ/ condition: $a }'})
            self.assertTrue(error, 'unsupported syntax must be rejected, not ignored')
            self.assertIsNone(result)
            self.assertIn('unexpected character', error['message'] if isinstance(error, dict) else str(error))

            unchanged = session.source_unchanged()
            self.assertTrue(unchanged)
            self.assertFalse(custom['idb_modified'])
            print(json.dumps({'engine': 'ghidra', 'builtinRule': 'upx_stub',
                              'customRule': custom['ruleMatches']['matches'][0]['rule'],
                              'rejectedSyntax': 'regex', 'sourceUnchanged': unchanged,
                              'targetExecuted': False}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', choices=['none', 'ghidra'], default='none')
    options, rest = parser.parse_known_args()
    GhidraAcceptance.runtime = options.runtime == 'ghidra'
    unittest.main(argv=[sys.argv[0], *rest], verbosity=2)
