"""Restricted YARA-style rule matching over the bytes a scan already reads.

The subset is deliberately small and **everything outside it is rejected at compile time**
(silently ignoring a construct would turn a typo into a false negative):

``rule NAME : tag ... { meta: ... strings: ... condition: ... }``

* strings: ``$id = "text" [ascii] [wide] [nocase]`` or
  ``$id = { 4D 5A ?? 00 ?A A? }`` (byte wildcards and nibble wildcards only)
* condition: ``all of them`` / ``any of them`` / ``N of them`` / ``$id`` /
  ``not`` / ``and`` / ``or`` / parentheses / ``true`` / ``false``
* meta: ``description = "..."`` and other ``key = "value"`` or ``key = 123`` entries

Not supported (compile error): regexes, jumps ``[n-m]``, alternatives ``( | )``,
``fullword``/``xor`` modifiers, counts ``#a``, ``at``/``in``, ``for`` loops, modules.

A satisfied rule means the listed bytes occur in the ranges the caller scanned.  It is
evidence level E0: a signature lead, not proof of behavior, packing, intent or identity.
No target execution, no file access, no network; the matcher only looks at buffers the
scan provider already read.
"""
from __future__ import annotations

import re

SCHEMA = 'ig5.ruleMatches.v1'
SUBSET_VERSION = 1

MAX_RULES = 64
MAX_SOURCE_BYTES = 65536
MAX_STRINGS_PER_RULE = 32
MAX_TOTAL_STRINGS = 256
MAX_PATTERN_BYTES = 256
MAX_TAGS = 8
MAX_META_ENTRIES = 16
MAX_META_CHARS = 512
MAX_CONDITION_NODES = 128
# Occurrences counted per compiled pattern.  A rule needs one occurrence to fire, so
# counting stops here and the report says so; this is what bounds a one-byte pattern.
MAX_OCCURRENCES_PER_PATTERN = 1024

_HEX = frozenset('0123456789abcdefABCDEF')
_NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
_TAG = re.compile(r'^[a-z][a-z0-9_-]{0,31}$')
_TOKEN_IDENT = re.compile(r'[A-Za-z_][A-Za-z0-9_-]*')
_TOKEN_PID = re.compile(r'\$[A-Za-z_][A-Za-z0-9_]*')
_TOKEN_NUMBER = re.compile(r'[0-9]+')
_PUNCTUATION = frozenset('{}():=,')

TEXT_MODIFIERS = frozenset({'ascii', 'wide', 'nocase'})
SECTION_KEYWORDS = frozenset({'meta', 'strings', 'condition'})


class RuleError(ValueError):
    """The rule source is outside the supported subset or otherwise invalid."""


class _Token(object):
    __slots__ = ('kind', 'value', 'at')

    def __init__(self, kind, value, at):
        self.kind, self.value, self.at = kind, value, at

    def __repr__(self):
        return '_Token(%r, %r, %d)' % (self.kind, self.value, self.at)


def _decode_text(raw, at):
    """Decode a quoted rule literal (ASCII escapes) into bytes; non-ASCII is UTF-8."""
    out = bytearray()
    index = 0
    while index < len(raw):
        char = raw[index]
        if char != '\\':
            out.extend(char.encode('utf-8'))
            index += 1
            continue
        if index + 1 >= len(raw):
            raise RuleError('dangling backslash in string literal near character %d' % at)
        escape = raw[index + 1]
        simple = {'n': 10, 'r': 13, 't': 9, '0': 0, '\\': 92, '"': 34}
        if escape in simple:
            out.append(simple[escape])
            index += 2
            continue
        if escape == 'x':
            digits = raw[index + 2:index + 4]
            if len(digits) != 2 or any(digit not in _HEX for digit in digits):
                raise RuleError('\\x needs two hex digits near character %d' % at)
            out.append(int(digits, 16))
            index += 4
            continue
        raise RuleError('unsupported escape \\%s near character %d' % (escape, at))
    return bytes(out)


class _Lexer(object):
    def __init__(self, text):
        self.text = text
        self.pos = 0

    def _skip(self):
        while self.pos < len(self.text):
            char = self.text[self.pos]
            if char in ' \t\r\n':
                self.pos += 1
                continue
            if self.text.startswith('//', self.pos):
                newline = self.text.find('\n', self.pos)
                self.pos = len(self.text) if newline < 0 else newline + 1
                continue
            return

    def next(self):
        self._skip()
        start = self.pos
        if start >= len(self.text):
            return _Token('eof', '', start)
        char = self.text[start]
        if char == '"':
            index = start + 1
            while index < len(self.text):
                if self.text[index] == '\\':
                    index += 2
                    continue
                if self.text[index] == '"':
                    value = self.text[start + 1:index]
                    self.pos = index + 1
                    return _Token('string', value, start)
                if self.text[index] == '\n':
                    raise RuleError('unterminated string literal at character %d' % start)
                index += 1
            raise RuleError('unterminated string literal at character %d' % start)
        if char == '$':
            match = _TOKEN_PID.match(self.text, start)
            if not match:
                raise RuleError('malformed string identifier at character %d' % start)
            self.pos = match.end()
            return _Token('pid', match.group(0), start)
        if char in _PUNCTUATION:
            self.pos = start + 1
            return _Token(char, char, start)
        if char.isdigit():
            match = _TOKEN_NUMBER.match(self.text, start)
            self.pos = match.end()
            return _Token('number', int(match.group(0)), start)
        match = _TOKEN_IDENT.match(self.text, start)
        if match:
            self.pos = match.end()
            return _Token('ident', match.group(0), start)
        raise RuleError('unexpected character %r at character %d' % (char, start))

    def read_hex(self):
        """Read a hex string body; ``pos`` is already just past ``{``."""
        items = []
        while True:
            self._skip()
            if self.pos >= len(self.text):
                raise RuleError('unterminated hex string started at character %d' % self.pos)
            char = self.text[self.pos]
            if char == '}':
                self.pos += 1
                return items
            if char in '[(':
                raise RuleError('hex jumps, alternatives and regex are outside the supported subset '
                                '(character %d)' % self.pos)
            if char == '?':
                if self.text.startswith('??', self.pos):
                    items.append(('wild', 0, 0))
                    self.pos += 2
                    continue
                following = self.text[self.pos + 1:self.pos + 2]
                if following in _HEX:
                    items.append(('nibble', int(following, 16), 'low'))
                    self.pos += 2
                    continue
                raise RuleError('malformed wildcard at character %d' % self.pos)
            if char in _HEX:
                pair = self.text[self.pos:self.pos + 2]
                if len(pair) == 2 and pair[1] in _HEX:
                    items.append(('byte', int(pair, 16), 0))
                    self.pos += 2
                    continue
                if len(pair) == 2 and pair[1] == '?':
                    items.append(('nibble', int(char, 16), 'high'))
                    self.pos += 2
                    continue
                raise RuleError('hex bytes need two digits at character %d' % self.pos)
            raise RuleError('unexpected %r inside hex string at character %d' % (char, self.pos))


def _hex_regex(items):
    parts = []
    for kind, value, side in items:
        if kind == 'byte':
            parts.append(re.escape(bytes([value])))
        elif kind == 'wild':
            parts.append(b'.')
        else:
            # ``?A`` fixes the low nibble to A; ``4?`` fixes the high nibble to 4.
            mask = 0x0f if side == 'low' else 0xf0
            wanted = value if side == 'low' else value << 4
            candidates = [number for number in range(0x100) if number & mask == wanted]
            parts.append(b'[' + b''.join(re.escape(bytes([number])) for number in candidates) + b']')
    return b''.join(parts)


def _compile_text(raw, modifiers, at):
    data = _decode_text(raw, at)
    if not data:
        raise RuleError('empty text string near character %d' % at)
    if len(data) > MAX_PATTERN_BYTES:
        raise RuleError('text string longer than %d bytes near character %d' % (MAX_PATTERN_BYTES, at))
    patterns = []
    if 'wide' in modifiers:
        if any(byte > 0x7f for byte in data):
            raise RuleError('wide text strings must be ASCII near character %d' % at)
        patterns.append(b''.join(bytes([byte, 0]) for byte in data))
    if 'wide' not in modifiers or 'ascii' in modifiers:
        patterns.append(data)
    if any(len(pattern) > MAX_PATTERN_BYTES for pattern in patterns):
        raise RuleError('wide text string longer than %d bytes near character %d' % (MAX_PATTERN_BYTES, at))
    flags = re.DOTALL | (re.IGNORECASE if 'nocase' in modifiers else 0)
    return {'kind': 'text', 'modifiers': sorted(modifiers),
            'variants': [{'regex': re.compile(re.escape(pattern), flags), 'bytes': pattern, 'length': len(pattern)}
                         for pattern in patterns]}


def _compile_hex(items, at):
    if not items:
        raise RuleError('empty hex string near character %d' % at)
    if len(items) > MAX_PATTERN_BYTES:
        raise RuleError('hex string longer than %d bytes near character %d' % (MAX_PATTERN_BYTES, at))
    if all(kind == 'wild' for kind, _, _ in items):
        raise RuleError('hex string needs at least one fixed byte near character %d' % at)
    return {'kind': 'hex', 'modifiers': [],
            'variants': [{'regex': re.compile(_hex_regex(items), re.DOTALL), 'bytes': None, 'length': len(items)}]}


class _Parser(object):
    def __init__(self, text):
        self.text = text
        self.lexer = _Lexer(text)
        self.current = self.lexer.next()
        self.nodes = 0

    # -- token helpers --------------------------------------------------------------------------------------------
    def advance(self):
        token = self.current
        self.current = self.lexer.next()
        return token

    def expect(self, kind, what):
        if self.current.kind != kind:
            raise RuleError('expected %s near character %d, found %r' % (what, self.current.at, self.current.value))
        return self.advance()

    def accept_keyword(self, value):
        if self.current.kind == 'ident' and self.current.value == value:
            self.advance()
            return True
        return False

    def _them(self):
        of = self.expect('ident', "'of'")
        if of.value != 'of':
            raise RuleError("expected 'of' near character %d" % of.at)
        them = self.expect('ident', "'them'")
        if them.value != 'them':
            raise RuleError("expected 'them' near character %d" % them.at)

    # -- grammar --------------------------------------------------------------------------------------------------
    def parse(self, max_rules):
        rules = []
        while self.current.kind != 'eof':
            if len(rules) >= max_rules:
                raise RuleError('more than %d rules' % max_rules)
            rules.append(self.rule())
        if not rules:
            raise RuleError('rule source contains no rules')
        return rules

    def rule(self):
        start = self.expect('ident', "the word 'rule'")
        if start.value != 'rule':
            raise RuleError("expected 'rule' near character %d, found %r" % (start.at, start.value))
        name = self.expect('ident', 'a rule name')
        if not _NAME.match(name.value):
            raise RuleError('invalid rule name %r at character %d' % (name.value, name.at))
        tags = []
        if self.current.kind == ':':
            self.advance()
            while self.current.kind == 'ident':
                tag = self.advance().value
                if tag in SECTION_KEYWORDS:
                    raise RuleError('tag %r collides with a section keyword' % tag)
                if not _TAG.match(tag):
                    raise RuleError('invalid tag %r; tags are lower-case [a-z0-9_-], at most 32 characters' % tag)
                if tag in tags:
                    raise RuleError('duplicate tag %r' % tag)
                if len(tags) >= MAX_TAGS:
                    raise RuleError('more than %d tags' % MAX_TAGS)
                tags.append(tag)
        self.expect('{', "'{'")
        meta = self.meta()
        strings = self.strings()
        condition = self.condition(strings)
        self.expect('}', "'}'")
        return {'id': name.value, 'tags': tags, 'meta': meta, 'strings': strings, 'condition': condition,
                'at': name.at}

    def meta(self):
        values = {}
        if not self.accept_keyword('meta'):
            return values
        self.expect(':', "':' after meta")
        while self.current.kind == 'ident' and self.current.value not in SECTION_KEYWORDS:
            key = self.advance()
            if not _NAME.match(key.value):
                raise RuleError('invalid meta key %r at character %d' % (key.value, key.at))
            self.expect('=', "'=' after a meta key")
            if self.current.kind not in ('string', 'number'):
                raise RuleError('meta %r needs a quoted string or integer near character %d'
                                % (key.value, self.current.at))
            token = self.advance()
            value = _decode_text(token.value, token.at).decode('utf-8', 'replace') if token.kind == 'string' else token.value
            if len(str(value)) > MAX_META_CHARS:
                raise RuleError('meta %r is longer than %d characters' % (key.value, MAX_META_CHARS))
            if key.value in values:
                raise RuleError('duplicate meta key %r' % key.value)
            if len(values) >= MAX_META_ENTRIES:
                raise RuleError('more than %d meta entries' % MAX_META_ENTRIES)
            values[key.value] = value
        return values

    def strings(self):
        rows = []
        if not self.accept_keyword('strings'):
            return rows
        self.expect(':', "':' after strings")
        while self.current.kind == 'pid':
            rows.append(self.string())
            if len(rows) > MAX_STRINGS_PER_RULE:
                raise RuleError('more than %d strings in one rule' % MAX_STRINGS_PER_RULE)
        return rows

    def string(self):
        identifier = self.advance()
        at = identifier.at
        self.expect('=', "'=' after %s" % identifier.value)
        if self.current.kind == '{':
            items = self.lexer.read_hex()
            self.current = self.lexer.next()
            compiled = _compile_hex(items, at)
        elif self.current.kind == 'string':
            token = self.advance()
            modifiers = set()
            while self.current.kind == 'ident' and self.current.value in TEXT_MODIFIERS:
                modifier = self.advance().value
                if modifier in modifiers:
                    raise RuleError('duplicate modifier %r near character %d' % (modifier, at))
                modifiers.add(modifier)
            if self.current.kind == 'ident' and self.current.value not in SECTION_KEYWORDS:
                raise RuleError('unsupported string modifier %r near character %d'
                                % (self.current.value, self.current.at))
            compiled = _compile_text(token.value, modifiers, at)
        else:
            raise RuleError('string %s needs a quoted text or hex body near character %d'
                            % (identifier.value, self.current.at))
        return {'id': identifier.value, **compiled, 'at': at}

    def condition(self, strings):
        self.nodes = 0                      # the node budget applies to one condition
        keyword = self.expect('ident', 'condition')
        if keyword.value != 'condition':
            raise RuleError("expected 'condition' near character %d" % keyword.at)
        self.expect(':', "':' after condition")
        node = self.expression()
        self._validate_condition(node, strings)
        return node

    def _node(self):
        self.nodes += 1
        if self.nodes > MAX_CONDITION_NODES:
            raise RuleError('condition has more than %d nodes' % MAX_CONDITION_NODES)

    def expression(self):
        """or-expression: ``and`` binds tighter than ``or``, ``not`` tighter than both."""
        self._node()
        node = self.and_expression()
        while self.current.kind == 'ident' and self.current.value == 'or':
            self.advance()
            node = ('or', node, self.and_expression())
        return node

    def and_expression(self):
        self._node()
        node = self.unary()
        while self.current.kind == 'ident' and self.current.value == 'and':
            self.advance()
            node = ('and', node, self.unary())
        return node

    def unary(self):
        self._node()
        if self.accept_keyword('not'):
            return ('not', self.unary())
        return self.primary()

    def primary(self):
        if self.current.kind == '(':
            self.advance()
            node = self.expression()
            self.expect(')', "')'")
            return node
        if self.current.kind == 'pid':
            return ('id', self.advance().value)
        if self.current.kind == 'ident' and self.current.value in ('all', 'any'):
            which = self.advance().value
            self._them()
            return ('of', which)
        if self.current.kind == 'number':
            count = self.advance().value
            self._them()
            return ('of', count)
        if self.current.kind == 'ident' and self.current.value in ('true', 'false'):
            return ('const', self.advance().value == 'true')
        raise RuleError('unsupported condition near character %d: %r' % (self.current.at, self.current.value))

    def _validate_condition(self, node, strings):
        known = {row['id'] for row in strings}
        total = len(strings)

        def walk(item):
            kind = item[0]
            if kind == 'id':
                if item[1] not in known:
                    raise RuleError('condition names undefined string %s' % item[1])
            elif kind in ('and', 'or'):
                walk(item[1])
                walk(item[2])
            elif kind == 'not':
                walk(item[1])
            elif kind == 'of':
                if total == 0:
                    raise RuleError("'of them' needs at least one string")
                if isinstance(item[1], int) and not 1 <= item[1] <= total:
                    raise RuleError('condition asks for %d of %d strings' % (item[1], total))
        walk(node)


def _evaluate(node, hits, total):
    kind = node[0]
    if kind == 'const':
        return node[1]
    if kind == 'id':
        return node[1] in hits
    if kind == 'and':
        return _evaluate(node[1], hits, total) and _evaluate(node[2], hits, total)
    if kind == 'or':
        return _evaluate(node[1], hits, total) or _evaluate(node[2], hits, total)
    if kind == 'not':
        return not _evaluate(node[1], hits, total)
    if kind == 'of':
        which = node[1]
        if which == 'all':
            return total > 0 and len(hits) == total
        if which == 'any':
            return len(hits) > 0
        return len(hits) >= which
    raise AssertionError('unknown condition node %r' % (node,))


class _Variant(object):
    __slots__ = ('rule', 'string', 'regex', 'length', 'occurrences', 'locations', 'capped')

    def __init__(self, rule, string, regex, length):
        self.rule, self.string, self.regex, self.length = rule, string, regex, length
        self.occurrences = 0
        self.locations = []
        self.capped = False


class RuleSet(object):
    """A compiled rule set plus its per-scan match state (one instance per scan)."""

    def __init__(self, rules, origin, version, max_locations):
        self.rules = rules
        self.origin = origin
        self.version = version
        self.max_locations = int(max_locations)
        self.recorded = 0
        self.matches_truncated = False
        self.occurrences_truncated = False
        self.variants = []
        for index, rule in enumerate(rules):
            for row in rule['strings']:
                for variant in row['variants']:
                    self.variants.append(_Variant(index, row['id'], variant['regex'], variant['length']))
        self.overlap = max([variant.length for variant in self.variants] or [0]) - 1
        self.overlap = max(0, self.overlap)

    def feed(self, buffer, base, segment, fresh_from):
        """Match one scan buffer.  ``fresh_from`` bytes at its start were already scanned."""
        if not buffer:
            return
        for variant in self.variants:
            if variant.capped:
                continue
            position = 0
            while variant.occurrences < MAX_OCCURRENCES_PER_PATTERN:
                match = variant.regex.search(buffer, position)
                if match is None:
                    break
                start, end = match.start(), match.end()
                position = start + 1
                if end <= fresh_from:
                    continue                      # wholly inside the overlap tail: already seen
                variant.occurrences += 1
                if self.recorded < self.max_locations:
                    variant.locations.append({'string': variant.string, 'segment': segment,
                                              'ea': hex(base + start), 'length': end - start})
                    self.recorded += 1
                else:
                    self.matches_truncated = True
                if variant.occurrences >= MAX_OCCURRENCES_PER_PATTERN:
                    variant.capped = True
                    self.occurrences_truncated = True

    def result(self, bytes_scanned):
        hits = [set() for _ in self.rules]
        occurrences = [0 for _ in self.rules]
        evidence = [[] for _ in self.rules]
        for variant in self.variants:
            if variant.occurrences:
                hits[variant.rule].add(variant.string)
                occurrences[variant.rule] += variant.occurrences
                if evidence[variant.rule] is not None:
                    evidence[variant.rule].extend(variant.locations)
        matches = []
        for index, rule in enumerate(self.rules):
            if not _evaluate(rule['condition'], hits[index], len(rule['strings'])):
                continue
            matches.append({'rule': rule['id'], 'tags': list(rule['tags']),
                            'description': str(rule['meta'].get('description', '')),
                            'stringsMatched': len(hits[index]), 'strings': len(rule['strings']),
                            'occurrences': occurrences[index], 'evidence': evidence[index][:16]})
        return {'schema': SCHEMA, 'evidenceLevel': 'E0',
                'ruleSet': {'origin': self.origin, 'version': self.version, 'rules': len(self.rules),
                            'strings': len(self.variants)},
                'matches': matches,
                'coverage': {'bytesScanned': int(bytes_scanned),
                             'sampling': 'same bounded ranges as the indicator sweep; unread ranges were not matched',
                             'matchedRules': len(matches), 'matchesTruncated': self.matches_truncated,
                             'occurrencesTruncated': self.occurrences_truncated,
                             'truncated': bool(self.matches_truncated or self.occurrences_truncated)},
                'note': 'A satisfied rule means those bytes occur in the scanned ranges. It is a signature lead, '
                        'not proof of behavior, packing, intent or identity.'}


def compile_rules(source, *, origin='custom', version=SUBSET_VERSION, max_locations=256):
    """Parse and compile a restricted YARA-style rule source.  Raises RuleError."""
    if not isinstance(source, str):
        raise RuleError('rule source must be text')
    encoded = source.encode('utf-8')
    if len(encoded) > MAX_SOURCE_BYTES:
        raise RuleError('rule source is longer than %d bytes' % MAX_SOURCE_BYTES)
    if not source.strip():
        raise RuleError('rule source is empty')
    rules = _Parser(source).parse(MAX_RULES)
    identifiers = [rule['id'] for rule in rules]
    if len(set(identifiers)) != len(identifiers):
        raise RuleError('rule identifiers must be unique')
    total_strings = sum(len(rule['strings']) for rule in rules)
    if total_strings > MAX_TOTAL_STRINGS:
        raise RuleError('more than %d strings in total' % MAX_TOTAL_STRINGS)
    return RuleSet(rules, origin, version, max_locations)
