"""Behavior inventory: taxonomy integrity, backward compatibility, aggregation precision, and a real-engine acceptance.

Unit tests need only the bundled Python. The real-engine acceptance (``--runtime ghidra``) analyzes a generated PE
and never executes it. Run:  runtimes/ghidra/python/python.exe -I -B -X utf8 scripts/test_behavior_inventory.py [--runtime ghidra]
"""
from pathlib import Path
import argparse
import copy
import json
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'worker'))
sys.path.insert(0, str(ROOT / 'scripts'))
import behavior_rules as rules
from behavior_inventory import behavior_inventory
from scan_analysis import scan_image

# The API table exactly as scan_analysis.py shipped it before the taxonomy moved: no name may lose its category.
ORIGINAL_GROUPS = {
    'crypto': ('cryptencrypt', 'cryptdecrypt', 'cryptacquirecontext', 'cryptgenkey', 'cryptderivekey', 'cryptimportkey', 'crypthashdata',
               'cryptprotectdata', 'cryptunprotectdata', 'bcryptencrypt', 'bcryptdecrypt', 'bcryptgeneratesymmetrickey', 'bcryptderivekey',
               'bcryptimportkey', 'bcryptcreatehash', 'bcrypthashdata', 'bcryptgenrandom', 'ncryptdecrypt', 'ncryptencrypt',
               'evp_encryptinit_ex', 'evp_encryptupdate', 'evp_decryptinit_ex', 'evp_decryptupdate', 'aes_encrypt', 'aes_decrypt', 'rc4',
               'pk11_decrypt', 'pk11_encrypt'),
    'network': ('send', 'sendto', 'recv', 'recvfrom', 'wsasend', 'wsasendto', 'wsarecv', 'wsarecvfrom', 'socket', 'connect', 'accept', 'bind',
                'listen', 'getaddrinfo', 'ssl_read', 'ssl_write', 'ssl_read_ex', 'ssl_write_ex', 'gnutls_record_recv', 'gnutls_record_send',
                'winhttpreaddata', 'winhttpwritedata', 'winhttpsendrequest', 'winhttpconnect', 'internetreadfile', 'internetwritefile',
                'internetopenurl', 'httpsendrequest', 'urldownloadtofile'),
    'memory-execution': ('virtualalloc', 'virtualprotect', 'writeprocessmemory', 'createremotethread', 'ntallocatevirtualmemory',
                         'ntwritevirtualmemory', 'ntprotectvirtualmemory', 'mmap', 'mprotect'),
    'execution': ('winexec', 'shellexecute', 'createprocess', 'system', 'execve', 'popen'),
    'registry': ('regsetvalue', 'regsetvalueex'),
    'dynamic-loading': ('loadlibrary', 'loadlibraryex', 'getprocaddress', 'dlopen', 'dlsym'),
    'debug-detection': ('isdebuggerpresent', 'checkremotedebuggerpresent', 'ptrace'),
    'hooks': ('setwindowshookex',),
}


def refs(*triples):
    return [{'ea': site, 'function': {'ea': entry, 'name': name} if entry else None} for site, entry, name in triples]


def row(api, *triples, module='KERNEL32.dll', **extra):
    return {'api': api, 'module': module, 'referenceFunctions': refs(*triples), **extra}


class TaxonomyTests(unittest.TestCase):
    def test_no_original_api_changed_category_or_disappeared(self):
        for category, names in ORIGINAL_GROUPS.items():
            for name in names:
                self.assertEqual(rules.api_category(name), category, name)

    def test_taxonomy_is_substantially_wider_and_self_consistent(self):
        self.assertGreaterEqual(len(rules.API_CATEGORIES), 350)
        self.assertGreaterEqual(len(rules.API_GROUPS), 20)
        self.assertEqual(len(rules.API_CATEGORIES), sum(len(names) for names in rules.API_GROUPS.values()), 'a name is in two categories')
        for chain in rules.CHAINS:
            for group in chain['groups']:
                self.assertTrue(group <= set(rules.API_CATEGORIES), chain['id'])

    def test_the_gaps_that_motivated_the_rewrite_are_closed(self):
        for name, category in [('ReadProcessMemory', 'process-access'), ('OpenProcess', 'process-access'), ('CreateServiceW', 'service-driver'),
                               ('NtLoadDriver', 'service-driver'), ('AdjustTokenPrivileges', 'privilege'), ('GetAsyncKeyState', 'input-capture'),
                               ('SendInput', 'input-synthesis'), ('CreateToolhelp32Snapshot', 'process-enumeration'),
                               ('RegCreateKeyExA', 'registry'), ('process_vm_readv', 'process-access'), ('init_module', 'service-driver'),
                               ('MH_CreateHook', 'hooks'), ('NtQueryInformationProcess', 'debug-detection')]:
            self.assertEqual(rules.api_category(name), category, name)

    def test_name_normalization(self):
        cases = {'__imp_BCryptDecrypt@24': 'bcryptdecrypt', 'CreateProcessW': 'createprocess', 'CreateProcessA': 'createprocess',
                 'ZwAllocateVirtualMemory': 'ntallocatevirtualmemory', 'ZwWriteVirtualMemory': 'ntwritevirtualmemory', '_ptrace': 'ptrace',
                 'send@plt': 'send', 'InflateInit_': 'inflateinit_', 'LoadLibraryExW': 'loadlibraryex'}
        for name, key in cases.items():
            self.assertEqual(rules.canonical(name), key, name)
        for name in ('my_send_helper', 'FUN_00401000', '', 'thunk_FUN_140001000', 'sender'):
            self.assertIsNone(rules.canonical(name), name)

    def test_string_that_looks_like_an_api_name(self):
        for text in ('VirtualAllocEx', 'WriteProcessMemory', 'process_vm_readv', 'NtUnmapViewOfSection', 'CreateRemoteThread'):
            self.assertTrue(rules.is_api_name_string(text), text)
        for text in ('connect', 'system', 'accept', 'send', 'listen', 'bind', 'VirtualAllocEx is unsafe', 'C:\\x\\VirtualAllocEx', ''):
            self.assertFalse(rules.is_api_name_string(text), text)


class InventoryTests(unittest.TestCase):
    def test_function_level_precision(self):
        # WriteProcessMemory lives in a function without OpenProcess: no "foreign write" chain there.
        inventory = behavior_inventory([
            row('OpenProcess', ('0x401010', '0x401000', 'scan')), row('ReadProcessMemory', ('0x401020', '0x401000', 'scan')),
            row('CreateToolhelp32Snapshot', ('0x401004', '0x401000', 'scan')), row('WriteProcessMemory', ('0x402010', '0x402000', 'patcher'))])
        found = {(chain['id'], chain['function']['name']) for chain in inventory['chains']}
        self.assertEqual(found, {('foreign-process-memory-read', 'scan'), ('locate-and-read-process', 'scan')})
        self.assertTrue(inventory['coverage']['functionAttribution'])
        self.assertEqual(inventory['summary']['chainCounts'], {'foreign-process-memory-read': 1, 'locate-and-read-process': 1})

    def test_remote_injection_and_process_replacement(self):
        inject = behavior_inventory([row('VirtualAllocEx', ('0x1', '0x10', 'inj')), row('WriteProcessMemory', ('0x2', '0x10', 'inj')),
                                     row('CreateRemoteThread', ('0x3', '0x10', 'inj'))])
        self.assertEqual([chain['id'] for chain in inject['chains']], ['remote-code-injection'])
        self.assertEqual(inject['chains'][0]['apis'], ['createremotethread', 'virtualallocex', 'writeprocessmemory'])
        self.assertEqual(inject['chains'][0]['evidenceEas'], ['0x1', '0x2', '0x3'])
        spread = behavior_inventory([row('VirtualAllocEx', ('0x1', '0x10', 'a')), row('WriteProcessMemory', ('0x2', '0x20', 'b')),
                                     row('CreateRemoteThread', ('0x3', '0x30', 'c'))])
        self.assertEqual(spread['chains'], [], 'the same APIs spread over three functions are not a chain')
        replace = behavior_inventory([row(name, ('0x1', '0x10', 'hollow')) for name in ('CreateProcessW', 'NtUnmapViewOfSection', 'WriteProcessMemory', 'ResumeThread')])
        self.assertIn('process-replacement', [chain['id'] for chain in replace['chains']])

    def test_distinct_rule_needs_different_mechanisms(self):
        two = behavior_inventory([row('IsDebuggerPresent', ('0x1', '0x10', 'f')), row('CheckRemoteDebuggerPresent', ('0x2', '0x10', 'f'))])
        self.assertEqual([c['id'] for c in two['chains']], ['multiple-debugger-checks'])
        same = behavior_inventory([row('IsDebuggerPresent', ('0x1', '0x10', 'f'), ('0x2', '0x10', 'f'))])
        self.assertEqual(same['chains'], [], 'calling one check twice is not several mechanisms')

    def test_strings_count_as_run_time_resolution_and_are_marked(self):
        inventory = behavior_inventory(
            [row('GetProcAddress', ('0x5', '0x50', 'loader')), row('LoadLibraryA', ('0x6', '0x50', 'loader'))],
            [{'api': 'VirtualAllocEx', 'stringEa': '0x2800', 'confidence': 'medium', 'referenceFunctions': refs(('0x7', '0x50', 'loader'))}])
        self.assertEqual([c['id'] for c in inventory['chains']], ['runtime-api-resolution'])
        function = inventory['functions'][0]
        self.assertIn('virtualallocex', function['apis'])
        self.assertEqual(inventory['dynamicApiStrings'][0]['functions'], ['loader'])
        sources = {api['api']: api['sources'] for category in inventory['categories'] for api in category['apis']}
        self.assertEqual(sources['VirtualAllocEx'], ['string']); self.assertEqual(sources['GetProcAddress'], ['import'])

    def test_missing_attribution_is_reported_not_invented(self):
        inventory = behavior_inventory([{'api': 'OpenProcess', 'module': 'k', 'referenceEas': ['0x1', '0x2']},
                                        row('ReadProcessMemory', ('0x9', None, None))])
        self.assertEqual(inventory['chains'], [])
        self.assertEqual(inventory['coverage']['unattributedReferences'], 1)
        self.assertEqual(sum(api['referenceCount'] for c in inventory['categories'] for api in c['apis']), 3)

    def test_truncation_flags_and_determinism(self):
        rows = [row(f'OpenProcess' if i == 0 else 'ReadProcessMemory', (hex(i), hex(0x1000 + i), f'fn{i}')) for i in range(300)]
        rows[0]['referencesTruncated'] = True
        before = copy.deepcopy(rows)
        first = behavior_inventory(rows)
        self.assertEqual(rows, before, 'the input must not be modified')
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(behavior_inventory(rows), sort_keys=True))
        self.assertEqual(first['coverage']['apisWithTruncatedReferences'], 1)
        self.assertTrue(first['truncation']['functions']); self.assertLessEqual(len(first['functions']), 100)
        json.dumps(first)   # strict JSON-serializable

    def test_weak_categories_never_outrank_strong_ones(self):
        inventory = behavior_inventory([row('CreateFileW', ('0x1', '0x10', 'io')), row('ReadFile', ('0x2', '0x10', 'io')),
                                        row('OpenProcess', ('0x3', '0x20', 'probe'))])
        self.assertEqual([c['strength'] for c in inventory['categories']][0], 'strong')
        self.assertEqual(inventory['functions'][0]['name'], 'probe')


class ScanIntegrationTests(unittest.TestCase):
    def scan(self, imports=(), strings=()):
        return scan_image([{'name': '.data', 'start': 0x1000, 'size': 4, 'read': lambda offset, size: b'abcd'[offset:offset + size]}],
                          imports, strings, source_engine='test')

    def test_legacy_output_is_unchanged_and_behaviors_are_added(self):
        result = self.scan([{'module': 'bcrypt.dll', 'api': '__imp_BCryptDecrypt@24', 'ea': '0x1234'}, {'module': 'winsock', 'api': 'recv'},
                            {'module': 'fixture', 'api': 'my_send_helper'}])
        self.assertEqual([r['category'] for r in result['suspicious_apis']], ['crypto', 'network'])
        self.assertIs(result['suspiciousApis'], result['suspicious_apis'])
        self.assertEqual(result['behaviors']['schemaVersion'], 1)
        self.assertFalse(result['behaviors']['coverage']['functionAttribution'], 'no provider attribution was supplied')
        json.dumps(result)

    def test_only_flagged_api_name_strings_become_dynamic_leads(self):
        result = self.scan(strings=[
            {'text': 'VirtualAllocEx', 'apiNameCandidate': True, 'ea': '0x2800', 'referenceFunctions': refs(('0x7', '0x50', 'loader'))},
            'WriteProcessMemory',                                                           # plain string: no provider address, not flagged
            {'text': 'connect', 'apiNameCandidate': True, 'ea': '0x2810', 'referenceFunctions': []},   # ordinary word
            {'text': 'process_vm_readv', 'apiNameCandidate': True, 'ea': '0x2820', 'referenceFunctions': refs(('0x8', '0x50', 'loader'))}])
        leads = result['behaviors']['dynamicApiStrings']
        self.assertEqual([lead['api'] for lead in leads], ['VirtualAllocEx', 'process_vm_readv'])
        self.assertEqual([lead['confidence'] for lead in leads], ['medium', 'low'])
        self.assertEqual(result['stringFamilies']['total'], 4)

    def test_import_table_name_entries_are_not_runtime_resolution_leads(self):
        imports = [{'module': 'KERNEL32.dll', 'api': 'VirtualAllocEx'}, {'module': 'KERNEL32.dll', 'api': 'OpenProcess'}]
        result = self.scan(imports, strings=[
            {'text': 'VirtualAllocEx', 'apiNameCandidate': True, 'ea': '0x2302', 'referenceFunctions': []},          # the import table's own entry
            {'text': 'OpenProcess', 'apiNameCandidate': True, 'ea': '0x2322', 'referenceFunctions': refs(('0x7', '0x50', 'loader'))},  # code uses it
            {'text': 'NtUnmapViewOfSection', 'apiNameCandidate': True, 'ea': '0x2340', 'referenceFunctions': []}])    # not imported, no code ref: kept
        self.assertEqual([lead['api'] for lead in result['behaviors']['dynamicApiStrings']], ['OpenProcess', 'NtUnmapViewOfSection'])

    def test_new_string_families_do_not_disturb_existing_ones(self):
        result = self.scan(strings=['http://x', r'Software\Microsoft\Windows\CurrentVersion\Run', 'VBoxService.exe', '/etc/cron.d/x'])
        families = result['stringFamilies']
        self.assertEqual(families['network'], 1); self.assertEqual(families['registry'], 1)
        self.assertEqual(families['persistence'], 2); self.assertEqual(families['anti-analysis'], 1)


# ---------------------------------------------------------------------------------------------- real engine
IMPORTS = ['CreateToolhelp32Snapshot', 'OpenProcess', 'ReadProcessMemory', 'WriteProcessMemory', 'VirtualAllocEx', 'CreateRemoteThread',
           'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'GetProcAddress', 'LoadLibraryA', 'TerminateProcess']
IAT_RVA, CODE_RVA, STRING_RVA = 0x2200, 0x1000, 0x2800


def pe_with_behaviors():
    image = bytearray(0x1400)
    def u16(o, v): struct.pack_into('<H', image, o, v)
    def u32(o, v): struct.pack_into('<I', image, o, v)
    def u64(o, v): struct.pack_into('<Q', image, o, v)
    def raw(rva): return rva - 0x1000 + 0x200 if rva < 0x2000 else rva - 0x2000 + 0x400
    def put(o, v): image[o:o + len(v)] = v
    put(0, b'MZ'); u32(0x3c, 0x80); put(0x80, b'PE\0\0')
    u16(0x84, 0x8664); u16(0x86, 2); u16(0x94, 0xf0); u16(0x96, 0x22)
    o = 0x98
    u16(o, 0x20b); u32(o + 4, 0x200); u32(o + 8, 0x1000); u32(o + 16, CODE_RVA); u32(o + 20, 0x1000); u64(o + 24, 0x140000000)
    u32(o + 32, 0x1000); u32(o + 36, 0x200); u16(o + 40, 6); u16(o + 48, 6); u32(o + 56, 0x3000); u32(o + 60, 0x200); u16(o + 68, 3)
    u64(o + 72, 0x100000); u64(o + 80, 0x1000); u64(o + 88, 0x100000); u64(o + 96, 0x1000); u32(o + 108, 16); u32(o + 120, 0x2000); u32(o + 124, 40)
    for index, name, rva, offset, size, perm in [(0, b'.text', 0x1000, 0x200, 0x200, 0x60000020), (1, b'.rdata', 0x2000, 0x400, 0x1000, 0x40000040)]:
        s = o + 0xf0 + 40 * index
        put(s, name); u32(s + 8, size); u32(s + 12, rva); u32(s + 16, size); u32(s + 20, offset); u32(s + 36, perm)
    # import table: one DLL, 11 functions
    u32(raw(0x2000), 0x2100); u32(raw(0x2000) + 12, 0x2040); u32(raw(0x2000) + 16, IAT_RVA)
    put(raw(0x2040), b'KERNEL32.dll\0')
    for index, name in enumerate(IMPORTS):
        hint_rva = 0x2300 + index * 0x20
        put(raw(hint_rva), b'\0\0' + name.encode() + b'\0')
        u64(raw(0x2100) + 8 * index, hint_rva); u64(raw(IAT_RVA) + 8 * index, hint_rva)
    put(raw(STRING_RVA), b'VirtualAllocEx\0')
    slot = lambda n: CODE_RVA + 0x40 * n
    iat = lambda name: IAT_RVA + 8 * IMPORTS.index(name)
    def call_iat(at, name): return b'\xff\x15' + struct.pack('<i', iat(name) - (at + 6))
    def jmp_iat(at, name): return b'\xff\x25' + struct.pack('<i', iat(name) - (at + 6))
    def call_rel(at, target): return b'\xe8' + struct.pack('<i', target - (at + 5))
    def lea_string(at): return b'\x48\x8d\x05' + struct.pack('<i', STRING_RVA - (at + 7))
    prologue, epilogue = b'\x48\x83\xec\x28', b'\x48\x83\xc4\x28\xc3'
    def function(n, steps):
        code = bytearray(prologue)
        for step in steps:
            code += step(slot(n) + len(code))
        return bytes(code + epilogue)
    funcs = {
        0: [lambda a: call_iat(a, 'CreateToolhelp32Snapshot'), lambda a: call_iat(a, 'OpenProcess'), lambda a: call_iat(a, 'ReadProcessMemory'),
            lambda a: call_rel(a, slot(1)), lambda a: call_rel(a, slot(2)), lambda a: call_rel(a, slot(3)), lambda a: call_rel(a, slot(4))],
        1: [lambda a: call_iat(a, 'WriteProcessMemory'), lambda a: call_iat(a, 'IsDebuggerPresent'), lambda a: call_iat(a, 'CheckRemoteDebuggerPresent')],
        2: [lambda a: call_iat(a, 'VirtualAllocEx'), lambda a: call_iat(a, 'WriteProcessMemory'), lambda a: call_iat(a, 'CreateRemoteThread')],
        3: [lambda a: lea_string(a), lambda a: call_iat(a, 'GetProcAddress'), lambda a: call_iat(a, 'LoadLibraryA')],
        4: [lambda a: call_rel(a, slot(5))],
    }
    for n, steps in funcs.items():
        code = function(n, steps)
        assert len(code) <= 0x40, (n, len(code))
        put(raw(slot(n)), code)
    put(raw(slot(5)), jmp_iat(slot(5), 'TerminateProcess'))     # an import thunk: jmp [IAT]
    return bytes(image)


def runtime_test():
    from fixtures.ghidra_session import GhidraSession
    with GhidraSession(pe_with_behaviors(), 'behavior-fixture.exe', prefix='ig5-behavior-') as ghidra:
        print('evidence directory:', ghidra.scratch)
        before = ghidra.rpc('stats')
        result = ghidra.rpc('scan')
        behaviors = result['behaviors']
        (ghidra.scratch / 'observed.json').write_text(json.dumps({'behaviors': behaviors, 'suspicious_apis': result['suspicious_apis']}, indent=2), encoding='utf-8')
        by_function = {}
        for chain in behaviors['chains']:
            by_function.setdefault(chain['function']['ea'], set()).add(chain['id'])
        functions = {row['ea']: row for row in behaviors['functions']}
        ea = lambda n: hex(0x140000000 + 0x1000 + 0x40 * n)
        # main: process enumeration + open + read
        assert by_function.get(ea(0)) == {'foreign-process-memory-read', 'locate-and-read-process'}, by_function
        # function 1: write without open => no foreign-write chain; two different debugger checks
        assert by_function.get(ea(1)) == {'multiple-debugger-checks'}, by_function
        # function 2: allocate + write + remote thread
        assert by_function.get(ea(2)) == {'remote-code-injection'}, by_function
        # function 3: run-time resolution, with VirtualAllocEx known only from a string
        assert by_function.get(ea(3)) == {'runtime-api-resolution'}, by_function
        assert 'virtualallocex' in functions[ea(3)]['apis'], functions[ea(3)]
        assert [(lead['api'], len(lead['functions'])) for lead in behaviors['dynamicApiStrings']] == [('VirtualAllocEx', 1)], \
            'only the string a function actually uses is a lead; the import table\'s own name entries are not: ' + str(behaviors['dynamicApiStrings'])
        # function 4 calls an import thunk: TerminateProcess is attributed to the CALLER, not to the stub
        assert ea(4) in functions and 'terminateprocess' in functions[ea(4)]['apis'], \
            'an API reached through an import thunk must be attributed to the thunk\'s caller: ' + str({k: v['apis'] for k, v in functions.items()})
        assert ea(5) not in functions, 'the thunk itself must not be reported as the user of the API'
        assert behaviors['coverage']['functionAttribution'] is True
        assert behaviors['coverage']['unattributedReferences'] == 0, 'the import table\'s own pointer slots must not count as uses: ' + str(behaviors['coverage'])
        assert ghidra.rpc('stats')['revision'] == before['revision'], 'scanning must not modify the database'
        assert ghidra.source_unchanged()
        print(json.dumps({'ok': True, 'engine': 'ghidra', 'chains': sorted({c['id'] for c in behaviors['chains']}),
                          'functions': len(behaviors['functions']), 'artifacts': str(ghidra.scratch)}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', choices=('ghidra',))
    args, rest = parser.parse_known_args()
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    if not unittest.TextTestRunner(verbosity=1).run(suite).wasSuccessful():
        sys.exit(1)
    if args.runtime:
        runtime_test()
