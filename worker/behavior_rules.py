"""Behavior taxonomy: API name -> category, plus multi-API patterns ("chains").

Pure data and name normalization; no engine access. Presence of an API, or several
APIs inside one function, is a lead for review. It is NOT proof that the behavior
executes, nor of what it targets. Categories describe what an API can do, not intent.

Rules for editing this file:
  * Names are lowercase, without the ANSI/wide suffix (A/W) and without NT/Zw prefix
    variants: ``zwfoo`` is looked up as ``ntfoo``.
  * A name belongs to exactly one category (checked at import time).
  * Every API named in a chain must exist in the taxonomy (checked at import time).
"""
from __future__ import annotations

import re

TAXONOMY_VERSION = 1

API_GROUPS = {
    'crypto': (
        'cryptencrypt', 'cryptdecrypt', 'cryptacquirecontext', 'cryptgenkey', 'cryptderivekey', 'cryptimportkey',
        'crypthashdata', 'cryptprotectdata', 'cryptunprotectdata', 'cryptcreatehash', 'cryptdestroykey', 'cryptexportkey',
        'cryptsetkeyparam', 'bcryptencrypt', 'bcryptdecrypt', 'bcryptgeneratesymmetrickey', 'bcryptderivekey', 'bcryptimportkey',
        'bcryptcreatehash', 'bcrypthashdata', 'bcryptgenrandom', 'bcryptopenalgorithmprovider', 'bcryptsignhash',
        'bcryptverifysignature', 'bcryptdestroykey', 'bcryptexportkey', 'bcryptfinishhash', 'ncryptdecrypt', 'ncryptencrypt',
        'ncryptimportkey', 'ncryptopenstorageprovider', 'evp_encryptinit_ex', 'evp_encryptupdate', 'evp_decryptinit_ex',
        'evp_decryptupdate', 'evp_cipherinit_ex', 'evp_cipher', 'evp_digestinit_ex', 'evp_digestupdate', 'evp_digestfinal_ex',
        'evp_pkey_decrypt', 'evp_pkey_encrypt', 'rsa_private_decrypt', 'rsa_public_encrypt', 'aes_encrypt', 'aes_decrypt',
        'aes_set_encrypt_key', 'aes_set_decrypt_key', 'aes_cbc_encrypt', 'aes_ecb_encrypt', 'md5_init', 'md5_update', 'md5_final',
        'sha1_init', 'sha1_update', 'sha256_init', 'sha256_update', 'rc4', 'rc4_set_key', 'des_ecb_encrypt', 'pk11_decrypt',
        'pk11_encrypt', 'crypto_secretbox_easy', 'crypto_stream_xor', 'mbedtls_aes_crypt_cbc', 'mbedtls_aes_setkey_enc',
        'gcry_cipher_encrypt', 'gcry_cipher_decrypt'),
    'network': (
        'send', 'sendto', 'recv', 'recvfrom', 'sendmsg', 'recvmsg', 'wsasend', 'wsasendto', 'wsarecv', 'wsarecvfrom', 'wsastartup',
        'wsasocket', 'wsaconnect', 'wsaaccept', 'socket', 'connect', 'accept', 'bind', 'listen', 'setsockopt', 'getsockopt',
        'getaddrinfo', 'gethostbyname', 'gethostbyaddr', 'getnameinfo', 'inet_addr', 'inet_pton', 'inet_ntop', 'ssl_read',
        'ssl_write', 'ssl_read_ex', 'ssl_write_ex', 'gnutls_record_recv', 'gnutls_record_send', 'winhttpopen', 'winhttpopenrequest',
        'winhttpconnect', 'winhttpsendrequest', 'winhttpreceiveresponse', 'winhttpquerydataavailable', 'winhttpreaddata',
        'winhttpwritedata', 'internetopen', 'internetconnect', 'internetopenurl', 'httpopenrequest', 'httpsendrequest',
        'internetreadfile', 'internetwritefile', 'urldownloadtofile', 'urldownloadtocachefile', 'dnsquery', 'dnsquery_a',
        'dnsquery_w', 'curl_easy_setopt', 'curl_easy_perform'),
    'memory-execution': (
        'virtualalloc', 'virtualallocex', 'virtualprotect', 'virtualprotectex', 'writeprocessmemory', 'createremotethread',
        'createremotethreadex', 'ntallocatevirtualmemory', 'ntwritevirtualmemory', 'ntprotectvirtualmemory', 'ntmapviewofsection',
        'ntunmapviewofsection', 'ntcreatethreadex', 'rtlcreateuserthread', 'queueuserapc', 'ntqueueapcthread', 'setthreadcontext',
        'ntsetcontextthread', 'mapviewoffile', 'mapviewoffileex', 'mmap', 'mprotect'),
    'process-access': (
        'openprocess', 'ntopenprocess', 'readprocessmemory', 'ntreadvirtualmemory', 'virtualqueryex', 'ntqueryvirtualmemory',
        'duplicatehandle', 'openthread', 'ntopenthread', 'suspendthread', 'ntsuspendthread', 'resumethread', 'ntresumethread',
        'ntsuspendprocess', 'ntresumeprocess', 'getthreadcontext', 'ntgetcontextthread', 'terminateprocess', 'ntterminateprocess',
        'process_vm_readv', 'process_vm_writev'),
    'process-enumeration': (
        'createtoolhelp32snapshot', 'process32first', 'process32next', 'module32first', 'module32next', 'thread32first',
        'thread32next', 'heap32listfirst', 'enumprocesses', 'enumprocessmodules', 'enumprocessmodulesex', 'getmodulefilenameex',
        'getprocessimagefilename', 'queryfullprocessimagename', 'ntquerysysteminformation', 'findwindow', 'findwindowex',
        'enumwindows', 'getwindowthreadprocessid', 'getforegroundwindow'),
    'execution': (
        'winexec', 'shellexecute', 'shellexecuteex', 'createprocess', 'createprocessasuser', 'createprocesswithlogon',
        'createprocesswithtoken', 'ntcreateuserprocess', 'rtlcreateuserprocess', 'system', 'wsystem', 'popen', 'execve', 'execl',
        'execle', 'execlp', 'execv', 'execvp', 'execvpe', 'fork', 'vfork', 'posix_spawn', 'posix_spawnp'),
    'registry': (
        'regsetvalue', 'regsetvalueex', 'regsetkeyvalue', 'regcreatekey', 'regcreatekeyex', 'regdeletevalue', 'regdeletekey',
        'regdeletekeyex', 'ntsetvaluekey', 'ntcreatekey', 'ntdeletevaluekey'),
    'service-driver': (
        'openscmanager', 'createservice', 'openservice', 'startservice', 'controlservice', 'deleteservice', 'changeserviceconfig',
        'changeserviceconfig2', 'ntloaddriver', 'ntunloaddriver', 'deviceiocontrol', 'ntdeviceiocontrolfile', 'init_module',
        'finit_module', 'delete_module'),
    'privilege': (
        'openprocesstoken', 'ntopenprocesstoken', 'adjusttokenprivileges', 'ntadjustprivilegestoken', 'lookupprivilegevalue',
        'duplicatetoken', 'duplicatetokenex', 'impersonateloggedonuser', 'impersonatenamedpipeclient', 'setthreadtoken', 'logonuser',
        'rtladjustprivilege', 'setuid', 'setgid', 'seteuid', 'setreuid', 'setresuid', 'setresgid', 'capset'),
    'credential-access': (
        'credenumerate', 'credread', 'credwrite', 'lsaretrieveprivatedata', 'lsaenumeratelogonsessions', 'getspnam'),
    'input-capture': (
        'getasynckeystate', 'getkeystate', 'getkeyboardstate', 'getrawinputdata', 'registerrawinputdevices', 'getclipboarddata',
        'setclipboardviewer', 'addclipboardformatlistener', 'getkeynametext', 'attachthreadinput'),
    'input-synthesis': (
        'sendinput', 'keybd_event', 'mouse_event', 'setcursorpos', 'blockinput', 'xtestfakekeyevent', 'xtestfakebuttonevent'),
    'screen-capture': (
        'bitblt', 'stretchblt', 'getdc', 'getwindowdc', 'getdibits', 'createcompatibledc', 'createcompatiblebitmap', 'printwindow',
        'xgetimage', 'xshmgetimage'),
    'hooks': (
        'setwindowshookex', 'unhookwindowshookex', 'setwineventhook', 'mh_initialize', 'mh_createhook', 'mh_enablehook',
        'detourattach', 'detourtransactionbegin', 'detourupdatethread', 'detourtransactioncommit'),
    'dynamic-loading': (
        'loadlibrary', 'loadlibraryex', 'getprocaddress', 'getmodulehandle', 'getmodulehandleex', 'ldrloaddll',
        'ldrgetprocedureaddress', 'ldrgetdllhandle', 'dlopen', 'dlsym', 'dlmopen', 'dlvsym'),
    'debug-detection': (
        'isdebuggerpresent', 'checkremotedebuggerpresent', 'ptrace', 'ntqueryinformationprocess', 'ntsetinformationthread',
        'outputdebugstring', 'debugbreak', 'debugactiveprocess', 'debugactiveprocessstop'),
    'file-destruction': (
        'deletefile', 'removedirectory', 'movefileex', 'ntdeletefile', 'setendoffile', 'setfileinformationbyhandle', 'unlink',
        'unlinkat', 'rmdir', 'truncate', 'ftruncate'),
    'file-enumeration': (
        'findfirstfile', 'findnextfile', 'findfirstfileex', 'getlogicaldrives', 'getlogicaldrivestrings', 'getdrivetype', 'opendir',
        'readdir', 'scandir', 'ftw', 'nftw', 'fts_open', 'fts_read'),
    'file-io': (
        'createfile', 'createfilemapping', 'readfile', 'writefile', 'ntcreatefile', 'ntwritefile', 'ntreadfile', 'copyfile',
        'copyfileex', 'movefile'),
    'environment-query': (
        'getsystemfirmwaretable', 'enumsystemfirmwaretables', 'getadaptersinfo', 'getadaptersaddresses', 'getcomputername',
        'getusername', 'getvolumeinformation', 'globalmemorystatusex', 'getdiskfreespaceex', 'getsysteminfo', 'getnativesysteminfo',
        'isprocessorfeaturepresent', 'uname', 'gethostid'),
    'compression-codec': (
        'rtldecompressbuffer', 'rtldecompressbufferex', 'rtlcompressbuffer', 'uncompress', 'compress2', 'inflate', 'inflateinit_',
        'inflateinit2_', 'deflate', 'lzma_raw_decoder', 'lzma_stream_decoder', 'brotlidecoderdecompress', 'cryptstringtobinary',
        'cryptbinarytostring'),
}

# Categories that are too common in benign programs to be a lead on their own.
WEAK_CATEGORIES = frozenset({'file-io', 'environment-query', 'screen-capture', 'dynamic-loading', 'compression-codec'})


def _index():
    index = {}
    for category, names in API_GROUPS.items():
        for name in names:
            if name in index:
                raise ValueError(f'behavior taxonomy: {name!r} is in both {index[name]!r} and {category!r}')
            if name != name.lower() or name.endswith(('@', ' ')) or not name:
                raise ValueError(f'behavior taxonomy: {name!r} must be lowercase')
            index[name] = category
    return index


API_CATEGORIES = _index()
_PREFIX = re.compile(r'^(?:__imp_|imp_|_)+')


def canonical(name):
    """Return the taxonomy key for an imported/resolved API name, or None."""
    cleaned = _PREFIX.sub('', str(name).lower().split('@@')[0].split('@')[0])
    variants = [cleaned]
    if cleaned.endswith(('a', 'w')):
        variants.append(cleaned[:-1])                       # ANSI / wide-character form
    variants += ['nt' + variant[2:] for variant in list(variants) if variant.startswith('zw')]   # Zw* is Nt*
    return next((variant for variant in variants if variant in API_CATEGORIES), None)


def api_category(name):
    key = canonical(name)
    return API_CATEGORIES[key] if key else None


_IDENTIFIER = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')


def is_api_name_string(text):
    """True when a string looks like a deliberately stored API name (a run-time resolution lead).

    Short all-lowercase words (``connect``, ``system``, ``accept``) are ordinary vocabulary, so they
    only qualify when they are at least 8 characters long or use mixed case such as ``VirtualAllocEx``.
    """
    return (isinstance(text, str) and len(text) <= 64 and _IDENTIFIER.fullmatch(text) is not None
            and canonical(text) is not None and (len(text) >= 8 or any(c.isupper() for c in text)))


def _group(*names):
    return frozenset(names)


# A chain matches when EVERY group has at least one member present in the SAME function.
CHAINS = (
    {'id': 'remote-code-injection', 'strength': 'strong',
     'label': 'Allocates and writes memory in another process and starts execution there',
     'groups': (_group('virtualallocex', 'ntallocatevirtualmemory', 'ntmapviewofsection'),
                _group('writeprocessmemory', 'ntwritevirtualmemory'),
                _group('createremotethread', 'createremotethreadex', 'ntcreatethreadex', 'rtlcreateuserthread', 'queueuserapc',
                       'ntqueueapcthread', 'setthreadcontext', 'ntsetcontextthread'))},
    {'id': 'process-replacement', 'strength': 'strong',
     'label': 'Creates a process, unmaps its image, writes new content and resumes it',
     'groups': (_group('createprocess', 'createprocessasuser', 'ntcreateuserprocess'), _group('ntunmapviewofsection'),
                _group('writeprocessmemory', 'ntwritevirtualmemory'),
                _group('resumethread', 'ntresumethread', 'setthreadcontext', 'ntsetcontextthread'))},
    {'id': 'foreign-process-memory-read', 'strength': 'strong', 'label': 'Opens another process and reads its memory',
     'groups': (_group('openprocess', 'ntopenprocess'), _group('readprocessmemory', 'ntreadvirtualmemory'))},
    {'id': 'foreign-process-memory-write', 'strength': 'strong', 'label': 'Opens another process and writes its memory',
     'groups': (_group('openprocess', 'ntopenprocess'), _group('writeprocessmemory', 'ntwritevirtualmemory'))},
    {'id': 'locate-and-read-process', 'strength': 'strong', 'label': 'Locates a process or window and reads its memory',
     'groups': (_group('createtoolhelp32snapshot', 'process32first', 'process32next', 'findwindow', 'findwindowex', 'enumprocesses',
                       'getwindowthreadprocessid'),
                _group('openprocess', 'ntopenprocess'), _group('readprocessmemory', 'ntreadvirtualmemory'))},
    {'id': 'inline-hook-installation', 'strength': 'strong', 'label': 'Changes memory protection and installs a function hook',
     'groups': (_group('virtualprotect', 'virtualprotectex', 'ntprotectvirtualmemory', 'mprotect'),
                _group('mh_createhook', 'mh_enablehook', 'detourattach', 'detourtransactioncommit'))},
    {'id': 'service-install', 'strength': 'strong', 'label': 'Opens the service manager and creates a service',
     'groups': (_group('openscmanager'), _group('createservice'))},
    {'id': 'driver-load-and-control', 'strength': 'strong', 'label': 'Creates or loads a driver and sends it control codes',
     'groups': (_group('createservice', 'ntloaddriver'), _group('deviceiocontrol', 'ntdeviceiocontrolfile'))},
    {'id': 'download-write-execute', 'strength': 'strong', 'label': 'Downloads data, writes a file and starts a process',
     'groups': (_group('urldownloadtofile', 'urldownloadtocachefile', 'internetreadfile', 'winhttpreaddata', 'curl_easy_perform'),
                _group('createfile', 'writefile', 'ntcreatefile', 'ntwritefile'),
                _group('winexec', 'shellexecute', 'shellexecuteex', 'createprocess', 'execve', 'execv', 'execl', 'system', 'popen',
                       'posix_spawn'))},
    {'id': 'keyboard-monitoring', 'strength': 'strong', 'label': 'Registers for keyboard input and reads key state',
     'groups': (_group('setwindowshookex', 'registerrawinputdevices'),
                _group('getasynckeystate', 'getkeystate', 'getkeyboardstate', 'getrawinputdata'))},
    {'id': 'screen-capture', 'strength': 'weak', 'label': 'Copies a window or screen into a bitmap and reads its pixels',
     'groups': (_group('getdc', 'getwindowdc', 'createcompatibledc'), _group('bitblt', 'stretchblt', 'printwindow'), _group('getdibits'))},
    {'id': 'privilege-enabling', 'strength': 'weak', 'label': 'Opens a token and enables a privilege',
     'groups': (_group('openprocesstoken', 'ntopenprocesstoken'), _group('lookupprivilegevalue'),
                _group('adjusttokenprivileges', 'ntadjustprivilegestoken'))},
    {'id': 'runtime-api-resolution', 'strength': 'weak', 'label': 'Loads a module and resolves functions at run time',
     'groups': (_group('loadlibrary', 'ldrloaddll', 'getmodulehandle'), _group('getprocaddress', 'ldrgetprocedureaddress'))},
    {'id': 'input-synthesis-with-window-targeting', 'strength': 'weak', 'label': 'Synthesizes input and finds a target window',
     'groups': (_group('sendinput', 'keybd_event', 'mouse_event', 'setcursorpos'),
                _group('findwindow', 'findwindowex', 'getforegroundwindow', 'enumwindows'))},
)

# A rule of another shape: several distinct APIs from one category inside one function.
DISTINCT_RULES = (
    {'id': 'multiple-debugger-checks', 'strength': 'strong', 'category': 'debug-detection', 'minimum': 2,
     'label': 'Uses several different debugger-detection mechanisms'},
)


def _validate():
    for chain in CHAINS:
        for index, group in enumerate(chain['groups']):
            missing = sorted(name for name in group if name not in API_CATEGORIES)
            if missing:
                raise ValueError(f"behavior chain {chain['id']!r} group {index} names unknown APIs: {missing}")
    ids = [item['id'] for item in (*CHAINS, *DISTINCT_RULES)]
    if len(set(ids)) != len(ids):
        raise ValueError('behavior chain ids must be unique')
    for rule in DISTINCT_RULES:
        if rule['category'] not in API_GROUPS:
            raise ValueError(f"distinct rule {rule['id']!r} names an unknown category")


_validate()
