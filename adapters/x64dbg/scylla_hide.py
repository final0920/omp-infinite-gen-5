"""Pinned, target-scoped user-mode ScyllaHide sidecar for an approved start.

No arbitrary PID/path/profile API, no drivers, no privilege adjustment. This
changes the owned debuggee's environment and is never presented as passive.
"""
import ctypes
from ctypes import wintypes as w
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time

MANIFEST_SHA256 = 'd6e2bb2f6c1ecb4a59a54a80c21a9475561b0fa877dbdc7b2a9c44e90d865a82'
PROFILE = 'scyllahide-thread-context'


def load_bundle(root=None):
    root = Path(root) if root is not None else Path(__file__).resolve().parents[2] / 'runtimes/scyllahide'
    if root.resolve() != root.absolute(): raise ValueError('ScyllaHide runtime must be a physical directory')
    inventory = root / 'ig5-manifest.json'
    if inventory.resolve() != inventory.absolute() or not inventory.is_file() or inventory.stat().st_size > 16384:
        raise ValueError('ScyllaHide inventory is missing/linked/oversized')
    data = inventory.read_bytes()
    if hashlib.sha256(data).hexdigest() != MANIFEST_SHA256: raise ValueError('Pinned ScyllaHide inventory changed')
    manifest = json.loads(data)
    if manifest['schema'] != 'ig5.scyllahide-runtime.v1' or manifest['profile'] != 'IG5-thread-context': raise ValueError('ScyllaHide profile differs')
    files = {}
    for row in manifest['files']:
        if row['path'] not in ('InjectorCLIx64.exe', 'HookLibraryx64.dll', 'scylla_hide.ini', 'LICENSE'): raise ValueError('Unexpected ScyllaHide file')
        p = root / row['path']
        if p.resolve() != p.absolute() or not p.is_file() or p.stat().st_size > 8 * 1024 * 1024: raise ValueError('ScyllaHide asset is missing/linked/oversized')
        blob = p.read_bytes()
        if len(blob) != row['bytes'] or hashlib.sha256(blob).hexdigest() != row['sha256']: raise ValueError('ScyllaHide asset hash differs')
        files[row['path']] = blob
    if len(files) != 4: raise ValueError('Incomplete ScyllaHide runtime')
    return manifest, files


def verify_owned(adapter, before, RpcError):
    if adapter.target['bits'] != 64 or not adapter.job or not adapter.job.handle or before['state'] != 'suspended' or not before.get('pid'):
        raise RpcError('ESTATE', 'ScyllaHide requires a paused owned native x64 debuggee')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]; kernel.OpenProcess.restype = w.HANDLE
    kernel.IsProcessInJob.argtypes = [w.HANDLE, w.HANDLE, ctypes.POINTER(w.BOOL)]; kernel.IsProcessInJob.restype = w.BOOL
    kernel.CheckRemoteDebuggerPresent.argtypes = [w.HANDLE, ctypes.POINTER(w.BOOL)]; kernel.CheckRemoteDebuggerPresent.restype = w.BOOL
    kernel.CloseHandle.argtypes = [w.HANDLE]
    handle = kernel.OpenProcess(0x0400, False, before['pid'])  # QUERY_INFORMATION only
    if not handle: raise RpcError('ESTATE', 'Owned target could not be queried for ScyllaHide')
    try:
        owned, debugged = w.BOOL(), w.BOOL()
        if not kernel.IsProcessInJob(handle, adapter.job.handle, ctypes.byref(owned)) or not owned.value:
            raise RpcError('ESTATE', 'ScyllaHide target is outside the debugger cleanup job')
        if not kernel.CheckRemoteDebuggerPresent(handle, ctypes.byref(debugged)) or not debugged.value:
            raise RpcError('ESTATE', 'ScyllaHide target is not currently debugged')
        after = adapter.state()
        if any(after.get(k) != before.get(k) for k in ('state', 'pid', 'tid', 'runId', 'stopSeq', 'nativeRunEpoch')):
            raise RpcError('ESTATE', 'Owned pause changed before ScyllaHide')
    finally: kernel.CloseHandle(handle)


def apply_profile(adapter, bundle, RpcError):
    manifest, files = bundle
    before = adapter.state(); verify_owned(adapter, before, RpcError)
    directory = Path(tempfile.mkdtemp(prefix='scyllahide-', dir=adapter.state_root / 'sessions'))
    for name, data in files.items():
        with (directory / name).open('xb') as f: f.write(data)
    log_path = directory / 'injection.log'; process = None
    started = time.monotonic()
    try:
        with log_path.open('xb') as log:
            process = subprocess.Popen([str(directory / 'InjectorCLIx64.exe'), 'pid:' + str(before['pid']),
                str(directory / 'HookLibraryx64.dll'), 'nowait'], cwd=directory, stdin=subprocess.DEVNULL,
                stdout=log, stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NO_WINDOW)
            while process.poll() is None:
                adapter.check()
                if time.monotonic() - started > 20: raise RpcError('ETIMEDOUT', 'ScyllaHide sidecar exceeded 20 seconds')
                if log_path.stat().st_size > 65536: raise RpcError('EBACKEND', 'ScyllaHide log budget exceeded')
                time.sleep(0.025)
        data = log_path.read_bytes()
        if len(data) > 65536: raise RpcError('EBACKEND', 'ScyllaHide log budget exceeded')
        match = re.search(rb'Hook injection successful, image base ([0-9A-Fa-f]+)', data)
        if process.returncode != 0 or not match:
            raise RpcError('EBACKEND', 'ScyllaHide did not confirm hook installation', sidecarExitCode=process.returncode,
                logPath=str(log_path), logSha256=hashlib.sha256(data).hexdigest())
        verify_owned(adapter, before, RpcError)
        return {'profile': PROFILE, 'source': 'x64dbg/ScyllaHide GPL-3.0 standalone sidecar',
            'revision': manifest['revision'], 'manifestSha256': MANIFEST_SHA256,
            'enabledOptions': manifest['enabledOptions'], 'installationConfirmedBySidecar': True,
            'perHookBehaviorVerified': False, 'remoteImageBase': hex(int(match[1], 16)),
            'nativeTargetEnvironmentModified': True, 'originalFileModified': False,
            'driverLoaded': False, 'systemSecuritySettingsModified': False, 'privilegesAdjusted': False,
            'processId': before['pid'], 'runId': before['runId'], 'stopSeq': before['stopSeq'],
            'logPath': str(log_path), 'logSha256': hashlib.sha256(data).hexdigest()}
    finally:
        if process and process.poll() is None:
            process.terminate()
            try: process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=3)
