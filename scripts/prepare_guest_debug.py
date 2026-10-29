"""Prepare a private, bounded catalog guest bundle; never starts a target/VM.

Input --spec is UTF-8 JSON: {guestCID,port,guestLabel,targets:[{id,path,sha256}]}.
Output and host-profile paths must be new, absolute and outside this plugin.
Pairing material is generated locally; this PRIVATE bundle must not be released.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'adapters/vmci'))
from guest_profile import stable_read

def digest(data): return hashlib.sha256(data).hexdigest()

def dependency_files(row, machine):
    """Explicit app-local DLL bytes only; never discover/download/execute DLLs."""
    dependencies = row.get('dependencies', [])
    if not isinstance(dependencies, list) or len(dependencies) > 16:
        raise ValueError('At most 16 explicitly pinned app-local dependencies per target')
    result, names = {}, set()
    for dep in dependencies:
        if not isinstance(dep, dict) or set(dep) != {'name', 'path', 'sha256'} or not isinstance(dep['name'], str) or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,123}\.dll', dep['name'], re.I) is None or dep['name'].casefold() in names or not isinstance(dep['path'], str) or not isinstance(dep['sha256'], str) or re.fullmatch('[a-f0-9]{64}', dep['sha256']) is None:
            raise ValueError('Dependencies require unique DLL basenames, absolute sources and SHA-256')
        source = Path(dep['path'])
        if not source.is_absolute() or source.resolve() != source.absolute() or source.name.casefold() != dep['name'].casefold():
            raise ValueError('Dependency source must be canonical and keep its original basename')
        data = stable_read(source, 64*1024*1024)
        if digest(data) != dep['sha256'] or len(data) < 64 or data[:2] != b'MZ':
            raise ValueError('Dependency bytes/hash differ')
        pe = struct.unpack_from('<I', data, 0x3c)[0]
        if pe < 64 or pe+26 > len(data) or data[pe:pe+4] != b'PE\0\0' or struct.unpack_from('<H', data, pe+4)[0] != machine or not struct.unpack_from('<H', data, pe+22)[0] & 0x2000:
            raise ValueError('Dependency must be a same-architecture PE DLL')
        names.add(dep['name'].casefold()); result[dep['name']] = data
    return result
def write_json(file, value):
    with file.open('xb') as output:
        output.write(json.dumps(value, indent=2, ensure_ascii=True).encode('ascii')); output.flush(); os.fsync(output.fileno())

def prepare(spec_path, destination, host_profile):
    for file in (spec_path, destination, host_profile):
        if not file.is_absolute() or file.resolve() != file.absolute() or file.is_relative_to(ROOT):
            raise ValueError('Use canonical absolute inputs/outputs outside the plugin')
    if destination.exists() or host_profile.exists(): raise ValueError('Output directory/profile must be new; existing files are preserved')
    spec = json.loads(stable_read(spec_path, 65536))
    if not isinstance(spec, dict) or set(spec) != {'guestCID', 'port', 'guestLabel', 'targets'} or type(spec['guestCID']) is not int or not 3 <= spec['guestCID'] <= 0xfffffffe or type(spec['port']) is not int or not 1024 <= spec['port'] <= 0xfffffffe or not isinstance(spec['guestLabel'], str) or not spec['guestLabel'].strip() or len(spec['guestLabel']) > 128 or not isinstance(spec['targets'], list) or not 1 <= len(spec['targets']) <= 64:
        raise ValueError('Invalid explicit guest identity or bounded catalog')
    files, targets, hashes, ids = {}, [], set(), set()
    for row in spec['targets']:
        if not isinstance(row, dict) or not {'id', 'path', 'sha256'} <= set(row) or set(row) - {'id', 'path', 'sha256', 'dependencies'} or not isinstance(row['id'], str) or re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', row['id']) is None or row['id'] in ids or not isinstance(row['sha256'], str) or re.fullmatch('[0-9a-f]{64}', row['sha256']) is None or row['sha256'] in hashes:
            raise ValueError('Target IDs/digests must be unique and explicit')
        data = stable_read(row['path'], 64*1024*1024)
        if digest(data) != row['sha256'] or len(data) < 64 or data[:2] != b'MZ': raise ValueError('Target size/hash/PE header differs')
        pe = struct.unpack_from('<I', data, 0x3c)[0]
        if pe+26 > len(data) or data[pe:pe+4] != b'PE\0\0' or struct.unpack_from('<H', data, pe+4)[0] not in (0x14c, 0x8664): raise ValueError('Target must be an x86/x64 PE')
        dependencies = dependency_files(row, struct.unpack_from('<H', data, pe+4)[0])
        # Separate directories prevent x86/x64 DLL basename collisions. Old
        # dependency-free bundle layout remains byte-compatible in shape.
        prefix = 'targets/' + row['id'] + '/' if dependencies else 'targets/'
        name = prefix + row['id'] + '.exe'; files[name] = data
        for dep_name, dep_bytes in dependencies.items(): files[prefix + dep_name] = dep_bytes
        targets.append({'id': row['id'], 'path': name, 'sha256': row['sha256']}); ids.add(row['id']); hashes.add(row['sha256'])
    inventory = []
    for directory in ('runtimes/x64dbg', 'worker/trace_vendor'):
        inventory.extend(file for file in (ROOT / directory).rglob('*') if file.is_file() and '__pycache__' not in file.parts)
    for directory, pattern in (('adapters/x64dbg', '*.py'), ('adapters/vmci', '*.py'), ('worker', 'trace*.py')):
        inventory.extend((ROOT / directory).glob(pattern))
    inventory.extend(ROOT / name for name in ('LICENSE', 'THIRD_PARTY_NOTICES.txt', 'adapters/vmci/launcher.cpp',
                                             'worker/behavior_rules.py', 'worker/api_trace_summary.py'))
    for file in sorted(inventory):
        if file.resolve() != file.absolute(): raise ValueError('Bundle source cannot be linked')
        files[file.relative_to(ROOT).as_posix()] = stable_read(file, 128*1024*1024)
    launcher = ROOT / 'adapters/vmci/native/IG5-Guest-Debug.exe'
    proof_data = stable_read(ROOT / 'adapters/vmci/native/build-proof.json', 16384); proof = json.loads(proof_data)
    launcher_data = stable_read(launcher, 1024*1024)
    if proof.get('schema') != 'ig5-guest-launcher-build-v1' or proof.get('exeSHA256') != digest(launcher_data) or proof.get('sourceSHA256') != digest(files['adapters/vmci/launcher.cpp']):
        raise ValueError('Build the current fixed guest launcher first')
    files['IG5-Guest-Debug.exe'] = launcher_data; files['launcher-build-proof.json'] = proof_data
    key = secrets.token_bytes(32); files['guest-pairing.key'] = key
    files['guest-catalog.json'] = json.dumps({'schema': 'ig5-vmci-target-catalog-v1', 'port': spec['port'], 'targets': targets}, sort_keys=True).encode('ascii')
    files['README.txt'] = b'PRIVATE IG5 paired guest debugger bundle. Copy this complete folder into the guest and open IG5-Guest-Debug.exe. Uses VMCI host CID2 and locally generated pairing key; no IP listener or auto-start. DSH public ig5_dbg approvals control target operations. Never publish this folder/key/derived ISO. Key possession authenticates pairing, not guest process attestation; traffic is not encrypted. Service stops after one hour or 64 connections; guest OS/security settings remain unchanged. Local state/cleanup-receipts stores original signed terminal proofs for recovery.\r\n'
    if len(files) > 1024 or sum(map(len, files.values())) > 512*1024*1024: raise ValueError('Guest bundle exceeds 1024 files/512 MiB')
    manifest = {'schema': 'ig5-vmci-guest-bundle-v1', 'files': [{'path': name, 'bytes': len(data), 'sha256': digest(data)} for name, data in sorted(files.items())]}
    manifest_data = json.dumps(manifest, indent=2).encode('ascii'); files['guest-manifest.json'] = manifest_data
    destination.mkdir(parents=True, exist_ok=False)
    for name, data in files.items():
        file = destination / name; file.parent.mkdir(parents=True, exist_ok=True)
        with file.open('xb') as output: output.write(data)
    for name, data in files.items():
        if digest(stable_read(destination / name, 128*1024*1024)) != digest(data): raise ValueError('Prepared bundle file changed')
    profile = {'schema': 'ig5-vmci-guest-profile-v1', 'guestCID': spec['guestCID'], 'port': spec['port'], 'guestLabel': spec['guestLabel'],
        'bundleSha256': digest(manifest_data), 'pairingKeyRef': {'path': str(destination / 'guest-pairing.key'), 'sha256': digest(key)},
        'targets': [{'id': row['id'], 'sha256': row['sha256']} for row in targets]}
    host_profile.parent.mkdir(parents=True, exist_ok=True); write_json(host_profile, profile)
    receipt = {'schema': 'ig5-guest-preparation-v1', 'bundle': str(destination), 'hostProfile': str(host_profile), 'bindingSha256': digest(host_profile.read_bytes()),
        'bundleSha256': profile['bundleSha256'], 'files': len(files), 'bytes': sum(map(len, files.values())), 'allFilesRechecked': True,
        'privatePairingKeyIncluded': True, 'publicDistributionAllowed': False, 'authenticatedStartupVerified': False, 'nativeTargetExecuted': False}
    write_json(destination.parent / (destination.name + '-preparation.json'), receipt)
    return receipt

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--spec', type=Path, required=True); parser.add_argument('--output', type=Path, required=True); parser.add_argument('--host-profile', type=Path, required=True)
    options = parser.parse_args()
    print(json.dumps(prepare(options.spec, options.output, options.host_profile)))
