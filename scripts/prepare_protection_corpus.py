"""Bounded data extraction with parent/member provenance; no sample execution.

Uses the user's installed 7-Zip solely as an archive decoder. Upstream programs,
scripts, and APKs are never started. Store results outside the plugin.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time


def digest(data):
    return hashlib.sha256(data).hexdigest()


def prepare(manifest_path, root, seven_zip):
    root = root.resolve()
    source = Path(__file__).resolve().parents[1]
    if root == source or source in root.parents: raise ValueError('Corpus must stay outside plugin')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8-sig'))
    excluded = {row['file'] for row in manifest['files'] if row.get('storageState') == 'blocked'}
    rows = [row for row in manifest['files'] if 'derivedFrom' not in row]
    total = 0
    for row in rows:
        filename = root / row['file']
        if filename.resolve() != filename.absolute() or not filename.is_file() or os.stat(filename).st_nlink != 1:
            raise ValueError('Missing/linked corpus file: ' + row['file'])
        data = filename.read_bytes()
        if len(data) != row['bytes'] or digest(data) != row['sha256']: raise ValueError('Corpus pin mismatch: ' + row['file'])
        if re.search(r'\.vmp\.trace(?:\.[12])?$', row['file']): row['role'] = 'trace'
        if row['file'].endswith('/LICENSE'): row['role'] = 'reference'
    def publish(parent, member, data, relative, role, **extra):
        nonlocal total
        total += len(data)
        if total > 256 * 1024 * 1024 or len(rows) >= 1000: raise ValueError('Extraction combined budget exceeded')
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.parent.resolve() != target.parent.absolute(): raise ValueError('Linked extraction directory')
        if relative in excluded: pass  # Persist a recorded quarantine; no restore/retry.
        elif target.exists():
            if not target.is_file() or target.is_symlink() or os.stat(target).st_nlink != 1 or digest(target.read_bytes()) != digest(data):
                raise ValueError('Derived file changed: ' + relative)
        else:
            with target.open('xb') as output: output.write(data)
        row = {'file': relative, 'bytes': len(data), 'sha256': digest(data), 'role': role,
               'derivedFrom': parent['file'], 'parentSha256': parent['sha256'], 'archiveMember': member, **extra}
        if relative in excluded: row['storageState'] = 'blocked'
        rows.append(row)
        return row
    raw = next(row for row in rows if row['file'] == 'salwan-vmp/vmp_traces/sample5.vmp.trace.2')
    lines = (root / raw['file']).read_bytes().splitlines(keepends=True)
    allowed = {b'sh: line 1: zenity: command not found', b'This application is protected with unregistered version of VMProtect.', b'> 1001'}
    removed = [{'line': i + 1, 'text': line.rstrip().decode('ascii')} for i, line in enumerate(lines) if line.rstrip() in allowed]
    positions = [i for i, line in enumerate(lines) if line.startswith(b'i:')]
    if len(removed) != 3 or not positions or not all(item['line'] - 1 < positions[0] or item['line'] - 1 > positions[-1] for item in removed):
        raise ValueError('Unexpected non-trace records; normalization refused')
    clean = b''.join(line for line in lines if line.rstrip() not in allowed)
    publish(raw, None, clean, 'derived/sample5.vmp.trace.2', 'trace-derived', removedLines=removed,
            transformation='Remove three exact preamble/epilogue lines. All r/mr/i records retained verbatim.')
    queue = [(row, 0) for row in list(rows) if row['role'] == 'archive']
    seven_zip = seven_zip.resolve(strict=True)
    rejected = []
    for parent, depth in queue:
        password = parent.get('password', 'www.52pojie.cn')
        archive = root / parent['file']
        listing = subprocess.run([str(seven_zip), 'l', '-ba', '-slt', '-sccUTF-8', '-p' + password, '--', str(archive)],
                                 capture_output=True, timeout=30, check=True).stdout.decode('utf-8', 'strict').replace('\r\n', '\n')
        if len(listing) > 2 * 1024 * 1024: raise ValueError('Archive listing budget exceeded')
        entries = [dict(line.split(' = ', 1) for line in block.splitlines() if ' = ' in line) for block in listing.strip().split('\n\n')]
        if len(entries) > 1000: raise ValueError('Archive member budget exceeded')
        for entry in entries:
            member = entry.get('Path', '')
            # Never hand an archive member path to the filesystem. Output names
            # are SHA-256 identifiers; the original name is metadata only.
            suffix = Path(member).suffix.lower()
            if entry.get('Folder') == '+' or suffix not in {'.exe', '.dll', '.so', '.apk', '.bin', '.elf', '.zip', '.rar', '.txt', '.md'}: continue
            if not member or '\x00' in member or any(part in {'.', '..'} for part in member.replace('\\', '/').split('/')):
                rejected.append({'parent': parent['file'], 'member': member, 'reason': 'unsafe member path'}); continue
            size = int(entry.get('Size', '-1'))
            if not 0 <= size <= 32 * 1024 * 1024:
                rejected.append({'parent': parent['file'], 'member': member, 'reason': 'member exceeds 32 MiB'}); continue
            child_archive = suffix in {'.zip', '.rar'}
            if child_archive and depth >= 2:
                rejected.append({'parent': parent['file'], 'member': member, 'reason': 'nested archive depth budget'}); continue
            # Bounded stdout reads, rather than unbounded capture_output on data.
            child = subprocess.Popen([str(seven_zip), 'x', '-so', '-y', '-p' + password, '--', str(archive), member], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            watchdog = threading.Timer(45, child.kill)
            watchdog.daemon = True
            watchdog.start()
            chunks, count, started = [], 0, time.monotonic()
            try:
                while chunk := child.stdout.read(65536):
                    count += len(chunk)
                    if count > size or time.monotonic() - started > 45: raise ValueError('Archive extraction exceeded declared size/time')
                    chunks.append(chunk)
                if child.wait(timeout=5) != 0 or count != size: raise ValueError('Archive extraction failed/size mismatch')
            finally:
                watchdog.cancel()
                if child.poll() is None: child.kill(); child.wait(timeout=5)
            data = b''.join(chunks)
            relative = 'derived/' + digest(data) + suffix
            if any(row['file'] == relative for row in rows):
                rejected.append({'parent': parent['file'], 'member': member, 'reason': 'duplicate content', 'sha256': digest(data)}); continue
            role = 'archive-derived' if child_archive else 'reference-derived' if suffix in {'.txt', '.md'} else 'challenge-unknown-protection'
            if parent['file'].startswith('vmp-recompiled/'): role = 'protected-author-reported'
            if suffix == '.bin' and not data.startswith((b'MZ', b'\x7fELF')): role = 'data'
            row = publish(parent, member, data, relative, role, protection='VMProtect 3.6 DEMO (author reported)' if role == 'protected-author-reported' else 'unknown; filename/difficulty is not protector evidence',
                          sourcePage=parent.get('sourcePage'), difficulty=next((grade for grade in ['高级', '中级', '初级'] if grade in member), 'unspecified'))
            if child_archive: queue.append((row, depth + 1))
        print(json.dumps({'archive': parent['file'], 'members': len(entries), 'preparedRecords': len(rows)}, ensure_ascii=False), flush=True)
    result = {**manifest, 'files': rows, 'preparation': {'extractedBytes': total, 'nativeTargetExecuted': False, 'rejectedOrDuplicate': rejected}}
    (root / 'prepared-manifest.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'records': len(rows), 'derivedBytes': total, 'skipped': len(rejected)}))


if __name__ == '__main__':
    if len(sys.argv) != 4: raise SystemExit('Usage: prepare_protection_corpus.py MANIFEST CORPUS_ROOT SEVEN_ZIP')
    prepare(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
