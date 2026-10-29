"""Hash/provenance preflight and real IG5 binary-loader corpus intake.

These are static intake tests, not devirtualization or executable behavior tests.
External files are never executed and unsupported inputs remain visible.
"""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'worker'))
from kernel_image import BinaryImage


def run(root, output, manifest_path=None):
    source = Path(__file__).resolve().parents[1]
    manifest_path = manifest_path or source / 'scripts/fixtures/protection_corpus.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8-sig'))
    files = {row['file']: row for row in manifest['files']}
    if len(files) != len(manifest['files']): raise ValueError('Duplicate manifest path')
    # All pins/parents must pass before analysis starts.
    blocked = {}
    for row in files.values():
        filename = root / row['file']
        if not filename.is_file():
            blocked[row['file']] = 'Corpus file is unavailable on disk; excluded from analysis'
            continue
        if filename.resolve() != filename.absolute() or os.stat(filename).st_nlink != 1: raise ValueError('Linked corpus input')
        try: data = filename.read_bytes()
        except OSError as error:
            blocked[row['file']] = str(error)
            continue
        if len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256']: raise ValueError('Corpus pin mismatch: ' + row['file'])
        if 'derivedFrom' in row and files[row['derivedFrom']]['sha256'] != row['parentSha256']: raise ValueError('Derived parent pin mismatch')
    rows = []
    for row in files.values():
        if row['role'] not in {'control', 'protected-author-reported', 'protected-self-generated', 'challenge-unknown-protection'}: continue
        filename = root / row['file']
        result = {'file': row['file'], 'role': row['role'], 'sha256': row['sha256'], 'bytes': row['bytes'],
                  'nativeTargetExecuted': False, 'businessLogicRecovered': False, 'archiveMember': row.get('archiveMember'), 'difficulty': row.get('difficulty')}
        if row['file'] in blocked:
            result.update(status='storage-blocked', error=blocked[row['file']], hashVerifiedOnDisk=False)
            rows.append(result); continue
        data = filename.read_bytes()
        result['hashVerifiedOnDisk'] = True
        if data.startswith(b'PK'):
            result['status'] = 'unsupported-archive-bytecode'
            result['format'] = 'APK/ZIP'
            with zipfile.ZipFile(filename) as archive:
                entries = archive.infolist()
                if len(entries) > 4096: raise ValueError('APK member budget exceeded')
                result['bytecodeMembers'] = [entry.filename for entry in entries if entry.filename.endswith(('.dex', '.so'))][:128]
            rows.append(result); continue
        try:
            image = BinaryImage.from_bytes(data, name=str(filename))
            description = image.describe()
            result.update(status='strict-loader-passed', format=image.format, bits=image.bits, architecture=image.architecture, description=description)
            if image.entrypoint is not None:
                result['entryBytes'] = image.read(image.entrypoint, 1).hex()
            result['loadedScope'] = 'IG5 binary loader, entry mapping; no disassembler or program semantics'
        except Exception as error:
            result.update(status='strict-loader-rejected', error=str(error))
            if data.startswith(b'\x7fELF'):
                try:
                    mapped = BinaryImage.from_bytes(data, name=str(filename), elf_sections='program-headers')
                    result['programHeadersOnly'] = {'loaded': True, 'format': mapped.format, 'bits': mapped.bits,
                                                    'entryBytes': mapped.read(mapped.entrypoint, 1).hex(), 'sectionMetadataVerified': False}
                except Exception as load_error: result['programHeadersOnly'] = {'loaded': False, 'error': str(load_error)}
        rows.append(result)
    unique = {row['sha256']: row for row in rows}
    receipt = {'schema': 'ig5.protection-corpus-intake.v1', 'pluginRoot': str(source), 'corpusRoot': str(root),
               'manifestSha256': hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
               'loaderSha256': hashlib.sha256((source / 'worker/kernel_image.py').read_bytes()).hexdigest(),
               'metadataRecords': len(files), 'binaryRecords': len(rows), 'uniqueBinaries': len(unique),
               'uniqueRoles': dict(Counter(row['role'] for row in unique.values())),
               'statuses': dict(Counter(row['status'] for row in rows)), 'nativeTargetExecuted': False,
               'preflightBlocked': blocked,
               'limits': ['Intake/entry mapping is not devirtualization.', 'Author-reported protection is not independently identified.',
                          'APK bytecode and unknown protection remain unsupported/unproved.', 'PT_LOAD mapping does not validate ELF sections.'], 'rows': rows}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({key: receipt[key] for key in ['metadataRecords', 'binaryRecords', 'uniqueBinaries', 'uniqueRoles', 'statuses', 'nativeTargetExecuted']}))


if __name__ == '__main__':
    base = Path(os.environ.get('IG5_CORPUS_EVIDENCE', str(Path.home() / '.dsh/ig5/artifacts/corpus-expansion-20261014')))
    selected_manifest = os.environ.get('IG5_CORPUS_MANIFEST')
    run(Path(os.environ.get('IG5_PROTECTION_CORPUS', str(base / 'corpus'))), base / 'intake.json', Path(selected_manifest) if selected_manifest else None)
