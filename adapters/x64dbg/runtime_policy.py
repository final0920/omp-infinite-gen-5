"""Application-local memory of actual blocked launches; never changes OS policy.

Records do not expire or clear automatically. They prevent another Popen at the
same configured component path, including for a different target/work directory.
They are capability history, not execution approval or process-cleanup evidence.
"""
import hashlib
import json
import os
from pathlib import Path
import re
from datetime import datetime, timezone

class RuntimePolicyBlocked(RuntimeError):
    def __init__(self, record, message='Known application-control block; no debugger launch attempted'):
        super().__init__(message)
        self.record = record

def component_key(component):
    return os.path.normcase(os.path.abspath(os.fspath(component)))

def record_path(root, component):
    key = component_key(component)
    return Path(root) / (hashlib.sha256(key.encode('utf-8')).hexdigest() + '.json')

def read_block(root, component):
    directory = Path(root)
    try:
        directory.lstat()
        if directory.is_symlink() or not directory.is_dir():
            raise RuntimePolicyBlocked(None, 'Runtime policy directory is unsafe; no launch attempted')
    except FileNotFoundError:
        return None
    except OSError as error:
        raise RuntimePolicyBlocked(None, 'Runtime policy directory is unreadable; no launch attempted') from error
    file = record_path(root, component)
    try:
        stat = file.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise RuntimePolicyBlocked(None, 'Runtime policy record is unreadable; no launch attempted') from error
    if file.is_symlink() or not file.is_file() or stat.st_size > 8192:
        raise RuntimePolicyBlocked(None, 'Runtime policy record is unsafe/unreadable; launch remains unverified')
    try:
        with file.open('rb') as source:
            opened = os.fstat(source.fileno())
            if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns):
                raise ValueError('Policy record changed before read')
            raw = source.read(8193)
        if len(raw) > 8192:
            raise ValueError('Policy record exceeded its budget')
        value = json.loads(raw)
        current = file.lstat()
        if ((stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns) != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
            or set(value) != {'schema', 'component', 'winError', 'recordedAt', 'source', 'evidence', 'automaticRetryAllowed'}
            or value['schema'] != 'ig5-runtime-policy-block-v1' or value['component'] != component_key(component)
            or value['winError'] != 4551 or value['automaticRetryAllowed'] is not False
            or not isinstance(value['recordedAt'], str) or not 1 <= len(value['recordedAt']) <= 64
            or value['source'] not in ('observed-launch-error', 'imported-policy-evidence')
            or not valid_evidence(value['evidence'])):
            raise ValueError('Invalid policy record')
        return value
    except RuntimePolicyBlocked:
        raise
    except Exception as error:
        raise RuntimePolicyBlocked(None, 'Runtime policy record changed/invalid; no launch attempted') from error

def assert_launch_permitted(root, component):
    value = read_block(root, component)
    if value is not None:
        raise RuntimePolicyBlocked(value)

def valid_evidence(value):
    return value is None or (isinstance(value, dict) and set(value) == {'path', 'sha256'}
        and isinstance(value['path'], str) and 1 <= len(value['path']) <= 4096 and '\0' not in value['path']
        and os.path.isabs(value['path']) and isinstance(value['sha256'], str) and re.fullmatch('[a-f0-9]{64}', value['sha256']) is not None)

def record_block(root, component, error, evidence=None):
    if getattr(error, 'winerror', None) != 4551:
        return None
    if not valid_evidence(evidence):
        raise ValueError('Invalid policy evidence reference')
    prior = read_block(root, component)
    if prior is not None:
        return prior
    directory = Path(root)
    directory.mkdir(parents=True, exist_ok=True)
    if directory.is_symlink() or not directory.is_dir():
        raise RuntimePolicyBlocked(None, 'Runtime policy state directory is unsafe')
    value = {'schema': 'ig5-runtime-policy-block-v1', 'component': component_key(component), 'winError': 4551,
             'recordedAt': datetime.now(timezone.utc).isoformat(), 'source': 'imported-policy-evidence' if evidence else 'observed-launch-error',
             'evidence': evidence, 'automaticRetryAllowed': False}
    raw = json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode('ascii')
    if len(raw) > 8192:
        raise ValueError('Runtime policy evidence exceeds 8 KiB')
    try:
        with record_path(root, component).open('xb') as output:
            output.write(raw); output.flush(); os.fsync(output.fileno())
    except FileExistsError:
        return read_block(root, component)
    return value
