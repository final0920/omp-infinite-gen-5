"""Entry point for one firmware request: JSON on stdin, one JSON document on stdout. No sample content is ever executed."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from firmware_io import FirmwareError
from firmware_scan import scan_firmware


def main():
    try:
        request = json.loads(sys.stdin.read())
        action = request.get('action')
        if action not in ('scan', 'extract'):
            raise FirmwareError('INVALID_INPUT', 'action must be scan or extract')
        path = request.get('path')
        if not isinstance(path, str) or not path or '\0' in path:
            raise FirmwareError('INVALID_INPUT', 'path must be a file path')
        out = request.get('output_dir') if action == 'extract' else None
        if action == 'extract' and (not isinstance(out, str) or not out):
            raise FirmwareError('INVALID_INPUT', 'extract needs output_dir')
        limits = {k: v for k, v in (request.get('limits') or {}).items() if isinstance(v, int) and not isinstance(v, bool) and v > 0}
        seconds = request.get('deadline_seconds', 300)
        if not isinstance(seconds, (int, float)) or isinstance(seconds, bool) or not 1 <= seconds <= 3600:
            raise FirmwareError('INVALID_INPUT', 'deadline_seconds must be 1..3600')
        report = scan_firmware(os.path.abspath(path), extract_to=os.path.abspath(out) if out else None, limits=limits, deadline_seconds=seconds)
        result = {'ok': True, 'report': report}
    except FirmwareError as error:
        result = {'ok': False, 'error': {'code': error.code, 'message': str(error)[:400]}}
    except MemoryError:
        result = {'ok': False, 'error': {'code': 'MEMORY', 'message': 'the firmware needed more memory than the worker may use'}}
    except Exception as error:                                   # noqa: BLE001 - report as a failure, never as a traceback with paths
        result = {'ok': False, 'error': {'code': 'ANALYSIS_FAILED', 'message': f'{type(error).__name__} while analysing the firmware'}}
    sys.stdout.write(json.dumps(result, ensure_ascii=True, default=str))
    sys.stdout.flush()


if __name__ == '__main__':
    main()
