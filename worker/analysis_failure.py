"""Bounded diagnostics for owned projection failures; never a success certificate."""
import hashlib
import json
from pathlib import Path

from lift_runtime import locked_file

FILES = {
    'java-input.json': 65536,
    'java-decode/started.json': 4096,
    'java-decode/stdout.log': 4 * 1024**2,
    'java-decode/stderr.log': 4 * 1024**2,
    'java-decode-process.json': 16384,
    'request.json': 65536,
    'state-computation-process.json': 16384,
    'stdout.log': 4 * 1024**2,
    'stderr.log': 4 * 1024**2,
}


def diagnostic(raw, *, java=False):
    lines = [line.strip() for line in raw.decode('utf8', errors='replace').splitlines() if line.strip()]
    if not lines:
        return 'Analysis process returned no diagnostic'
    if java:
        causes = [line for line in lines if line.startswith(('Exception in thread ', 'Caused by: '))]
        # The first exception identifies the failing operation; preserve bounded
        # nested causes too. A final stack frame alone hides the actual failure.
        return ' | '.join(causes[:3] or [next((line for line in lines if not line.startswith('at ')), lines[0])])[:1024]
    return lines[-1][:1024]


def capture(directory, *, params, method, runtime_pin, java_pin, stage, stages, cleanup, code, message):
    directory = Path(directory)
    if directory.resolve(strict=True) != directory or not directory.is_dir():
        raise ValueError('Failure evidence requires the physical owned job directory')
    files = []
    for name, maximum in FILES.items():
        row = {'name': name}
        filename = directory / name
        if not cleanup:
            row['status'] = 'not-read-cleanup-unconfirmed'
        elif not filename.exists():
            row['status'] = 'missing'
        elif filename.stat().st_size > maximum:
            row['status'] = 'output-limit'
        else:
            try:
                with locked_file(filename, maximum) as data:
                    row.update(status='captured', bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            except Exception:
                row['status'] = 'unavailable'
        files.append(row)
    result = {
        'schema': 'ig5-analysis-failure-v1', 'status': 'failed-unverified',
        'method': method, 'jobId': params['job_id'], 'nonce': params['nonce'],
        'targetSha256': params['sha256'], 'projectionDecoder': params.get('projection_decoder', 'native'),
        'runtimeManifestPin': runtime_pin, 'javaDecoderManifestPin': java_pin,
        'failedStage': stage, 'cleanupConfirmed': cleanup, 'processStages': stages,
        'error': {'code': code, 'message': message}, 'files': files,
        'nativeTargetExecuted': False, 'databaseModified': False,
        'businessAccepted': False, 'wholeBinaryVerified': False,
    }
    if method=='discover':
        from path_discovery import PIN
        result['discoveryExpectedManifestPin']=PIN
    if method=='project-recorded':
        result['recordedCoordinatesSha256']=params['recorded_coordinates_sha256']
    data = json.dumps(result, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode('utf8')
    if len(data) > 65536:
        raise ValueError('Failure receipt exceeds 64 KiB')
    with (directory / 'analysis-failure.json').open('xb') as stream:
        stream.write(data)
    return {'name': 'analysis-failure.json', 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
