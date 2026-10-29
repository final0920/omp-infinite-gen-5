"""One bounded offline trace request; separate process, no JVM or sample launch."""
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from kernel_image import BinaryImage
from trace_analysis import analyze, load_triton
from trace_recorded_image import RecordedImageIdentity

PROTOCOL = os.fdopen(os.dup(sys.stdout.fileno()), 'w', encoding='utf-8', buffering=1)
os.dup2(sys.stderr.fileno(), sys.stdout.fileno())
sys.stdout = sys.stderr


def emit(value):
    PROTOCOL.write(json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',', ':')) + '\n')


def main():
    emit({'ig5': 'ready', 'engine': 'IG5 Offline Trace', 'capabilities': ['trace']})
    request = {}
    try:
        line = sys.stdin.buffer.readline(12 * 1024 * 1024 + 1)
        if len(line) > 12 * 1024 * 1024 or not line.endswith(b'\n'): raise ValueError('Trace request exceeds its transport budget')
        request = json.loads(line)
        if not isinstance(request, dict): request = {}; raise ValueError('Invalid trace request')
        if request.get('method') != 'trace': raise ValueError('Unsupported trace worker method')
        params = request['params']
        if params.get('trace_image_only') is True:
            if params.get('trace_target_sha256') != params['target_sha256']:
                raise ValueError('Recorded target digest differs')
            images = [trace.get('loaded_image') or params.get('loaded_image') for trace in params.get('traces', [])]
            if not images or any(not image for image in images):
                raise ValueError('Recorded-image-only semantics require an image for every path')
            image = RecordedImageIdentity(images[0], params['target_sha256'], params['target'])
        else:
            if params.get('trace_image_only', False) is not False or 'trace_target_sha256' in params:
                raise ValueError('Recorded target digest requires explicit trace_image_only=true')
            image = BinaryImage.from_file(params['target'], elf_sections='program-headers')
            if image.sha256 != params['target_sha256']: raise ValueError('Target changed after host snapshot')
        emit({'id': request.get('id'), 'result': analyze(params, load_triton(), image)})
    except Exception as error:
        emit({'id': request.get('id'), 'error': {'code': 'TRACE_RECOVERY_FAILED', 'message': str(error)[:1024]}})


if __name__ == '__main__': main()
