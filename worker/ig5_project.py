"""One owned, read-only projection job; reuse the lifter cleanup protocol."""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lift_process import run_owned, OwnedProcessError
from lift_runtime import locked_file
from composition_selection import validate_plan, selected_addresses
from analysis_failure import diagnostic, capture as capture_failure

PROTOCOL = os.fdopen(os.dup(sys.stdout.fileno()), 'w', encoding='utf8', buffering=1)
os.dup2(sys.stderr.fileno(), sys.stdout.fileno())
sys.stdout = sys.stderr
UUID = re.compile(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\Z')
MANIFEST_PIN = '8fc4ae42f775f0139aa5f184c912db71f77e68d661c14564ab6f4820d434abea'


def emit(value):
    PROTOCOL.write(json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(',', ':')) + '\n')


def strict_json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError('Duplicate request property')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON number')))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--artifacts-root', required=True)
    root = Path(parser.parse_args().artifacts_root)
    if not root.is_absolute() or root.resolve(strict=True) != root:
        raise ValueError('Physical projection artifact root required')
    emit({'ig5': 'ready', 'engine': 'projection', 'capabilities': ['project', 'project-recorded', 'compose', 'discover', 'decode-observed', 'flow-semantics','bv-candidate']})
    request, nonce, cleanup = {}, None, True
    directory, p, stages, failed_stage, java_pin = None, None, [], 'preflight', None
    cancel, started = threading.Event(), time.monotonic()
    try:
        raw = sys.stdin.buffer.readline(64 * 1024 + 1)
        if len(raw) > 64 * 1024 or not raw.endswith(b'\n'):
            raise ValueError('Projection request framing limit')
        request = strict_json(raw)
        if not isinstance(request, dict) or request.get('method') not in ('project', 'project-recorded', 'compose','discover','decode-observed','flow-semantics','bv-candidate') or request.get('id') != 1:
            raise ValueError('Unsupported projection request')
        composing = request['method'] == 'compose'
        recorded = request['method'] == 'project-recorded'
        discovering = request['method'] == 'discover'
        observing = request['method'] == 'decode-observed'
        semanticizing = request['method'] == 'flow-semantics'
        candidate_check = request['method'] == 'bv-candidate'
        data_mode = observing or semanticizing or candidate_check
        p = request['params']
        if not isinstance(p, dict):
            raise ValueError('Invalid projection parameters')
        nonce = p.get('nonce')
        expected = ({'job_id','nonce','sha256','budget_ms'} if data_mode else {'job_id','nonce','sha256','ea','max_instructions','follow_direct_calls','budget_ms'} if discovering else
                    {'job_id', 'nonce', 'sha256', 'composition_plan', 'budget_ms'} if composing else
                    {'job_id', 'nonce', 'sha256', 'projection_path', 'projection_registers', 'budget_ms'} |
                    ({'projection_mode'} if 'projection_mode' in p else set()))
        if 'projection_decoder' in p:
            expected |= {'projection_decoder'}
        if recorded:
            expected |= {'recorded_coordinates_sha256'}
        if set(p) != expected:
            raise ValueError('Invalid projection parameter scope')
        decoder_mode = p.get('projection_decoder', 'native')
        if recorded and (decoder_mode != 'java' or p.get('projection_mode') != 'opaque-status' or not isinstance(p['recorded_coordinates_sha256'], str) or not re.fullmatch('[a-f0-9]{64}',p['recorded_coordinates_sha256'])):
            raise ValueError('Recorded projection requires fixed Java opaque-status coordinates')
        if (discovering or data_mode) and 'projection_decoder' in p:raise ValueError('Data analysis does not accept projection decoder selection')
        if type(decoder_mode) is not str or decoder_mode not in ('native', 'java'):
            raise ValueError('Invalid projection decoder')
        if not isinstance(nonce, str) or not UUID.fullmatch(nonce) or not isinstance(p['job_id'], str) or not UUID.fullmatch(p['job_id']):
            raise ValueError('Invalid projection ownership')
        if not isinstance(p['sha256'], str) or not re.fullmatch('[a-f0-9]{64}', p['sha256']):
            raise ValueError('Invalid projection digest')
        if type(p['budget_ms']) is not int or not 1 <= p['budget_ms'] <= 50000:
            raise ValueError('Invalid projection budget')
        if not composing and (type(p.get('projection_mode', 'strict')) is not str or p.get('projection_mode', 'strict') not in ('strict', 'guarded-path', 'opaque-effects','opaque-status')):
            raise ValueError('Invalid projection mode')
        # Validation is repeated in the isolated compute process. Import only
        # the pure engine module in that child, after it enters the OS job.
        if data_mode:
            pass  # Only a bounded SHA blob; no preferred PE address or state processing.
        elif discovering:
            if (not isinstance(p['ea'],str) or not re.fullmatch(r'0x[0-9a-f]{1,16}',p['ea']) or int(p['ea'],16)==0 or
                type(p['max_instructions']) is not int or not 1<=p['max_instructions']<=128 or type(p['follow_direct_calls']) is not bool):raise ValueError('Invalid bounded discovery selection')
        elif composing:
            plan = validate_plan(p['composition_plan'])
        else:
            paths, registers = p['projection_path'], p['projection_registers']
        if not composing and not discovering and not data_mode and (not isinstance(paths, list) or not 1 <= len(paths) <= 128 or
                any(not isinstance(x, str) or not re.fullmatch(r'0x[0-9a-f]{1,16}', x) or int(x, 16) == 0 for x in paths) or
                len(set(int(x, 16) for x in paths)) != len(paths) or
                not isinstance(registers, list) or not 1 <= len(registers) <= 16 or
                any(x not in 'rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15'.split() for x in registers) or
                len(set(registers)) != len(registers)):
            raise ValueError('Invalid projection path/register selection')
        selected_directory = root / 'jobs' / p['job_id']
        if selected_directory.resolve(strict=True) != selected_directory or not selected_directory.is_dir() or any(selected_directory.iterdir()):
            raise ValueError('Projection output must be a fresh physical job directory')
        directory = selected_directory

        def controls():
            try:
                while True:
                    line = sys.stdin.buffer.readline(4097)
                    if not line or len(line) > 4096 or not line.endswith(b'\n'):
                        cancel.set(); return
                    message = strict_json(line)
                    if message == {'id': 0, 'method': 'cancel', 'params': {'requestId': 1, 'nonce': nonce}}:
                        cancel.set(); return
                    cancel.set(); return
            except Exception:
                cancel.set()
        threading.Thread(target=controls, daemon=True).start()
        package = Path(__file__).resolve().parents[1]
        with ExitStack() as held:
            manifest_raw = held.enter_context(locked_file(package / 'runtimes/manifest.json', 2 * 1024**2))
            if hashlib.sha256(manifest_raw).hexdigest() != MANIFEST_PIN:
                raise ValueError('Projection runtime manifest pin mismatch')
            inventory = {row['path']: row for row in json.loads(manifest_raw)['files']}
            executable = package / 'runtimes/ghidra/python/python.exe'
            if Path(sys.executable).resolve() != executable.resolve():
                raise ValueError('Projection requires the bundled Python runtime')
            # Hold the executable and native Python runtime against replacement.
            for name in ('ghidra/python/python.exe', 'ghidra/python/python312.dll'):
                data = held.enter_context(locked_file(package / 'runtimes' / name, 32 * 1024**2))
                pin = inventory[name]
                if len(data) != pin['bytes'] or hashlib.sha256(data).hexdigest() != pin['sha256']:
                    raise ValueError('Projection Python runtime pin mismatch')
            data = held.enter_context(locked_file(root / 'blobs' / (p['sha256'] + '.bin'), 65536 if observing or candidate_check else 4 * 1024**2 if semanticizing else 64 * 1024**2))
            if hashlib.sha256(data).hexdigest() != p['sha256']:
                raise ValueError('Projection input digest mismatch')
            def remaining_budget():
                if cancel.is_set():
                    raise ValueError('Projection cancelled before compute stage')
                remaining = min(p['budget_ms'], 50000) - int((time.monotonic() - started) * 1000)
                if remaining < 1:
                    raise ValueError('Projection shared compute deadline exhausted')
                return remaining
            remaining = remaining_budget()
            child_request = ({'sha256':p['sha256']} if data_mode else {key:p[key] for key in ('sha256','ea','max_instructions','follow_direct_calls')} if discovering else
                             {'sha256': p['sha256'], 'composition_plan': plan} if composing else
                             {key: p[key] for key in ('sha256', 'projection_path', 'projection_registers')})
            if not composing and 'projection_mode' in p:
                child_request['projection_mode'] = p['projection_mode']
            if recorded:
                child_request['recorded_coordinates_sha256'] = p['recorded_coordinates_sha256']
            if decoder_mode == 'java':
                from java_projection import held_runtime, prepare_input, arguments, validate_output, digest, JAVA_RUNTIME_PIN
                java_pin, failed_stage = JAVA_RUNTIME_PIN, 'java-runtime'
                config_raw = held.enter_context(locked_file(package / 'runtimes/ghidra/runtime.json', 65536))
                config_pin = inventory['ghidra/runtime.json']
                if len(config_raw) != config_pin['bytes'] or digest(config_raw) != config_pin['sha256']:
                    raise ValueError('Java decoder runtime configuration pin mismatch')
                config = strict_json(config_raw)
                java_manifest = held.enter_context(held_runtime(package, inventory, config, remaining_budget))
                addresses = [int(a, 16) for a in selected_addresses(plan)] if composing else [int(a, 16) for a in paths]
                if recorded:
                    from recorded_coordinates import prepare_recorded_input
                    coordinate_raw = held.enter_context(locked_file(root / 'blobs' / (p['recorded_coordinates_sha256'] + '.bin'),65536))
                    prepared, _ = prepare_recorded_input(data,p['sha256'],addresses,coordinate_raw,p['recorded_coordinates_sha256'])
                else:
                    prepared = prepare_input(data, p['sha256'], addresses)
                prepared_path = directory / 'java-input.json'
                with prepared_path.open('xb') as stream:
                    stream.write(prepared)
                held.enter_context(locked_file(prepared_path, 65536))
                decode_directory = directory / 'java-decode'
                decode_directory.mkdir()
                java_executable, java_arguments = arguments(package, java_manifest, prepared_path, digest(prepared), decode_directory)
                decode_budget = remaining_budget()
                def decode_started(pid):
                    with (decode_directory / 'started.json').open('x', encoding='utf8') as stream:
                        json.dump({'pid': pid, 'nonce': nonce, 'jobAssignedAtCreation': True,
                                   'nativeTargetExecuted': False}, stream)
                cleanup = False
                failed_stage = 'java-decode'
                decode_process = run_owned(str(java_executable), java_arguments, decode_directory,
                                           budget_ms=decode_budget, cancel=cancel, on_started=decode_started)
                cleanup = decode_process['childExitConfirmed']
                with (directory / 'java-decode-process.json').open('x', encoding='utf8') as stream:
                    json.dump(decode_process, stream)
                stages.append({'stage': 'java-decode', 'budgetMs': decode_budget, 'process': decode_process})
                if decode_process['status'] != 'completed' or decode_process['exitCode'] != 0:
                    detail = decode_process['limitReason']
                    if not detail:
                        with locked_file(decode_directory / 'stderr.log', 4 * 1024**2) as errors:
                            detail = diagnostic(errors, java=True)
                    raise ValueError('Java projection decode failed: ' + str(detail))
                failed_stage = 'java-validation'
                decoded_raw = held.enter_context(locked_file(decode_directory / 'stdout.log', 4 * 1024**2))
                validate_output(decoded_raw, prepared)
                child_request.update(projection_decoder='java', decoded_input={'sha256': digest(decoded_raw), 'inputSha256': digest(prepared)})
                remaining = remaining_budget()
            child_request.update(target=str(root / 'blobs' / (p['sha256'] + '.bin')), budget_ms=remaining)
            request_file = directory / 'request.json'
            with request_file.open('x', encoding='utf8') as stream:
                json.dump(child_request, stream, ensure_ascii=True)
            held.enter_context(locked_file(request_file, 64 * 1024))
            cleanup = False
            failed_stage = 'state-computation'
            process = run_owned(str(executable), ['-I', '-B', '-X', 'utf8', str(package / ('worker/bitvector_verify.py' if candidate_check else 'worker/flow_semantics_worker.py' if semanticizing else 'worker/observed_decode_worker.py' if observing else 'worker/path_discovery_worker.py' if discovering else 'worker/projection_worker.py')), str(request_file)],
                                directory, budget_ms=remaining, cancel=cancel)
            cleanup = process['childExitConfirmed']
            with (directory / 'state-computation-process.json').open('x', encoding='utf8') as stream:
                json.dump(process, stream)
            stages.append({'stage': 'state-computation', 'budgetMs': remaining, 'process': process})
        if process['status'] != 'completed' or process['exitCode'] != 0:
            detail = process['limitReason']
            if not detail:
                with locked_file(directory / 'stderr.log', 4 * 1024**2) as errors:
                    detail = diagnostic(errors)
            raise ValueError('Projection analysis failed: ' + str(detail))
        failed_stage = 'result-validation'
        with locked_file(directory / 'stdout.log', 4 * 1024**2) as output:
            result = strict_json(output)
        expected_schema = ('ig5-bitvector-solver-v1' if candidate_check else 'ig5-flow-semantic-assessment-v1' if semanticizing else 'ig5-observed-decode-v1' if observing else 'ig5-path-discovery-v1' if discovering else ('ig5-pcode-opaque-status-transition-chain-v1' if plan.get('template_mode') == 'opaque-status' else
                            'ig5-pcode-opaque-transition-chain-v1' if plan.get('template_mode') == 'opaque-effects' else
                            'ig5-pcode-transition-chain-v1' if plan.get('representation') == 'transition-chain' else 'ig5-pcode-composition-v1') if composing else
                           'ig5-pcode-guarded-projection-v1' if p.get('projection_mode') == 'guarded-path' else
                           'ig5-pcode-opaque-status-projection-v1' if p.get('projection_mode') == 'opaque-status' else
                           'ig5-pcode-opaque-projection-v1' if p.get('projection_mode') == 'opaque-effects' else 'ig5-pcode-projection-v1')
        if (not isinstance(result, dict) or result.get('schema') != expected_schema or result.get('inputSha256' if data_mode else 'targetSha256') != p['sha256'] or
                any(result.get(key) is not False for key in ('nativeTargetExecuted', 'databaseModified', 'businessAccepted', 'wholeBinaryVerified'))):
            raise ValueError('Projection returned inconsistent evidence scope')
        emit({'id': 1, 'nonce': nonce, 'cleanupConfirmed': cleanup,
              'result': {'targetSha256': p['sha256'], 'process': process, 'outputBytes': len(output),
                         'outputSha256': hashlib.sha256(output).hexdigest(), 'runtimeManifestPin': MANIFEST_PIN,
                         **({'processBudgetMs':remaining,'sharedBudgetMs':p['budget_ms']} if discovering or data_mode else {}),
                         **({'projectionDecoder': 'java', 'javaDecoderManifestPin': JAVA_RUNTIME_PIN,
                             'processStages': stages, 'sharedBudgetMs': p['budget_ms']} if decoder_mode == 'java' else {})}})
    except Exception as error:
        if isinstance(error, OwnedProcessError):
            cleanup = error.child_exit_confirmed
        code = 'COMPOSITION_FAILED' if isinstance(request, dict) and request.get('method') == 'compose' else 'DISCOVERY_FAILED' if isinstance(request,dict) and request.get('method')=='discover' else 'PROJECTION_FAILED'
        message, evidence = str(error)[:2000], None
        if directory is not None:
            try:
                evidence = capture_failure(directory, params=p, method=request['method'], runtime_pin=MANIFEST_PIN,
                                           java_pin=java_pin, stage=failed_stage, stages=stages,
                                           cleanup=cleanup, code=code, message=message)
            except Exception:
                # Evidence failure must not hide the original error or supply
                # an invented child-exit ACK.
                pass
        emit({'id': request.get('id') if isinstance(request, dict) else None, 'nonce': nonce,
              'cleanupConfirmed': cleanup, 'error': {'code': code, 'message': message},
              **({'analysisFailure': evidence} if evidence is not None else {})})


if __name__ == '__main__':
    main()
