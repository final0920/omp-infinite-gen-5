"""Bounded raw-file SLEIGH decoding and symbolic state projection. No execution."""
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import re
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from kernel_image import BinaryImage
from kernel_analysis import SleighDecoder
from lift_runtime import locked_file
from pcode_projection import project
from composition_selection import validate_plan, plan_paths, selected_addresses

MANIFEST_PIN = '8fc4ae42f775f0139aa5f184c912db71f77e68d661c14564ab6f4820d434abea'
GPRS = 'rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15'.split()
HEX = re.compile(r'0x[0-9a-fA-F]{1,16}\Z')


def validate_selection(p):
    addresses, registers = p.get('projection_path'), p.get('projection_registers')
    if (not isinstance(addresses, list) or not 1 <= len(addresses) <= 128 or
            any(not isinstance(x, str) or not HEX.fullmatch(x) or int(x, 16) == 0 for x in addresses)):
        raise ValueError('projection_path requires 1..128 explicit nonzero preferred addresses')
    addresses = [int(x, 16) for x in addresses]
    if len(set(addresses)) != len(addresses):
        raise ValueError('Repeated instruction addresses require a loop model; unsupported')
    if (not isinstance(registers, list) or not 1 <= len(registers) <= 16 or
            any(not isinstance(x, str) or x not in GPRS for x in registers) or len(set(registers)) != len(registers)):
        raise ValueError('projection_registers requires unique full-width x64 GPR names')
    return addresses, registers


def main():
    if len(sys.argv) != 2:
        raise ValueError('One fixed job request path required')
    request_path = Path(sys.argv[1])
    with locked_file(request_path, 64 * 1024) as raw:
        p = json.loads(raw)
    composing = 'composition_plan' in p
    expected = ({'target', 'sha256', 'composition_plan', 'budget_ms'} if composing else
                {'target', 'sha256', 'projection_path', 'projection_registers', 'budget_ms'} |
                ({'projection_mode'} if 'projection_mode' in p else set()))
    decoder_mode = p.get('projection_decoder', 'native')
    recorded = 'recorded_coordinates_sha256' in p
    if recorded:
        expected |= {'recorded_coordinates_sha256'}
        if decoder_mode != 'java' or composing or p.get('projection_mode') != 'opaque-status':
            raise ValueError('Recorded coordinates require fixed Java opaque-status projection')
    if 'projection_decoder' in p:
        expected |= {'projection_decoder'}
    if decoder_mode == 'java':
        expected |= {'decoded_input'}
    if set(p) != expected:
        raise ValueError('Invalid projection child request')
    if type(decoder_mode) is not str or decoder_mode not in ('native', 'java'):
        raise ValueError('Invalid projection decoder')
    mode = p.get('projection_mode', 'strict')
    if type(mode) is not str or mode not in ('strict', 'guarded-path', 'opaque-effects','opaque-status'):
        raise ValueError('Invalid projection mode')
    if composing:
        plan = validate_plan(p['composition_plan'])
        addresses, registers = [int(a, 16) for a in selected_addresses(plan)], GPRS
    else:
        addresses, registers = validate_selection(p)
    if type(p['budget_ms']) is not int or not 1 <= p['budget_ms'] <= 50000:
        raise ValueError('Invalid projection deadline')
    if not isinstance(p['sha256'], str) or not re.fullmatch('[a-f0-9]{64}', p['sha256']):
        raise ValueError('Invalid target SHA-256')
    deadline = time.monotonic() + p['budget_ms'] / 1000

    def check():
        if time.monotonic() >= deadline:
            raise ValueError('Projection deadline exceeded')

    root = Path(__file__).resolve().parents[1]
    runtime = root / 'runtimes'
    pins = []
    with ExitStack() as held:
        manifest_raw = held.enter_context(locked_file(runtime / 'manifest.json', 2 * 1024**2))
        if hashlib.sha256(manifest_raw).hexdigest() != MANIFEST_PIN:
            raise ValueError('Bundled decoder manifest pin mismatch')
        manifest = json.loads(manifest_raw)
        inventory = {x['path']: x for x in manifest['files']}
        config_raw = held.enter_context(locked_file(runtime / 'ghidra/runtime.json', 64 * 1024))
        config_pin = inventory['ghidra/runtime.json']
        if len(config_raw) != config_pin['bytes'] or hashlib.sha256(config_raw).hexdigest() != config_pin['sha256']:
            raise ValueError('Bundled runtime configuration pin mismatch')
        config = json.loads(config_raw)
        home = runtime / 'ghidra' / config['ghidraHome']
        java = runtime / 'ghidra' / config['javaHome']
        decoder_files = [str(home.relative_to(runtime)).replace('\\', '/') + '/Ghidra/Processors/x86/data/languages/x86-64.sla']
        if decoder_mode == 'native':
            decoder_files.insert(0, 'ghidra/ig5_sleigh.dll')
        for name in decoder_files:
            row = inventory[name]
            data = held.enter_context(locked_file(runtime / name, 64 * 1024**2))
            if len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256']:
                raise ValueError('Decoder asset pin mismatch')
            pins.append(row)
        data = held.enter_context(locked_file(Path(p['target']), 64 * 1024**2))
        if hashlib.sha256(data).hexdigest() != p['sha256']:
            raise ValueError('Projection target snapshot digest mismatch')
        image = BinaryImage.from_bytes(data)
        if image.format != 'PE' or image.bits != 64 or image.machine != 0x8664:
            raise ValueError('Projection requires a raw AMD64 PE32+ image')
        java_rows, recorded_binding = None, None
        if decoder_mode == 'java':
            from java_projection import load_manifest, prepare_input, validate_output, digest, JAVA_RUNTIME_PIN
            manifest_raw = held.enter_context(locked_file(root / 'adapters/ghidra/projection-java/manifest.json', 128 * 1024))
            java_manifest = load_manifest(manifest_raw)
            helper = java_manifest['helper']
            helper_raw = held.enter_context(locked_file(root / 'adapters/ghidra/projection-java' / helper['path'], 64 * 1024))
            if len(helper_raw) != helper['bytes'] or digest(helper_raw) != helper['sha256']:
                raise ValueError('Java projection helper pin mismatch')
            reference = p['decoded_input']
            if not isinstance(reference, dict) or set(reference) != {'sha256', 'inputSha256'}:
                raise ValueError('Java projection private decode reference scope')
            if recorded:
                from recorded_coordinates import prepare_recorded_input
                coordinate_sha = p['recorded_coordinates_sha256']
                if type(coordinate_sha) is not str or not re.fullmatch('[a-f0-9]{64}',coordinate_sha):
                    raise ValueError('Recorded coordinate digest scope')
                coordinate_raw = held.enter_context(locked_file(Path(p['target']).parent / (coordinate_sha + '.bin'),65536))
                prepared, recorded_binding = prepare_recorded_input(data,p['sha256'],addresses,coordinate_raw,coordinate_sha)
            else:
                prepared = prepare_input(data, p['sha256'], addresses)
            if reference['inputSha256'] != digest(prepared):
                raise ValueError('Java decode input no longer matches locked original bytes')
            decoded_raw = held.enter_context(locked_file(request_path.parent / 'java-decode/stdout.log', 4 * 1024**2))
            if reference['sha256'] != digest(decoded_raw):
                raise ValueError('Java decode output digest mismatch')
            decoded_java = validate_output(decoded_raw, prepared)
            java_rows = {int(row['ea'], 16): {k: v for k, v in row.items() if k != 'codeBytes'} for row in decoded_java['instructions']}
            pins.append({**helper, 'path': 'adapters/ghidra/projection-java/' + helper['path'], 'root': 'plugin'})
        else:
            decoder = SleighDecoder(runtime / 'ghidra', home, java)
        instructions, raw_rows = [], []
        for ordinal, ea in enumerate(addresses):
            check()
            mappings = [r for r in image.regions if r.start <= ea < r.start + len(r.data)]
            if len(mappings) != 1:
                raise ValueError('Projection address must map uniquely to file-backed bytes')
            region = mappings[0]
            if not region.permissions & 4:
                raise ValueError('Projection address must be in an executable file-backed region')
            offset = ea - region.start
            code = region.data[offset:offset + 15]
            decode_ea = ea
            if recorded_binding is not None:
                coordinate_row = recorded_binding['input']['rows'][ordinal]
                decode_ea = int(coordinate_row['runtimePc'],16)
                code = bytes.fromhex(coordinate_row['bytes'])
            decoded = ({'ok': True, 'instructions': [java_rows[decode_ea]], 'error': None,
                        'consumedBytes': java_rows[decode_ea]['size']} if java_rows is not None else decoder.decode(image, code, ea, 1))
            rows = decoded.get('instructions', [])
            if not decoded.get('ok') or len(rows) != 1 or decoded.get('error'):
                raise ValueError('Projection instruction decode failed')
            instruction = rows[0]
            size = instruction.get('size')
            if type(size) is not int or not 1 <= size <= min(15, len(code)) or int(instruction['ea'], 16) != decode_ea or recorded and size != len(code):
                raise ValueError('Invalid decoded instruction boundary')
            if decoded.get('consumedBytes') != size:
                raise ValueError('Decoder byte coverage mismatch')
            if composing and (type(instruction.get('pcode')) is not list or len(instruction['pcode']) > 128):
                raise ValueError('Composition decode exceeds128 raw p-code operations per instruction')
            # Bind internal architectural-effect classification to immutable bytes,
            # not only the decoder's printable mnemonic/operand strings.
            instructions.append({**instruction, 'codeBytes': code[:size].hex()})
            raw_rows.append({'ea': hex(decode_ea), 'bytes': code[:size].hex(), 'decoded': instruction})
        if composing:
            from projection_composition import compose_paths, compose_until_exit
            by_address = {row['ea']: row for row in instructions}
            raw_path = lambda path: [by_address[a] for a in path]
            options = {'indirect_mode': plan['indirect_mode']}
            if plan['strategy'] == 'sequence':
                result = compose_paths([raw_path(path) for path in plan['paths']], check,
                                       representation=plan.get('representation', 'flat'), template_mode=plan.get('template_mode', 'strict'), **options)
            else:
                result = compose_until_exit(raw_path(plan['prefix']), raw_path(plan['body']),
                                            [raw_path(path) for path in plan['suffix']], check, **options)
            result['representationSchema'] = result['schema']
            result['schema'] = ('ig5-pcode-opaque-status-transition-chain-v1' if plan.get('template_mode') == 'opaque-status' else
                                'ig5-pcode-opaque-transition-chain-v1' if plan.get('template_mode') == 'opaque-effects' else
                                'ig5-pcode-transition-chain-v1' if plan.get('representation') == 'transition-chain'
                                else 'ig5-pcode-composition-v1')
            result['publicToolRouteExposed'] = True
            result['compositionLimits'] = result.pop('internalPrototypeLimits')
            result['compositionPlan'] = plan
            result['decodeStatistics'] = {'instructions': len(instructions),
                'rawPcodeOperations': sum(len(row['pcode']) for row in instructions),
                'providedAddressOccurrences': sum(len(path) for path in plan_paths(plan))}
            result['scope']['code'] = 'Original snapshot bytes and decoder assets held and hash-verified in this owned analysis child; no code/data-fetch coherence.'
            result['scope']['integration'] = 'Public level=compose address-plan route; expanded work budgets are separate from the unchanged level=project fixed-path limits.'
        else:
            result = project(instructions, registers, check, mode=mode)
        result.update(backend='IG5 state projection / Ghidra SLEIGH', targetSha256=p['sha256'],
                      runtimeManifestPin=MANIFEST_PIN, decoderAssets=pins, decodedPath=raw_rows,
                      inputScope='Raw-file preferred addresses; fixed decoded code, no relocation or captured-image substitution.')
        if composing:
            result['backend'] = 'IG5 state composition / Ghidra SLEIGH'
        else:
            result.update(projectionPath=[hex(x) for x in addresses], projectionRegisters=registers)
        if recorded_binding is not None:
            result.update(recordedCoordinates=recorded_binding,originalPreferredPath=[hex(x) for x in addresses],
                          projectionPath=[r['runtimePc'] for r in recorded_binding['input']['rows']],
                          inputScope='Exact recorded runtime PCs and instruction lengths bound to original executable file bytes; ordinary GPR/RAM/data constants are not relocated.')
        if decoder_mode == 'java':
            result['projectionDecoder'] = 'java'
            result['javaDecoder'] = {'runtimeManifestPin': JAVA_RUNTIME_PIN, 'upstreamManifestPin': MANIFEST_PIN,
                'helperSha256': helper['sha256'], 'inputSha256': digest(prepared), 'outputSha256': digest(decoded_raw),
                'language': decoded_java['language'], 'runtimeAssetCount': len(java_manifest['upstreamAssets'])}
            result['backend'] = 'IG5 state ' + ('composition' if composing else 'projection') + ' / Ghidra Java SLEIGH'
            result['scope']['code'] = 'Original snapshot and language/helper held and hash-verified here; the supervisor holds all pinned Java runtime assets across sequential decode and computation jobs. Fixed code bytes, no code/data-fetch coherence.'
        encoded = json.dumps(result, ensure_ascii=True, allow_nan=False, separators=(',', ':'))
        if len(encoded.encode('utf8')) > 4 * 1024**2:
            raise ValueError('Projection report exceeds 4 MiB')
        print(encoded)


if __name__ == '__main__':
    main()
