"""Decode at most 128 recorded instruction byte strings. Never process/execute them."""
from contextlib import ExitStack
from pathlib import Path
import hashlib, json, re, sys, time
sys.path.insert(0, str(Path(__file__).resolve().parent))
from lift_runtime import locked_file
from trace_analysis import load_triton, MANIFEST_SHA256

def decode_sites(tt, sites, check=lambda: None):
    if not isinstance(sites, list) or not 0 <= len(sites) <= 128:
        raise ValueError('Recorded decode requires at most 128 sites')
    ctx, output, seen = tt.TritonContext(tt.ARCH.X86_64), [], set()
    def register(r):
        if not r.getId(): return None
        return {'kind': 'register', 'name': r.getName(), 'bits': r.getBitSize(),
                'low': r.getBitvector().getLow(), 'parent': ctx.getParentRegister(r).getName()}
    for site in sites:
        check()
        if (not isinstance(site, dict) or set(site) != {'pc', 'bytes'} or
            not isinstance(site['pc'], str) or not re.fullmatch(r'0x[0-9a-f]{1,16}', site['pc']) or
            not isinstance(site['bytes'], str) or not re.fullmatch(r'(?:[0-9a-f]{2}){1,15}', site['bytes'])):
            raise ValueError('Invalid recorded decode site')
        identity = (site['pc'], site['bytes'])
        if identity in seen: raise ValueError('Duplicate recorded decode site')
        seen.add(identity)
        try:
            instruction = tt.Instruction(int(site['pc'], 16), bytes.fromhex(site['bytes']))
            ctx.disassembly(instruction)
            if instruction.getType() == 0 or instruction.getSize() != len(site['bytes']) // 2:
                raise ValueError('Decoder size differs from complete recorded instruction')
            operands = []
            for op in instruction.getOperands():
                if op.getType() == tt.OPERAND.REG: operands.append(register(op))
                elif op.getType() == tt.OPERAND.MEM:
                    operands.append({'kind': 'memory', 'bytes': op.getSize(),
                        'base': register(op.getBaseRegister()), 'index': register(op.getIndexRegister()),
                        'segment': op.getSegmentRegister().getName() if op.getSegmentRegister().getId() else None,
                        'scale': op.getScale().getValue(), 'displacement': hex(op.getDisplacement().getValue()),
                        'displacementBits': op.getDisplacement().getBitSize()})
                elif op.getType() == tt.OPERAND.IMM:
                    operands.append({'kind': 'immediate', 'value': hex(op.getValue()), 'bits': op.getBitSize()})
                else: raise ValueError('Unsupported decoded operand')
            output.append({**site, 'status': 'decoded', 'text': instruction.getDisassembly(),
                           'controlFlow': instruction.isControlFlow(), 'operands': operands})
        except (TypeError, ValueError) as error:
            output.append({**site, 'status': 'decode-rejected', 'error': str(error)[:512]})
    return output

def main():
    if len(sys.argv) != 2: raise ValueError('One private recorded decode request required')
    with ExitStack() as held:
        p = json.loads(held.enter_context(locked_file(Path(sys.argv[1]), 65536)))
        if set(p) != {'target', 'sha256', 'budget_ms'} or type(p['budget_ms']) is not int or not 1 <= p['budget_ms'] <= 50000:
            raise ValueError('Invalid recorded decode child request')
        deadline = time.monotonic() + p['budget_ms'] / 1000
        def check():
            if time.monotonic() >= deadline: raise ValueError('Recorded decode deadline exhausted')
        raw = held.enter_context(locked_file(Path(p['target']), 65536))
        if hashlib.sha256(raw).hexdigest() != p['sha256']: raise ValueError('Recorded decode input digest differs')
        request = json.loads(raw)
        if set(request) != {'schema', 'sites'} or request['schema'] != 'ig5-observed-decode-input-v1':
            raise ValueError('Invalid recorded byte input schema')
        vendor = Path(__file__).resolve().parent / 'trace_vendor'
        inventory = held.enter_context(locked_file(vendor / 'ig5-manifest.json', 4 * 1024**2))
        if hashlib.sha256(inventory).hexdigest() != MANIFEST_SHA256: raise ValueError('Recorded decoder inventory differs')
        for row in json.loads(inventory)['files']:
            check(); filename = vendor / row['path']
            if not filename.resolve().is_relative_to(vendor.resolve()): raise ValueError('Recorded decoder dependency outside vendor')
            content = held.enter_context(locked_file(filename, 128 * 1024**2))
            if len(content) != row['bytes'] or hashlib.sha256(content).hexdigest() != row['sha256']: raise ValueError('Recorded decoder dependency differs')
        result = {'schema': 'ig5-observed-decode-v1', 'inputSha256': p['sha256'],
            'decoder': 'pinned-triton-disassembly-only', 'decoderManifestPin': MANIFEST_SHA256,
            'runtimeManifestPin': '8fc4ae42f775f0139aa5f184c912db71f77e68d661c14564ab6f4820d434abea',
            'nativeTargetExecuted': False, 'databaseModified': False, 'businessAccepted': False, 'wholeBinaryVerified': False,
            'sites': decode_sites(load_triton(), request['sites'], check)}
        output = (json.dumps(result, ensure_ascii=True, allow_nan=False, separators=(',', ':')) + '\n').encode('ascii')
        if len(output) > 4 * 1024**2: raise ValueError('Recorded decode output exceeds 4 MiB')
        sys.stdout.buffer.write(output)

if __name__ == '__main__': main()
