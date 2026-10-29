"""Revalidate original file bytes before decoding at recorded runtime PCs.

The caller is the owned internal committed-reference workflow, not a public
raw-pcode API. Reference labels do not independently attest native reachability.
No initial GPR, RAM, flags, data constants or upstream asset is relocated.
"""
import hashlib
import json
import re
from kernel_image import BinaryImage

HEX = re.compile(r'0x[0-9a-f]{1,16}\Z')
SHA = re.compile(r'[a-f0-9]{64}\Z')
UUID = re.compile(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\Z')


def require(value, message):
    if not value:
        raise ValueError('Recorded projection coordinates: ' + message)


def fields(value, names):
    require(type(value) is dict and set(value) == set(names), 'object scope')


def text(value, pattern):
    return type(value) is str and pattern.fullmatch(value) is not None


def integer(value, maximum=(1 << 53) - 1):
    return type(value) is int and 0 <= value <= maximum


def prepare_recorded_input(data, target_sha256, addresses, raw, coordinate_sha256):
    from java_projection import strict_json
    require(type(raw) is bytes and len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == coordinate_sha256, 'coordinate snapshot digest')
    require(hashlib.sha256(data).hexdigest() == target_sha256, 'original target digest')
    x = strict_json(raw)
    fields(x, ('schema', 'targetSha256', 'preferredBase', 'runtimeBase', 'source', 'rows'))
    require(x['schema'] == 'ig5-recorded-runtime-code-input-v1' and x['targetSha256'] == target_sha256 and text(x['preferredBase'], HEX) and text(x['runtimeBase'], HEX), 'input identity')
    s = x['source']
    fields(s, ('recurrencesRef', 'selectionRef', 'runId', 'threadId', 'windows'))
    for ref in (s['recurrencesRef'], s['selectionRef']):
        fields(ref, ('id', 'sha256'))
        require(text(ref['id'], UUID) and text(ref['sha256'], SHA), 'committed reference')
    require(type(s['runId']) is str and re.fullmatch(r'[a-zA-Z0-9_-]{1,128}', s['runId']) and integer(s['threadId'], 0xffffffff) and s['threadId'] > 0, 'source identity')
    require(type(s['windows']) is list and 1 <= len(s['windows']) <= 128, 'window budget')
    windows = set()
    for w in s['windows']:
        fields(w, ('reportId', 'reportSha256', 'traceSha256'))
        require(text(w['reportId'], UUID) and text(w['reportSha256'], SHA) and text(w['traceSha256'], SHA) and w['reportId'] not in windows, 'window identity')
        windows.add(w['reportId'])
    rows = x['rows']
    require(type(rows) is list and 1 <= len(rows) <= 128 and type(addresses) is list and len(rows) == len(addresses), '128 site budget')
    image = BinaryImage.from_bytes(data)
    require(image.format == 'PE' and image.bits == 64 and image.machine == 0x8664 and int(x['preferredBase'], 16) == image.imagebase, 'raw AMD64 PE32+ identity')
    preferred_base, runtime_base = int(x['preferredBase'], 16), int(x['runtimeBase'], 16)
    seen, used, previous, prepared = set(), set(), None, []
    for r, ea in zip(rows, addresses):
        fields(r, ('groupIndex', 'recordingId', 'preferred', 'runtimePc', 'fileOffset', 'bytes', 'pauseBefore', 'pauseAfter'))
        require(integer(r['groupIndex'], 100000) and r['recordingId'] in windows and text(r['preferred'], HEX) and text(r['runtimePc'], HEX) and integer(r['fileOffset'], 64 * 1024**2) and type(r['bytes']) is str and re.fullmatch(r'(?:[a-f0-9]{2}){1,15}', r['bytes']), 'row identity')
        require(integer(r['pauseBefore']) and integer(r['pauseAfter']) and r['pauseAfter'] == r['pauseBefore'] + 1, 'single-step pause boundary')
        preferred, runtime, code = int(r['preferred'], 16), int(r['runtimePc'], 16), bytes.fromhex(r['bytes'])
        require(type(ea) is int and preferred == ea and preferred >= preferred_base and runtime >= runtime_base and preferred > 0 and runtime > 0 and preferred - preferred_base == runtime - runtime_base and runtime + len(code) < 1 << 64 and runtime not in seen, 'coordinate relation')
        if previous is not None:
            require(r['groupIndex'] == previous['groupIndex'] + 1 and r['pauseBefore'] == previous['pauseAfter'], 'non-contiguous recorded body')
        mappings = [region for region in image.regions if region.start <= preferred and preferred + len(code) <= region.start + len(region.data)]
        require(len(mappings) == 1 and mappings[0].permissions & 4, 'unique executable file mapping')
        region = mappings[0]
        offset = preferred - region.start
        require(region.file_offset + offset == r['fileOffset'] and region.data[offset:offset + len(code)] == code, 'original file bytes differ')
        prepared.append({'ea': hex(runtime), 'codeBytes': code.hex()})
        used.add(r['recordingId']); seen.add(runtime); previous = r
    require(used == windows, 'unrelated source window')
    encoded = json.dumps({'schema': 'ig5-java-projection-input-v1', 'targetSha256': target_sha256, 'instructions': prepared}, ensure_ascii=True, separators=(',', ':')).encode('ascii')
    require(len(encoded) <= 65536, 'Java input budget')
    binding = {'schema': 'ig5-recorded-runtime-code-binding-v1', 'inputSha256': coordinate_sha256, 'input': x, 'ordinaryDataRelocated': False, 'globalCodeEpochProved': False}
    return encoded, binding
