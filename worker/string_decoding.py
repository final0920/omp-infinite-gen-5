"""Find string/config decoder routines and decode their call sites by emulation.

Engine independent. A provider supplies decoder candidates (a function plus the constant arguments resolved at
each of its call sites) and a ``run`` callback that emulates one call with write tracing. This module scores the
candidates, plans bounded runs, extracts text from what the decoder wrote, and re-runs each hit once to check it
reproduces. Everything it reports is "consistent with an emulated execution" (level E1); it is not proof that the
program decodes these strings at run time, and decoders that call imports or the OS cannot be emulated here.
"""
from __future__ import annotations

import re
import time

SCHEMA_VERSION = 1
LIMITS = {'min_calls': (3, 1, 1000), 'max_decoders': (16, 1, 64), 'max_runs': (200, 1, 2000), 'max_runs_per_decoder': (64, 1, 500),
          'time_budget_ms': (30000, 100, 120000), 'max_strings': (500, 1, 2000), 'min_text': (4, 3, 64), 'max_size': (600, 16, 4096)}
SCRATCH_BASE = {64: 0x600000000000, 32: 0x60000000}
SCRATCH_SIZE, SCORE_THRESHOLD = 4096, 5
INTERPRETATION = ('Text written by a candidate decoder during emulation of one call. Level E1: consistent with that emulated execution, '
                  'reproduced once. It does not prove the program decodes the string at run time, and a candidate is chosen '
                  'by structure (loop, arithmetic, memory writes), not by knowing it is a decoder.')
LIMITATIONS = ['CPU and copied memory only: a decoder that calls imports, the OS or the heap cannot be emulated and is reported as unsupported',
               'Arguments are the constants resolved at each call site; stack-relative buffers are replaced by a scratch buffer and unresolved '
               'arguments are passed as 0',
               'Only text written to memory is extracted (ASCII and UTF-16LE); decoders that return a pointer to existing memory are not covered',
               'x86-64 call sites only']
_ASCII = re.compile(rb'[\x20-\x7e\t\r\n]{%d,}')
_UTF16 = re.compile(rb'(?:[\x20-\x7e]\x00){%d,}')


def limits_from(params):
    result = {}
    for key, (default, low, high) in LIMITS.items():
        value = (params or {}).get(key, default)
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise ValueError('%s must be an integer in %d..%d' % (key, low, high))
        result[key] = value
    return result


def score_decoder(feature):
    """Return (score, reasons) for a function that looks like a decoder, else None."""
    if not feature.get('hasLoop') or not feature.get('arithmetic') or not feature.get('memoryWrites'):
        return None
    score, reasons = 3, ['contains a loop']
    arithmetic = min(3, int(feature['arithmetic']))
    score += arithmetic
    reasons.append('%d byte-level arithmetic/logic operation(s)' % feature['arithmetic'])
    score += 2
    reasons.append('writes memory')
    fan_in = int(feature.get('fanIn', 0))
    score += min(4, fan_in // 2)
    reasons.append('called from %d site(s)' % fan_in)
    if feature.get('externalCalls'):
        score -= 3
        reasons.append('calls %d import/unknown function(s) and may not be emulatable' % feature['externalCalls'])
    elif feature.get('calls'):
        score -= 1
        reasons.append('calls other functions')
    if int(feature.get('size', 0)) > 300:
        score -= 2
        reasons.append('larger than a typical decoder')
    return score, reasons


def plan_arguments(site_args, bits):
    """Turn resolved call-site arguments into concrete emulator arguments.

    Returns (args, scratch, unresolved): ``args`` are integers; ``scratch`` lists the scratch buffers to map; a
    stack-relative argument becomes the address of its own scratch buffer; an unknown argument becomes 0.
    """
    args, scratch, kinds = [], [], []
    for argument in site_args:
        kind = argument.get('kind') if isinstance(argument, dict) else None
        kinds.append(kind)
        if kind == 'const':
            args.append(int(argument['value']) & ((1 << bits) - 1))
        elif kind == 'stack':
            address = SCRATCH_BASE[bits] + len(scratch) * 2 * SCRATCH_SIZE
            scratch.append({'ea': hex(address), 'hex': '00' * SCRATCH_SIZE})
            args.append(address)
        else:
            args.append(0)
    # The callee's arity is unknown, so trailing arguments that nothing sets are most likely unused: only
    # unknown arguments that sit before the last known one are counted as unresolved.
    last_known = max((index for index, kind in enumerate(kinds) if kind in ('const', 'stack')), default=-1)
    unresolved = sum(1 for kind in kinds[:max(last_known, 0)] if kind not in ('const', 'stack'))
    return args, scratch, unresolved


def extract_texts(writes, minimum):
    """Text runs (ASCII, UTF-16LE) that lie at least partly in bytes the decoder changed."""
    ascii_re = re.compile(_ASCII.pattern % minimum)
    wide_re = re.compile(_UTF16.pattern % minimum)
    found = []
    for write in writes:
        before, after = bytes.fromhex(write['before']), bytes.fromhex(write['after'])
        base = int(write['ea'], 16)
        changed = [a != b for a, b in zip(after, before)]
        for encoding, pattern, step in (('ascii', ascii_re, 1), ('utf-16le', wide_re, 2)):
            for match in pattern.finditer(after):
                start, end = match.span()
                if not any(changed[start:end]):
                    continue
                raw = match.group()
                text = (raw.decode('ascii') if step == 1 else raw.decode('utf-16le')).strip()
                if len(text) >= minimum and len(set(text)) >= 3:
                    found.append({'text': text, 'encoding': encoding, 'ea': hex(base + start), 'size': end - start})
    return found


def _fault_reason(result):
    fault = result.get('fault') or {}
    if result.get('reason') == 'unmapped-memory' and fault.get('accessType') == 'execute':
        return 'calls-outside-image'
    if result.get('reason') == 'memory-protection' and fault.get('accessType') == 'write':
        return 'writes-read-only-memory'
    return str(result.get('reason') or 'failed')


def decode_strings(candidates, run, params=None, *, clock=time.monotonic, considered=0):
    """Decode every resolvable call site of the best decoder candidates.

    ``run(entry, args, scratch)`` emulates one call and returns the emulator result with ``writes``.
    """
    limits = limits_from(params)
    started = clock()
    scored = []
    for candidate in candidates:
        features = {**candidate['features'], 'size': candidate.get('size', 0)}
        if candidate.get('forced'):
            # The caller named this function: try it whatever its structure, but still report how it scored.
            scoring = score_decoder(features) or (0, ['does not look like a decoder by structure'])
            scored.append((scoring[0], int(features.get('fanIn', 0)), candidate, ['selected explicitly by the caller'] + scoring[1]))
            continue
        scoring = score_decoder(features) if int(features.get('fanIn', 0)) >= limits['min_calls'] else None
        if scoring and scoring[0] >= SCORE_THRESHOLD and int(candidate.get('size', 0)) <= limits['max_size']:
            scored.append((scoring[0], int(features.get('fanIn', 0)), candidate, scoring[1]))
    scored.sort(key=lambda item: (-item[0], -item[1], item[2]['ea']))
    truncation = {'decoders': len(scored) > limits['max_decoders'], 'runs': False, 'time': False, 'strings': False}
    decoders, strings, seen, runs, sites_total, unresolved_total = [], [], set(), 0, 0, 0
    for score, _, candidate, reasons in scored[:limits['max_decoders']]:
        row = {'ea': candidate['ea'], 'name': candidate.get('name', ''), 'score': score, 'reasons': reasons, 'size': candidate.get('size'),
               'callSites': len(candidate['sites']), 'runs': 0, 'decodedRuns': 0, 'strings': 0, 'unstableRuns': 0, 'unresolvedArguments': 0,
               'unsupported': {}, 'status': 'no-output'}
        entry = int(candidate['ea'], 16)
        sites_total += len(candidate['sites'])
        for site in sorted(candidate['sites'], key=lambda item: item['ea'])[:limits['max_runs_per_decoder']]:
            if runs >= limits['max_runs']:
                truncation['runs'] = True
                break
            if (clock() - started) * 1000 >= limits['time_budget_ms']:
                truncation['time'] = True
                break
            args, scratch, unresolved = plan_arguments(site.get('args') or [], candidate.get('bits', 64))
            row['unresolvedArguments'] += unresolved
            unresolved_total += unresolved
            runs += 1
            row['runs'] += 1
            result = run(entry, args, scratch)
            if result.get('reason') != 'returned':
                reason = _fault_reason(result)
                row['unsupported'][reason] = row['unsupported'].get(reason, 0) + 1
                continue
            texts = extract_texts(result.get('writes') or [], limits['min_text'])
            if not texts:
                continue
            again = run(entry, args, scratch)
            if again.get('reason') != 'returned' or again.get('writes') != result.get('writes'):
                row['unstableRuns'] += 1
                continue
            row['decodedRuns'] += 1
            for text in texts:
                key = (site['ea'], text['ea'], text['text'])
                if key in seen:
                    continue
                if len(strings) >= limits['max_strings']:
                    truncation['strings'] = True
                    break
                seen.add(key)
                row['strings'] += 1
                strings.append({**text, 'callSite': site['ea'], 'caller': site.get('caller'), 'decoder': candidate['ea'],
                                'args': [hex(value) for value in args], 'stackArguments': len(scratch), 'reproduced': True,
                                'verificationLevel': 'E1', 'basis': 'unicorn-emulation'})
        if row['strings']:
            row['status'] = 'decoded'
        elif row['runs'] and sum(row['unsupported'].values()) == row['runs']:
            row['status'] = 'unsupported'      # every emulated call failed: do not present this as "nothing to decode"
        decoders.append(row)
    return {'schemaVersion': SCHEMA_VERSION, 'mode': 'decode_strings', 'interpretation': INTERPRETATION, 'decoders': decoders,
            'strings': strings, 'coverage': {'functionsConsidered': considered, 'candidates': len(scored), 'decodersTried': len(decoders),
                                             'callSites': sites_total, 'runs': runs, 'stringsFound': len(strings),
                                             'unresolvedArguments': unresolved_total},
            'truncation': truncation, 'limits': limits, 'limitations': list(LIMITATIONS)}
