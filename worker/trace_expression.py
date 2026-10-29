"""Bounded structural bit-vector simplification with local SMT certificates.

Every accepted rewrite is independently proved; parent rebuilding uses equality
congruence. No sample name, reference source or observed input value is used.
"""
import json


def normalize_expression(value, build_ast, prove, check_budget, prove_instance=None):
    steps, attempts = [], []
    remaining = [512]

    def same(left, right):
        return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)

    def unary(op, child):
        return {'op': op, 'bits': child['bits'], 'args': [child]}

    def invert(child):
        return child['args'][0] if child['op'] == 'not' else unary('not', child)

    def low_projection(node, bits):
        if node.get('bits', 0) < bits: return None
        if node['op'] == 'input': return {**node, 'bits': bits}
        if node['op'] == 'constant': return {**node, 'bits': bits, 'value': hex(int(node['value'], 16) & ((1 << bits) - 1))}
        if node['op'] not in ('add', 'sub', 'mul', 'and', 'or', 'xor', 'not'): return None
        children = [low_projection(child, bits) for child in node['args']]
        if any(child is None for child in children): return None
        return {**node, 'bits': bits, 'args': children}

    def candidate(node, depth):
        op, args, bits = node['op'], node.get('args', []), node.get('bits')
        if op == 'or' and len(args) == 2:
            for left, right in (args, args[::-1]):
                if left['op'] != 'shl' or right['op'] != 'lshr': continue
                a, n = left['args']; b, inverse = right['args']
                if any(item.get('bits') != bits for item in (left, right, a, b, n, inverse)): continue
                if n['op'] != 'constant' or inverse['op'] != 'constant' or not same(a, b): continue
                count = int(n['value'], 16)
                if 0 < count < bits and int(inverse['value'], 16) == bits - count:
                    return 'complementary-shift-rotation', {'op': 'rol', 'bits': bits, 'args': [a, n]}, {'subject': a}
        if op in ('rol', 'ror') and len(args) == 2:
            inner, count = args
            if inner['op'] == op and count['op'] == 'constant' and inner['args'][1]['op'] == 'constant':
                subject, first = inner['args']
                if all(item.get('bits') == bits for item in (inner, count, subject, first)):
                    total = (int(count['value'], 16) + int(first['value'], 16)) % bits
                    return 'consecutive-constant-rotations', {'op': op, 'bits': bits,
                        'args': [subject, {'op': 'constant', 'value': hex(total), 'bits': bits}]}, {'subject': subject}
        if op == 'not' and args[0]['op'] == 'not': return 'double-complement', args[0]['args'][0]
        if op == 'not' and args[0]['op'] in ('and', 'or'):
            gate = args[0]
            # Prove this local identity before visiting newly exposed nodes.
            # Candidate construction itself never records unused child rewrites.
            children = [invert(child) for child in gate['args']]
            return 'bitvector-de-morgan', {'op': 'or' if gate['op'] == 'and' else 'and', 'bits': bits, 'args': children}
        if op == 'and' and len(args) == 2:
            for positive, negative in (args, args[::-1]):
                if positive['op'] != 'or' or negative['op'] != 'or' or len(positive['args']) != 2 or len(negative['args']) != 2: continue
                a, b = positive['args']
                inverses = [invert(a), invert(b)]
                if (same(inverses[0], negative['args'][0]) and same(inverses[1], negative['args'][1])) or (same(inverses[0], negative['args'][1]) and same(inverses[1], negative['args'][0])):
                    return 'exclusive-union', {'op': 'xor', 'bits': bits, 'args': [a, b]}
        if op == 'add' and len(args) == 2:
            for constant, product in (args, args[::-1]):
                if constant['op'] != 'constant' or product['op'] != 'mul' or len(product['args']) != 2: continue
                for multiplier, term in (product['args'], product['args'][::-1]):
                    if multiplier['op'] != 'constant' or multiplier['bits'] != bits: continue
                    mask = (1 << bits) - 1
                    c, m = int(constant['value'], 16) & mask, int(multiplier['value'], 16) & mask
                    if not m: continue
                    if m & 1: offset = c * pow(m, -1, 1 << bits) & mask
                    elif c % m == 0: offset = c // m
                    else: continue
                    return 'modular-common-factor', {'op': 'mul', 'bits': bits, 'args': [multiplier,
                        {'op': 'add', 'bits': bits, 'args': [term, {'op': 'constant', 'bits': bits, 'value': hex(offset)}]}]}
        if op == 'concat' and len(args) >= 2 and args[0]['op'] == 'constant' and int(args[0]['value'], 16) == 0:
            rest = args[1] if len(args) == 2 else {'op': 'concat', 'bits': bits - args[0]['bits'], 'args': args[1:]}
            return 'zero-prefix-extension', {'op': 'zx', 'bits': bits, 'args': [rest]}
        if op == 'concat' and len(args) == 2 and args[0]['op'] == 'extract':
            high, low = args
            base = high['args'][0]
            projected = low_projection(base, low['bits'])
            if high['low'] == low['bits'] and high['bits'] + low['bits'] == base['bits'] == bits and projected is not None and same(projected, low):
                return 'adjacent-width-projections', base
        if op == 'concat' and 2 <= len(args) <= 64:
            # Compiler/protector output may split a word into contiguous
            # slices, complementing some slices instead of emitting XOR.
            # Recover the mask from structure alone, then prove the identity.
            pieces = [part['args'][0] if part['op'] == 'not' else part for part in args]
            bases = [part['args'][0] for part in pieces if part['op'] == 'extract']
            if not bases: return None
            base = bases[0]
            if base.get('bits') != bits: return None
            offset, mask = bits, 0
            for original, part in zip(args, pieces):
                width = original.get('bits', 0)
                if not isinstance(width, int) or width <= 0 or width != part.get('bits'): return None
                offset -= width
                if offset < 0: return None
                if part['op'] == 'extract':
                    if part.get('low') != offset or not same(part['args'][0], base): return None
                elif offset != 0 or not same(low_projection(base, width), part): return None
                if original['op'] == 'not': mask |= ((1 << width) - 1) << offset
            if offset != 0: return None
            proposed = base if not mask else {'op': 'xor', 'bits': bits, 'args': [base,
                {'op': 'constant', 'bits': bits, 'value': hex(mask)}]}
            return 'contiguous-complemented-projections', proposed
        if op in ('add', 'mul', 'and', 'or', 'xor') and len(args) >= 2:
            # Same-width modular operations only. Flattening and sorting share
            # the existing work budget; no observed input/environment is folded.
            pending = list(reversed(args)); terms = []; constants = []
            while pending:
                check_budget(); remaining[0] -= 1
                if remaining[0] < 0 or len(terms) + len(constants) >= 64: return None
                term = pending.pop()
                if term.get('bits') != bits: return None
                if term['op'] == op: pending.extend(reversed(term['args']))
                elif term['op'] == 'constant': constants.append(int(term['value'], 16))
                else: terms.append(term)
            mask = (1 << bits) - 1
            identity = 1 if op == 'mul' else mask if op == 'and' else 0
            constant = identity
            functions = {'add': lambda a,b:a+b, 'mul':lambda a,b:a*b,
                'and':lambda a,b:a&b, 'or':lambda a,b:a|b, 'xor':lambda a,b:a^b}
            for item in constants: constant = functions[op](constant, item) & mask
            if constant != identity or not terms: terms.append({'op':'constant','bits':bits,'value':hex(constant)})
            terms.sort(key=lambda item: json.dumps(item, sort_keys=True))
            proposed = terms[0] if len(terms) == 1 else {'op':op,'bits':bits,'args':terms}
            if not same(node, proposed): return 'modular-associative-commutative-normal-form', proposed, None
        return None

    def visit(node, depth=0):
        check_budget()
        remaining[0] -= 1
        if remaining[0] < 0 or depth > 32 or len(attempts) >= 64: return node
        # Congruence transports already proved child equalities to this parent.
        current = dict(node)
        if 'args' in node: current['args'] = [visit(child, depth + 1) for child in node['args']]
        for key in ('then', 'else'):
            if key in node: current[key] = visit(node[key], depth + 1)
        if remaining[0] < 0 or len(attempts) >= 64: return current
        rewrite = candidate(current, depth)
        if rewrite is None: return current
        rule, proposed = rewrite[:2]
        if same(current, proposed): return current
        # Reject invalid widths or unproved/time-limited candidates. No proof
        # budget is enlarged; an unsimplified expression remains valid.
        try:
            before, after = build_ast(current), build_ast(proposed)
            if before.getBitvectorSize() != after.getBitvectorSize(): return current
        except (KeyError, TypeError, ValueError): return current
        # Deadline/query/cancellation errors must propagate, never be mistaken
        # for a harmless rejected candidate at the end of a request.
        proof = prove_instance(current, proposed, rule, rewrite[2]) if len(rewrite) > 2 and prove_instance else prove(before, after)
        attempts.append({'rule': rule, 'bits': current['bits'], 'proof': proof})
        if proof['status'] != 'unsat': return current
        steps.append({'rule': rule, 'bits': current['bits'], 'proof': proof})
        if rule == 'modular-associative-commutative-normal-form':
            # Reordering/flattening/composing literal constants introduces no
            # unvisited nonconstant child. Rewalking all proved descendants
            # needlessly spent the same node budget once per outer VM round.
            return proposed
        return visit(proposed, depth + 1)

    return visit(value), steps, attempts
