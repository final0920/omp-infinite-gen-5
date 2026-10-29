"""Bounded local bitwise equivalence and indirect-target dependency evidence.

No trace execution, target resolution, memory model, or code rewriting. Every
input leaf remains an independent typed SSA value, including LOAD/phi results.
"""
BITWISE = {'COPY', 'INT_NEGATE', 'INT_AND', 'INT_OR', 'INT_XOR'}


def analyze_local(analyzer, key_of, width_of, constant_of, known):
    expressions, transfers = [], []
    truncated = False
    locations = {key_of(op.get('output')): (block['id'], op)
                 for block in analyzer.blocks.values() for op in block.get('instructions', [])
                 if key_of(op.get('output')) is not None}

    def normalized(node):
        # Exact native x86 register assembly/extraction. Do not identify values
        # by physical register offsets; repeated slices share the source SSA ID.
        for _ in range(12):
            if not analyzer.tick(): return None
            operation = analyzer.definitions.get(key_of(node))
            if not operation or operation.get('inputsTruncated') or operation.get('outputOmitted'): return node
            code, args = operation.get('mnemonic'), operation.get('inputs', [])
            if code == 'COPY' and len(args) == 1 and width_of(args[0]) == width_of(node):
                node = args[0]
                continue
            if code == 'SUBPIECE' and len(args) == 2 and width_of(args[0]):
                shift = constant_of(args[1])
                if not known(shift) or shift * 8 + width_of(node) > width_of(args[0]): return node
                source = analyzer.definitions.get(key_of(args[0]))
                if source and not source.get('inputsTruncated') and not source.get('outputOmitted'):
                    parts = source.get('inputs', [])
                    if source.get('mnemonic') == 'PIECE' and len(parts) == 2 and all(width_of(p) for p in parts) and sum(width_of(p) for p in parts) == width_of(args[0]):
                        if shift == 0 and width_of(node) == width_of(parts[1]): node = parts[1]; continue
                        if shift * 8 == width_of(parts[1]) and width_of(node) == width_of(parts[0]): node = parts[0]; continue
                    if source.get('mnemonic') in ('INT_ZEXT', 'INT_SEXT') and len(parts) == 1 and shift == 0 and width_of(node) == width_of(parts[0]) and width_of(parts[0]) < width_of(args[0]):
                        node = parts[0]
                        continue
            return node
        return None

    def semantic_key(node):
        node = normalized(node)
        if node is None: return None
        key = key_of(node)
        operation = analyzer.definitions.get(key)
        args = operation.get('inputs', []) if operation else []
        if operation and operation.get('mnemonic') == 'SUBPIECE' and len(args) == 2 and not operation.get('inputsTruncated'):
            shift = constant_of(args[1])
            if known(shift) and width_of(args[0]) and shift * 8 + width_of(node) <= width_of(args[0]) and key_of(args[0]) is not None:
                return ('slice', key_of(args[0]), shift, node['size'])
        return ('ssa', key) if key is not None else None

    def linear_mba(root):
        width = width_of(root)
        def alias(node):
            return normalized(node)

        def definition(node, opcode):
            node = alias(node)
            if node is None: return None
            operation = analyzer.definitions.get(key_of(node))
            if not operation or operation.get('mnemonic') != opcode or operation.get('inputsTruncated') or operation.get('outputOmitted'): return None
            args = operation.get('inputs', [])
            return args if len(args) == 2 and width_of(operation.get('output')) == width and all(width_of(arg) == width for arg in args) else None

        def same_pair(left, right):
            if left is None or right is None: return False
            a, b = [alias(n) for n in left], [alias(n) for n in right]
            return (all(n is not None and key_of(n) is not None for n in a + b)
                    and sorted((semantic_key(n) for n in a), key=str) == sorted((semantic_key(n) for n in b), key=str))

        def double_and(node):
            args = definition(node, 'INT_MULT')
            if args:
                for value, inner in (args, list(reversed(args))):
                    if constant_of(value) == 2:
                        return definition(inner, 'INT_AND')
            return None

        operation = analyzer.definitions.get(key_of(root))
        args = operation.get('inputs', []) if operation else []
        opcode = operation.get('mnemonic') if operation else None
        if len(args) != 2 or any(width_of(arg) != width for arg in args) or operation.get('inputsTruncated') or operation.get('outputOmitted'): return None
        candidates = [args, list(reversed(args))] if opcode == 'INT_ADD' else [args]
        for left, right in candidates:
            for outer, first, second, result, count in (
                    ('INT_ADD', 'INT_XOR', 'double-and', 'INT_ADD', 4),
                    ('INT_SUB', 'INT_ADD', 'double-and', 'INT_XOR', 4),
                    ('INT_ADD', 'INT_OR', 'INT_AND', 'INT_ADD', 3),
                    ('INT_SUB', 'INT_OR', 'INT_AND', 'INT_XOR', 3),
                    ('INT_ADD', 'INT_XOR', 'INT_AND', 'INT_OR', 3)):
                if opcode != outer: continue
                a = definition(left, first)
                b = double_and(right) if second == 'double-and' else definition(right, second)
                if same_pair(a, b):
                    return {'width': width, 'replacement': {'opcode': result, 'inputs': a},
                            'operationsBefore': count, 'operationsAfter': 1,
                            'proof': 'modular-bitvector-algebra-identity', 'rule': outer + '-' + first + '-' + second,
                            'scope': 'local equal-width SSA algebra modulo 2**width; no whole-function or path equivalence claim'}
        return None

    def boolean_expression(root):
        width = width_of(root)
        leaves, nodes, seen, visiting = {}, {}, set(), set()
        cut = False

        def build(node, depth=0):
            nonlocal cut
            if not analyzer.tick(): return None
            if width_of(node) != width: return None
            node = normalized(node)
            if node is None: return None
            if node.get('kind') == 'constant':
                value = constant_of(node)
                if not known(value) or value not in (0, (1 << width) - 1): return None
                return ('constant', int(value != 0))
            key = key_of(node)
            if key is None: return None
            if key in nodes: return nodes[key]
            if depth >= 12 or len(seen) >= 32:
                cut = True
                return None
            seen.add(key)
            operation = analyzer.definitions.get(key)
            opcode = operation.get('mnemonic') if operation else None
            args = operation.get('inputs', []) if operation else []
            if key in visiting: return None
            # Unsupported definitions are opaque independent values, never
            # substituted with their input or a physical memory/register slot.
            if opcode not in BITWISE:
                leaf_key = semantic_key(node)
                if leaf_key is None: return None
                if len(leaves) >= 6 and leaf_key not in leaves:
                    cut = True
                    return None
                leaves[leaf_key] = node
                result = ('leaf', leaf_key)
            else:
                expected = 1 if opcode in ('COPY', 'INT_NEGATE') else 2
                if len(args) != expected or operation.get('inputsTruncated') or operation.get('outputOmitted'): return None
                visiting.add(key)
                children = [build(arg, depth + 1) for arg in args]
                visiting.remove(key)
                if any(arg is None for arg in children): return None
                result = children[0] if opcode == 'COPY' else (opcode, *children)
            nodes[key] = result
            return result

        tree = build(root)
        if tree is None or not leaves: return None, cut
        ordered = sorted(leaves, key=str)
        rows = 1 << len(ordered)
        table_mask = (1 << rows) - 1
        variables = {key: sum(((row >> index) & 1) << row for row in range(rows)) for index, key in enumerate(ordered)}

        def evaluate(expr):
            if not analyzer.tick(): return None
            code = expr[0]
            if code == 'constant': return table_mask if expr[1] else 0
            if code == 'leaf': return variables[expr[1]]
            args = [evaluate(arg) for arg in expr[1:]]
            if any(arg is None for arg in args): return None
            if code == 'INT_NEGATE': return args[0] ^ table_mask
            if code == 'INT_AND': return args[0] & args[1]
            if code == 'INT_OR': return args[0] | args[1]
            return args[0] ^ args[1]

        table = evaluate(tree)
        if table is None: return None, cut
        # Only replace with strictly fewer non-COPY typed operations.
        cost = sum(analyzer.definitions.get(key, {}).get('mnemonic') in BITWISE - {'COPY'} for key in nodes)
        replacement, replacement_cost = None, 0
        if table in (0, table_mask):
            replacement = {'opcode': 'COPY', 'constant': hex(0 if table == 0 else (1 << width) - 1)}
        else:
            for key in ordered:
                if table == variables[key]: replacement = {'opcode': 'COPY', 'inputs': [leaves[key]]}; break
                if table == variables[key] ^ table_mask:
                    replacement, replacement_cost = {'opcode': 'INT_NEGATE', 'inputs': [leaves[key]]}, 1
                    break
            if replacement is None and cost > 1:
                for i, left in enumerate(ordered):
                    for right in ordered[i + 1:]:
                        if not analyzer.tick(): return None, cut
                        for opcode, result in (('INT_AND', variables[left] & variables[right]),
                                               ('INT_OR', variables[left] | variables[right]),
                                               ('INT_XOR', variables[left] ^ variables[right])):
                            if result == table:
                                replacement, replacement_cost = {'opcode': opcode, 'inputs': [leaves[left], leaves[right]]}, 1
                                break
                        if replacement is not None: break
                    if replacement is not None: break
        if replacement is None or replacement_cost >= cost: return None, cut
        return {'width': width, 'replacement': replacement, 'operationsBefore': cost,
                'operationsAfter': replacement_cost, 'proof': 'exhaustive-single-bit-truth-table',
                'truthTableRows': rows, 'truthTable': hex(table), 'variables': [leaves[key] for key in ordered],
                'scope': 'local typed SSA expression; does not prove reachability, memory stability, or whole-function equivalence'}, cut

    for block in analyzer.blocks.values():
        for op in block.get('instructions', []):
            if not analyzer.tick(): break
            opcode = op.get('mnemonic')
            if opcode in BITWISE - {'COPY'} and width_of(op.get('output')):
                proof, cut = boolean_expression(op['output'])
                truncated |= cut
                if proof:
                    if len(expressions) < analyzer.evidence_limit:
                        expressions.append({'block': block['id'], 'ea': op.get('ea'), 'instruction': op.get('index'),
                                            'ssa': key_of(op['output'])[0], **proof})
                    else: truncated = True
            if opcode in ('INT_ADD', 'INT_SUB') and width_of(op.get('output')):
                proof = linear_mba(op['output'])
                if proof:
                    if len(expressions) < analyzer.evidence_limit:
                        expressions.append({'block': block['id'], 'ea': op.get('ea'), 'instruction': op.get('index'),
                                            'ssa': key_of(op['output'])[0], **proof})
                    else: truncated = True
            if opcode not in ('BRANCHIND', 'CALLIND') or not op.get('inputs'): continue
            if len(transfers) >= analyzer.evidence_limit:
                truncated = True
                continue
            pending, seen, dependencies, leaves = [op['inputs'][0]], set(), [], []
            incomplete = bool(op.get('inputsTruncated'))
            while pending and len(dependencies) + len(leaves) < 32:
                if not analyzer.tick(): break
                node = pending.pop()
                key = key_of(node)
                if key is None or key in seen: continue
                seen.add(key)
                definition = locations.get(key)
                if not definition:
                    leaves.append(node)
                    continue
                location, producer = definition
                dependencies.append({'ssa': key[0], 'block': location, 'ea': producer.get('ea'),
                                     'opcode': producer.get('mnemonic'), 'inputs': producer.get('inputs', [])})
                incomplete |= bool(producer.get('inputsTruncated') or producer.get('outputOmitted'))
                pending.extend(reversed(producer.get('inputs', [])))
            incomplete |= bool(pending or analyzer.exhausted or analyzer.graph.get('partial') or analyzer.graph.get('truncated'))
            truncated |= bool(pending)
            transfers.append({'block': block['id'], 'ea': op.get('ea'), 'instruction': op.get('index'), 'opcode': opcode,
                              'target': op['inputs'][0], 'dependencies': dependencies, 'externalInputs': leaves,
                              'slicePartial': incomplete, 'targetsResolved': False,
                              'meaning': 'backward SSA dependencies of the indirect target; LOAD addresses are expressions, not recovered handler tables or VM bytecode'})
        if analyzer.exhausted: break
    complete = not (analyzer.exhausted or analyzer.graph.get('partial') or analyzer.graph.get('truncated'))
    if not complete: expressions = []
    return {'expressionSimplifications': expressions, 'indirectTransfers': transfers,
            'localExpressionsComplete': complete, 'localEvidenceTruncated': truncated,
            'localExpressionLimits': {'maxNodes': 32, 'maxDepth': 12, 'maxVariables': 6, 'maxTruthTableRows': 64, 'maxDependencyNodes': 32}}
