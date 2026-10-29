"""Read-only sparse conditional constant propagation over typed native SSA.

This produces an evidence overlay. It never rewrites p-code, machine bytes,
decompiler source or a database, and does not execute target instructions.
"""
BOTTOM = object()
UNKNOWN = object()
ARITHMETIC = {'INT_ADD', 'INT_SUB', 'INT_MULT', 'INT_XOR', 'INT_AND', 'INT_OR',
              'INT_DIV', 'INT_REM', 'INT_SDIV', 'INT_SREM'}
COMPARE = {'INT_EQUAL', 'INT_NOTEQUAL', 'INT_LESS', 'INT_LESSEQUAL', 'INT_SLESS', 'INT_SLESSEQUAL'}
SIDE_EFFECTS = {'LOAD', 'STORE', 'CALL', 'CALLIND', 'CALLOTHER', 'INDIRECT', 'BRANCHIND'}


def _limit(value, default, maximum, name):
    value = default if value is None else value
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise ValueError('%s must be an integer in 1..%d' % (name, maximum))
    return value


def _width(node):
    size = node.get('size') if isinstance(node, dict) else None
    return size * 8 if isinstance(size, int) and not isinstance(size, bool) and 1 <= size <= 8 else None


def _key(node):
    if not isinstance(node, dict) or node.get('kind') == 'constant' or not _width(node):
        return None
    identity = node.get('id')
    if isinstance(identity, bool) or not isinstance(identity, int) or identity < 0:
        return None
    return identity, node.get('space'), node['size']


def _constant(node):
    width = _width(node)
    if not width or node.get('kind') != 'constant' or node.get('valueComplete') is False or node.get('offsetOnly'):
        return UNKNOWN
    value = node.get('value')
    if not isinstance(value, str) or not value.startswith('0x'):
        return UNKNOWN
    try:
        number = int(value, 16)
    except ValueError:
        return UNKNOWN
    return number if 0 <= number < 1 << width else UNKNOWN


def _known(value):
    return value is not BOTTOM and value is not UNKNOWN


def _meet(left, right):
    if left is BOTTOM:
        return right
    if right is BOTTOM:
        return left
    if left is UNKNOWN or right is UNKNOWN or left != right:
        return UNKNOWN
    return left


def _signed(value, width):
    return value - (1 << width) if value & (1 << (width - 1)) else value


class Analyzer:
    def __init__(self, graph, params, monitor=None):
        self.graph, self.monitor = graph, monitor
        self.maximum = _limit(params.get('max_steps'), 100000, 250000, 'max_steps')
        self.evidence_limit = _limit(params.get('max_evidence'), 128, 512, 'max_evidence')
        self.steps, self.exhausted = 0, False
        self.blocks = {block['id']: block for block in graph.get('blocks', [])}
        if len(self.blocks) != len(graph.get('blocks', [])):
            raise ValueError('Duplicate native SSA block identity')
        self.definitions, identities = {}, {}
        self.values, self.executable, self.reachable = {}, set(), set()
        for block in self.blocks.values():
            for operation in block.get('instructions', []):
                key = _key(operation.get('output'))
                if key is not None:
                    if key in self.definitions:
                        raise ValueError('Duplicate native SSA definition identity')
                    self.definitions[key] = operation
                for node in operation.get('inputs', []) + [operation.get('output')]:
                    node_key = _key(node)
                    if node_key is not None:
                        if node_key[0] in identities and identities[node_key[0]] != node_key:
                            raise ValueError('Native SSA identity has conflicting width or address space')
                        identities[node_key[0]] = node_key
        self.entry = graph.get('entryBlock')
        if self.entry not in self.blocks:
            raise ValueError('Native SSA entry block is unavailable')
        self.reachable.add(self.entry)

    def tick(self):
        if self.steps >= self.maximum:
            self.exhausted = True
            return False
        self.steps += 1
        if self.monitor is not None and self.steps % 128 == 0:
            self.monitor.checkCancelled()
        return True

    def value(self, node, overrides=None):
        if not isinstance(node, dict):
            return UNKNOWN
        if node.get('kind') == 'constant':
            return _constant(node)
        key = _key(node)
        if key is None:
            return UNKNOWN
        if overrides is not None and key in overrides:
            return overrides[key]
        return self.values.get(key, BOTTOM if key in self.definitions else UNKNOWN)

    def alias(self, node, depth=0):
        key = _key(node)
        if key is None or depth >= 12:
            return key
        op = self.definitions.get(key)
        if op and op.get('mnemonic') == 'COPY' and len(op.get('inputs', [])) == 1 and _width(op['inputs'][0]) == _width(node):
            return self.alias(op['inputs'][0], depth + 1)
        return key

    def same(self, left, right):
        return _width(left) == _width(right) and self.alias(left) is not None and self.alias(left) == self.alias(right)

    def slice_value(self, node, shift, width, overrides=None, depth=0):
        """Read a proven bit slice without requiring unknown adjacent bits."""
        if depth >= 24 or not self.tick() or not _width(node) or shift < 0 or shift + width > _width(node):
            return UNKNOWN
        value = self.value(node, overrides)
        if _known(value): return (value >> shift) & ((1 << width) - 1)
        operation = self.definitions.get(_key(node))
        if not operation or operation.get('inputsTruncated') or operation.get('outputOmitted'): return value
        args, opcode = operation.get('inputs', []), operation.get('mnemonic')
        if opcode == 'COPY' and len(args) == 1 and _width(args[0]) == _width(node):
            return self.slice_value(args[0], shift, width, overrides, depth + 1)
        if opcode == 'SUBPIECE' and len(args) == 2 and _known(_constant(args[1])):
            return self.slice_value(args[0], shift + _constant(args[1]) * 8, width, overrides, depth + 1)
        if opcode in ('INT_ZEXT', 'INT_SEXT') and len(args) == 1 and _width(args[0]) and _width(args[0]) < _width(node):
            if shift + width <= _width(args[0]): return self.slice_value(args[0], shift, width, overrides, depth + 1)
            if opcode == 'INT_ZEXT' and shift >= _width(args[0]): return 0
        if opcode == 'PIECE' and len(args) == 2 and all(_width(arg) for arg in args) and _width(args[0]) + _width(args[1]) == _width(node):
            low_width = _width(args[1])
            if shift + width <= low_width: return self.slice_value(args[1], shift, width, overrides, depth + 1)
            if shift >= low_width: return self.slice_value(args[0], shift - low_width, width, overrides, depth + 1)
            low_bits = low_width - shift
            low = self.slice_value(args[1], shift, low_bits, overrides, depth + 1)
            high = self.slice_value(args[0], 0, width - low_bits, overrides, depth + 1)
            if _known(low) and _known(high): return low | (high << low_bits)
            return BOTTOM if low is BOTTOM or high is BOTTOM else UNKNOWN
        return value

    def low_bit_source(self, node):
        # These typed operations preserve bit zero, including signed extension
        # and low-half extraction around x86's double-width multiply.
        for _ in range(12):
            operation = self.definitions.get(_key(node))
            if not operation or operation.get('inputsTruncated') or operation.get('outputOmitted'): break
            inputs, opcode = operation.get('inputs', []), operation.get('mnemonic')
            if len(inputs) == 1 and opcode == 'COPY' and _width(node) == _width(inputs[0]):
                node = inputs[0]
            elif len(inputs) == 1 and opcode in ('INT_ZEXT', 'INT_SEXT') and _width(inputs[0]) and _width(node) > _width(inputs[0]):
                node = inputs[0]
            elif len(inputs) == 2 and opcode == 'SUBPIECE' and _constant(inputs[1]) == 0 and _width(inputs[0]) and _width(node) <= _width(inputs[0]):
                node = inputs[0]
            elif len(inputs) == 2 and opcode == 'PIECE' and all(_width(item) for item in inputs) and sum(_width(item) for item in inputs) == _width(node):
                node = inputs[1]
            else: break
        return node

    def even_product(self, node):
        node = self.low_bit_source(node)
        product = self.definitions.get(_key(node))
        if not product or product.get('mnemonic') != 'INT_MULT' or len(product.get('inputs', [])) != 2:
            return False
        width = _width(node)
        if not width or any(_width(item) != width for item in product['inputs']):
            return False
        for base, adjacent in (product['inputs'], list(reversed(product['inputs']))):
            base, adjacent = self.low_bit_source(base), self.low_bit_source(adjacent)
            step = self.definitions.get(_key(adjacent))
            if not step or step.get('mnemonic') not in ('INT_ADD', 'INT_SUB') or len(step.get('inputs', [])) != 2:
                continue
            a, b = step['inputs']
            step_width = _width(adjacent)
            if _width(a) != step_width or _width(b) != step_width:
                continue
            delta = _constant(b)
            if self.same(base, self.low_bit_source(a)) and _known(delta) and delta in (1, (1 << step_width) - 1):
                return True
            if step['mnemonic'] == 'INT_ADD' and self.same(base, self.low_bit_source(b)) and _constant(a) in (1, (1 << step_width) - 1):
                return True
        return False

    def evaluate(self, operation, overrides=None):
        if not self.tick():
            return UNKNOWN, 'work-budget'
        args, output = operation.get('inputs', []), operation.get('output')
        opcode, width = operation.get('mnemonic'), _width(output)
        if operation.get('inputsTruncated') or operation.get('outputOmitted'):
            return UNKNOWN, 'incomplete-operands'
        if not width:
            return UNKNOWN, 'unsupported-output-width'
        if opcode in SIDE_EFFECTS:
            return UNKNOWN, 'memory-call-or-indirect-effect'
        values = [self.value(node, overrides) for node in args]
        widths = [_width(node) for node in args]
        mask = (1 << width) - 1
        if opcode == 'COPY' and len(args) == 1 and widths[0] == width:
            return values[0], 'copy'
        if opcode in ('INT_ZEXT', 'INT_SEXT') and len(args) == 1 and widths[0] and widths[0] < width:
            if not _known(values[0]):
                return values[0], 'extension-unknown'
            return (values[0] if opcode == 'INT_ZEXT' else _signed(values[0], widths[0])) & mask, 'integer-extension'
        if opcode == 'PIECE' and len(args) == 2 and all(widths) and sum(widths) == width:
            if all(_known(v) for v in values):
                return (values[0] << widths[1]) | values[1], 'piece'
        if opcode == 'SUBPIECE' and len(args) == 2 and widths[0] and width <= widths[0] and _known(values[1]):
            shift = values[1] * 8
            if shift + width <= widths[0]:
                return self.slice_value(args[0], shift, width, overrides), 'exact-bit-slice'
            return UNKNOWN, 'subpiece-out-of-range-or-unknown'
        if opcode in ('INT_NEGATE', 'INT_2COMP', 'BOOL_NEGATE', 'POPCOUNT', 'LZCOUNT') and len(args) == 1 and widths[0]:
            if not _known(values[0]):
                return values[0], 'unary-unknown'
            if opcode in ('INT_NEGATE', 'INT_2COMP') and widths[0] != width:
                return UNKNOWN, 'width-mismatch'
            if opcode == 'BOOL_NEGATE' and (width != 8 or widths[0] != 8 or values[0] not in (0, 1)):
                return UNKNOWN, 'non-boolean-input'
            result = (~values[0] if opcode == 'INT_NEGATE' else -values[0] if opcode == 'INT_2COMP' else
                      int(not values[0]) if opcode == 'BOOL_NEGATE' else values[0].bit_count() if opcode == 'POPCOUNT' else widths[0] - values[0].bit_length())
            return result & mask, 'integer-unary'
        if len(args) != 2 or not all(widths):
            return UNKNOWN, 'unsupported-opcode-or-arity'
        if opcode in ARITHMETIC and (widths[0] != width or widths[1] != width):
            return UNKNOWN, 'width-mismatch'
        if opcode in COMPARE and (widths[0] != widths[1] or width != 8):
            return UNKNOWN, 'comparison-width-mismatch'
        if self.same(args[0], args[1]):
            if opcode in ('INT_XOR', 'INT_SUB', 'INT_NOTEQUAL', 'INT_LESS', 'INT_SLESS'):
                return 0, 'same-ssa-identity'
            if opcode in ('INT_EQUAL', 'INT_LESSEQUAL', 'INT_SLESSEQUAL'):
                return 1, 'same-ssa-identity'
            if opcode in ('INT_AND', 'INT_OR'):
                return values[0], 'same-ssa-copy'
        if opcode in ('INT_AND', 'INT_MULT') and 0 in values:
            return 0, 'absorbing-zero'
        if opcode == 'INT_OR' and mask in values:
            return mask, 'absorbing-all-bits'
        if opcode == 'INT_AND':
            for number, node in zip(values, reversed(args)):
                if number == 1 and self.even_product(node):
                    return 0, 'consecutive-integer-product-is-even'
        if BOTTOM in values:
            return BOTTOM, 'definition-not-yet-executable'
        if not all(_known(v) for v in values):
            return UNKNOWN, 'unknown-input'
        a, b = values
        if opcode == 'INT_ADD': result = a + b
        elif opcode == 'INT_SUB': result = a - b
        elif opcode == 'INT_MULT': result = a * b
        elif opcode == 'INT_XOR': result = a ^ b
        elif opcode == 'INT_AND': result = a & b
        elif opcode == 'INT_OR': result = a | b
        elif opcode in ('INT_LEFT', 'INT_RIGHT', 'INT_SRIGHT'):
            if width != widths[0] or b >= width:
                return UNKNOWN, 'overshift-or-width-mismatch'
            result = a << b if opcode == 'INT_LEFT' else a >> b if opcode == 'INT_RIGHT' else _signed(a, width) >> b
        elif opcode in ('INT_DIV', 'INT_REM', 'INT_SDIV', 'INT_SREM'):
            if b == 0:
                return UNKNOWN, 'division-by-zero'
            if opcode.startswith('INT_S'):
                a, b = _signed(a, width), _signed(b, width)
                if a == -(1 << (width - 1)) and b == -1:
                    return UNKNOWN, 'signed-division-overflow'
                quotient = (abs(a) // abs(b)) * (-1 if (a < 0) != (b < 0) else 1)
                result = quotient if opcode == 'INT_SDIV' else a - quotient * b
            else:
                result = a // b if opcode == 'INT_DIV' else a % b
        elif opcode in COMPARE:
            if opcode in ('INT_SLESS', 'INT_SLESSEQUAL'):
                a, b = _signed(a, widths[0]), _signed(b, widths[1])
            result = int(a == b if opcode == 'INT_EQUAL' else a != b if opcode == 'INT_NOTEQUAL' else
                         a < b if opcode in ('INT_LESS', 'INT_SLESS') else a <= b)
        elif opcode in ('BOOL_AND', 'BOOL_OR', 'BOOL_XOR') and width == 8 and widths == [8, 8]:
            if a not in (0, 1) or b not in (0, 1):
                return UNKNOWN, 'non-boolean-input'
            result = int(bool(a) and bool(b)) if opcode == 'BOOL_AND' else int(bool(a) or bool(b)) if opcode == 'BOOL_OR' else int(bool(a) != bool(b))
        elif opcode in ('INT_CARRY', 'INT_SCARRY', 'INT_SBORROW') and width == 8 and widths[0] == widths[1]:
            bits = widths[0]
            signed = _signed(a, bits) + _signed(b, bits) if opcode == 'INT_SCARRY' else _signed(a, bits) - _signed(b, bits)
            result = int(a + b >= 1 << bits) if opcode == 'INT_CARRY' else int(not -(1 << (bits - 1)) <= signed < 1 << (bits - 1))
        else:
            return UNKNOWN, 'unsupported-opcode'
        return result & mask, 'constant-bitvector-evaluation'

    def phi(self, block, operation, overrides=None, predecessor=None):
        if not self.tick(): return UNKNOWN
        inputs, preds = operation.get('inputs', []), block.get('preds', [])
        if block.get('edgesTruncated') or operation.get('inputsTruncated') or len(inputs) != len(preds) or len(set(preds)) != len(preds) or not _width(operation.get('output')):
            return UNKNOWN
        value = BOTTOM
        for node, previous in zip(inputs, preds):
            if _width(node) != _width(operation['output']): return UNKNOWN
            if (previous, block['id']) in self.executable and (predecessor is None or predecessor == previous):
                value = _meet(value, self.value(node, overrides))
        return value

    def destinations(self, block, overrides=None):
        operations, successors = block.get('instructions', []), block.get('succs', [])
        if not operations or block.get('truncated') or block.get('edgesTruncated'):
            return successors, None
        last = operations[-1]
        if last.get('mnemonic') != 'CBRANCH' or len(last.get('inputs', [])) != 2 or last.get('inputsTruncated'):
            return successors, None
        condition = self.value(last['inputs'][1], overrides)
        true, false = block.get('trueSuccessor'), block.get('falseSuccessor')
        if true not in successors or false not in successors or len(successors) != 2:
            return successors, None
        if condition is BOTTOM:
            return [], None
        if _known(condition):
            destination = true if condition else false
            return [destination], {'block': block['id'], 'ea': last.get('ea'), 'instruction': last.get('index'),
                                  'condition': hex(condition), 'taken': bool(condition), 'destination': destination,
                                  'discarded': [item for item in successors if item != destination]}
        return successors, None

    def propagate(self):
        changed = True
        while changed and not self.exhausted:
            changed = False
            for identity, block in self.blocks.items():
                if identity not in self.reachable: continue
                for operation in block.get('instructions', []):
                    key = _key(operation.get('output'))
                    if key is None: continue
                    value = self.phi(block, operation) if operation.get('mnemonic') == 'MULTIEQUAL' else self.evaluate(operation)[0]
                    old = self.values.get(key, BOTTOM)
                    merged = _meet(old, value)
                    if merged is not old and merged != old:
                        self.values[key] = merged; changed = True
                    if self.exhausted: return
                for destination in self.destinations(block)[0]:
                    if destination not in self.blocks: continue
                    edge = identity, destination
                    if edge not in self.executable:
                        self.executable.add(edge); self.reachable.add(destination); changed = True
            if not changed:
                # A closed, undefined phi cycle is not proof that its branch
                # cannot execute. Widen remaining bottom values before claiming
                # any edge or block is unreachable.
                for identity in self.reachable:
                    for operation in self.blocks[identity].get('instructions', []):
                        key = _key(operation.get('output'))
                        if key is not None and self.values.get(key, BOTTOM) is BOTTOM:
                            self.values[key] = UNKNOWN
                            changed = True

    def dispatcher_routes(self):
        routes = []
        self.route_evidence_truncated = False
        for identity, block in self.blocks.items():
            if identity not in self.reachable or not any(op.get('mnemonic') == 'MULTIEQUAL' for op in block.get('instructions', [])):
                continue
            for predecessor in dict.fromkeys(block.get('preds', [])):
                if (predecessor, identity) not in self.executable: continue
                current, previous, overrides, path, assignments = identity, predecessor, {}, [], []
                assignments_truncated = False
                for _ in range(16):
                    candidate = self.blocks[current]
                    operations = candidate.get('instructions', [])
                    if not operations or operations[-1].get('mnemonic') != 'CBRANCH' or candidate.get('truncated') or candidate.get('edgesTruncated') or any(op.get('mnemonic') in SIDE_EFFECTS for op in operations): break
                    incoming_values = dict(overrides)
                    for operation in operations:
                        key = _key(operation.get('output'))
                        if key is None: continue
                        is_phi = operation.get('mnemonic') == 'MULTIEQUAL'
                        value = self.phi(candidate, operation, incoming_values, previous) if is_phi else self.evaluate(operation, overrides)[0]
                        overrides[key] = value
                        if is_phi and _known(value):
                            if len(assignments) < 8:
                                assignments.append({'ssa': key[0], 'width': key[2] * 8, 'value': hex(value)})
                            else: assignments_truncated = True
                    selected, decision = self.destinations(candidate, overrides)
                    if self.exhausted or not decision: break
                    path.append({'block': current, 'destination': selected[0], 'condition': decision['condition']})
                    previous, current = current, selected[0]
                    if current not in self.blocks or any(item['block'] == current for item in path): break
                if path and assignments:
                    next_operations = self.blocks.get(current, {}).get('instructions', [])
                    path_truncated = bool(len(path) >= 16 and next_operations and next_operations[-1].get('mnemonic') == 'CBRANCH' and not any(item['block'] == current for item in path))
                    self.route_evidence_truncated |= assignments_truncated or path_truncated
                    if len(routes) >= self.evidence_limit:
                        self.route_evidence_truncated = True
                        return routes
                    routes.append({'predecessor': predecessor, 'dispatcher': identity, 'destination': current,
                                   'path': path, 'stateEvidence': assignments,
                                   'stateEvidenceTruncated': assignments_truncated, 'pathTruncated': path_truncated,
                                   'meaning': 'conditional route for this executable incoming edge; no blocks or assignments are removed'})
                if self.exhausted: return routes
        return routes

    def run(self):
        self.propagate()
        constants, simplifications, decisions, unresolved = [], [], [], []
        truncated_evidence = False
        for identity, block in self.blocks.items():
            if identity not in self.reachable: continue
            decision = self.destinations(block)[1]
            if decision:
                if len(decisions) < self.evidence_limit: decisions.append(decision)
                else: truncated_evidence = True
            for operation in block.get('instructions', []):
                key = _key(operation.get('output'))
                value = self.values.get(key, UNKNOWN)
                if key is not None and _known(value):
                    item = {'block': identity, 'ea': operation.get('ea'), 'instruction': operation.get('index'),
                            'opcode': operation.get('mnemonic'), 'ssa': key[0], 'space': key[1], 'width': key[2] * 8, 'value': hex(value)}
                    if len(constants) < self.evidence_limit: constants.append(item)
                    else: truncated_evidence = True
                    if operation.get('mnemonic') != 'MULTIEQUAL' and not self.exhausted:
                        _, rule = self.evaluate(operation)
                        if len(simplifications) < self.evidence_limit: simplifications.append({**item, 'rule': rule, 'replacement': {'opcode': 'COPY', 'constant': hex(value)}})
                elif key is not None or operation.get('mnemonic') in SIDE_EFFECTS or (operation.get('mnemonic') == 'CBRANCH' and not decision):
                    reason = 'memory-call-or-indirect-effect' if operation.get('mnemonic') in SIDE_EFFECTS else 'unknown-or-unsupported-input'
                    if len(unresolved) < self.evidence_limit:
                        unresolved.append({'block': identity, 'ea': operation.get('ea'), 'opcode': operation.get('mnemonic'), 'reason': reason})
                    else: truncated_evidence = True
        routes = self.dispatcher_routes() if not self.exhausted else []
        truncated_evidence |= getattr(self, 'route_evidence_truncated', False)
        from deobfuscation_symbolic import analyze_local
        local = analyze_local(self, _key, _width, _constant, _known)
        truncated_evidence |= local['localEvidenceTruncated']
        indirect = any(op.get('mnemonic') == 'BRANCHIND' for identity in self.reachable for op in self.blocks[identity].get('instructions', []))
        partial = bool(self.graph.get('partial') or self.graph.get('truncated') or self.exhausted or indirect)
        # Provisional values/edges from an unfinished fixpoint are never published
        # as proofs. Existing native partial graphs still expose the reason only.
        if partial:
            constants, simplifications, decisions, routes = [], [], [], []
        return {'algorithm': 'sccp-bitvector-v1', 'representation': 'native HighFunction SSA evidence overlay',
                'constants': constants, 'simplifications': simplifications, 'branchDecisions': decisions,
                'executableEdges': [{'from': a, 'to': b} for a, b in sorted(self.executable)] if not partial else [],
                'unreachableBlocks': sorted(set(self.blocks) - self.reachable) if not partial else [],
                'dispatcherRoutes': routes, 'unresolved': unresolved, 'partial': partial, 'evidenceTruncated': truncated_evidence,
                'controlFlowIncomplete': indirect,
                **local,
                'budget': {'steps': self.steps, 'maxSteps': self.maximum, 'exhausted': self.exhausted, 'maxEvidence': self.evidence_limit},
                'rewritten': False, 'idb_modified': False, 'executed': False,
                'limitations': ['No memory/call models, SMT solving, indirect-target proof or universal deobfuscation.',
                                'Only exact 1..64-bit integer operations are folded; division faults and overshifts remain unknown.',
                                'Dispatcher routes are incoming-edge-conditioned evidence, not a rewritten machine CFG.',
                                'Native lifting and the selected function CFG remain assumptions; no runtime equivalence claim.']}


def analyze_deobfuscation(graph, params=None, monitor=None):
    return Analyzer(graph, params or {}, monitor).run()
