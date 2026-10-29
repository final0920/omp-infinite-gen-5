"""Internal closed GPR/data-memory path composition, not a public route.

Every template is retranslated from byte-bound, trusted-decoder raw instructions
by the strict projector with all16 GPR outputs. Its existing initial-flags ban
is essential: flags are not exported or supplied between templates. This does
not establish that caller-provided decoding matches any file; the native reader
must hold and bind the original file/decoder. No external summaries/certificates
are accepted. The prototype reports all expanded work and is not an exemption
from the public128-instruction/256-byte path limits.
"""
from __future__ import annotations
import hashlib
import json
import copy
from pcode_projection import GPRS, LIMITS as PUBLIC_LIMITS, ProjectionError, _Dag, project
import composition_memory

LIMITS = {'steps': 64, 'distinctInstructions': 128, 'logicalInstructions': 1024,
          'logicalPcodeOperations': 65536, 'memoryBytes': 1024,
          'dagNodes': 2048, 'dagReferences': 8192, 'dagDepth': 128,
          'reportBytes': 4 * 1024**2}


def require(condition, message):
    if not condition:
        raise ProjectionError('Closed composition: ' + message)


def canonical_path(instructions, check=lambda: None):
    require(type(instructions) is list and 1 <= len(instructions) <= 128, 'invalid template instruction count')
    result = []
    def variable(value):
        if value is None:
            return None
        require(type(value) is dict, 'invalid raw varnode')
        selected = {k: value[k] for k in ('kind', 'space', 'spaceId', 'offset', 'size') if k in value}
        require(all(type(v) is int or (type(v) is str and len(v) <= 64) for v in selected.values()), 'invalid raw varnode value')
        return selected
    for item in instructions:
        check()
        require(type(item) is dict, 'invalid decoded instruction')
        raw, size, ea = item.get('codeBytes'), item.get('size'), item.get('ea')
        require(type(raw) is str and type(size) is int and 1 <= size <= 15
                and len(raw) == size * 2 and all(c in '0123456789abcdefABCDEF' for c in raw), 'bound bytes required')
        require(type(ea) is str and len(ea) <= 18 and ea.startswith('0x')
                and all(c in '0123456789abcdefABCDEF' for c in ea[2:]) and len(ea) > 2, 'invalid instruction address')
        require(type(item.get('mnemonic')) is str and len(item['mnemonic']) <= 64
                and type(item.get('operands')) is str and len(item['operands']) <= 512, 'invalid instruction metadata')
        ops = item.get('pcode')
        require(type(ops) is list and len(ops) <= 128, 'invalid raw operation count')
        normalized = []
        for op in ops:
            check()
            require(type(op) is dict and type(op.get('opcode')) is str and len(op['opcode']) <= 64
                    and type(op.get('inputs')) is list and len(op['inputs']) <= 3, 'invalid raw operation')
            normalized.append({'opcode': op['opcode'], 'output': variable(op.get('output')),
                               'inputs': [variable(v) for v in op['inputs']]})
        result.append({'ea': hex(int(ea, 16)), 'size': size, 'codeBytes': raw.lower(),
                       'mnemonic': item['mnemonic'], 'operands': item['operands'], 'pcode': normalized})
    require(len({r['ea'] for r in result}) == len(result), 'a template itself must be a strict path without repeated addresses')
    return result


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')).hexdigest()


class CompositionDag(_Dag):
    """Exact constants and proven affine read-after-write relations; no observations."""
    def __init__(self, check):
        super().__init__(check)
        composition_memory.initialize(self)

    def make(self, op, args=(), bits=None, **data):
        if op == 'load_le':
            return composition_memory.normalize_load(self, args[0], args[1], bits, data.get('size'), super().make)
        nodes = [self.nodes[n] for n in args]
        if bits is not None and nodes and all(n['op'] == 'const' for n in nodes):
            values = [int(n['value'], 16) for n in nodes]
            x, y = values[0], values[1] if len(values) > 1 else None
            value = None
            if op == 'INT_ADD': value = x + y
            elif op == 'INT_SUB': value = x - y
            elif op == 'INT_MULT': value = x * y
            elif op == 'INT_AND': value = x & y
            elif op == 'INT_OR': value = x | y
            elif op == 'INT_XOR': value = x ^ y
            elif op == 'INT_EQUAL': value = int(x == y)
            elif op == 'INT_NOTEQUAL': value = int(x != y)
            elif op == 'BOOL_NEGATE': value = int(not x)
            elif op == 'BOOL_AND': value = int(bool(x) and bool(y))
            elif op == 'BOOL_OR': value = int(bool(x) or bool(y))
            elif op == 'BOOL_XOR': value = int(bool(x) != bool(y))
            elif op == 'INT_ZEXT': value = x
            elif op == 'INT_SEXT': value = x - (1 << nodes[0]['bits']) if x & (1 << (nodes[0]['bits'] - 1)) else x
            if value is not None:
                return self.const(value, bits)
        return super().make(op, args, bits, **data)


def _status_overlay_nodes(template):
    """Only generated canonical mask/boolean/placement nodes bypass folding.

    Original operand/status computations keep their ordinary optimizations.
    Overlay nodes receive application scope so constant-only subtrees cannot
    intern across exact state boundaries. No initial flag value is supplied.
    """
    nodes=template['dag']['nodes'];selected=set()
    for effect in template['opaqueEffects']:
        image=effect.get('flagImageRefinement')
        if image is None:continue
        cursor=image['valueNode']
        for _ in image['knownFlags']:
            join=nodes[cursor];require(join['op']=='INT_OR','invalid generated status join')
            placed=nodes[join['args'][1]];require(placed['op']=='INT_MULT','invalid generated status placement')
            wide=nodes[placed['args'][0]];require(wide['op']=='INT_ZEXT','invalid generated status extension')
            boolean=nodes[wide['args'][0]];require(boolean['op']=='INT_NOTEQUAL','invalid generated status boolean')
            selected.update((cursor,placed['id'],wide['id'],boolean['id']));cursor=join['args'][0]
        if image['knownFlags']:
            require(nodes[cursor]['op']=='INT_AND','invalid generated unknown mask');selected.add(cursor)
    return selected


def _compose_paths(paths, check, translation_cache, indirect_mode, *, transition_chain=False, template_mode='strict'):
    """Translate an explicit finite sequence, preserving every alternate exit.

    Pure internal prototype. Templates may repeat between steps, never within a
    step. Each is compiled afresh once per canonical raw path, not supplied by a
    caller as a trusted summary. No native/architectural/SMT/business claim.
    """
    require(type(paths) is list and 1 <= len(paths) <= LIMITS['steps'], 'step budget exceeded')
    require(callable(check), 'cancellation check required')
    require(type(indirect_mode) is str and indirect_mode in ('reject', 'guarded-target'), 'invalid indirect mode')
    require(template_mode in ('strict', 'opaque-effects', 'opaque-status') and (template_mode == 'strict' or transition_chain),
            f'{template_mode} requires an explicit transition-chain sequence')
    opaque = template_mode in ('opaque-effects','opaque-status')
    status = template_mode == 'opaque-status'
    dag = CompositionDag(check)
    templates, compiled, indexes, source_definitions = [], {}, [], {}
    logical_instructions = logical_pcode = memory_bytes = 0
    for path in paths:
        check()
        raw = canonical_path(path, check)
        logical_instructions += len(raw)
        require(logical_instructions <= LIMITS['logicalInstructions'], 'logical instruction budget exceeded')
        for row in raw:
            digest = fingerprint(row)
            require(row['ea'] not in source_definitions or source_definitions[row['ea']] == digest, 'conflicting bytes/p-code at one instruction address')
            source_definitions[row['ea']] = digest
        require(len(source_definitions) <= LIMITS['distinctInstructions'], 'distinct instruction budget exceeded')
        key = fingerprint(raw)
        if key not in compiled:
            translated = translation_cache.get(key)
            if translated is None:
                translated = project(raw, list(GPRS), check, mode=template_mode,
                                     _memory_account=dag.memory_normalization if opaque else None)
                translation_cache[key] = translated
            require(set(translated['registers']) == set(GPRS), 'all16 GPR outputs required')
            ordinal = len(templates)
            compiled[key] = (ordinal, translated)
            templates.append({'id': ordinal, 'rawSHA256': key, 'instructions': raw,
                              'statistics': translated['statistics'], 'internalElisions': translated['internalElisions'],
                              'initialFlagsSupplied': False, 'flagsExported': False})
            if opaque:
                effects=copy.deepcopy(translated['opaqueEffects']) if status else translated['opaqueEffects']
                if status:
                    for effect in effects:
                        if 'flagImageRefinement' in effect:del effect['flagImageRefinement']['valueNode']
                    templates[-1]['flagPolicies']=translated['flagPolicies']
                templates[-1].update(projectionMode=template_mode, opaqueEffects=effects,
                    liveUnknownInstructions=[{k: x[k] for k in ('instructionIndex','bits','kind','source')}
                                             for x in translated['nondeterministicInputs']])
        index, translated = compiled[key]
        indexes.append(index)
        logical_pcode += translated['statistics']['pcodeOperations']
        memory_bytes += translated['statistics']['memoryBytes']
        require(logical_pcode <= LIMITS['logicalPcodeOperations'], 'logical p-code budget exceeded')
        require(memory_bytes <= LIMITS['memoryBytes'], 'expanded memory byte budget exceeded')
    initial = {name: dag.make('input', bits=64, name=name) for name in GPRS}
    initial_memory = dag.make('initial_memory', name='M0', addressBits=64, elementBits=8)
    registers, memory = dict(initial), initial_memory
    path_guard = dag.const(1, 8)
    stores, side_exits, boundaries, layers, nondeterministic_inputs = [], [], [], [], []
    def bind(source, step, name):
        # A definitional equality, NOT a fresh independent input. Its source is
        # an explicit semantic reference counted separately from local args.
        original = dag.nodes[source]
        value = dag.make('state_binding', bits=original.get('bits'),
                         source=source, stateIndex=step + 1, name=name)
        dag.references += 1
        require(dag.references <= LIMITS['dagReferences'], 'binding reference budget exceeded')
        return value
    control = None
    for step, index in enumerate(indexes):
        check()
        if status:
            # A prior application may contain nonfolded pure flag computations
            # of constants. Reusing their old IDs bypasses the exact incoming
            # state boundary even when values coincide. Constants alone may
            # be shared; re-create every other imported expression locally.
            dag.intern={key:identity for key,identity in dag.intern.items() if dag.nodes[identity]['op']=='const'}
        template = next(value[1] for value in compiled.values() if value[0] == index)
        bindings, before_memory = dict(registers), memory
        imported = {}
        overlay_nodes=_status_overlay_nodes(template) if status else set()
        def node(identity):
            check()
            if identity in imported:
                return imported[identity]
            original = template['dag']['nodes'][identity]
            require(original['id'] == identity and all(0 <= n < identity for n in original['args']), 'invalid template DAG order')
            if original['op'] == 'input':
                require(original['bits'] == 64 and original['name'] in bindings, 'unknown template input')
                value = bindings[original['name']]
            elif original['op'] == 'initial_memory':
                value = before_memory
            elif original['op'] == 'nondeterministic':
                require(opaque, 'opaque input requires explicit template mode')
                source = next(x for x in template['nondeterministicInputs'] if x['node'] == identity)
                ordinal = source['instructionIndex']
                value = dag.make('nondeterministic', bits=64, name=f'step_{step}_opaque_{ordinal}',
                    kind=source['kind'], source=source['source'], stepIndex=step, templateIndex=index,
                    instructionIndex=ordinal)
                nondeterministic_inputs.append({**source, 'node':value, 'stepIndex':step, 'templateIndex':index})
            else:
                args = [node(n) for n in original['args']]
                data = {k: v for k, v in original.items() if k not in ('id', 'op', 'type', 'args', 'bits')}
                if identity in overlay_nodes:
                    value=_Dag.make(dag,original['op'],args,original.get('bits'),**data,statusOverlayStep=step)
                elif original['op'] == 'extract':
                    value = dag.extract(args[0], original['offset'], original['bits'])
                elif original['op'] == 'concat':
                    value = dag.concat(args)
                else:
                    value = dag.make(original['op'], args, original.get('bits'), **data)
            imported[identity] = value
            return value
        # Root traversal imports only relevant nodes, but work/access accounting
        # above includes every raw instruction and access at every application.
        for store in template['stores']:
            stores.append({'stepIndex': step, 'templateIndex': index,
                           **{k: store[k] for k in ('instructionIndex', 'pcodeIndex', 'size')},
                           **{k: node(store[k]) for k in ('address', 'value', 'beforeMemory', 'afterMemory')},
                           'guard': path_guard})
            if 'replacementPcodeIndex' in store:
                stores[-1]['replacementPcodeIndex'] = store['replacementPcodeIndex']
        flag_images=[{'instructionIndex':e['instructionIndex'],'valueNode':node(e['flagImageRefinement']['valueNode'])}
                     for e in template.get('opaqueEffects',[]) if 'flagImageRefinement' in e] if status else None
        layer_start = len(dag.nodes)
        # Stores above can already have imported nodes, so use the previous
        # layer's ending binding to delimit the entire application instead.
        if transition_chain:
            layer_start = layers[-1]['nodeEnd'] if layers else len(initial) + 2
        registers = {name: node(value) for name, value in template['registers'].items()}
        memory = node(template['currentMemory'])
        control = {k: node(v) if k in ('target', 'condition', 'taken', 'fallthrough') else v
                   for k, v in template['control'].items()}
        entry_guard = path_guard
        if transition_chain:
            registers = {name: bind(value, step, name) for name, value in registers.items()}
            memory = bind(memory, step, 'memory')
        next_ea = int(templates[indexes[step + 1]]['instructions'][0]['ea'], 16) if step + 1 < len(indexes) else None
        if next_ea is not None:
            if control['kind'] == 'conditional':
                taken, fallthrough = [int(dag.nodes[control[k]]['value'], 16) for k in ('taken', 'fallthrough')]
                require(taken != fallthrough and next_ea in (taken, fallthrough), 'conditional successor must match exactly one side')
                continued_taken = next_ea == taken
                condition = control['condition']
                inverse = dag.make('BOOL_NEGATE', [condition], 8)
                continued = condition if continued_taken else inverse
                alternate = inverse if continued_taken else condition
                side_exits.append({'stepIndex': step, 'guard': dag.make('BOOL_AND', [entry_guard, alternate], 8),
                                   'target': control['fallthrough'] if continued_taken else control['taken'],
                                   'registers': dict(registers), 'currentMemory': memory,
                                   'continuation': 'not-analyzed', 'statusFlags': 'not-exported'})
                path_guard = dag.make('BOOL_AND', [entry_guard, continued], 8)
            elif control['kind'] in ('indirect', 'return'):
                require(indirect_mode == 'guarded-target', 'intermediate indirect/return requires explicit guarded-target mode')
                destination = control['target']
                require(dag.nodes[destination].get('bits') == 64, 'indirect target must be uint64')
                selected_target = dag.const(next_ea, 64)
                selected = dag.make('INT_EQUAL', [destination, selected_target], 8)
                alternate = dag.make('BOOL_NEGATE', [selected], 8)
                side_exits.append({'stepIndex': step, 'guard': dag.make('BOOL_AND', [entry_guard, alternate], 8),
                                   'target': destination, 'controlKind': control['kind'],
                                   'selectedTarget': selected_target, 'selectionCondition': selected,
                                   'registers': dict(registers), 'currentMemory': memory,
                                   'continuation': 'not-analyzed', 'statusFlags': 'not-exported'})
                path_guard = dag.make('BOOL_AND', [entry_guard, selected], 8)
            else:
                require(control['kind'] in ('fallthrough', 'direct'), 'unsupported intermediate control')
                destination = dag.nodes[control['target']]
                require(destination['op'] == 'const' and int(destination['value'], 16) == next_ea, 'direct successor mismatch')
        if transition_chain:
            path_guard = bind(path_guard, step, 'guard')
            layers.append({'stepIndex': step, 'nodeStart': layer_start, 'nodeEnd': len(dag.nodes),
                           'inputRegisters': bindings, 'inputMemory': before_memory, 'entryGuard': entry_guard,
                           'registers': dict(registers), 'currentMemory': memory, 'pathGuard': path_guard})
            if status:layers[-1]['flagImages']=flag_images
        boundaries.append({'stepIndex': step, 'templateIndex': index, 'entryGuard': entry_guard,
                           'continuedGuard': path_guard, 'registers': dict(registers), 'currentMemory': memory,
                           'control': control})
    roots = len(initial) + len(registers) + 3 + len(stores) * 5
    roots += sum(3 + len(e['registers']) for e in side_exits)
    roots += sum(2 for e in side_exits if 'selectionCondition' in e)
    roots += sum(3 + len(b['registers']) + sum(k in b['control'] for k in ('condition', 'taken', 'fallthrough', 'target')) for b in boundaries)
    roots += sum(k in control for k in ('condition', 'taken', 'fallthrough', 'target'))
    if transition_chain:
        roots += len(layers) * 36  # two complete 16-GPR/memory/guard states
    if opaque:
        roots += len(nondeterministic_inputs)
    if status:
        roots += sum(len(layer['flagImages']) for layer in layers)
    require(dag.references + roots <= LIMITS['dagReferences'], 'DAG roots exceed reference budget')
    result = {'schema': 'ig5-internal-closed-path-composition-v1', 'status': 'translated-unverified',
        'nativeTargetExecuted': False, 'databaseModified': False, 'businessAccepted': False, 'wholeBinaryVerified': False,
        'publicToolRouteExposed': False, 'initialRegisters': initial, 'initialMemory': initial_memory,
        'registers': registers, 'currentMemory': memory, 'pathGuard': path_guard,
        'stores': stores, 'sideExits': side_exits, 'boundaries': boundaries, 'control': control,
        'templates': templates, 'steps': indexes,
        'dag': {'nodes': dag.nodes, 'references': dag.references + roots, 'depth': max(dag.depth)},
        'statistics': {'templates': len(templates), 'steps': len(paths), 'distinctInstructions': len(source_definitions),
                       'logicalInstructions': logical_instructions, 'logicalPcodeOperations': logical_pcode,
                       'expandedMemoryBytes': memory_bytes, 'dagNodes': len(dag.nodes)},
        'memoryNormalization': dict(dag.memory_normalization),
        'internalPrototypeLimits': dict(LIMITS), 'unchangedPublicProjectionLimits': dict(PUBLIC_LIMITS),
        'fitsPublicFixedPathLimits': (logical_instructions == len(source_definitions)
            and logical_instructions <= PUBLIC_LIMITS['instructions'] and memory_bytes <= PUBLIC_LIMITS['memoryBytes']),
        'scope': {'initialState': 'all16 independent free uint64 GPRs and arbitrary coherent total byte memory',
                  'validity': 'final state/control only under pathGuard; each store and side exit has its own guard',
                  'flags': 'every strict template rejects live initial flags; no inter-template flag transfer or export',
                  'memory': 'post-prior-write memory is substituted at each application; aliasing and uint64 wrap retained',
                  'code': 'fixed trusted decoder input; caller must bind source bytes/assets; no code/data-fetch coherence',
                  'evidence': 'translation only; no solver, architecture, reachability, path coverage or protected-business certificate',
                  'integration': 'internal prototype; expanded work/access budgets do not authorize a larger public project request'}}
    if indirect_mode == 'guarded-target':
        result['schema'] = 'ig5-internal-guarded-target-composition-v1'
        result['indirectMode'] = indirect_mode
        result['scope']['indirect'] = ('explicit next uint64 EA is guarded by equality to the actual target expression; '
            'the complementary exit retains post-control GPR/data-memory state and the original dynamic target; '
            'no assumption is added to registers or memory, no reachability, candidate discovery or target enumeration proof')
    if transition_chain:
        expanded_depths = []
        for item in dag.nodes:
            check()
            references = item['args'] + ([item['source']] if item['op'] == 'state_binding' else [])
            expanded_depths.append(1 + max((expanded_depths[n] for n in references), default=0))
        result.update(schema='ig5-internal-state-transition-chain-v1', representation='transition-chain', layers=layers)
        result['dag']['expandedDependencyDepth'] = max(expanded_depths)
        result['dag']['bindingCount'] = len(layers) * 18
        result['scope']['representation'] = ('state_binding is an exact equality to its earlier source, never an independent free value. '
            'All16 GPRs, coherent memory and path guard receive distinct bindings after every application. '
            'dag.depth bounds retained local expressions at128; expandedDependencyDepth follows the binding sources too '
            'and may exceed128. Default flat depth refusal is unchanged. All nodes, equality sources and state roots count toward existing budgets.')
        result['scope']['memory'] = 'Each application consumes the previous exact memory binding; unknown aliases keep LOAD. Ordered writes and wrap remain; no observed/file-memory substitution.'
    if opaque:
        result.update(schema='ig5-internal-opaque-status-transition-chain-v1' if status else 'ig5-internal-opaque-transition-chain-v1', templateMode=template_mode,
                      nondeterministicInputs=nondeterministic_inputs)
        result['statistics'].update(
            expandedAbstractedInstructions=sum(len(templates[i]['opaqueEffects']) for i in indexes),
            expandedAbstractedRawOperations=sum(sum(e['rawOperationCount'] for e in templates[i]['opaqueEffects']) for i in indexes),
            expandedReplacementOperations=sum(sum(e['replacementOperationCount'] for e in templates[i]['opaqueEffects']) for i in indexes),
            liveNondeterministicInputs=len(nondeterministic_inputs))
        result['scope']['opaqueEffects'] = ('Explicit conservative byte-bound PUSHFQ/RDTSC/canonical16-bit BSWAP models; '
            'each live unknown has a fresh application/instruction-scoped node. All raw effects including dead unknown outputs remain counted. '
            'No observations, flag-image correlations, hardware-time relations, exact undefined-GPR behavior or CPU proof. '
            'Every template still rejects other live initial/undefined/unmodeled flags and unsupported effects.')
        result['scope']['normalizationBudget'] = 'All opaque template translations and global composition share the same4096 STORE-visit counters; per-DAG caches and identities stay separate.'
        result['scope']['flags'] = 'All templates reject other live initial/undefined/unmodeled flags; the explicit PUSHFQ approximation stores an unrelated arbitrary flag image. No status flags are supplied, transferred or exported.'
        if status:
            result['scope']['opaqueEffects']='Byte-bound conservative effects with within-template defined/modeled status-bit overlays on fresh64-bit PUSHFQ inputs. Unmodeled/undefined/initial/ambient bits remain unknown; no observations or CPU proof.'
            result['scope']['flags']='Each template independently closes status dependencies. Stored flag-image data and exact memory flow cross boundaries; CPU status flags are never supplied, transferred or exported.'
            result['scope']['flagImages']='Template descriptors contain no value node; each layers[].flagImages entry names that application\'s actual STORE value. All these64-bit roots count in the original reference budget. Canonical overlay nodes carry statusOverlayStep to prevent cross-layer constant subtree sharing.'
    require(len(json.dumps(result, ensure_ascii=True, allow_nan=False).encode('utf-8')) <= LIMITS['reportBytes'], 'report byte budget exceeded')
    return result


def compose_paths(paths, check=lambda: None, *, indirect_mode='reject', representation='flat', template_mode='strict'):
    """Compose trusted raw paths; guarded-target opts into conditional dynamic edges.

    A selected dynamic edge is an equality guard, never a substituted target or
    a reachability claim. The default still rejects intermediate indirect/RET.
    """
    require(representation in ('flat', 'transition-chain'), 'invalid representation')
    return _compose_paths(paths, check, {}, indirect_mode, transition_chain=representation == 'transition-chain', template_mode=template_mode)


def compose_until_exit(prefix, body, suffix, check=lambda: None, *, indirect_mode='reject'):
    """Infer bounded repeats from exact constant closed-state branch conditions.

    prefix ends at a conditional boundary after which body may repeat. It must
    already be closed over all16 GPR/data memory (e.g. include the first body
    application when earlier dead scratch effects cannot be exported). body
    returns to the same header on one side and to the suffix on the other.
    Unknown conditions, nontermination within bounds or incompatible flags are
    refused. No observed register, memory or branch value enters this function.
    """
    require(callable(check), 'cancellation check required')
    prefix, body = canonical_path(prefix, check), canonical_path(body, check)
    require(type(suffix) is list and 1 <= len(suffix) < LIMITS['steps'], 'a bounded exit suffix is required')
    suffix = [canonical_path(path, check) for path in suffix]
    body_entry, exit_entry = int(body[0]['ea'], 16), int(suffix[0][0]['ea'], 16)
    require(body_entry != exit_entry, 'loop header and exit must differ')
    paths, cache, trace = [prefix], {}, []
    attempted_instructions = attempted_memory = 0
    while True:
        check()
        trial = _compose_paths(paths, check, cache, indirect_mode)
        attempted_instructions += trial['statistics']['logicalInstructions']
        attempted_memory += trial['statistics']['expandedMemoryBytes']
        require(attempted_instructions <= 65536 and attempted_memory <= 65536, 'repeat inference work budget exceeded')
        control = trial['control']
        require(control['kind'] == 'conditional', 'repeat boundary must be conditional')
        destinations = {}
        for key in ('taken', 'fallthrough'):
            node = trial['dag']['nodes'][control[key]]
            require(node['op'] == 'const', 'repeat destination must be fixed')
            destinations[key] = int(node['value'], 16)
        require(set(destinations.values()) == {body_entry, exit_entry}, 'repeat boundary does not match header/exit')
        condition = trial['dag']['nodes'][control['condition']]
        require(condition['op'] == 'const', 'loop exit not established from a constant closed-state condition')
        truth = int(condition['value'], 16) != 0
        selected = destinations['taken' if truth else 'fallthrough']
        trace.append({'bodyApplications': len(paths) - 1, 'conditionValue': condition['value'],
                      'selectedTarget': hex(selected), 'willRepeat': selected == body_entry})
        require(len(trace) <= LIMITS['steps'], 'repeat inference attempt budget exceeded')
        if selected == exit_entry:
            break
        require(len(paths) + len(suffix) < LIMITS['steps'], 'loop exit not established within the step budget')
        paths.append(body)
    result = _compose_paths(paths + suffix, check, cache, indirect_mode)
    result['inferredRepeat'] = {'method': 'exact-constant-closed-state-condition',
        'bodyEntry': hex(body_entry), 'exitEntry': hex(exit_entry),
        'bodyApplicationsAfterPrefix': len(paths) - 1, 'attempts': len(trace),
        'attemptedLogicalInstructions': attempted_instructions,
        'attemptedMemoryBytes': attempted_memory, 'inferenceWorkLimitEach': 65536,
        'finalTranslationAccountedSeparately': True, 'trace': trace,
        'observedValuesUsed': False, 'independentSMTProof': False,
        'scope': 'Finite constant-branch propagation in this fixed p-code/GPR/ordinary-memory model; no CPU architecture or native reachability proof'}
    require(len(json.dumps(result, ensure_ascii=True, allow_nan=False).encode('utf-8')) <= LIMITS['reportBytes'], 'report byte budget exceeded')
    return result
