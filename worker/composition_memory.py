"""Exact read-after-write normalization for a total wrapping byte array.

Only a shared opaque uint64 base plus constant offsets establishes an address
relation. Different bases are unknown, never disjoint. Stores stay in the DAG
and in the ordered effect list. Exhausted optimization work retains the read.
No file bytes, observations, caller alias assertions or solver are consulted.
"""
from pcode_projection import ProjectionError

MASK = (1 << 64) - 1
STORE_VISIT_LIMIT = 4096


def initialize(dag):
    dag.memory_forms = {}
    dag.memory_reads = {}
    dag.memory_normalization = {
        'method': 'exact-ordered-byte-forwarding', 'maxStoreVisits': STORE_VISIT_LIMIT,
        'storeVisits': 0, 'forwardedBytes': 0, 'disjointStoreBypasses': 0,
        'unknownAliasFallbacks': 0, 'budgetFallbacks': 0, 'cacheHits': 0,
        'observedValuesUsed': False, 'independentSMTProof': False,
        'scope': 'shared opaque uint64 base plus modular constant offsets only; unknown alias and exhausted work retain LOAD; every STORE remains observable'}


def address_form(dag, identity):
    """Return an exact (opaque base identity or None, modular offset)."""
    dag.check()
    if identity in dag.memory_forms:
        return dag.memory_forms[identity]
    node = dag.nodes[identity]
    if node.get('bits') != 64:
        raise ProjectionError('Memory normalization requires uint64 addresses')
    result = (identity, 0)
    if node['op'] == 'const':
        result = (None, int(node['value'], 16) & MASK)
    elif node['op'] in ('INT_ADD', 'INT_SUB') and len(node['args']) == 2:
        a, b = node['args']
        left, right = dag.nodes[a], dag.nodes[b]
        if right['op'] == 'const' and right.get('bits') == 64:
            base, offset = address_form(dag, a)
            constant = int(right['value'], 16)
            result = (base, (offset + (constant if node['op'] == 'INT_ADD' else -constant)) & MASK)
        elif node['op'] == 'INT_ADD' and left['op'] == 'const' and left.get('bits') == 64:
            base, offset = address_form(dag, b)
            result = (base, (offset + int(left['value'], 16)) & MASK)
    dag.memory_forms[identity] = result
    return result


def normalize_load(dag, memory, address, bits, size, raw_make):
    """Read exactly the newest matching byte; stop at any unknown alias."""
    dag.check()
    if type(size) is not int or not 1 <= size <= 16 or bits != size * 8:
        raise ProjectionError('Invalid memory normalization load width')
    key = (memory, address, size)
    stats = dag.memory_normalization
    if key in dag.memory_reads:
        stats['cacheHits'] += 1
        return dag.memory_reads[key]

    def original():
        value = raw_make('load_le', (memory, address), bits, size=size)
        dag.memory_reads[key] = value
        return value

    store = dag.nodes[memory]
    if store['op'] != 'store_le':
        return original()
    if stats['storeVisits'] >= STORE_VISIT_LIMIT:
        stats['budgetFallbacks'] += 1
        return original()
    stats['storeVisits'] += 1
    before, destination, value = store['args']
    read_base, read_offset = address_form(dag, address)
    write_base, write_offset = address_form(dag, destination)
    if read_base != write_base:
        stats['unknownAliasFallbacks'] += 1
        return original()
    delta = (read_offset - write_offset) & MASK
    positions = [(delta + i) & MASK for i in range(size)]
    covered = [position < store['size'] for position in positions]
    if not any(covered):
        stats['disjointStoreBypasses'] += 1
        result = dag.make('load_le', (before, address), bits, size=size)
    elif all(covered) and delta + size <= store['size']:
        stats['forwardedBytes'] += size
        result = dag.extract(value, delta * 8, bits)
    else:
        pieces = []
        for index in reversed(range(size)):
            dag.check()
            if covered[index]:
                stats['forwardedBytes'] += 1
                pieces.append(dag.extract(value, positions[index] * 8, 8))
            else:
                byte_address = address if index == 0 else dag.make('INT_ADD', (address, dag.const(index, 64)), 64)
                pieces.append(dag.make('load_le', (before, byte_address), 8, size=1))
        result = dag.concat(pieces)
    dag.memory_reads[key] = result
    return result
