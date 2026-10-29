"""Aggregate categorized API references into a per-function behavior inventory.

Input rows come from an engine provider. Each row names an API and (optionally) the
functions that reference it. Nothing here executes a target or touches a database.
Co-occurrence of APIs inside one function is a lead for review, not proof of behavior.
"""
from __future__ import annotations

from behavior_rules import API_CATEGORIES, CHAINS, DISTINCT_RULES, TAXONOMY_VERSION, WEAK_CATEGORIES, canonical

INTERPRETATION = ('API presence, and co-occurrence inside one function, are leads for review. They do not prove that the '
                  'behavior executes, what it targets, or intent; confirm by reading the function or tracing it.')
LIMITS = {'functions': 100, 'chains': 100, 'apis_per_category': 32, 'functions_per_api': 4, 'refs_per_api': 8}


def _text(value, limit=256):
    return str(value)[:limit]


def _function(ref):
    """Return (ea, name) for a reference row that resolved to a function, else None."""
    function = ref.get('function') if isinstance(ref, dict) else None
    if not isinstance(function, dict) or not function.get('ea'):
        return None
    return _text(function['ea'], 32), _text(function.get('name', ''), 256)


def behavior_inventory(api_rows, string_rows=()):
    """Build the inventory. ``string_rows`` are API names found as strings (likely resolved at run time)."""
    categories, functions = {}, {}
    unattributed = truncated_refs = 0
    attributed = False

    def note(row, key, source):
        nonlocal unattributed, truncated_refs, attributed
        category = API_CATEGORIES[key]
        entry = categories.setdefault(category, {'category': category, 'strength': 'weak' if category in WEAK_CATEGORIES else 'strong',
                                                 'apis': {}, 'referenceCount': 0}) ['apis'].setdefault(key, {
            'api': _text(row.get('api', key), 128), 'module': _text(row.get('module', ''), 128), 'sources': set(),
            'referenceCount': 0, 'referencesTruncated': False, 'functions': {}})
        entry['sources'].add(source)
        if row.get('referencesTruncated'):
            entry['referencesTruncated'] = True
            truncated_refs += 1
        refs = row.get('referenceFunctions')
        if refs is None:
            entry['referenceCount'] += len(row.get('referenceEas') or ())
            return
        attributed = True
        for ref in refs:
            entry['referenceCount'] += 1
            resolved = _function(ref)
            if resolved is None:
                unattributed += 1
                continue
            ea, name = resolved
            entry['functions'][ea] = name
            fn = functions.setdefault(ea, {'ea': ea, 'name': name, 'apis': {}})
            hit = fn['apis'].setdefault(key, {'sources': set(), 'refs': []})
            hit['sources'].add(source)
            site = ref.get('ea')
            if site and site not in hit['refs'] and len(hit['refs']) < LIMITS['refs_per_api']:
                hit['refs'].append(_text(site, 32))

    for row in api_rows:
        key = canonical(row.get('api', ''))
        if key:
            note(row, key, 'import')
    dynamic = []
    for row in string_rows:
        key = canonical(row.get('api', ''))
        if not key:
            continue
        note(row, key, 'string')
        names = {resolved[1] for resolved in map(_function, row.get('referenceFunctions') or ()) if resolved}
        dynamic.append({'api': _text(row.get('api'), 128), 'category': API_CATEGORIES[key], 'confidence': row.get('confidence', 'low'),
                        'stringEa': row.get('stringEa'), 'functions': sorted(names)[:LIMITS['functions_per_api']]})

    chains, function_rows, chain_counts = [], [], {}
    for fn in functions.values():
        present = set(fn['apis'])
        matched = []
        for chain in CHAINS:
            if all(group & present for group in chain['groups']):
                matched.append((chain, sorted(set().union(*(group & present for group in chain['groups'])))))
        for rule in DISTINCT_RULES:
            found = sorted(name for name in present if API_CATEGORIES[name] == rule['category'])
            if len(found) >= rule['minimum']:
                matched.append((rule, found))
        for chain, apis in matched:
            chain_counts[chain['id']] = chain_counts.get(chain['id'], 0) + 1
            chains.append({'id': chain['id'], 'label': chain['label'], 'strength': chain['strength'],
                           'function': {'ea': fn['ea'], 'name': fn['name']}, 'apis': apis,
                           'evidenceEas': sorted({site for name in apis for site in fn['apis'][name]['refs']})[:LIMITS['refs_per_api'] * 2],
                           'viaString': [name for name in apis if 'string' in fn['apis'][name]['sources']]})
        cats = sorted({API_CATEGORIES[name] for name in present})
        strong = [c for c in cats if c not in WEAK_CATEGORIES]
        function_rows.append({'ea': fn['ea'], 'name': fn['name'], 'categories': cats, 'apis': sorted(present),
                              'chains': [chain['id'] for chain, _ in matched],
                              '_score': len(strong) + 3 * sum(1 for chain, _ in matched if chain['strength'] == 'strong')})
    strength_order = {'strong': 0, 'weak': 1}
    chains.sort(key=lambda row: (strength_order[row['strength']], row['id'], row['function']['name']))
    function_rows.sort(key=lambda row: (-row['_score'], row['name'], row['ea']))
    for row in function_rows:
        del row['_score']

    category_rows = []
    for category in sorted(categories.values(), key=lambda c: (strength_order[c['strength']], -sum(a['referenceCount'] for a in c['apis'].values()), c['category'])):
        apis = sorted(category['apis'].values(), key=lambda a: (-a['referenceCount'], a['api'].lower()))
        category_rows.append({'category': category['category'], 'strength': category['strength'], 'apiCount': len(apis),
                              'referenceCount': sum(a['referenceCount'] for a in apis),
                              'apis': [{'api': a['api'], 'module': a['module'], 'sources': sorted(a['sources']),
                                        'referenceCount': a['referenceCount'], 'referencesTruncated': a['referencesTruncated'],
                                        'functions': [{'ea': ea, 'name': name} for ea, name in sorted(a['functions'].items(), key=lambda item: item[1])[:LIMITS['functions_per_api']]],
                                        'functionsTruncated': len(a['functions']) > LIMITS['functions_per_api']}
                                       for a in apis[:LIMITS['apis_per_category']]],
                              'apisTruncated': len(apis) > LIMITS['apis_per_category']})
    return {'schemaVersion': 1, 'taxonomyVersion': TAXONOMY_VERSION, 'interpretation': INTERPRETATION,
            'categories': category_rows, 'chains': chains[:LIMITS['chains']], 'functions': function_rows[:LIMITS['functions']],
            'dynamicApiStrings': dynamic[:LIMITS['functions']],
            'summary': {'categories': len(category_rows), 'apis': sum(c['apiCount'] for c in category_rows),
                        'functionsWithBehaviors': len(function_rows), 'chainCounts': dict(sorted(chain_counts.items()))},
            'coverage': {'functionAttribution': attributed, 'unattributedReferences': unattributed,
                         'apisWithTruncatedReferences': truncated_refs},
            'truncation': {'chains': len(chains) > LIMITS['chains'], 'functions': len(function_rows) > LIMITS['functions'],
                           'dynamicApiStrings': len(dynamic) > LIMITS['functions']},
            'limits': dict(LIMITS)}
