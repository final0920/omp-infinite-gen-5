"""Bounded diagnostics of the complete recorded path's input domain.

Splitting is permitted only after exact DAG lowering refuses. Each query retains
ALL original fixed-environment assumptions. SAT for one group disproves the
whole conjunction's universality; UNSAT requires a gap-free partition of every
condition. This diagnostic does not discard guards or certify binary coverage.
"""


def diagnose_guard_domain(rows, ast, prove, check_budget, can_query, max_attempts=16):
    if not rows or not 1 <= max_attempts <= 16:
        raise ValueError('Guard diagnostic requires conditions and 1..16 attempts')
    assumptions = tuple(item for _, _, fixed in rows for item in fixed)
    pending = [(0, len(rows))]
    proved = []
    attempts = []
    result = {'diagnosticOnly': True, 'conditionCount': len(rows),
        'fixedAssumptionCount': len(assumptions), 'attemptLimit': max_attempts,
        'status': 'unknown', 'attempts': attempts, 'provedRanges': proved,
        'scope': 'All recorded conditions and fixed environment assumptions retained; no binary/path coverage upgrade'}
    while pending:
        check_budget()
        if len(attempts) >= max_attempts or not can_query():
            result['reason'] = 'Shared guard diagnostic or solver budget reached'
            return result
        start, end = pending.pop()
        conditions = [row[1] for row in rows[start:end]]
        conjunction = ast.land(conditions) if len(conditions) > 1 else conditions[0]
        proof = prove(ast.lnot(conjunction), assumptions)
        attempts.append({'start': start, 'end': end,
            'groupFirstSource': hex(rows[start][0]), 'groupLastSource': hex(rows[end - 1][0]), 'proof': proof})
        if proof['status'] == 'sat':
            result.update(status='not-universal', witness=attempts[-1])
            return result
        if proof['status'] == 'unsat':
            proved.append({'start': start, 'end': end, 'attemptIndex': len(attempts) - 1})
            continue
        if proof.get('method') == 'bounded-SMT-DAG-refusal' and end - start > 1:
            mid = (start + end) // 2
            pending.extend([(mid, end), (start, mid)])
            continue
        result['reason'] = proof.get('reason') or ('Guard solver returned ' + proof['status'])
        return result
    # An independently checkable complete partition is required for universality.
    cursor = 0
    for group in sorted(proved, key=lambda group: group['start']):
        if group['start'] != cursor or group['end'] <= cursor:
            raise ValueError('Guard diagnostic partition is incomplete or overlapping')
        cursor = group['end']
    if cursor != len(rows): raise ValueError('Guard diagnostic omitted recorded conditions')
    result.update(status='universal-under-fixed-environment', allConditionsCovered=True)
    return result
