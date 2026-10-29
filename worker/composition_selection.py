"""Pure address-plan validation shared by the protocol root and compute child."""
import re

HEX = re.compile(r'0x[0-9a-fA-F]{1,16}\Z')
PLAN_LIMITS = {'steps': 64, 'distinctInstructions': 128, 'providedInstructionOccurrences': 1024}


def validate_plan(plan):
    if type(plan) is not dict:
        raise ValueError('composition_plan must be an address-only object')
    strategy = plan.get('strategy')
    fields = {'strategy', 'paths'} if strategy == 'sequence' else {'strategy', 'prefix', 'body', 'suffix'}
    optional = {k for k in ('indirect_mode', 'representation', 'template_mode') if k in plan}
    if strategy not in ('sequence', 'constant-loop') or set(plan) != fields | optional:
        raise ValueError('composition_plan requires exactly the fields of sequence or constant-loop')
    representation = plan.get('representation', 'flat')
    if type(representation) is not str or representation not in ('flat', 'transition-chain'):
        raise ValueError('composition_plan.representation requires flat or transition-chain')
    if representation == 'transition-chain' and strategy != 'sequence':
        raise ValueError('transition-chain requires an explicit sequence; constant-loop inference remains flat')
    representation_field = {'representation': representation} if 'representation' in plan else {}
    template_mode = plan.get('template_mode', 'strict')
    if type(template_mode) is not str or template_mode not in ('strict', 'opaque-effects','opaque-status'):
        raise ValueError('composition_plan.template_mode requires strict, opaque-effects or opaque-status')
    if template_mode in ('opaque-effects','opaque-status') and (representation != 'transition-chain' or strategy != 'sequence'):
        raise ValueError(template_mode+' requires an explicit transition-chain sequence')
    representation_field.update({'template_mode': template_mode} if 'template_mode' in plan else {})
    mode = plan.get('indirect_mode', 'reject')
    if type(mode) is not str or mode not in ('reject', 'guarded-target'):
        raise ValueError('composition_plan.indirect_mode requires reject or guarded-target')
    occurrences, distinct = 0, set()

    def path(value):
        nonlocal occurrences
        if type(value) is not list or not 1 <= len(value) <= 128 or any(type(a) is not str or not HEX.fullmatch(a) or int(a, 16) == 0 for a in value):
            raise ValueError('Each composition template requires 1..128 explicit nonzero preferred addresses')
        result = [hex(int(a, 16)) for a in value]
        if len(set(result)) != len(result):
            raise ValueError('Repeated addresses within one composition template are unsupported')
        occurrences += len(result); distinct.update(result)
        if occurrences > 1024 or len(distinct) > 128:
            raise ValueError('Composition plan exceeds1024 provided occurrences or128 distinct instructions')
        return result

    if strategy == 'sequence':
        if type(plan['paths']) is not list or not 1 <= len(plan['paths']) <= 64:
            raise ValueError('Sequence composition requires1..64 path applications')
        return {'strategy': strategy, 'paths': [path(p) for p in plan['paths']], 'indirect_mode': mode, **representation_field}
    if type(plan['suffix']) is not list or not 1 <= len(plan['suffix']) < 64:
        raise ValueError('Constant-loop composition requires1..63 exit suffix paths')
    prefix, body = path(plan['prefix']), path(plan['body'])
    return {'strategy': strategy, 'prefix': prefix, 'body': body,
            'suffix': [path(p) for p in plan['suffix']], 'indirect_mode': mode, **representation_field}


def plan_paths(plan):
    return plan['paths'] if plan['strategy'] == 'sequence' else [plan['prefix'], plan['body'], *plan['suffix']]


def selected_addresses(plan):
    return list(dict.fromkeys(a for path in plan_paths(plan) for a in path))
