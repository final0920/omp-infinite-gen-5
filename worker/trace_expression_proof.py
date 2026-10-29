"""Universal local lemmas, instantiated with exact expression subjects."""
import json


def prove_instance(ctx, ast, before, after, rule, metadata, prove, templates):
    bits = before['bits']
    if after['bits'] != bits: raise ValueError('Local expression lemma width mismatch')
    if rule == 'modular-associative-commutative-normal-form':
        allowed = {before['op']}
        if before['op'] not in ('add', 'mul', 'and', 'or', 'xor'): raise ValueError('Unknown modular lemma')
        subjects = None
    elif rule in ('complementary-shift-rotation', 'consecutive-constant-rotations'):
        allowed = {'or', 'shl', 'lshr', 'rol', 'ror'}
        subjects = {json.dumps(metadata['subject'], sort_keys=True)}
    else: raise ValueError('Unknown expression instantiation rule')
    atoms = {}

    def abstract(node, existing_only=False, depth=0):
        if depth > 32: raise ValueError('Local expression lemma depth exceeded')
        if node['bits'] != bits: raise ValueError('Local expression lemma operand width mismatch')
        key = json.dumps(node, sort_keys=True)
        if node['op'] == 'constant': return node
        atom = key in subjects if subjects is not None else node['op'] not in allowed
        if atom:
            if key not in atoms:
                if existing_only or len(atoms) >= 64: raise ValueError('Local lemma introduces an unmatched subject')
                atoms[key] = len(atoms)
            return {'op': 'lemma-variable', 'index': atoms[key], 'bits': bits}
        if node['op'] not in allowed: raise ValueError('Local lemma has an unsupported operator')
        return {'op': node['op'], 'bits': bits,
                'args': [abstract(child, existing_only, depth + 1) for child in node['args']]}

    left, right = abstract(before), abstract(after, True)
    key = json.dumps([rule, left, right], sort_keys=True)
    if key not in templates:
        variables = [ast.variable(ctx.newSymbolicVariable(bits,
            'ig5_expression_lemma_' + str(len(templates)) + '_' + str(i))) for i in range(len(atoms))]
        functions = {'add': ast.bvadd, 'mul': ast.bvmul, 'and': ast.bvand, 'or': ast.bvor,
                     'xor': ast.bvxor, 'shl': ast.bvshl, 'lshr': ast.bvlshr,
                     'rol': ast.bvrol, 'ror': ast.bvror}
        def build(node):
            if node['op'] == 'lemma-variable': return variables[node['index']]
            if node['op'] == 'constant': return ast.bv(int(node['value'], 16), bits)
            children = [build(child) for child in node['args']]
            result = children[0]
            for child in children[1:]: result = functions[node['op']](result, child)
            return result
        templates[key] = ast.distinct(build(left), build(right))
    proof = prove(templates[key])
    return {**proof, 'method': 'SMT-universal-expression-template-and-exact-instantiation',
            'template': {'rule': rule, 'subjectBits': bits, 'arbitrarySubjects': len(atoms)},
            'scope': 'Arbitrary full-width subjects; exact original terms substituted; parent rebuilding preserves equality'}
