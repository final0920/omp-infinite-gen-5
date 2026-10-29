"""Independent source-reference SMT check of an OWN recovered function model.

The recovery tool has already finished. Reference formulas are not passed to it.
No protected executable or upstream script is executed here.
"""
import json
import hashlib
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'worker'))
from trace_analysis import Recovery, load_triton
from kernel_image import BinaryImage

folder = Path(sys.argv[1]).resolve()
receipt = json.loads((folder / 'receipt.json').read_text(encoding='utf-8'))
acceptance_path = folder / 'acceptance.json'
acceptance = json.loads(acceptance_path.read_text(encoding='utf-8'))
assert acceptance['status'] == 'owned-compiled-suite-function-model-verified'
assert acceptance['id'] in ('compiled-rotate-mix64', 'compiled-signed-select64', 'compiled-mul-mix32', 'packed-branch-mix64', 'packed-round-mix64')
assert acceptance['referenceWasNotSuppliedToRecovery']
image = BinaryImage.from_file(receipt['target'])
assert image.sha256 == acceptance['targetSha256']
tt = load_triton()
recovery = Recovery(tt, {'initial_flags': '0x202'}, image)
for alias, name in [('x', 'rcx'), ('y', 'rdx')]:
    symbol = recovery.ctx.symbolizeRegister(getattr(recovery.ctx.registers, name), alias)
    recovery.input_nodes[alias] = recovery.ast.variable(symbol)
ast = recovery.ast
x, y = recovery.input_nodes['x'], recovery.input_nodes['y']
actual = recovery.expression_ast(acceptance['result']['recoveredExpression'])
classes = []
for count in range(64) if acceptance['id'] == 'compiled-rotate-mix64' else []:
    # Constant rotate is a separate native-library primitive oracle. Every
    # uint64 y belongs to exactly one of these exhaustive low-six-bit classes.
    expected = ast.bvxor(ast.bvrol(x, ast.bv(count, 64)), ast.bvadd(x, y))
    assumption = ast.equal(ast.bvand(y, ast.bv(63, 64)), ast.bv(count, 64))
    proof = recovery.proof(ast.distinct(actual, expected), [assumption])
    if proof['status'] != 'unsat': raise AssertionError((count, proof))
    classes.append({'count': count, 'proof': proof})
method, formula = '64-exhaustive-count-classes-independent-constant-rotate-oracle', 'rol64(x,y&63) ^ uint64(x+y)'
if acceptance['id'] != 'compiled-rotate-mix64':
    if acceptance['id'] == 'compiled-signed-select64':
        expected = ast.ite(ast.bvsgt(x, y), x, y)
        formula = '(int64)x > (int64)y ? x : y'
    elif acceptance['id'] == 'packed-branch-mix64':
        condition = ast.distinct(ast.bvand(ast.bvxor(x, y), ast.bv(1, 64)), ast.bv(0, 64))
        expected = ast.ite(condition, ast.bvxor(ast.bvadd(x, y), ast.bv(0xd6e8feb86659fd93, 64)), ast.bvadd(ast.bvxor(x, y), ast.bv(0x9e3779b97f4a7c15, 64)))
        formula = '((x^y)&1) ? (x+y)^0xd6e8feb86659fd93 : (x^y)+0x9e3779b97f4a7c15'
    elif acceptance['id'] == 'packed-round-mix64':
        expected = x
        for i in range(8): expected = ast.bvxor(ast.bvrol(ast.bvadd(ast.bvadd(expected, y), ast.bv(i, 64)), ast.bv(7, 64)), ast.bvmul(y, ast.bv(0x9e3779b97f4a7c15, 64)))
        formula = '8 fixed rounds: state=rol64(state+y+i,7) ^ uint64(y*0x9e3779b97f4a7c15)'
    else:
        a, b = ast.extract(31, 0, x), ast.extract(31, 0, y)
        expected = ast.bvmul(ast.bvadd(ast.bvxor(a, b), ast.bv(99, 32)), ast.bv(143, 32))
        # Own C performs unsigned 32-bit arithmetic, then returns uint64.
        assert actual.getBitvectorSize() in (32, 64)
        if actual.getBitvectorSize() == 64: expected = ast.zx(32, expected)
        formula = 'uint64(uint32((uint32(x) ^ uint32(y)) + 99) * uint32(143))'
    proof = recovery.proof(ast.distinct(actual, expected))
    if proof['status'] != 'unsat': raise AssertionError(proof)
    classes.append({'class': 'all-inputs', 'proof': proof})
    method = 'independent-source-reference-bitvector-equivalence'
evidence = {'method': method,
            'result': 'all-unsat', 'formula': formula,
            'nativeAcceptanceSha256': hashlib.sha256(acceptance_path.read_bytes()).hexdigest(),
            'inputDomain': 'uint64 x and y', 'classes': classes,
            'scope': 'Recovered function model versus own source reference; original binary paths/environment and side effects are not proved',
            'wholeBinaryVerified': False, 'referenceWasNotSuppliedToRecovery': True}
(folder / 'source-reference-proof.json').write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'status': 'source-reference-function-model-proved', 'classes': len(classes), 'all': 'unsat', 'wholeBinaryVerified': False}))
