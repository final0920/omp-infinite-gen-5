"""Bounded, certified structural rewrites before expression tree projection.

Pre-order rules prevent a shared rotate/MBA chain from expanding first. No
reference formula, concrete input substitution or AST mutation is used.
"""


def normalize_ast(value, tt, ast, prove, check_budget, prove_instance=None, work_budget=None):
    steps, attempts, memo, reference_memo, reference_ids = [], [], {}, {}, {}
    remaining = work_budget if work_budget is not None else [512]
    types = tt.AST_NODE

    def unwrap(node):
        original = node
        key = node.getHash()
        for prior, result in reference_memo.get(key, ()):
            if node.equalTo(prior): return result
        trail = []
        while node.getType() == types.REFERENCE and remaining[0] > 0:
            check_budget(); remaining[0] -= 1
            # Constant bitvectors contain no input/environment symbol and can
            # be evaluated exactly, independent of reference-chain length.
            if not node.isSymbolized() and not node.isLogical():
                node = ast.bv(node.evaluate(), node.getBitvectorSize()); break
            expression = node.getSymbolicExpression(); ident = expression.getId()
            if ident in reference_ids:
                node = reference_ids[ident]; break
            trail.append(ident); node = expression.getAst()
        if node.getType() != types.REFERENCE:
            for ident in trail: reference_ids[ident] = node
        reference_memo.setdefault(key, []).append((original, node))
        return node

    def shift_rotation(node):
        node = unwrap(node)
        if node.getType() != types.BVOR or len(node.getChildren()) != 2: return None
        pair = [unwrap(child) for child in node.getChildren()]
        for left, right in (pair, pair[::-1]):
            if left.getType() != types.BVSHL or right.getType() != types.BVLSHR: continue
            a, lcount = left.getChildren(); b, rcount = right.getChildren()
            a, b, lcount, rcount = [unwrap(item) for item in (a, b, lcount, rcount)]
            bits = node.getBitvectorSize()
            if any(item.getBitvectorSize() != bits for item in (left, right, a, b, lcount, rcount)): continue
            if lcount.isSymbolized() or rcount.isSymbolized() or not a.equalTo(b): continue
            count = lcount.evaluate()
            if 0 < count < bits and rcount.evaluate() == bits - count: return a, count
        return None

    def match(node):
        kind, children = node.getType(), node.getChildren()
        rotation = shift_rotation(node) if kind == types.BVOR else None
        if rotation:
            base, count = rotation
            inner = shift_rotation(base)
            counts = (count,)
            if inner:
                base, inner_count = inner; counts = (inner_count, count)
            return 'complementary-shift-rotation', ast.bvrol(base, ast.bv(sum(counts) % node.getBitvectorSize(), node.getBitvectorSize())), counts
        if kind == types.BVNOT and unwrap(children[0]).getType() == types.BVNOT:
            return 'double-complement', unwrap(children[0]).getChildren()[0]
        if kind == types.BVXOR and all(unwrap(child).getType() == types.BVNOT for child in children):
            return 'exclusive-union-two-complements', ast.bvxor(*(unwrap(child).getChildren()[0] for child in children))
        if kind == types.BVAND and len(children) == 2:
            gates = [unwrap(child) for child in children]
            if all(gate.getType() == types.BVNOT for gate in gates):
                gates = [unwrap(gate.getChildren()[0]) for gate in gates]
                if all(gate.getType() == types.BVAND for gate in gates):
                    for direct, inverse in (gates, gates[::-1]):
                        a, b = direct.getChildren()
                        c, d = inverse.getChildren()
                        def complements(left, right):
                            left, right = unwrap(left), unwrap(right)
                            return ((left.getType() == types.BVNOT and unwrap(left.getChildren()[0]).equalTo(right)) or
                                    (right.getType() == types.BVNOT and unwrap(right.getChildren()[0]).equalTo(left)))
                        if (complements(a,c) and complements(b,d)) or (complements(a,d) and complements(b,c)):
                            return 'nand-complement-exclusive-union', ast.bvxor(a, b)
        if kind == types.EXTRACT:
            high, low = children[0].getInteger(), children[1].getInteger()
            shifted = unwrap(children[2]); shift_kind = shifted.getType()
            if shift_kind not in (types.BVSHL, types.BVLSHR): return None
            source, count = shifted.getChildren(); source = unwrap(source)
            if source.getType() != types.CONCAT or count.isSymbolized(): return None
            parts = source.getChildren()
            if len(parts) != 2: return None
            a, b = [unwrap(part) for part in parts]; width = a.getBitvectorSize()
            if width != b.getBitvectorSize() or not a.equalTo(b) or not 0 <= count.evaluate() < width: return None
            if shift_kind == types.BVSHL and low == width and high == 2 * width - 1:
                return 'duplicated-word-left-rotation', ast.bvrol(a, ast.bv(count.evaluate(), width))
            if shift_kind == types.BVLSHR and low == 0 and high == width - 1:
                return 'duplicated-word-right-rotation', ast.bvror(a, ast.bv(count.evaluate(), width))
        return None

    binary = {types.BVADD: ast.bvadd, types.BVSUB: ast.bvsub, types.BVMUL: ast.bvmul,
        types.BVAND: ast.bvand, types.BVOR: ast.bvor, types.BVXOR: ast.bvxor,
        types.BVSHL: ast.bvshl, types.BVLSHR: ast.bvlshr, types.BVASHR: ast.bvashr,
        types.BVUREM: ast.bvurem, types.BVROL: ast.bvrol, types.BVROR: ast.bvror}

    def rebuild(node, children):
        kind = node.getType()
        if kind in (types.BVROL, types.BVROR):
            count = children[1]
            if count.getType() == types.INTEGER: count = ast.bv(count.getInteger(), children[0].getBitvectorSize())
            return binary[kind](children[0], count)
        if kind in binary: return binary[kind](*children)
        if kind == types.BVNOT: return ast.bvnot(children[0])
        if kind == types.EXTRACT: return ast.extract(children[0].getInteger(), children[1].getInteger(), children[2])
        if kind == types.CONCAT: return ast.concat(children)
        if kind in (types.ZX, types.SX): return (ast.zx if kind == types.ZX else ast.sx)(children[0].getInteger(), children[1])
        # Unknown parents remain intact; no child equality is transported into
        # a construct whose rebuilding semantics are not explicitly supported.
        return node

    def visit(node, depth=0):
        check_budget()
        key = node.getHash()
        for original, result in memo.get(key, ()):
            if node.equalTo(original): return result
        remaining[0] -= 1
        if remaining[0] < 0 or depth > 32: return node
        current = unwrap(node)
        for _ in range(4):
            rewrite = match(current) if len(attempts) < 64 else None
            if rewrite is None: break
            rule, proposed = rewrite[:2]
            if current.getBitvectorSize() != proposed.getBitvectorSize(): break
            proof = prove_instance(current, proposed, rule, rewrite[2]) if len(rewrite) > 2 and prove_instance else prove(current, proposed)
            entry = {'rule': rule, 'bits': current.getBitvectorSize(), 'proof': proof}
            attempts.append(entry)
            if proof['status'] != 'unsat': break
            steps.append(entry); current = proposed
        children = current.getChildren()
        updated = [visit(child, depth + 1) for child in children]
        if any(not left.equalTo(right) for left, right in zip(children, updated)):
            current = rebuild(current, updated)
        memo.setdefault(key, []).append((node, current))
        return current

    return visit(value), steps, attempts
