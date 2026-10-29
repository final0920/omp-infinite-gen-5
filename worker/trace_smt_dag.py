"""Exact, bounded SMT DAG definitions; no input or path constraint substitution.

Fresh variables are solver-only. Every compound term has a complete equality /
Boolean equivalence definition, so satisfiability is preserved in both directions.
"""


def lower_query(ctx, tt, formula, check_budget, prefix, node_limit=2048, reference_limit=8192):
    ast = ctx.getAstContext(); types = tt.AST_NODE
    logical_xor = ast.lxor([ast.equal(ast.bv(0,1),ast.bv(0,1)),ast.equal(ast.bv(0,1),ast.bv(1,1))]).getType()
    refs, terms, definitions, variables, source_memo, original_variables = {}, {}, [], [], {}, set()
    work = [reference_limit]
    visits = [reference_limit]
    binary = {types.BVADD:ast.bvadd, types.BVSUB:ast.bvsub, types.BVMUL:ast.bvmul,
        types.BVAND:ast.bvand,types.BVOR:ast.bvor,types.BVXOR:ast.bvxor,
        types.BVSHL:ast.bvshl,types.BVLSHR:ast.bvlshr,types.BVASHR:ast.bvashr,
        types.BVUDIV:ast.bvudiv,types.BVSDIV:ast.bvsdiv,types.BVUREM:ast.bvurem,types.BVSREM:ast.bvsrem,
        types.EQUAL:ast.equal,types.DISTINCT:ast.distinct,types.BVULT:ast.bvult,types.BVULE:ast.bvule,
        types.BVUGT:ast.bvugt,types.BVUGE:ast.bvuge,types.BVSLT:ast.bvslt,types.BVSLE:ast.bvsle,
        types.BVSGT:ast.bvsgt,types.BVSGE:ast.bvsge}
    unary = {types.BVNOT:ast.bvnot,types.BVNEG:ast.bvneg,types.LNOT:ast.lnot}
    logical = {types.LAND:ast.land,types.LOR:ast.lor,logical_xor:ast.lxor}

    def rebuild(kind, children):
        if kind in binary:return binary[kind](*children)
        if kind in unary:return unary[kind](children[0])
        if kind in logical:return logical[kind](children)
        if kind == types.ITE:return ast.ite(*children)
        if kind == types.CONCAT:return ast.concat(children)
        if kind == types.EXTRACT:return ast.extract(children[0].getInteger(),children[1].getInteger(),children[2])
        if kind in (types.ZX,types.SX):return (ast.zx if kind==types.ZX else ast.sx)(children[0].getInteger(),children[1])
        if kind in (types.BVROL,types.BVROR):
            count=children[1]
            if count.getType()==types.INTEGER:count=ast.bv(count.getInteger(),children[0].getBitvectorSize())
            return (ast.bvrol if kind==types.BVROL else ast.bvror)(children[0],count)
        raise ValueError('SMT DAG unsupported AST kind '+str(kind))

    def intern(key, builder):
        if key in terms:return terms[key]
        if len(terms)>=node_limit:raise ValueError('SMT DAG node budget exceeded')
        result=(builder(),len(terms));terms[key]=result;return result

    def visit(node,depth=0):
        check_budget()
        visits[0]-=1
        if visits[0]<0:raise ValueError('SMT DAG traversal budget exceeded')
        if depth>128:raise ValueError('SMT DAG depth budget exceeded')
        trail=[]; seen_refs=set()
        while node.getType()==types.REFERENCE:
            check_budget();work[0]-=1
            if work[0]<0:raise ValueError('SMT DAG reference budget exceeded')
            expression=node.getSymbolicExpression();ident=expression.getId()
            if ident in refs:return refs[ident]
            if ident in seen_refs:raise ValueError('SMT DAG cyclic reference')
            seen_refs.add(ident);trail.append(ident);node=expression.getAst()
        kind=node.getType();bits=node.getBitvectorSize()
        source_key=(kind,bits,node.getHash())
        for original,result in source_memo.get(source_key,()):
            if node.equalTo(original):
                for ident in trail:refs[ident]=result
                return result
        if kind==types.VARIABLE:
            original_variables.add(node.getSymbolicVariable().getId())
            result=intern(('variable',node.getSymbolicVariable().getId()),lambda:node)
        elif kind==types.INTEGER:
            result=intern(('integer',node.getInteger()),lambda:node)
        elif kind==types.BV:
            result=intern(('constant',bits,node.evaluate()),lambda:node)
        else:
            children=[visit(child,depth+1) for child in node.getChildren()]
            key=('operation',kind,bits,tuple(ident for _,ident in children))
            def build():
                rhs=rebuild(kind,[value for value,_ in children])
                if not 1<=bits<=256:raise ValueError('SMT DAG term width is unsupported')
                symbol=ctx.newSymbolicVariable(1 if rhs.isLogical() else bits,prefix+str(len(variables)))
                variables.append(symbol.getId());variable=ast.variable(symbol)
                if rhs.isLogical():
                    value=ast.equal(variable,ast.bv(1,1))
                    definition=ast.lnot(ast.lxor([value,rhs]))
                else:
                    value=variable;definition=ast.equal(value,rhs)
                definitions.append(definition)
                return value
            result=intern(key,build)
        for ident in trail:refs[ident]=result
        source_memo.setdefault(source_key,[]).append((node,result))
        return result

    root,_=visit(formula)
    if not root.isLogical():raise ValueError('SMT DAG query must be Boolean')
    query=ast.land(definitions+[root]) if definitions else root
    return query, {'method':'exact-SMT-DAG-definitions','nodes':len(terms),'definitions':len(definitions),
        'referenceExpansions':reference_limit-work[0],'nodeBudget':node_limit,'referenceBudget':reference_limit,
        'traversals':reference_limit-visits[0],'traversalBudget':reference_limit,
        'freshVariableIds':variables,'originalVariableIds':sorted(original_variables),
        'scope':'All definitions retained; original variables remain free; satisfiability preserved in both directions'}
