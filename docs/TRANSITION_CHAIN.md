# Bounded state transition chains

The default templates remain strict. A separately named explicit conservative
extension is documented in [OPAQUE_COMPOSITION.md](OPAQUE_COMPOSITION.md).

`ig5_ir level=compose` accepts the explicit address-plan option
`representation: "transition-chain"` for `strategy: "sequence"`. Omitting it
keeps the existing flat DAG and its depth128 rejection. Constant-loop inference
continues to use flat composition; this option does not infer loops or targets.
All other plan fields and SHA-bound plan-file inputs work as before.

Every strict, byte-bound template still retains all16 GPRs, closes its own flags,
and consumes coherent memory after all preceding writes. After each application,
18 distinct `state_binding` nodes name all16 GPRs, memory and the continuation
guard. Each binding is **exactly equal to its earlier `source`**, of the same type
and width. It is not a fresh independent input or an observed value. The next
application consumes these bindings; `layers` records complete incoming and
outgoing states. Ordered STOREs keep their application entry guard. Conditional
and explicitly guarded dynamic edges retain complementary exits with post-control
state, including RET's popped stack pointer. No flags cross a boundary.

Public schema: `ig5-pcode-transition-chain-v1`. Internal representation schema:
`ig5-internal-state-transition-chain-v1`. Ordinary consumers must resolve binding
source equalities; a flat DAG evaluator that treats them as independent variables
would give incorrect results and must reject the schema instead.

`dag.depth` measures retained local expression depth, at most128. The separately
reported `dag.expandedDependencyDepth` follows source equalities as well and can
exceed128. This is a different representation, not a claim that the old flat
request passed. All bindings count as nodes; every source equality and every
layer state root counts as a reference. Existing limits remain64 applications,
128 distinct instructions,1024 logical instructions,65536 logical p-code ops,
1024 accessed bytes,2048 retained nodes,8192 references,4MiB final report, two
owned requests, and the shared50s/2GiB analysis-process limits. Hitting any limit
still rejects. Unknown aliases keep LOADs. No target executes or database changes.

The host independently checks state freshness, complete incoming state binding,
source order/type, application intervals, no cross-boundary expression bypass,
ordered memory and STORE guards, direct successors, conditional/dynamic selection
and complementary exits, both depths and complete reference accounting. This
checks report consistency; it is not an independent CPU equivalence certificate.

Validation: `test:transition-chain` covers numeric memory aliasing and uint64
wrap, all16 GPRs, RET and conditional exits, default refusal, cancellation and
forged reports. `scripts/test_transition_chain_runtime.mjs` uses the actual public
route and pinned Java decoder on owned3.11 Demo Ultra paths at2/4/8/16 applications,
plus the original default flat16 refusal. The independent runtime verifier checks
complete states, memory, writes, guards and exits against a separate ordinary
formula. Source, installed-plugin and actual configured-model acceptance are
separate receipts. These local translations do not establish exact3.8 support,
native reachability/relocation assumptions or complete protected-business recovery.
