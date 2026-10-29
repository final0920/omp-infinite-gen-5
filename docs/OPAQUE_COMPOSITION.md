# Explicit opaque-effect state chains

This page keeps the original opaque-effects contract. An explicit separate
[opaque-status mode](OPAQUE_STATUS_COMPOSITION.md) preserves modeled status
correlations in stored flag-image data while each template still closes its
own CPU-flag dependencies; no behavior changes implicitly.

An address-only composition plan may explicitly select all of:

```json
{
  "strategy": "sequence",
  "representation": "transition-chain",
  "template_mode": "opaque-effects",
  "indirect_mode": "guarded-target",
  "paths": [["0x14005206a"]]
}
```

The addresses above are an example, not a supplied summary or execution request.
Both inline plans and SHA-bound plan files use the same validators. No caller
can provide unknown values, observations, p-code, effect descriptions or trusted
summaries. `template_mode` defaults to strict. Opaque effects require an explicit
sequence transition chain; flat/default composition and constant-loop inference
keep their old behavior and refusal boundaries.

Public schema: `ig5-pcode-opaque-transition-chain-v1`. Representation schema:
`ig5-internal-opaque-transition-chain-v1`. These extend the separately named
[state-binding representation](TRANSITION_CHAIN.md). Consumers must resolve
every exact `state_binding.source` equality, not treat bindings as free inputs.

Only the already byte-bound, complete fixed-decoder models from
[opaque projection](OPAQUE_PROJECTION.md) are reused:

- PUSHFQ decrements RSP by8 and writes an arbitrary64-bit flag image. Its relation
  to flags and architectural reserved bits is not retained.
- RDTSC generates one fresh64-bit value, split into EDX:EAX, clearing both GPRs'
  upper32 bits. No timing or cross-read relation is assumed.
- Canonical undefined16-bit BSWAP havocs the whole destination GPR. This is a
  conservative superset, not an exact interpretation of undefined behavior.

Each live unknown is distinct for its application and instruction. Its name,
step/template/instruction identities, source EA and type are independently
checked by the host. Reusing the compiled template never reuses its unknown
value. Effects whose outputs die inside the template still remain in
`templates[].opaqueEffects` and expanded raw-work accounting. The global
`nondeterministicInputs` array lists only live imported unknowns; it is not an
array of concrete values. PUSHFQ STOREs retain raw `pcodeIndex=56` and internal
`replacementPcodeIndex=2`, separately.

All16 GPRs, coherent memory, ordered STORE entry guards and complementary exits
remain in the chain. Other live initial/undefined/unmodeled flags and unsupported
effects still reject. No status flags cross a template boundary. Conditional
continuation does not replace the actual dynamic target in data state. A false
guard invalidates the hypothetical later execution; it does not erase earlier
STOREs or the post-control state on the complementary exit.

All opaque template translations and global composition share the original4096
STORE-visit optimization counters. Their caches and DAG identities remain local.
Unknown aliases and exhausted optimization work retain LOADs. Existing64-step,
128-distinct-address,1024-logical-instruction/1024-accessed-byte,65536-p-code,
2048-node,8192-reference,128-retained-depth,4MiB-report, two-slot and shared50s/2GiB
limits remain. Expanded dependency depth is reported separately as before.

The public `representationValidation` is produced by the host after validation,
not accepted from the child as a certificate. It reports the exact report schema,
fixed-project fit, typed binding counts, memory-source and guard checks, fresh
unknown counts and provenance checks. It verifies serialization and the stated
representation contract. It does not prove CPU/SMT equivalence, actual stack or
relocation premises, native reachability or complete protected business.

`test:opaque-chain` covers fresh repeated PUSHFQ/RDTSC/BSWAP, independent numeric
memory effects and wrap, rejection of observations/shared unknowns/forged
metadata, strict flag refusal and shared normalization exhaustion. The real Java
runtime suite checks the owned3.11 Demo Ultra entry alone, entry plus2/16 handler
applications, repeated entry, unchanged strict refusal and original1024-byte
budget refusal. The reference verifier uses the prior immutable entry projection
and separately derived ordinary handler equations: it is whole-chain consistency
checking, not an independent entry CPU interpreter. Source, installed and actual
configured-model evidence remain separate. Exact3.8 and full Ultra/Enigma business
recovery are still unverified.
