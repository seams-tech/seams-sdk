# Fixed two-party MTA v1

Status: implementation checkpoint 6, integrated by checkpoint 7. This layer
produces sealed additive multiplication shares consumed only by committed
triple finalization.

## Fixed role and size assignment

Each triple consumes one corrected random-OT extension output containing 768
OTs. The output is split into two fixed 384-OT MTA instances:

- instance 0 multiplies the sender's `a` share by the receiver's `b` share;
- instance 1 multiplies the sender's `b` share by the receiver's `a` share;
- Triple 0 fixes Client as MTA sender and SigningWorker as receiver; and
- Triple 1 fixes SigningWorker as MTA sender and Client as receiver.

This assignment covers exactly two triples and balances the directional work.
Public APIs expose no batch size, participant list, runtime role, or role-order
comparison.

## MTA equations

For each instance, the sender has random-OT pairs `(v0_i, v1_i)`, input `a`,
and independent masks `delta_i`. It sends:

```text
c0_i = v0_i + delta_i + a
c1_i = v1_i + delta_i - a
```

The receiver holds choice bits `t_i`, selected random-OT values `v_i`, and
input `b`. After receiving every `c` value, it samples a fresh seed and derives
`chi_i` for `i = 1..383`. It constructs:

```text
chi_0 = (-1)^t_0 * (b - sum_{i=1..383} (-1)^t_i * chi_i)
m_i   = c[t_i]_i - v_i
beta  = sum_{i=0..383} chi_i * m_i
```

The receiver sends `chi_0` and the seed. The sender derives the same tail and
computes:

```text
alpha = -sum_{i=0..383} delta_i * chi_i
```

The invariant is:

```text
alpha + beta = a * b
```

Combining both instances and both local products gives:

```text
c_client + c_worker
  = a_client*b_client + a_worker*b_worker
  + a_client*b_worker + a_worker*b_client
  = (a_client + a_worker) * (b_client + b_worker)
```

The implementation derives each tail scalar with SHA-512 reduced modulo the
secp256k1 scalar order. The transcript binds the signing scope, pair context,
triple index, MTA-sender role, instance, coefficient index, suite, and fresh
seed.

## State and boundary invariants

- Corrected random-OT outputs are consumed once and remain inaccessible to
  production callers.
- Operands bind their role-specific type, signing context, and triple index.
- Ciphertext and response messages use fixed arrays and canonical scalar
  parsing.
- Client-sender output is accepted only for Triple 0; SigningWorker-sender
  output is accepted only for Triple 1.
- Context and triple-index checks complete before receiver randomness is
  sampled.
- Masks, operands, ciphertext scalars, response scalars, seeds, intermediate
  coefficients, and output shares zeroize on drop.
- Multiplication shares stay sealed for terminal triple construction.
- A role-specific two-triple bundle accepts exactly a Triple 0 share followed
  by a Triple 1 share under one context and owner role.

## Malicious behavior boundary

The MTA equations contain no independent ciphertext proof. This matches the
pinned construction. An altered ciphertext or response can corrupt the
resulting additive shares. Checkpoint 7 proves knowledge of each resulting
share commitment, binds it to the polynomial contribution, and rejects a
corrupted exchange at the terminal product equation before `ValidatedTriple`
emission.

Transport provides private authenticated role-to-role delivery. The canonical
driver rejects role, round, context, and replay substitutions. The persistent
pool adapters own timeout, one-use destruction, crash recovery, and ambiguous
delivery after presign output exists.

## Pinned source alignment

| Purpose-built behavior | Pinned NEAR source | Disposition | Confidence |
| --- | --- | --- | ---: |
| `c0`, `c1`, `alpha` equations | `triples/mta.rs:36-75` | Preserved with fixed arrays | 1.00 |
| Choice selection, `chi_0`, `beta` equations | `triples/mta.rs:85-135` | Preserved with fixed arrays | 1.00 |
| Two 384-OT instances for the two cross terms | `triples/multiplication.rs:66-91`, `125-150` | Preserved | 1.00 |
| Add local product to the two cross-term shares | `triples/multiplication.rs:197-201` | Preserved for fixed two-party roles | 1.00 |
| Direction assignment across two triples | `triples/multiplication.rs:204-292` | Specialized to fixed Triple 0/1 roles | 0.99 |
| Tail-coefficient derivation | `triples/mta.rs:68-72`, `109-112` | Same equation; domain-separated SHA-512 replaces NEAR's transcript RNG | 0.98 |
| Fixed size and canonical wire parsing | Generic vectors in pinned source | Stronger purpose-built boundary | 1.00 |

No mismatch was found in the MTA or multiplication equations. The
domain-separated coefficient derivation and fixed role schedule are deliberate
adaptations, recorded above. Terminal proof and triple checks consume this
layer before a `ValidatedTriple` becomes reachable.

## Constant-time boundary

All loops and slices have fixed public bounds. Secret choice bits select
ciphertext branches and coefficient signs through `subtle` constant-time
selection. Scalar arithmetic and reduction use `k256`. Division and remainder
operations apply only to public bit indexes. The only protocol branches inspect
public context, role, index, or canonical boundary data.

The optimized native arm64 audit reports zero division or square-root errors for
the complete presign crate. The release Wasm scan rejects unapproved integer
division/remainder and floating division/square-root operators. Conditional
branch dataflow and target-runtime timing remain explicit non-claims under
`A-CT-BRANCH-DATAFLOW` and `A-CT-RUNTIME` in `assurance-ledger-v1.md`.
