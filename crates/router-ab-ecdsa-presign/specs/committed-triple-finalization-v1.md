# Fixed committed-triple finalization v1

Status: implementation checkpoint 7. This layer is the sole production owner
of `ValidatedTriple` construction.

## Fixed equations

For each role `i` and triple, let `e_i(X)` and `f_i(X)` be degree-one
polynomials. Let `r_i` be the role's random product-sharing slope and `l0_i`
its sealed MTA output. Define:

```text
A       = sum_i e_i(0) G
B       = sum_i f_i(0) G
C_i     = e_i(0) B
C       = sum_i C_i
hat_C_i = l0_i G
R_L     = sum_i r_i G
l_i(X)  = l0_i + r_i X
L(X)    = sum_i l_i(X)
```

Each role proves knowledge of `e_i(0)` and `f_i(0)`, proves the DLogEq
relation between `e_i(0)G` and `C_i = e_i(0)B`, and proves knowledge of
`l0_i` for `hat_C_i`. Finalization requires:

```text
C = sum_i hat_C_i
c_role G = C + z_role R_L
```

The private message carries only `l_i(z_peer)`. It never carries `l0_i` or
`r_i`. The recipient combines that evaluation with its own `l_i(z_role)` to
obtain its Shamir share `c_role`. The reconstructed constant satisfies:

```text
c = 3 c_client - 2 c_signing_worker
c G = C
c = a b
```

## Pinned source mapping

The behavioral source is NEAR `threshold-signatures` commit
`db609be5021eb9d794f577601f422818fbdfe246`, Git tree
`05f60d54971e2f1e417dab7191f0f5d02f82468c`.

| ID | Pinned source | Purpose-built disposition | Confidence |
| --- | --- | --- | ---: |
| `TRI-FINAL-01` | `triples/generation.rs:98-112` generates and commits degree-one `E`, degree-one `F`, and the degree-zero random value later used as the `L` slope | `triples.rs` fixes the same scalar and commitment shape | 1.00 |
| `TRI-FINAL-02` | `generation.rs:159-183` proves knowledge of the local `E(0)` and `F(0)` scalars | `triples/finalize.rs` emits role/context/index-bound `TripleA` and `TripleB` DLog proofs | 1.00 |
| `TRI-FINAL-03` | `generation.rs:220-304` aggregates commitments and verifies private `a` and `b` evaluations | Finalization aggregates fixed-role commitments and verifies both local reconstructed shares at coordinate `2` or `3` | 1.00 |
| `TRI-FINAL-04` | `generation.rs:307-354` proves and aggregates `C_i = e_i(0)F(0)` | Finalization uses the same DLogEq statement and rejects a failed peer proof | 1.00 |
| `TRI-FINAL-05` | `generation.rs:366-400` commits to the MTA output `l0_i` and proves its discrete log | Finalization commits to the sealed multiplication share and emits a `ProductShare` DLog proof | 1.00 |
| `TRI-FINAL-06` | `generation.rs:403-412` constructs `l_i(X) = l0_i + r_iX` and privately sends its peer evaluation | Finalization retains the raw MTA share locally and sends only the fixed recipient evaluation | 1.00 |
| `TRI-FINAL-07` | `generation.rs:414-440` verifies peer MTA proofs and requires `sum hat_C_i = C` | Both roles enforce the same terminal public product equation | 1.00 |
| `TRI-FINAL-08` | `generation.rs:446-457` aggregates private product evaluations and verifies `c_iG = L(z_i)` | Both roles verify `c_role G = C + z_role R_L` before output | 1.00 |
| `TRI-FINAL-09` | `generation.rs:460-477` returns private shares and common public `A`, `B`, `C` | The checked state machine alone constructs opaque `ValidatedTriple` values | 1.00 |

The production transcript uses the project's tagged SHA-256 profile, fixed
roles, fixed coordinates, and fixed two-triple scheduling. Those deliberate
specializations preserve the equations and strengthen session binding.

## Abort boundary

Finalization returns a typed terminal error for a context, triple-index, or
role mismatch; an identity aggregate; a zero multiplication share; a failed
DLog or DLogEq proof; a malformed scalar or point; a private polynomial-share
equation failure; a private product-share equation failure; or a failed
terminal product equation.

A ciphertext corruption test changes a valid MTA message before receiver
processing. Both MTA exchanges complete and both finalization messages contain
valid proofs for the resulting shares. Both roles reject at the terminal
`C = sum hat_C_i` equation, and no `ValidatedTriple` is emitted.

## Deterministic evidence

The fixed in-process session covers both role directions, both triples, all
proof types, and recipient-specific product evaluations. It reconstructs and
checks `A`, `B`, `C`, and `c = ab`, asserts the two role-local `c` shares are
distinct for the frozen vector, and pins the semantic output digest:

```text
9657d135f23db8a295423d0d31a6fff178e02a3800ec7fb8c50ef921bc296f6d
```

## Constant-time boundary

Secret scalar and point operations use `k256`; comparisons use `subtle`.
Loops have fixed public bounds. Branches disclose public role/context/index
validity, proof validity, or the terminal accept/abort result. Source review
found no secret division, remainder, indexing, variable-length loop, or branch
that reveals a recoverable bit of a valid scalar. Optimized arm64 inspection
covered nine emitted receive/finalization and boundary functions with zero
errors and eight branch warnings. Those warnings map to public role selection,
malformed/identity input rejection, proof validity, and the terminal protocol
result. Generic preparation monomorphizations and Wasm output still require
compiled inspection before a constant-time release claim.
