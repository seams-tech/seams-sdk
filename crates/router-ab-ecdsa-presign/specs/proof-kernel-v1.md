# Fixed proof kernels v1

Status: kernels integrated by implementation checkpoint 7. Phase 4 review
remains pending.

## Source mapping

The behavioral source is NEAR `threshold-signatures` commit
`db609be5021eb9d794f577601f422818fbdfe246`, Git tree
`05f60d54971e2f1e417dab7191f0f5d02f82468c`.

| ID | Pinned source evidence | Purpose-built implementation | Alignment | Confidence |
| --- | --- | --- | --- | --- |
| `PF-DLOG-01` | `src/crypto/proofs/dlog.rs:83-104` computes `R = rG`, derives non-zero `e`, and returns `s = r + ex` | `src/proofs.rs:386-405` computes the same Schnorr relation and carries `(R, s)` | Full mathematical match | `1.00` |
| `PF-DLOG-02` | `src/crypto/proofs/dlog.rs:108-125` reconstructs `R = sG - eX` and accepts only the transcript-derived `e` | `src/proofs.rs:407-422` checks `sG = R + eX` using the production challenge | Full mathematical match | `1.00` |
| `PF-EQ-01` | `src/crypto/proofs/dlogeq.rs:139-165` computes `(R0, R1) = (rG, rH)` and `s = r + ex` | `src/proofs.rs:424-449` computes the same Chaum–Pedersen relation | Full mathematical match | `1.00` |
| `PF-EQ-02` | `src/crypto/proofs/dlogeq.rs:170-190` reconstructs both commitments and derives the challenge | `src/proofs.rs:451-480` checks `sG = R0 + eX0` and `sH = R1 + eX1` | Full mathematical match | `1.00` |
| `PF-USE-01` | `src/ecdsa/ot_based_ecdsa/triples/generation.rs:631-655` proves knowledge of each role's `a` and `b` constants | `DLogProofKind::TripleA` and `TripleB` bind these two proof uses | Full fixed-path mapping | `0.95` |
| `PF-USE-02` | `src/ecdsa/ot_based_ecdsa/triples/generation.rs:307-354` proves equality between a role's `E_i` discrete log and its contribution under aggregate `F` | `ClientDLogEqContext` and `SigningWorkerDLogEqContext` bind and verify the fixed product proof during finalization | Full fixed-path integration | `1.00` |
| `PF-TRANSCRIPT-01` | NEAR uses Mini-Merlin/STROBE labels and participant forks | `src/proofs.rs:504-538` uses the production SHA-256 tagged transcript below | Deliberate transcript-profile divergence required by the refactor plan | `1.00` |

Line numbers refer to the pinned source and the checkpoint-2 formatted source.
Later edits must update this table alongside the code.

## Proof representation

DLog proves knowledge of `x` such that `X = xG`:

```text
R = rG
e = H(context, X, R)
s = r + ex
verify: sG = R + eX
```

DLogEq proves the same `x` relates `X0 = xG` and `X1 = xH`:

```text
R0 = rG
R1 = rH
e = H(context, X0, H, X1, R0, R1)
s = r + ex
verify: sG = R0 + eX0 and sH = R1 + eX1
```

All scalars are secp256k1 scalars. Statements, alternate generators, and proof
commitments use compressed non-identity SEC1 points.

## Transcript registry

Every field is absorbed as `tag_u16_be || length_u32_be || value`.

| Tag | Value |
| --- | --- |
| `1` | `seams/router-ab-ecdsa-presign/proof/v1` |
| `2` | `secp256k1+sha256` |
| `3` | 32-byte signing-scope digest |
| `4` | 32-byte presign-pair context digest |
| `5` | triple index: `0` or `1` |
| `6` | prover role: Client `1`, SigningWorker `2` |
| `7` | proof type: DLog `1`, DLogEq `2` |
| `8` | proof kind: triple-A `1`, triple-B `2`, product-share `3`; DLogEq product relation `1` |
| `16..20` | compressed statement and commitment points in equation order |
| `255` | two-byte big-endian challenge retry counter |

SHA-256 output is reduced modulo the secp256k1 scalar order. Zero challenges
retry with counters `0..255`; exhaustion returns a typed terminal error.

## Randomness and API boundary

Production proof functions accept a `CryptoRngCore` and generate fresh non-zero
nonces internally. Caller-supplied nonce APIs and `ProofNonce` exist only under
unit-test or `test-utils` compilation. The oracle crate is the only current
consumer of `test-utils`. Production dependency checks reject that feature.

Secret witness and nonce types expose no `Clone`, `Copy`, `Debug`, or broad
serialization. They zeroize on drop. Proof statements and outputs are public
protocol values.

## Integrated uses

The checked triple generator now uses all three DLog proof kinds and the DLogEq
product relation. It verifies peer proofs before checking the terminal product
and private sharing-polynomial equations. The complete mapping is recorded in
`committed-triple-finalization-v1.md`.
