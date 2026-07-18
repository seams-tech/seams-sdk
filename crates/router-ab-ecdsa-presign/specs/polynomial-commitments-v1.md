# Fixed polynomial commitments v1

Status: implemented and integrated. OT, MTA, proof integration, polynomial
aggregation, and terminal triple validation consume this layer in the complete
fixed backend. Independent cryptographic review remains the promotion gate.

## Source mapping

The behavioral source is NEAR `threshold-signatures` commit
`db609be5021eb9d794f577601f422818fbdfe246`, Git tree
`05f60d54971e2f1e417dab7191f0f5d02f82468c`.

| ID | Pinned source evidence | Purpose-built implementation | Alignment | Confidence |
| --- | --- | --- | --- | --- |
| `POLY-SHAPE-01` | `src/ecdsa/ot_based_ecdsa/triples/generation.rs:523-539` creates degree `threshold - 1` `E` and `F` and degree `threshold - 2` `L`; fixed `threshold = 2` gives degrees one, one, and zero | `src/triples.rs:102-158` stores exactly two scalar coefficients for `E` and `F` and one for `L` | Full fixed-parameter match | `1.00` |
| `POLY-COMMIT-01` | `src/crypto/polynomials.rs:165-177` commits each scalar coefficient as `coefficient * G` | `src/triples.rs:116-120,144-149` computes the same coefficient commitments | Full mathematical match | `1.00` |
| `POLY-DEGREE-01` | `src/ecdsa/ot_based_ecdsa/triples/generation.rs:733-741` rejects `E`, `F`, or `L` with the wrong degree | `src/triples.rs:70-89` accepts exactly five non-identity coefficients in the fixed one/one/zero shape | Code is structurally stronger than the runtime vector-length check | `0.98` |
| `POLY-OPEN-01` | `src/crypto/commitment.rs:19-40` hashes a randomizer and serialized polynomial commitments, then compares the digest in constant time; generation uses it at `triples/generation.rs:541-543` and verifies it at `743-754` | `src/triples.rs:487-510,541-575,631-660` hashes a fixed tagged encoding and verifies with constant-time equality | Full commit/open behavior; deliberate encoding and domain divergence | `1.00` |
| `POLY-EVAL-01` | `src/crypto/polynomials.rs:102-130` evaluates scalar polynomials and `286-308` evaluates coefficient commitments at a participant coordinate | `src/triples.rs:57-60,123-125,152-156` specializes both equations to a linear polynomial | Full mathematical match | `1.00` |
| `POLY-SHARE-01` | `src/ecdsa/ot_based_ecdsa/triples/generation.rs:789-820` sums received evaluations and requires `E(z_i) = a_i G` and `F(z_i) = b_i G` | `src/triples.rs:405-420,455-484,577-609` emits and verifies the peer contribution at fixed coordinate `2` or `3`; `src/triples/finalize.rs` integrates the aggregated product/share equations | Full fixed-role share and aggregation path | `0.98` |
| `POLY-RNG-01` | `src/crypto/polynomials.rs:56-90` samples polynomial coefficients with `CryptoRngCore`; degree-zero all-zero generation aborts and a zero highest coefficient is later rejected by the degree check | `src/triples.rs:108-141,621-629` samples each required coefficient as non-zero with bounded retries | Code is stronger and preserves the accepted exact-degree distribution up to rejection sampling | `0.95` |

Line numbers refer to the pinned source and the checkpoint-3 formatted source.
Later edits must update this table alongside the code.

## Fixed representation and equations

For each role and triple index:

```text
E(x) = e0 + e1*x
F(x) = f0 + f1*x
L(x) = l0

BigE(x) = e0*G + (e1*G)*x
BigF(x) = f0*G + (f1*G)*x
BigL(0) = l0*G
```

All five coefficients are non-zero secp256k1 scalars. This guarantees the
fixed degree and makes each compressed coefficient commitment a non-identity
SEC1 point. A polynomial evaluation may be zero; private share messages accept
canonical zero scalars and validate them through the public equation.

The fixed coordinates are Client `2` and SigningWorker `3`. A sender evaluates
its `E` and `F` at the recipient coordinate. Verification requires:

```text
BigE(z_recipient) = e_share*G
BigF(z_recipient) = f_share*G
```

The verified opening is opaque and retains its signing-scope digest,
presign-pair digest, and triple index. Share verification checks those bindings
again before evaluating either equation.

## Commitment transcript

Every field is absorbed as `tag_u16_be || length_u32_be || value`.

| Tag | Value |
| --- | --- |
| `1` | `seams/router-ab-ecdsa-presign/polynomial-opening/v1` |
| `2` | `secp256k1+sha256` |
| `3` | 32-byte signing-scope digest |
| `4` | 32-byte presign-pair digest |
| `5` | triple index: `0` or `1` |
| `6` | prover role: Client `1`, SigningWorker `2` |
| `16` | compressed `e0*G` |
| `17` | compressed `e1*G` |
| `18` | compressed `f0*G` |
| `19` | compressed `f1*G` |
| `20` | compressed `l0*G` |
| `21` | 32-byte opening randomizer |

The commitment digest is SHA-256 over the complete tagged encoding. Role
binding prevents reflection. The scope, pair, and triple fields prevent reuse
across sessions or triple slots. This transcript intentionally replaces NEAR's
generic MessagePack encoding with one fixed canonical representation.

## Claim boundary

This layer specifies the committed polynomial shape, opening, and per-peer
`E`/`F` share equations. Knowledge proofs, multiplication output binding to
`L`, aggregation, and the terminal `c = ab` relation are implemented by the
proof, MTA, and committed-triple finalization layers referenced by
`assurance-ledger-v1.md`. This layer alone makes no complete-construction
security claim.
