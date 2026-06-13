# `threshold-prf` `t-of-N` Protocol And API Spec

Last updated: June 13, 2026

## Scope

This document specifies the active configurable `t-of-N` threshold-prf API
for [crates/threshold-prf](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf).

The canonical API is the only active threshold-prf public protocol surface. Downstream
Router/A/B may still use `/v1` in purpose labels or serialized Router/A/B
request fields; those names identify Router/A/B protocol versions.

## Suite

```text
threshold-prf/ristretto255-sha512
```

The suite uses:

- Ristretto255
- canonical `curve25519-dalek` scalar encodings
- SHA-512 for hash-to-group input expansion
- SHA-512 for output hashing
- Shamir sharing over the Ristretto scalar field

## Policy

```text
1 <= threshold <= share_count <= MAX_SHARE_COUNT
valid_share_ids = {1, ..., share_count}
combine_count = threshold
```

Raw threshold policy input is normalized into `ThresholdPolicy` once at the
boundary. Core split, reconstruct, combine, and verified-combine logic receives
validated policy and subset types.

## Rust API

Callers import operations from `threshold_prf`:

```rust
use threshold_prf::{
    combine_partials,
    combine_verified_partials,
    evaluate_partial,
    split_signing_root,
    ThresholdPolicy,
    ValidatedThresholdSet,
};
```

The module exports:

- `ThresholdPolicy`
- `ThresholdShareId`
- `ValidatedThresholdSet<T>`
- `SigningRootScalar`
- `SigningRootShare`
- `SigningRootShareWire`
- `PrfPartial`
- `PrfPartialWire`
- `SigningRootShareCommitment`
- `PrfDleqProof`
- `PrfPartialProofBundle`
- split, reconstruct, partial evaluation, DLEQ proof, combine, and
  verified-combine functions

## Wire Formats

All integer fields are big-endian.

| Wire | Layout | Width |
| --- | --- | ---: |
| signing-root share | `u16be(share_id) || scalar[32]` | 34 bytes |
| partial | `u16be(share_id) || context_tag[32] || compressed_point[32]` | 66 bytes |
| commitment | `u16be(share_id) || compressed_point[32]` | 34 bytes |
| DLEQ proof | `challenge_scalar[32] || response_scalar[32]` | 64 bytes |
| proof bundle | partial wire + commitment wire + proof wire | 164 bytes |

Wire decoding validates fixed width, canonical scalar encodings where relevant,
compressed point encodings where relevant, and non-zero share IDs. Policy
membership is checked when the decoded item enters a `ValidatedThresholdSet`.

## Purposes

Current fixed purposes:

- `ecdsa-hss/y_relayer`
- `ed25519-hss/y_relayer`
- `ed25519-hss/tau_relayer`
- `router-ab/x_client_base/v1`
- `router-ab/x_relayer_base/v1`

The Router/A/B purpose suffixes are Router/A/B transcript-version names. They
do not version the threshold-prf protocol.

## DLEQ

Verified combine requires each proof bundle to bind:

- share ID
- partial point
- share commitment
- context tag
- PRF context

The combiner rejects malformed proofs, wrong context tags, mismatched
commitments, duplicate share IDs, wrong subset size, and share IDs outside the
selected policy.

## WASM Boundary

The production WASM exports use explicit `threshold_prf_` names. Boundary
inputs are raw JS numbers and byte arrays; the WASM wrapper normalizes them into
policy and wire types before calling core Rust logic.

Current exported boundary groups:

- ECDSA HSS `y_relayer`
- Ed25519 HSS server inputs
- partial combine
- verified partial combine

## Fixtures And Verification

Committed fixtures cover:

- `2-of-3`
- `3-of-5`
- Router/A/B `2-of-3` context bytes through the suite label

Current validation:

```bash
cargo test --manifest-path crates/threshold-prf/Cargo.toml
just threshold-prf-fv
just threshold-prf-wasm-smoke
```
