# `threshold-prf` V2 `t-of-N` Protocol And API Spec

Date created: June 12, 2026

## Scope

This document sketches a future generic `t-of-N` threshold-PRF protocol for
[crates/threshold-prf](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf).

V1 remains the fixed 2-of-3 protocol:

```text
threshold = 2
share_count = 3
valid_share_ids = {1, 2, 3}
combine_count = 2
```

V2 is a protocol/API revision. It should have separate types, vectors,
benchmarks, WASM bindings, and formal-verification models.

## Goals

- Support generic threshold policies with `1 <= t <= N`.
- Make invalid threshold policies unrepresentable after boundary parsing.
- Validate threshold subsets once before split, reconstruct, combine, or DLEQ
  verified-combine logic runs.
- Preserve fixed v1 vectors and wire formats.
- Keep v2 protocol selection explicit in Router/A/B, HSS integration, and WASM
  bindings.

## Non-Goals

- changing v1 behavior
- changing v1 wire formats
- migrating callers implicitly
- accepting raw unvalidated share sets in core logic
- adding a curve or hash abstraction
- implementing distributed key generation
- implementing distributed refresh in the first v2 slice

## Policy Model

Candidate policy type:

```rust
pub struct ThresholdPolicyV2 {
    threshold: NonZeroU16,
    share_count: NonZeroU16,
}
```

Boundary validation rules:

- `threshold >= 1`
- `share_count >= 1`
- `threshold <= share_count`
- `share_count <= MAX_SHARE_COUNT_V2`
- all share IDs are non-zero
- every share ID is unique within a policy
- every threshold subset has exactly `threshold` entries
- every threshold subset ID belongs to the policy ID set

The first implementation should use `u16` share IDs. That supports large signer
sets while keeping fixed-width encodings small. Move to `u32` only if product
requirements identify signer sets larger than `u16::MAX`.

## Internal State Shapes

Candidate validated subset type:

```rust
pub struct ValidatedThresholdSetV2<T> {
    policy: ThresholdPolicyV2,
    values: Vec<T>,
}
```

Construction should happen only at boundary helpers such as:

```rust
ValidatedThresholdSetV2<SigningRootShareV2>::from_shares(policy, shares)
ValidatedThresholdSetV2<PrfPartialV2>::from_partials(policy, partials)
ValidatedThresholdSetV2<PrfPartialProofBundleV2>::from_proof_bundles(policy, bundles)
```

Core functions should accept `ValidatedThresholdSetV2<T>` instead of raw slices.
That keeps subset-size, duplicate-ID, and policy-membership checks out of
interpolation and output logic.

## Wire Formats

V2 should introduce explicit v2 wire types:

```rust
SigningRootShareWireV2
PrfPartialWireV2
SigningRootShareCommitmentV2
PrfDleqProofV2
```

Preferred fixed-width shape for v2 share-bearing messages:

```text
u16be(share_id) || payload
```

Policy metadata should be carried out of band when the caller already has a
trusted protocol configuration. Self-describing wire messages can be added at
persistence or request boundaries that truly need them.

Do not mutate these v1 widths:

```text
SigningRootShareWireV1          = 33 bytes
PrfPartialWireV1                = 65 bytes
SigningRootShareCommitmentV1    = 33 bytes
PrfDleqProofV1                  = 64 bytes
```

## Lagrange Interpolation

V2 needs generic interpolation over any validated threshold subset:

```text
lambda_i = product over j != i of x_j / (x_j - x_i)
root     = sum(lambda_i * y_i)
Z        = sum(lambda_i * partial_i.point)
```

Inputs to interpolation:

- validated distinct share IDs
- exactly `threshold` shares or partials
- public share IDs converted to field elements

The interpolation helper must reject duplicate IDs before any inversion. The
branching is over public IDs and subset shape.

## Public Rust API Sketch

Candidate split and combine APIs:

```rust
pub fn split_signing_root_v2<R>(
    root: &SigningRootScalar,
    policy: ThresholdPolicyV2,
    rng: &mut R,
) -> ThresholdPrfResult<Vec<SigningRootShareV2>>
where
    R: RngCore + CryptoRng;

pub fn reconstruct_signing_root_v2(
    policy: ThresholdPolicyV2,
    shares: ValidatedThresholdSetV2<SigningRootShareV2>,
) -> ThresholdPrfResult<SigningRootScalar>;

pub fn combine_partials_v2(
    policy: ThresholdPolicyV2,
    partials: ValidatedThresholdSetV2<PrfPartialV2>,
    context: &PrfContext,
) -> ThresholdPrfResult<PrfOutput32>;

pub fn combine_verified_partials_v2(
    policy: ThresholdPolicyV2,
    bundles: ValidatedThresholdSetV2<PrfPartialProofBundleV2>,
    context: &PrfContext,
) -> ThresholdPrfResult<PrfOutput32>;
```

The final function signatures can omit `policy` when the validated set carries
the policy and exposes it through a narrow accessor.

## WASM API Sketch

Keep v1 exports as explicit v1 functions. Add v2 exports with policy-shaped
inputs:

```text
threshold_prf_v2_derive_ecdsa_hss_y_relayer(policy, share_wires, context_fields)
threshold_prf_v2_derive_ed25519_hss_server_inputs(policy, share_wires, context_fields)
threshold_prf_v2_combine_partials(policy, partial_wires, context)
threshold_prf_v2_combine_verified_partials(policy, proof_bundle_wires, context)
```

WASM boundary parsing should normalize raw JS values into precise internal
policy and wire types once. Core Rust should never receive raw JS arrays,
partial objects, or stringly typed threshold settings.

## Router/A/B Selection

Router/A/B should select v1 or v2 through explicit protocol configuration:

```text
threshold_prf_protocol = "v1-2-of-3" | "v2-t-of-n"
```

That selection must feed:

- context construction
- WASM binding selection
- stored vector corpus selection
- benchmark labels
- formal-verification claim labels

Mixed v1/v2 combine inputs should be rejected at the protocol boundary.

## Vectors

V2 vectors should live in a separate corpus, for example:

```text
fixtures/protocol-v2-t-of-n.json
```

Minimum vector matrix:

- `N = 3, t = 2`
- `N = 5, t = 3`
- `N = 7, t = 5`
- every valid subset size for each policy
- ordered and reversed subset cases
- duplicate-ID rejection
- insufficient-subset rejection
- oversized-subset rejection
- wrong-policy-ID rejection
- DLEQ verified-combine for more than two partials

V2 must prove that the v2 2-of-3 policy matches v1 only if a compatibility claim
is explicitly needed. The default stance is separate vectors and separate
protocol labels.

## Formal Verification

V2 needs a new threshold-set model. The model should cover:

- policy validation
- subset membership
- duplicate rejection
- generic Lagrange coefficient shape
- direct-vs-threshold equivalence for arbitrary valid threshold subsets
- wire-policy binding
- DLEQ verified-combine with `threshold` proof bundles

The current v1 Verus and Lean tracks should keep their v1 names and fixed 2-of-3
assumptions.

## Performance

V2 performance work should start with benchmarks:

- native generic interpolation for several `(t, N)` policies
- local Node/V8 WASM generic interpolation
- deployed Worker benchmarks for HSS-facing v2 exports
- comparison against the specialized v1 2-of-3 path

Keep the v1 specialized path unless benchmark evidence shows one generic path
is simpler and still comfortably below the Worker latency budget.

## First Implementation Slice

1. Add `ThresholdPolicyV2` and validation tests.
2. Add `ValidatedThresholdSetV2<T>` for shares only.
3. Implement generic split and reconstruct.
4. Add v2 vector generation for `N = 3, t = 2` and `N = 5, t = 3`.
5. Add generic partial combine.
6. Add v2 WASM exports for Option A only.
7. Add deployed Worker benchmarks for the v2 Option A exports.
8. Extend FV with policy and generic subset proofs.

Keep DLEQ v2 and distributed refresh as follow-up slices unless product claims
require them in the first release.
