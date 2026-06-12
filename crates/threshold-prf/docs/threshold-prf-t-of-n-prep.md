# `threshold-prf` `t-of-N` Refactor Preparation Plan

Date created: June 12, 2026

## Scope

This plan prepares
[crates/threshold-prf](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf)
for a future generic `t-of-N` threshold-PRF protocol.

Version 1 remains fixed 2-of-3. This plan should make that fixed shape
explicit, localized, and easy to replace later. It should not implement
generic `t-of-N`, change v1 wire formats, change v1 vectors, or add unused
generic abstractions.

## Current V1 Policy

The current protocol policy is:

```text
threshold = 2
share_count = 3
valid_share_ids = {1, 2, 3}
combine_count = 2
```

Current public v1 APIs encode this directly:

- `split_signing_root_2_of_3`
- `reconstruct_signing_root_2_of_3`
- `refresh_signing_root_shares_2_of_3`
- `derive_output_from_signing_root_shares`
- `derive_output_from_signing_root_share_wires`
- `combine_partials`
- `combine_verified_partials`

The future `t-of-N` refactor should be a v2 protocol/API revision. V1 should
stay stable for existing vectors, WASM bindings, Router/A/B adapters, and HSS
integration.

## Goals

- Make every fixed 2-of-3 assumption easy to find.
- Keep v1 behavior byte-for-byte unchanged.
- Create clear internal seams for future `ValidatedThresholdSet` style inputs.
- Keep current FV and vector coverage focused on v1.
- Avoid speculative generic APIs that are not needed by current callers.

## Non-Goals

- implementing generic `t-of-N`
- changing share ID encoding
- changing v1 wire formats
- changing v1 purpose labels or output encodings
- changing committed vectors
- changing WASM exports
- introducing a generic curve or field abstraction
- preserving a compatibility path inside core logic after a future v2 lands

## Phase 1: Name And Document V1 Policy

- [x] Add a short v1 threshold-policy section to
  [protocol.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/docs/protocol.md)
  with:
  - `threshold = 2`
  - `share_count = 3`
  - `valid_share_ids = {1, 2, 3}`
  - `combine_count = 2`
- [x] Add the same policy summary to
  [README.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/README.md).
- [x] Add tests that assert the current v1 share ID domain accepts only `1`,
  `2`, and `3`.
- [x] Add tests that assert one-share, three-share, and duplicate-share inputs
  fail through the intended errors.

Exit criteria:

- v1 fixed policy is visible in docs and tests
- no API suggests generic threshold behavior

## Phase 2: Localize Fixed Pair Validation

Introduce private pair-shaped boundary helpers. Public APIs may keep slices for
now, but all v1 core logic should receive validated pair shapes.

Candidate private types:

```rust
struct SigningRootSharePair<'a> {
    left: &'a SigningRootShare,
    right: &'a SigningRootShare,
}

struct PrfPartialPair<'a> {
    left: &'a PrfPartial,
    right: &'a PrfPartial,
}

struct PrfProofBundlePair<'a> {
    left: &'a PrfPartialProofBundleV1,
    right: &'a PrfPartialProofBundleV1,
}
```

Tasks:

- [x] Replace ad hoc internal `[left, right]` validation returns with private
  pair types.
- [x] Keep public error behavior unchanged:
  - wrong subset size -> `InvalidThresholdSubset`
  - duplicate share ID -> `DuplicateShareId`
- [x] Route `derive_output_from_signing_root_shares`,
  `combine_partials`, and `combine_verified_partials` through the pair helpers.
- [x] Add focused tests proving the public APIs still reject invalid subset
  shapes.

Exit criteria:

- v1 pair validation has one implementation per domain shape
- future v2 can replace pair types with threshold-set types without searching
  through combine logic

## Phase 3: Isolate Lagrange Math

The current coefficient calculation is v1-specific. Make that explicit.

Tasks:

- [x] Rename or wrap the current coefficient function as
  `lagrange_coefficients_2_of_3`.
- [x] Remove the old internal function name instead of preserving a delegating
  shim.
- [x] Add tests for every ordered valid v1 pair:
  - `(1, 2)`
  - `(2, 1)`
  - `(1, 3)`
  - `(3, 1)`
  - `(2, 3)`
  - `(3, 2)`
- [x] Add tests proving duplicate IDs fail before coefficient use.

Exit criteria:

- all v1 interpolation math is behind a v1-specific seam
- future generic Lagrange code has an obvious replacement point

## Phase 4: Keep Wire Types Explicitly Versioned

The v1 wire types should remain fixed-width and versioned. A future `t-of-N`
revision can add new types if the encoding changes.

Tasks:

- [x] Audit docs and comments for generic wording around:
  - `SigningRootShareWireV1`
  - `PrfPartialWireV1`
  - `SigningRootShareCommitmentV1`
  - `PrfDleqProofV1`
- [x] Ensure each wire type states its v1 width and v1 assumptions.
- [x] Add source guards or tests that pin the fixed widths.
- [x] Document that generic `t-of-N` may require `V2` wire types if share ID,
  threshold policy, or proof bundle metadata changes.

Exit criteria:

- v1 wire formats remain stable and visibly fixed
- future v2 wire design cannot accidentally mutate v1 in place

## Phase 5: FV And Vector Preparation

Keep the existing FV model v1-specific. Add only prep that makes future v2
work easier.

Tasks:

- [x] Add a v1 threshold-policy model section to the Verus documentation.
- [x] Keep the current Verus proofs named or documented as 2-of-3/v1 proofs.
- [x] Add a short future-work note in
  [threshold-prf-formal-verification-2.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/docs/threshold-prf-formal-verification-2.md)
  explaining that generic `t-of-N` needs a new threshold-set model.
- [x] Document that v2 vectors must include:
  - multiple `N` values
  - multiple `t` values
  - all valid subset sizes
  - duplicate and insufficient-subset rejection
  - DLEQ verified-combine cases for more than two partials

Exit criteria:

- FV docs clearly separate v1 2-of-3 proofs from future `t-of-N` proof work
- vector expectations for future v2 are written down

## Phase 6: V2 API Sketch

Write a design stub only. Do not implement it.

Expanded spec:
[threshold-prf-v2-t-of-n-spec.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/docs/threshold-prf-v2-t-of-n-spec.md)

Candidate API sketch:

```rust
pub struct ThresholdPolicyV2 {
    pub threshold: NonZeroU16,
    pub share_count: NonZeroU16,
}

pub struct ValidatedThresholdSetV2<T> {
    policy: ThresholdPolicyV2,
    values: Vec<T>,
}
```

Questions to answer in the stub:

- Share ID range: support non-zero numeric share IDs and choose the maximum
  after the largest expected deployment size is known.
- Share ID width: prefer `u16` unless deployment requirements justify `u32`.
  Avoid variable-length IDs unless wire compactness or external identifiers
  require them.
- Wire formats: keep v2 wire formats fixed-width when threshold policy is
  carried out of band. Add explicit policy metadata only at protocol boundaries
  that need self-describing messages.
- WASM APIs: expose policy-shaped constructors and validated threshold-set
  combine APIs. Leave v1 bindings as explicit v1 exports.
- Specialization: keep optimized v1 2-of-3 paths. Add v2 specialization for
  common policies after benchmarks show generic interpolation cost matters.
- Vector separation: store v1 and v2 vectors as separate corpora with separate
  suite or protocol version labels.
- Router/A/B selection: route by an explicit protocol version in Router/A/B
  config and context construction, then pass that version into the threshold-PRF
  binding layer.

Exit criteria:

- future `t-of-N` design questions are explicit
- v1 implementation remains unchanged

## Recommended Order

1. Name and document v1 policy.
2. Localize fixed pair validation.
3. Isolate Lagrange math.
4. Audit v1 wire type wording.
5. Update FV/vector prep notes.
6. Write the v2 API sketch.

If only one preparation slice is funded, do Phases 1 and 2. They provide the
best future leverage without adding speculative generic code.

## API-Neutral Follow-Up Prep

Implemented after the initial prep:

- [x] Add a private threshold-policy shape for internal validation.
- [x] Route v1 share, partial, and proof-bundle subset validation through one
  v1 policy helper.
- [x] Add a private generic Lagrange-at-zero helper.
- [x] Keep the public 2-of-3 APIs, v1 wire formats, vectors, and WASM exports
  unchanged.
- [x] Add hidden 3-of-5 interpolation tests to exercise the future math seam.
- [x] Add a local ignored timing harness for private generic interpolation:
  `just threshold-prf-t-of-n-prep-bench`.
- [x] Extend the local timing harness to separate:
  - Lagrange coefficient computation for `2-of-3`, `3-of-5`, and `5-of-7`
  - point interpolation for those same private generic policies
  - current v1 partial evaluation, combine, share-wire derive, DLEQ proof, and
    verified-combine costs
- [x] Add private `5-of-7` scalar and point interpolation tests for the future
  generic combine seam.

Remaining for the public v2 refactor:

- introduce public v2 policy and share-id types
- add v2 wire types and vector corpus
- expose v2 WASM bindings
- extend benchmarks and FV models to generic threshold sets
