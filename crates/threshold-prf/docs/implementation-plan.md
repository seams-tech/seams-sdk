# `threshold-prf` Implementation Plan

Last updated: June 13, 2026

## Current State

The crate implements the active configurable `t-of-N` threshold-prf protocol.
The public Rust API is `threshold_prf`; the crate root exposes context,
purpose, suite, output, error, threshold-policy, wire, split, partial
evaluation, proof, and combine APIs.

The fixed-pair public API, fixed-pair fixture corpus, fixed-pair WASM exports,
and fixed-pair benchmark labels have been removed.

## Implemented API

`threshold_prf` exports:

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
- `generate_signing_root`
- `split_signing_root`
- `reconstruct_signing_root`
- `evaluate_direct_reference`
- `evaluate_partial`
- `evaluate_partial_with_dleq_proof`
- `verify_partial_dleq_proof`
- `combine_partials`
- `combine_verified_partials`

## Implemented Wire Formats

The canonical API wire widths:

| Wire | Width |
| --- | ---: |
| signing-root share wire | 34 bytes |
| partial wire | 66 bytes |
| share commitment wire | 34 bytes |
| DLEQ proof wire | 64 bytes |
| proof bundle wire | 164 bytes |

Share IDs are `u16` and are validated against the selected `ThresholdPolicy`.
Subset validation rejects wrong subset size, duplicate share IDs, and share IDs
outside the policy before combine or verified-combine logic runs.

## Implemented Runtime Boundaries

- Native Rust Criterion benchmark coverage for `2-of-3` and `3-of-5`.
- Local Node/V8 WASM benchmark coverage for Option A and DLEQ paths.
- Production WASM exports for HSS derivation and distributed combine.
- Generated package smoke tests for output fixtures and rejection cases.
- Server SDK signing-root resolver boundaries.
- Router/A/B Candidate A backend integration through `threshold_prf`.

## Implemented Verification

- protocol tests
- committed fixture anti-drift tests
- formal-verification model
- FV parity tests
- Lean privacy model

Current validation command:

```bash
just threshold-prf-fv
```

## Remaining Work

1. Complete the Router/A/B and server SDK `V1` naming audit. Retain suffixes
   only for active serialized Router/A/B or persistence boundaries.
2. Defer deployed Cloudflare Worker benchmarks until live testing resumes.
3. Add broader downstream Router/A/B policy coverage only after the public
   Router/A/B protocol shape is updated for configurable threshold policies.
4. Continue the FV plan with generic reconstruction and DLEQ verified-combine
   proof obligations.
