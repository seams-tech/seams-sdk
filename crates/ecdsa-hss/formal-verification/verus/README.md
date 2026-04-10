# `ecdsa-hss` Verus Track

This directory is the Verus implementation-proof track for the narrow stable
slice of [crates/ecdsa-hss](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss).

Current bootstrap scope:

- `encode_context_v1`
- canonical `x` derivation shape
- additive-share derivation with explicit retry/share-construction logic
- fixed participant-ID mapping with the actual `{1,2}` 2P mapping formula
- explicit-export output-policy shape

This is intentionally not the full privacy/boundary stack yet. The Aeneas +
Lean tracks stay deferred until there is a stable Rust boundary to extract.

## Recommended Layout

- `Cargo.toml`
- `src/lib.rs`
- `src/shared/context.rs`
- `src/shared/derivation.rs`
- `src/integration/share_mapping.rs`
- `src/server/policy.rs`
- `src/server/state.rs`
- `docs/implementation-plan.md`

The verification crate should mirror the future production module layout
closely enough to prevent drift, without pulling in the production runtime or
pretending the full protocol is already implemented.

## Current Bootstrap Status

- `Cargo.toml` exists
- `src/lib.rs` exists
- the narrow stable-slice mirror exists under:
  - `src/shared/context.rs`
  - `src/shared/derivation.rs`
  - `src/integration/share_mapping.rs`
  - `src/server/policy.rs`
  - `src/server/state.rs`
- fixture parity test exists at:
  [tests/fixture_parity.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/verus/tests/fixture_parity.rs)
- hidden-eval/runtime-seam anti-drift tests now exist at:
  [tests/anti_drift.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/verus/tests/anti_drift.rs)
- proof inventory exists at:
  [../docs/proof-inventory.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/docs/proof-inventory.md)
- fixed-function corpus exists at:
  [../../fixtures/phase1_v1.json](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/fixtures/phase1_v1.json)

## Current Command Path

Current bootstrap commands:

- `just ecdsa-hss-fv-parity`
- `just ecdsa-hss-fv-verus`
- `just ecdsa-hss-fv`

`just ecdsa-hss-fv-verus` runs `cargo verus verify` for the narrow `ecdsa-hss`
Verus crate. `just ecdsa-hss-fv` runs the executable FV test suite first
(fixture parity plus hidden-eval anti-drift) and then runs the Verus verifier.

## Current Proof Boundary

The current Verus boundary is frozen at:

- context encoding shape
- canonical `x` derivation shape
- additive-share derivation with explicit retry/share-construction logic
- fixed participant-ID mapping with the actual `{1, 2}` mapping formula
- explicit-export output-policy shape
- finalized retained-state exclusion shape

It does not yet try to prove:

- cryptographic privacy claims
- backend-equivalence theorems beyond the current fixed-ID seam
- retained-state privacy claims
- end-to-end integration behavior

See:

- [docs/implementation-plan.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/verus/docs/implementation-plan.md)
