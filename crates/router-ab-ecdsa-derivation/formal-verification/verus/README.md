# `router-ab-ecdsa-derivation` Verus Track

This directory is the Verus implementation-proof track for the narrow stable
slice of [crates/router-ab-ecdsa-derivation](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation).

Current bootstrap scope after old-context removal:

- `encode_context_v2`
- canonical `x` derivation shape
- additive-share derivation with explicit retry/share-construction logic
- fixed participant-ID mapping with the actual `{1,2}` 2P mapping formula
- explicit-export output-policy shape
- initial true-blind role-local boundary mirror

This is intentionally narrower than the full privacy/boundary stack. The Aeneas
+ Lean bridge stays deferred until there is a stable Rust boundary to extract.

## Recommended Layout

- `Cargo.toml`
- `src/lib.rs`
- `src/shared/context.rs`
- `src/shared/derivation.rs`
- `src/shared/true_blind_boundary.rs`
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
  - `src/shared/true_blind_boundary.rs`
  - `src/integration/share_mapping.rs`
  - `src/server/policy.rs`
  - `src/server/state.rs`
- proof inventory exists at:
  [../docs/proof-inventory.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/formal-verification/docs/proof-inventory.md)
- the old executable fixture parity and hidden-eval anti-drift tests were
  removed with the old context version; new parity checks should target the
  active v2 crate API.

## Current Command Path

Current bootstrap commands:

- `just router-ab-ecdsa-derivation-fv-parity`
- `just router-ab-ecdsa-derivation-fv-verus`
- `just router-ab-ecdsa-derivation-fv`

`just router-ab-ecdsa-derivation-fv-verus` runs `cargo verus verify` for the narrow `router-ab-ecdsa-derivation`
Verus crate. `just router-ab-ecdsa-derivation-fv-parity` now runs the active V2 crate parity
test instead of the removed old executable parity tests.

## Current Proof Boundary

The current Verus boundary is frozen at:

- context encoding shape
- fixed `evm-family` key-scope encoding for EVM-family addresses
- canonical `x` derivation shape
- additive-share derivation with explicit retry/share-construction logic
- fixed participant-ID mapping with the actual `{1, 2}` mapping formula
- explicit-export output-policy shape
- finalized retained-state exclusion shape
- true-blind role-local wire/session boundary shape

Remaining outside this scope:

- cryptographic privacy claims
- backend-equivalence theorems beyond the current fixed-ID seam
- retained-state privacy claims beyond the modeled boundary shape
- end-to-end integration behavior

See:

- [docs/implementation-plan.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/formal-verification/verus/docs/implementation-plan.md)

