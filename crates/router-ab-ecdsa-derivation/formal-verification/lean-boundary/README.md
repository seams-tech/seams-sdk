# `router-ab-ecdsa-derivation` Aeneas Lean Boundary Track

This directory is the narrow Rust-to-Lean boundary track for `router-ab-ecdsa-derivation`.

Its job is intentionally smaller than the Verus track:

- freeze the extraction target to the non-export/export boundary slice
- keep the generated Rust boundary separate from handwritten Lean boundary
  lemmas
- provide a reproducible local extraction path for the staged boundary slice

This track is not the full privacy stack.
It is also not the main implementation gate.
The implementation-facing guarantees stay in Verus.

Current status:

- the Verus stable slice is complete and green
- a non-production Rust extraction crate mirrors the role-local boundary without
  reintroducing joined-root production APIs
- the Lean workspace exists and builds locally
- the pinned `aeneas` and `charon` toolchain is installed locally
- the Rust extraction artifact is generated under:
  - [`generated/visible-boundary-input/router_ab_ecdsa_derivation.llbc`](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/formal-verification/lean-boundary/generated/visible-boundary-input/router_ab_ecdsa_derivation.llbc)
  - [`generated/visible-boundary-package/RouterAbEcdsaDerivation/Funs.lean`](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/formal-verification/lean-boundary/generated/visible-boundary-package/RouterAbEcdsaDerivation/Funs.lean)
- the checked-in generated package lives in:
  - [`RouterAbEcdsaDerivation/Funs.lean`](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/formal-verification/lean-boundary/RouterAbEcdsaDerivation/Funs.lean)
  - [`RouterAbEcdsaDerivation/Types.lean`](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/formal-verification/lean-boundary/RouterAbEcdsaDerivation/Types.lean)
- the handwritten boundary model is typed to that generated field layout in:
  - [`RouterAbEcdsaDerivationBoundary/Scope.lean`](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/formal-verification/lean-boundary/RouterAbEcdsaDerivationBoundary/Scope.lean)
- the bridge lemmas live in:
  - [`RouterAbEcdsaDerivationBoundary/GeneratedVisibleBoundary.lean`](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/formal-verification/lean-boundary/RouterAbEcdsaDerivationBoundary/GeneratedVisibleBoundary.lean)
- the generated boundary matches the handwritten boundary model for:
  - operation-to-output-kind boundary shape
  - non-export visible output shape
  - explicit-export visible output shape
  - finalized retained-state shape
  - hidden-eval input, transport, and persisted-state shape

The extraction scope is intentionally narrow:

- only the subset needed to connect:
  - non-export visible outputs
  - explicit export visible outputs
  - finalized retained-state boundary
  - operation-to-output-kind boundary

Out of scope here:

- canonical `x` algebraic correctness
- additive-share derivation correctness
- backend share-mapping correctness
- full privacy theorems beyond the handwritten boundary model

Those stay in the Verus track until the Rust-to-Lean bridge is real.

## Commands

Run the boundary extraction and Lean bridge check with:

```sh
just router-ab-ecdsa-derivation-fv-boundary
```

The default crate-local `router-ab-ecdsa-derivation` proof path includes Verus parity, Verus
verification, the Aeneas boundary extraction, and the Lean privacy workspace.

The setup script for the extraction toolchain is:

- [`scripts/setup-aeneas.sh`](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/formal-verification/lean-boundary/scripts/setup-aeneas.sh)

The pinned toolchain metadata lives in:

- [`aeneas-toolchain.toml`](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/formal-verification/lean-boundary/aeneas-toolchain.toml)

The reproducible extraction script is:

- [`scripts/extract-visible-boundary.sh`](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/formal-verification/lean-boundary/scripts/extract-visible-boundary.sh)

## Layout

- `lakefile.lean`
- `lean-toolchain`
- `RouterAbEcdsaDerivationBoundary.lean`
- `RouterAbEcdsaDerivationBoundary/`
- `docs/`
- `scripts/`

See:

- [`docs/implementation-plan.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/formal-verification/lean-boundary/docs/implementation-plan.md)

