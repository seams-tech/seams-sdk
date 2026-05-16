# `ecdsa-hss` Aeneas Lean Boundary Track

This directory is the narrow Rust-to-Lean boundary track for `ecdsa-hss`.

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
- the extraction target is now frozen to the narrow boundary slice
- the Lean workspace exists and builds locally
- a narrow Rust extraction facade now exists at:
  [`../../src/server/reference_boundary.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/server/reference_boundary.rs)
- the pinned `aeneas` and `charon` toolchain is installed locally
- the first Rust extraction artifact now exists under:
  - [`generated/visible-boundary-input/ecdsa_hss.llbc`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-boundary/generated/visible-boundary-input/ecdsa_hss.llbc)
  - [`generated/visible-boundary-package/EcdsaHss/Funs.lean`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-boundary/generated/visible-boundary-package/EcdsaHss/Funs.lean)
- the checked-in generated package now lives in:
  - [`EcdsaHss/Funs.lean`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-boundary/EcdsaHss/Funs.lean)
  - [`EcdsaHss/Types.lean`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-boundary/EcdsaHss/Types.lean)
  - [`EcdsaHss/FunsExternal.lean`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-boundary/EcdsaHss/FunsExternal.lean)
- the handwritten boundary model is now typed to the generated field layout in:
  - [`EcdsaHssBoundary/Scope.lean`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-boundary/EcdsaHssBoundary/Scope.lean)
- the current bridge lemmas now live in:
  - [`EcdsaHssBoundary/GeneratedVisibleBoundary.lean`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-boundary/EcdsaHssBoundary/GeneratedVisibleBoundary.lean)
- the narrow generated boundary now matches the handwritten boundary model for:
  - operation-to-output-kind boundary shape
  - non-export visible output shape
  - explicit-export visible output shape
  - finalized retained-state shape

The initial extraction scope is intentionally narrow:

- [`../../src/server/reference_boundary.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/server/reference_boundary.rs)
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

The boundary command is:

```sh
just ecdsa-hss-fv-boundary
```

Today that command:

- regenerates the narrow boundary artifact with Charon + Aeneas
- copies the generated Lean package into `EcdsaHss/`
- builds the Lean workspace

It is part of the default crate-local `ecdsa-hss` proof path through
`just ecdsa-hss-fv`; its scope remains limited to boundary extraction and the
Lean workspace build.

The setup script for the extraction toolchain is:

- [`scripts/setup-aeneas.sh`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-boundary/scripts/setup-aeneas.sh)

The pinned toolchain metadata lives in:

- [`aeneas-toolchain.toml`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-boundary/aeneas-toolchain.toml)

The reproducible extraction script is:

- [`scripts/extract-visible-boundary.sh`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-boundary/scripts/extract-visible-boundary.sh)

## Layout

- `lakefile.lean`
- `lean-toolchain`
- `EcdsaHssBoundary.lean`
- `EcdsaHssBoundary/`
- `docs/`
- `scripts/`

See:

- [`docs/implementation-plan.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-boundary/docs/implementation-plan.md)
