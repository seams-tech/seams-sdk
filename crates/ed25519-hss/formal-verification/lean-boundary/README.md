# `ed25519-hss` Aeneas Lean Boundary Track

This directory is the future Aeneas-backed Rust-to-Lean boundary track for
`ed25519-hss`.

Its job is narrower than both the Verus and Lean privacy tracks:

- generate a Lean model mechanically from the Rust boundary slice
- keep that generated Rust boundary separate from handwritten privacy proofs
- prove bridge lemmas from the generated Rust boundary to the handwritten
  privacy boundary

This track is not intended to translate the full crate.
It is also not intended to replace the implementation-facing Verus work.
Implementation-specific boundary discipline stays in Verus; this Aeneas track
stops at the non-export privacy boundary.

Current status:

- the pinned Aeneas/Charon toolchain is installed locally
- the minimal helper slice through `extract_a_bytes_from_hash` can be extracted
  to Lean successfully
- the primary boundary artifact now comes from
  [`../../src/shared/reference_boundary.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/shared/reference_boundary.rs),
  which projects the three visible outputs from production `eval_f_expand`
- widening straight through `sha512_one_block` is still blocked on Charon
  failures once `sha2`/`digest` enters the graph
- the current generated-theorem cutoff is intentionally frozen at:
  - `GeneratedClientCannotDeriveYRelayer`
  - `GeneratedClientCannotDeriveTauRelayer`
  - `GeneratedServerCannotDeriveClientSecrets`
  - `GeneratedNonExportHiddenSeedIsHidden`

Out of scope here:

- explicit export boundary coverage
- runtime output packet boundary proofs
- operation-to-output-kind mapping
- boundary completeness theorems

Those implementation-facing guarantees stay in the Verus track.

The initial extraction scope is intentionally narrow:

- [`../../src/shared/reference.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/shared/reference.rs)
- only the subset needed to connect:
  - `eval_f_expand`
  - `canonical_seed`
  - `x_client_base`
  - `x_relayer_base`

## Commands

The bootstrap wrapper command is:

```sh
cargo hss-fv aeneas-check
just fv-aeneas
```

Today this command verifies:

- the `lean-boundary/` workspace builds with Lean
- the `aeneas` and `charon` binaries are present

It does not yet run extraction as part of the default proof path.
It is also not part of the default CI-gated command path.

The default gate is still:

- `pnpm check:formal-verification`

That default gate covers vectors, parity, Lean privacy, and Verus. Aeneas stays
opt-in because it is a narrower Rust-to-Lean bridge track rather than the main
implementation gate.

The current reproducible extraction script for the minimal helper slice is:

- [`scripts/extract-reference-minimal.sh`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/lean-boundary/scripts/extract-reference-minimal.sh)

The current reproducible extraction script for the main visible-boundary
artifact is:

- [`scripts/extract-visible-boundary.sh`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/lean-boundary/scripts/extract-visible-boundary.sh)

That script writes:

- [`generated/reference-minimal/ed25519_hss.llbc`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/lean-boundary/generated/reference-minimal/ed25519_hss.llbc)
- [`generated/reference-minimal-lean/Ed25519Hss.lean`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/lean-boundary/generated/reference-minimal-lean/Ed25519Hss.lean)
- [`generated/reference-minimal-lean/Funs.lean`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/lean-boundary/generated/reference-minimal-lean/Funs.lean)
- [`generated/reference-minimal-lean/Types.lean`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/lean-boundary/generated/reference-minimal-lean/Types.lean)

The main visible-boundary script writes:

- [`generated/visible-boundary-input/ed25519_hss.llbc`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/lean-boundary/generated/visible-boundary-input/ed25519_hss.llbc)
- [`generated/visible-boundary-package/Ed25519Hss/Funs.lean`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/lean-boundary/generated/visible-boundary-package/Ed25519Hss/Funs.lean)
- [`Ed25519Hss/Funs.lean`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/lean-boundary/Ed25519Hss/Funs.lean)
- [`Ed25519HssBoundary/GeneratedVisibleBoundary.lean`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/lean-boundary/Ed25519HssBoundary/GeneratedVisibleBoundary.lean)

The pinned toolchain metadata lives in:

- [`aeneas-toolchain.toml`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/lean-boundary/aeneas-toolchain.toml)

The bootstrap setup script is:

- [`scripts/setup-aeneas.sh`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/lean-boundary/scripts/setup-aeneas.sh)

The current pins are:

- Aeneas `42c0e90dacf486f7d3ed5b6cde3a9a81f04915a4`
- Charon `419f53b6eed3fe487a8427fd290a734c49634366`
- Lean `leanprover/lean4:v4.28.0-rc1`

## Layout

- `lakefile.lean`
- `lean-toolchain`
- `Ed25519HssBoundary.lean`
- `Ed25519HssBoundary/`
- `docs/`

See:

- [`docs/implementation-plan.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/lean-boundary/docs/implementation-plan.md)
