# `signer-core` Formal Verification

This directory contains the `signer-core` formal-verification track.

The current implementation follows the plan in:

- [`../docs/formal-verification-plan.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-core/docs/formal-verification-plan.md)
- [`../docs/formal-verification-proof-inventory.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-core/docs/formal-verification-proof-inventory.md)

## Current Strategy

The active strategy is:

- Verus first
- executable anti-drift checks against production helpers
- no standalone Lean boundary/privacy track initially

That matches the role of `signer-core`: it is a shared helper crate, not a
crate-local privacy boundary.

The Phase 5 Aeneas + Lean decision has been made for the current scope:
do not add a signer-core Lean track yet. Revisit only if a stable, shared
Rust-facing boundary becomes proof-relevant on its own.

Current status: the signer-core Verus-first scope is complete for the current
plan. The full repository FV command, `just fv`, passed on 2026-04-16.

## Current Scope

The first implemented slice covers the high-impact `secp256k1` helper seam:

1. HKDF-output-to-nonzero-scalar reduction shape
2. relayer-share derivation output shape
3. canonical secp256k1 keypair derivation output shape
4. fixed `{1, 2}` additive-share mapping formula
5. public-key helper output-shape invariants
6. committed secp256k1 fixture corpus and executable anti-drift checks for
   production output layout and mapping

The first `near_threshold_ed25519` model has also started. It currently covers:

1. threshold client signing-share derivation shape
2. non-zero signing-share output
3. verifying-share-from-signing-share relation
4. fixed 32-byte signing/verifying-share layout
5. participant-ID normalization and 2P validation shape
6. key-package construction shape
7. NEP-413 digest construction and exact nonce-length shape
8. committed Ed25519 derivation and NEP-413 fixtures with anti-drift checks

The current Verus model still treats cryptographic primitives and external
library internals as trusted boundaries. The executable checks pin those
boundaries to production behavior for representative vectors and scalar-domain
edge cases.

## Commands

Run the current signer-core formal-verification path with:

```sh
just signer-core-fv
```

The current path runs:

- executable anti-drift tests
- Verus verification

The full repository formal-verification path also includes signer-core:

```sh
just fv
```

## Layout

- [`docs/implementation-plan.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-core/formal-verification/docs/implementation-plan.md)
- [`docs/proof-inventory.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-core/formal-verification/docs/proof-inventory.md)
- [`verus/`](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-core/formal-verification/verus)
