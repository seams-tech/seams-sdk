# `signer-core` Formal Verification Implementation Plan

Last updated: 2026-04-16

This is the crate-local implementation plan for the active
`signer-core` formal-verification track.

The source plan lives at:

- [`../../docs/formal-verification-plan.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-core/docs/formal-verification-plan.md)

## Decision

Start with Verus and executable anti-drift checks.

Do not create a Lean boundary/privacy track until there is a specific
`signer-core` boundary worth extracting.

Current status:

- [x] current Verus-first signer-core scope complete
- [x] `just signer-core-fv` passes
- [x] full repository `just fv` passes

## Phase 0: Bootstrap

- [x] create `crates/signer-core/formal-verification/`
- [x] add `formal-verification/README.md`
- [x] add `formal-verification/docs/implementation-plan.md`
- [x] add `formal-verification/docs/proof-inventory.md`
- [x] add `formal-verification/verus/`
- [x] add `formal-verification/verus/Cargo.toml`
- [x] add `formal-verification/verus/README.md`
- [x] add `formal-verification/verus/docs/implementation-plan.md`
- [x] add `formal-verification/verus/src/lib.rs`
- [x] mirror the production module layout minimally under `verus/src/`
- [x] wire repo-local wrapper commands for `signer-core` verification

## Phase 1: `secp256k1` Scalar Reduction And Key Derivation

- [x] add a Verus module for HKDF-output reduction in `src/secp256k1.rs`
- [x] prove deterministic reduction from 64-byte HKDF output
- [x] prove the reduction output is always a valid non-zero secp256k1 scalar
- [x] add a Verus model for canonical keypair derivation from `(prf_second, near_account_id)`
- [x] prove canonical keypair derivation is deterministic
- [x] model compressed public key and Ethereum address derivation from the same private key
- [x] add executable anti-drift checks for representative vectors

## Phase 2: `secp256k1` Public-Key Consistency

- [x] prove public-key helper output shape invariants in Verus
- [x] add executable anti-drift checks for scalar-byte encoding and public-key behavior

## Phase 3: `near_threshold_ed25519` Shared Derivation

- [x] add a Verus module for threshold client-share derivation from `(wrap_key_seed, near_account_id)`
- [x] prove deterministic share derivation
- [x] prove non-zero client-share output
- [x] prove verifying-share derivation matches the derived signing share
- [x] prove participant-ID normalization and validation invariants
- [x] prove key-package construction preserves the intended signing-share / verifying-share / group-key relationship
- [x] prove NEP-413 digest construction shape and exact nonce-length validation
- [x] add executable anti-drift checks for the committed Ed25519 derivation slice
- [x] add executable anti-drift checks for committed NEP-413 digest vectors

## Phase 4: Shared-Helper Boundary And Anti-Drift Expansion

- [x] add a committed vector corpus for the `secp256k1` slice
- [x] add a committed vector corpus for the `near_threshold_ed25519` derivation slice
- [x] add a committed vector corpus for the `near_threshold_ed25519` NEP-413 digest slice
- [x] add anti-drift checks between production code and the Verus mirror for the first `secp256k1` slice
- [x] add anti-drift checks for helper output layout and rejected-input shape for the first `secp256k1` slice

## Phase 5: Decide Whether Aeneas + Lean Expansion Is Justified

- [x] decide whether any `signer-core` Rust-facing boundary is stable and important enough to justify extraction

Decision:

No current `signer-core` helper boundary warrants Aeneas + Lean extraction.
The active track should remain Verus plus executable anti-drift checks until a
stable shared Rust-facing boundary becomes proof-relevant on its own.

## Deferred Future Work

Only if a future stable shared Rust-facing boundary justifies extraction:

- create `formal-verification/lean-boundary/`
- install the pinned Aeneas/Charon toolchain locally
- generate the first Rust-derived Lean boundary artifact
- keep generated modules separate from handwritten Lean bridge lemmas
- create `formal-verification/lean-privacy/` if a real privacy boundary exists
- freeze the extraction target to one narrow helper boundary only
- keep broader privacy/boundary expansion out of scope until the first bridge works
