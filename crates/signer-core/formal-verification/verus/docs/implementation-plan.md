# `signer-core` Verus Implementation Plan

Last updated: 2026-04-16

The Verus-local plan starts with the highest-impact shared ECDSA helper seam:

1. scalar-domain model for secp256k1 private scalars
2. HKDF-output reduction shape
3. relayer-share output shape
4. canonical keypair output shape
5. fixed `{1, 2}` additive-share mapping formula
6. public-key helper output-shape invariants
7. executable anti-drift tests against committed secp256k1 fixtures
8. threshold Ed25519 client-share derivation shape
9. threshold Ed25519 participant-ID validation shape
10. threshold Ed25519 key-package construction shape
11. NEP-413 digest construction and nonce-length shape

## Completed

- [x] bootstrap Verus crate
- [x] add `secp256k1` module mirror
- [x] model scalar reduction output domain
- [x] model relayer-share derivation output layout
- [x] model canonical keypair derivation output layout
- [x] prove fixed `{1, 2}` mapping algebra
- [x] model public-key helper output-shape invariants
- [x] add committed secp256k1 vector corpus
- [x] add executable anti-drift tests for first `secp256k1` slice
- [x] model threshold Ed25519 client-share derivation shape
- [x] prove threshold Ed25519 client-share determinism
- [x] prove threshold Ed25519 client signing-share non-zero output
- [x] prove threshold Ed25519 verifying-share-from-signing-share relation
- [x] add committed threshold Ed25519 derivation vector corpus
- [x] add threshold Ed25519 derivation anti-drift tests
- [x] model threshold Ed25519 participant-ID normalization and validation
- [x] model threshold Ed25519 key-package construction shape
- [x] model NEP-413 digest construction shape and nonce-length validation
- [x] add committed NEP-413 digest vector corpus
- [x] add NEP-413 digest anti-drift tests
- [x] pass `just signer-core-fv`
- [x] pass full repository `just fv`

## Deferred Future Work

Revisit Aeneas + Lean only if a stable shared Rust-facing boundary becomes
proof-relevant on its own.
