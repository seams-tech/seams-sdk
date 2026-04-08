# `ed25519-hss` Spec Corpus

Last updated: 2026-04-05

## Purpose

Freeze the local spec corpus and source precedence for formal verification and
spec-to-code compliance.

## Source Precedence

1. Clear fixed-function semantics:
   [`../src/shared/reference.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/shared/reference.rs)
2. Fixed-function math and reconstruction invariant:
   [`../specs/derivation.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/specs/derivation.md)
3. Protocol layers, artifact shape, and active boundary rules:
   [`../specs/protocol.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/specs/protocol.md)
4. Active security clarifications for the current runtime path:
   [`../security.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/security.md)
5. Refactor-specific module and boundary expectations:
   [`../docs/plans/refactor-hss-1.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/docs/plans/refactor-hss-1.md)
6. Boundary-oriented public API summary:
   [`../README.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/README.md)

## Canonical Spec Items

- Fixed-function formula:
  - `m = y_client + y_relayer mod 2^256`
  - `d = LE32(m)`
  - `h = SHA-512(d)`
  - `a_bytes = clamp(h[0..31])`
  - `a = LE256(a_bytes) mod l`
  - `tau = tau_client + tau_relayer mod l`
  - `x_client_base = a + tau mod l`
  - `x_relayer_base = a + 2 * tau mod l`
  - `A = [a]B`
- Reconstruction invariant:
  - `a = 2 * x_client_base - x_relayer_base mod l`
- Runtime role split:
  - client = evaluator
  - server = garbler
- Artifact/circuit stages:
  - add-mod-`2^256`
  - message schedule
  - SHA-512 round stages
  - clamp/reduce
  - output projector

## Known Ambiguity To Resolve Before Boundary Proofs

The older spec corpus used to say:

- “no interparty wire type may carry both halves of a hidden server-owned
  value”

But the current packet flow seals both relayer halves into one
`ServerInputsPacket` ciphertext before the evaluator opens them into left/right
transport bundles.

That means boundary proofs should currently avoid claiming the stronger
“never both halves in one wire packet” property until the docs are reconciled.
