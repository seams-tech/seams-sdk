# `threshold-prf` Formal Verification

This directory contains the active `threshold-prf` formal-verification track.

The source plans live at:

- [`../docs/formal-verification-plan.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/docs/formal-verification-plan.md)
- [`../docs/formal-verification-proof-inventory.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/docs/formal-verification-proof-inventory.md)

## Current Strategy

The active strategy is:

- Verus first for algebraic, encoding, subset, and equivalence invariants
- executable anti-drift checks against the committed JSON vector corpus
- Aeneas + Lean boundary work only after the Rust-facing boundary is stable
- a narrow Lean privacy model for one-server/two-server execution-state
  visibility

## Threshold Policy Model

The active model is policy-shaped:

```text
1 <= threshold <= share_count <= MAX_SHARE_COUNT
valid_share_ids = {1, ..., share_count}
combine_count = threshold
```

Current subset, Shamir, share-wire, and reconstruction proofs model the
policy-shaped boundary used by production Rust and WASM callers.

## Current Status

This formal-verification track now has a Verus abstract spec model, committed
vector anti-drift parity tests, a narrow Lean privacy execution-state model,
concrete transcript fixtures, generated production property tests, DLEQ nonce
contract tests, and the `just threshold-prf-fv` gate. Lean boundary extraction
remains deferred.

The current Verus track covers:

- an abstract spec model for threshold-policy, subset, Shamir, and share-wire
  behavior
- production anti-drift parity against the committed JSON vector corpus
- a structural Lean privacy model proving that one-server mode is not a privacy
  boundary, while one two-server participant, combiner state, and public output
  state do not carry enough plaintext shares to reconstruct `k_org`

The current folder structure is intentionally present early so the Rust API can
be shaped around proof targets:

- [`docs/implementation-plan.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/formal-verification/docs/implementation-plan.md)
- [`docs/proof-inventory.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/formal-verification/docs/proof-inventory.md)
- [`fixtures/`](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/formal-verification/fixtures)
- [`verus/`](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/formal-verification/verus)
- [`lean-boundary/`](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/formal-verification/lean-boundary)
- [`lean-privacy/`](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/formal-verification/lean-privacy)

## First Proof Slice

The first active proof slice is implemented in
[`verus/src/model.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/formal-verification/verus/src/model.rs):

1. threshold policy bounds
2. share-ID membership
3. duplicate and out-of-range subset rejection
4. representative 2-of-3 and 3-of-5 subset acceptance
5. fixed-width share, partial, commitment, and proof wire claims
6. signing-root share wire decode
7. proof-bundle ID-binding rejection
8. 2-of-N and 3-of-N abstract reconstruction claims

Do not add placeholder proofs that are disconnected from production formulas.

Run the current threshold-prf FV gate with:

```bash
just threshold-prf-fv
```
