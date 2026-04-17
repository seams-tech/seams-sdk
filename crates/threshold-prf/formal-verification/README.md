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

## Current Status

This formal-verification track now has a Verus abstract spec model, committed
vector anti-drift parity tests, a narrow Lean privacy execution-state model,
and a `just threshold-prf-fv` command. Lean boundary extraction remains
deferred.

The current Verus track covers:

- an abstract spec model for subset, Shamir, partial-combine, and wire-tag
  behavior
- an abstract server-SDK `ProjectRootShareWireV1` decode and Option A
  derivation boundary model
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

1. input-domain and output-width model
2. 2-of-3 subset validation model
3. duplicate/insufficient-share rejection model
4. zero-root rejection and zero-share acceptance model
5. direct reference evaluation shape
6. threshold partial-combine shape
7. direct-vs-threshold equivalence over the abstract model
8. partial wire context-tag validation model
9. abstract malformed scalar-encoding rejection
10. explicit output-derivation input tuple binding
11. abstract DLEQ commitment/proof boundary model
12. DLEQ-enforced verified-combine boundary model
13. secret project-root share wire decode and Option A derivation boundary model

Do not add placeholder proofs that are disconnected from production formulas.

Run the current threshold-prf FV gate with:

```bash
just threshold-prf-fv
```
