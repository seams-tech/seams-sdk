# `threshold-prf` Formal Verification Proof Inventory

Last updated: June 13, 2026

This inventory tracks the active crate-local formal-verification surface for the
configurable `t-of-N` threshold-prf API.

Current gates:

```bash
just threshold-prf-fv
```

## Verus Proof Surface

Implemented in
[`verus/src/model.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/formal-verification/verus/src/model.rs):

- threshold-policy validity:
  `1 <= threshold <= share_count <= MAX_SHARE_COUNT`
  with current `MAX_SHARE_COUNT = 255`
- share-ID membership:
  `1 <= share_id <= share_count`
- duplicate subset rejection for representative `2-of-N` and `3-of-N` shapes
- out-of-policy share-ID rejection for representative subset shapes
- representative `2-of-3` and `3-of-5` subset acceptance
- fixed-width wire claims:
  - signing-root share wire: 34 bytes
  - partial wire: 66 bytes
  - share commitment wire: 34 bytes
  - DLEQ proof wire: 64 bytes
  - proof bundle wire: 164 bytes
- signing-root share-wire decode shape
- proof-bundle ID binding:
  - commitment/partial share-ID mismatch is rejected
  - commitment share IDs outside the selected policy are rejected
- representative abstract reconstruction claims for `2-of-N` and `3-of-N`

Remaining trust:

- `curve25519-dalek` scalar and Ristretto point arithmetic
- SHA-512 transcript hashing
- Fiat-Shamir DLEQ soundness
- production Lagrange interpolation helper linkage

## Executable Anti-Drift

Implemented in
[`verus/tests/anti_drift.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/formal-verification/verus/tests/anti_drift.rs)
and the production crate tests:

- committed `2-of-3` vector parity
- committed `3-of-5` vector parity
- Router/A/B-suite vector parity through current context bytes
- fixed-width signing-root share and partial wire parity
- subset-rejection behavior against production helpers
- DLEQ verified-combine output parity for generated valid proof bundles
- DLEQ malformed proof, wrong-context, duplicate-bundle, and
  commitment/partial share-ID mismatch rejection in production Rust tests

## Lean Proof Surface

Implemented in
[`lean-privacy`](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/formal-verification/lean-privacy):

- one-server mode is not a privacy boundary
- one two-server participant does not hold enough plaintext shares to reconstruct
  the signing root
- combiner-visible state does not include plaintext signing-root shares
- public output state does not include enough material to reconstruct the signing
  root

## Remaining Proof Work

1. Prove generic interpolation for arbitrary valid threshold subsets.
2. Connect the generic reconstruction lemma to the production Lagrange helper.
3. Add symbolic DLEQ verified-combine obligations for wrong context, wrong
   commitment, malformed proof, and duplicate bundle rejection.
4. Model DLEQ challenge transcript binding beyond fixed-width wire shape.
5. Model the Router/A/B context-binding boundary once Router/A/B protocol names
   settle.
6. Revisit Lean boundary extraction after the Rust API and downstream
   boundary stop changing.
