# `threshold-prf` Formal Verification

This directory contains the active `threshold-prf` formal-verification track.

The current strategy is:

- Verus abstract models for policy, subset, wire, and reconstruction invariants
- executable Rust anti-drift tests against the committed JSON vector corpus
- a narrow Lean privacy model for one-server and two-server execution-state
  visibility
- Lean boundary extraction only after a Rust-facing boundary is stable enough to
  extract and compare

## Threshold Policy Model

The active model is policy-shaped:

```text
1 <= threshold <= share_count <= MAX_SHARE_COUNT
valid_share_ids = {1, ..., share_count}
combine_count = threshold
```

The current production bound is `MAX_SHARE_COUNT = 255`; the larger `u16`
share-ID encoding is wire capacity, not an accepted operational policy size.

Current subset, Shamir, share-wire, and reconstruction proofs model the
policy-shaped boundary used by production Rust and WASM callers.

## Current Surface

The canonical inventory is
[`docs/proof-inventory.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/formal-verification/docs/proof-inventory.md).

Implemented tracks:

- [`verus/`](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/formal-verification/verus):
  abstract threshold-policy, subset, wire, proof-bundle ID-binding, and
  reconstruction claims plus production anti-drift parity tests
- [`lean-privacy/`](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/formal-verification/lean-privacy):
  structural visibility model for one-runtime and two-runtime execution states
- [`lean-boundary/`](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/formal-verification/lean-boundary):
  deferred extraction track
- [`fixtures/`](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/formal-verification/fixtures):
  notes for vector-backed anti-drift coverage

Current high-impact remaining work:

1. Prove generic interpolation for arbitrary valid threshold subsets.
2. Connect the generic reconstruction lemma to the production Lagrange helper.
3. Add symbolic DLEQ verified-combine obligations for wrong context, wrong
   commitment, malformed proof, and duplicate bundle rejection.
4. Model DLEQ challenge transcript binding beyond fixed-width wire shape.
5. Model the Router/A/B context-binding boundary once Router/A/B protocol names
   settle.
6. Revisit Lean boundary extraction after the Rust API and downstream boundary
   stop changing.

Run the current threshold-prf FV gate with:

```bash
just threshold-prf-fv
```
