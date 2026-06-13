# `threshold-prf` Formal Verification Proof Inventory

Last updated: June 13, 2026

## Active Proof Surface

The active formal-verification surface is the configurable `t-of-N`
threshold-policy API. The deleted fixed-pair protocol is out of scope for new
proof work.

Current gates:

```bash
just threshold-prf-fv
just threshold-prf-fv
```

The latest `just threshold-prf-fv` run completed with:

- Verus: `18 verified, 0 errors`
- Lean privacy model: build completed successfully
- Rust FV parity tests: passed

## Verus Inventory

Implemented in
[verus/src/model.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/formal-verification/verus/src/model.rs):

- threshold policy validity:
  `1 <= threshold <= share_count <= MAX_SHARE_COUNT`
- share-id membership:
  `1 <= share_id <= share_count`
- threshold subset acceptance for representative `2-of-3` and `3-of-5`
  policies
- duplicate share-id rejection
- out-of-policy share-id rejection
- fixed-width wire claims:
  - signing-root share wire: 34 bytes
  - partial wire: 66 bytes
  - share commitment wire: 34 bytes
  - DLEQ proof wire: 64 bytes
  - proof bundle wire: 164 bytes
- abstract share-wire decode shape
- abstract proof-bundle ID-binding rejection:
  - commitment/partial share-ID mismatch
  - commitment share ID outside the selected policy
- representative abstract reconstruction claims for `2-of-N` and `3-of-N`

## Executable Anti-Drift

The Rust anti-drift tests bind proof assumptions to committed production
fixtures:

- `2-of-3` fixture coverage
- `3-of-5` fixture coverage
- Router/A/B `2-of-3` fixture coverage through current context bytes
- wire width and subset-rejection behavior

These tests are intentionally executable rather than purely symbolic. They catch
changes in fixture shape, wire width, suite labels, purpose labels, and context
encoding before the abstract models drift away from production code.

## Lean Inventory

The active Lean privacy model covers deployment-state visibility:

- one-server mode is not a privacy boundary
- a single two-server participant does not hold enough plaintext shares to
  reconstruct the signing root
- combiner-visible state does not include plaintext signing-root shares
- public output state does not include enough material to reconstruct the
  signing root

Lean boundary extraction remains deferred until the Rust API and downstream
Router/A/B boundary are stable.

## Remaining Proof Work

1. Add a symbolic interpolation lemma for arbitrary valid threshold subsets.
2. Connect the abstract reconstruction model to the production Lagrange helper.
3. Add symbolic proof obligations for DLEQ challenge binding and
   verified-combine rejection cases beyond proof-bundle ID binding.
4. Model the Router/A/B context-binding boundary once Router/A/B protocol names
   settle.
5. Revisit Lean boundary extraction after the downstream API stops changing.
