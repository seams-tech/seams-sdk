# `threshold-prf` Formal Verification Plan

Last updated: June 13, 2026

## Scope

This plan covers formal verification for the active configurable `t-of-N`
threshold-prf protocol. The public Rust API is `threshold_prf`; fixed-pair
proof artifacts were removed with the old fixed-pair protocol.

## Strategy

Use three layers:

1. Verus abstract models for policy, subset, wire, and reconstruction
   invariants.
2. Executable Rust anti-drift tests against committed fixtures.
3. Lean privacy models for deployment-state visibility.

The FV surface should stay tied to production code. Avoid placeholder proofs
that model a shape no caller uses.

## Completed Work

- [x] Model threshold policy validity.
- [x] Model share-id membership.
- [x] Model duplicate and out-of-policy subset rejection.
- [x] Model representative `2-of-3` and `3-of-5` valid subsets.
- [x] Model fixed-width share, partial, commitment, proof, and proof-bundle
      wire claims.
- [x] Add an abstract share-wire decode model.
- [x] Add abstract proof-bundle ID-binding rejection claims.
- [x] Add representative abstract reconstruction claims.
- [x] Add production anti-drift tests for committed fixtures.
- [x] Add a Lean privacy model for one-server and two-server state visibility.
- [x] Add `just threshold-prf-fv` and `just threshold-prf-fv` gates.

## Current Gates

Run:

```bash
just threshold-prf-fv
```

Latest status:

- Verus: `18 verified, 0 errors`
- Lean privacy: build completed successfully
- Rust FV parity tests: passed

## Next High-Impact Work

1. Prove generic subset reconstruction for arbitrary valid policies.
2. Connect the generic reconstruction lemma to the production interpolation
   helper.
3. Add DLEQ verified-combine proof obligations for wrong context, wrong
   commitment, wrong share ID, malformed proof, and duplicate bundle rejection.
4. Add a small Router/A/B context-binding model after the Router/A/B boundary
   naming audit is complete.
5. Revisit Lean boundary extraction once the Rust API is stable across
   downstream users.
