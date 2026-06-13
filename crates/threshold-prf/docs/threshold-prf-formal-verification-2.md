# `threshold-prf` High-Impact Formal Verification Plan

Last updated: June 13, 2026

## Scope

This plan tracks high-impact formal-verification work for the active `t-of-N` threshold-prf protocol.

## Completed High-Impact Work

- [x] Replace the old fixed-pair abstract model with a threshold-policy
      model.
- [x] Prove policy bounds for `1 <= threshold <= share_count`.
- [x] Prove share-id membership and out-of-policy rejection in the abstract
      model.
- [x] Prove duplicate subset rejection in the abstract model.
- [x] Add representative valid-subset coverage for `2-of-3` and `3-of-5`.
- [x] Pin wire widths in the Verus model.
- [x] Add committed-fixture anti-drift tests.
- [x] Add a Lean privacy model for one-server and two-server state visibility.
- [x] Run `just threshold-prf-fv` successfully.

## Current Proof Claims

The current FV gate supports these claims:

- threshold policies reject invalid threshold/count pairs.
- threshold subsets reject duplicates and share IDs outside the selected
  policy.
- wire widths match the production API.
- committed fixtures remain consistent with production context, purpose, and
  wire encodings.
- one two-server participant and combiner-visible state do not carry enough
  plaintext share material to reconstruct the signing root.

## Remaining High-Impact Work

1. Prove generic reconstruction for arbitrary valid threshold subsets.
2. Tie the reconstruction proof to production interpolation.
3. Model DLEQ verified-combine rejection behavior.
4. Add Router/A/B context-binding proof obligations after the Router/A/B naming
   boundary is finalized.
5. Consider Lean boundary extraction only after the Rust API and downstream
   Router/A/B adapter stop changing.

## Gate

Run:

```bash
just threshold-prf-fv
```
