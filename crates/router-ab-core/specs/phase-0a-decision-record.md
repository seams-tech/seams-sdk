# Phase 0A Decision Record

This record captures the side-by-side evidence for the Router/A/B split
derivation primitive comparison and records the production primitive selection.

## Status

Production candidate: `mpc_threshold_prf_v1`.

Rationale: the measured Candidate A proof path is sub-ms, both candidates have
the same Router-facing round-trip shape, and Candidate A has the clearer
correctness-hardening, refresh-continuity, and formal-verification path through
`threshold-prf`.

Archived comparison/prototype candidate: `split_root_derivation_v1`.

## Evidence Snapshot

| Dimension | `mpc_threshold_prf_v1` | `split_root_derivation_v1` | Current read |
| --- | --- | --- | --- |
| Server-blind invariant | Router excludes plaintext partials; A and B hold role-local PRF shares; recipients combine their own outputs | Router excludes plaintext shares; A and B hold role-local split roots; recipients combine their own outputs | Both satisfy the target role-visibility invariant in the current adapter model |
| Router-facing round trips | one client request, one Router invocation, one A invocation, one B invocation, zero direct A/B rounds | one client request, one Router invocation, one A invocation, one B invocation, zero direct A/B rounds | Tie |
| Native cryptographic latency | two proofs plus combine: about `466.80 us` | derive share: about `2.46 us`; combine shares: about `6.58 us` | Candidate B is much faster locally |
| Correctness hardening | Existing `threshold-prf` DLEQ proof machinery gives a clear path for partial correctness | Minimum Level C only binds delivery; signer bias needs root-generation, address-verification, or public-share-binding gates | Candidate A has the clearer hardening path |
| Refresh semantics | Underlying threshold PRF model can preserve the logical PRF key; Router/A/B adapter still needs production purpose binding | New epoch creates a new verified output relation; preserving refresh is unavailable in the current adapter | Candidate A is cleaner for long-lived account continuity |
| Implementation complexity | More integration work through `threshold-prf`, proof bundles, and purpose binding | Smaller local primitive and lower adapter complexity | Candidate B is simpler locally |
| Dependency risk | Reuses reviewed `threshold-prf` curve, DLEQ, vector, and benchmark machinery | Adds a new split-root derivation suite with new bias and root-generation assumptions | Candidate A reuses more existing machinery |
| Formal verification effort | Reuse threshold PRF proof concepts plus Router/A/B role-boundary proofs | Requires fresh formula, bias, refresh, and root-generation reasoning | Candidate A has less new cryptographic proof surface |
| Worker evidence | library wasm builds pass; deployable Worker size/runtime missing | library wasm builds pass; deployable Worker size/runtime missing | Tie; both need Worker adapter evidence |

## Decision Guidance

Use `mpc_threshold_prf_v1` for the production Router A/B path.

Revisit `split_root_derivation_v1` only after these gates are resolved:

- root generation ceremony
- anti-bias mechanism or accepted address-verification-only activation model
- refresh and root-rotation acceptance for new verified output relations
- deployable Worker bundle-size evidence
- Cloudflare Worker runtime latency evidence

## Required Follow-Up

- Start the `threshold-prf` adapter follow-up refactor and freeze Candidate A
  vectors.
- Keep Candidate B only as comparison/prototype material until its unresolved
  gates justify revisiting it.
