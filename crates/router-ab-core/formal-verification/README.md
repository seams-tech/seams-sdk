# `router-ab-core` Formal Verification

This directory tracks formal verification for the fixed Router A/B ECDSA
threshold-PRF construction.

The intended structure follows the existing `threshold-prf` and `ecdsa-hss`
tracks:

- `docs/implementation-plan.md`
- `docs/proof-inventory.md`
- `verus/`
- `lean-boundary/`
- `lean-privacy/`

## Strategy

- use Verus first for field inclusion, role separation, and abstract
  derivation-state invariants
- use committed Rust vectors as anti-drift fixtures
- use Lean for the execution-state privacy model
- consider Aeneas boundary extraction after the fixed Rust API is stable

## First Proof Slice

The first useful proof slice should model:

- role identities
- fixed Deriver A/B share identifiers
- opened-value kinds
- forbidden joined-state kinds
- which roles may observe which opened-value kinds
- transcript fields included in the digest

Avoid placeholder proofs that do not bind back to production Rust formulas or
committed vectors.
