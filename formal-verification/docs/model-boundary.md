# Formal Model Boundary

Last updated: 2026-04-03

## Purpose

Define exactly what properties are proven in the formal verification workspace, what is trusted, and what remains covered by integration and E2E testing.

## Verified Scope

- Cryptographic and algebraic correctness properties for in-scope signer-core functions.
- Implementation-level correctness properties for in-scope signer-core functions:
  - deterministic encoding and hash preimages,
  - signature finalize invariants,
  - share-mapping and participant-id constraints,
  - modeled reject/accept behavior at protocol composition boundaries.
- `ed25519-hss` fixed-function expansion correctness properties:
  - clear-spec correctness for `F_expand`,
  - deterministic, context-bound artifact/compiler generation,
  - equivalence between the clear fixed-function spec and the compiled hidden-eval realization at the `FExpandOutput` boundary.

## Trusted Assumptions

- Correctness of third-party cryptographic crate internals:
  - `k256`
  - `curve25519-dalek`
  - `frost-ed25519`
  - `threshold-signatures` (pinned revision)
  - `sha2`
- Runtime/infra semantics:
  - browser execution model,
  - network transport and retry timing,
  - relay/store durability and deployment behavior.
  - OT/HSS message delivery ordering and runtime scheduling behavior in `ed25519-hss`

## Non-Goals of Formal Proofs

Formal proofs in this workspace are not used to validate production runtime orchestration under real network failures or distributed timing behavior. Those remain in integration/E2E suites.

For `ed25519-hss`, non-goals include proving the distributed transport/session layer end to end. The proof target is the low-level fixed-function expansion pipeline, not the surrounding transport orchestration.

## Conformance Strategy

- Theorem proofs establish properties over the formal model.
- Deterministic generated vectors from the model are consumed by Rust parity tests.
- Any byte-level divergence between generated vectors and Rust behavior is treated as a failing conformance check.
