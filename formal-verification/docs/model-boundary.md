# Formal Model Boundary

Last updated: 2026-02-26

## Purpose

Define exactly what properties are proven in Coq, what is trusted, and what remains covered by integration and E2E testing.

## Verified Scope

- Cryptographic and algebraic correctness properties for in-scope signer-core functions.
- Implementation-level correctness properties for in-scope signer-core functions:
  - deterministic encoding and hash preimages,
  - signature finalize invariants,
  - share-mapping and participant-id constraints,
  - modeled reject/accept behavior at protocol composition boundaries.

## Trusted Assumptions

- Correctness of third-party cryptographic crate internals:
  - `k256`
  - `curve25519-dalek`
  - `frost-ed25519`
  - `threshold-signatures` (pinned revision)
- Runtime/infra semantics:
  - browser execution model,
  - network transport and retry timing,
  - relay/store durability and deployment behavior.

## Non-Goals of Coq Proofs

Coq proofs in this workspace are not used to validate production runtime orchestration under real network failures or distributed timing behavior. Those remain in integration/E2E suites.

## Conformance Strategy

- Coq theorem proofs establish properties over the formal model.
- Deterministic generated vectors from the model are consumed by Rust parity tests.
- Any byte-level divergence between generated vectors and Rust behavior is treated as a failing conformance check.
