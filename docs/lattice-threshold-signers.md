# Lattice Threshold Signers

Last updated: 2026-03-31
Status: Proposed refactor plan

## 1. Goal

Refactor the threshold signer architecture so a new threshold signer family can be added without threading curve-specific assumptions through the SDK, workers, relayer, and session model.

The immediate target is introduction of a lattice-based threshold signer based on the `FSwA-threshold` design, but the refactor should produce a generic threshold signer architecture rather than a one-off lattice integration.

## 2. Scope

This document is split into two phases:

1. Phase 1: refactor the current threshold signer architecture into a generic family-based model.
2. Phase 2: implement the lattice threshold signer on top of the generic model.

This document does not cover a separate onchain verification redesign for NEAR or EVM. If the lattice signer must become a first-class onchain signer, that requires additional specs after Phase 2.

## 3. Non-Negotiable Invariants

- No duplicate legacy codepaths are kept during the refactor.
- Breaking changes are acceptable if they simplify the threshold architecture.
- Existing `ed25519` and `ecdsa` threshold paths must be migrated onto the generic model instead of leaving curve-specific side paths in place.
- Session ownership, worker ownership, and signer-family boundaries remain explicit.
- Missing or stale threshold session state must continue to fail closed.
- Confirmation UX must remain immediate; network and protocol preparation may hydrate after modal mount.

## 4. Current Problem

The top-level signing engine is reasonably extensible, but the threshold stack still assumes:

- threshold signer families are only `ed25519` and `ecdsa`
- warm-session planning is `ed25519 -> ecdsa`
- worker kinds are fixed to `nearSigner`, `ethSigner`, and `tempoSigner`
- relayer auth and scheme selection only distinguish `ed25519` and `ecdsa`
- queue, session, and persistence models are named after the current curve families

That means the architecture is only partially generic. A new lattice threshold signer would currently require invasive special cases across the stack.

## 5. Target End State

After the refactor, the system should model threshold signers in terms of:

- signer family
- protocol/session family
- verification target
- chain adaptor compatibility
- worker runtime ownership

The important separation is:

- signer family answers "what cryptographic protocol is this?"
- chain family answers "what chain or execution environment consumes the result?"
- verification target answers "who verifies this signature and in what format?"

This allows:

- threshold Ed25519
- threshold secp256k1 ECDSA
- threshold lattice signatures
- future signer families

without reintroducing family-specific control flow in shared orchestration.

## 6. Phase 1: Refactor To A Generic Threshold Signer Architecture

### 6.1 Canonical Domain Model

Replace curve-specific threshold naming in shared layers with signer-family terminology.

Required outcomes:

- introduce a canonical threshold signer family identifier in shared client/server types
- separate signer family from chain family in runtime state
- separate session scheme from signer family where needed
- define a canonical threshold signer record shape with common fields and family-specific payloads
- define a canonical verification target field so non-ECDSA/non-Ed25519 families do not need to pretend to be chain-native signers

### 6.2 Client Signing Interfaces

Refactor the client signing interfaces so new threshold families can register without patching shared unions each time.

Required outcomes:

- replace hard-coded `ed25519 | secp256k1 | webauthnP256` assumptions in threshold-facing shared types with a family-aware model
- replace the current threshold key-ref shape with a generic threshold signer key ref plus family-specific payload
- keep `executeSigningIntent(...)` generic, but remove curve-specific resolution assumptions from shared threshold plumbing
- update chain adaptors so they request signer-family capabilities instead of implicitly selecting the current threshold families

### 6.3 Warm Session And Activation Graph

Refactor warm-session planning into a generic dependency graph of threshold signer families.

Required outcomes:

- replace the hard-coded `['ed25519', 'ecdsa']` warmup planner with a family registry or declarative dependency graph
- make session priming tasks family-owned
- support families that derive from the same passkey assertion but produce different session artifacts
- support families with no dependency on Ed25519

Important cleanup:

- remove the current assumption that `ecdsa` must always be warmed through `ed25519`
- migrate current Ed25519/ECDSA warmup onto the generic planner instead of keeping a compatibility layer

### 6.4 Worker Architecture

Refactor worker registration and operation dispatch so new threshold signer runtimes can be added without expanding fixed enums in multiple layers.

Required outcomes:

- replace fixed multichain worker kind assumptions with a registry or family-owned worker definitions
- define a generic threshold worker operation envelope
- move family-specific operation typing behind worker-owned modules
- allow a lattice signer worker or WASM runtime to exist without pretending to be the EVM or Tempo signer worker

Important cleanup:

- remove shared assumptions that threshold operations belong to the secp256k1 worker surface

### 6.5 Relayer Scheme Registry And Auth

Refactor server threshold scheme routing so the relayer can host multiple signer families without `ed25519`/`ecdsa` branching in shared code.

Required outcomes:

- generalize scheme IDs and scheme registration
- generalize threshold-session auth policy beyond `ed25519 | ecdsa`
- define generic session claim parsing for threshold signer families
- define shared persistence interfaces for per-family protocol state, attempt state, and session state
- keep family-specific route handlers thin and move protocol ownership into family modules

Important cleanup:

- remove shared route/auth assumptions that threshold session schemes are only `ed25519` or `ecdsa`

### 6.6 Generic Queueing, Retry, And Attempt Semantics

Introduce generic threshold protocol lifecycle concepts that can model both current presign-based flows and future retry/abort protocols.

Required outcomes:

- define a generic threshold protocol lane key
- define a generic attempt model for multi-round threshold protocols
- allow families to declare whether they use:
  - presign pools
  - inline attempts
  - rejection/retry loops
  - batch attempts
- move family-specific retry semantics out of shared queue primitives

This matters because the lattice signer has explicit attempt/rejection behavior that does not fit the current presign-only mental model.

### 6.7 Testing And Observability

Refactor test and telemetry surfaces so new threshold families do not require bespoke harnesses at every layer.

Required outcomes:

- define shared test fixtures for threshold signer family registration, warmup, activation, queueing, and session expiry
- define common structured telemetry fields:
  - signer family
  - protocol session id
  - attempt id
  - queue lane
  - retry count
  - verification target
- migrate current Ed25519/ECDSA tests onto the generic model as they are touched

### 6.8 Phase 1 Acceptance Criteria

Phase 1 is complete when:

1. Current threshold Ed25519 and threshold ECDSA run through the same generic threshold-family architecture.
2. Shared client/server layers no longer branch on only `ed25519` vs `ecdsa`.
3. Warm-session planning is family-based rather than curve-name-based.
4. Worker dispatch can register a new threshold signer runtime without widening fixed shared enums across unrelated modules.
5. Relayer scheme routing and threshold-session auth can register a third threshold signer family cleanly.
6. No duplicate legacy path remains for the pre-refactor threshold architecture.

## 7. Phase 2: Implement The Lattice Threshold Signer

### 7.1 Family Definition

Introduce a new threshold signer family for the lattice signer with explicit family-owned types.

Required outcomes:

- define the signer-family id
- define key material types
- define session/bootstrap material
- define protocol message types
- define signature encoding and verification target
- define how the lattice family appears in client/runtime configuration

This family must not be forced into the secp256k1 or Ed25519 shapes.

### 7.2 Core Rust Integration

Bring the lattice protocol into the repo as a family-owned core module.

Required outcomes:

- add the lattice core crate or an internal wrapper crate
- normalize encoding and error surfaces to repo conventions
- define deterministic vectors and fixture generation
- expose only the operations the runtime actually needs

If the upstream crate layout is adopted, wrap it behind repo-owned interfaces instead of leaking external shapes directly into SDK and server layers.

### 7.3 Worker And WASM Runtime

Build a dedicated runtime surface for the lattice signer.

Required outcomes:

- implement a lattice signer worker or equivalent runtime module
- expose session init, protocol step, abort, retry, and finalize operations
- support the protocol's explicit attempt/rejection semantics
- keep protocol state worker-owned where appropriate

The implementation should model the FSwA-style multi-round flow directly rather than translating it into the existing secp256k1 presign protocol.

### 7.4 Client Session And Signing Flow

Add a client-side threshold lattice signing flow on top of the Phase 1 generic architecture.

Required outcomes:

- define bootstrap/connect flow for the lattice family
- define how a passkey assertion contributes to lattice-family session setup, if applicable
- define the signing engine implementation
- define touch-confirm integration and confirmer hydration behavior
- define session caching, expiry, and reconnect rules

If the lattice signer does not map to the current Ed25519-led warm-session path, implement its own family-owned warmup task without introducing curve-specific fallback logic.

### 7.5 Relayer Protocol Ownership

Implement server-side protocol ownership for the lattice signer.

Required outcomes:

- add a scheme module for the lattice signer
- add family-owned route handlers
- add stores for protocol session state and attempt state
- implement retry/rejection handling
- add healthz and structured telemetry

The relayer should own protocol persistence and recovery semantics explicitly rather than trying to reuse ECDSA presign storage.

### 7.6 Verification Target And Product Surface

Make the verification model explicit.

Required outcomes:

- define whether Phase 2 verification is:
  - off-chain service verification
  - app-layer verification
  - a custom verifier contract
  - another target defined by specs
- encode that verification target in the family definition
- avoid claiming NEAR-native or EVM-native compatibility unless the signature format actually satisfies those ecosystems

This is the key boundary preventing architectural confusion. The lattice signer must enter the system as its own signer family with its own verification target, not as a disguised replacement for ECDSA or Ed25519.

### 7.7 Testing, Benchmarks, And Security Review

Required outcomes:

- unit tests for protocol steps and encoding
- worker/runtime integration tests
- relayer E2E tests for session lifecycle and retry behavior
- deterministic vector cross-checks against reference outputs
- benchmark docs for signing latency, retry rate, and payload size
- explicit security review checklist for protocol-state persistence, replay handling, and abort/retry correctness

### 7.8 Phase 2 Acceptance Criteria

Phase 2 is complete when:

1. The repo can provision, warm, and sign with the lattice threshold signer through the generic threshold-family architecture.
2. The lattice family has its own worker/runtime, server scheme, session model, and verification target.
3. The implementation does not introduce special-case branches back into shared threshold code.
4. Existing Ed25519/ECDSA threshold families still run on the Phase 1 generic architecture.
5. End-to-end tests cover bootstrap, active signing, retry/rejection handling, expiry, and reconnect.

## 8. Recommended Execution Order

1. Land the shared type-system and scheme-registry refactor.
2. Land the warm-session planner refactor.
3. Land the worker registration refactor.
4. Migrate existing threshold Ed25519 and threshold ECDSA onto the generic architecture.
5. Delete the old threshold-family-specific shared assumptions.
6. Add the lattice family core module and runtime.
7. Add client and relayer protocol flows for the lattice family.
8. Land vectors, benchmarks, and end-to-end tests.

## 9. Risks

- The largest technical risk is letting the lattice signer reuse secp256k1-shaped abstractions for convenience; that would recreate the same architectural problem in a new form.
- The largest product risk is leaving the verification target ambiguous. The lattice signer must have explicit specs for who verifies signatures and where.
- The largest refactor risk is preserving current Ed25519/ECDSA behavior through compatibility layers instead of migrating them fully to the generic model.

## 10. Deliverable

The deliverable is not "support one lattice signer."

The deliverable is:

1. one generic threshold signer architecture
2. current Ed25519 and ECDSA families migrated onto it
3. one implemented lattice threshold signer family using the same architecture
