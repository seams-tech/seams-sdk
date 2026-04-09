# `ecdsa-hss` Lean Privacy Plan

Last updated: 2026-04-09

## Goal

Use Lean 4 for the narrow privacy claim that the server-visible staged boundary
cannot reveal threshold-derived private material.

Initial target:

1. the server cannot observe `canonical_x`
2. the server cannot observe `x_client`
3. the generated Rust boundary from `lean-boundary/` maps into that same
   handwritten server-visible model

## Plan Status

This track is now bootstrapped as a separate Lean workspace and intentionally
depends on the completed narrow boundary bridge.

The intended split is:

- Verus proves implementation-facing algebraic and retained-state invariants
- `lean-boundary/` proves the generated Rust boundary matches the handwritten
  staged boundary model
- `lean-privacy/` proves the server-visible staged boundary is insensitive to
  hidden threshold-derived private material

This privacy pass is now intentionally frozen at that server-visible staged
boundary. Client-side privacy claims remain out of scope for `ecdsa-hss`
unless a separate adversary model is introduced later.

The first widening slice beyond pure boundary non-observability is now in
place:

- explicit `ProtocolExecutionState`
- explicit `ClientSecretState` and `ServerSecretState`
- explicit `ClientObservableProfile` and `ServerObservableProfile`
- explicit non-export / explicit-export client and server view projections
- state-variation relations over shared client/server observable boundaries
- simulator inputs and compatibility theorems for observable-only non-export
  and explicit-export client/server views
- explicit observable-profile equivalence and indistinguishability relations
  over the frozen staged-boundary fields
- first reconstruction-style goals now exist for:
- `ServerCannotDeriveClientSecrets`
- `ClientCannotDeriveServerSecrets`
- `ServerCannotDeriveCanonicalSecret`
- `ServerCannotDeriveClientThresholdShare`
- field-based canonical-secret disclosure predicates now exist
- the explicit-export exception theorem now exists for policy-consistent
  canonical-secret disclosure
- widened generated-boundary client/server view mappings and theorem lifts now
  exist in `AeneasBridge.lean`

## Completed Checklist

- [x] Create the new `formal-verification/lean-privacy/` workspace.
- [x] Wire it to depend on `formal-verification/lean-boundary/`.
- [x] Define a handwritten server-visible boundary model.
- [x] Define the hidden threshold-private material model:
      `canonical_x` and `x_client`.
- [x] Define the observable server profile by dropping client-only payloads.
- [x] State and prove the narrow server-visibility theorem over the handwritten
      model.
- [x] Prove that the observable server profile is unchanged under
      client-output variation when operation/finalize/retained fields are
      fixed.
- [x] Add the generated-boundary bridge theorem for the same server-visibility
      claim.
- [x] Lift the client-output-invariance theorem onto the generated Rust
      boundary as well.

## Remaining Checklist

- [x] Decide whether to widen this privacy track beyond the current
      server-visible staged boundary.
- [x] Decide whether boundary-level client/server non-derivability belongs here
      while richer client-adversary models remain out of scope.

## Expansion Checklist: Explicit Secret-Reconstruction Model

If we widen `lean-privacy` beyond the current boundary non-observability pass,
use the following concrete sequence.

### Phase P1: Explicit Secret-State Model

- [x] Extend
      [EcdsaHssPrivacy/Model.lean](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-privacy/EcdsaHssPrivacy/Model.lean)
      with explicit `ClientSecretState`.
- [x] Extend
      [EcdsaHssPrivacy/Model.lean](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-privacy/EcdsaHssPrivacy/Model.lean)
      with explicit `ServerSecretState`.
- [x] Freeze the minimum client-secret set for the widened model:
      `y_client`, `x_client`, and any client-only explicit-export material if
      required by the staged boundary.
- [x] Freeze the minimum server-secret set for the widened model:
      `y_relayer`, `x_relayer`, relayer threshold share, and any server-only
      continuation material required by the staged boundary.
- [x] Keep `canonical_x` modeled as a threshold-derived private value, not as a
      server-visible field.
- [x] Add a full handwritten execution state carrying boundary plus client
      secrets, server secrets, and `canonical_x`.

### Phase P2: Explicit Client/Server Views

- [x] Extend
      [EcdsaHssPrivacy/Views.lean](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-privacy/EcdsaHssPrivacy/Views.lean)
      with `ClientObservableProfile`.
- [x] Extend
      [EcdsaHssPrivacy/Views.lean](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-privacy/EcdsaHssPrivacy/Views.lean)
      with `ServerObservableProfile`.
- [x] Define non-export client/server view projections.
- [x] Define explicit-export client/server view projections.
- [x] Freeze which client-output fields are observable to the client adversary.
- [x] Freeze which staged-boundary fields are observable to the server
      adversary.
- [x] Project client/server observable views from full execution state rather
      than from erased secret arguments.

### Phase P3: Simulator And Compatibility Layer

- [x] Add
      [EcdsaHssPrivacy/Simulators.lean](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-privacy/EcdsaHssPrivacy/Simulators.lean).
- [x] Define client-view compatibility under server-secret variation.
- [x] Define server-view compatibility under client-secret variation.
- [x] Define simulator inputs for the non-export boundary.
- [x] Define simulator inputs for the explicit-export boundary.
- [x] Restrict simulator inputs to observable boundary projections only.
- [x] Keep hidden-eval/compiler/runtime internals out of scope in this track
      and model them only through compatibility assumptions.

### Phase P4: Indistinguishability Assumptions

- [x] Strengthen
      [EcdsaHssPrivacy/Assumptions.lean](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-privacy/EcdsaHssPrivacy/Assumptions.lean)
      from raw equality of server-observable profiles to explicit
      indistinguishability relations.
- [x] Add client-view indistinguishability under server-secret variation.
- [x] Add server-view indistinguishability under client-secret variation.
- [x] Define observable-profile equivalence relations rather than relying only
      on record equality.
- [x] Keep the observational layer tied to the frozen staged boundary fields.

### Phase P5: Secret-Reconstruction Goals

- [x] Extend
      [EcdsaHssPrivacy/Goals.lean](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-privacy/EcdsaHssPrivacy/Goals.lean)
      with `ServerCannotDeriveClientSecrets`.
- [x] Extend
      [EcdsaHssPrivacy/Goals.lean](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-privacy/EcdsaHssPrivacy/Goals.lean)
      with `ClientCannotDeriveServerSecrets`.
- [x] Add an explicit theorem for `ServerCannotDeriveCanonicalSecret`.
- [x] Add an explicit theorem for `ServerCannotDeriveClientThresholdShare`.
- [x] Add a non-export theorem for threshold-secret hiding.
- [x] Add an explicit-export exception theorem isolating the only allowed
      disclosure path.
- [x] Make the disclosure theorem field-based for canonical-secret payload
      presence, not enum-tag based.

### Phase P6: Recommended Proof Order

- [x] Prove server non-derivability of client secrets first.
- [x] Then prove client non-derivability of server secrets.
- [x] Then prove the explicit-export exception isolation theorem.
- [x] Then restate the widened privacy theorems over the generated Rust
      boundary.

### Phase P7: Generated-Boundary Lift

- [x] Extend
      [EcdsaHssPrivacy/AeneasBridge.lean](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-privacy/EcdsaHssPrivacy/AeneasBridge.lean)
      with generated-boundary client-view mappings.
- [x] Extend
      [EcdsaHssPrivacy/AeneasBridge.lean](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-privacy/EcdsaHssPrivacy/AeneasBridge.lean)
      with generated-boundary server-view mappings.
- [x] Prove the generated non-export boundary matches the widened handwritten
      privacy view model.
- [x] Prove the generated explicit-export boundary matches the widened
      handwritten export-exception model.
- [x] Lift `ServerCannotDeriveClientSecrets` onto the generated boundary.
- [x] Lift `ClientCannotDeriveServerSecrets` onto the generated boundary.

### Phase P8: Out Of Scope Unless Re-Decided

- [x] Do not widen this track into hidden-eval compiler correctness.
- [x] Do not widen this track into transport/runtime orchestration proofs.
- [x] Do not widen this track into side-channel claims.
- [x] Keep implementation-facing algebraic proofs in Verus.

## Current Scope

The current proof boundary is intentionally frozen at:

- the handwritten staged boundary model in
  [../../lean-boundary/EcdsaHssBoundary/Scope.lean](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-boundary/EcdsaHssBoundary/Scope.lean)
- the generated Rust boundary bridge in
  [../../lean-boundary/EcdsaHssBoundary/GeneratedVisibleBoundary.lean](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-boundary/EcdsaHssBoundary/GeneratedVisibleBoundary.lean)

This privacy pass does not attempt to prove hidden-eval compilation, transport,
or runtime orchestration semantics.

Current decision:

- keep this privacy track frozen at the current server-visible staged boundary
- keep boundary-level client/server non-derivability in scope, while richer
  client-adversary models stay out of scope
- widen only if there is a concrete hidden-eval or client-adversary proof need
- keep hidden-eval compiler correctness, transport/runtime orchestration, and
  side-channel claims out of this track
- keep implementation-facing algebraic proofs in Verus

## Next Expansion: Hidden-Eval And Runtime-Seam Privacy

If we widen beyond the current frozen staged-boundary model, the next step
should be a narrow hidden-eval/compiler and transport/state-seam expansion.

That means:

- keep proving secrecy over explicit boundary models
- do not jump directly to "prove the whole runtime"
- treat side-channel resistance as a separate security-engineering track

### Phase P9: Hidden-Eval/Compiler Boundary Model

- [ ] add a handwritten Lean model for the hidden-eval/compiler-facing
      boundary
- [ ] define the exact observable fields at that seam for non-export and
      explicit-export flows
- [ ] define which hidden materials may vary behind that seam while preserving
      the same observable hidden-eval/compiler boundary
- [ ] restate the current secrecy goals over hidden-eval/compiler-boundary
      state pairs instead of only staged-boundary state pairs

### Phase P10: Transport And Persisted-State Exclusion

- [ ] add a handwritten model for transport-visible non-export messages
- [ ] add a handwritten model for transport-visible explicit-export messages
- [ ] add a handwritten model for persisted staged runtime state
- [ ] define field-level disclosure predicates for those message/state models
- [ ] prove forbidden secret material is absent from non-export transport
      messages
- [ ] prove forbidden secret material is absent from persisted staged runtime
      state after the accepted boundary
- [ ] prove explicit export remains the only allowed canonical-secret
      disclosure exception at the transport/state layer

### Phase P11: Generated-Boundary Lift For The New Seam

- [ ] extend the `lean-boundary/` extraction path to the hidden-eval/compiler
      facade
- [ ] map the generated hidden-eval/compiler artifact into the new handwritten
      privacy model
- [ ] lift the hidden-eval/compiler secrecy theorems onto the generated Rust
      boundary
- [ ] add anti-drift checks so the Rust hidden-eval/compiler seam cannot move
      without updating the Lean model

### Still Out Of Scope

- [ ] do not widen this track into full runtime orchestration proofs
- [ ] do not widen this track into compiler correctness beyond the frozen
      hidden-eval/compiler-facing facade
- [ ] do not widen this track into side-channel claims
