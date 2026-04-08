# `ed25519-hss` Lean Privacy Plan

Last updated: 2026-04-08

## Goal

Use Lean 4 for the privacy properties that are stronger than the current Verus
boundary proofs:

1. non-export hidden-seed expansion is hidden from the client and the server
2. the client cannot derive `y_relayer` or `tau_relayer` from allowed outputs
3. the server cannot derive client-secret material from allowed outputs
4. explicit key export is the only allowed exception

## Plan Status

This Lean privacy pass is complete for its intended proof boundary and is now
frozen at the observable-profile indistinguishability layer.

## Boundary

This Lean track should sit above the current Verus-visible boundary and should
not rebuild a second full implementation model.

The intended bridge is:

- Verus proves the Rust implementation exposes only the intended visible
  boundary
- Lean proves secrecy and hiding properties over that visible boundary under
  the selected assumptions

## Initial Theorem Targets

### Phase 0: Bootstrap

- [x] Create the new `formal-verification/lean-privacy/` workspace.
- [x] Add a minimal `lakefile.lean` and root module.
- [x] Replace references to the retired `formal-verification/lean/` tree.

### Phase 1: Privacy Model

- [x] Define the privacy-layer public parameters.
- [x] Define client-secret and server-secret state.
- [x] Define the non-export visible boundary.
- [x] Define the explicit export boundary.
- [x] Define client view and server view projections.

### Phase 2: Adversary / Simulator Layer

- [x] Define the non-export client adversary view.
- [x] Define the non-export server adversary view.
- [x] Define a simulator for the client-visible non-export outputs.
- [x] Define a simulator for the server-visible non-export outputs.

### Phase 3: Privacy Theorem Statements

- [x] State client non-derivability of `y_relayer`.
- [x] State client non-derivability of `tau_relayer`.
- [x] State server non-derivability of client-secret material.
- [x] State non-export hidden-seed hiding.
- [x] State explicit-export exception isolation.

### Phase 4: First Privacy Proofs

- [x] Prove explicit-export exception isolation.
- [x] Prove simulator existence for non-export hidden-seed hiding.
- [x] Prove client non-derivability of `y_relayer`.
- [x] Prove client non-derivability of `tau_relayer`.
- [x] Prove server non-derivability of client-secret material.

### Phase 5: Strengthen Assumptions

- [x] Replace placeholder `True` compatibility assumptions with simulator-based compatibility assumptions.
- [x] Prove the current compatibility assumptions hold from the simulator layer.
- [x] Strengthen the simulator-based compatibility assumptions into a sharper secrecy model.

### Phase 6: Refine Privacy Claims

- [x] Recast the current non-derivability goals in terms of the new observational-secrecy layer.
- [x] Tighten the hidden-seed hiding statement from simulator existence to a stronger privacy relation.

### Phase 7: Indistinguishability Layer

- [x] Introduce an explicit indistinguishability relation for client and server adversary views.
- [x] Prove the current observational-secrecy layer implies boundary indistinguishability under hidden-secret variation.
- [x] Recast the current privacy goals in terms of the new indistinguishability layer.

### Phase 8: Strengthen Indistinguishability

- [x] Replace direct view equality with structured equivalence over public parameters and visible boundary fields.
- [x] Introduce a more abstract observable-profile indistinguishability relation above the explicit field-equality layer.

### Phase 9: Freeze Privacy Boundary

- [x] Decide to stop at the current observable-profile indistinguishability boundary for this Lean privacy pass.
- [x] Keep richer nontrivial indistinguishability relations out of scope until there is a concrete adversary model that requires them.

## Current Status

Completed now:

- the retired `formal-verification/lean/` tree has been replaced with this new
  `lean-privacy/` workspace,
- the shared `proof-check` path now targets this privacy-specific Lean track,
- the Phase 1 privacy model is now in place in:
  - `Ed25519HssPrivacy/Model.lean`
  - `Ed25519HssPrivacy/Views.lean`
- the Phase 2 adversary/simulator layer is now in place in:
  - `Ed25519HssPrivacy/Simulators.lean`
- the Phase 3 theorem statements are now in place in:
  - `Ed25519HssPrivacy/Goals.lean`
- the first proved privacy theorems are now in place in:
  - `nonExportHiddenSeedIsHidden_proved`
  - `explicitExportIsOnlyDisclosureException_proved`
- the assumption-relative non-derivability theorems are now also proved:
  - `clientCannotDeriveYRelayer_proved`
  - `clientCannotDeriveTauRelayer_proved`
  - `serverCannotDeriveClientSecrets_proved`
- the placeholder `True` assumptions have been replaced with simulator-based
  compatibility assumptions in:
  - `Ed25519HssPrivacy/Assumptions.lean`
- the simulator-based compatibility assumptions are now strengthened by
  explicit observational-secrecy statements:
  - `ClientObservationallyHidesServerSecret`
  - `ServerObservationallyHidesClientSecret`
- the current privacy goals are now phrased directly in terms of the stronger
  observational-secrecy layer:
  - `ClientCannotDeriveYRelayer`
  - `ClientCannotDeriveTauRelayer`
  - `ServerCannotDeriveClientSecrets`
  - `NonExportHiddenSeedIsHidden`
- an explicit indistinguishability layer is now in place in:
  - `ClientViewsIndistinguishable`
  - `ServerViewsIndistinguishable`
  - `ClientBoundaryIndistinguishableUnderServerSecretVariation`
  - `ServerBoundaryIndistinguishableUnderClientSecretVariation`
- the current privacy goals now sit on that indistinguishability layer.
- the indistinguishability relation is now stronger than raw view equality:
  it is expressed explicitly as observable-field equivalence over:
  - `PublicParametersEquivalent`
  - `NonExportBoundaryEquivalent`
- the indistinguishability relation is now also abstracted through:
  - `ClientObservableProfile`
  - `ServerObservableProfile`
  - `clientObservableProfile`
  - `serverObservableProfile`
- the current Lean privacy pass is now intentionally frozen at the
  observable-profile boundary.
- richer nontrivial indistinguishability relations are left out of scope until
  there is a concrete adversary model that requires them.
