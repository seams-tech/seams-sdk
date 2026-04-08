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

This Lean privacy pass is complete for its intended proof boundary.
This Lean track should sit above the current Verus-visible boundary and should
not rebuild a second full implementation model.

The intended bridge is:
- Verus proves the Rust implementation exposes only the intended visible
  boundary
- Lean proves secrecy and hiding properties over that visible boundary under
  the selected assumptions

## Completed Checklist

- [x] Create the new `formal-verification/lean-privacy/` workspace
- [x] Define the privacy model:
      public parameters, client/server secret state, non-export visible
      boundary, explicit export boundary, and client/server view projections.
- [x] Define the adversary and simulator layer for non-export client/server
      views.
- [x] State and prove the core privacy theorems:
      non-export hidden-seed hiding, client non-derivability of `y_relayer`
      and `tau_relayer`, server non-derivability of client-secret material,
      and explicit-export exception isolation.
- [x] Replace placeholder assumptions with simulator-based compatibility and
      observational-secrecy assumptions.
- [x] Recast the privacy goals onto explicit indistinguishability relations for
      client/server views under hidden-secret variation.
- [x] Strengthen indistinguishability from raw view equality to structured
      observable-field equivalence and observable profiles.
- [x] Freeze this Lean privacy pass at the observable-profile
      indistinguishability boundary.

## Current Status

Completed now:

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

## Future Work: Aeneas Rust-to-Lean Boundary Link

If we want a mechanically linked Rust→Lean boundary proof, add Aeneas as a
separate follow-on track. The goal is not to rebuild a second full
implementation model in Lean. The goal is to generate a narrow Lean boundary
model from Rust and prove that it matches the handwritten privacy boundary.

### Aeneas Phased Todo List

#### Phase A0: Bootstrap Aeneas Workspace

- [x] Choose the generated-code location:
      either `lean-privacy/generated/` or a sibling `lean-boundary/` folder.
- [x] Add repo-local wrapper commands for this track.
- [x] Add a pinned Aeneas/Charon/Lean toolchain manifest.
- [x] Add a repo-local Aeneas setup script based on the official install path.
- [x] Document the Rust→Lean boundary scope and what remains out of scope.

#### Phase A1: Boundary Extraction Target

- [x] Freeze the initial extraction slice to the narrow boundary only.
- [x] Start with `crates/ed25519-hss/src/shared/reference.rs`.
- [x] Identify the smallest subset needed for:
      `eval_f_expand`, `canonical_seed`, `x_client_base`, and
      `x_relayer_base`.

#### Phase A2: Generate Lean Boundary Model

- [x] Run Aeneas on the selected Rust slice.
- [x] Check the generated Lean modules into the repo as generated artifacts.
- [x] Keep generated code separate from handwritten privacy proof modules.

#### Phase A3: Bridge Generated Boundary to Privacy Model

- [x] Define the mapping from the Aeneas-generated boundary types to
      `Ed25519HssPrivacy.Model`.
- [x] Prove that the generated Rust boundary model matches the handwritten
      non-export visible boundary model.
- [x] Prove that the generated client/server views match the current Lean
      privacy view projections.

#### Phase A4: Lift Privacy Theorems Across the Bridge

- [x] Re-state the current non-export privacy theorems over the Aeneas-generated
      boundary.
- [x] Prove that the existing non-export privacy theorems apply to the
      generated Rust boundary through the bridge lemmas.
- [x] Make the Rust→Lean boundary proof the default interpretation of the
      non-export Lean privacy claims.

#### Phase A5: Scope Decision

- [x] Decide to stop at the non-export visible-boundary slice.
- [x] Keep implementation-facing expansion out of scope in Aeneas and cover it
      in Verus instead.
- [x] Keep full-crate Rust→Lean translation out of scope unless there is a
      concrete new privacy-proof need that justifies the extra complexity.
