# `router-ab-ecdsa-derivation` Aeneas Lean Boundary Plan

Last updated: 2026-05-20

## Goal

Use Aeneas to generate a narrow Lean boundary model from the `router-ab-ecdsa-derivation` Rust
boundary, then prove that the generated boundary matches the handwritten Lean
boundary model for:

- non-export visible outputs
- explicit export visible outputs
- finalized retained-state exclusions
- operation-to-output-kind boundary shape

## Plan Status

This track previously had a working local extraction path for the narrow staged
server boundary. The role-local rewrite deleted the production
`server::reference_boundary` facade. The current track uses a non-production
extraction crate that mirrors the role-local boundary for Aeneas without adding
a runtime reference path.

Current observed state:

- the Verus stable slice is complete and warning-free
- the Rust boundary is stable enough to justify a narrow extraction target
- the non-production extraction crate exists under `rust-boundary/`
- the Lean workspace bootstrap exists
- the pinned `aeneas` and `charon` toolchain is installed locally
- the generated Lean artifact exists under `generated/visible-boundary-*`
- the generated package is copied into `RouterAbEcdsaDerivation/`
- handwritten bridge lemmas live in `RouterAbEcdsaDerivationBoundary/`
- the handwritten boundary model is typed to the role-local generated field
  layout
- bridge lemmas cover:
  - operation-to-output-kind policy
  - visible non-export output shape
  - visible explicit-export output shape
  - retained-state boundary shape
  - hidden-eval input, transport, and persisted-state shape

## Completed Checklist

- [x] Decide that the Rust boundary is stable enough to justify extraction.
- [x] Create a separate `formal-verification/lean-boundary/` workspace for the
      Rust-to-Lean boundary link.
- [x] Freeze the initial extraction target to the narrow non-export/export
      boundary.
- [x] Keep broader protocol/privacy expansion out of scope until the first
      boundary bridge works.
- [x] Add Lean workspace bootstrap files:
      `lakefile.lean`, `lean-toolchain`, and root modules.
- [x] Add pinned Aeneas/Charon toolchain metadata.
- [x] Add a repo-local setup script for the future Aeneas/Charon toolchain.
- [x] Add a repo-local wrapper command for the Lean boundary bootstrap.
- [x] Add a narrow Rust boundary facade for the previous extraction.
- [x] Delete the previous production facade during the role-local rewrite.
- [x] Disable the stale extraction command so it cannot be mistaken for current
      role-local bridge coverage.
- [x] Add a non-production role-local extraction crate.
- [x] Regenerate the Rust-derived Lean boundary artifact from the role-local
      crate.
- [x] Update handwritten bridge lemmas for the role-local generated field
      layout.
- [x] Re-enable the Aeneas boundary command in the default `router-ab-ecdsa-derivation` formal
      gate.

## Remaining Checklist

- [x] Install the pinned Aeneas/Charon toolchain for local development.
- [x] Generate the first Rust-derived Lean boundary artifact for the previous
      non-export/export boundary.
- [x] Keep the generated Aeneas modules separate from handwritten bridge
      lemmas.
- [x] Define the type-level mapping from the generated boundary to the
      handwritten Lean boundary.
- [x] Prove the generated boundary matches the handwritten boundary model.
- [x] Decide whether a separate `lean-privacy/` workspace is justified after
      the first boundary bridge works.
- [x] Add a non-production role-local extraction crate or fixture-only facade.
- [x] Regenerate the Rust-derived Lean boundary artifact from the role-local
      facade.
- [x] Update handwritten bridge lemmas for the role-local generated field
      layout.

## Next Expansion: Hidden-Eval Boundary

After the current staged-boundary bridge, the next extraction target should be
the hidden-eval/compiler-facing seam rather than a broader runtime grab-bag.

That next bridge should answer:

- does the generated hidden-eval/compiler boundary match the handwritten
  secrecy model we rely on?
- do the Rust-visible fields at that seam exclude forbidden secret material in
  non-export flows?

It should not try to cover:

- full runtime orchestration
- session transport implementations outside the frozen seam
- side-channel properties

### Hidden-Eval Boundary Checklist

- [x] freeze the Rust facade for the hidden-eval/compiler-facing seam
- [x] create a dedicated extraction target for that facade
- [x] generate the first Rust-derived Lean artifact for the hidden-eval seam
- [x] keep generated hidden-eval modules separate from handwritten bridge
      lemmas
- [x] define the handwritten Lean model for the hidden-eval/compiler boundary
- [x] prove the generated hidden-eval/compiler boundary matches that
      handwritten model
- [x] connect the hidden-eval/compiler boundary bridge to the existing
      `lean-privacy/` secrecy theorems

## Current Scope

The extraction target is a non-production facade that mirrors the role-local
server/client boundary. Keep the production crate free of
`server::reference_boundary` modules.

The first bridge should stop at:

- non-export output shape
- explicit export output shape
- finalized retained-state shape
- operation-to-output-kind mapping

It should not widen into:

- canonical `x` derivation
- additive-share derivation
- backend share mapping
- secp256k1/Keccak primitive modeling

Those remain in Verus.

