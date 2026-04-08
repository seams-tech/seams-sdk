# `ed25519-hss` Aeneas Lean Boundary Plan

Last updated: 2026-04-08

## Goal

Use Aeneas to generate a narrow Lean boundary model from the Rust
implementation, then prove that the generated Rust boundary matches the
handwritten Lean privacy boundary.

## Plan Status

This Aeneas track is bootstrapped and can generate a Rust-derived Lean boundary
artifact for the visible hidden-seed output slice. The remaining gap is the
handwritten bridge from that generated boundary into the Lean privacy model.
That bridge is now in place for the non-export privacy claims, and this Aeneas
track is intentionally frozen at that boundary.

## Completed Checklist

- [x] Create a separate `formal-verification/lean-boundary/` workspace for the
      future Rust-to-Lean boundary link.
- [x] Choose a sibling `lean-boundary/` folder instead of mixing generated code
      into `lean-privacy/`.
- [x] Freeze the initial extraction target to the narrow boundary slice in
      [`../../src/shared/reference.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/shared/reference.rs).
- [x] Limit the first boundary link to the subset needed for:
      `eval_f_expand`, `canonical_seed`, `x_client_base`, and
      `x_relayer_base`.
- [x] Add repo-local wrapper commands for bootstrap validation:
      `cargo hss-fv aeneas-check` and `just fv-aeneas`.
- [x] Add a pinned toolchain manifest for Aeneas, Charon, and the Lean backend.
- [x] Add a repo-local Aeneas setup script based on the official Aeneas install
      path.
- [x] Install the pinned Aeneas/Charon toolchain for local development.
- [x] Generate the first Rust-derived Lean artifacts for a minimal helper slice:
      `add_le_bytes_mod_2_256`, `clamp_rfc8032`, and
      `extract_a_bytes_from_hash`.
- [x] Keep the first generated Aeneas modules separate from handwritten bridge
      lemmas.
- [x] Add a narrow Rust boundary facade in
      [`../../src/shared/reference_boundary.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/shared/reference_boundary.rs)
      that projects the visible boundary from production `eval_f_expand`.
- [x] Generate a Lean boundary artifact for
      `eval_f_expand_visible_boundary` with production `eval_f_expand` treated
      as an opaque external.
- [x] Import the generated Lean boundary package into the `lean-boundary/`
      workspace and add the first handwritten wrapper lemmas over the generated
      visible-boundary type.

## Remaining Checklist

- [ ] Wire the pinned Aeneas/Charon toolchain into CI.
- [x] Define the type-level mapping from the generated Rust boundary to the
      handwritten privacy boundary.
- [x] Prove the generated boundary matches the handwritten non-export
      visible boundary.
- [x] Lift the current non-export Lean privacy theorems across the
      Aeneas-generated boundary bridge.
- [x] Decide to stop at the non-export visible-boundary slice.
- [x] Keep implementation-facing expansion out of scope here; cover those
      guarantees in Verus instead.

## Current Blocker

The first whole-boundary extraction attempt against
[`../../src/shared/reference.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/shared/reference.rs)
failed inside Charon after MIR transformations, not in the handwritten Lean
workspace.

Current observed boundary:

- Charon can extract self-contained helpers like `add_le_bytes_mod_2_256` and
  `clamp_rfc8032`.
- Charon can also widen one step further to `extract_a_bytes_from_hash`.
- Charon currently fails when the slice reaches `sha512_one_block`, due to
  transformed-type errors in transitive dependencies from `sha2`/`digest`,
  notably `digest/core_api/wrapper.rs`.
- The current workaround is the narrow
  [`reference_boundary.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/shared/reference_boundary.rs)
  facade, which extracts successfully when production `eval_f_expand` is kept
  opaque.

This means the current Aeneas result is intentionally narrow:

- `GeneratedClientCannotDeriveYRelayer`
- `GeneratedClientCannotDeriveTauRelayer`
- `GeneratedServerCannotDeriveClientSecrets`
- `GeneratedNonExportHiddenSeedIsHidden`

Future work, if any, should be limited to maintenance and CI wiring unless
there is a concrete new privacy-proof need that justifies widening the Rust
slice.
