# `ed25519-hss` Verus Implementation Plan

Last updated: 2026-04-07

## Decision

The new primary verification path is Verus so we can prove the Rust
implementation more directly.

## Plan Status

This Verus pass is complete for its intended proof boundary and is now frozen
at implementation/boundary correctness plus anti-drift coverage.

## Recommended Location

The Verus code should live in:

- [`formal-verification/verus/`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/verus)

Recommended structure:

- `formal-verification/verus/Cargo.toml`
- `formal-verification/verus/src/lib.rs`
- `formal-verification/verus/src/shared/reference.rs`
- `formal-verification/verus/src/candidate.rs`
- `formal-verification/verus/src/artifact/prime_order_encoder.rs`
- `formal-verification/verus/src/ddh/hidden_eval.rs`
- `formal-verification/verus/src/ddh/hidden_eval_executor.rs`
- `formal-verification/verus/docs/`

## Why This Location

- It keeps verifier-specific code out of the production crate while we are
  still discovering the right proof boundary.
- It lets the verification code mirror the production Rust module tree 1:1.
- It avoids mixing Lean privacy artifacts with the active Rust-verification
  effort.
- It keeps future breaking refactors local to the verification track instead of
  polluting `src/` with transitional proof scaffolding.

## Initial Proof Boundary

Start with the same low-level scope already identified for the crate:

1. [`../../src/shared/reference.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/shared/reference.rs)
   - `add_le_bytes_mod_2_256`
   - `clamp_rfc8032`
   - `extract_a_bytes_from_hash`
   - `eval_nonlinear_expansion`
   - `derive_output_shares`
   - `recover_a_from_base_shares`
   - `public_key_from_scalar_bytes`
   - `public_key_from_base_shares`
   - `eval_f_expand`
2. [`../../src/candidate.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/candidate.rs)
3. [`../../src/artifact/prime_order_encoder.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/artifact/prime_order_encoder.rs)
4. [`../../src/ddh/hidden_eval.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/ddh/hidden_eval.rs)

Do not start with:

- full OT/session/runtime proof
- full client/server protocol proof
- browser/server integration proof

## Trusted Boundaries

The first Verus pass should still treat these as trusted boundaries:

- `sha2` SHA-512 internals
- `curve25519-dalek` scalar arithmetic internals
- `curve25519-dalek` basepoint multiplication/compression internals

The first goal is to prove the crate's glue logic and invariant preservation
around those dependencies, not to prove the cryptographic libraries
themselves.

## Phased Todo List

### Phase 0: Bootstrap

- [x] Create the standalone verification crate at `formal-verification/verus/`.
- [x] Add `Cargo.toml` and `src/lib.rs`.
- [x] Mirror the production module layout under `verus/src/`.
- [x] Add bootstrap placeholder modules for:
  - `shared/reference.rs`
  - `candidate.rs`
  - `artifact/prime_order_encoder.rs`
  - `ddh/hidden_eval.rs`
  - `ddh/hidden_eval_executor.rs`
- [x] Add top-level Verus track docs:
  - `verus/README.md`
  - `verus/docs/implementation-plan.md`
- [x] Validate the bootstrap crate with plain `cargo check`.
- [x] Add the actual Verus toolchain command path.
- [x] Decide whether Verus runs in place or through a wrapper command.

### Phase 1: Reference Helpers

- [x] Mirror the Rust data types from `shared/reference.rs` in the Verus crate.
- [x] Start with `add_le_bytes_mod_2_256`.
- [x] Add `clamp_rfc8032`.
- [x] Add `extract_a_bytes_from_hash`.
- [x] Add `eval_nonlinear_expansion`.
- [x] Add `derive_output_shares`.
- [x] Add `recover_a_from_base_shares`.
- [x] Add `public_key_from_scalar_bytes`.
- [x] Add `public_key_from_base_shares`.
- [x] Add `eval_f_expand`.
- [x] Reuse the committed fixture corpus as an executable parity bridge.

Definition of done:

- the Verus crate has verified counterparts for the clear helper functions,
- the core `F_expand` field relations are expressed against Rust-shaped types,
- fixture-backed parity remains green.

### Phase 2: Deterministic Shape

- [x] Add a verification module for `candidate.rs`.
- [x] Prove the first candidate metadata/shape invariants.
- [x] Extend `candidate.rs` with backend-family and artifact-inventory shape invariants.
- [x] Add a verification module for `artifact/prime_order_encoder.rs`.
- [x] Prove the first fixed section layout/size invariants.
- [x] Add a verification module for `ddh/hidden_eval.rs`.
- [x] Prove the first hidden-eval stage count and stage ordering invariants.
- [x] Prove the first output-boundary shape invariants.

### Phase 3: Executor Boundary

- [x] Add a verification module for `ddh/hidden_eval_executor.rs`.
- [x] Add the first visible executor-boundary shape slice.
- [x] Expose the first spec-facing `eval_f_expand` boundary slice for `canonical_seed`.
- [x] Factor the reference visible-boundary projection into a shared helper used by the executor proof path.
- [x] Make the shared/output-boundary projection helpers spec-usable and prove executor/reference projection agreement for any `FExpandOutput`.
- [x] Make the lower-level three-output executor/reference boundary match explicit as a whole-record equality at the output projection layer.
- [x] Add a single reference-side input-to-visible-boundary helper and route the executor helper through it.
- [x] Check the `auto_spec` feasibility of the input-level visible-boundary helper and record the current blocker.
- [x] Add the first non-export boundary-discipline proof excluding direct `y_relayer`, `tau_relayer`, and commitment outputs from the visible executor surface.
- [x] Add the non-export boundary-discipline proof that relayer-base is exposed only as transport bundles, not as a direct visible share bundle.
- [x] Add the non-export boundary-discipline proof excluding the remaining clear `F_expand` fields from the visible executor surface.
- [x] Add the positive non-export boundary-discipline proof for the allowed visible output classes.
- [x] Add the exact non-export boundary partition theorem combining allowed and excluded output classes.
- [x] Prove the shared and executor visible-boundary projections depend only on the three allowed visible fields.
- [x] Extend the spec-facing `eval_f_expand` boundary to `x_client_base` and `x_relayer_base`.
- [x] Prove the executor boundary matches `eval_f_expand` at:
  - `canonical_seed`
  - `x_client_base`
  - `x_relayer_base`
- [x] Keep full runtime/transport proof out of scope.

### Phase 4: Decide Next Expansion

- [x] Add anti-drift checks between production Rust constants/layout facts and the Verus mirror.
- [x] Add executable anti-drift parity for the output-level visible-boundary projection.
- [x] Add anti-drift executor visible-boundary parity against the production reference output path.
- [x] Add the first selected runtime invariant isolating the explicit export exception.
- [x] Prove the seed-capable runtime predicate is exactly `ExplicitKeyExport`.
- [x] Add the narrow finalize/output-packet invariant tying seed-output presence to the export exception.
- [x] Add the narrow output-projection stage-response invariant tying `allowed_output_kind` to the export exception.
- [x] Prove the finalize and output-projection runtime boundaries stay consistent for the same operation.
- [x] Add the minimal server boundary-state invariant showing the carried operation determines both outward-facing boundaries.
- [x] Add the first narrow transport-facing property: output-projection responses are metadata-only and never carry seed output directly.
- [x] Prove finalize is the only runtime boundary that can carry seed output directly.
- [x] Prove non-export operations stay client-output-only across both runtime packet shapes and the derived boundary state.
- [x] Add a packet-level anti-drift check for the runtime output-kind boundary.
- [x] Add a packet-level anti-drift check that finalize and report delivery keep client/seed/server output lanes split.
- [x] Decide whether to continue with deeper executor proof.
- [x] Decide whether to add narrower transport-facing properties.

## Current Status

Completed now:

- standalone Verus verification crate exists,
- Rust-shaped module skeleton exists,
- top-level docs exist,
- the bootstrap crate passes `cargo check`,
- Verus runs through the wrapper command path:
  `cargo hss-fv verus-check` and `just fv-verus`,
- the Verus toolchain is installed locally and the wrapper now runs the real
  verifier,
- the verification-side `shared/reference.rs` mirrors the production
  `CanonicalContext`, `FExpandInput`, `FExpandOutput`,
  `NonlinearExpansionOutput`, and `OutputShareDerivationOutput` shapes,
- the first verified reference-helper slice is in place for
  `add_le_bytes_mod_2_256`, `clamp_rfc8032`, and
  `extract_a_bytes_from_hash`,
- `eval_nonlinear_expansion` is now verified around explicit trusted
  boundaries for SHA-512 and scalar reduction,
- the share-derivation, recovery, public-key, and top-level `eval_f_expand`
  helper layer is now verified around explicit trusted scalar and basepoint
  boundaries,
- the committed fixture corpus now runs as the executable parity bridge in the
  `just fv-verus` wrapper path,
- the first deterministic candidate-shape slice is in place for the fixed
  candidate version/function-id constants and the fixed message-flow and
  hidden-core stage counts/boundaries,
- `candidate.rs` now also covers the fixed backend-family count and the fixed
  artifact-inventory bucket counts from the production candidate builder,
- `shared/reference.rs` now carries a real spec-level model for
  `add_le_bytes_mod_2_256`, and `eval_f_expand` is strengthened against that
  byte-level addition model instead of only the local exec helper,
- `artifact/prime_order_encoder.rs` now covers the fixed section-count,
  allocated-prefix-byte, fixed prefix section byte-length, and first/last
  section invariants for the production prime-order layout,
- `ddh/hidden_eval.rs` now covers the fixed seven-stage order, the four
  round-state stage blocks, fixed active/preload window counts, the first
  output-boundary shape counts, and the fixed `prime_order_ddh` primitive kind,
- `ddh/hidden_eval_executor.rs` now covers the first visible executor-boundary
  slice: a Rust-shaped visible record for `canonical_seed`, `x_client_base`,
  and `x_relayer_base`, plus fixed visible-output count/order invariants and
  the production-shaped four-bundle split with two relayer transport bundles,
- `shared/reference.rs` now exposes the first spec-facing `eval_f_expand`
  boundary slice for `canonical_seed`, and
  `ddh/hidden_eval_executor.rs` proves the executor-visible `canonical_seed`
  matches that byte-level boundary spec,
- `shared/reference.rs` now also lifts the input-level visible boundary onto
  whole-array spec values for `canonical_seed`, `x_client_base`, and
  `x_relayer_base`,
- `shared/reference.rs` now also owns the shared projection from
  `FExpandOutput` into the stable three-field visible boundary shape, and
  `ddh/hidden_eval_executor.rs` delegates to that helper instead of projecting
  those fields independently,
- the shared reference-side and executor-side output-boundary projection
  helpers are now spec-usable, and `ddh/hidden_eval_executor.rs` proves their
  field-by-field agreement for any `FExpandOutput`,
- `ddh/hidden_eval_executor.rs` now also proves the lower-level
  executor/reference visible-boundary match as a whole-record equality at the
  output projection layer,
- `shared/reference.rs` now owns the input-level visible-boundary helper as
  well, and `ddh/hidden_eval_executor.rs` routes its input-level projection
  through that single shared helper instead of wiring `eval_f_expand`
  directly,
- the input-level helper is not yet `auto_spec`-compatible because it still
  calls exec-only `eval_f_expand`; the plan now treats that as an explicit
  blocker instead of pretending the all-three-output input-level boundary is
  already spec-usable,
- `ddh/hidden_eval_executor.rs` now also carries the first non-export
  boundary-discipline proof: the visible executor surface excludes direct
  `y_relayer`, `tau_relayer`, and commitment outputs,
- `ddh/hidden_eval_executor.rs` now also proves the non-export relayer-base
  output is transport-only rather than a direct visible share bundle,
- `ddh/hidden_eval_executor.rs` now also excludes the remaining clear
  `F_expand` fields from the non-export visible executor surface:
  `tau`, `a`, `a_bytes`, `public_key`, and `context_binding`,
- `ddh/hidden_eval_executor.rs` now also states the positive non-export
  boundary rule explicitly: one canonical-seed visible bundle, one
  `x_client_base` visible bundle, and two relayer-base transport bundles,
- `ddh/hidden_eval_executor.rs` now also combines the allowed and excluded
  classes into one exact non-export boundary partition theorem,
- `shared/reference.rs` and `ddh/hidden_eval_executor.rs` now also prove that
  the visible-boundary projections depend only on the three allowed visible
  fields and ignore the excluded clear `F_expand` fields,
- the output-level and input-level executor/reference visible-boundary matches
  are both now proved for `canonical_seed`, `x_client_base`, and
  `x_relayer_base`,
- the current proof boundary is now intentionally frozen at:
  reference helpers, deterministic shape, executor visible-boundary
  equivalence, runtime export-boundary invariants, and anti-drift checks,
- deeper executor internals and full runtime/transport proof are intentionally
  left out of scope for this Verus pass,
- `server/api.rs` is now mirrored narrowly enough to prove the first runtime
  invariant around the export exception: `ExplicitKeyExport` is the only
  seed-capable operation, while non-export operations remain client-output
  only,
- `server/api.rs` now also states that runtime fact as an exact predicate:
  seed-capable output is equivalent to `ExplicitKeyExport`,
- `server/api.rs` now also mirrors the narrow finalize/output-packet shape and
  proves that seed-output presence is tied exactly to the export exception,
- `server/api.rs` now also mirrors the narrow output-projection stage-response
  shape and proves its `allowed_output_kind` stays aligned with the same
  export exception boundary,
- `server/api.rs` now also proves the finalize and output-projection runtime
  boundaries stay aligned for the same operation,
- `server/api.rs` now also models a minimal server boundary state and proves
  that its carried operation determines both outward-facing boundaries and the
  finalize seed-output bit,
- `server/api.rs` now also proves the first narrow transport-facing property:
  output-projection responses carry `allowed_output_kind` metadata but never
  carry seed output directly,
- `server/api.rs` now also proves finalize is the only runtime boundary that
  can carry seed output directly,
- `server/api.rs` now also proves every non-export operation stays
  client-output-only across output projection, finalize, and the derived
  server boundary state,
- `server/api.rs` now also proves the minimal server boundary state carries one
  coherent runtime story: operation, output-projection metadata, and finalize
  seed-output behavior all encode the same export exception,
- `verus/tests/anti_drift.rs` now also checks the packet-level runtime output
  boundary on real production wire structs for both non-export and export
  cases,
- `verus/tests/anti_drift.rs` now also checks that `ServerFinalizePacket`
  keeps `server_output` out of the finalize surface and that `OutputDelivery`
  keeps the `client`, `seed`, and `server` lanes split on the report side,
- `verus/tests/anti_drift.rs` now compares the production candidate, artifact,
  and hidden-eval constants/layout facts against the Verus mirror, and
  `cargo hss-fv verus-check` runs those anti-drift tests after verifier
  success,
- the next work, if any, should be additive and narrow:
  another packet-level anti-drift check or another runtime boundary theorem,
  not a reopened full transport proof.
- `verus/tests/anti_drift.rs` now also checks executable parity between the
  reference-side and executor-side output-level visible-boundary projections on
  a real production `FExpandOutput`, and checks both projections against the
  production `eval_f_expand` output path directly at `canonical_seed`,
  `x_client_base`, and `x_relayer_base`,
- `cargo hss-fv verus-check` and `just fv-verus` are green against the current
  Verus crate.

Immediate next work:

- decide whether to stop at the now-clean output projection boundary or to
  keep pushing the blocked input-level `eval_f_expand` boundary toward full
  three-field spec usability,
- if we stay pragmatic, keep moving on non-exposure properties for non-export
  flows instead of adding more spec machinery to `shared/reference.rs`,
- isolate the explicit export exception next if we want the strongest
  implementation-facing security story without reopening the blocked
  input-level equivalence work,
- after that, decide whether the next runtime-facing slice should stay at the
  operation/output-kind layer or add a narrow server-state invariant,
- if we keep going on the runtime-facing path, the next clean target after the
  finalize/output-packet, output-projection, and minimal server-state
  invariants is either another packet-level anti-drift check or another narrow
  transport-facing property,
- if we keep going on the runtime-facing path, the next clean target is a
  narrow server-state/output packet invariant rather than a broader transport
  proof,
- if we reopen deeper executor equivalence, extend the spec-facing
  `eval_f_expand` boundary in `shared/reference.rs` from `canonical_seed` to
  `x_client_base` and `x_relayer_base` without adding opaque array specs that
  the verifier cannot connect back to the exec helpers,
- then strengthen `ddh/hidden_eval_executor.rs` so the executor-visible
  boundary matches the reference boundary at all three visible outputs from the
  input level instead of only the output projection layer,
- decide whether `artifact/prime_order_encoder.rs` still needs any additional
  fixed layout facts before the main focus shifts to deeper executor proof or
  non-exposure properties,
- keep `cargo hss-fv verus-check` green as executor-side invariants land.

## Optimization Drift Policy

The accepted work tracked in
[`optimization-v4.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/docs/plans/optimization-v4.md)
can legitimately change performance-sensitive implementation details.

When that happens:

- prefer the accepted production optimization if it does not introduce a
  security issue,
- update the Verus mirror and anti-drift checks to follow the new production
  shape,
- keep anti-drift checks focused on security-relevant stable invariants and
  visible boundaries rather than freezing every performance-related internal
  detail.

## Non-Goals For The First Verus Slice

- proving the full staged client/server flow end to end
- proving browser/wasm integration
- proving the OT protocol
- proving external cryptographic crate internals

## Migration Policy

- The Lean privacy track now lives under
  `formal-verification/lean-privacy/` for secrecy and hiding theorems above
  the current implementation boundary.
- New proof-planning and new verification code should go under
  `formal-verification/verus/`.
- Shared spec and compliance inputs remain at the top level under
  `formal-verification/docs/`.
