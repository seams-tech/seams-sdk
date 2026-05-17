# `ecdsa-hss` Verus Implementation Plan

Last updated: 2026-05-17

This document is the Verus-local implementation plan for the narrow stable
slice.

The wider formal-verification strategy still lives at:

- [../../docs/implementation-plan.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/docs/implementation-plan.md)

## Scope

The current Verus crate covers only the stable slice that is already frozen in
the specs:

1. `encode_context_v1`
2. canonical `x` derivation shape
3. additive-share derivation shape
4. fixed participant-ID mapping shape into the current backend seam
5. explicit-export output-policy shape
6. initial true-blind role-local boundary shape

## Phase 0: Bootstrap

- [x] add `Cargo.toml`
- [x] add `src/lib.rs`
- [x] add narrow stable-slice module mirrors
- [x] add root proof inventory reference
- [x] add repo-local verifier wrapper commands

## Phase 1: Shared Fixed-Function Slice

- [x] add `src/shared/context.rs`
- [x] add `src/shared/derivation.rs`
- [x] prove deterministic `encode_context_v1`
- [x] prove canonical `x` determinism and valid scalar range
- [x] prove additive-share reconstruction and non-zero outputs
- [x] connect proofs to the fixture corpus

## Phase 2: Backend Seam

- [x] add `src/integration/share_mapping.rs`
- [x] prove the fixed `{1, 2}` participant-ID mapping
- [x] prove mapped shares preserve the same effective signing key
- [x] prove threshold public key equals `x * G`
- [x] prove threshold signing address equals `addr(x * G)`

## Phase 3: Output Policy

- [x] add `src/server/policy.rs`
- [x] add `src/server/state.rs`
- [x] prove explicit export is the only key-revealing operation
- [x] prove non-export operations cannot return canonical `x`
- [x] prove retained-state exclusions for forbidden root material

## Phase 4: True-Blind Boundary Mirror

- [x] add `src/shared/true_blind_boundary.rs`
- [x] mirror the settled Lean true-blind boundary contract in Rust-shaped Verus
      types
- [x] prove active wire envelopes exclude client root material, client share
      material, and canonical `x`
- [x] prove relayer export share release is restricted to explicit-export wire
      envelopes
- [x] prove explicit-export authorization and wire envelopes bind to the same
      public transcript
- [x] prove role-local signing sessions require matching public identity and
      context binding
- [x] align the context encoding model with the fixed `evm-family` key scope

## Remaining Scope

Remaining outside this bootstrap:

- full production server-blindness after the Rust rewrite
- retained-state privacy beyond the modeled boundary shape
- full Rust boundary extraction
- full integration/runtime correctness

Those remain follow-on work after the production Rust boundary exists.
