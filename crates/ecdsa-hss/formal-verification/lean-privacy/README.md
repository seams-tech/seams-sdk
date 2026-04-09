# `ecdsa-hss` Lean Privacy Track

This directory is the Lean 4 track for privacy claims that are intentionally
separate from the implementation-oriented Verus pass and the narrow Rust-to-Lean
boundary bridge:

- the server-visible staged boundary does not reveal threshold-derived private
  material
- client/server secrecy claims are stated over full handwritten execution
  states and proved via observable-boundary projections
- explicit export is the only canonical-secret disclosure exception in the
  frozen client-visible boundary

This track sits above
[lean-boundary/](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-boundary)
and uses its generated boundary bridge rather than rebuilding a second Rust
model.

## Layout

- `lakefile.lean`
- `lean-toolchain`
- `EcdsaHssPrivacy.lean`
- `EcdsaHssPrivacy/`
- `docs/`

## Commands

Run from this directory:

```sh
lake build
```

Or from the repo root through the wrapper:

```sh
just ecdsa-hss-fv-privacy
```

## Scope

This first `ecdsa-hss` privacy pass is intentionally narrow:

- server-visible staged boundary only
- hidden threshold-derived private material only:
  - `canonical_x`
  - `x_client`
- explicit `ProtocolExecutionState` now exists and carries the boundary plus
  client secrets, server secrets, and `canonical_x`
- explicit `ClientSecretState` and `ServerSecretState` now exist for the first
  widened reconstruction-oriented model slice
- explicit `ClientObservableProfile` and `ServerObservableProfile` now exist
- simulator inputs are now built only from observable client/server boundary
  projections, not from hidden secrets
- compatibility theorems now connect full execution states to those
  observable-only simulators
- explicit observable-profile equivalence and indistinguishability relations
  now exist for client/server views over the frozen staged-boundary fields
- first reconstruction-style non-derivability goals now exist for client and
  server secrets over state pairs that share the same observable boundary
- the explicit-export exception is now isolated for canonical-secret payload
  disclosure on policy-consistent boundaries
- generated-boundary client/server view mappings and non-derivability lifts now
  exist in the Aeneas bridge
- bridge lemmas from the generated boundary into the handwritten full-state
  privacy model now exist

Out of scope here:

- full indistinguishability machinery for richer adversaries
- hidden-eval compiler semantics
- Verus implementation invariants

Current decision:

- keep this track frozen at the server-visible staged boundary
- keep privacy claims limited to frozen-boundary observable-view invariance,
  not richer client-adversary or hidden-eval models
- keep hidden-eval compiler correctness, transport/runtime orchestration, and
  side-channel claims out of this track
- keep implementation-facing algebraic proofs in Verus

See:

- [docs/implementation-plan.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-privacy/docs/implementation-plan.md)
