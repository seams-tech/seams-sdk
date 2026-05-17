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

## True-Blind Scaffold

The true server-blindness scaffold starts in
[EcdsaHssPrivacy/TrueBlind.lean](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-privacy/EcdsaHssPrivacy/TrueBlind.lean).
The role-local boundary contract lives in
[EcdsaHssPrivacy/TrueBlindBoundary.lean](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-privacy/EcdsaHssPrivacy/TrueBlindBoundary.lean).

That module is the Lean-first target for the next ECDSA HSS protocol shape:

- client derives only `x_client`
- server derives only `x_relayer`
- public identity is `X = x_clientG + x_relayerG`
- non-export server view excludes `y_client`, `x_client`, and canonical `x`
- non-export client view excludes `y_relayer` and `x_relayer`
- explicit export reconstructs canonical `x` in the client export view

The scaffold now has scalar addition modulo the secp256k1 group order, abstract
public-key operations, concrete additive public-key agreement predicates,
explicit export reconstruction predicates, `F_ecdsa_hss_true_blind`,
observable-only simulators, first non-export view-invariance theorems, explicit
derivation assumptions for the Rust/Verus boundary, ideal-functionality
well-formedness theorems under those assumptions, and typed operation views that
prove the disclosure policy for non-export and explicit-export flows. It also
models the public transcript fields and proves the transcript excludes
root/share/canonical-secret payloads.

The boundary contract now models client bootstrap wire, server bootstrap wire,
role-local retained client/server state, explicit export wire, and client export
reconstruction. It proves those boundary shapes exclude forbidden
root/share/canonical-secret payloads and proves client reconstruction from the
export wire matches the ideal explicit-export client view. It also wraps export
wire in a transcript-bound authorization envelope and proves that explicit export
is the only active wire variant allowed to carry the relayer export share.
Bound explicit-export sessions now tie client retained state, export
authorization, and export wire to the same public identity/context before
client-side reconstruction.
Bound role-local signing sessions now tie retained client/server state to the
same public identity/context before non-export signing composition and prove
that mismatched public identities or context bindings cannot construct such a
session.
Export authorization envelopes now include a digest-validity predicate bound to
the explicit-export public transcript. The boundary proves state-created export
envelopes carry valid digests, malformed digests prevent valid export envelopes,
and a role-local envelope carrying the relayer export share must be an
authorized explicit-export wire.

The next implementation step is the active role-local Rust boundary. After that
lands, extract the implemented boundary with Aeneas and bridge it back to this
Lean model.

See:

- [docs/implementation-plan.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/docs/implementation-plan.md)
