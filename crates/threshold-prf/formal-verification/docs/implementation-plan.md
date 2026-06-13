# `threshold-prf` Formal Verification Implementation Plan

Last updated: 2026-04-17

This is the crate-local implementation plan for the active
`threshold-prf` formal-verification track.

The source plan lives at:

- [`../../docs/formal-verification-plan.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/docs/formal-verification-plan.md)

## Decision

Start with a Verus abstract spec model plus executable anti-drift checks against
the committed JSON vector corpus.

Do not implement Lean boundary extraction until there is a specific stable Rust
boundary worth extracting. The narrow Lean privacy track is active because the
one-server/two-server visibility model is stable enough to prove structurally.

Current status:

- [x] formal-verification scaffold exists
- [x] proof inventory exists
- [x] Verus-local plan exists
- [x] Lean boundary track is explicitly deferred
- [x] narrow Lean privacy execution-state model exists
- [x] prototype `threshold-prf` API exists
- [x] `PrfPartialWire` is frozen in Rust
- [x] production `threshold-prf` API/spec boundary is stable enough for parity FV
- [x] committed JSON vector corpus exists
- [x] first Verus abstract spec model exists
- [x] production anti-drift parity test exists
- [x] `just threshold-prf-fv` exists
- [x] abstract malformed scalar-encoding rejection is proved
- [x] output derivation explicitly carries suite, purpose, context, and point
  inputs in the model
- [x] abstract DLEQ boundary model exists
- [x] abstract secret signing-root share wire boundary model exists
- [x] current FV scope is accepted as sufficient for first Option A integration

## Phase 0: Scaffold

- [x] create `crates/threshold-prf/formal-verification/`
- [x] add `formal-verification/README.md`
- [x] add `formal-verification/docs/implementation-plan.md`
- [x] add `formal-verification/docs/proof-inventory.md`
- [x] add `formal-verification/fixtures/README.md`
- [x] add `formal-verification/verus/README.md`
- [x] add `formal-verification/verus/docs/implementation-plan.md`
- [x] add `formal-verification/lean-boundary/README.md`
- [x] add `formal-verification/lean-boundary/docs/implementation-plan.md`
- [x] add `formal-verification/lean-privacy/README.md`
- [x] add `formal-verification/lean-privacy/docs/implementation-plan.md`

## Phase 1: Verus Abstract Spec Bootstrap

- [x] create `formal-verification/verus/Cargo.toml`
- [x] create `formal-verification/verus/src/lib.rs`
- [x] create `formal-verification/verus/src/model.rs`
- [x] add abstract scalar, share, partial, context, purpose, and output models
- [x] add an abstract `PrfPartialWire` model with share ID, context tag, and
  compressed point fields
- [x] add an abstract `SigningRootShareWire` model with share ID and canonical
  share scalar fields
- [x] avoid proving against placeholder formulas disconnected from the specs
- [ ] mirror the production module layout under `verus/src/` after the Rust/FV
  module split can compile under both Verus and normal Cargo parity tests

Decision: the production module mirror is deferred maintainability. The current
Verus abstract spec model, production anti-drift tests, and Lean privacy model
are accepted as the first Option A integration gate. Do not add a duplicate
legacy mirror unless it can compile cleanly under both Verus and normal Cargo
parity tests.

## Phase 2: Input Domain And Encoding Proofs

- [x] prove output width is fixed
- [x] prove share IDs are non-zero
- [x] prove duplicate share IDs are rejected
- [x] prove insufficient threshold subsets are rejected
- [x] prove malformed scalar encodings are rejected
- [x] prove zero root scalars are rejected
- [x] prove zero share scalars are accepted when canonically encoded
- [x] prove partial wire context tag width and presence
- [x] prove secret signing-root share wire width, share-ID, and scalar-domain
  rejection behavior

## Phase 3: Shamir And Refresh Proofs

- [x] model 2-of-3 Shamir shares over the chosen field abstraction
- [x] prove each valid pair reconstructs the same root scalar
- [x] prove all three valid 2-of-3 pairs are equivalent
- [x] prove refreshed shares preserve the same root scalar
- [x] prove refreshed valid pairs reconstruct the same root scalar

## Phase 4: PRF Equivalence Proofs

- [x] model direct reference PRF evaluation
- [x] model partial PRF evaluation
- [x] model partial combination
- [x] prove every valid 2-of-3 partial combination equals direct reference output
- [x] prove one-worker and two-worker placement are byte-identical in the model
- [x] prove purpose/context are explicit inputs to output derivation
- [x] prove transported partial context tags are checked before combine
- [x] prove the production Option A/Option B model does not depend on direct
  reference evaluation
- [x] prove generated secret share-wire Option A derivation matches direct
  reference output

## Phase 5: Vectors And Anti-Drift

- [x] define the initial fixed 2-of-3 vector corpus
- [x] mirror or reference the committed corpus from `formal-verification/fixtures/`
- [x] add root-generation vectors from fixed seed material
- [x] add 2-of-3 splitting vectors
- [x] add direct reference evaluation vectors
- [x] add every valid pairwise combine vector
- [x] add refreshed-share vectors
- [x] add `PrfPartialWire` vectors
- [x] add malformed-input rejection vectors where practical
- [x] add anti-drift tests comparing production helpers to vectors
- [x] add anti-drift coverage for server-SDK signing-root share wire derivation
- [x] add anti-drift coverage for malformed server-SDK signing-root share wires

## Phase 6: DLEQ Boundary Proofs

- [x] model share commitment wire width
- [x] model DLEQ proof wire width
- [x] model proof-bundle wire width
- [x] prove commitment/partial share-ID mismatch is rejected
- [x] prove commitment share IDs outside the selected policy are rejected
- [x] add production Rust rejection coverage for wrong-context, duplicate-bundle,
  malformed-proof, and commitment/partial share-ID mismatch cases
- [ ] model DLEQ challenge input binding tuple
- [ ] prove generated abstract DLEQ proof verifies for a valid evaluated partial
- [ ] prove wrong-context DLEQ verification is rejected
- [ ] model and prove the DLEQ-enforced `combine_verified_partials` boundary
- [ ] add committed DLEQ vectors if DLEQ byte compatibility becomes a production
  compatibility boundary
- [x] decide whether DLEQ cryptographic soundness beyond the abstract boundary is
  in scope

Decision: DLEQ cryptographic soundness beyond the abstract boundary is out of
scope for the current Verus track. Ristretto arithmetic, SHA-512,
Fiat-Shamir soundness, and concrete malicious-worker security remain trusted
seams unless a dedicated cryptographic proof track is approved.

## Deferred Lean Boundary

Only after the Rust-facing boundary is stable:

- decide whether any boundary is important enough to justify Aeneas extraction
- if yes, freeze that boundary and add extraction/build commands
- if no, keep Verus plus anti-drift as the active FV path

## Lean Privacy

The narrow Lean privacy track is active as a structural execution-state model.
It does not prove runtime isolation or cryptographic DLEQ soundness.

- [x] define one-server and two-server execution states
- [x] model one-server mode as observing two plaintext root shares
- [x] prove a single two-server participant cannot reconstruct `k_org` from one
  local share state in the structural share-count model
- [x] prove combiner-visible state excludes plaintext root and share scalars
- [x] document explicitly that one-server mode is not a malicious-runtime
  privacy boundary
- [x] prove public outputs exclude root scalars, share scalars, and
  reconstructed `k_org`

## Justfile Commands

The active commands are:

```just
threshold-prf-fv-parity:
  cargo test -q --manifest-path crates/threshold-prf/formal-verification/verus/Cargo.toml --tests

threshold-prf-fv-verus:
  cargo verus verify --manifest-path crates/threshold-prf/formal-verification/verus/Cargo.toml

threshold-prf-fv:
  just threshold-prf-fv-parity
  just threshold-prf-fv-verus
  just threshold-prf-fv-privacy

threshold-prf-fv-privacy:
  cd crates/threshold-prf/formal-verification/lean-privacy && $HOME/.elan/bin/lake build
```

`just threshold-prf-fv` is included in the top-level `fv` recipe.
