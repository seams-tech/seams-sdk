# `threshold-prf` Verus Implementation Plan

Last updated: 2026-04-16

The Verus-local track has started with an abstract spec model. This model is
independent of the Rust implementation. Production anti-drift checks pin the
committed vector corpus to the current Rust helper APIs.

## Module Mirror

The Verus crate intentionally keeps one abstract model module today. A
production-shaped module split is deferred until the same files can compile
under both Verus and the normal Cargo parity-test path. A simple re-export layer
over Verus ghost/spec functions is not sufficient because those items are not
ordinary Rust exports.

Decision: this deferral is not a blocker for first Option A integration. The
current Verus abstract spec model plus production anti-drift tests are the
accepted Verus gate; add production-shaped mirrors later only if they avoid a
parallel legacy model.

## Phase 0: Bootstrap

- [x] add `formal-verification/verus/Cargo.toml`
- [x] add `formal-verification/verus/src/lib.rs`
- [x] add `formal-verification/verus/src/model.rs`
- [x] defer module mirrors for the first production slice until the Rust/FV
  module split can compile under both Verus and normal Cargo parity tests
  without creating a duplicate legacy model
- [x] add `formal-verification/verus/tests/anti_drift.rs`
- [x] load committed vectors from `crates/threshold-prf/fixtures/protocol-v1.json`
- [x] wire `just threshold-prf-fv-parity`
- [x] wire `just threshold-prf-fv-verus`
- [x] wire `just threshold-prf-fv`

## Phase 1: Domains And Encodings

- [x] model abstract suite, purpose, and context identity
- [x] model project-root scalar domain
- [x] model project-root share scalar domain, including zero share values
- [x] model non-zero share IDs
- [x] model fixed 32-byte PRF output
- [x] model fixed 33-byte secret `ProjectRootShareWireV1`
- [x] model `PrfPartialWireV1` as share ID, context tag, and compressed point
- [x] pin canonical HSS context bytes through production anti-drift vectors
- [x] prove malformed scalar encodings are rejected at the abstract model boundary
- [x] prove zero root encodings are rejected while zero share encodings are accepted
- [x] prove secret project-root share wire decode rejects wrong width, invalid
  share IDs, and invalid share scalars

## Phase 2: 2-of-3 Share Semantics

- [x] model exactly three share IDs
- [x] model valid 2-of-3 subsets
- [x] prove duplicate share IDs are rejected
- [x] prove one-share subsets are rejected
- [x] prove each valid pair reconstructs the same abstract root scalar

## Phase 3: PRF Equivalence

- [x] model direct reference evaluation
- [x] model partial evaluation
- [x] model partial combination
- [x] prove valid pairwise combination equals direct reference evaluation
- [x] prove one-worker and two-worker placement equivalence
- [x] prove direct reference evaluation is not part of the production
  Option A/Option B path
- [x] prove partial wire context tags are checked before combine
- [x] prove output derivation carries suite, purpose, context, and point inputs
- [x] prove generated secret share-wire Option A derivation matches direct
  reference output

## Phase 4: Refresh

- [x] model share refresh
- [x] prove refreshed shares preserve root scalar
- [x] prove refreshed valid pairs combine to the same PRF output

## Phase 5: Anti-Drift

- [x] add fixture loader for `crates/threshold-prf/fixtures/protocol-v1.json`
- [x] compare production root generation against vectors
- [x] compare production splitting against vectors
- [x] compare production direct reference evaluation against vectors
- [x] compare production pairwise combine against vectors
- [x] compare production server-SDK share-wire derivation against vectors
- [x] compare production `PrfPartialWireV1` against vectors
- [x] compare production refresh against vectors
- [x] compare rejected malformed inputs against vectors

## Phase 6: DLEQ Boundary

- [x] model share commitment wire width
- [x] model DLEQ proof wire width
- [x] model DLEQ challenge input tuple
- [x] prove generated abstract DLEQ proof verifies for a valid evaluated partial
- [x] prove commitment/partial share-ID mismatch is rejected
- [x] prove wrong-context DLEQ verification is rejected
- [x] model DLEQ proof generation as rejecting zero nonce input
- [x] model and prove the DLEQ-enforced `combine_verified_partials` boundary
- [x] add DLEQ vector parity if DLEQ byte compatibility becomes a production
  compatibility boundary
