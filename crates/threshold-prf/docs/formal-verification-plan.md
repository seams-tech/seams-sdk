# `threshold-prf` Formal Verification Plan

Last updated: 2026-04-17

## Decision

The recommended verification strategy for
[crates/threshold-prf](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf)
is:

- **Verus first**
- **executable anti-drift vectors against the committed JSON corpus**
- **Lean/Aeneas later only after the Rust boundary is stable**

This crate has a prototype Rust implementation and a first Verus abstract spec
model. The model proves the intended threshold-prf algebra and boundary shape,
and anti-drift tests pin the committed JSON corpus to the production Rust
helpers.

Decision: the current formal-verification scope is accepted as sufficient for
first Option A integration. The remaining production-shaped Verus module mirror
is deferred maintainability, not a correctness blocker. Trusted seams remain
Ristretto arithmetic, SHA-512, hash-to-group, Fiat-Shamir soundness, randomness
generation, runtime isolation, transport authenticity, side-channel resistance,
authenticated commitment registry behavior, and Cloudflare Worker runtime
behavior.

## Why This Is Worth Doing

`threshold-prf` is planned to own the `k_org -> y_relayer` layer before
`ed25519-hss` or `ecdsa-hss` consume server-side HSS inputs.

That means a bug here could create:

- different wallet/server inputs across one-server and two-server variants
- weak or ambiguous context binding
- purpose-domain collisions between HSS consumers
- accidental acceptance of insufficient or duplicate shares
- drift between direct reference evaluation and threshold partial combination

The highest-value FV target is the equivalence invariant:

```text
direct_prf(k_org, context, purpose)
  == combine_prf_partials([share_i, share_j], context, purpose)
  == y_relayer
```

## Primary Scope

### Priority 1: Input Domains And Encodings

The first FV pass should model:

1. suite id encoding
2. purpose encoding
3. canonical context bytes
4. non-zero signing-root scalar domain
5. canonical share scalar domain, including valid zero share values
6. non-zero share ID domain
7. output width and encoding
8. partial wire fields: share ID, context tag, and compressed point

These are high-impact because every later proof assumes stable byte-level input
domains.

### Priority 2: 2-of-3 Shamir Shape

The second FV pass should model:

1. exactly three valid share IDs
2. threshold subset size of exactly two
3. duplicate-share rejection
4. insufficient-share rejection
5. public Lagrange coefficient shape for each valid pair
6. reconstruction equivalence for each valid 2-of-3 pair
7. share refresh preserving the same root scalar
8. zero share values remain valid Shamir shares when canonically encoded

This should be proved over a small abstract field model before connecting to a
real curve suite.

### Priority 3: Threshold PRF Equivalence

The third FV pass should model:

1. direct reference evaluation
2. partial evaluation
3. partial combination
4. one-worker and two-worker placement equivalence
5. output equality for all valid 2-of-3 subsets
6. output separation by purpose and context at the model boundary
7. context-tag mismatch rejection for transported partials

The goal is not to prove hash-to-group or hash-to-bytes internals from first
principles. The goal is to prove that the crate wires the same abstract PRF
inputs through direct and threshold paths.

### Priority 4: Privacy Boundary Model

After the Rust API is stable, add a narrow Lean privacy model for:

1. one-server mode explicitly observes two root shares and is therefore not a
   malicious-runtime privacy boundary
2. two-server mode prevents either single server from reconstructing `k_org`
   from its own local state
3. combiner observes partials and `y_relayer`, not plaintext root shares
4. public outputs never include root scalars, share scalars, or reconstructed
   `k_org`

This should not start until the production boundary is stable enough to avoid
proof churn.

## Explicit Non-Goals

The initial `threshold-prf` FV plan should not try to prove:

1. full hash-to-group primitive correctness
2. full SHA-512 or hash-to-bytes correctness
3. side-channel resistance
4. operating-system or worker-runtime isolation
5. DLEQ proof soundness from first principles
6. HSS downstream correctness inside `ed25519-hss` or `ecdsa-hss`

Those remain trusted primitive/library/runtime seams unless a later dedicated
track is approved.

## Recommended Layout

The crate-local FV structure should be:

- `formal-verification/README.md`
- `formal-verification/docs/implementation-plan.md`
- `formal-verification/docs/proof-inventory.md`
- `formal-verification/fixtures/`
- `formal-verification/verus/`
- `formal-verification/lean-boundary/`
- `formal-verification/lean-privacy/`

Sequencing:

- `verus/` is the first active implementation-proof track
- `fixtures/` pins production behavior as soon as vectors exist
- `lean-boundary/` stays deferred until a Rust-facing boundary is stable
- `lean-privacy/` now carries the narrow structural two-server visibility model

## Phased Todo List

Current status:

- [x] create crate-local formal-verification docs scaffold
- [x] implement prototype `threshold-prf` crate API
- [x] freeze `PrfPartialWireV1`
- [x] add committed JSON vector corpus
- [x] add first Verus abstract spec model
- [x] add anti-drift tests against the JSON vector corpus
- [x] wire `just threshold-prf-fv`
- [x] add abstract DLEQ boundary model
- [x] add abstract `SigningRootShareWireV1` decode and Option A derivation
  boundary model
- [x] add narrow Lean privacy execution-state model
- [x] accept current FV scope as sufficient for first Option A integration

### Phase 0: Scaffold

- [x] create `crates/threshold-prf/formal-verification/`
- [x] add `formal-verification/README.md`
- [x] add `formal-verification/docs/implementation-plan.md`
- [x] add `formal-verification/docs/proof-inventory.md`
- [x] add `formal-verification/fixtures/README.md`
- [x] add `formal-verification/verus/README.md`
- [x] add `formal-verification/verus/docs/implementation-plan.md`
- [x] add deferred `formal-verification/lean-boundary/README.md`
- [x] add deferred `formal-verification/lean-boundary/docs/implementation-plan.md`
- [x] add deferred `formal-verification/lean-privacy/README.md`
- [x] add deferred `formal-verification/lean-privacy/docs/implementation-plan.md`

### Phase 1: Verus Abstract Spec Bootstrap

- [x] create `formal-verification/verus/Cargo.toml`
- [x] create `formal-verification/verus/src/lib.rs`
- [x] add `formal-verification/verus/src/model.rs`
- [x] model suite, purpose, context, scalar, share, partial, and output types
- [x] model `PrfPartialWireV1` fields and context-tag validation
- [x] model sole public context-bound partial wire decode
- [x] model secret `SigningRootShareWireV1` fields and fixed-width decode
- [x] add placeholder-free proof functions for the abstract spec model
- [ ] add production-shaped module mirror views after the Rust/FV module split
  can compile under both Verus and normal Cargo parity tests

Decision: production-shaped module mirror views remain deferred. Add them later
only if they can compile cleanly under both Verus and normal Cargo parity tests
without creating duplicate legacy proof models.

### Phase 2: Domain And Encoding Proofs

- [x] prove fixed output width
- [x] prove share IDs are non-zero
- [x] prove duplicate share IDs are rejected
- [x] prove insufficient threshold subsets are rejected
- [x] prove malformed scalar encodings are rejected at the model boundary
- [x] prove zero root scalars are rejected at the model boundary
- [x] prove zero share scalars are accepted when canonically encoded and paired
  with a valid share ID
- [x] prove partial wire context tags are present and fixed-width
- [x] prove secret signing-root share wires reject wrong width, invalid share
  IDs, and invalid share scalars

### Phase 3: Shamir And Refresh Proofs

- [x] model 2-of-3 share generation over an abstract field abstraction
- [x] prove each valid pair reconstructs the same root scalar
- [x] prove all three valid pairs produce the same reconstructed scalar
- [x] prove share refresh preserves the root scalar
- [x] prove refreshed valid pairs reconstruct the same root scalar

### Phase 4: PRF Equivalence Proofs

- [x] model direct reference evaluation
- [x] model partial evaluation
- [x] model partial combination
- [x] prove each valid 2-of-3 partial combination equals direct reference evaluation
- [x] prove one-worker and two-worker placement produce identical output
- [x] prove purpose/context bytes are included in the output derivation model
- [x] prove direct reference evaluation is not required by the production
  Option A/Option B model
- [x] prove generated secret share-wire Option A derivation matches direct
  reference output

### Phase 5: Vectors And Anti-Drift

- [x] define `crates/threshold-prf/fixtures/protocol-v1.json`
- [x] mirror or reference the same corpus from `formal-verification/fixtures/`
- [x] add deterministic vectors for root generation from fixed seed material
- [x] add deterministic vectors for 2-of-3 splitting
- [x] add deterministic vectors for direct reference evaluation
- [x] add deterministic vectors for every valid pairwise combine path
- [x] add deterministic vectors for refreshed shares
- [x] add deterministic vectors for `PrfPartialWireV1`
- [x] add rejection vectors for malformed scalar/share/subset inputs where practical
- [x] add anti-drift tests against production helpers
- [x] add anti-drift coverage for server-SDK signing-root share wire derivation
- [x] add anti-drift coverage for malformed server-SDK signing-root share wires

### Phase 6: DLEQ Boundary Proofs

- [x] model share commitment wire width
- [x] model DLEQ proof wire width
- [x] model DLEQ challenge input binding tuple
- [x] prove generated abstract DLEQ proof verifies for a valid evaluated partial
- [x] prove commitment/partial share-ID mismatch is rejected
- [x] prove wrong-context DLEQ verification is rejected
- [x] model DLEQ proof generation as rejecting zero nonce input
- [x] model and prove the DLEQ-enforced `combine_verified_partials` boundary
- [x] add committed DLEQ vectors if DLEQ byte compatibility becomes a
  production compatibility boundary
- [x] decide whether DLEQ cryptographic soundness beyond the abstract boundary is
  in scope

Decision: DLEQ cryptographic soundness beyond the abstract boundary is out of
scope for the current Verus track. Ristretto arithmetic, SHA-512,
Fiat-Shamir soundness, and concrete malicious-worker security remain trusted
seams unless a dedicated cryptographic proof track is approved.

### Phase 7: Deferred Lean/Aeneas Boundary

- [x] decide whether any stable Rust-facing boundary warrants extraction
- [x] keep Verus plus anti-drift as the active track for now

Decision: no Aeneas/Lean extraction boundary is warranted yet. Revisit after the
first HSS/server integration boundary is stable.

### Phase 8: Lean Privacy

- [x] define a two-server execution-state model
- [x] prove one server cannot reconstruct `k_org` from one local share state in
  the structural share-count model
- [x] prove combiner-visible state excludes plaintext root and share scalars
- [x] prove public outputs exclude root scalars, share scalars, and reconstructed
  `k_org`
- [x] document explicitly that one-server mode is not a malicious-runtime privacy
  boundary

## Integration Gate

Do not wire `threshold-prf` into HSS flows until the following are complete:

1. committed protocol specs
2. committed vectors
3. direct-vs-threshold output equivalence tests
4. first Verus proof slice
5. anti-drift tests against production helpers
6. benchmark report
7. explicit remaining-trust inventory
