# `threshold-prf` Formal Verification Proof Inventory

Last updated: 2026-04-17

This inventory tracks planned proof targets for
[crates/threshold-prf](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf).

The Rust crate has a prototype implementation, a first Verus abstract spec
model, production anti-drift parity tests, a narrow Lean privacy
execution-state model, and a full `just threshold-prf-fv` command. Lean
boundary extraction remains deferred.

## FV-THRESHOLD-PRF-001

Target:

- suite, purpose, context, scalar, share, partial, and output encodings

Property:

- suite id is fixed for the prototype
- purpose strings are explicit and domain-separated
- context bytes are canonical inputs, not implicit runtime state
- signing-root scalars are non-zero
- share scalars are canonical field encodings and may be zero
- share IDs are non-zero
- secret signing-root share wires reject wrong width, invalid share IDs, and
  invalid share scalars
- PRF output width is fixed
- partial wire fields include share ID, context tag, and compressed point

Status:

- proved in the abstract Verus spec model

Remaining trust:

- concrete `curve25519-dalek` canonical scalar parsing remains a library seam;
  production anti-drift tests cover the crate boundary for representative
  malformed inputs

## FV-THRESHOLD-PRF-002

Target:

- 2-of-3 Shamir share validation and reconstruction model

Property:

- exactly two distinct shares are required for combine/reconstruction
- duplicate share IDs are rejected
- one-share subsets are rejected
- each valid 2-of-3 pair reconstructs the same root scalar
- all valid 2-of-3 pairs are equivalent

Status:

- proved in the abstract Verus spec model

Remaining trust:

- finite-field arithmetic implementation remains trusted until connected to a
  verified or well-reviewed arithmetic backend

## FV-THRESHOLD-PRF-003

Target:

- share refresh

Property:

- refreshed shares preserve the same root scalar
- refreshed valid 2-of-3 pairs reconstruct the same root scalar as the original
  shares
- refreshed shares still satisfy canonical share-scalar and share-ID
  requirements

Status:

- proved in the abstract Verus spec model for reconstruct-then-resplit refresh

## FV-THRESHOLD-PRF-004

Target:

- direct reference PRF evaluation

Property:

- direct evaluation is deterministic for fixed root, suite, purpose, and context
- output shape is fixed
- purpose and context are included in the output derivation model

Status:

- proved in the abstract Verus spec model; concrete purpose/context byte
  inclusion is pinned by the committed vector corpus

Remaining trust:

- hash-to-group and hash-to-bytes internals remain trusted primitive seams

## FV-THRESHOLD-PRF-005

Target:

- threshold partial evaluation and combination

Property:

- partial evaluation is deterministic for fixed share, suite, purpose, and context
- partial combination is deterministic for fixed valid subset and context
- every valid 2-of-3 pair combines to the same output as direct reference
  evaluation
- one-worker and two-worker placement produce byte-identical outputs
- direct reference evaluation is not needed in the production Option A/Option B
  model
- transported partials reject mismatched context tags
- server-SDK secret share-wire Option A derivation produces the same output as
  direct reference evaluation for generated valid shares

Status:

- proved in the abstract Verus spec model

## FV-THRESHOLD-PRF-006

Target:

- anti-drift vectors

Property:

- committed vectors pin root generation from fixed seed material
- committed vectors pin 2-of-3 splitting
- committed vectors pin direct reference evaluation
- committed vectors pin each valid pairwise combine path
- committed vectors pin server-SDK signing-root share wire derivation parity
- committed vectors pin refreshed-share behavior
- committed vectors pin `PrfPartialWireV1` context-tag transport behavior
- committed vectors pin DLEQ commitment and proof byte compatibility
- rejection parity covers malformed scalar/share/subset inputs and malformed
  server-SDK signing-root share wires where practical

Status:

- implemented through committed JSON vectors and executable anti-drift tests

## FV-THRESHOLD-PRF-007

Target:

- DLEQ partial-authenticity boundary

Property:

- share commitment wire width is fixed
- DLEQ proof wire width is fixed
- challenge input model carries suite, purpose, context tag, share ID,
  commitment point, partial point, and nonce points
- generated abstract DLEQ proofs verify for valid evaluated partials
- DLEQ proof generation rejects zero nonce input in the abstract boundary model
- commitment/partial share-ID mismatch is rejected
- wrong-context DLEQ verification is rejected
- DLEQ-enforced verified combine rejects duplicate or unverified bundles
- generated verified bundles combine to the same output as direct reference
- committed DLEQ vectors match production helpers

Status:

- proved in the abstract Verus spec model and covered by production anti-drift
  tests for committed DLEQ vectors and verified-combine output parity

Remaining trust:

- Ristretto group arithmetic, SHA-512 challenge derivation, Fiat-Shamir
  soundness, and concrete DLEQ malicious-worker security remain trusted
  primitive/protocol seams unless a dedicated cryptographic proof track is added

## FV-THRESHOLD-PRF-008

Target:

- two-server privacy model

Property:

- one server with one signing-root share cannot reconstruct `k_org` in the
  abstract execution-state model
- combiner-visible state excludes plaintext root and share scalars
- public outputs exclude root scalars, share scalars, and reconstructed `k_org`
- one-server mode is explicitly modeled as observing enough plaintext material
  to reconstruct `k_org`

Status:

- proved in the narrow Lean privacy structural execution-state model

Remaining trust:

- runtime isolation, key wrapping, transport behavior, side-channel resistance,
  and malicious-server partial correctness remain outside the initial model

## Recommended Order

Implement in this order:

1. `FV-THRESHOLD-PRF-001`
2. `FV-THRESHOLD-PRF-002`
3. `FV-THRESHOLD-PRF-004`
4. `FV-THRESHOLD-PRF-005`
5. `FV-THRESHOLD-PRF-003`
6. `FV-THRESHOLD-PRF-006`
7. `FV-THRESHOLD-PRF-007`
8. `FV-THRESHOLD-PRF-008`

If only one initial slice is funded, stop after the domain/encoding and
direct-vs-threshold equivalence model.
