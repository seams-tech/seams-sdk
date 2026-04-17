# `threshold-prf` Formal Verification Proof Inventory

Last updated: 2026-04-17

This inventory tracks planned crate-local proof targets for:

- [`crates/threshold-prf`](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf)

## Current Posture

- Verus has a first abstract spec-model track.
- Executable anti-drift tests pin the committed vector corpus to production
  helper behavior.
- Lean/Aeneas boundary extraction is deferred until the Rust boundary is stable.
- Lean privacy has a narrow structural execution-state model.
- Current status: Verus abstract spec model exists, production anti-drift
  parity exists, narrow Lean privacy exists, and `just threshold-prf-fv` is
  wired. Lean boundary extraction remains deferred.

## FV-THRESHOLD-PRF-001: Domains And Encodings

Target:

- suite id
- purpose
- context bytes
- root scalar
- share scalar
- share ID
- secret signing-root share wire fields
- partial wire fields
- PRF output

Property:

- fixed output width
- explicit purpose/context inputs
- non-zero signing-root scalar domain
- canonical share scalar domain, including zero share values
- non-zero share IDs
- fixed-width secret signing-root share wires reject wrong width, invalid share
  IDs, and invalid share scalars
- fixed-width partial wire context tag
- malformed encodings rejected

Status:

- proved in the abstract Verus spec model

Remaining trust:

- concrete `curve25519-dalek` canonical scalar parsing remains a library seam;
  production anti-drift tests cover the crate boundary for representative
  malformed inputs

## FV-THRESHOLD-PRF-002: 2-of-3 Share Validation

Target:

- 2-of-3 subset validation

Property:

- duplicate share IDs rejected
- one-share subsets rejected
- unknown/unsupported share IDs rejected if the selected suite fixes IDs to
  `{1, 2, 3}`
- each valid pair accepted

Status:

- proved in the abstract Verus spec model

## FV-THRESHOLD-PRF-003: Shamir Reconstruction

Target:

- Lagrange coefficient model
- reconstruction from valid 2-of-3 subsets

Property:

- every valid pair reconstructs the same root scalar
- all valid pairs are equivalent

Status:

- proved in the abstract Verus spec model for generated shares

## FV-THRESHOLD-PRF-004: Share Refresh

Target:

- refreshed 2-of-3 share set

Property:

- share refresh preserves the root scalar
- refreshed valid pairs reconstruct the same root scalar

Status:

- proved in the abstract Verus spec model for reconstruct-then-resplit refresh

## FV-THRESHOLD-PRF-005: Direct Reference PRF

Target:

- direct reference evaluation

Property:

- deterministic for fixed root, suite, purpose, and context
- output width is fixed
- purpose/context are explicit output-derivation inputs

Status:

- proved in the abstract Verus spec model; concrete purpose/context byte
  inclusion is pinned by the committed vector corpus

## FV-THRESHOLD-PRF-006: Threshold PRF Equivalence

Target:

- partial evaluation
- partial combination
- partial wire context-tag validation

Property:

- each valid 2-of-3 partial combination equals direct reference output
- one-worker and two-worker placement are byte-identical
- server-SDK secret share-wire Option A derivation produces the same output as
  direct reference evaluation for generated valid shares
- transported partials with mismatched context tags are rejected
- production Option A/Option B equivalence does not depend on direct reference
  evaluation

Status:

- proved in the abstract Verus spec model

## FV-THRESHOLD-PRF-007: Anti-Drift Vectors

Target:

- committed vector corpus
- executable parity tests

Property:

- vectors cover root generation, share splitting, direct reference evaluation,
  valid pairwise combination, server-SDK share-wire derivation, partial wire
  encoding, share refresh, and malformed-input rejection where practical,
  including malformed server-SDK signing-root share wires

Status:

- implemented through committed JSON vectors and executable anti-drift tests

## FV-THRESHOLD-PRF-008: DLEQ Boundary

Target:

- DLEQ partial-authenticity boundary

Property:

- share commitment wire width is fixed
- DLEQ proof wire width is fixed
- challenge input model carries suite, purpose, context tag, share ID,
  commitment point, partial point, and nonce points
- generated abstract DLEQ proofs verify for valid evaluated partials
- DLEQ proof generation rejects zero nonce input
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

## FV-THRESHOLD-PRF-009: Two-Server Privacy

Target:

- one-server execution state
- two-server participant execution state
- combiner execution state
- public output state

Property:

- one-server mode observes two plaintext root shares and is not modeled as a
  malicious-runtime privacy boundary
- one two-server participant observes only one plaintext root share
- one two-server participant cannot reconstruct `k_org` in the structural
  share-count model
- combiner state excludes plaintext root and share scalars
- public output state excludes root scalars, share scalars, and reconstructed
  `k_org`

Status:

- proved in the narrow Lean privacy structural execution-state model

Remaining trust:

- runtime isolation, key wrapping, transport behavior, side-channel resistance,
  and malicious-server partial correctness remain outside this model
