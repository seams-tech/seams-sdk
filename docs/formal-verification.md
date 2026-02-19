# Formal Verification Plan (Coq)

Last updated: 2026-02-18

## Goal

Use Coq to formally verify security-critical cryptographic logic in Rust, focusing on our own composition/orchestration code and deterministic encoding paths in `signer-core`.

## Constraints

- No legacy verification tracks or deprecated proof targets.
- Breaking changes are acceptable during development if they improve proofability and remove obsolete code paths.
- Proof scope must be explicit about trusted dependencies vs verified code.

## Verification Boundary

### In scope (prove)

- Deterministic encoding + hashing logic:
  - `crates/signer-core/src/codec.rs`
  - `crates/signer-core/src/eip1559.rs`
  - `crates/signer-core/src/tempo_tx.rs`
- secp256k1 scalar/share mapping and signature invariants:
  - `crates/signer-core/src/secp256k1.rs`
  - `crates/signer-core/src/threshold_ecdsa.rs`
- Ed25519/FROST 2-party algebra and participant-id invariants:
  - `crates/signer-core/src/near_threshold_frost.rs`
  - `crates/signer-core/src/near_threshold_ed25519.rs`

### Out of scope (trusted assumptions)

- Internal correctness of third-party cryptography crates:
  - `k256`
  - `curve25519-dalek`
  - `frost-ed25519`
  - `threshold-signatures` (pinned rev)
- Browser runtime, network transport, and relay durability semantics.

## Specification Sources and Weighting

We use a weighted source hierarchy so proofs follow the exact implementation we run.

## Tier 0 (highest): Pinned implementation spec for `threshold-signatures`

Authoritative for threshold ECDSA behavior because our code is pinned to:

- `crates/signer-core/Cargo.toml` (`threshold-signatures` rev `db609be5021eb9d794f577601f422818fbdfe246`)
- `wasm/eth_signer/Cargo.toml` (`threshold-signatures` rev `db609be5021eb9d794f577601f422818fbdfe246`)

Primary references (pinned commit links):

- `https://github.com/near/threshold-signatures/blob/db609be5021eb9d794f577601f422818fbdfe246/docs/benches/model.md`
- `https://github.com/near/threshold-signatures/blob/db609be5021eb9d794f577601f422818fbdfe246/docs/confidential_key_derivation/confidential_key_derivation.md`
- `https://github.com/near/threshold-signatures/blob/db609be5021eb9d794f577601f422818fbdfe246/docs/crypto/proofs.md`
- `https://github.com/near/threshold-signatures/blob/db609be5021eb9d794f577601f422818fbdfe246/docs/ecdsa/preliminaries.md`
- `https://github.com/near/threshold-signatures/blob/db609be5021eb9d794f577601f422818fbdfe246/docs/ecdsa/ot_based_ecdsa/orchestration.md`
- `https://github.com/near/threshold-signatures/blob/db609be5021eb9d794f577601f422818fbdfe246/docs/ecdsa/ot_based_ecdsa/signing.md`
- `https://github.com/near/threshold-signatures/blob/db609be5021eb9d794f577601f422818fbdfe246/docs/ecdsa/ot_based_ecdsa/triples.md`
- `https://github.com/near/threshold-signatures/blob/db609be5021eb9d794f577601f422818fbdfe246/docs/ecdsa/robust_ecdsa/signing.md`
- `https://github.com/near/threshold-signatures/blob/db609be5021eb9d794f577601f422818fbdfe246/docs/eddsa/signing.md`
- `https://github.com/near/threshold-signatures/blob/db609be5021eb9d794f577601f422818fbdfe246/docs/dkg.md`

Notes on weighting:

- For ECDSA proofs, `ot_based_ecdsa` docs are primary.
- `robust_ecdsa` docs are reference-only unless/until implementation switches.
- `benches/model` and `confidential_key_derivation` are contextual references, not normative protocol behavior for current signer-core APIs.

## Tier 1: Standards-level references

- RFC 9591 (FROST): `https://datatracker.ietf.org/doc/html/rfc9591`
- RFC 8032 (Ed25519): `https://datatracker.ietf.org/doc/html/rfc8032`

These constrain Ed25519/FROST semantics where applicable and resolve ambiguity in secondary docs.

## Tier 2: Cait-Sith origin docs (secondary/background)

Useful for rationale and lineage, but lower priority than pinned `near/threshold-signatures` docs:

- `https://github.com/cronokirby/cait-sith/blob/main/docs/key-generation.md`
- `https://github.com/cronokirby/cait-sith/blob/main/docs/orchestration.md`
- `https://github.com/cronokirby/cait-sith/blob/main/docs/proofs.md`
- `https://github.com/cronokirby/cait-sith/blob/main/docs/signing.md`
- `https://github.com/cronokirby/cait-sith/blob/main/docs/triples.md`

## Conflict Resolution Policy

- If sources disagree, use this precedence:
  - Pinned `near/threshold-signatures` docs + pinned code semantics
  - RFC constraints (for Ed25519/FROST semantics)
  - Cait-Sith docs
- Every theorem in `formal/docs/proof-inventory.md` must cite one Tier 0 source and may cite Tier 1/Tier 2 as supporting context.

## Proof Objectives (Priority)

## P0 (must prove first)

- Share-mapping correctness for 2-party ECDSA:
  - `map_additive_share_to_threshold_signatures_share_2p` preserves additive secret under expected Lagrange factors.
- ECDSA finalize invariants:
  - final `r,s,recid` signature verifies against expected public key.
  - low-`s` normalization invariant holds.
- Deterministic tx digest and signed encoding:
  - EIP-1559 hash preimage correctness and serialization determinism.
  - Tempo sender-hash and signed payload serialization determinism.

## P1

- FROST 2-party group key reconstruction from verifying shares is algebraically correct.
- Participant-id validation invariants prevent ambiguous signer-set behavior.
- Non-zero scalar constraints are preserved through deterministic derivation paths.

## P2

- Additional protocol-state invariants around presign/session transitions.
- Extended model checks for cosigner polynomial helpers and Lagrange-at-zero helper APIs.

## Phased Plan

## Phase 0: Lock Model and Threat Contract

- [ ] Write a formal model boundary doc:
  - trusted assumptions
  - attacker model
  - security and correctness properties
- [ ] Freeze canonical theorem names and mapping to Rust functions.
- [ ] Freeze spec source mapping in `formal/docs/proof-inventory.md`:
  - theorem -> Rust function
  - theorem -> Tier 0 source URL(s)
  - supporting Tier 1/Tier 2 URLs when used
- [ ] Define pass/fail criteria for each property class (P0/P1/P2).

Definition of done:

- Every proof target has an unambiguous Rust function mapping and acceptance criterion.

## Phase 1: Create Formal Workspace

- [ ] Create top-level workspace:
  - `formal/coq`
  - `formal/vectors/generated`
  - `formal/scripts`
  - `formal/docs`
- [ ] Add Coq build files (`_CoqProject`, `Makefile`) and deterministic tooling entrypoints.
- [ ] Add `formal/docs/proof-inventory.md` with theorem coverage table.

Definition of done:

- `coqc` runs in CI on at least one starter theorem and inventory exists.

## Phase 2: Verify Encoding and Hashing (P0)

- [ ] Model and prove hex/decimal/rlp primitives (`codec.rs`) used by signing pipelines.
- [ ] Prove EIP-1559 hash and signed-transaction encoding relations (`eip1559.rs`).
- [ ] Prove Tempo sender-hash and signed-payload encoding relations (`tempo_tx.rs`).
- [ ] Export Coq-generated vectors to `formal/vectors/generated/*.json`.
- [ ] Add/extend Rust parity tests in:
  - `crates/signer-core/tests/baseline_behavior.rs`
  - `crates/signer-core/fixtures/signing-vectors/`

Definition of done:

- Rust vector tests fail on any encoding/hash divergence from Coq-generated vectors.

## Phase 3: Verify secp256k1 Share Algebra and Signature Invariants (P0/P1)

- [ ] Prove 2-party share mapping algebra:
  - inverse-Lagrange mapping recovers original additive share.
  - mapped share is in valid non-zero scalar range.
- [ ] Prove `sign_secp256k1_recoverable` invariants:
  - output length/shape.
  - low-`s` behavior and recovery-id consistency constraints.
- [ ] Prove key relation invariants for public-key addition/address derivation helpers.

Definition of done:

- Required theorems for `secp256k1.rs` are proven and covered by generated-vector parity tests.

## Phase 4: Verify Threshold ECDSA Composition (P0)

- [ ] Model presign + rerandomization composition at the abstraction boundary used by `threshold_ecdsa.rs`.
- [ ] Prove signature-share combination formula corresponds to final signature equation.
- [ ] Prove finalize step rejects invalid combinations and accepts valid ones under model assumptions.

Definition of done:

- Formal model proves the finalize path cannot emit an accepting signature that violates equation checks.

## Phase 5: Verify Threshold Ed25519/FROST 2P Algebra (P1)

- [ ] Prove group-public-key reconstruction from verifying shares and participant IDs.
- [ ] Prove round-2 cosigner share algebra corresponds to modeled challenge equation.
- [ ] Prove participant-id constraints eliminate degenerate denominators and invalid signer sets.

Definition of done:

- Theorems cover core Ed25519 threshold key/share math in current production path.

## Phase 6: CI and Change Management

- [ ] Add CI job:
  - `coqc` proof build
  - vector export consistency check
  - Rust parity tests
- [ ] Add guard script preventing Rust crypto-function changes without proof-inventory updates.
- [ ] Document workflow for updating proofs when dependencies or function signatures change.

Definition of done:

- PRs cannot merge when proofs/vectors are out of sync with Rust implementation.

## Deliverables

- `docs/formal-verification.md` (this plan)
- `formal/docs/model-boundary.md`
- `formal/docs/proof-inventory.md`
- `formal/coq/**` theorem files
- `formal/vectors/generated/*.json`
- Updated `signer-core` vector fixtures + parity tests
- CI gate for formal + parity checks

## Risks and Mitigations

- Risk: Coq model diverges from Rust byte-level semantics.
  - Mitigation: generated vectors as hard parity oracle in Rust tests.
- Risk: Over-modeling third-party cryptography internals stalls progress.
  - Mitigation: keep strict assumption boundary; prove composition logic first.
- Risk: Proof maintenance burden slows iteration.
  - Mitigation: prioritize P0 theorem set and enforce proof-inventory ownership.

## Immediate Next Actions

- [ ] Create `formal/` skeleton and baseline Coq build in one PR.
- [ ] Implement first pilot proof on:
  - `crates/signer-core/src/secp256k1.rs::map_additive_share_to_threshold_signatures_share_2p`
- [ ] Wire pilot proof output into `crates/signer-core/tests/baseline_behavior.rs`.
