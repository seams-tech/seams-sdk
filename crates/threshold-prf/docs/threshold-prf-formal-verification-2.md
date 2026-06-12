# `threshold-prf` High-Impact Formal Verification 2 Plan

Date created: June 12, 2026

## Scope

This plan defines only high-impact second-stage verification work for
[crates/threshold-prf](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf).

The first formal-verification track already provides:

- a Verus abstract spec model
- executable anti-drift tests against committed vectors
- an abstract DLEQ boundary model
- an abstract `SigningRootShareWireV1` decode and Option A derivation boundary
  model
- a narrow Lean privacy execution-state model
- a `just threshold-prf-fv` gate

FV2 should focus on proof and test work that can catch high-impact production
failures:

- transcript framing drift or ambiguous domain separation
- mismatch between concrete Rust helpers and the abstract model
- DLEQ nonce handling failures
- unsupported malicious-worker or two-server privacy claims

Broad proof architecture work stays deferred until a specific release claim
needs it.

## High-Impact Tasks

### 1. Transcript Encoding Proofs And Fixtures

Transcript framing controls domain separation for input hashing, output hashing,
partial context tags, and DLEQ challenges. A missing field or ambiguous encoding
would be a serious protocol bug.

Targets:

- `threshold-prf:v1/input`
- `threshold-prf:v1/output`
- `threshold-prf:v1/partial-context`
- `threshold-prf:v1/dleq`
- suite ID inclusion
- purpose inclusion
- context byte inclusion
- output payload inclusion
- DLEQ tuple field inclusion
- length-prefix ambiguity rejection

Tasks:

- [x] Model `push_len16` and `push_len32` in the Verus track.
- [x] Prove encoded fields are length-delimited and ordered.
- [x] Prove every transcript domain includes suite ID and purpose label.
- [x] Prove input, output, and partial-context transcripts include canonical
  context bytes.
- [x] Prove the DLEQ challenge transcript includes:
  - suite ID
  - purpose label
  - context tag
  - share ID
  - basepoint
  - input point
  - commitment point
  - partial point
  - both nonce points
- [x] Add concrete transcript fixture tests that pin encoded bytes for at least
  one case per domain.
- [x] Add negative tests for transcript length overflow.

Exit criteria:

- transcript model proves unambiguous field separation
- concrete fixture tests expose any production framing drift
- future optimization work must preserve transcript fixtures

### 2. Concrete Generated Property Tests

Committed vectors pin known cases. Deterministic generated tests should broaden
coverage over production Rust helpers while staying cheap to run.

Targets:

- direct-vs-threshold equivalence
- every valid 2-of-3 pair
- pair order behavior
- share refresh preservation
- context-tag rejection
- malformed wire rejection
- DLEQ rejection cases

Tasks:

- [x] Add deterministic generated property tests using fixed seeded RNG cases.
- [x] Cover every valid pair from at least 100 generated signing roots.
- [x] Assert each pair combines to the same output as direct reference
  evaluation.
- [x] Assert share order does not change the combined output.
- [x] Assert duplicate shares are rejected.
- [x] Assert one-share and three-share combine inputs are rejected.
- [x] Assert partial wires decoded under the wrong context fail.
- [x] Assert DLEQ proof verification fails for:
  - wrong context
  - wrong commitment
  - wrong partial
  - wrong share ID
  - malformed proof bytes
  - duplicate proof bundles
- [x] Keep failure messages tied to seed and case index.

Exit criteria:

- tests are deterministic and fast enough for the crate test target
- test failures identify the generated case clearly
- no obsolete behavior is preserved for compatibility

### 3. RNG And DLEQ Nonce Contract Tests

DLEQ proof generation depends on fresh nonzero nonces. Nonce reuse can reveal
the signing-root share scalar, so this contract deserves focused coverage.

Tasks:

- [x] Document the DLEQ nonce contract in
  [protocol.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/docs/protocol.md).
- [x] Add a deterministic test RNG that returns zero first, then nonzero, and
  assert proof generation retries safely.
- [x] Add a deterministic test RNG that returns repeated nonzero values and
  document that the crate cannot detect RNG reuse across independent
  statements.
- [x] Keep the current requirement for a caller-provided `CryptoRng`.
- [ ] Evaluate deterministic nonce derivation only as a separate protocol
  proposal if RNG quality becomes a release risk.

Exit criteria:

- callers know exactly what nonce freshness property they must provide
- zero nonce handling is tested
- nonce reuse remains documented as a catastrophic RNG failure

### 4. DLEQ Soundness Model For Malicious-Worker Claims

Add this track when the product needs to claim malicious-worker partial
correctness through DLEQ. Keep it deferred while the release only needs
semi-honest or authenticated-runtime assumptions.

Target property:

```text
VerifyDleq(commitment = [x]G, partial = [x]P, proof, context) accepts
  => proof relation binds the same witness x to G and P
```

Tasks:

- [ ] Decide whether this track lives in Lean or Verus.
- [ ] Model the DLEQ statement over an abstract cyclic group and scalar field.
- [ ] Prove honest proof generation verifies.
- [ ] Prove verification equations enforce a common witness under the modeled
  challenge assumption.
- [ ] Prove changing context, purpose, share ID, commitment, or partial changes
  the modeled challenge input.
- [ ] Document remaining trust in hash soundness and group arithmetic.

Exit criteria:

- malicious-worker DLEQ claims reference an explicit abstract proof
- remaining cryptographic assumptions are named in one place

### 5. Trace-Level Privacy Model For Two-Server Claims

Add this track when the product needs a stronger two-server privacy claim across
full ceremonies and refreshes.

Target trace properties:

- one-server mode observes enough plaintext share material to reconstruct
  `k_org`
- a single two-server participant observes only its own plaintext root share
  during a ceremony
- combiner state observes partials and output material, not plaintext root
  shares
- public outputs exclude root scalars, share scalars, and reconstructed
  `k_org`
- refresh traces preserve the same logical PRF root while rotating share
  material

Tasks:

- [ ] Add ceremony trace events:
  - share unwrap
  - partial evaluation
  - partial encryption or delivery
  - partial verification
  - combine
  - refresh
- [ ] Prove a single two-server participant trace never accumulates two
  plaintext root shares for the same root epoch.
- [ ] Prove combiner trace state never includes plaintext share scalars.
- [ ] Prove replayed public transcript views do not add plaintext share
  visibility.
- [ ] Add explicit assumptions for runtime isolation and transport secrecy.

Exit criteria:

- privacy claims cover ceremony traces
- one-server limitations remain explicit
- runtime and transport assumptions are stated beside each theorem family

## Phased Todo List

### Phase 0: Baseline And Scope Lock

- [ ] Run the current FV gate and record the baseline:

```bash
just threshold-prf-fv
```

- [ ] Run the current crate tests and record any existing failures:

```bash
cargo test -q --manifest-path crates/threshold-prf/Cargo.toml --tests
```

- [ ] Confirm the active FV2 scope is limited to:
  - transcript encoding proofs and fixtures
  - concrete generated property tests
  - RNG and DLEQ nonce contract tests
  - DLEQ soundness only when malicious-worker safety is a release claim
  - trace-level privacy only when two-server privacy is a release claim
- [ ] Do not start broad production-shaped Verus mirrors in this phase.

Exit criteria:

- baseline command results are known
- FV2 scope has no low-impact proof work in the active checklist

### Phase 1: Transcript Fixtures

- [x] Add a production Rust test helper that exposes encoded transcript bytes
  for test builds only.
- [x] Add fixture tests for:
  - input transcript
  - output transcript
  - partial-context transcript
  - DLEQ challenge transcript
- [x] Assert suite ID, purpose label, context bytes, payload, and DLEQ tuple
  fields appear in the expected order.
- [x] Add negative tests for `u16` and `u32` transcript length overflow.
- [x] Keep fixture data small and hand-reviewable.

Exit criteria:

- any transcript field omission or field-order drift fails a concrete Rust test
- no public production API is added only for tests

### Phase 2: Transcript Verus Model

- [x] Model `push_len16` and `push_len32`.
- [x] Prove length-delimited field ordering.
- [x] Prove every modeled transcript domain includes suite ID and purpose.
- [x] Prove input, output, and partial-context transcripts include canonical
  context bytes.
- [x] Prove the DLEQ challenge tuple includes context tag, share ID, basepoint,
  input point, commitment point, partial point, and both nonce points.
- [ ] Add anti-drift parity between modeled constants and production constants
  where practical.

Exit criteria:

- transcript framing is covered by both concrete fixtures and Verus model proofs
- `cargo verus verify --manifest-path crates/threshold-prf/formal-verification/verus/Cargo.toml`
  passes

### Phase 3: Generated Equivalence Properties

- [x] Add deterministic generated tests with fixed seeded RNG inputs.
- [x] For at least 100 generated signing roots, test all valid 2-of-3 pairs.
- [x] Assert each pair matches direct reference evaluation for each current
  production purpose.
- [x] Assert pair order does not change the combined output.
- [x] Assert refreshed shares preserve the same output.
- [x] Include seed and case index in every failure message.

Exit criteria:

- direct-vs-threshold equivalence has broad deterministic production coverage
- generated tests are fast enough for normal crate test runs

### Phase 4: Generated Rejection Properties

- [x] Add deterministic rejection tests for duplicate shares.
- [x] Add deterministic rejection tests for one-share and three-share combine
  inputs.
- [x] Add wrong-context `PrfPartialWireV1` decode tests.
- [x] Add malformed share-wire and partial-wire tests.
- [x] Add DLEQ rejection tests for:
  - wrong context
  - wrong commitment
  - wrong partial
  - wrong share ID
  - malformed proof bytes
  - duplicate proof bundles

Exit criteria:

- known invalid states fail through the intended boundary errors
- tests do not preserve obsolete compatibility behavior

### Phase 5: RNG And DLEQ Nonce Contracts

- [x] Document the DLEQ nonce contract in
  [protocol.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/docs/protocol.md).
- [x] Add a deterministic test RNG that returns zero first, then nonzero.
- [x] Assert proof generation retries safely after a zero nonce.
- [x] Add a deterministic test RNG that repeats a nonzero nonce.
- [x] Document that repeated nonzero nonces across independent statements are a
  catastrophic caller/RNG failure that this crate cannot detect after the fact.
- [x] Keep deterministic nonce derivation out of this phase unless approved as a
  separate protocol change.

Exit criteria:

- zero nonce handling is tested
- nonce freshness requirements are explicit for callers

### Phase 6: FV2 Gate

- [x] Add `threshold-prf-fv2` to the `justfile`.
- [x] Make the initial gate run:

```text
just threshold-prf-fv
cargo test -q --manifest-path crates/threshold-prf/Cargo.toml --tests
cargo test -q --manifest-path crates/threshold-prf/formal-verification/verus/Cargo.toml --tests
cargo verus verify --manifest-path crates/threshold-prf/formal-verification/verus/Cargo.toml
```

- [x] Document the gate in
  [formal-verification/README.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/formal-verification/README.md).
- [x] Keep Lean DLEQ and trace commands out of the gate until those tracks
  become active release work.

Exit criteria:

- one command runs all active high-impact FV2 checks
- the existing `threshold-prf-fv` command remains valid

### Phase 7: Release-Claim Proof Tracks

Start this phase only when the product makes the matching release claim.

- [ ] If malicious-worker partial correctness is claimed, implement the DLEQ
  soundness model.
- [ ] If full two-server privacy across ceremonies is claimed, implement the
  trace-level privacy model.
- [ ] Add the new Lean or Verus commands to `threshold-prf-fv2` only after the
  proof track is stable.
- [ ] Update protocol docs to state the proved claim and remaining assumptions.

Exit criteria:

- release claims have matching proof artifacts
- remaining assumptions are explicit beside the claim

## Deferred Work

These tasks are outside the active FV2 plan because their impact is lower than
the work above:

- broad production-shaped Verus mirrors beyond transcript and boundary
  constants
- Aeneas or Lean extraction for the full Rust crate
- full proofs of `curve25519-dalek` internals
- full SHA-512 proofs
- side-channel timing harnesses before a threat model requires them
- proof work for future purpose labels

Move a deferred item into the active plan only when it supports a concrete
release claim or guards a known risky change.

## Future `t-of-N` FV Work

The current FV2 gate models v1 as fixed 2-of-3:

```text
threshold = 2
share_count = 3
valid_share_ids = {1, 2, 3}
combine_count = 2
```

A generic `t-of-N` protocol needs a new threshold-set model. That model should
cover multiple `N` values, multiple `t` values, all valid subset sizes,
duplicate and insufficient-subset rejection, and DLEQ verified-combine cases for
more than two partials. V2 vectors should live beside the v2 protocol/API
surface rather than mutating the v1 vector expectations.

## FV2 Gate

Start with an additive high-impact gate:

```bash
just threshold-prf-fv2
```

Proposed command sequence after the first FV2 tasks exist:

```text
just threshold-prf-fv
cargo test -q --manifest-path crates/threshold-prf/Cargo.toml --tests
cargo test -q --manifest-path crates/threshold-prf/formal-verification/verus/Cargo.toml --tests
cargo verus verify --manifest-path crates/threshold-prf/formal-verification/verus/Cargo.toml
```

Add Lean DLEQ or trace commands only after those tracks become active release
work.

## Non-Goals

- proving `curve25519-dalek` internals
- proving SHA-512 internals
- proving operating-system or Cloudflare Worker isolation
- proving transport confidentiality
- proving HSS downstream protocols
- preserving obsolete behavior in tests or fixtures

## Recommended Order

1. Transcript encoding proofs and fixtures.
2. Concrete generated property tests.
3. RNG and DLEQ nonce contract tests.
4. DLEQ soundness model when malicious-worker safety becomes a release claim.
5. Trace-level privacy model when two-server privacy becomes a release claim.

If only one FV2 slice is funded, implement transcript encoding proofs and
fixtures first.
