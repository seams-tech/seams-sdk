# `ecdsa-hss` Proof Inventory

Last updated: 2026-04-09

This inventory tracks the narrow stable-slice proof targets for
[crates/ecdsa-hss](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss).

The current verification posture is:

- Verus for implementation-facing algebraic and boundary invariants
- Aeneas + Lean for the extracted server-visible boundary and narrow privacy
  claims over that frozen scope

## Current Status

- Verus bootstrap crate exists under:
  [verus/](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/verus)
- published fixed-function corpus exists at:
  [../fixtures/phase1_v1.json](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/fixtures/phase1_v1.json)
- current scope is intentionally limited to:
  - `encode_context_v1`
  - canonical `x` derivation shape
  - additive-share derivation shape
  - fixed participant-ID mapping shape for the current backend seam
  - explicit-export output-policy shape
- Lean boundary extraction now exists for the frozen server-visible staged
  boundary
- Lean privacy theorems now exist for the same frozen staged boundary,
  including widened client/server view models, non-derivability theorems, and
  the explicit-export exception

## FV-ECDSA-HSS-001

Target:

- `encode_context_v1`

Property:

- v1 context encoding is deterministic
- field order is frozen
- participant layout is fixed to `{client=1, relayer=2}`

Planned Verus module:

- [verus/src/shared/context.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/verus/src/shared/context.rs)

Status:

- field-order, participant-layout, and determinism lemmas exist
- fixture parity is wired to the committed corpus
- the current parity bridge checks byte encoding, scalar range, and additive reconstruction on committed fixtures

## FV-ECDSA-HSS-002

Target:

- canonical `x` derivation

Property:

- for fixed `(y_client, y_relayer, context)`, derivation is deterministic
- output is a valid non-zero secp256k1 scalar

Planned Verus module:

- [verus/src/shared/derivation.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/verus/src/shared/derivation.rs)

Status:

- determinism lemma exists
- explicit scalar-domain predicates now exist in the Verus model
- canonical-scalar domain goals are wired to the reduction output shape
- scalar-range theorem now exists in the Verus model
- this theorem currently depends on an explicit trusted axiom for scalar reduction
- committed-corpus parity checks cover scalar-range regression cases

## FV-ECDSA-HSS-003

Target:

- additive-share derivation

Property:

- `x = x_client + x_relayer mod n`
- `x_client != 0`
- `x_relayer != 0`
- retry counter is deterministic under the frozen v1 rule

Planned Verus module:

- [verus/src/shared/derivation.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/verus/src/shared/derivation.rs)

Status:

- retry-counter output shape and determinism lemmas exist
- explicit reconstruction and share-domain predicates now exist in the Verus model
- additive-share goals are wired to derived output shape in the verifier
- additive reconstruction and non-zero-share theorems now exist in the Verus model
- these theorems currently depend on explicit trusted axioms for retry-counter share selection and relayer-share construction
- committed-corpus parity checks cover additive reconstruction and non-zero-share regressions

## FV-ECDSA-HSS-004

Target:

- additive-share mapping into the current backend seam

Property:

- fixed participant IDs remain `{1, 2}`
- mapped shares preserve the same effective signing key

Planned Verus module:

- [verus/src/integration/share_mapping.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/verus/src/integration/share_mapping.rs)

Status:

- participant-ID skeleton exists
- backend-domain acceptance theorem now exists in the Verus model
- same-key preservation theorem now exists in the Verus model
- these theorems currently depend on an explicit trusted axiom for the production 2P mapper

## FV-ECDSA-HSS-005

Target:

- single-key equivalence

Property:

- exported `x`
- threshold public key
- threshold signing address

all refer to the same logical key.

Planned Verus modules:

- [verus/src/shared/derivation.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/verus/src/shared/derivation.rs)
- [verus/src/integration/share_mapping.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/verus/src/integration/share_mapping.rs)

Status:

- public-key equivalence theorem now exists in the Verus model
- address equivalence theorem now exists in the Verus model
- these theorems currently depend on an explicit trusted axiom tying backend group public key derivation to the effective group secret

## FV-ECDSA-HSS-006

Target:

- output-policy boundary

Property:

- non-export operations cannot return canonical `x`
- explicit export is the only operation allowed to return canonical `x`

Planned Verus module:

- [verus/src/server/policy.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/verus/src/server/policy.rs)

Status:

- explicit-export and non-export output-policy lemmas exist

## FV-ECDSA-HSS-007

Target:

- retained-state boundary

Property:

- forbidden root material is not retained past the accepted staged boundary

Planned track:

- Verus first for narrow runtime-state shape invariants
- Aeneas + Lean later for the higher-level privacy/boundary story

Status:

- finalized retained-state exclusion theorems now exist in the Verus model
- the model matches the current server-side retained state shape:
  relayer threshold share, relayer public key, threshold public key, threshold address, and retry counter
- forbidden root material is explicitly excluded after finalize:
  raw client root share, raw relayer root share, and canonical scalar

## FV-ECDSA-HSS-008

Target:

- widened privacy model over the frozen staged boundary

Property:

- the server cannot derive client secrets across full states that share the
  same frozen server-visible boundary
- the client cannot derive server secrets across full states that share the
  same frozen client-visible boundary
- explicit export is the only canonical-secret disclosure exception
- the generated Rust boundary satisfies the same widened privacy model

Planned track:

- Lean privacy over the handwritten boundary model
- Aeneas + Lean bridge for the generated boundary

Status:

- explicit `ProtocolExecutionState`, `ClientSecretState`, and
  `ServerSecretState` models exist
- explicit client/server observable profiles and observable-only simulator
  compatibility layers exist
- server non-derivability of client secrets now exists in the Lean model
- client non-derivability of server secrets now exists in the Lean model
- the field-based canonical-secret disclosure exception theorem now exists in
  the Lean model
- widened privacy theorems are lifted onto the generated boundary
- this track is intentionally frozen at the staged-boundary view model and does
  not attempt hidden-eval compiler correctness, transport/runtime
  orchestration, side-channel claims, or implementation-facing algebraic proofs
