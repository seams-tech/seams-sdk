# `ecdsa-hss` Proof Inventory

Last updated: 2026-05-17

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
  - initial true-blind role-local boundary mirror
- Lean boundary extraction now exists for the frozen server-visible staged
  boundary
- Lean privacy theorems now exist for the same frozen staged boundary,
  including widened client/server view models, non-derivability theorems, and
  the explicit-export exception
- Verus now mirrors the settled true-blind role-local boundary contract for
  Rust-facing anti-drift checks before the production rewrite
- protocol, export, and security docs now define the role-local additive
  boundary as the production target

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
- the encoded key scope is fixed to `evm-family` in the Verus mirror
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
- executable anti-drift now checks the production `k256` reduction against the
  frozen modulo-`(n - 1) + 1` formula across fixtures, scalar-boundary
  samples, and a generated digest corpus
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
- the relayer-share construction is now proved from the exact modular-subtraction model
- the candidate-share path now follows the actual share-domain hash-reduction shape
- the remaining trusted boundary on this slice is the
  scalar-reduction/selected-counter seam, plus the scalar-int-to-bytes
  encoding bridge
- the former scalar-byte injectivity axiom has been removed; the retry and
  relayer-share proofs now depend on integer-level distinctness instead
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
- the current `{1,2}` mapping formula is now proved from the real fixed lambdas and modular inverses
- the remaining trusted boundary on this slice is the scalar-int-to-bytes
  encoding bridge, not the mapper formula itself

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

## FV-ECDSA-HSS-009

Target:

- hidden-eval/compiler-facing boundary and transport/persisted-state seam

Property:

- the generated hidden-eval/compiler-facing boundary matches the handwritten
  seam model
- non-export transport excludes canonical-secret disclosure
- transport never carries raw root material
- accepted persisted state excludes forbidden root material
- explicit export remains the only canonical-secret disclosure exception at the
  transport/state seam

Planned track:

- Aeneas + Lean boundary for the generated hidden-eval seam
- Lean privacy for transport/state exclusion and disclosure policy

Status:

- a frozen Rust hidden-eval/reference facade now exists in
  [../../src/server/reference_boundary.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/server/reference_boundary.rs)
- the `lean-boundary/` extraction path now includes that facade
- handwritten hidden-eval boundary models now exist for:
  input, transport-visible response, and persisted accepted state
- the generated hidden-eval boundary now matches the handwritten seam model
- transport/persisted-state exclusion theorems now exist in `lean-privacy/`
- executable anti-drift checks now exist in
  [verus/tests/anti_drift.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/verus/tests/anti_drift.rs)

## FV-ECDSA-HSS-010

Target:

- true server-blindness model

Property:

- client derives `x_client` from client-owned material
- server derives `x_relayer` from server-owned material
- non-export server views exclude `y_client`, `x_client`, and canonical `x`
- non-export client views exclude `y_relayer` and `x_relayer`
- public identity is shared through `X = x_clientG + x_relayerG`
- explicit export reconstructs canonical `x` in the client export view
- explicit export wires require a digest-valid authorization envelope bound to
  the export public transcript

Planned track:

- Lean privacy scaffold first
- Rust implementation after the Lean boundary has stable definitions
- Aeneas bridge after the Rust boundary exists

Status:

- initial Lean scaffold exists at
  [lean-privacy/EcdsaHssPrivacy/TrueBlind.lean](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-privacy/EcdsaHssPrivacy/TrueBlind.lean)
- current scaffold includes role-local input/share models, non-export
  client/server views, explicit-export views, exclusion theorems, and named
  algebraic obligations for additive public-key agreement and export verification
- the model now includes scalar addition modulo the secp256k1 group order,
  abstract base multiplication/public-key addition primitives, concrete
  public-key agreement predicates, export reconstruction predicates, and a
  `wellFormedExecutionState` predicate that packages the true-blind algebraic
  requirements
- the model now defines `F_ecdsa_hss_true_blind`, ideal non-export/export views,
  and observable-only simulators for those views
- first non-export view-invariance theorems now prove that changing client-side
  secrets cannot change the server view when the server share and public identity
  are fixed, and changing server-side secrets cannot change the client view when
  the client share and public identity are fixed
- derivation assumptions now explicitly name the future Rust/Verus obligations:
  client-share public-key agreement, server-share public-key agreement, and the
  secp256k1 additive public-key law
- the ideal functionality now has well-formedness theorems under those
  assumptions, plus export reconstruction and shared-public-identity theorems
- typed operation views now make the non-export and explicit-export disclosure
  policy explicit, including proofs that non-export client operations expose no
  relayer share or canonical scalar, explicit client export exposes the intended
  relayer share and reconstructed scalar, and server operation views expose no
  canonical scalar
- public transcript fields are now modeled explicitly as context binding, public
  share keys, threshold public key, address, operation kind, and transcript
  digest, with proofs that transcripts expose no root/share/canonical-secret
  payloads
- the Lean role-local boundary contract now exists at
  [lean-privacy/EcdsaHssPrivacy/TrueBlindBoundary.lean](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-privacy/EcdsaHssPrivacy/TrueBlindBoundary.lean)
- the boundary contract models client bootstrap wire, server bootstrap wire,
  role-local retained client/server state, explicit export wire, and client
  export reconstruction
- boundary-contract theorems now prove that non-export wire/state shapes exclude
  forbidden root/share/canonical-secret payloads, explicit export wire releases
  only the relayer share needed for export, and client reconstruction from that
  wire matches the ideal explicit-export client view
- an authorized explicit-export envelope now binds export authorization to the
  explicit-export public transcript
- active wire-envelope theorems now prove that only explicit export can carry the
  relayer export share and every active wire envelope excludes client
  root/share material plus canonical `x`
- bound explicit-export session theorems now tie client retained state, export
  authorization, and export wire to the same public identity/context before
  client-side reconstruction
- bound-session reconstruction theorems now prove the reconstructed view
  preserves the authorized public identity, matches the ideal explicit-export
  client view for same-state sessions, and verifies against public key `X`
- bound role-local signing-session theorems now tie retained client/server state
  to the same public identity/context before non-export signing composition
- mismatch-prevention theorems now prove that different public identities or
  different context bindings prevent construction of a bound role-local signing
  session
- export authorization theorems now prove state-created explicit-export
  envelopes carry valid authorization digests, malformed digests prevent valid
  explicit-export envelopes, and any valid role-local envelope carrying a
  relayer export share must be an authorized explicit-export wire
- state-derived signing-session theorems now prove the composed role-local scalar
  matches the ideal reconstructed scalar and verifies against public key `X`
- the Verus mirror now exists at
  [verus/src/shared/true_blind_boundary.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/verus/src/shared/true_blind_boundary.rs)
- Verus mirror proofs cover active wire forbidden-field exclusion,
  explicit-export authorization binding, explicit-export-only relayer-share
  release, and role-local signing-session identity/context binding
