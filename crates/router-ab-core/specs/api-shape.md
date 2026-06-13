# Public Rust API Shape

This spec defines the intended Rust API before implementation. The exact code
can evolve, but these ownership and type boundaries should remain stable.

## Modules

Recommended modules:

```text
src/
  boundary.rs
  context.rs
  transcript.rs
  envelope.rs
  evidence.rs
  state_machine.rs
  diagnostics.rs
  secrets.rs
  vectors.rs
  candidate_mpc_prf.rs
  wire/
```

## Boundary Parsers

Raw inputs are parsed once at the boundary:

```rust
pub fn parse_context_v1(raw: RawContextV1) -> Result<DerivationContext>;
pub fn parse_transcript_v1(raw: RawTranscriptV1) -> Result<TranscriptBinding>;
pub fn parse_envelope_header_v1(raw: RawEnvelopeHeaderV1) -> Result<EnvelopeHeaderV1>;
pub fn parse_minimum_level_c_evidence_v1(
    raw: RawMinimumLevelCEvidenceV1,
) -> Result<MinimumLevelCEvidenceV1>;
```

The raw V1 structs use canonical string labels and adapter-owned bytes. Parsers
normalize them into `DerivationContext`, `TranscriptBinding`,
`EnvelopeHeaderV1`, and `MinimumLevelCEvidenceV1` by calling the same
constructors and validators used by core code. Core functions accept typed
values only.

Typed envelope, delivery-package, state-machine, and verifier-input structs are
constructor-only where they carry normalized envelope/package values. They do
not deserialize directly from raw request JSON; adapters must parse raw boundary
shapes first.

Typed context and transcript structs may remain serializable for fixtures and
contract vectors, but deserialization must call the same validating constructors
used by the raw parser path. Direct typed serde must reject empty required
fields, non-`all(2)` signer sets, duplicate signer identities, and malformed
transcript identity fields.

Context, transcript, signer-set, and signer-entry types are private-field,
constructor/accessor-only types. Invalid signer-set shapes are rejected by
constructors such as `SignerSetBinding::v1_all2` and
`SignerSetBinding::from_indexed_v1`, including boundary parser input and
rejection-vector generation.

Protocol-local payload, identity, lifecycle, and local HTTP structs may remain
public serde/wire shapes when they are validated at protocol boundaries. They
must not replace the derivation invariant types inside core derivation logic.

Typed Minimum Level C receipt/evidence structs are constructor/accessor-only.
`AuthenticatedSignerReceiptV1` and `MinimumLevelCEvidenceV1` may deserialize
for fixtures and contract vectors, but direct typed serde must run the same
validating constructors as the raw parser path. `VerifiedMinimumLevelCEvidenceV1`
must not deserialize from raw JSON; it is created only after verifier success.

## Request Scope

Use request-kind-specific scope:

```rust
pub enum RequestScope {
    Registration(RegistrationScope),
    Export(ExportScope),
    Refresh(RefreshScope),
}
```

`RefreshScope` includes both old and new epochs.

## Transcript API

```rust
pub struct SignerSetBinding;
pub struct IndexedDeriverBinding;
pub enum QuorumPolicy;

impl SignerSetBinding {
    pub fn v1_all2(...) -> Result<SignerSetBinding>;
}

pub fn encode_context_v1(context: &DerivationContext) -> Result<Vec<u8>>;
pub fn context_digest_v1(context: &DerivationContext) -> Result<PublicDigest32>;
pub fn encode_transcript_v1(binding: &TranscriptBinding) -> Result<Vec<u8>>;
pub fn transcript_digest_v1(binding: &TranscriptBinding) -> Result<PublicDigest32>;
```

These functions operate on public metadata and may use ordinary branching.
V1 transcript APIs model internals around deriver sets while enforcing
`quorumPolicy = all(2)`.

## Envelope API

```rust
pub fn envelope_aad_v1(header: &EnvelopeHeaderV1) -> Result<Vec<u8>>;
pub fn package_commitment_v1(package: &DeliveryPackageV1) -> Result<PublicDigest32>;
pub fn envelope_idempotency_key_v1(header: &EnvelopeHeaderV1) -> Result<PublicDigest32>;
```

Encryption and decryption stay in adapters.
`EnvelopeHeaderV1` and `DeliveryPackageV1` expose accessors plus validated
constructors. Public field construction is intentionally unavailable.

## Minimum Level C API

```rust
pub fn verify_minimum_level_c_v1(
    input: MinimumLevelCVerificationInputV1,
) -> Result<VerifiedMinimumLevelCEvidenceV1>;
```

The verified return type is distinct from parsed evidence, so activation APIs
can require verified evidence.

`AuthenticatedSignerReceiptV1` requires exactly two signer output commitments:
client output and SigningWorker/relayer output. `MinimumLevelCEvidenceV1`
requires exactly two client package commitments and exactly two
SigningWorker/relayer package commitments, one from each deriver. State-machine
output binding enforces the same exact shape.

## State Machine API

Use branch-specific builders:

```rust
pub fn begin_requested(input: BeginCeremonyInput) -> Result<CeremonyRequested>;
pub fn create_role_envelopes(state: CeremonyRequested) -> Result<RoleEnvelopesCreated>;
pub fn accept_signer_inputs(input: SignerInputAcceptance) -> Result<SignerInputsAccepted>;
pub fn bind_outputs(input: OutputBindingInput) -> Result<OutputsBound>;
pub fn mark_delivered(input: DeliveryReceiptInput) -> Result<CeremonyDelivered>;
pub fn verify_ceremony(input: VerificationInput) -> Result<CeremonyVerified>;
pub fn abort_ceremony(input: AbortInput) -> Result<CeremonyAborted>;
```

No function should accept a broad `CeremonyState` when it needs one exact state.

## Candidate APIs

The selected v1 derivation path is `mpc_threshold_prf_v1`. Public candidate APIs
expose the threshold-PRF proof-bundle path and the threshold backend adapter
boundary.

```rust
pub mod candidate_mpc_prf {
    pub fn plan_mpc_prf_purpose_binding_v1(...);
    pub fn evaluate_mpc_prf_signer_partial_with_threshold_backend_v1(...);
    pub fn verify_mpc_prf_partial_with_threshold_backend_v1(...);
    pub fn combine_mpc_prf_proof_bundles_with_threshold_backend_v1(...);
}
```

The old split-root implementation is removed from compiled core. Split-root may
remain in specs, fixtures, or benches as comparison material until fresh review
gates accept it.

## Future Threshold Upgrade Path

V1 APIs should avoid fixed two-deriver internals below the product request
boundary. Public examples can expose A/B names for readability, while core
types use:

- deriver set id
- indexed deriver entries
- deriver identity
- deriver key epoch
- quorum policy
- selected SigningWorker identity
- selected SigningWorker recipient encryption key
- client identity
- client ephemeral public key

Encrypted-envelope digests are carried by protocol payload assignment metadata,
outside the derivation transcript.

Future N-of-N can extend the deriver set under a new protocol version. Future
t-of-N requires new candidate specs, vectors, leakage analysis, quorum
selection, replay and equivocation handling, and refresh/reshare semantics.

## Diagnostics API

```rust
pub fn redacted_diagnostic(error: &RouterAbDerivationError) -> RedactedDiagnostic;
```

Diagnostics are public metadata only. They cannot influence protocol control
flow except through stable error codes.

## Feature Flags

Initial feature policy:

- default native Rust library
- optional `wasm` feature only for adapter-compatible APIs
- optional `bench` feature only for benchmarks
- no legacy compatibility features

## Wasm Compatibility

Public APIs must avoid:

- OS-specific filesystem access
- blocking network access
- thread-local secret state
- non-deterministic global initialization

Adapters own Worker bindings, randomness sources, clocks, and storage.
