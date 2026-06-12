# Public Rust API Shape

This spec defines the intended Rust API before implementation. The exact code
can evolve, but these ownership and type boundaries should remain stable.

## Modules

Recommended modules:

```text
src/
  context.rs
  transcript.rs
  envelope.rs
  evidence.rs
  state_machine.rs
  diagnostics.rs
  secrets.rs
  vectors.rs
  candidate_mpc_prf.rs
  candidate_split_root.rs
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

Core functions accept typed values only.

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
pub struct IndexedSignerBinding;
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
V1 transcript APIs model internals around signer sets while enforcing
`quorumPolicy = all(2)`.

## Envelope API

```rust
pub fn envelope_aad_v1(header: &EnvelopeHeaderV1) -> Result<Vec<u8>>;
pub fn package_commitment_v1(package: &DeliveryPackageV1) -> Result<PublicDigest32>;
pub fn envelope_idempotency_key_v1(header: &EnvelopeHeaderV1) -> Result<PublicDigest32>;
```

Encryption and decryption stay in adapters.

## Minimum Level C API

```rust
pub fn verify_minimum_level_c_v1(
    input: MinimumLevelCVerificationInputV1,
) -> Result<VerifiedMinimumLevelCEvidenceV1>;
```

The verified return type is distinct from parsed evidence, so activation APIs
can require verified evidence.

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

Candidate APIs stay behind explicit candidate modules:

```rust
pub mod candidate_mpc_prf {
    pub fn derive_signer_partial_v1(input: MpcPrfSignerInputV1) -> Result<MpcPrfSignerOutputV1>;
    pub fn verify_partial_v1(input: MpcPrfPartialVerificationInputV1) -> Result<VerifiedMpcPrfPartialV1>;
}

pub mod candidate_split_root {
    pub fn derive_output_share_v1(input: SplitRootSignerInputV1) -> Result<SplitRootSignerOutputV1>;
    pub fn verify_output_share_v1(input: SplitRootVerificationInputV1) -> Result<VerifiedSplitRootShareV1>;
}
```

Candidate implementation remains gated until candidate-specific specs settle.

## Future Threshold Upgrade Path

V1 APIs should avoid fixed two-signer internals below the product request
boundary. Public examples can expose A/B names for readability, while core
types use:

- signer set id
- indexed signer entries
- signer identity
- signer key epoch
- quorum policy
- selected relayer identity
- selected relayer recipient encryption key
- client identity
- client ephemeral public key

Encrypted-envelope digests are carried by protocol payload assignment metadata,
outside the derivation transcript.

Future N-of-N can extend the signer set under a new protocol version. Future
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
