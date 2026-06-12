# Errors And Diagnostics

This spec defines stable errors and redacted diagnostics for the
Router/A/B split-derivation crate.

## Error Enum

The Rust crate should expose a stable error code enum:

```rust
pub enum RouterAbDerivationErrorCode {
    EmptyField,
    MalformedInput,
    UnsupportedVersion,
    UnsupportedVectorVersion,
    UnsupportedCandidate,
    NotImplemented,
    CorrectnessLevelMismatch,
    DuplicateSignerIdentity,
    SignerIdentityMismatch,
    SignerReceiptMismatch,
    RootEpochMismatch,
    TranscriptMismatch,
    RecipientMismatch,
    ReplayMismatch,
    UnauthenticatedEnvelope,
    PackageCommitmentMismatch,
    OutputVerificationFailed,
    AddressVerificationRequired,
    InvalidStateTransition,
    SecretMaterialExposure,
}
```

Existing variants should be kept only if they are part of this current enum.
Development-stage breaking changes are acceptable.

## Error Contract

Every error contains:

- stable error code
- redacted message
- optional redacted diagnostic object

Every error excludes:

- secret shares
- root bytes
- scalar bytes
- private keys
- decrypted envelope plaintext
- decrypted delivery material
- joined secret values

## Redacted Diagnostic Struct

Suggested shape:

```rust
pub struct RedactedDiagnostic {
    pub code: RouterAbDerivationErrorCode,
    pub role: Option<Role>,
    pub candidate_id: Option<CandidateId>,
    pub request_kind: Option<RequestKind>,
    pub correctness_level: Option<CorrectnessLevel>,
    pub ceremony_id: Option<CeremonyId>,
    pub root_share_epoch: Option<RootShareEpochLabel>,
    pub transcript_digest: Option<PublicDigest32>,
    pub package_commitment: Option<PublicDigest32>,
}
```

These fields are public or metadata. They can be logged after boundary policy
checks.

## Error Mapping

| Condition | Error code |
| --- | --- |
| empty required field | `EmptyField` |
| unknown context version | `UnsupportedVersion` |
| unknown candidate id | `UnsupportedCandidate` |
| unsupported fixture version | `UnsupportedVectorVersion` |
| wrong correctness level | `CorrectnessLevelMismatch` |
| same identity for Signer A and Signer B | `DuplicateSignerIdentity` |
| expected signer identity differs | `SignerIdentityMismatch` |
| signer receipt does not bind expected transcript | `SignerReceiptMismatch` |
| expected epoch differs | `RootEpochMismatch` |
| transcript digest differs | `TranscriptMismatch` |
| recipient role or identity differs | `RecipientMismatch` |
| replay key reused with different value | `ReplayMismatch` |
| missing envelope authentication | `UnauthenticatedEnvelope` |
| package commitment differs | `PackageCommitmentMismatch` |
| address or account relation verification failed | `OutputVerificationFailed` |
| activation attempted before address verification | `AddressVerificationRequired` |
| state transition is invalid | `InvalidStateTransition` |
| code path attempts to expose secret material | `SecretMaterialExposure` |

## Source Guards

Source guards should fail on:

- `Debug` implementation that prints secret bytes
- logging of fields named `root`, `share`, `scalar`, `secret`, `private_key`,
  `plaintext`, or `delivery_material` outside allowlisted tests
- functions returning `SecretMaterial32` through public adapter APIs
- broad serialization derives on secret material
- use of `unwrap` in verification paths
- error strings that include raw envelope plaintext

Allowlist:

- docs
- fixture names
- tests that assert redaction
- secret wrapper `Debug` implementations that print `[redacted]`

## Test Vectors

Diagnostics vectors must cover:

- duplicate signer identity
- transcript mismatch
- replay mismatch
- recipient mismatch
- root epoch mismatch
- unauthenticated envelope
- package commitment mismatch
- address verification required

Each vector must assert:

- expected stable error code
- expected redacted diagnostic fields
- absence of forbidden plaintext substrings
