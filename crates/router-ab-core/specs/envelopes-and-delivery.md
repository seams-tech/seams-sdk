# Envelopes And Delivery

This spec defines the encrypted envelope boundary for Router/A/B split
derivation. Encryption implementation is owned by adapters, while this crate
owns the typed metadata, associated data, and commitment shape.

## Boundary Model

This crate models encrypted envelopes as opaque ciphertext packages with typed
public metadata.

Router may inspect:

- envelope version
- ceremony id
- candidate id
- request kind
- sender role and identity
- recipient role and identity
- root-share epoch
- content kind
- ciphertext length
- ciphertext digest

Router must not inspect:

- plaintext role input
- plaintext A/B derivation share
- plaintext output share
- decrypted client delivery material
- decrypted relayer delivery material

## Envelope Kinds

| Kind | Sender | Recipient | Plaintext owner |
| --- | --- | --- | --- |
| `router_to_signer_a` | Router | Signer A | Signer A |
| `router_to_signer_b` | Router | Signer B | Signer B |
| `signer_a_to_signer_b` | Signer A | Signer B | Signer B |
| `signer_b_to_signer_a` | Signer B | Signer A | Signer A |
| `signer_a_to_client` | Signer A | Client | Client |
| `signer_b_to_client` | Signer B | Client | Client |
| `signer_a_to_relayer` | Signer A | Relayer | Relayer |
| `signer_b_to_relayer` | Signer B | Relayer | Relayer |

Direct A/B coordination may use `signer_a_to_signer_b` and
`signer_b_to_signer_a`. Router-mediated relay transports the same encrypted
messages without plaintext access.

## Envelope Public Header

Every envelope has:

- `envelope_version`
- `envelope_kind`
- `candidate_id`
- `request_kind`
- `correctness_level`
- `ceremony_id`
- `root_share_epoch`
- `transcript_digest`
- `sender_role`
- `sender_identity`
- `recipient_role`
- `recipient_identity`
- `content_kind`
- `ciphertext_digest`
- `ciphertext_len`

The public header is loggable after redaction rules are applied.

## Envelope AAD V1

Envelope encryption uses this associated data:

```text
lp("router-ab-derivation/envelope-aad/v1")
|| lp(envelope_version)
|| lp(envelope_kind)
|| lp(candidate_id)
|| lp(request_kind)
|| lp(correctness_level)
|| lp(ceremony_id)
|| lp(root_share_epoch)
|| lp(transcript_digest)
|| lp(sender_role)
|| lp(sender_identity)
|| lp(recipient_role)
|| lp(recipient_identity)
|| lp(content_kind)
```

The ciphertext digest is not included in AAD because it is computed after
encryption. Package commitments include it.

## Content Kinds

Initial content kinds:

- `signer_input`
- `a_to_b_coordination`
- `b_to_a_coordination`
- `client_output_share`
- `relayer_output_share`
- `minimum_level_c_evidence`
- `public_share_binding_evidence`

Each content kind must have a candidate-specific plaintext schema before
implementation.

### `signer_input` Plaintext V1

`signer_input` is the only plaintext content kind a Router-to-signer envelope
may decrypt to in Router A/B v1. The decryption adapter must return typed
`SignerInputPlaintextV1` data to the signer engine; production signer engines
must not accept raw decrypted bytes after the adapter boundary.

Canonical `SignerInputPlaintextV1` bytes bind:

- plaintext schema version: `router_ab_signer_input_plaintext_v1`
- selected candidate: `mpc_threshold_prf_v1`
- primitive request kind
- lifecycle id
- signer-set id
- v1 quorum policy: `all(2)`
- recipient signer role
- recipient signer id
- recipient signer key epoch
- root-share epoch
- selected relayer id
- selected relayer key epoch
- transcript digest
- Router public request digest
- role-envelope AAD digest
- output requests

Allowed output request pairs are:

- `x_client_base` opened to the client recipient
- `x_relayer_base` opened to the selected relayer recipient

Request-kind policy may narrow the output-request list for a specific product
operation. The decoder must reject an output request whose opened share kind and
recipient role do not match the allowlist above.

Forbidden plaintext fields:

- joined `d`
- joined `a`
- joined `x_client_base`
- joined `y_relayer`
- joined `tau_relayer`
- raw root shares
- peer signer root shares
- HSS joined executor state
- OT/evaluator driver state
- client-output or relayer-output plaintext material

Strict decoding rules:

- reject unknown schema versions
- reject unknown candidate ids
- reject unknown content kinds
- reject trailing bytes
- reject duplicate output requests
- reject empty identity, epoch, lifecycle, or recipient fields
- reject signer role mismatch against the envelope header, Router-to-signer
  assignment, and local signer identity
- reject signer id or key epoch mismatch against the signer set
- reject root-share epoch mismatch against local root-share metadata
- reject transcript, request-digest, or AAD-digest mismatch

This schema intentionally carries public derivation metadata and output
instructions only. The signer-local root share is loaded from signer-local
storage after the plaintext passes these checks.

## Delivery Packages

Client and relayer delivery packages contain:

- public envelope header
- ciphertext bytes
- package commitment

Package commitment V1:

```text
SHA-256(
  lp("router-ab-derivation/package-commitment/v1")
  || lp(envelope_header_encoding)
  || lp(ciphertext_digest)
)
```

Minimum Level C evidence commits to delivery package commitments instead of
plaintext outputs.

## Recipient-Output Ciphertext AAD V1

Recipient-output encryption adapters use canonical associated data from
`encode_recipient_output_ciphertext_aad_v1`:

```text
lp("router-ab-protocol/recipient-output-ciphertext-aad/v1")
|| lp(algorithm)
|| lp(recipient_role)
|| lp(opened_share_kind)
|| lp(recipient_identity)
|| lp(recipient_encryption_key)
|| lp(transcript_digest)
|| lp(package_commitment)
|| lp(nonce)
```

This AAD authenticates the delivery context. The full canonical ciphertext
envelope additionally commits to `ciphertext_and_tag`, and package commitments
continue to bind the delivered bytes.

Recipient-output plaintext crosses the crate boundary only through
`RecipientOutputEncryptionRequestV1` and `RecipientOutputEncryptorV1`.
`RecipientOutputEncryptionRequestV1` is intentionally not serializable. It is
valid only inside signer-local or recipient-local encryption code.

Production recipient-output delivery uses algorithm
`hpke_x25519_hkdf_sha256_aes256gcm_v1`: DHKEM X25519, HKDF-SHA256, and
AES-256-GCM. The public recipient key field must use
`x25519:<64 lowercase hex chars>` encoding for that suite. Local simulation may
use `local_deterministic_sha256_v1` only inside the local deterministic
encryptor.

The HPKE implementation dependency is a release gate. Add encryption/decryption
vectors for the chosen crate before routing production delivery through this
suite.

Dependency evaluation note, 2026-06-12: `hpke = "=0.14.0-pre.2"` was evaluated
as the first direct Rust dependency for the Cloudflare adapter. Its transitive
pre-release graph failed to compile locally in `sha3-0.11.0-rc.7`, so this crate
is deferred for production recipient-output delivery until a stable or reviewed
dependency graph passes native and `wasm32-unknown-unknown` builds.

Selected dependency note, 2026-06-12: `hpke-ng = "=0.1.0"` is the first pinned
Cloudflare adapter dependency for this suite, with default features disabled.
Native adapter tests and the `wasm32-unknown-unknown` Cloudflare check pass.
An RFC 9180 AES-256-GCM base-mode open vector passes in the adapter tests.
Deterministic seal vectors, a Wasm vector pass, and explicit AES-GCM
constant-time review for the Cloudflare Wasm target remain release gates before
production delivery can rely on this path. If the AES-GCM posture is
insufficient for Wasm, define a ChaCha20-Poly1305 HPKE suite as a new protocol
algorithm.

## Authentication

Each signer-originated envelope must be authenticated by one of:

- envelope encryption with sender-authenticated public keys
- a detached role signature over the envelope header and ciphertext digest
- a mutually authenticated channel plus an adapter-level signed receipt

The chosen adapter must expose a typed `AuthenticatedEnvelope` boundary to this
crate. Unauthenticated signer envelopes are invalid.

## Retry And Idempotency

Idempotency key:

```text
SHA-256(
  lp("router-ab-derivation/envelope-idempotency/v1")
  || lp(transcript_digest)
  || lp(envelope_kind)
  || lp(sender_identity)
  || lp(recipient_identity)
  || lp(content_kind)
)
```

Rules:

- same idempotency key and same ciphertext digest can be replayed safely
- same idempotency key with a different ciphertext digest is invalid
- partial delivery can be retried by resending the same committed package
- changed transcript fields require a new ceremony id

## Implementation Boundary

This crate should define:

- public header structs
- AAD encoder
- package commitment helper
- idempotency key helper
- redacted diagnostics

Adapters should provide:

- encryption
- decryption
- sender authentication
- transport
- persistence
