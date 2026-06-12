# Candidate Spec: Split Root Derivation

Candidate id: `split_root_derivation_v1`

This candidate derives output material from independent A/B root states and
recipient-side combination. It is attractive if it gives lower latency or lower
implementation complexity than threshold PRF partial verification.

## State

Signer A holds:

- `root_a`
- Signer A identity key
- current root-share epoch
- candidate suite id

Signer B holds:

- `root_b`
- Signer B identity key
- current root-share epoch
- candidate suite id

Router holds public metadata and encrypted packages only.

## Output Inputs

Each role derives a role-local output share from:

- candidate domain label
- signer role
- signer identity
- transcript digest
- output kind
- recipient role
- recipient identity
- root-share epoch

## Candidate Formula Under Evaluation

Implemented adapter boundary:

- `SplitRootSecretShareV1`
- `SplitRootOutputRequestV1`
- `SplitRootSignerInputV1`
- `SplitRootOutputShareBindingV1`
- `SplitRootOutputShareWireV1`
- `SplitRootSignerOutputShareV1`
- `SplitRootVerifiedOutputShareV1`

Implemented suite and label types:

- `SplitRootSuiteId::HashToScalarSha512V1`
- `SplitRootDerivationLabelV1::OutputShare`

The implemented measurement formula is:

```text
share_i = Scalar::from_bytes_mod_order_wide(
  SHA-512(
    len32("router-ab-derivation/split-root/output-share/v1")
    || len32("split_root_hash_to_scalar_sha512_v1")
    || len32(root_i)
    || len32(transcript_digest)
    || len32(output_kind)
    || len32(recipient_role)
    || len32(recipient_identity)
    || len32(signer_role)
    || len32(signer_identity)
    || len32(root_share_epoch)
  )
)

output = share_a + share_b mod group_order
```

`len32` is a four-byte big-endian length prefix followed by the field bytes.
The output-share wire is `share_i.to_bytes()`. The recipient combiner accepts
only canonical 32-byte scalar-share wires via
`Scalar::from_canonical_bytes`, then returns `(share_a + share_b).to_bytes()`
as recipient-local secret output material.

This formula is implemented for measurement and vector work. Production
selection still requires bias analysis, root-generation analysis, refresh
analysis, and address-verification release gates.

## Message Flow

Registration and export:

1. Router creates transcript and role envelopes.
2. Router sends encrypted signer input to A and B.
3. A and B validate transcript, signer identity, and epoch.
4. A derives A-side client and relayer output shares.
5. B derives B-side client and relayer output shares.
6. A encrypts client share to client and relayer share to relayer.
7. B encrypts client share to client and relayer share to relayer.
8. A and B return authenticated receipts and package commitments.
9. Minimum Level C verifies transcript and delivery binding.
10. Recipients decrypt and add their own two shares.

No Router plaintext combine is allowed.

No direct A/B coordination messages are required for the basic split-root
output-share path. Future proof or anti-bias ceremonies must introduce a new
coordination-message version and new vectors.

## Output Share Format

Implemented planner: `plan_split_root_output_share_v1`.

Required public binding fields:

- suite id
- derivation label
- transcript digest
- root-share epoch
- output kind: `x_client_base` or `x_relayer_base`
- recipient role
- recipient identity
- signer role
- signer identity

`scalar share bytes` are secret until delivered to the recipient.
`SplitRootOutputShareWireV1` is fixed-width, zeroizing, debug-redacted, and
intentionally non-serializable. Adapters must encrypt share bytes before
transport.

## Combiner Behavior

Implemented planner: `plan_split_root_combine_v1`.

The planner validates:

- context candidate id is `split_root_derivation_v1`
- two verified shares bind the same transcript digest
- shares bind the requested recipient role and identity
- `x_client_base` outputs target the client
- `x_relayer_base` outputs target the relayer
- signer roles are distinct
- signer identities match the transcript signer set

The cryptographic combine path parses both fixed-width share wires as
canonical Curve25519 scalars and adds them with `curve25519-dalek`.

## Refresh

Refresh is the main resolved tradeoff for the adapter prototype.

Implemented planner: `plan_split_root_refresh_v1`.

Implemented mode:

- `SplitRootRefreshModeV1::FutureEpochNewOutputRelation`

This mode rotates `root_a` and `root_b` for future ceremonies and creates a new
verified output relation. Activation requires address verification for the new
epoch.

Preserving refresh for existing account-output relations is unavailable in this
candidate adapter. The plan records `preserves_existing_output_relation =
false`.

Reasoning:

- The additive output formula binds the root-share epoch.
- Rotating independent roots changes future output shares.
- Production activation must treat the new epoch as a fresh verified output
  relation.

## Bias Analysis

A malicious signer may choose its root or output share to influence the final
combined output. Before implementation, the spec must define:

- root generation ceremony
- commitment to root or output share
- whether output share proofs are required
- whether address verification catches biased output before activation
- whether public-share-binding hardening is mandatory for this candidate

## Leakage Table

| View | Visible plaintext | Forbidden material excluded | Adapter guard |
| --- | --- | --- | --- |
| Router | context, transcript, signer-set metadata, encrypted package headers, commitments, receipts, replay decisions | split roots, plaintext output-share wires, joined outputs | Router APIs only accept public metadata and package commitments |
| Signer A | `root_a`, A-side output-share wires before encryption, signer input metadata | `root_b`, B-side output-share wires, joined `x_client_base`, joined `x_relayer_base`, joined `d`, joined `a` | signer input validates Signer A identity, transcript digest, recipient binding, and epoch |
| Signer B | `root_b`, B-side output-share wires before encryption, signer input metadata | `root_a`, A-side output-share wires, joined `x_client_base`, joined `x_relayer_base`, joined `d`, joined `a` | signer input validates Signer B identity, transcript digest, recipient binding, and epoch |
| Client | client-targeted A/B output-share wires after decryption, `x_client_base` after combine, Minimum Level C evidence | relayer-targeted output-share wires, `x_relayer_base`, relayer HSS material | output request enforces `x_client_base -> client` |
| Relayer | relayer-targeted A/B output-share wires after decryption, `x_relayer_base` after combine, Minimum Level C evidence | client-targeted output-share wires, `x_client_base`, client hidden computation material | output request enforces `x_relayer_base -> relayer` |
| Sealed-root storage | encrypted A/B split roots, key epoch labels, signer identity labels | decrypted split roots, output-share wires, joined outputs | storage is outside this crate; adapters must decrypt into zeroizing wrappers |
| Diagnostics/logging | stable error codes, redacted diagnostics, public digests | split-root bytes, output-share wire bytes, plaintext package bytes | source guards reject logging macros and secret serialization |
| Replayed transcript view | replay cache key, accepted transcript digest, prior public package commitments | fresh output-share wires or alternate recipient openings | Minimum Level C replay binding rejects changed transcript digest |

Minimum Level C protects server blindness and delivery binding. A malicious
signer can still choose or bias a root/output share unless address verification
or public-share-binding hardening catches the resulting output relation before
activation.

## Constant-Time Requirements

Implementation must avoid:

- branching on root bytes or scalar share bits
- table lookup by root bytes or scalar share bits
- division or modulo by secret-derived values
- early-exit comparison of secret shares

Scalar reduction and addition must use vetted constant-time curve/scalar
library operations.

Current adapter scope:

- fixed-width checks operate on public wire lengths
- signer role, recipient role, and transcript checks operate on public metadata
- plaintext root and output-share wrappers zeroize and redact debug output
- scalar reduction and scalar addition use `curve25519-dalek` scalar APIs

## Open Items

- root generation ceremony
- bias-resistance mechanism
- whether this candidate can support production root rotation cleanly
- whether the provisional SHA-512-to-Scalar and scalar-share encoding become
  the selected production suite
