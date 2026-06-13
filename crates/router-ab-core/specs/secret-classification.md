# Secret Classification

This spec classifies fields for logging, persistence, constant-time handling,
and formal verification.

## Classes

| Class | Meaning | Loggable | Persistable |
| --- | --- | --- | --- |
| `public` | Safe to publish | yes | yes |
| `metadata` | Public within system logs | yes, with policy | yes |
| `encrypted_sensitive` | Ciphertext carrying secret plaintext | header only | yes |
| `role_local_secret` | Secret owned by exactly one role | no | only encrypted/role-local |
| `recipient_secret` | Secret after recipient decrypts | no | recipient-local only |
| `forbidden_joined_secret` | Joined state the system must never materialize | no | no |

## Public Fields

- candidate id
- request kind
- correctness level
- protocol versions
- domain labels
- context digest
- transcript digest
- package commitment
- ciphertext digest
- ciphertext length
- public transcript evidence

## Metadata Fields

- network id
- account id
- account public key
- root-share epoch label
- ceremony id
- role name
- role identity
- deployment id
- retry counter
- verification status

## Encrypted Sensitive Fields

- deriver input ciphertext
- A/B coordination ciphertext
- client delivery ciphertext
- SigningWorker delivery ciphertext

Only headers, digests, lengths, and commitments are loggable.

## Role-Local Secrets

Deriver A:

- `root_a`
- `prf_share_a`
- A-side output shares
- A-side private authentication key

Deriver B:

- `root_b`
- `prf_share_b`
- B-side output shares
- B-side private authentication key

Router:

- Router private authentication key
- envelope encryption private key when Router is a recipient for metadata

Client:

- client decryption key
- client-output partials

SigningWorker:

- SigningWorker decryption key
- SigningWorker-output partials

## Recipient Secrets

Client recipient secrets:

- decrypted client package plaintext
- client-output shares
- opened `x_client_base`

SigningWorker recipient secrets:

- decrypted SigningWorker package plaintext
- SigningWorker-output shares
- opened `x_relayer_base`

## Forbidden Joined Secrets

These values must never be materialized by Router, Deriver A, Deriver B, or
shared server-side code:

- joined `d`
- joined `a`
- joined `x_client_base`

These values must never be materialized by client code:

- joined `d`
- joined `a`
- joined `y_relayer`
- joined `tau_relayer`

## Constant-Time Requirements

Constant-time handling is required for:

- scalar share arithmetic
- root-share expansion
- PRF share evaluation
- secret partial comparison
- secret key parsing
- `HashToScalar` reduction when inputs include secret-keyed material

Allowed variable-time operations:

- public context validation
- public transcript digest comparison
- public package commitment comparison
- public string parsing
- public vector parsing

Forbidden operations on secret-derived values:

- division
- modulo through variable-time integer operations
- branch conditions
- loop bounds
- table indexes
- early-exit equality

Scalar operations should use vetted constant-time curve/scalar libraries.

## Rust Type Requirements

Secret types must:

- avoid `Serialize`
- avoid plaintext `Debug`
- zeroize on drop
- expose bytes only through crate-private methods or explicit recipient APIs
- use constant-time equality where equality is needed

Public types may derive:

- `Debug`
- `Clone`
- `PartialEq`
- `Eq`
- `Serialize`
- `Deserialize`

## Review Checklist

Before candidate implementation lands:

- every struct field has a class
- every secret type has redacted `Debug`
- every secret type zeroizes on drop
- every public API return type excludes forbidden joined secrets
- constant-time review has checked secret arithmetic and comparisons
