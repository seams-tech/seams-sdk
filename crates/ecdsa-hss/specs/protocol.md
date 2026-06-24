# Protocol Spec

This document defines the target protocol shape for `ecdsa-hss`.

The production design is role-local additive derivation: the client derives the
client ECDSA share locally, the server derives the relayer ECDSA share locally,
and the live server process never reconstructs the canonical secp256k1 private
scalar.

## Purpose

`ecdsa-hss` produces one canonical secp256k1 key for EVM use that is:

- threshold-signable
- exportable by the authorized client
- deterministic
- server-blind during non-export and export-preparation flows

The protocol must preserve one logical EVM key for both threshold signing and
explicit export.

## Parties

- client
- server / relayer

## Canonical Key Object

The canonical key identity is the logical secp256k1 scalar:

```text
x = x_client + x_relayer mod n
```

where:

- `n` is the secp256k1 group order
- `x_client` is derived by the client from client-owned material
- `x_relayer` is derived by the server from server-owned material

The public identity is:

```text
X_client = x_client * G
X_relayer = x_relayer * G
X = X_client + X_relayer
X = (x_client + x_relayer) * G
address = ethereum_address(X)
```

The scalar `x` is a logical/export scalar. The server process must never compute
or retain it.

## Fixed Input Domain

The role-local input domain is:

- `y_client`: client-owned 32-byte local derivation input
- `y_relayer`: server-owned 32-byte local derivation input

`y_client` is accepted only by the client role. `y_relayer` is accepted only by
the server role. A production request path must not accept both values in one
process.

The active HSS context binding tuple is v4:

- `scheme_id = "ecdsa-hss-v4"`
- `curve = "secp256k1"`
- `application_binding_digest`: 32 opaque bytes supplied by the SDK
- `participant_ids = [1, 2]`

This context is part of deterministic role-local derivation. The Rust crate
does not know the SDK product fields that produced the digest.

Funds-safety invariant: every EVM-class target for the same SDK application
binding digest must derive the same threshold ECDSA public key and Ethereum
address. Concrete chain targets, wallet key aliases, RP IDs, and auth-method
labels stay out of the HSS stable key context unless the SDK intentionally folds
them into the digest before crossing the crate boundary. Cross-chain replay
protection belongs to EVM transaction chain IDs and typed-data domain
separation.

### `chain_target` Cleanup

Public SDK and product flows still require concrete `chainTarget` for EVM lane
selection, budgets, sealed recovery lookup, transaction serialization, nonce
handling, and signing policy. That product-level field stays outside the HSS
stable-key derivation context.

The `ecdsa-hss` Rust context does not contain `chain_target`. Request and
persistence boundaries may parse product-level chain target values only to route
the operation before building the HSS context.

Implementation rule:

- product/API surface: concrete `chainTarget` is allowed for routing and policy
- HSS stable context: `chain_target` is absent
- HSS derivation: SDK-controlled fields enter only through
  `application_binding_digest`
- tests: changing only concrete `chainTarget` must preserve the HSS public key
  and Ethereum address

### Removed Context-Version Boundary

The historical context used `wallet_session_user_id` and `subject_id`.
After v2 invalidation, those records require wipe/recreate before active
signing or export. Production request, persistence, signing, export, and Rust
crate boundaries must reject those fields for active ECDSA HSS records.

The Rust crate no longer retains the old context version, byte encoder, wire
types, server/client APIs, fixtures, benchmarks, or formal-verification tests.
The only active context format is `encode_context`.

## `encode_context` Byte Contract

`encode_context` is the active HSS context format.

The byte encoding is:

- ASCII domain tag: `b"ecdsa-hss:context:v4"`
- followed by the fixed tuple fields in this exact order:
  1. `scheme_id`
  2. `curve`
  3. `application_binding_digest`
  4. `participant_ids`

The string fields are:

- `scheme_id`
- `curve`

The string length and ASCII validation rules are the same for every string
field. The application binding digest is exactly 32 raw bytes. The active
participant-id bytes are `0x02 || 0x0001 || 0x0002`.

## Role-Local Share Derivation

Define:

```text
frame(domain, fields...) =
  ascii(domain) || field_count:u8 || repeated field(tag:u8, len:u16be, value)

H_scalar(domain, context_binding32, context_bytes, input_le32, retry_counter) =
  reduce_to_nonzero_scalar(SHA-512(frame(
    domain,
    field(0x01, context_binding32),
    field(0x02, context_bytes),
    field(0x03, input_le32),
    field(0x04, retry_counter:u32be)
  )))
```

The active product share derivation is:

```text
context = encode_context(...)
context_binding32 = SHA-256(frame(
  "ecdsa-hss:role-local:v2:context-binding",
  field(0x01, context)
))
x_client = H_scalar(
  "ecdsa-hss:role-local:v2:client-share",
  context_binding32,
  context,
  y_client,
  client_retry_counter
)
x_relayer = H_scalar(
  "ecdsa-hss:role-local:v2:relayer-share",
  context_binding32,
  context,
  y_relayer,
  relayer_retry_counter
)
```

This guarantees each role-local share is a valid non-zero secp256k1 scalar.

The public identity is derived without reconstructing `x`:

```text
X_client = x_client * G
X_relayer = x_relayer * G
X = X_client + X_relayer
address = ethereum_address(X)
```

### Zero Canonical Key Case

`x_client` and `x_relayer` are each non-zero, but their sum can still be zero
modulo the secp256k1 group order with negligible probability. That would make
the logical canonical key invalid and would make `X_client + X_relayer` the
point at infinity.

The deterministic rule is:

1. client derivation retries only for an invalid or zero `x_client`
2. server derivation retries for invalid or zero `x_relayer`
3. after receiving `X_client`, the server checks `X_client + X_relayer`
4. if the sum is the identity point, the server increments
   `relayer_retry_counter` and rederives `x_relayer`
5. the accepted relayer retry counter is persisted and included in the public
   transcript

Client verification must reject a public identity whose threshold public key is
the identity point or whose relayer retry counter does not match the accepted
public transcript.

### Public Key Validation

Every public key accepted from another role must pass these checks before it is
stored, transcript-bound, or used for Cait-Sith setup:

- exactly 33 bytes
- SEC1 compressed encoding
- prefix is `0x02` or `0x03`
- decompresses to a valid secp256k1 affine point
- canonical re-encoding equals the input bytes
- represents a non-identity point

`threshold_public_key33 = X_client + X_relayer` must also be a valid non-identity
compressed point. Public key validation failures burn the staged ceremony state.

The server retains only:

- `x_relayer`
- `X_relayer`
- `X_client`
- `X`
- `address`
- context binding and audit metadata

The client retains only:

- `x_client`
- `X_client`
- `X_relayer`
- `X`
- `address`
- context binding and local audit metadata

## Single-Key Invariant

The protocol is correct only if all three refer to the same logical key:

1. the client-reconstructed export scalar
2. the threshold signing public key
3. the Ethereum address used for threshold signing

In shorthand:

```text
x_export = x_client + x_relayer_export mod n
x_export * G == X
ethereum_address(X) == expected_address
```

## Operations

The protocol defines four logical operation classes.

### 1. RegistrationBootstrap

Purpose:

- establish the role-local client and relayer shares for a newly registered
  account
- establish shared public identity `X` and address

Output policy:

- must not return canonical `x`
- must not send `y_client` or `x_client` to the server
- must not send `y_relayer` or `x_relayer` to the client

### 2. SessionBootstrap

Purpose:

- restore or reconnect a threshold-signing session using persisted role-local
  shares and shared public identity

Output policy:

- must not return canonical `x`
- must not return export-capable material

### 3. NonExportSign

Purpose:

- produce threshold ECDSA signatures using role-local shares that compose to the
  canonical logical key

Output policy:

- must not return canonical `x`
- must not return `x_relayer` to the client
- must not expose export-capable material through retry, abort, or session
  cleanup paths

### 4. ExplicitKeyExport

Purpose:

- intentionally let the authorized client reconstruct canonical `x`

Output policy:

- server may release only an export-authorized relayer share envelope
- client reconstructs `x = x_client + x_relayer_export mod n`
- export must be explicit, policy-bound, transcript-bound, and auditable

## High-Level Lifecycle

The target lifecycle is:

1. Client derives `x_client` locally from `y_client` and context.
2. Server derives `x_relayer` locally from `y_relayer` and context.
3. Client and server exchange public share commitments and transcript metadata.
4. Both roles verify the same public identity `X` and address.
5. Non-export signing maps role-local shares into the Cait-Sith backend share
   format.
6. Explicit export returns an authorized relayer export share to the client.
7. The client reconstructs and verifies `x` locally.

## Fixed Scope

The first implementation pass is intentionally narrower than generic threshold
ECDSA.

Scope:

- fixed 2-of-2 only
- fixed participant IDs:
  - client = `1`
  - relayer = `2`
- integration through the existing 2-party additive-share mapping layer

Out of scope:

- generalized `t-of-n`
- alternate participant-ID layouts
- a second share-mapping implementation path

## Backend Share Mapping

The threshold backend receives mapped shares derived from:

```text
x_client
x_relayer
```

The mapping layer must preserve the effective signing key:

```text
effective_backend_secret == x_client + x_relayer mod n
backend_public_key == X
backend_address == ethereum_address(X)
```

If backend compatibility requires resharing, the resharing step must preserve
the same `X` and address.

## Wire And Retained-State Contract

The active role-local boundary shape is:

- client bootstrap wire:
  - context binding
  - `X_client`
  - transcript digest
- server bootstrap wire:
  - public transcript with context binding, `X_client`, `X_relayer`, `X`,
    address, operation kind, and transcript digest
- non-export retained server state:
  - `x_relayer`
  - public identity
  - accepted transcript
- non-export retained client state:
  - `x_client`
  - public identity
  - accepted transcript
- explicit export wire:
  - export-authorized `x_relayer`
  - public transcript

Every active wire envelope must exclude:

- client root material
- client share material
- canonical `x`

Only the explicit export wire envelope may carry `x_relayer` to the client, and
that envelope must bind to the same public identity and context as the client
retained state.

## Relayer Key Rotation

Initial rotation policy is fail-closed:

- retained role-local relayer state is bound to `relayer_key_id`
- every bootstrap, signing, presign, and export request must name the retained
  `relayer_key_id`
- if the request relayer key id differs from persisted state, reject the request
- relayer key rotation requires a new role-local HSS bootstrap
- persisted presign/triple state is invalid across relayer key rotation

This keeps relayer-key identity in the public/audit surface and avoids implicit
reuse of `x_relayer` under a different operator key.

## WASM API Split

Browser WASM may expose only client-role operations:

- `derive_client_role_share`
- `verify_role_local_public_identity`
- `map_client_role_share_for_cait_sith`
- `authorize_explicit_export`
- `reconstruct_explicit_export`

Server/native WASM or server Rust may expose only relayer-role operations:

- `derive_relayer_role_share`
- `compose_role_local_public_identity`
- `map_relayer_role_share_for_cait_sith`
- `authorize_relayer_export_share`
- `release_authorized_relayer_export_share`

Browser/client bundles must not export relayer derivation or relayer export-share
release functions. Server bundles must not export client derivation or canonical
export reconstruction functions.

## Required Equivalence Checks

The implementation must check:

- `pub(x_client) == X_client`
- `pub(x_relayer) == X_relayer`
- `X_client + X_relayer == X`
- `ethereum_address(X) == expected_address`
- explicit export reconstructs `x_export`
- `x_export * G == X`
- `ethereum_address(x_export * G) == expected_address`

These are main protocol identity checks.

## Fixture And Reference Requirements

The joined-root fixture corpus has been removed. The active fixture emitter is:

- [emit_fixture_json.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/bin/emit_fixture_json.rs)

The next committed role-local fixture corpus should cover:

- `y_client`
- `y_relayer`
- `context`
- `encode_context_v2(context)` bytes
- `x_client`
- `x_relayer`
- `X_client`
- `X_relayer`
- `X`
- Ethereum address
- mapped backend shares for participant IDs `{1, 2}`
- explicit export reconstruction `x_export`

Reference-only code may reconstruct `x` for fixture generation and algebraic
tests. Production server code must never do so.

Reference helper gating:

- full-key reconstruction helpers live under `fixtures`, `reference`, tests,
  benches, or the fixture-emitter binary
- production modules do not import reference helpers
- reference helpers are not re-exported from crate root as public production API
- reference-only functions use `reference_` or `fixture_` prefixes
- reference-only digest labels remain distinct from role-local production labels
- tests include an import guard for server/client production modules

## Audit And Log Redaction

Allowed log/audit fields:

- event kind
- operation kind
- result and failure code
- `relayer_key_id`
- client device/session identifiers
- application binding digest fingerprint
- context binding
- public transcript digest
- export authorization digest
- compressed public key fingerprints
- Ethereum address
- timestamp and expiry

Forbidden log/audit fields:

- `y_client`
- `y_relayer`
- `x_client`
- `x_relayer`
- canonical `x`
- mapped backend threshold private shares
- Cait-Sith triple, presignature scalar, nonce, or sigma shares
- raw root-share material

Secret-bearing types should either omit `Debug` or implement redacted `Debug`.
Serialization should be absent for secret newtypes unless the serialized form is
an explicitly named encrypted or export-only artifact.

## Non-Goals

This protocol excludes:

- a generic ECDSA MPC framework
- a generic wallet derivation framework
- the old two-key EVM model
- export-capable output during normal signing

## Settled Byte-Level Items

The implementation pass should use the framed digest and transcript formats in
this document and in
[docs/plans/true-server-blindness.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/docs/plans/true-server-blindness.md).

Remaining implementation choices are limited to concrete Rust names, storage
column names, and transport serialization wrappers. Those choices must preserve
the field order, domain labels, and rejection rules above.

The lifecycle, role-local share contract, and single-key invariant in this
document are the design source of truth.

## Related Docs

- Security model:
  [security.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/security.md)
- Export semantics:
  [export.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/export.md)
- Integration shape:
  [integration-cait-sith-backend.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/integration-cait-sith-backend.md)
