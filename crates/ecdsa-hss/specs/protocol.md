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

The fixed context binding tuple is:

- `scheme_id = "ecdsa-hss-v1"`
- `curve = "secp256k1"`
- `wallet_session_user_id`
- `subject_id`
- `key_scope = "evm-family"`
- `ecdsa_threshold_key_id`
- `signing_root_id`
- `signing_root_version`
- `key_purpose`
- `key_version`
- `participant_ids = [1, 2]`

This context is part of deterministic role-local derivation. Changing any field
except the concrete EVM chain target changes the derived key.

Funds-safety invariant: every EVM-class target for the same wallet, subject,
RP, signing root, and key version must derive the same threshold ECDSA public
key and Ethereum address. The fixed `key_scope = "evm-family"` field is the
stable EVM-family key scope. Concrete chain targets stay out of the stable key
context. Cross-chain replay protection belongs to EVM transaction chain IDs and
typed-data domain separation.

## `encode_context_v1` Byte Contract

`encode_context_v1` is frozen for the current context format.

The byte encoding is:

- ASCII domain tag: `b"ecdsa-hss:context:v1"`
- followed by the fixed tuple fields in this exact order:
  1. `scheme_id`
  2. `curve`
  3. `wallet_session_user_id`
  4. `subject_id`
  5. `key_scope`
  6. `ecdsa_threshold_key_id`
  7. `signing_root_id`
  8. `signing_root_version`
  9. `key_purpose`
  10. `key_version`
  11. `participant_ids`

### String Encoding

The string fields are:

- `scheme_id`
- `curve`
- `wallet_session_user_id`
- `subject_id`
- `key_scope`
- `ecdsa_threshold_key_id`
- `signing_root_id`
- `signing_root_version`
- `key_purpose`
- `key_version`

Each string field is encoded as:

- `u16be(length_in_bytes)`
- raw ASCII bytes

Validation rules:

- all string fields must be non-empty
- all string fields must be ASCII-only
- Unicode normalization is forbidden
- non-ASCII input is invalid

This is intentionally strict so Rust, TypeScript, and native runtimes generate
exactly the same vectors.

### Participant ID Encoding

The participant IDs are fixed to `[1, 2]`.

They are encoded as:

- `u8(count)`
- `count` participant IDs as `u16be`

The participant-id bytes are always:

- `0x02 || 0x0001 || 0x0002`

### Full Layout

The full `encode_context_v1(...)` byte layout is:

- `b"ecdsa-hss:context:v1"`
- `u16be(len("ecdsa-hss-v1")) || b"ecdsa-hss-v1"`
- `u16be(len("secp256k1")) || b"secp256k1"`
- `u16be(len(wallet_session_user_id)) || wallet_session_user_id_ascii_bytes`
- `u16be(len(subject_id)) || subject_id_ascii_bytes`
- `u16be(len(key_scope)) || key_scope_ascii_bytes`
- `u16be(len(ecdsa_threshold_key_id)) || ecdsa_threshold_key_id_ascii_bytes`
- `u16be(len(signing_root_id)) || signing_root_id_ascii_bytes`
- `u16be(len(signing_root_version)) || signing_root_version_ascii_bytes`
- `u16be(len(key_purpose)) || key_purpose_ascii_bytes`
- `u16be(len(key_version)) || key_version_ascii_bytes`
- `0x02 || 0x0001 || 0x0002`

There is:

- no JSON layer
- no key sorting
- no locale dependence
- no platform-specific text normalization

## Role-Local Share Derivation

Define:

```text
H_scalar(domain, context, input) =
  1 + (BE512(SHA-512(domain || context || input)) mod (n - 1))
```

The production share derivation is:

```text
context = encode_context_v1(...)
x_client = H_scalar("ecdsa-hss:client-share", context, y_client)
x_relayer = H_scalar("ecdsa-hss:relayer-share", context, y_relayer)
```

This guarantees each role-local share is a valid non-zero secp256k1 scalar.

The public identity is derived without reconstructing `x`:

```text
X_client = x_client * G
X_relayer = x_relayer * G
X = X_client + X_relayer
address = ethereum_address(X)
```

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

The current committed fixture corpus covers the existing fixed-function slice:

- [fixtures/phase1_v1.json](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/fixtures/phase1_v1.json)

Before the Rust role-local implementation lands, generate a new role-local
fixture corpus covering:

- `y_client`
- `y_relayer`
- `context`
- `encode_context_v1(context)` bytes
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

## Non-Goals

This protocol excludes:

- a generic ECDSA MPC framework
- a generic wallet derivation framework
- the old two-key EVM model
- export-capable output during normal signing

## Open Byte-Level Items

These items remain for the implementation pass:

- exact wire payload encoding
- exact retained-state serialization format
- exact context-binding digest function used in public transcripts
- exact export-authorization digest format

The lifecycle, role-local share contract, and single-key invariant in this
document are the design source of truth.

## Related Docs

- Security model:
  [security.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/security.md)
- Export semantics:
  [export.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/export.md)
- Integration shape:
  [integration-near-threshold.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/integration-near-threshold.md)
