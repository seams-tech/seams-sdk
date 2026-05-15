# Protocol Spec

This document defines the current working protocol shape for `ecdsa-hss`.

It freezes the current reference lifecycle and invariants for the first
implementation pass, but it does not yet freeze every byte-level wire
encoding.

## Purpose

`ecdsa-hss` exists to produce one canonical secp256k1 key for EVM use that is:

- threshold-signable
- exportable
- deterministic
- server-blind

The protocol must not preserve a separate threshold-signing key and export key.

## Parties

- client
- server / relayer

## Canonical Key Object

The current working v1 spec chooses:

- canonical export object: secp256k1 private scalar `x`

This means the protocol's canonical key identity is:

- `x`
- public key `X = x * G`
- Ethereum address derived from `X`

## Fixed v1 Input Domain

The fixed-function input domain for v1 is:

- `y_client`: 32-byte little-endian integer
- `y_relayer`: 32-byte little-endian integer

Those values are interpreted modulo `2^256` for the fixed hidden derivation
step.

The fixed v1 context binding tuple is:

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

This context is part of deterministic derivation. Changing it changes the
derived key.

Funds-safety invariant: every EVM-class target for the same wallet, subject,
RP, signing root, and key version MUST derive the same threshold ECDSA public
key and Ethereum address. The fixed `key_scope = "evm-family"` field is the
stable EVM-family key scope. Concrete chain targets must stay out of the stable
key context.

## `encode_context_v1` Byte Contract

`encode_context_v1` is now frozen for v1.

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

The v1 string fields are:

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
- followed by raw ASCII bytes

v1 validation rules:

- all string fields must be non-empty
- all string fields must be ASCII-only
- no Unicode normalization is performed
- non-ASCII input is invalid for v1

This is intentionally strict so Rust, TypeScript, and future native runtimes
can generate exactly the same vectors.

### Participant ID Encoding

For v1, `participant_ids` is fixed to `[1, 2]`.

It is encoded as:

- `u8(count)`
- followed by `count` participant IDs as `u16be`

So the participant-id bytes are always:

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

## Canonical `x` Derivation Contract

The working v1 canonical-key derivation is:

1. `m = y_client + y_relayer mod 2^256`
2. `d = LE32(m)`
3. `context = encode_context_v1(...)`
4. `h_x = SHA-512("ecdsa-hss:v1:canonical-x" || context || d)`
5. `x = 1 + (BE512(h_x) mod (n - 1))`

Where:

- `n` is the secp256k1 group order
- `BE512(h_x)` interprets the 64-byte SHA-512 digest as a big-endian integer

This construction is the current working v1 contract because it guarantees:

- deterministic derivation
- domain separation from other protocol uses of `d`
- `x` is always a valid non-zero secp256k1 scalar

This contract is now the Phase 1 fixed-function target for fixtures and
reference vectors.

## Single-Key Invariant

The protocol is correct only if all three are the same logical key:

1. the exported private key
2. the threshold signing public key
3. the Ethereum address used for threshold signing

In shorthand:

- export returns `x`
- threshold signing public key must equal `x * G`
- threshold signing address must equal `addr(x * G)`

## Operations

The working protocol defines four logical operation classes:

### 1. RegistrationBootstrap

Purpose:

- derive canonical hidden key material for a newly registered account
- derive threshold signing shares from that same canonical key

Output policy:

- must not return canonical `x`

### 2. SessionBootstrap

Purpose:

- restore or reconnect the threshold-signing session using the canonical-key
  model

Output policy:

- must not return canonical `x`

### 3. NonExportSign

Purpose:

- produce threshold ECDSA signatures using shares derived from canonical `x`

Output policy:

- must not return canonical `x`
- must not return export-capable material

### 4. ExplicitKeyExport

Purpose:

- intentionally disclose canonical `x` to the client

Output policy:

- may return canonical `x`
- must be explicit and policy-bound

## High-Level Lifecycle

The working lifecycle is:

1. Client and server contribute root-share material.
2. `ecdsa-hss` derives one canonical hidden secp256k1 secret `x`.
3. `ecdsa-hss` derives threshold signing share material from that same `x`.
4. The threshold ECDSA backend signs using shares derived from `x`.
5. Explicit export returns `x`.

The intended v1 path is:

- direct additive-share derivation from canonical `x`
- reuse of the current threshold ECDSA backend through the existing additive
  share mapping layer

The fallback path is:

- public-key-preserving resharing into the current backend if direct additive
  shares are insufficient

## Fixed v1 Scope

The first implementation pass is intentionally narrower than generic threshold
ECDSA.

v1 scope is:

- fixed 2-of-2 only
- fixed participant IDs:
  - client = `1`
  - relayer = `2`
- integration through the existing 2-party additive-share mapping layer

Out of scope for v1:

- generalized `t-of-n`
- alternate participant-ID layouts
- a second share-mapping implementation path

## Share-Derivation Working Model

The working v1 model is:

- derive additive 2-party shares `x_client` and `x_relayer`
- enforce:
  - `x = x_client + x_relayer mod n`
- adapt those shares into the current threshold ECDSA backend

The material split is also fixed for v1:

- export-capable material:
  - canonical secp256k1 scalar `x`
- threshold-signing-only material:
  - `x_client`
  - `x_relayer`
  - mapped backend shares derived from `x_client` / `x_relayer`
  - threshold public key
  - threshold Ethereum address

This document treats that as the intended implementation target.

If that path fails backend compatibility review, the protocol will be revised
to include a resharing layer while preserving the same public key.

## Frozen v1 Additive-Share Contract

The direct additive-share path is now frozen as the working v1 target.

The share-derivation function is:

- `derive_additive_shares_v1(x, context) -> (x_client, x_relayer, retry_counter)`

with the following deterministic algorithm:

1. `x_bytes = BE32(x)`
2. for `counter = 0, 1, 2, ...`:
   - `h_share = SHA-512("ecdsa-hss:v1:additive-share:client" || context || BE32(counter) || x_bytes)`
   - `candidate = 1 + (BE512(h_share) mod (n - 1))`
   - if `candidate == x`, continue
   - otherwise accept:
     - `x_client = candidate`
     - `x_relayer = (x - x_client) mod n`
     - return `(x_client, x_relayer, counter)`

This contract guarantees:

- `x = x_client + x_relayer mod n`
- `x_client` is a valid non-zero secp256k1 scalar
- `x_relayer` is a valid non-zero secp256k1 scalar
- derivation is deterministic for the same canonical `x` and context
- derivation is domain-separated from canonical-`x` derivation

The only rejection condition is:

- `candidate == x`

That condition is required because otherwise `x_relayer` would be zero, and the
current additive-share mapping layer rejects zero/out-of-range shares.

## Share-Derivation Readiness Gate

The direct additive-share path is not ready for implementation until the share
derivation contract is frozen more precisely than "derive additive shares from
`x`."

Before Phase 2 or Phase 3 begins, the implementation must produce fixtures and
reference vectors for the frozen contracts above, including:

- `y_client`
- `y_relayer`
- `context`
- `encode_context_v1(context)` bytes
- `d`
- canonical `x`
- compressed public key
- Ethereum address
- `retry_counter`
- `x_client`
- `x_relayer`
- mapped backend shares for participant IDs `{1, 2}`

This vector corpus is mandatory because the current additive-share mapping layer
rejects zero or out-of-range shares, and the one-key invariant depends on exact
cross-runtime agreement.

Current published fixture corpus:

- [fixtures/protocol-v1.json](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/fixtures/protocol-v1.json)

## Boundary Model

The protocol should follow the same boundary discipline that worked in
`ed25519-hss`:

- explicit staged server-owned execution
- early dropping of raw root-share material
- no joined-input legacy seam
- no export-capable output in non-export operations

The exact prepare/respond/finalize wire shape will be frozen once the first
implementation lands. The lifecycle and output rules above are already part of
the intended spec.

## Required Equivalence Checks

The implementation must be able to check all of:

- exported `x` derives the expected public key
- exported `x` derives the expected Ethereum address
- threshold signing public key equals the public key derived from exported `x`
- threshold signing address equals the address derived from exported `x`

These are not optional tests. They are the main protocol identity checks.

## Non-Goals

This protocol does not aim to:

- define a generic ECDSA MPC framework
- define a generic wallet derivation framework
- preserve the current two-key EVM model
- expose export-capable output during normal signing

## Open Byte-Level Items

These items are intentionally left for the first implementation pass:

- exact wire payload encoding
- exact retained-state serialization format

Those are implementation-level details still to be frozen. The lifecycle and
single-key invariant in this document are already the design source of truth.

## Related Docs

- Security model:
  [security.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/security.md)
- Export semantics:
  [export.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/export.md)
- Integration shape:
  [integration-near-threshold.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/integration-near-threshold.md)
