# Security Model

Removal note: the old Router A/B ECDSA derivation context version and its crate APIs were removed
after v3 invalidation. The active crate surface receives only an opaque
SDK-owned `application_binding_digest` plus fixed protocol constants for
role-local derivation.

This file is the security-focused entrypoint for
[crates/router-ab-ecdsa-derivation](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation).
Protocol shape and lifecycle live in
[specs/protocol.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/specs/protocol.md).

The target `router-ab-ecdsa-derivation` design uses role-local additive derivation:

```text
x_client = H_scalar("router-ab-ecdsa-derivation:client-share", context, y_client)
x_relayer = H_scalar("router-ab-ecdsa-derivation:relayer-share", context, y_relayer)
x = x_client + x_relayer mod n
X = x_clientG + x_relayerG
```

The server derives and stores only its relayer share. The client reconstructs
canonical `x` only during explicit export.

## Threat Model

Two parties participate in the lifecycle:

- client
- server / relayer

The main product requirements are:

- export and threshold signing refer to the same logical key
- the live server process never learns canonical `x`
- non-export client flows never learn `x_relayer`
- explicit export releases `x_relayer` only to the authorized client export
  runtime

## Core Security Goals

### 1. Single-Key Invariant

There must be exactly one canonical EVM private key per account under this
protocol.

That means:

```text
x_export = x_client + x_relayer_export mod n
x_export * G == threshold signing public key
ethereum_address(x_export * G) == threshold signing address
```

If export and threshold signing use different public keys or addresses, the
protocol has failed.

### 2. Server-Blindness

The live server process must never learn canonical `x`, even when it:

- participates in key setup
- participates in threshold signing
- participates in export preparation

The server may hold:

- its own local derivation input
- `x_relayer`
- relayer public key
- threshold public key
- threshold Ethereum address
- accepted public transcript and audit metadata

The server must reject and must not retain:

- plaintext canonical `x`
- `x_client`
- client root material
- an export-capable reconstruction of `x`

Hard invariant: no production server request path may combine client-owned
secret input with server-owned secret input in a way that reconstructs
canonical `x`.

### 3. Client Non-Export Privacy

During registration, session bootstrap, and non-export signing, the client may
hold:

- its own local derivation input
- `x_client`
- client public key
- relayer public key
- threshold public key
- threshold Ethereum address
- accepted public transcript and local audit metadata

The client must not receive `x_relayer` outside an explicit export envelope.

### 4. Standard EVM Compatibility

The signing output must remain standard secp256k1 ECDSA compatible for:

- Ethereum transaction signing
- public-key recovery
- standard RPC and wallet tooling

### 5. Explicit Export Policy

Export must be:

- explicit
- policy-bound
- transcript-bound
- auditable

Signing flows must never produce export-capable output.

## Role-Local Boundary

The target boundary is:

- non-export server flows accept only server-owned secret inputs plus public
  client commitments
- non-export server flows retain only relayer-owned share state plus public
  identity
- non-export client flows retain only client-owned share state plus public
  identity
- export flows release only an export-authorized relayer share envelope
- client export runtime reconstructs `x` and verifies it against public key `X`

This is the hard security property for the Rust rewrite:

```text
No live server path can reconstruct canonical x.
```

Reference-only fixture code may reconstruct `x` for algebraic tests. Production
server code must not contain that path.

## Retained-State Rule

The retained-state rule is:

- after role-local derivation, raw root material is dropped as early as possible
- server state advances from `x_relayer` and public identity
- client state advances from `x_client` and public identity
- failed export, signing, presign, or retry sessions burn their role-local
  session state

Server retained state must exclude:

- client root material
- `x_client`
- canonical `x`

Client non-export retained state must exclude:

- server root material
- `x_relayer`

Explicit export is the only allowed client-side `x_relayer` disclosure path.

## Public Transcript Binding

Every active protocol transcript must bind:

- context binding
- client public key
- relayer public key
- threshold public key
- threshold Ethereum address
- operation kind
- transcript digest

Explicit export additionally requires an authorization witness bound to the
same public identity and context. A mismatch in public identity or context must
prevent export reconstruction and non-export signing composition.

## Edge-Case And Validation Rules

Zero canonical key handling:

- `x_client` and `x_relayer` are each non-zero by construction
- `x_client + x_relayer == 0 mod n` is still possible with negligible
  probability
- the server must retry relayer derivation if `X_client + X_relayer` is the
  identity point
- the accepted relayer retry counter is public, persisted, and transcript-bound
- clients reject identity threshold public keys and retry-counter mismatches

Public key validation:

- all remote compressed public keys must be exactly 33-byte SEC1 compressed
  secp256k1 keys
- accepted prefixes are `0x02` and `0x03`
- keys must decompress to valid non-identity curve points
- canonical compressed re-encoding must equal the received bytes
- public identity composition fails closed if `X_client + X_relayer` is the
  identity point

Relayer key rotation:

- retained server state is bound to `relayer_key_id`
- mismatched relayer key id rejects bootstrap, signing, presign, and export
  requests
- relayer key rotation requires new role-local Router A/B ECDSA derivation bootstrap
- stale triples, presignatures, export authorizations, and export nonces are
  invalid across relayer key rotation

Export authorization freshness:

- each export request uses a fresh `export_request_nonce32`
- the relayer atomically records the nonce before releasing `x_relayer`
- replayed nonces are rejected for successful and failed export attempts
- nonce storage is keyed by wallet session user id, ECDSA threshold key id,
  relayer key id, and nonce
- nonce storage contains no secret scalar material

WASM API separation:

- browser WASM exposes client derivation, client public-identity verification,
  client Cait-Sith share mapping, export authorization, and export
  reconstruction
- browser WASM does not expose relayer derivation or relayer export-share
  release
- server/native bindings expose relayer operations and omit client export
  reconstruction

Reference helper gating:

- full-key reconstruction helpers are available only to tests, benches,
  fixtures, or fixture-emitter binaries
- production server/client modules do not import reference helpers
- reference helpers are absent from public production exports

## Main Security Risks

### Risk 1: Recreating The Two-Key Model

If threshold signing and export use separate derivation lanes, the crate
recreates the old EVM safety issue.

Mitigation:

- define the single-key invariant in specs
- test public-key and address equivalence everywhere
- reject any design that preserves separate signing and export keys

### Risk 2: Server-Blindness Drift

Convenience APIs can accidentally accept both client-owned and server-owned
secret inputs in one process.

Mitigation:

- production server APIs accept only relayer-owned secret input
- client-owned secret fields are absent from server request types
- Verus and tests fail if server-visible state gains client-owned secrets or
  canonical `x`

### Risk 3: Export-Authorization Drift

Export can become unsafe if retries, aborts, or stale envelopes reuse failed
state.

Mitigation:

- bind export authorization to the public transcript
- burn failed export sessions
- require fresh export state for retry
- store and reject reused export nonces
- bind export authorization to relayer key id and authenticated client session
- audit export separately from signing

### Risk 4: Backend-Mismatch Drift

The threshold ECDSA backend must represent the same logical key as the exported
scalar.

Mitigation:

- map role-local additive shares into backend shares with fixed participant IDs
  `{1, 2}`
- prove and test `backend_public_key == X`
- preserve `X` and address if resharing is introduced

## Current Implementation Review Findings

The current crate has been reviewed against its runtime boundary and core
cryptographic helpers. These findings remain relevant during the role-local
rewrite.

### Finding 1: Secret-dependent big-integer arithmetic

The original reference implementation used `BigUint` in canonical-scalar
reduction, additive-share derivation, and 2P backend-share mapping.

Why it mattered:

- `BigUint` arithmetic is variable-time
- secret-derived comparisons and modular operations widened the timing/cache
  exposure surface
- the backend-share mapper used variable-time exponentiation to compute the
  inverse Lagrange coefficient

Implemented mitigation:

- reduced secret scalar arithmetic now uses fixed-width `k256` secp256k1 scalar
  types
- the 2P backend-share mapper now uses constant-time scalar inversion and
  multiplication on `k256` scalars
- canonical-scalar reduction now uses `k256` wide reduction

### Finding 2: Boundary helpers trusted response tuples too much

The original integration helpers accepted `RespondResponseV1` values after only
finalize-envelope validation, then reused supplied key/share fields without
recomputing cryptographic relationships between them.

Why it mattered:

- malformed responses could carry inconsistent secret/public tuples across the
  client/server seam
- explicit export checked some public identity fields without fully tying the
  client-reconstructed export scalar to the expected public key and address

Implemented mitigation:

- the integration boundary now recomputes and verifies:
  - `pub(x_client32) == client_public_key33`
  - `pub(x_relayer32) == relayer_public_key33`
  - `pub(x_client32) + pub(x_relayer32) == threshold_public_key33`
  - `addr(threshold_public_key33) == threshold_ethereum_address20`
  - `pub(x_export32) == threshold_public_key33`
  - `addr(threshold_public_key33) == threshold_ethereum_address20`
- the client-output threshold identity is checked against retained server
  identity

### Finding 3: Secret-bearing structs were not zeroized

The original reference flow kept canonical secrets, additive shares, export
objects, bootstrap material, and retained relayer shares in ordinary arrays and
vectors without drop-time zeroization.

Why it mattered:

- secret material remained in heap/stack allocations longer than necessary
- intermediate staging objects widened the memory exposure window

Implemented mitigation:

- secret-bearing structs in the wire, client, server, shared derivation, and
  integration layers now zeroize on drop
- `signer-core` now zeroizes sensitive HKDF output buffers used during
  secp256k1 key/share derivation

## Intended Verification Targets

The highest-priority proof/audit targets are:

- exported private key public key equals threshold signing public key
- exported private key address equals threshold signing address
- server never learns canonical `x`
- non-export signing flows never expose export-capable output
- retained state does not preserve forbidden root material past the accepted
  boundary
- mismatched public identity or context prevents signing and export composition

## Current FV Status

Completed:

- Verus stable slice for:
  - `encode_context_v1`
  - canonical `x` derivation shape and scalar-domain theorems
  - additive-share reconstruction and non-zero-share theorems
  - fixed `{1, 2}` backend share-mapping seam
  - output-policy boundary
  - finalized retained-state exclusion shape
- Aeneas + Lean boundary bridge for the frozen server-visible staged boundary
- Lean privacy theorems for the same frozen server-visible staged boundary
- widened Lean privacy theorems over paired full execution states and explicit
  secret-reconstruction-style client/server view models
- Lean true-blind model for role-local client/server shares, explicit export,
  public transcript binding, and signing-session identity/context binding
- Verus mirror for the settled true-blind boundary contract, including active
  wire forbidden-field exclusion and explicit-export-only relayer share release

Important caveat:

- the current Verus slice still uses explicit trusted axioms at a few
  production-boundary seams:
  - scalar reduction
  - retry/share selection and relayer-share construction
  - the production 2P mapper
  - the tie from backend group public key derivation to the effective group
    secret

Remaining verification work:

- extend Verus from the boundary mirror into role-local derivation and
  public-key addition
- add production anti-drift checks for role-local server/client types
- extract the implemented Rust boundary with Aeneas
- bridge the generated boundary back to the Lean true-blind model

Still intentionally out of scope:

- hidden-eval compiler semantics
- richer runtime orchestration or transport privacy claims
- backend-general proofs beyond the fixed `{1, 2}` seam

## Related Docs

- Protocol shape:
  [specs/protocol.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/specs/protocol.md)
- Export semantics:
  [specs/export.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/specs/export.md)
- Integration with the current backend:
  [specs/integration-cait-sith-backend.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/specs/integration-cait-sith-backend.md)
- Implementation plan:
  [docs/plans/implementation-plan.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/docs/plans/implementation-plan.md)
- Share-derivation design memo:
  [docs/plans/share-derivation-design-memo.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/docs/plans/share-derivation-design-memo.md)


