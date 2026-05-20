# True Server-Blindness Plan

This plan updates
[crates/ecdsa-hss](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss)
so ECDSA HSS enforces true server blindness for non-export flows and explicit
export.

The current security issue is in the ECDSA HSS derivation boundary: the
crate-local reference path can combine client root input with relayer root input,
derive canonical `x`, derive both additive shares, and return/retain role
outputs. That shape is useful for fixtures and review, but it is too powerful
for the production server boundary.

The target property is:

- the server never receives client root material in plaintext
- the server never learns canonical secp256k1 scalar `x`
- the server never learns `x_client`
- the server learns only `x_relayer` plus public verification data
- the client never receives server root material in plaintext
- the client never learns `x_relayer` during non-export flows
- explicit export delivers export-capable material to the authorized client
  without the server computing canonical `x`
- threshold signing and export still refer to the same EVM address

Existing ECDSA HSS accounts and IndexedDB state can be wiped. The implementation
should replace the active protocol shape directly, delete superseded v1 paths,
and avoid compatibility branches.

## Current Starting Point

Relevant existing material:

- active protocol spec:
  [specs/protocol.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/protocol.md)
- security model:
  [security.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/security.md)
- export semantics:
  [specs/export.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/export.md)
- threshold backend integration:
  [specs/integration-cait-sith-backend.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/integration-cait-sith-backend.md)
- formal verification area:
  [formal-verification](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification)
- current native benchmark:
  [benches/performance_baseline.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/benches/performance_baseline.rs)

## Replacement Design

Use role-local additive derivation as the production design:

```text
x_client = H_scalar("ecdsa-hss:client-share", context, y_client)
x_relayer = H_scalar("ecdsa-hss:relayer-share", context, y_relayer)
x = x_client + x_relayer mod n
X = xG = x_clientG + x_relayerG
address = ethereum_address(X)
```

The client derives `x_client` locally. The server derives `x_relayer` locally.
Neither side derives canonical `x` during non-export ceremonies.

For explicit export:

```text
server_export_share = x_relayer
client_export_key = x_client + server_export_share mod n
```

The server export share must be policy-gated, transcript-bound, auditable, and
encrypted or otherwise delivered only to the authorized client export runtime.
The client verifies:

```text
client_export_key * G == X
ethereum_address(X) == expected_address
```

The Cait-Sith signing input remains:

```text
x = x_client + x_relayer mod n
```

Each party maps only its own additive share into the
`threshold-signatures`/Cait-Sith participant-share format.

## Performance Scope

True server blindness should affect ECDSA HSS setup, session bootstrap, recovery,
and explicit export. It should leave the Cait-Sith presign/sign protocol in the
same cost class because the final threshold key is still a two-party additive
secp256k1 key.

Measure overhead in:

- registration bootstrap
- session bootstrap
- Email OTP recovery/bootstrap
- explicit export
- first presign after bootstrap
- normal presign/sign with persisted shares

The main performance budget is:

- keep HSS derivation sub-millisecond in native Rust
- avoid adding network round trips to normal signing
- avoid adding browser WASM role code for server-only derivation
- avoid changing Cait-Sith triple/presign/sign cost
- keep export overhead isolated to explicit export

## MVP Priority

Ship the role-local boundary first. The MVP is complete when production Rust can
bootstrap, sign, and explicitly export using one active protocol shape where the
server never combines both role roots or reconstructs canonical `x`.

MVP work:

1. Replace joined-root derivation with role-local client and relayer derivation.
2. Replace wire/server/client retained state so each role stores only its own
   secret share plus public verification data.
3. Bind context, public identity, relayer key id, retry counters, and explicit
   export authorization into stable framed digests.
4. Validate public keys and handle the zero canonical key case through relayer
   retry and transcript binding.
5. Reconstruct export keys only in the authorized client export runtime.
6. Feed Cait-Sith from the role-local additive shares.
7. Add focused regression tests for algebra, forbidden fields, export
   reconstruction, relayer key mismatch, nonce freshness, and public key
   validation.

Formal verification scope for the MVP:

- keep the existing Lean model as the source proof of the role-local boundary
  property
- keep Verus focused on mirror claims that block forbidden fields, mismatched
  identities, and unauthorized export share release
- keep generated Aeneas extraction scoped to the role-local boundary facade
- avoid proving hash internals, ECDSA/Cait-Sith internals, logging policy,
  performance claims, and product packaging in this MVP phase

Post-MVP work:

- broaden golden vectors into a shared Rust/WASM/Verus/Lean corpus
- expand WASM bundle and FFI surface tests after bindings are touched
- add audit/log redaction and import-guard tests after the production module
  shape settles
- run the detailed benchmark matrix after correctness and boundary tests pass

## Phase 1: Lean Model First

Do proof work before changing production Rust.

- [x] Add the initial true-blind Lean scaffold:
  [TrueBlind.lean](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-privacy/EcdsaHssPrivacy/TrueBlind.lean).
- [x] Add scalar-addition and public-key agreement relations for the true-blind model.
- [x] Define `F_ecdsa_hss_true_blind` as the ideal functionality.
- [x] Freeze the new ideal functionality in Lean:
  `F_ecdsa_hss_true_blind`.
- [x] Model private inputs:
  `y_client`, `y_relayer`.
- [x] Model role-local derived shares:
  `x_client`, `x_relayer`.
- [x] Model public outputs:
  `X_client = x_clientG`, `X_relayer = x_relayerG`, `X = X_client + X_relayer`,
  and Ethereum address.
- [x] Model explicit export as a separate operation that releases
  `x_relayer` only to the authorized client export view.
- [x] Prove the additive identity:

  ```text
  X = (x_client + x_relayer)G
  X = x_clientG + x_relayerG
  ```

- [x] Prove the non-export server view excludes `y_client`, `x_client`, and
  canonical `x`.
- [x] Prove the non-export client view excludes `y_relayer` and `x_relayer`.
- [x] Prove explicit export gives the client enough material to reconstruct `x`
  and verify `xG == X`.
- [x] Prove export and threshold signing share the same public key `X`.
- [x] Add observable-only simulators for non-export and explicit-export views.
- [x] Add first non-export view-invariance theorems for client-secret and
  server-secret variation.
- [x] Add explicit derivation assumptions for client-share agreement,
  server-share agreement, and the secp256k1 additive public-key law.
- [x] Prove ideal-functionality well-formedness, export reconstruction, and
  shared-public-identity properties under those assumptions.
- [x] Add typed operation views for non-export and explicit export, with proved
  disclosure rules for export-only material.
- [x] Define allowed public transcript fields:
  context binding, public share commitments, public key `X`, address, operation,
  and transcript digests.
- [x] Define forbidden production fields in the server view:
  `y_client`, `x_client`, and canonical `x`.
- [x] Define forbidden production fields in the client non-export view:
  `y_relayer` and `x_relayer`.
- [x] Run the targeted Lean true-blind build:

  ```sh
  cd crates/ecdsa-hss/formal-verification/lean-privacy
  lake build EcdsaHssPrivacy.TrueBlindBoundary
  ```
- [x] Add the Lean role-local boundary contract:
  [TrueBlindBoundary.lean](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-privacy/EcdsaHssPrivacy/TrueBlindBoundary.lean).
- [x] Model client bootstrap wire, server bootstrap wire, role-local retained
  client/server state, explicit export wire, and client export reconstruction.
- [x] Prove those boundary shapes exclude forbidden root/share/canonical-secret
  payloads.
- [x] Prove client export reconstruction from the explicit export wire matches the
  ideal explicit-export client view and verifies against public key `X`.
- [x] Add an authorized explicit-export wire envelope with a transcript-bound
  authorization witness.
- [x] Prove only the explicit-export wire envelope can carry the relayer export
  share.
- [x] Prove every active wire envelope excludes client root/share material and
  canonical `x`.
- [x] Add a bound explicit-export session tying client retained state, export
  authorization, and export wire to the same public identity/context.
- [x] Prove bound-session reconstruction preserves the authorized public identity
  and matches the ideal explicit-export client view.
- [x] Add a bound role-local signing-session model tying retained client/server
  state to the same public identity/context.
- [x] Prove mismatched public identity or context prevents constructing a bound
  role-local signing session.
- [x] Prove state-derived role-local signing sessions reconstruct the same scalar
  and verify against public key `X`.
- [x] Add a digest-valid export authorization predicate for explicit export
  envelopes.
- [x] Prove state-created explicit export envelopes carry valid authorization
  digests.
- [x] Prove malformed authorization digests prevent valid explicit export
  envelopes.
- [x] Prove any valid role-local wire envelope carrying the relayer export share
  must be an authorized explicit-export wire.

## Phase 2: Boundary Contract

Turn the Lean model into a concrete implementation contract.

- [x] Update
  [formal-verification/docs/proof-inventory.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/docs/proof-inventory.md)
  with the true-blind proof targets.
- [x] Update
  [formal-verification/docs/implementation-plan.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/docs/implementation-plan.md)
  with the Lean-first order.
- [x] Update
  [specs/protocol.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/protocol.md)
  so the production protocol is defined by role-local additive derivation.
- [x] Update
  [specs/export.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/export.md)
  so export is client-side reconstruction from `x_client` and an export-authorized
  relayer share.
- [x] Update
  [security.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/security.md)
  with the hard invariant that the live server process cannot reconstruct
  canonical `x`.
- [x] Define one active role-local wire shape in Lean.
- [x] Define export authorization as transcript-bound in Lean.
- [x] Define the Lean same-identity/session-binding contract for explicit export.
- [x] Define the Lean same-identity/session-binding contract for non-export
  role-local signing.
- [x] Add an initial Verus mirror for the settled Lean boundary contract:
  [true_blind_boundary.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/verus/src/shared/true_blind_boundary.rs).
- [x] Prove Verus mirror claims for active wire forbidden-field exclusion,
  explicit-export authorization binding, explicit-export-only relayer-share
  release, and role-local signing-session identity/context binding.
- [x] Align the Verus context mirror and fixture parity tests with the fixed
  `evm-family` key scope used for EVM-family addresses.
- [x] Delete v1 request/response compatibility from production boundaries.
- [x] Define reference-only code paths for fixture generation and algebraic tests.

## Immediate Next Steps

- [x] Update protocol, export, and security docs to use the role-local
  derivation contract proved in Lean and mirrored in Verus.
- [x] Implement the MVP Rust boundary: role-local derivation, public identity
  composition, retained role state, explicit export reconstruction, and
  Cait-Sith share handoff.
- [x] Add the first MVP regression tests for algebra, forbidden fields, export
  reconstruction, public key validation, and role-local signing.
- [x] Add the remaining MVP regression tests for relayer key mismatch and nonce
  freshness when those request/persistence fields land.
- [x] Run the targeted crate tests and the existing Lean/Verus gates after the
  MVP Rust boundary compiles.
- [x] Disable the stale Aeneas extraction path after the role-local rewrite
  deleted the old production `server::reference_boundary` facade.
- [x] Add a non-production role-local extraction facade, then extend
  Verus/Aeneas/Lean bridges over that generated boundary.

Validation note at this pause point:

- `lake build EcdsaHssPrivacy.TrueBlindBoundary` passes for the Lean true-blind
  model and boundary contract.
- `lake build EcdsaHssPrivacy.Views` passes for the older privacy view module
  after Lean 4.28 proof cleanup.
- The generated boundary bridge now uses a non-production role-local extraction
  crate and maps the generated Aeneas types back into the handwritten boundary
  model.
- `just ecdsa-hss-fv-verus` and `just ecdsa-hss-fv-parity` pass for the
  formal-verification mirror.
- `just ecdsa-hss-fv` passes for the current default `ecdsa-hss` formal gate:
  Verus parity, Verus verification, Aeneas boundary extraction, and the Lean
  privacy workspace.
- `cargo test --manifest-path crates/ecdsa-hss/Cargo.toml` passes for the
  role-local MVP regression suite.
- `cargo check --manifest-path crates/ecdsa-hss/Cargo.toml --all-targets`
  passes.
- A manual constant-time review found no custom `%`, `/`, bigint arithmetic, or
  secret-dependent branches in the changed scalar derivation, export
  reconstruction, share mapping, or server authorization paths. The local
  scripted analyzer from the `constant-time-analysis` skill was unavailable in
  this workspace, so this remains a manual gate.

## Phase 3: Rust Implementation

After Lean proof obligations and the boundary contract are in place, update Rust.
This is the current pause point: the checklist below starts production Rust
changes and remains pending.

MVP implementation order:

1. Update
   [src/shared/derive.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/shared/derive.rs)
   with role-local client and relayer share derivation helpers:
   `derive_client_share`, `derive_relayer_share`, public identity composition,
   and client-side export reconstruction.
2. Update
   [src/wire/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/wire/mod.rs)
   so server request types carry public client commitments and transcript
   metadata instead of plaintext client root material.
3. Update
   [src/server/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/server/mod.rs)
   so `prepare` derives and retains only relayer-owned share state, and
   `respond` composes public identity without reconstructing canonical `x`.
4. Update
   [src/client/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/client/mod.rs)
   so non-export client output is produced from local client share state plus
   server public identity, and explicit export reconstructs `x` client-side.
5. Update
   [src/integration/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/integration/mod.rs)
   so Cait-Sith adapter construction receives role-local client material from
   the client side and relayer material from retained server state.
6. Delete production APIs that accept both role roots or canonical `x`.
7. Move any joined-root reconstruction that remains useful for fixture
   generation into reference-only fixture helpers after the MVP path passes.

### Phase 3 Implementation Contract

Use these Rust-facing contracts while replacing the current joined-root
implementation. Names may be adjusted to match local style, but the ownership
and construction rules should stay intact.

Settled decisions before Rust:

- Production replacement type names should omit `V1`/`V2` suffixes. Versioning
  belongs in domain labels, serialized `format_version` fields, and fixture
  names, not in active Rust type names.
- Keep the existing context semantics: `encode_context_v1` binds the fixed
  `evm-family` key scope instead of a chain-specific key scope. Cross-chain
  replay protection remains the caller's transaction/signature-domain
  responsibility.
- Use explicit framed byte encoders for every new digest. Do not concatenate
  variable-length fields without tags and lengths.
- Use SHA-512 only for hash-to-scalar input, then reduce with audited secp256k1
  scalar-field helpers. Use SHA-256 for 32-byte public transcript and
  authorization digests.
- Use constant-time scalar and equality helpers for secret-derived scalar work.
  Do not implement custom `%`, `/`, comparison, or early-exit equality over
  secret-derived scalar bytes.
- Treat export authorization digests as binding evidence, not bearer secrets.
  Product/server routes must still authenticate the user/session and verify
  policy state before releasing the relayer export share.
- Public SDK `chainTarget` stays for EVM lane selection, budgets, recovery
  lookup, transaction serialization, and signing policy. The HSS stable-key
  context should remove `chain_target` and keep only fixed
  `key_scope = "evm-family"`.
- Relayer key rotation follows the safer initial rule: relayer key id mismatch
  rejects, and rotation requires a new role-local HSS bootstrap.

Digest framing:

```text
frame(domain, fields...) =
  ascii(domain) ||
  field_count:u8 ||
  repeated field(tag:u8, len:u16be, value)

field(tag, value) = tag || len(value) || value
u32 fields are encoded big-endian
u64 timestamp fields are encoded big-endian
operation_kind is encoded as one byte:
  0x01 = RegistrationBootstrap
  0x02 = SessionBootstrap
  0x03 = NonExportSign
  0x04 = ExplicitKeyExport
```

Domain labels:

```text
context binding:
  "ecdsa-hss:role-local:v1:context-binding"

client role share:
  "ecdsa-hss:role-local:v1:client-share"

relayer role share:
  "ecdsa-hss:role-local:v1:relayer-share"

public transcript:
  "ecdsa-hss:role-local:v1:public-transcript"

export authorization:
  "ecdsa-hss:role-local:v1:export-authorization"

reference-only canonical reconstruction:
  "ecdsa-hss:role-local:v1:reference-canonical-x"
```

The `v1` marker here is domain separation for this new role-local construction.
It is not a compatibility switch and should not introduce alternate production
paths.

Context binding:

```text
context_bytes = encode_context_v1(context)
context_binding32 = SHA-256(frame(
  "ecdsa-hss:role-local:v1:context-binding",
  field(0x01, context_bytes)
))
```

Role-local hash-to-scalar:

```text
derive_role_share(role_label, context, y_role):
  context_bytes = encode_context_v1(context)
  context_binding32 = context_binding(context)
  retry_counter = 0

  loop:
    digest64 = SHA-512(frame(
      role_label,
      field(0x01, context_binding32),
      field(0x02, context_bytes),
      field(0x03, y_role_le32),
      field(0x04, retry_counter:u32be)
    ))
    x_role = reduce_digest_to_nonzero_secp256k1_scalar(digest64)
    if x_role is valid non-zero:
      return x_role, retry_counter
    retry_counter += 1
```

The retry counter is public, role-specific, and persisted. A retry should be
effectively unreachable in normal operation, but the transcript still needs to
bind it so fixtures, recovery, and formal checks agree.

Zero canonical key rule:

- after receiving `X_client`, the server computes `X = X_client + X_relayer`
- if `X` is the identity point, increment `relayer_retry_counter` and rederive
  `x_relayer`
- persist the accepted relayer retry counter
- bind both role retry counters into the public transcript
- client verification rejects identity `X` and retry-counter mismatches

Public transcript:

```text
public_transcript_digest32 = SHA-256(frame(
  "ecdsa-hss:role-local:v1:public-transcript",
  field(0x01, context_binding32),
  field(0x02, operation_kind:u8),
  field(0x03, client_public_key33),
  field(0x04, relayer_public_key33),
  field(0x05, threshold_public_key33),
  field(0x06, threshold_ethereum_address20),
  field(0x07, client_share_retry_counter:u32be),
  field(0x08, relayer_share_retry_counter:u32be)
))
```

Export policy binding:

```rust
struct ExportPolicyBinding {
    wallet_session_user_id: AsciiString,
    ecdsa_threshold_key_id: AsciiString,
    client_device_id: AsciiString,
    client_session_id: AsciiString,
    relayer_key_id: AsciiString,
    export_request_nonce32: PublicBytes32,
    confirmation_digest32: PublicBytes32,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}
```

Export authorization digest:

```text
authorization_digest32 = SHA-256(frame(
  "ecdsa-hss:role-local:v1:export-authorization",
  field(0x01, export_public_transcript_digest32),
  field(0x02, context_binding32),
  field(0x03, client_public_key33),
  field(0x04, relayer_public_key33),
  field(0x05, threshold_public_key33),
  field(0x06, threshold_ethereum_address20),
  field(0x07, wallet_session_user_id),
  field(0x08, ecdsa_threshold_key_id),
  field(0x09, client_device_id),
  field(0x0a, client_session_id),
  field(0x0b, relayer_key_id),
  field(0x0c, export_request_nonce32),
  field(0x0d, confirmation_digest32),
  field(0x0e, issued_at_unix_ms:u64be),
  field(0x0f, expires_at_unix_ms:u64be)
))
```

Server export release requires all of the following:

- authenticated session identity equals `wallet_session_user_id`
- authenticated device/session equals `client_device_id` and
  `client_session_id`
- requested key equals `ecdsa_threshold_key_id`
- retained relayer key equals `relayer_key_id`
- operation kind is `ExplicitKeyExport`
- authorization has not expired
- nonce has not been used before
- authorization digest matches the server-recomputed digest

Export freshness storage:

- store used export nonces by `(wallet_session_user_id, ecdsa_threshold_key_id,
  relayer_key_id, export_request_nonce32)`
- atomically insert the nonce before releasing `x_relayer`
- consume the nonce for success and for failures that reach the relayer export
  endpoint
- retain nonce records for at least `expires_at_unix_ms + clock_skew`; first
  implementation should retain them for at least 24 hours
- require a fresh nonce after crashes, aborts, retry, or relayer-key rotation

Public key validation:

- remote public keys must be 33-byte SEC1 compressed secp256k1 keys
- accepted prefixes are `0x02` and `0x03`
- decompression must produce a valid non-identity affine point
- canonical compressed re-encoding must match the input bytes
- `X_client + X_relayer` must produce a valid non-identity threshold key

Module ownership:

- [src/shared/derive.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/shared/derive.rs)
  owns scalar derivation, public-key derivation, public identity composition,
  export reconstruction, and Cait-Sith share mapping helpers.
- [src/wire/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/wire/mod.rs)
  owns request/response shapes. Wire types should carry public commitments,
  transcript fields, operation kinds, and export authorization envelopes.
- [src/client/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/client/mod.rs)
  owns client-retained state, client bootstrap output, non-export client
  material, and explicit-export reconstruction.
- [src/server/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/server/mod.rs)
  owns relayer derivation, relayer-retained state, server public output, and
  export-share release.
- [src/integration/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/integration/mod.rs)
  owns Cait-Sith adapter construction from already-derived role-local material.
- [src/fixtures.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/fixtures.rs)
  and
  [src/bin/emit_fixture_json.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/bin/emit_fixture_json.rs)
  are the only acceptable homes for reference-only full-key reconstruction.

Target internal types:

```rust
struct ClientDerivationInput {
    context: EcdsaHssStableKeyContext,
    y_client32_le: SecretBytes32,
}

struct RelayerDerivationInput {
    context: EcdsaHssStableKeyContext,
    y_relayer32_le: SecretBytes32,
}

struct ClientShareMaterial {
    x_client32: SecretScalarBytes32,
    client_public_key33: PublicKey33,
    retry_counter: u32,
}

struct RelayerShareMaterial {
    x_relayer32: SecretScalarBytes32,
    relayer_public_key33: PublicKey33,
    retry_counter: u32,
}

struct PublicIdentity {
    context_binding32: PublicBytes32,
    client_public_key33: PublicKey33,
    relayer_public_key33: PublicKey33,
    threshold_public_key33: PublicKey33,
    threshold_ethereum_address20: EthereumAddress20,
}

struct RoleLocalClientState {
    client_share: ClientShareMaterial,
    public_identity: PublicIdentity,
    accepted_transcript: PublicTranscript,
}

struct RoleLocalServerState {
    relayer_share: RelayerShareMaterial,
    public_identity: PublicIdentity,
    accepted_transcript: PublicTranscript,
}

struct ExplicitExportAuthorization {
    public_identity: PublicIdentity,
    export_transcript: PublicTranscript,
    policy_binding: ExportPolicyBinding,
    authorization_digest32: PublicBytes32,
}

struct ExplicitExportRelayerShareEnvelope {
    authorization: ExplicitExportAuthorization,
    export_relayer_share32: SecretScalarBytes32,
    public_transcript: PublicTranscript,
}

struct ClientExportReconstruction {
    x_export32: SecretScalarBytes32,
    export_public_key33: PublicKey33,
    export_ethereum_address20: EthereumAddress20,
}
```

Secret-bearing types should implement zeroization on drop. Avoid deriving
`Debug` for secret newtypes unless the implementation redacts payloads. Public
types may derive `Debug`, `Clone`, `PartialEq`, and serialization traits if
needed at the boundary.

Secret-type trait rules:

- secret newtypes: `Zeroize`, `ZeroizeOnDrop`, constant-time equality when
  equality is needed, no `Serialize`, no unredacted `Debug`
- secret state structs: no `Copy`; `Clone` only where ownership transfer would
  otherwise force broad borrowing through async/server boundaries
- public identity/transcript structs: `Debug`, `Clone`, `PartialEq`, and
  serialization are acceptable
- conversion from raw bytes to domain types happens once at the request,
  persistence, WASM, or fixture boundary
- core functions accept domain types, not raw `[u8; 32]` bags

Audit/log redaction policy:

- allowed: event kind, operation kind, result, failure code,
  `wallet_session_user_id`, `subject_id`, `ecdsa_threshold_key_id`,
  `relayer_key_id`, client device/session id, context binding, public
  transcript digest, export authorization digest, public-key fingerprints,
  Ethereum address, timestamps, and expiry
- forbidden: `y_client`, `y_relayer`, `x_client`, `x_relayer`, canonical `x`,
  mapped backend threshold private shares, Cait-Sith triple/presign scalar
  material, and raw root-share material
- secret-bearing types should omit `Debug` or use redacted `Debug`

Construction rules:

- `ClientShareMaterial` is constructed only by client-role derivation.
- `RelayerShareMaterial` is constructed only by relayer-role derivation.
- `PublicIdentity` is constructed only after parsing and validating both public
  share keys.
- `RoleLocalServerState` must be impossible to construct with `y_client32_le`,
  `x_client32`, or canonical `x`.
- `RoleLocalClientState` must be impossible to construct with `y_relayer32_le`
  or `x_relayer32`.
- `ClientExportReconstruction` is constructed only by the explicit client export
  procedure.
- Server production APIs must never accept a struct containing both
  `y_client32_le` and `y_relayer32_le`.
- Functions that need canonical `x` belong in fixture/reference helpers or
  client explicit-export code.

Derivation procedures:

```text
derive_client_share(context, y_client):
  context_bytes = encode_context(context)
  x_client = hash_to_nonzero_scalar(
    label = "ecdsa-hss:role-local:v1:client-share",
    context_bytes,
    y_client
  )
  X_client = x_client * G
  return ClientShareMaterial(x_client, X_client)

derive_relayer_share(context, y_relayer):
  context_bytes = encode_context(context)
  x_relayer = hash_to_nonzero_scalar(
    label = "ecdsa-hss:role-local:v1:relayer-share",
    context_bytes,
    y_relayer
  )
  X_relayer = x_relayer * G
  return RelayerShareMaterial(x_relayer, X_relayer)

compose_public_identity(context, X_client, X_relayer):
  X = X_client + X_relayer
  address = ethereum_address(X)
  transcript = H(
    "ecdsa-hss:role-local:v1:public-transcript",
    context_binding,
    X_client,
    X_relayer,
    X,
    address
  )
  return PublicIdentity(context_binding, X_client, X_relayer, X, address)
```

Hash-to-scalar details:

- use domain-separated labels for client and relayer derivation
- reduce into the secp256k1 scalar field with the existing audited helper style
- reject or retry zero scalars with a transcript-bound retry counter
- include the retry counter in public transcript material when a retry occurs
- never derive the relayer share from canonical `x - x_client` in production
- never use wrapping integer addition for scalar addition; use field arithmetic
  modulo the secp256k1 group order

Cait-Sith mapping procedure:

```text
map_client_to_cait_sith_share(x_client):
  participant_id = THRESHOLD_SECP256K1_2P_CLIENT_PARTICIPANT_ID
  return map_additive_share_to_threshold_signatures_share_2p(
    x_client,
    participant_id
  )

map_relayer_to_cait_sith_share(x_relayer):
  participant_id = THRESHOLD_SECP256K1_2P_RELAYER_PARTICIPANT_ID
  return map_additive_share_to_threshold_signatures_share_2p(
    x_relayer,
    participant_id
  )
```

Mapping checks:

- `client_public_key33 == x_client * G`
- `relayer_public_key33 == x_relayer * G`
- `threshold_public_key33 == client_public_key33 + relayer_public_key33`
- `threshold_ethereum_address20 == ethereum_address(threshold_public_key33)`
- Cait-Sith participant IDs remain fixed as `{client=1, relayer=2}`

Explicit export procedure:

```text
authorize_export(client_state, requested_identity, policy_context):
  require requested_identity == client_state.public_identity
  require operation == ExplicitKeyExport
  authorization_digest = H(
    "ecdsa-hss:role-local:v1:export-authorization",
    requested_identity,
    export_transcript,
    policy_context
  )
  return ExplicitExportAuthorization(...)

server_export_share(server_state, authorization):
  require authorization.public_identity == server_state.public_identity
  require authorization.export_transcript.context == accepted context
  require authorization.export_transcript.operation == ExplicitKeyExport
  require authorization_digest == expected digest
  return ExplicitExportRelayerShareEnvelope(
    authorization,
    x_relayer,
    public_transcript
  )

client_reconstruct_export(client_state, envelope):
  require envelope.authorization.public_identity == client_state.public_identity
  x = x_client + envelope.export_relayer_share mod n
  X = x * G
  require X == client_state.public_identity.threshold_public_key33
  require ethereum_address(X) == client_state.public_identity.address
  return ClientExportReconstruction(x, X, address)
```

Session cleanup rules:

- failed bootstrap burns the staged role-local material for that ceremony
- failed export authorization burns the export envelope and retry state
- failed presign/sign burns the failed triple/presign state
- retrying a failed presign must allocate fresh triple/presign material
- no request path may reuse failed triple/presign state across public identity,
  context, wallet session, client device, or relayer key changes

Deletion targets:

- `RootShareInputsV1` as a production request shape
- `CanonicalSecretMaterialV1` from production modules
- `derive_canonical_secret_v1` from production modules
- `derive_additive_shares_v1(x32, context)` from production modules
- server `respond` paths that accept `y_client32_le`
- integration request types that accept both root inputs together
- client explicit-export outputs that receive `canonical_x32` from the server
- tests whose assertions preserve joined-root derivation behavior

Reference-only helpers may keep equivalent algorithms for fixtures if they live
outside production server code and are named as reference material.

Reference-only guardrails:

- place full-key reconstruction under a `reference` or `fixtures` module gated
  to tests, benches, or the fixture-emitter binary
- do not re-export reference helpers from [src/lib.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/lib.rs)
  as production API
- add a static import check or targeted test that server/client production
  modules do not import reference helpers
- name reference functions with `reference_` or `fixture_` prefixes
- keep the reference domain label distinct from production role labels

WASM API split:

- browser/client WASM exports only client-role functions:
  `derive_client_role_share`, `verify_role_local_public_identity`,
  `map_client_role_share_for_cait_sith`, `authorize_explicit_export`, and
  `reconstruct_explicit_export`
- server/native WASM or Rust exports relayer-role functions:
  `derive_relayer_role_share`, `compose_role_local_public_identity`,
  `map_relayer_role_share_for_cait_sith`, `authorize_relayer_export_share`, and
  `release_authorized_relayer_export_share`
- browser/client bundles must not export relayer derivation or relayer
  export-share release
- server bundles must not export client derivation or canonical export
  reconstruction

Persistence records:

```rust
struct PersistedClientRoleState {
    format_version: u8,
    context_binding32: PublicBytes32,
    ecdsa_threshold_key_id: AsciiString,
    client_share32: SecretScalarBytes32,
    client_public_key33: PublicKey33,
    relayer_public_key33: PublicKey33,
    threshold_public_key33: PublicKey33,
    threshold_ethereum_address20: EthereumAddress20,
    client_share_retry_counter: u32,
    relayer_share_retry_counter: u32,
    accepted_transcript_digest32: PublicBytes32,
}

struct PersistedRelayerRoleState {
    format_version: u8,
    context_binding32: PublicBytes32,
    ecdsa_threshold_key_id: AsciiString,
    relayer_key_id: AsciiString,
    relayer_share32: SecretScalarBytes32,
    relayer_public_key33: PublicKey33,
    client_public_key33: PublicKey33,
    threshold_public_key33: PublicKey33,
    threshold_ethereum_address20: EthereumAddress20,
    client_share_retry_counter: u32,
    relayer_share_retry_counter: u32,
    accepted_transcript_digest32: PublicBytes32,
}
```

Persisted relayer state must not contain client root/share material or canonical
`x`. Persisted client non-export state must not contain relayer root/share
material. Existing records can be wiped, so add no migration path beyond
request/persistence boundary rejection with a clear error.

Golden vector contract:

Create a minimal role-local fixture before wiring product callers. The MVP
fixture must include:

- named fixture id and `format_version`
- raw context fields and `encode_context_v1(context)` bytes
- `context_binding32`
- frame-encoded byte payloads for:
  - context binding
  - client hash-to-scalar
  - relayer hash-to-scalar
  - public transcript
  - export authorization
- `y_client32_le` and `y_relayer32_le`
- `x_client32_be`, `x_relayer32_be`, and role retry counters
- `client_public_key33`, `relayer_public_key33`,
  `threshold_public_key33`, and `threshold_ethereum_address20`
- mapped Cait-Sith participant shares for participant ids `{1, 2}`
- public transcript digest for each operation kind
- export policy binding fields and export authorization digest
- client-side `x_export32_be`, public key, and address for explicit export

Golden vector rules:

- include one happy-path bootstrap/sign/export vector in the MVP
- include one deterministic zero-canonical-key retry vector in the MVP only if
  the test hook is small and local to fixtures
- include invalid public-key cases in focused Rust tests first
- expand the corpus to Rust/WASM/fixture JSON/Verus/Lean parity after the MVP
  boundary is stable

Persistence transaction rules:

- role-local relayer state writes are atomic with public identity persistence
- accepted transcript digest, retry counters, and `relayer_key_id` are persisted
  in the same transaction as `x_relayer`
- export nonce insertion happens before relayer share release
- concurrent export requests for the same nonce race through a unique
  `(wallet_session_user_id, ecdsa_threshold_key_id, relayer_key_id,
  export_request_nonce32)` constraint
- relayer key rotation invalidates retained sessions, triples, presignatures,
  export authorizations, and export nonce acceptance atomically
- failed bootstrap/export/signing transactions must leave no partially accepted
  role-local state

Error code taxonomy:

Use stable, non-secret error codes at Rust, WASM, and product boundaries.
Error messages must not include secret bytes, raw shares, or private scalar
material. Start with the MVP set required by the new boundary:

```text
invalid_context
invalid_public_key
identity_threshold_public_key
context_mismatch
public_identity_mismatch
relayer_key_mismatch
export_nonce_replay
export_authorization_expired
export_authorization_digest_mismatch
export_policy_denied
secret_serialization_forbidden
```

Add the broader product-facing taxonomy after MVP integration requires it:

```text
operation_mismatch
export_authorization_not_yet_valid
stale_presign_state
stale_export_state
invalid_retry_counter
reference_helper_forbidden
wasm_api_role_violation
```

MVP implementation slice order:

1. Add domain types, framed byte encoders, the MVP error codes, and one
   happy-path fixture.
2. Implement context binding, role-local derivation, public-key validation, zero
   canonical key retry, and public identity composition.
3. Replace wire/server/client boundary types and retained-state persistence.
4. Implement export policy binding, nonce storage, relayer share release, and
   client export reconstruction.
5. Update Cait-Sith adapter construction to consume role-local shares.
6. Run algebraic, boundary, export, relayer-key, nonce, and public-key tests.
7. Run the existing Lean/Verus checks plus a focused constant-time review of
   scalar helpers.

Post-MVP slice order:

1. Expand fixture/golden vector coverage across Rust, WASM, Verus, and Lean.
2. Extend Aeneas/Lean bridges after the Rust boundary settles.
3. Add WASM split, reference-helper import, and audit/log redaction tests.
4. Run the full performance benchmark matrix.

FFI/WASM serialization:

Apply these rules when a touched Rust API crosses JSON, FFI, or WASM. Detailed
bundle-surface tests are post-MVP unless the MVP Rust change edits those
bindings directly.

- JSON/WASM byte fields use unpadded base64url strings
- fixed-size byte fields must decode to exactly 20, 32, or 33 bytes as named
- internal private scalar fields use 32-byte big-endian encoding
- role derivation inputs keep the explicit `*_le32` little-endian suffix
- public keys use 33-byte compressed SEC1 encoding
- Ethereum addresses use raw 20-byte bytes in FFI and `0x` hex only at display
  or wallet-import boundaries
- exported `x_export` may be rendered as `0x` hex only in the explicit export
  artifact/UI boundary
- decoders must reject padded base64, hex strings at internal FFI boundaries,
  wrong lengths, non-canonical public keys, and ambiguous scalar endianness

Constant-time validation gate:

- review scalar derivation, scalar addition, export reconstruction, share
  mapping, and secret comparisons for secret-dependent branches or variable-time
  operations
- run focused constant-time analysis on Rust crypto helpers after implementation
- inspect analyzer findings manually because public length/format checks can be
  false positives
- secret-derived scalar code must use audited `k256` scalar operations or
  existing signer-core helpers
- custom `%`, `/`, variable-time big integer arithmetic, and early-exit
  comparisons over secret-derived bytes are release blockers

- [x] Add role-local client/relayer share derivation helpers, public identity
  composition, and client-side explicit export reconstruction in
  [src/shared/derive.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/shared/derive.rs).
- [x] Replace canonical derivation from joined roots in
  [src/shared/derive.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/shared/derive.rs)
  with role-local additive share derivation.
- [x] Remove production APIs that accept both `y_client` and `y_relayer` in one
  process.
- [x] Replace
  [src/wire/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/wire/mod.rs)
  request types so the server never receives plaintext client root material.
- [x] Replace
  [src/client/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/client/mod.rs)
  transport outputs so non-export returns public verification data only while the
  client retains `x_client` locally.
- [x] Replace
  [src/server/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/server/mod.rs)
  retained state so it stores only `x_relayer`, `X_relayer`, shared public key
  `X`, address, and verification data.
- [x] Update
  [src/integration/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/integration/mod.rs)
  so Cait-Sith receives mapped shares derived from role-local additive shares.
- [x] Update explicit export so the server response carries a relayer export
  share payload instead of canonical `x`.
- [x] Move full-key reconstruction to the client export runtime.
- [x] Delete old fixtures tied to joined-root v1 derivation.
- [x] Regenerate fixtures for additive derivation.
- [ ] Update WASM bindings so browser code exposes only client-role derivation
  and export reconstruction.
- [ ] Update server bindings so server code exposes only relayer-role derivation
  and export-share authorization.

## Post-MVP Runtime Coverage Details

Use these stage contracts during follow-up benchmarking. During MVP
implementation, measure only if a regression is suspected or a touched path is
already covered by a cheap local benchmark.

### Stage 0: Context Binding

Purpose:

- normalize account, subject, chain target, key id, signing root, and key version
- derive a stable HSS context binding

Performance risks:

- repeated hashing and serialization on hot paths
- larger typed context payloads crossing client/server boundaries

Todo:

- [x] Measure context encoding and binding time.
- [x] Measure context payload size.
- [ ] Cache context binding within a ceremony.

### Stage 1: Client Share Derivation

Purpose:

- client derives `x_client`
- client derives public share `X_client`
- client prepares public verification payload

Performance risks:

- extra scalar validation and public-key derivation in browser WASM
- larger client bootstrap payload if proof metadata grows

Todo:

- [ ] Measure browser client-share derivation time.
- [x] Measure `X_client` verification payload size.
- [x] Assert no server-owned fields enter the client derivation API.

### Stage 2: Server Share Derivation

Purpose:

- server derives `x_relayer`
- server derives public share `X_relayer`
- server computes shared public key `X = X_client + X_relayer`

Performance risks:

- public-key addition repeated across bootstrap and resume flows
- server retained-state growth from transcript metadata

Todo:

- [x] Measure server share derivation time.
- [ ] Measure public-key addition time.
- [x] Measure retained server state size.
- [x] Assert no client root/share fields enter the server derivation API.

### Stage 3: Public Key And Address Verification

Purpose:

- verify `X = X_client + X_relayer`
- verify `address = ethereum_address(X)`
- bind `X` and address to the key id/session

Performance risks:

- repeated compressed public-key parsing
- repeated Ethereum address derivation

Todo:

- [x] Measure public-key parse/add/address derivation time as part of relayer
  identity derivation.
- [ ] Cache verified public identity per key id.
- [ ] Assert every persisted key record includes `X_client`, `X_relayer`, `X`,
  and address.

### Stage 4: Cait-Sith Share Mapping

Purpose:

- map `x_client` and `x_relayer` into the participant-share representation used
  by the threshold ECDSA backend
- preserve the same public key `X`

Performance risks:

- extra scalar conversions in browser/server WASM
- mapping checks repeated for every presign

Todo:

- [ ] Measure additive-share mapping time per role.
- [ ] Cache mapped participant share for persisted signing sessions.
- [x] Assert mapped shares reconstruct the same public key `X`.

### Stage 5: Non-Export Presign/Sign

Purpose:

- use the existing Cait-Sith/triples/presign/sign flow with role-local shares

Performance risks:

- accidental extra bootstrap before presign
- additional round trips before normal signing
- invalidating existing triple/presign caches after harmless metadata changes

Todo:

- [x] Measure first presign after bootstrap.
- [x] Measure normal presign/sign with persisted shares.
- [ ] Confirm round-trip count matches the current signing path.
- [ ] Confirm triple/presign behavior is unchanged by role-local HSS.

### Stage 6: Explicit Export

Purpose:

- authorize export
- release encrypted/export-bound relayer share to the client
- reconstruct canonical `x` client-side
- verify `xG == X`

Performance risks:

- adding export checks to non-export paths
- expensive client-side reconstruction or verification in browser WASM
- oversized export envelope

Todo:

- [x] Benchmark export separately from non-export flows.
- [x] Measure export envelope size.
- [ ] Measure client-side scalar addition and public-key verification time.
- [x] Assert server never returns `privateKeyHex` or canonical `x`.

## Phase 4: Rust Verification Bridge

After the Rust MVP rewrite, link implementation back to the proof artifacts.
Keep this phase focused on boundary preservation. The first bridge should prove
that implemented role-local state and wire types preserve the Lean model's
secret-exclusion and same-public-identity properties.

MVP verification hooks to add as the Rust functions land:

| Rust surface | Verification hook |
| --- | --- |
| `derive_client_share` | Verus scalar-domain and public-key agreement obligation: `client_public_key33 == x_clientG`. |
| `derive_relayer_share` | Verus scalar-domain and public-key agreement obligation: `relayer_public_key33 == x_relayerG`. |
| `compose_public_identity` | Verus/Aeneas public identity obligation: `X == X_client + X_relayer` and address binds to `X`. |
| `RoleLocalServerState` | Verus anti-drift predicate excluding `y_client`, `x_client`, and canonical `x`. |
| `RoleLocalClientState` | Verus anti-drift predicate excluding `y_relayer` and `x_relayer`. |
| `server_export_share` | Verus/Aeneas authorization predicate requiring explicit export, same public identity, same context, and valid digest. |
| `client_reconstruct_export` | Verus/Lean reconstruction obligation: `x_exportG == X` and `address(x_exportG) == expected_address`. |

Post-MVP verification hooks:

| Rust surface | Verification hook |
| --- | --- |
| Cait-Sith adapter construction | Algebraic obligation that mapped participant shares preserve the same threshold public key. |
| Framed digest helpers | Field-order and domain-label parity against committed vectors. |
| WASM/FFI encoding | Boundary parity against the Rust fixture corpus. |

Bridge procedure:

1. Extend Verus predicates for the implemented MVP Rust types first.
2. Extract only the implemented role-local boundary slice with Aeneas through
   the non-production `formal-verification/lean-boundary/rust-boundary` crate.
3. Keep the generated extraction small: public wire structs, retained role-local
   states, export authorization envelope, and public identity composition.
4. Write handwritten bridge lemmas from generated types into
   [TrueBlindBoundary.lean](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-privacy/EcdsaHssPrivacy/TrueBlindBoundary.lean).
5. Add anti-drift checks before broad proof work so accidental secret-field
   additions fail early.
6. Re-run the Lean target and Verus target after each extracted boundary change.

MVP checklist:

- [x] Add Verus anti-drift checks that fail if server production types gain
  client-owned secrets.
- [x] Add Verus anti-drift checks that fail if client non-export types gain
  server-owned secrets.
- [x] Update Verus specifications for role-local derivation, public-key addition,
  output type separation, forbidden-field absence, and export isolation.
- [x] Run focused constant-time validation on scalar derivation, scalar
  addition, export reconstruction, share mapping, and secret comparisons.
- [x] Run the formal verification gate:

  ```sh
  just ecdsa-hss-fv
  ```

Post-MVP checklist:

- [x] Disable the stale Aeneas extraction script and remove it from the default
  `ecdsa-hss` formal gate after deleting the old production extraction facade.
- [x] Add a non-production role-local extraction facade.
- [x] Run Aeneas extraction for the new visible boundary slice after the MVP API
  stabilizes and the facade exists.
- [x] Update generated Lean boundary artifacts under
  [formal-verification/lean-boundary/generated](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-boundary/generated).
- [x] Prove bridge lemmas from generated boundary types to the Lean privacy
  model.
- [x] Add proof/model hooks for context frame field order and context-binding
  golden vector parity.
- [x] Add proof/model hooks for public transcript and export authorization
  binding, with committed export authorization digest parity.
- [x] Add proof/model hooks for role-local hash-to-scalar, Cait-Sith mapping,
  public identity, and export reconstruction golden vector parity.
- [ ] Add proof/model hooks for broader product/WASM golden vector parity.

## Phase 5: Tests

MVP test implementation order:

1. Add type/API rejection tests first, before replacing behavior.
2. Add algebraic derivation tests with deterministic fixture inputs.
3. Add boundary output tests for every operation kind.
4. Add explicit export success and mismatch tests.
5. Add relayer key mismatch, nonce freshness, public-key validation, and zero
   canonical key tests.
6. Add integration tests for bootstrap, resume, presign, sign, and export.
7. Delete joined-root tests after the replacement assertions are green.

MVP regression matrix:

| Area | Must accept | Must reject |
| --- | --- | --- |
| Client derivation | `context + y_client` | `y_relayer`, `x_relayer`, canonical `x` |
| Server derivation | `context + y_relayer + X_client` | `y_client`, `x_client`, canonical `x` |
| Non-export client output | `x_client`, public identity, Cait-Sith client share | `x_relayer`, canonical `x` |
| Non-export server state | `x_relayer`, public identity, Cait-Sith relayer share | `y_client`, `x_client`, canonical `x` |
| Explicit export request | valid same-identity authorization | mismatched context, public key, address, operation, digest, wallet session, or relayer key |
| Explicit export response | authorized relayer export share envelope | `privateKeyHex`, canonical `x`, client root/share material |
| Cait-Sith adapter | mapped role-local shares for participant IDs `{1, 2}` | swapped participant IDs, mismatched public identity, stale retry counter |
| Public key validation | canonical compressed non-identity secp256k1 keys | bad length, bad prefix, non-curve point, non-canonical encoding, identity threshold sum |
| Export freshness | fresh nonce within validity window | repeated nonce, expired authorization, nonce from rotated relayer key |

Post-MVP regression matrix:

| Area | Must accept | Must reject |
| --- | --- | --- |
| WASM/API split | client bundle exports client-role functions | client bundle exports relayer derivation or relayer export-share release |
| FFI serialization | unpadded base64url for fixed-size bytes | padded base64, hex at internal FFI boundaries, wrong lengths, ambiguous scalar endian |
| Error handling | stable non-secret error codes | secret bytes or raw shares in error messages |
| Persistence transactions | atomic role-state and nonce writes | partial accepted state after failed bootstrap/export/signing |

MVP checklist:

- [x] Add algebraic tests for:

  ```text
  X = x_clientG + x_relayerG
  X = (x_client + x_relayer)G
  ```

- [x] Add export tests proving client-side reconstruction produces the persisted
  address.
- [x] Add boundary tests that fail if a server request accepts `y_client`,
  `x_client`, or canonical `x`.
- [x] Add boundary tests that fail if a non-export client response includes
  `x_relayer`.
- [x] Add integration tests for bootstrap, session resume, presign, sign, and
  export.
- [x] Add regression tests that no server API returns `privateKeyHex` or
  canonical `x`.
- [x] Add zero-canonical-key regression using a deterministic mocked relayer
  share that forces `X_client + X_relayer` to identity, then assert public
  identity rejection before export/signing state is accepted.
- [x] Remove `chain_target` from the HSS context and add a regression proving
  the crate context binds only the EVM-family key scope.
- [x] Add export nonce replay tests for fresh authorization, repeated nonce, and
  expired authorization.
- [x] Add crate-level export authorization digest failure tests.
- [ ] Add product-level export policy failure and relayer key rotation tests when
  product persistence and authorization digest storage are wired.
- [x] Add relayer key mismatch tests for threshold response and explicit export.
- [ ] Add relayer key mismatch tests for product signing and presign paths when
  those routes consume the new crate boundary.
- [x] Delete tests whose only purpose is preserving joined-root behavior.
- [x] Run the crate test suite:

  ```sh
  cargo test --manifest-path crates/ecdsa-hss/Cargo.toml
  ```

Post-MVP checklist:

- [ ] Add WASM export-surface tests for client and server/native bundles.
- [ ] Add reference-helper import guard tests for production server/client
  modules.
- [ ] Add audit/log redaction tests for signing and explicit export failures.
- [x] Add golden vector tests for context frame encoding and context binding.
- [x] Add golden vector tests for public transcript digest binding.
- [x] Add golden vector tests for export authorization digest binding.
- [x] Add golden vector tests for hash-to-scalar, role-local public identity,
  Cait-Sith mapping, and explicit export reconstruction.
- [ ] Add persistence transaction tests for concurrent export nonce insertions,
  relayer key rotation, and failed bootstrap/export/signing writes.
- [ ] Add stable error-code tests for every failure class in the taxonomy.
- [ ] Add FFI/WASM serialization tests for unpadded base64url, fixed byte
  lengths, scalar endianness, compressed public keys, and displayed export hex.

## Phase 6: Product Integration

Product integration should treat the Rust crate boundary as the source of truth.
Do this after crate tests and verification hooks pass.

Procedure:

1. Update server routes to normalize raw request bodies into role-local wire
   types exactly once.
2. Update client code to store client role state locally and pass only public
   commitments to the server.
3. Update relayer persistence to store relayer role state and public identity.
4. Update export UI/runtime so canonical `x` appears only in the explicit client
   export runtime.
5. Delete old account records and IndexedDB compatibility readers because the
   existing accounts will be wiped.
6. Delete server-side migration paths after the new route shape is active.

Boundary checks for product integration:

- no server route body parser accepts `y_client32_le`, `x_client32`, or
  canonical `x`
- no client non-export response parser accepts `x_relayer32`
- no export response parser accepts `privateKeyHex`
- every persisted ECDSA HSS key record includes public identity fields:
  `X_client`, `X_relayer`, `X`, address, context binding, and relayer key id
- every request path binds `walletSessionUserId`, `ecdsaThresholdKeyId`, client
  device/session, and relayer key before it starts MPC or export work

- [ ] Update server ECDSA HSS routes to accept only role-local protocol
  messages.
- [ ] Update client signing-engine ECDSA bootstrap to derive and retain
  `x_client` locally.
- [ ] Update relayer persistence to store only `x_relayer`, public identity, and
  audit metadata.
- [ ] Update passkey and Email OTP ECDSA bootstrap flows.
- [ ] Update explicit export flow so the client reconstructs `x`.
- [ ] Delete old IndexedDB ECDSA account records and compatibility readers.
- [ ] Delete server-side migration and compatibility logic.
- [ ] Update docs to state that existing ECDSA HSS accounts must be recreated.

## Phase 7: Performance Benchmarks

Run the full benchmark matrix after MVP correctness tests pass and the
verification bridge is underway. During MVP implementation, run a targeted
benchmark only when a changed path plausibly affects signing latency, export
latency, or WASM size.

- [ ] Capture a pre-change baseline:

  ```sh
  cargo bench --manifest-path crates/ecdsa-hss/Cargo.toml
  ```

- [x] Capture post-change native derivation benchmarks:

  ```sh
  cargo bench --manifest-path crates/ecdsa-hss/Cargo.toml
  ```

- [x] Measure native crate-local:
  context binding time,
  client share derivation time,
  server share derivation time,
  public-key addition/address derivation as part of relayer identity,
  additive-share mapping as part of role derivation,
  first presign after bootstrap,
  normal presign/sign with persisted shares,
  and explicit export time.
- [x] Measure native crate-local logical:
  request/response byte sizes,
  retained server state size,
  and retained client state size.
- [ ] Measure:
  WASM artifact size,
  product/FFI serialized request/response byte sizes,
  product retained server state size,
  and product retained client state size.
- [x] Emit a native per-stage benchmark table covering:
  context binding,
  client share derivation,
  server share derivation,
  public key and address verification,
  Cait-Sith share mapping,
  non-export presign/sign,
  and explicit export.
- [x] Compare native results against current notes:
  native derivation/bootstrap/export sub-millisecond,
  and native sign about `~40 ms`.
- [ ] Compare Node-hosted wasm non-export sign against current notes of
  `~120 ms`.
- [ ] Treat any Cait-Sith presign/sign regression as a release blocker unless it
  is explained by intentional backend changes.
- [ ] Keep export overhead isolated from non-export signing.

Native role-local benchmark snapshot from `cargo bench --manifest-path
crates/ecdsa-hss/Cargo.toml --bench performance_baseline`:

| Stage | Mean |
| --- | ---: |
| Context binding | `668.03 ns` |
| Client share derivation | `33.785 us` |
| Relayer share + public identity | `63.104 us` |
| Bootstrap adapter | `215.38 us` |
| First presign roundtrip | `39.272 ms` |
| Full sign bridge | `39.736 ms` |
| Explicit export | `354.66 us` |

Interpretation:

- native derivation, bootstrap, and export remain sub-millisecond
- native sign remains aligned with the existing `~40 ms` note
- this does not cover browser/Node-hosted WASM size or latency

Native logical byte-size snapshot from
`crates/ecdsa-hss/fixtures/role_local_v1.json`:

These are crate-local logical binary estimates using fixed-width scalar/point
fields plus `u16` string lengths where strings cross a boundary. The
`ecdsa-hss` crate has no canonical serde wire format, so product/FFI serialized
sizes still need to be measured in the SDK integration layer.

| Item | Logical bytes |
| --- | ---: |
| HSS context encoding | `177` |
| Threshold request | `60` |
| Prepare non-export request | `201` |
| Bootstrap non-export response | `127` |
| Bootstrap explicit-export response | `159` |
| Finalize server envelope | `152` |
| Retained server state | `183` |
| Retained client role share | `310` |
| Public identity | `336` |
| Export authorization payload | `240` |

## Completion Criteria

MVP completion:

- [x] Lean privacy theorems for true ECDSA HSS server blindness pass.
- [x] Rust implementation exposes one active production protocol shape.
- [x] Production server cannot reconstruct canonical `x`.
- [x] Production client cannot reconstruct `x_relayer` in non-export flows.
- [x] Explicit export reconstructs canonical `x` client-side.
- [x] Threshold signing and export verify against the same public key `X` and
  Ethereum address.
- [x] Production crate joined-root request, wire, and derivation paths are
  deleted or moved into reference-only fixture helpers.
- [x] Verus checks pass.
- [x] Rust tests pass.

Post-MVP completion:

- [ ] Product account records, server migrations, and IndexedDB readers for the
  superseded protocol are removed.
- [x] Aeneas/Lean boundary bridge passes.
- [ ] Native and browser benchmark results are committed.
