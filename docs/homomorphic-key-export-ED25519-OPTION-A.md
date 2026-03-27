# Homomorphic Key Export Support Plan (Ed25519)

Date updated: March 23, 2026

## Objective

Define a separate Ed25519 homomorphic key-export plan that does not conflate:

- threshold scalar reconstruction,
- canonical NEAR private-key export,
- threshold-internal signing material.

Goals:

- keep the server blind to plaintext `clientShare` and plaintext reconstructed private material,
- keep finalize and artifact generation inside wallet worker memory only,
- keep the HE runtime worker-scoped and lazy-loaded only for export,
- make Ed25519 artifact semantics explicit,
- fail closed on public-key mismatch or unsupported account state.

## Current Repo Constraints

Current code paths now distinguish two Ed25519 concerns more explicitly:

- `crates/signer-core/src/near_ed25519_seed_export.rs` owns the seed-based export math and canonical NEAR `ed25519:` encoding for the new design,
- `crates/signer-core/src/near_threshold_frost.rs` and `crates/signer-core/src/near_threshold_ed25519.rs` still use FROST signing shares in scalar form for threshold signing.

Important consequence:

- HE over the current threshold Ed25519 share model reconstructs signing-scalar material,
- it does not reconstruct the original 32-byte Ed25519 seed,
- it also does not reconstruct a full Ed25519 expanded secret,
- therefore the ECDSA export plan cannot be reused unchanged for Ed25519.

## Problem Statement

For Ed25519, "private key" is overloaded:

- standard wallet/tooling flows often expect a seed-based private key representation,
- threshold signing flows work naturally over scalar shares,
- these are related, but they are not interchangeable encodings.

The repo's current NEAR export/import behavior is seed-based. That means:

- reconstructing only the scalar is not enough to emit the current canonical `ed25519:` private-key string,
- the seed cannot be recovered from the scalar after the fact,
- any doc or API that says "Ed25519 export" must state whether it means `scalar` or `seed`.

Do not use "expanded" as an export format label in this plan. Use only `scalar` or `seed`.

## Trust Model and Correctness Boundary

This export flow assumes:

- the server is trusted to load the correct scoped share material and apply add-constant correctly,
- the client is trusted to submit an encryption of the intended seed-export share material,
- the protocol goal is confidentiality of client-held share material and reconstructed private material, not a zero-knowledge proof that the ciphertext contains the canonical client share.

Important consequence:

- the server cannot verify whether the ciphertext encrypts the intended client contribution or some other client-chosen value,
- this is acceptable for export under this trust model,
- wrong plaintext or wrong combine is a correctness/availability failure rather than a plaintext-exposure failure.

Required correctness check:

- before emitting any export artifact, the client must derive the public key from the decrypted private material and compare it to the expected public key bound to `(orgId, accountId, keyPurpose, keyVersion)`,
- any mismatch fails closed and aborts export.

## Supported Export Artifact

### `near-ed25519-seed-v1`

This mode exports a canonical seed-based Ed25519 private key compatible with the repo's existing NEAR key format.

- artifact contains a canonical 32-byte Ed25519 seed,
- finalize derives the Ed25519 signing key and public key from that seed,
- only after public-key verification may the client emit `ed25519:` + base58(`seed || publicKey`),
- this seed cannot be recovered from the current scalar shares alone.

Properties:

- matches current NEAR private-key expectations,
- requires a separate seed-backed lifecycle design.

Out of scope for v1:

- `ed25519-scalar-v1`,
- any custom scalar-form export artifact that is not directly importable by standard NEAR wallet tooling.

## Recommended Strategy

1. Complete [`remove-local-ed25519-signer.md`](/Users/pta/Dev/rust/simple-threshold-signer/docs/remove-local-ed25519-signer.md) first so NEAR Ed25519 becomes threshold-only.
2. Retire existing scalar-only Ed25519 threshold accounts instead of carrying them forward into the export design.
3. Refactor Ed25519 threshold enrollment/rotation so every new threshold account is created with a canonical seed-backed export lifecycle.
4. Treat standard seed-compatible Ed25519 export as the only v1 product target.

## Strict Architectural Rule

There is exactly one Ed25519 lifecycle in this repo:

- seed-backed threshold Ed25519,
- one canonical public key per `(orgId, accountId, keyPurpose, keyVersion)`,
- threshold signing shares and export-seed shares both bound to that same public key,
- no alternate Ed25519 enrollment mode,
- no local Ed25519 fallback,
- no server-side Ed25519 share derivation from relay master secret for new accounts.

Implementation consequence:

- any Ed25519 path that still treats `clientVerifyingShareB64u` as the primary identity artifact, or that changes behavior based on `shareMode=derived|auto`, is legacy and must be removed rather than preserved behind fallback logic.

## Seed-Backed Design Requirements

A standard NEAR-compatible export path requires new lifecycle guarantees:

- create and bind a canonical export seed at Ed25519 enrollment or rotation time,
- ensure that the threshold public key and the export seed are bound to the same account/key version,
- protect export-seed material under a client/server split suitable for HE reconstruction,
- keep export-seed semantics separate from threshold signing-share semantics,
- reconstruct the seed only inside worker memory during export,
- derive the public key from the reconstructed seed and reject on mismatch before emitting the `ed25519:` private-key string.

Critical rule:

- never attempt to recover or synthesize a canonical seed from a reconstructed scalar after the fact.

## Required Threshold Signing Refactor Before HE Export

Before any HE export work, Ed25519 threshold signing should be refactored so the threshold signer and the standard NEAR private-key export are two views over one canonical key lifecycle.

### Canonical key material

At enrollment or rotation time, the client worker generates one canonical Ed25519 seed:

- `d in {0,1}^256`

Derive standard Ed25519 signing state:

- `h = SHA-512(d)`
- `a = clamp(h[0..31])`
- `prefix = h[32..63]`
- `A = [a]B`

Where:

- `d` is the canonical exportable private-key seed,
- `a` is the scalar the threshold signer must realize,
- `A` is the public key that must match both the threshold signer and the exported NEAR key.

The exported NEAR private key is then:

- `ed25519:` + base58(`d || A`)

### Threshold signing shares

FROST signing should continue to operate on shares of `a`, not on shares of `d`.

For a signer set with participant ids `i in S`, define signing shares `x_i` such that:

- `a = sum(lambda_i * x_i) mod l`

Where:

- `l` is the Ed25519 subgroup order,
- `lambda_i` are the standard Lagrange coefficients for recovery at zero for the active signer set,
- `X_i = [x_i]B` are the verifying-share points,
- `A = sum(lambda_i * X_i)`.

For the current 2-of-2 participant default `(1, 2)`, this becomes:

- `lambda_client = 2`
- `lambda_relayer = -1 mod l`
- `a = 2*x_client - x_relayer mod l`

So if the client chooses `x_client`, the relayer signing share must be:

- `x_relayer = 2*x_client - a mod l`

The threshold public key computed from verifying shares must equal the public key derived from the canonical seed `d`.

### Export-seed shares

Standard NEAR export must reconstruct `d`, not `a`.

Define an independent export-secret split for the seed:

- `m = LE256(d)`
- choose client export share `y_client in Z_(2^256)`
- set relayer export share `y_relayer = m - y_client mod 2^256`

This produces two parallel secret domains bound to the same key version:

- signing domain: FROST shares of `a` (`x_client`, `x_relayer`)
- export domain: additive shares of `d` (`y_client`, `y_relayer`)

Signing uses only the signing domain. Export uses only the export domain.

### Share derivation ownership

The seed-backed design should keep canonical private material inside the client worker only.

- `d` must be generated uniformly at random in the client worker for each new Ed25519 threshold enrollment or rotation,
- `d` must not be derived from WebAuthn PRF output,
- the client worker derives `a`, `m`, `x_client`, `y_client`, `x_relayer`, and `y_relayer`,
- the relayer must never receive plaintext `d`, plaintext `m`, plaintext `a`, or plaintext `prefix`,
- the relayer should receive only relayer-side share material plus public metadata bound to the key version,
- the client should not persist `d`, `x_client`, or `y_client`; those are re-derived or re-created in worker memory when needed.

Important consequence:

- the current relayer-side "derive relayer share from master secret and client verifying share" construction is not the right lifecycle for seed-backed Ed25519 export,
- seed-backed enrollment should instead submit a prepared relayer-share package computed by the client worker from the canonical seed lifecycle.

### Required invariants after the refactor

- every new threshold Ed25519 account must be created from a canonical seed `d`,
- the threshold signing public key derived from `x_i` shares must equal the public key derived from `d`,
- signing shares and export-seed shares must be stored as separate materials with separate type labels and code paths,
- `prefix` is derived from `d` during export verification only; it is not a threshold share,
- no new scalar-only Ed25519 threshold accounts may be created after this refactor.

### Enrollment / rotation output spec

After the refactor, Ed25519 enrollment or rotation should output and bind all of the following under one `(orgId, accountId, keyPurpose, keyVersion)`:

- canonical public key `A`,
- client share derivation spec for signing-share recovery,
- client share derivation spec for export-share recovery,
- relayer signing share material,
- relayer export-seed share material,
- participant-id set and derivation version,
- explicit artifact compatibility metadata indicating that standard `near-ed25519-seed-v1` export is supported.

Clarification:

- client-side shares remain ephemeral and deterministic from WebAuthn PRF output,
- relayer-side shares are the only share materials that need persistent backend storage,
- client IndexedDB should persist only metadata required to re-derive client shares and to request export for the correct key version.

### Why this refactor comes before HE export

Without this lifecycle change, HE export would only reconstruct scalar-form threshold signing material.

With this lifecycle change, HE export can reconstruct the canonical seed:

1. worker reconstructs `d` from export-seed shares,
2. worker derives `a`, `prefix`, and `A` from `d`,
3. worker verifies `A` matches the bound threshold public key,
4. worker emits the standard NEAR private key string.

This keeps threshold signing mathematically aligned with FROST while making standard NEAR-wallet export possible.

## Retirement Policy For Scalar-Only Accounts

Existing scalar-only Ed25519 threshold accounts are out of scope for this design:

- they should be retired rather than migrated into standard seed export support,
- they must not block the new seed-backed threshold lifecycle,
- `near-ed25519-seed-v1` applies only to accounts created or rotated under the refactored lifecycle described above.

No silent downgrade from standard seed export to any non-wallet-compatible scalar artifact.

## Protocol Shape

### Common Init

`POST /export/init` should return:

- `exportId`,
- bound context `(orgId, accountId, keyPurpose, keyVersion)`,
- expected public key (or equivalent fingerprint),
- explicit `artifactKind = near-ed25519-seed-v1`,
- short TTL and anti-replay metadata.

### Finalize

Client worker:

1. decrypts seed-form private material,
2. validates seed encoding/length spec,
3. derives the Ed25519 signing key and public key from the seed,
4. compares it to the expected public key,
5. emits wrapped `near-ed25519-seed-v1` artifact, and only then the canonical `ed25519:` string if the product surface needs it,
6. zeroizes all private material.

## Threats and Required Mitigations

### Format confusion

- artifact kind must be explicit and mandatory,
- standard `ed25519:` string output is allowed only for verified seed-based export.

### Wrong plaintext / wrong combine

- protocol does not require zero-knowledge proof that ciphertext contains the canonical client share,
- server-side correctness is an operational trust assumption for export,
- client detects wrong-share / wrong-combine outcomes by deriving the public key and comparing it to the expected public key,
- any mismatch aborts export without producing an artifact.

### Migration ambiguity

- accounts not enrolled into a seed-backed export lifecycle must reject `near-ed25519-seed-v1`,
- capability checks must happen before expensive worker/export steps proceed.

### Client bundle and runtime cost

- HE code must live only in the secure export worker path,
- the worker must lazy-load the HE runtime only after explicit export start,
- unsupported devices or worker-init failures must fail closed before artifact generation.

## Phase 0 Decisions Already Frozen

- v1 product export target is `near-ed25519-seed-v1`.
- `ed25519-scalar-v1` is out of scope and should not be implemented as part of this plan.
- v1 scope is seed-backed 2-of-2 threshold Ed25519 only.
- ambiguous "expanded secret" terminology has been removed from this plan.

## Frozen Implementation Specs

These decisions are already frozen for v1 and should now be treated as implementation inputs, not open design questions.

### Canonical seed ownership

- `d` is generated in the client worker, not by the relayer,
- `d` is uniformly random per key version, not deterministically derived from PRF output,
- the client worker computes `x_relayer` and `y_relayer` locally and sends only relayer-side shares to the backend,
- the backend must never observe plaintext `d`, `m`, `a`, or `prefix`.

### Deterministic client-share derivation

- participant ids are fixed to `(client=1, relayer=2)` for v1 and must be enforced at the type/API level,
- `x_client` uses HKDF-SHA256 with salt `tatchi/lite/threshold-ed25519/client-signing-share:v2`,
- `y_client` uses HKDF-SHA256 with salt `tatchi/lite/threshold-ed25519/client-export-share:v1`,
- HKDF info bytes are:
  - `nearAccountIdUtf8`
  - `0x00`
  - `keyVersionUtf8`
  - `0x00`
  - `u16be(clientParticipantId)`
  - `u16be(relayerParticipantId)`
  - `u32be(derivationPath)`
  - `u32be(counter)`
- for v1, `derivationPath = 0`,
- `x_client` derivation expands 64 bytes and interprets them with `from_bytes_mod_order_wide`,
- `x_client` must be non-zero; if zero, increment `counter` and retry deterministically,
- `y_client` derivation expands 32 bytes and interprets them as an unsigned little-endian integer in `Z_(2^256)`,
- `y_client` may be zero,
- signing-share and export-share derivation must never reuse the same salt label.

### Integer and byte encoding

- `d` is exactly 32 bytes,
- `m = LE256(d)` is the canonical unsigned integer encoding of the seed,
- `y_client` and `y_relayer` live in `Z_(2^256)`,
- export finalize decodes the decrypted value as `m mod 2^256`, then re-encodes it as 32 little-endian bytes before deriving the Ed25519 key,
- the standard NEAR wallet artifact is `ed25519:` + base58(`d || A`).

### Storage and capability model

- client storage must distinguish seed-backed threshold Ed25519 material from the old scalar-only record shape,
- relayer storage must separate signing-share material from export-seed-share material,
- both sides must bind those materials to the same `keyVersion` and public key,
- capability metadata such as `near-ed25519-seed-v1` support must be stored explicitly and checked before export begins.

### Export route spec

- reuse the shared export route family used by the ECDSA export plan,
- use `POST /export/init` and `POST /export/combine`,
- require `artifactKind = near-ed25519-seed-v1` on every Ed25519 export request and response,
- `init` returns capability, expected public key, artifact kind, participant ids, and `keyVersion`,
- accounts without seed-backed capability must be rejected before HE initialization,
- stale `keyVersion`, stale `exportId`, or mismatched participant metadata must fail closed,
- do not introduce a dedicated Ed25519-only export route in v1.

### Worker boundary and interoperability

- Ed25519 export stays worker-owned end to end,
- main-thread TypeScript must never hold plaintext `d`, `a`, `m`, `x_client`, `y_client`, or the emitted private key string,
- HE code remains lazy-loaded and scoped to the export worker only,
- sign-off targets are the repo-native `ed25519:` parser/import surface and `near-api-js` private-key parsing/import surface.

## Test Vector Publication Contract

Fixed test vectors are required before implementation is considered spec-complete.

Ownership:

- Rust core is the source of truth for generated vectors,
- Wasm worker tests consume the Rust-published vectors for parity,
- TypeScript tests consume the same vectors for orchestration/export parity.

Required artifacts:

- canonical seed `d`,
- derived `a`,
- derived public key `A`,
- `x_client`,
- `x_relayer`,
- `y_client`,
- `y_relayer`,
- final exported `ed25519:` private-key string.

Recommended file layout:

- Rust source-of-truth fixture under `crates/signer-core/fixtures/ed25519-export-seed-v1/`
- a generated JSON fixture for cross-runtime consumers in that same fixture directory,
- Wasm tests read the shared JSON fixture rather than re-encoding constants,
- TypeScript parity tests read the same shared JSON fixture rather than re-encoding constants.

## Comprehensive Phased Implementation Spec

### Prerequisite — Remove Legacy Local Ed25519 Signer

Before Phase 0 of this plan, complete
[`remove-local-ed25519-signer.md`](/Users/pta/Dev/rust/simple-threshold-signer/docs/remove-local-ed25519-signer.md).

Required outcome:

- [x] no local-only NEAR Ed25519 signer,
- [x] no local fallback in worker export/signing paths,
- [x] no local NEAR key material branches in client storage or orchestration,
- [x] no UI or relay spec that still treats local Ed25519 as a supported NEAR lifecycle.

### Phase 0 — Scope Freeze And Breaking Cleanup

- [x] Freeze `near-ed25519-seed-v1` as the product target for Ed25519 export.
- [x] Remove `ed25519-scalar-v1` from v1 scope and from the implementation plan.
- [x] Freeze v1 scope as seed-backed 2-of-2 threshold Ed25519 only.
- [x] Remove ambiguous "expanded secret" language everywhere in this plan and related Ed25519 export docs.
- [x] Verify the local-signer removal prerequisite is complete and remove any remaining Ed25519 export assumptions that rely on legacy local-signer recovery or scalar-only threshold accounts.

### Phase 1 — Crypto And Serialization Spec Freeze

- [x] Freeze the canonical seed derivation math:
  - `d in {0,1}^256`
  - `h = SHA-512(d)`
  - `a = clamp(h[0..31])`
  - `prefix = h[32..63]`
  - `A = [a]B`
- [x] Freeze the client signing-share derivation:
  - HKDF-SHA256 from `prf.first`
  - dedicated signing-share salt/version label
  - 64-byte OKM reduced with `from_bytes_mod_order_wide`
- [x] Freeze the client export-share derivation:
  - HKDF-SHA256 from `prf.first`
  - dedicated export-share salt/version label
  - 32-byte OKM interpreted as little-endian integer in `Z_(2^256)`
- [x] Freeze the default 2-of-2 share formulas:
  - `x_relayer = 2*x_client - a mod l`
  - `y_relayer = m - y_client mod 2^256`
- [x] Freeze the exact HKDF info layout. Minimum fields should include `nearAccountId`, `keyVersion`, participant ids, and derivation path.
- [x] Freeze the seed export encoding as `ed25519:` + base58(`d || A`).
- [x] Publish fixed test vectors for `d`, `a`, `A`, `x_client`, `x_relayer`, `y_client`, `y_relayer`, and the final `ed25519:` string.

## Linear Execution Order From Here

1. Define the new seed-backed Ed25519 enrollment spec.
   - add explicit request/response types for a prepared relayer-share package,
   - stop treating `clientVerifyingShareB64u` as the primary Ed25519 enrollment artifact for new accounts.
2. Remove the old server-side Ed25519 lifecycle.
   - delete the Ed25519 path that derives relayer shares from server master secret plus client verifying share,
   - stop letting `shareMode=derived|auto` affect Ed25519 behavior,
   - require persisted seed-backed relayer key material for Ed25519 session bootstrap and signing.
3. Refactor client worker enrollment and rotation.
   - generate canonical seed `d`,
   - derive `a`, `A`, `x_client`, `y_client`, `x_relayer`, and `y_relayer`,
   - validate the bundle before any enrollment request leaves worker memory.
4. Change client and relayer storage to the new seed-backed record shape.
   - persist only metadata on the client,
   - persist relayer-side signing/export shares on the backend,
   - bind both to the same `keyVersion` and public key.
5. Remove legacy Ed25519 field names and session assumptions on the server.
   - stop requiring `clientVerifyingShareB64u` for Ed25519 session bootstrap when persisted key material exists,
   - stop validating Ed25519 `relayerKeyId` by re-deriving from `clientVerifyingShareB64u`,
   - collapse request/session/store types so seed-backed Ed25519 is the only supported server model.
6. Record and verify runtime compatibility.
   - prove Rust, wasm, and SDK consumers all accept the published vectors and the standard `ed25519:` output.

Progress:

- seed-backed Ed25519 enrollment package is now implemented through Rust core, wasm worker, client registration flow, and relay registration bootstrap,
- registration bootstrap now accepts prepared relayer signing/export shares for new Ed25519 accounts,
- standalone `/threshold-ed25519/keygen` now accepts the same seed-backed package,
- `link-device` and `email-recovery` bootstrap requests now send the same seed-backed Ed25519 package from the client worker,
- client IndexedDB threshold-key metadata now persists `artifactKind`, `keyVersion`, `seedExportCapable`, and export-derivation metadata for seed-backed Ed25519 accounts,
- export recovery now rejects threshold Ed25519 records that are not explicitly provisioned as `near-ed25519-seed-v1`,
- export worker requests now carry `artifactKind`, `keyVersion`, and `seedExportCapable`, and the worker rejects NEAR export calls that are not explicitly seed-backed,
- relay route scaffolding now exists for `POST /threshold-ed25519/export/init` and `POST /threshold-ed25519/export/combine`,
- `POST /threshold-ed25519/export/init` now mints a short-lived `exportId` bound to `(relayerKeyId, keyVersion, artifactKind, publicKey, participantIds)`,
- `POST /threshold-ed25519/export/combine` now requires that `exportId` and validates the bound export session before any combine work,
- the client RPC layer now has typed wrappers for those Ed25519 export routes,
- `sync-account` now derives the seed-backed package on the client side, but the server side still only uses the bound credential for session bootstrap,
- server Ed25519 key resolution now requires persisted seed-backed relayer key material and no longer uses derived-share fallback or `shareMode`,
- Ed25519 session bootstrap and signing now resolve by persisted `relayerKeyId/publicKey` rather than re-deriving from `clientVerifyingShareB64u`,
- rotation remains the main unimplemented lifecycle migration.

### Phase 2 — Rust / Wasm Core Refactor

- [x] Add pure core helpers to:
  - derive `a`, `prefix`, and `A` from `d`
  - derive `x_client` and `y_client` from `prf.first`
  - compute `x_relayer` and `y_relayer`
  - encode and parse the standard NEAR `ed25519:` private key format
  Progress:
  - implemented in `crates/signer-core/src/near_ed25519_seed_export.rs`
- [x] Add explicit types for seed-backed Ed25519 key material rather than reusing scalar-only names.
- [x] Add a pure helper to verify that the threshold public key equals the seed-derived public key.
- [x] Delete the Ed25519 relayer-share derivation path that starts from relayer master secret plus client verifying share.
- [x] Remove Ed25519 dependence on `shareMode=derived|auto` in Rust/wasm/server integration paths.
- [x] Add unit tests for the first byte-order, modulo, and seed/public-key consistency boundaries.
- [x] Expose the new seed-backed bundle helper through the wasm worker boundary for enrollment and rotation flows.

### Phase 3 — Enrollment / Rotation Refactor

- [ ] Replace `clientVerifyingShareB64u`-driven Ed25519 enrollment with a seed-backed enrollment package across all Ed25519 enrollment surfaces.
- [ ] Generate canonical seed `d` inside the client worker during Ed25519 threshold enrollment and rotation.
- [ ] Derive `a`, `A`, `x_client`, `y_client`, `x_relayer`, and `y_relayer` inside the same worker session.
- [ ] Validate the generated seed/share bundle in the worker before sending any enrollment payload.
- [ ] Send only relayer-side shares plus public metadata to the relayer enrollment route.
- [ ] Ensure relayer enrollment persists both:
  - relayer signing share material
  - relayer export-seed share material
- [ ] Ensure client storage persists only metadata and derivation versions, not plaintext client shares or `d`.
- [ ] Bind the on-chain access key, relayer share records, and client metadata to the same `keyVersion` and public key.
- [ ] Rotation must replace the old share package completely; no new scalar-only Ed25519 accounts may be created after this phase.

Progress:

- registration bootstrap now uses a seed-backed enrollment package for new Ed25519 account creation,
- client worker now generates canonical seed-backed Ed25519 enrollment material in one request,
- standalone `/threshold-ed25519/keygen` now uses the same spec,
- `link-device` and `email-recovery` now use the same client-side package format,
- remaining work is to finish the sync-account server-side spec and move rotation onto the same spec.

### Phase 3.5 — Server Lifecycle Unification

- [x] Make persisted seed-backed key material mandatory for Ed25519 session bootstrap.
- [x] Remove `deriveRelayerKeyMaterial(...)` from the Ed25519 server path.
- [x] Remove `usesDerivedRelayerShares()` from Ed25519 flow control, or make it a no-op for Ed25519 and then delete it.
- [x] Remove Ed25519-only use of `THRESHOLD_ED25519_MASTER_SECRET_B64U` for new-account lifecycle behavior.
- [x] Remove Ed25519-only `shareMode` branching from:
  - keygen bootstrap,
  - session bootstrap,
  - relayer key resolution,
  - signing init/finalize,
  - export init/combine.
- [x] Make `relayerKeyId = publicKey` the only supported Ed25519 identity binding for new accounts.
- [x] Stop treating `clientVerifyingShareB64u` as an Ed25519 key-binding proof; keep it only if needed as auxiliary threshold metadata.
- [x] Collapse Ed25519 server request/session/store types so they no longer imply a derivable-share lifecycle.
- [ ] Add negative tests proving Ed25519 registration/signing/export fail when persisted key material is missing, rather than falling back to derivation.
- [ ] Remove dead config/docs/comments that still describe Ed25519 as `derived`, `auto`, or master-secret-backed.

### Phase 4 — Client And Relayer Data-Model Break

- [ ] Replace the current client IndexedDB record shape with a seed-backed threshold Ed25519 metadata type.
- [ ] Add explicit fields for:
  - `keyVersion`
  - `artifactKind`
  - `seedExportCapable`
  - client signing-share derivation version
  - client export-share derivation version
  - participant ids
  - relayer key reference / share reference
- [ ] Update all mappers, stores, and worker payload assemblers to use the new type.
- [ ] Update relayer persistence so signing-share state and export-seed-share state are stored as separate, typed materials.
- [ ] Remove old scalar-only Ed25519 material names and branches once callers are migrated.

Progress:

- client IndexedDB threshold-key storage now persists `artifactKind`, `keyVersion`, `seedExportCapable`, and `clientExportShareDerivation`,
- registration, sync-account, email-recovery, and link-device local persistence now write that metadata when the relay returns it,
- relayer key persistence already stores `keyVersion`, `seedExportCapable`, and `relayerExportShareB64u`,
- remaining work is to make sync-account return seed-backed metadata consistently and then collapse the remaining old field names.

### Server-Side Cleanup Checklist

The following server cleanups are directly related to the one-lifecycle refactor and should be completed as part of Phase 3.5, not deferred indefinitely:

- `server/src/core/ThresholdService/relayerKeyMaterial.ts`
  - [x] remove the Ed25519 derived fallback entirely once persisted seed-backed records are required.
- `server/src/core/ThresholdService/keygenStrategy.ts`
  - [x] remove `deriveRelayerKeyMaterial(...)` from the Ed25519 implementation,
  - [x] keep only seed-backed package ingestion for Ed25519 keygen.
- `server/src/core/ThresholdService/config.ts`
  - [x] stop exposing Ed25519 `derived|auto|kv` lifecycle choice if Ed25519 is no longer configurable that way.
- `server/src/core/types.ts`
  - [x] remove Ed25519 request/response comments and fields that imply `clientVerifyingShareB64u` is the primary key-binding artifact,
  - [x] collapse Ed25519 types around the seed-backed package and persisted `relayerKeyId/publicKey`.
- `server/src/core/AuthService.ts`
  - [x] remove registration, sync-account, link-device, and email-recovery branches that still pass Ed25519 through legacy verifying-share assumptions.
- `server/src/core/ThresholdService/stores/SessionStore.ts`
  - [x] remove Ed25519 session requirements that exist only to support derived-share reconstruction.
- `server/src/core/ThresholdService/signingHandlers.ts`
  - [x] require persisted Ed25519 relayer key material and stop using session-level `clientVerifyingShareB64u` as a fallback key-binding check.
- docs and runtime logging
  - [x] remove `shareMode: derived/auto` language for Ed25519 from logs and operator-facing comments,
  - [ ] remove any remaining README text that still documents the removed lifecycle.

### Phase 5 — Export API And HE Protocol

- [x] Define the initial `POST /export/init` scaffold for seed-backed Ed25519 export.
  Progress:
  - route is live on express and cloudflare threshold routers as `/threshold-ed25519/export/init`
  - current response returns `exportId`, `expiresAtMs`, `artifactKind`, `keyVersion`, expected public key, `participantIds`, and export-capability gating
  - current route still does not return an HE profile / parameter version yet
- [x] Add the initial relayer combine route scaffold.
  Progress:
  - route is live on express and cloudflare threshold routers as `/threshold-ed25519/export/combine`
  - route currently validates the export session and relayer key binding, then fails with `not_implemented` until the HE combine runtime is wired
- [ ] Extend `POST /export/init` to return:
  - HE profile / parameter version
  - TTL / anti-replay metadata
- [ ] Implement the relayer combine route so it:
  - loads the relayer export-seed share for the bound key version
  - applies homomorphic add-constant to the client ciphertext
  - returns the combined ciphertext
  - never exposes plaintext share material
- [ ] Define the client worker finalize spec:
  - derive `y_client`
  - HE-encrypt `y_client`
  - submit ciphertext to combine route
  - decrypt `m`
  - reduce mod `2^256`
  - decode `d`
  - derive `A`
  - compare `A` to expected public key
  - emit `ed25519:` + base58(`d || A`) only on match
- [ ] Freeze the plaintext-capacity requirement for the HE scheme so a 256-bit seed share can be encoded safely without ambiguity.
- [ ] Reject unsupported key material before HE runtime load.

### Phase 6 — Worker, UI, And Runtime Refactor

- [x] Change Ed25519 export worker inputs so the worker receives concrete threshold export capability metadata for `near-ed25519-seed-v1`.
- [x] Remove the old Ed25519 threshold-export fallback that reconstructed a local keypair via `recoverKeypairFromPasskey()`.
- [ ] Keep the entire seed reconstruction and `ed25519:` string emission inside secure worker memory only.
- [ ] Lazy-load the HE runtime only after explicit export confirmation and capability preflight.
- [ ] Update export UI copy to state that the output is a standard NEAR Ed25519 private key and that export fails closed on any public-key mismatch.

### Phase 7 — Verification, Interop, And Negative Tests

- [ ] Add fixed-vector tests that prove:
  - seed-derived public key equals threshold public key
  - `x_client` / `x_relayer` recombine to `a`
  - `y_client` / `y_relayer` recombine to `m`
- [ ] Add cross-runtime tests so Rust core, Wasm worker, and TypeScript orchestration agree on public key, share derivation, and export string.
- [ ] Record the compatibility matrix for the published `near-ed25519-seed-v1` vectors across Rust, wasm, SDK, repo-native parser, and `near-api-js`.
- [ ] Add end-to-end tests for:
  - enroll seed-backed threshold Ed25519 key
  - sign successfully with threshold flow
  - export successfully with HE
  - parse/import the resulting `ed25519:` key in at least the repo's parser and one external NEAR-compatible parser/import surface
- [ ] Add failure tests for:
  - wrong public key
  - wrong participant ids
  - stale `keyVersion`
  - stale `exportId`
  - malformed ciphertext
  - unsupported account material
  - worker HE initialization failure
- [ ] Add tests proving the HE bundle is not loaded during normal signing or app startup.

### Phase 8 — Cleanup And Cutover

- [ ] Delete old scalar-only Ed25519 enrollment, storage, and export branches that no longer serve the seed-backed design.
- [ ] Delete any remaining worker or API branches that assume legacy local NEAR Ed25519 export for threshold accounts.
- [ ] Remove dead docs once `near-ed25519-seed-v1` is the only supported product export path.
- [ ] Record the final compatibility matrix and link the published test vectors.

## Remaining Decision Gates Before Coding

No major design gates remain for v1. The remaining work is implementation.

## Notation and Math Appendix

### `LE256(d)`

`LE256(d)` means:

- interpret the 32-byte seed `d` as a 256-bit integer in little-endian byte order,
- this gives a reversible integer encoding `m in [0, 2^256 - 1]`,
- the export-share split operates on this integer form.

### `A = [a]B`

`B` is the standard Ed25519 base point on the curve.

- mathematically, `B` is a curve point,
- in code, it is typically represented as an Edwards-point structure,
- `[a]B` means scalar multiplication of the base point by the secret scalar `a`,
- the result `A` is the public-key point corresponding to `a`.

When serialized for Ed25519 public keys, `A` is usually compressed to 32 bytes using the standard Edwards-Y compressed encoding.

### `clamp(h[0..31])`

This is the standard Ed25519 bit-masking step applied to the first 32 bytes of `SHA-512(d)` before interpreting them as the signing scalar.

In byte form:

```text
s[0]  &= 248
s[31] &= 63
s[31] |= 64
```

Meaning:

- clear the lowest 3 bits of byte 0,
- clear the highest bit of byte 31,
- set the second-highest bit of byte 31.

This is a standard part of Ed25519 key derivation, not a project-specific convention.

## Citations

1. RFC 8032: "Edwards-Curve Digital Signature Algorithm (EdDSA)," IETF, 2017.
   - https://www.rfc-editor.org/rfc/rfc8032
2. RFC 8410: "Algorithm Identifiers for Ed25519, Ed448, X25519, and X448," IETF, 2018.
   - https://www.rfc-editor.org/rfc/rfc8410
3. Paillier, P. "Public-Key Cryptosystems Based on Composite Degree Residuosity Classes," EUROCRYPT 1999. DOI: `10.1007/3-540-48910-X_16`
   - https://www.iacr.org/cryptodb/data/paper.php?pubkey=2681
4. Damgard, I.; Jurik, M. "A Generalisation, a Simplification and some Applications of Paillier's Probabilistic Public-Key System," BRICS RS-00-45, 2000.
   - https://www.brics.dk/RS/00/45/
