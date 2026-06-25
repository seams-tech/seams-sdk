# Security Review 1: Threshold Ed25519 Nonces And Client-Side Secret Outputs

Date: 2026-06-26

Scope:

- Threshold Ed25519 signing paths that use `frost-ed25519`.
- Router A/B Ed25519 presign pool and finalize paths.
- Server-side cosigner session storage and presign consumption.
- Client-side WASM and worker APIs that can expose nonce, share, mask, or private-key material.
- `ed25519-hss` usage where it feeds Ed25519 key material.

## Summary

The active SDK threshold Ed25519 signing paths use `frost-ed25519` and consume nonce material once before producing a signature share. I found no active nonce reuse in the client, relayer, presign pool, or Durable Object storage paths.

The review did find client-side sensitive-output surfaces. Those are now remediated:

- Raw exported Ed25519 client presign WASM helpers were removed.
- Ed25519 HSS client output masks now stay behind one-use worker handles.
- Device-link temporary NEAR private keys now stay behind one-use Rust-owned WASM handles.
- Worker errors and logs now redact secret field names before crossing worker boundaries.

The `ed25519-hss` crate is used for key derivation, recovery, and export material. I found no path where it supplies FROST signing nonces.

## Findings And Remediations

### High: raw WASM client presign export permitted nonce reuse

Original issue:

- `threshold_ed25519_client_presign_create` returned serialized FROST nonce bytes as `client_nonce_handle_b64u`.
- `threshold_ed25519_client_presign_sign` accepted that value repeatedly.
- A caller could reuse one nonce value across different signing packages and extract the client signing share.

Remediation:

- Removed `threshold_ed25519_client_presign_create` and `threshold_ed25519_client_presign_sign` from `wasm/near_signer/src/threshold/threshold_frost.rs`.
- Rebuilt local near-signer WASM packages so generated declarations dropped those exports.
- Kept the worker-material presign API, which stores nonce bytes behind an opaque handle and removes the handle before signing.

Status: fixed.

### High: Ed25519 HSS client output mask crossed JS worker boundaries

Original issue:

- Registration setup derived `clientOutputMaskB64u` as a raw value.
- The mask crossed client-side worker and SDK boundaries before being consumed.

Remediation:

- Added one-use worker-held HSS mask handles.
- Updated registration/session bootstrap to pass `clientOutputMaskHandle`.
- Removed raw HSS client output mask request routes from public worker maps.
- Added static guards for raw mask/client-base field names in active source.

Status: fixed.

### High: device-link temporary NEAR private key crossed client-side boundaries

Original issue:

- Device-link setup generated a temporary NEAR keypair and kept `tempPrivateKey` in session state.
- The signing path accepted a raw `nearPrivateKey` payload.

Remediation:

- Replaced `tempPrivateKey` with `tempKeyHandle`.
- Added Rust-owned one-use WASM handle exports:
  - `near_ephemeral_keypair_create_handle`
  - `near_ephemeral_keypair_sign_with_handle`
- `handle_signer_message` now rejects raw `GenerateEphemeralNearKeypair` and `SignTransactionWithKeyPair` requests.
- TypeScript worker request maps exclude both raw operations.
- Rust private-key request storage zeroizes on drop.

Status: fixed.

### Medium: worker error/log output could echo secret fields

Original issue:

- Some worker errors included raw thrown messages, which could contain secret-bearing field names and values.

Remediation:

- Added shared redaction helpers in `packages/shared-ts/src/utils/errors.ts`.
- Updated near-signer and HSS client workers to use `safeErrorMessage` and `errorLogSummary`.
- Added forbidden-field guards for PRF, seed, client-base, output-mask, signing-share, and private-key payload fields.

Status: fixed.

## Intentional Sensitive Outputs

Key export and recovery flows still produce private-key or seed artifacts when the user explicitly performs an export. These are expected outputs, and they should remain confined to the export confirmation/viewer path:

- `WasmBuildThresholdEd25519SeedExportArtifactResult.privateKey`
- recovery/export viewer `privateKey` display payloads
- `canonicalSeedB64u` in seed output flows

These paths need confirmation, UI isolation, and redaction coverage. They are separate from signing nonce use and device-link temporary signing.

## Safe Paths Reviewed

### Core FROST nonce generation

`crates/signer-core/src/near_threshold_ed25519.rs` creates client round-1 state through `frost_ed25519::round1::commit(key_package.signing_share(), &mut OsRng)`. This delegates nonce generation to `frost-ed25519` and uses `OsRng`.

### Active client presign path

The active worker-material presign path creates fresh FROST nonce material and stores it behind an opaque runtime handle. Signing consumes the handle with take semantics before producing the signature share.

### Server cosigner path

The server stores relayer nonce material during cosign init and consumes the signing session before computing a relayer signature share. Mismatch branches restore the session before any signature share is computed.

### Presign storage consumption

Reviewed in-memory, Redis, and Postgres storage implementations consume presigns before returning them for finalize. Redis uses compare-and-delete; Postgres locks and deletes inside the transaction.

### Cloudflare Durable Object storage

Router A/B Durable Object paths use take-style APIs for local nonce material and presign pool entries.

## Validation

- `cargo test` in `wasm/near_signer`: 66 passed.
- `wasm-pack build` for near signer browser package: passed with existing dead-code warnings.
- `wasm-pack build` for near signer server HSS package: passed with existing dead-code warnings.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/linkDevice.flowEvents.unit.test.ts ./unit/addWalletSigner.orchestration.unit.test.ts ./unit/thresholdEcdsa.presignPoolRefill.unit.test.ts --reporter=line`: 24 passed.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/refactor74LoginNoHss.guard.unit.test.ts ./unit/thresholdEd25519.nearSignerWasm.unit.test.ts --reporter=line`: 37 passed.
- `pnpm -C packages/shared-ts type-check`: passed.
- `pnpm -C packages/sdk-web type-check`: blocked by existing server-side ECDSA session record type errors around `walletSessionUserId` and `walletKeyId`.

Focused source sweeps:

- Raw `threshold_ed25519_client_presign_create` / `threshold_ed25519_client_presign_sign` exports: no active source or rebuilt package matches.
- Device-link `tempPrivateKey`, raw `nearPrivateKey` transport, and old keypair WASM wrappers: no active link-device or near-signer worker matches outside redaction guards and intentional export types.
- Raw HSS client output mask wrapper names: removed from active SDK call sites.
