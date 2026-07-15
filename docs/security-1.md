# Security Review 1: Threshold Ed25519 Nonces And Client-Side Secret Outputs

Date: 2026-06-26

Status: historical review record. The Ed25519-HSS and Ed25519 presign-pool
paths discussed below have been deleted. The current Ed25519 authority is
[yaos-ab.md](./yaos-ab.md).

Scope:

- Threshold Ed25519 signing paths that use `frost-ed25519`.
- Router A/B Ed25519 presign pool and finalize paths.
- Server-side cosigner session storage and presign consumption.
- Client-side WASM and worker APIs that can expose nonce, share, mask, or private-key material.
- NEAR WebAuthn attestation/COSE extraction surfaces.
- `ed25519-hss` usage where it feeds Ed25519 key material.

## Summary

The active SDK threshold Ed25519 signing paths use `frost-ed25519` and consume nonce material once before producing a signature share. I found no active nonce reuse in the client, relayer, presign pool, or Durable Object storage paths.

The review did find client-side sensitive-output surfaces. Those are now remediated:

- Raw exported Ed25519 client presign WASM helpers were removed.
- Ed25519 HSS client output masks now stay behind one-use worker handles.
- The legacy device-link temporary NEAR key flow and raw worker requests were removed.
- The NEAR-signer attestation/COSE extraction path was removed; server-verified `credentialPublicKeyB64u` is now the credential public-key source of truth.
- Worker errors and logs now redact secret field names before crossing worker boundaries.

The `ed25519-hss` crate is used for key derivation, recovery, and export material. I found no path where it supplies FROST signing nonces.

Server-paid NEAR transaction signing remains intentionally supported for gas sponsorship and other relayer-paid flows. That signer is server-side only, uses the configured relayer key, and is treated as the current gas-relayer implementation detail until it moves into a smaller isolated gas relayer worker.

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

- Removed the legacy device-link temporary-key flow.
- Deleted the raw `GenerateEphemeralNearKeypair` and `SignTransactionWithKeyPair` worker request variants.
- Deleted the temporary key-handle wrapper exports and TypeScript request maps.
- Replaced client link-device implementation with explicit refactor-84 stubs.

Status: fixed.

### Medium: worker error/log output could echo secret fields

Original issue:

- Some worker errors included raw thrown messages, which could contain secret-bearing field names and values.

Remediation:

- Added shared redaction helpers in `packages/shared-ts/src/utils/errors.ts`.
- Updated near-signer and HSS client workers to use `safeErrorMessage` and `errorLogSummary`.
- Added forbidden-field guards for PRF, seed, client-base, output-mask, signing-share, and private-key payload fields.

Status: fixed.

### Medium: NEAR signer parsed WebAuthn attestation on the client side

Original issue:

- The NEAR signer worker exposed a COSE extraction request that parsed WebAuthn attestation objects client side.
- Legacy SDK versions used that path to derive the WebAuthn public key for on-chain P256 verification.
- WebAuthn verification now happens server side, so the client parser duplicated a trust decision and exposed a stale boundary surface.

Remediation:

- Deleted the NEAR-signer COSE parser, handler, worker request variant, tests, and `ciborium` dependency.
- Removed SDK-web `extractCosePublicKey` worker plumbing and signing-surface ports.
- Registration and recovery now store authenticator public keys only from server-verified `credentialPublicKeyB64u`.
- Kept Tempo P256 COSE decoding in the EVM/Tempo signer path.

Status: fixed.

### Medium: server relayer signing helper accepted arbitrary NEAR private keys

Original issue:

- The server-side transaction helper accepted `nearPrivateKey` as an input.
- Valid callers used the configured relayer key, but the helper shape looked like a generic private-key signing primitive.

Remediation:

- Narrowed the helper to `signGasRelayerNearTransaction`.
- Removed `nearPrivateKey` from email-recovery and signed-delegate signing callbacks.
- Kept server-paid NEAR signing for account creation, email recovery, and gas-sponsored signed delegates.

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

- `cargo fmt --manifest-path wasm/near_signer/Cargo.toml`: passed.
- `cargo test --manifest-path wasm/near_signer/Cargo.toml`: 65 passed, with existing dead-code warnings.
- `wasm-pack build --target web --out-dir pkg --out-name wasm_signer_worker --release --features hss-client-exports`: passed with existing dead-code warnings.
- `wasm-pack build --target web --out-dir pkg-server --out-name wasm_signer_worker --release --no-opt --features hss-server-exports`: passed with existing dead-code warnings.
- `pnpm -C packages/sdk-server-ts type-check`: passed.
- `pnpm -C packages/sdk-web type-check`: passed.
- `pnpm -C packages/sdk-server-ts build`: passed.
- `pnpm -C packages/sdk-web build`: passed.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/emailRecoveryService.test.ts ./wallet-iframe/router.computeOverlayIntent.test.ts --reporter=line`: 3 passed.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/linkDevice.flowEvents.unit.test.ts ./unit/signingRuntime.construction.unit.test.ts ./unit/refactor80SwitchCase.guard.unit.test.ts ./unit/refactor71WalletSessionNaming.guard.unit.test.ts ./unit/rawThresholdEcdsaBootstrapRemoval.unit.test.ts ./relayer/link-device.prepare.test.ts --reporter=line`: 26 passed.
- Runtime smoke script for direct NEAR transaction build/finalize plus Node Ed25519 signing: passed with a 32-byte digest, 64-byte signature, and finalized signed transaction Borsh output.
- `git diff --check`: passed.

Focused source sweeps:

- Raw `threshold_ed25519_client_presign_create` / `threshold_ed25519_client_presign_sign` exports: no active source or rebuilt package matches.
- Device-link `tempPrivateKey`, old keypair WASM wrappers, and raw worker request variants: no active source or rebuilt package matches outside this historical finding.
- Raw keypair signing names `SignTransactionWithKeyPair`, `GenerateEphemeralNearKeypair`, `signTransactionWithKeyPair`, and `signWithPrivateKey`: no source, rebuilt package, test, or near-signer match remains.
- NEAR COSE extraction names `ExtractCosePublicKey`, `extractCosePublicKey`, `CoseExtraction`, and `handle_extract_cose_public_key`: no active source or rebuilt package matches.
- Raw HSS client output mask wrapper names: removed from active SDK call sites.
