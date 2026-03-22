# Remove Legacy Local Ed25519 Signer

## Decision

No, these are not the same system.

- `crates/signer-core/src/near_ed25519.rs` is the legacy local NEAR signer path.
  It derives a full NEAR private key from passkey PRF output, produces an `ed25519:...` seed/keypair, and supports encrypted local storage plus seed-style export/recovery.
- `crates/signer-core/src/near_threshold_ed25519.rs` and `crates/signer-core/src/near_threshold_frost.rs` are the threshold Ed25519 path.
  They derive a deterministic client scalar/share from `WrapKeySeed` and participate in FROST with a relayer-held share. This path does not need a local NEAR seed/private key.

This plan assumes we no longer support:

- local-only NEAR signing
- local fallback from threshold signing
- local NEAR private-key export/recovery
- migration code whose only purpose is upgrading legacy local accounts into threshold accounts

Breaking existing local-only accounts is acceptable. Do not add compatibility shims.

## Target End State

- NEAR Ed25519 is threshold-only.
- `SignerMode` no longer has `local-signer`.
- NEAR registration and device linking only provision threshold Ed25519 key material.
- IndexedDB stores only threshold NEAR material for NEAR.
- The signer WASM worker no longer derives, encrypts, decrypts, or recovers local NEAR private keys.
- The server no longer accepts local NEAR key fields such as `new_public_key` or `local_public_key` for these flows.

## Keep

Keep the threshold stack:

- `crates/signer-core/src/near_threshold_ed25519.rs`
- `crates/signer-core/src/near_threshold_frost.rs`
- `wasm/near_signer/src/threshold/*`

Keep direct ephemeral key helpers only if link-device still needs them for temporary QR-session keys:

- `wasm/near_signer/src/handlers/handle_generate_ephemeral_near_keypair.rs`
- `wasm/near_signer/src/handlers/handle_sign_transaction_with_keypair.rs`
- the matching TS wrappers in `client/src/core/signingEngine/signers/wasm/nearSignerWasm.ts`

Those helpers are not the legacy passkey-derived local signer by themselves.

## Phase 1: Delete Seed-Based Rust And WASM Local-Signer Primitives

Remove the seed-based primitive and all bindings that exist only for local NEAR keypair derivation.

- Delete `crates/signer-core/src/near_ed25519.rs`.
- Remove the `near-ed25519` feature from:
  - `crates/signer-core/Cargo.toml`
  - `crates/signer-platform-web/Cargo.toml`
  - `crates/signer-platform-ios/Cargo.toml`
  - `wasm/near_signer/Cargo.toml`
- Remove `near_ed25519` exports from:
  - `crates/signer-core/src/lib.rs`
  - `crates/signer-platform-web/src/lib.rs`
  - `crates/signer-platform-ios/src/lib.rs`
- Remove local-signer test coverage tied to `near-ed25519` from:
  - `crates/signer-core/tests/baseline_behavior.rs`
  - `crates/signer-platform-web/src/tests.rs`
  - `crates/signer-platform-ios/src/tests.rs`
  - `tests/unit/signerParity.rustPlatforms.unit.test.ts`

Remove local NEAR key handlers and worker message types:

- Delete:
  - `wasm/near_signer/src/handlers/handle_derive_near_keypair_and_encrypt.rs`
  - `wasm/near_signer/src/handlers/handle_recover_keypair_from_passkey.rs`
  - `wasm/near_signer/src/handlers/handle_decrypt_private_key_with_prf.rs`
  - `wasm/near_signer/src/handlers/handle_register_device2_with_derived_key.rs`
- Remove their request/response enum entries and dispatch branches from:
  - `wasm/near_signer/src/types/worker_messages.rs`
  - `wasm/near_signer/src/handlers/mod.rs`
  - `wasm/near_signer/src/lib.rs`
- Remove `crate::crypto::derive_ed25519_key_from_prf_output` and any no-longer-used local encryption helpers from `wasm/near_signer/src/crypto.rs`.
- Re-evaluate whether `near_crypto` is still needed by `wasm/near_signer`; if not, drop that dependency from the near signer worker as part of the same cut.

Simplify the signer backend to threshold-only:

- In `wasm/near_signer/src/types/signing.rs`, delete `SignerMode::LocalSigner` and make threshold mode the only supported NEAR mode.
- In `wasm/near_signer/src/threshold/signer_backend.rs`:
  - delete `LocalEd25519Signer`
  - delete `Ed25519SignerBackend::from_encrypted_near_private_key`
  - delete the `Local(...)` variant and all branches that decrypt local private keys
- In the NEAR signing handlers, remove local branches from:
  - `wasm/near_signer/src/handlers/handle_sign_transactions_with_actions.rs`
  - `wasm/near_signer/src/handlers/handle_sign_delegate_action.rs`
  - `wasm/near_signer/src/handlers/handle_sign_nep413_message.rs`

## Phase 2: Remove Local NEAR Storage And Recovery APIs

Delete the client-side APIs whose only purpose is storing or recovering local NEAR private keys.

- Remove local key ops from:
  - `client/src/core/signingEngine/interfaces/nearKeyOps.ts`
  - `client/src/core/signingEngine/workerManager/nearKeyOps/index.ts`
  - `client/src/core/signingEngine/SigningEngine.ts`
- Delete:
  - `client/src/core/signingEngine/workerManager/nearKeyOps/deriveNearKeypairAndEncryptFromSerialized.ts`
  - `client/src/core/signingEngine/workerManager/nearKeyOps/recoverKeypairFromPasskey.ts`
  - `client/src/core/signingEngine/workerManager/nearKeyOps/decryptPrivateKeyWithPrf.ts`
  - `client/src/core/signingEngine/api/recovery/nearKeyDerivation.ts`
  - `client/src/core/signingEngine/api/recovery/privateKeyExportRecovery.ts` for the NEAR Ed25519 export/recovery path

Delete local NEAR IndexedDB types and helpers:

- Remove `local_near_sk_v3` and `local_sk_encrypted_v1` from:
  - `client/src/core/indexedDB/passkeyNearKeysDB.types.ts`
  - `client/src/core/indexedDB/near/keyMaterial.ts`
  - `client/src/core/indexedDB/near/index.ts`
  - `client/src/core/indexedDB/unifiedIndexedDBManager.ts`
  - `client/src/core/indexedDB/passkeyNearKeysDB/envelope.ts`
- Remove all `getNearLocalKeyMaterial` and `storeNearLocalKeyMaterial` call sites.
- Remove local-key warmup from `client/src/core/signingEngine/bootstrap/workerResourceWarmup.ts`.

Because breaking changes are acceptable, do not add migration adapters for old IndexedDB records. Remove the code and, if needed, add a one-time purge of legacy `local_sk_encrypted_v1` rows instead of continuing to parse them.

## Phase 3: Collapse NEAR Signing To Threshold-Only

Remove the public API and orchestration concept of "local signer" entirely.

- In `client/src/core/types/signer-worker.ts`:
  - remove `local-signer` from `SignerMode`
  - remove `DEFAULT_SIGNER_MODE = 'local-signer'`
  - remove `ThresholdBehavior` fallback semantics if fallback only meant "fallback to local"
- Update config and public typing:
  - `client/src/core/config/configHelpers.ts`
  - `client/src/core/types/tatchi.ts`
  - `client/src/core/types/sdkSentEvents.ts`
  - `client/src/core/types/delegate.ts`
- Remove local/fallback logic from:
  - `client/src/core/signingEngine/orchestration/near/shared/signingMaterials.ts`
  - `client/src/core/signingEngine/threshold/session/ed25519RelayerHealth.ts`
  - `client/src/core/signingEngine/orchestration/near/transactionsFlow.ts`
  - `client/src/core/signingEngine/orchestration/near/nep413Flow.ts`
  - `client/src/core/signingEngine/orchestration/near/delegateFlow.ts`

After this phase:

- NEAR signing requests always require threshold key material.
- missing threshold material is a hard error
- relayer unsupported is a hard error
- there is no `decryption` payload in NEAR worker signing requests

## Phase 4: Remove Local-Signer Registration, Linking, And Migration Paths

Registration and device-linking still carry legacy local-key branches. Remove them completely.

Registration:

- In `client/src/core/TatchiPasskey/registration.ts`:
  - remove the `requestedSignerModeStr !== 'threshold-signer'` branch
  - remove `backupLocalKey`
  - stop deriving `localKeyMaterialForPersist`
  - stop persisting local backup/export material
- Remove `backupLocalKey` plumbing from:
  - `client/src/core/TatchiPasskey/index.ts`
  - `client/src/core/WalletIframe/client/router.ts`
  - `client/src/core/WalletIframe/TatchiPasskeyIframe.ts`

Device linking:

- In `client/src/core/TatchiPasskey/near/linkDevice.ts`:
  - remove `localSignerEnabled`
  - stop deriving `localPublicKey`
  - stop sending `local_public_key` to the relay
  - stop storing local NEAR key material on device2
- Remove `localSignerEnabled` from:
  - `client/src/core/types/linkDevice.ts`
  - `client/src/react/components/PasskeyAuthMenu/types.ts`
  - `client/src/react/components/PasskeyAuthMenu/client.tsx`
  - `client/src/react/components/ShowQRCode.tsx`
  - `client/src/core/WalletIframe/shared/messages.ts`
  - `client/src/core/WalletIframe/host/wallet-iframe-handlers.ts`

Legacy migration/activation:

- Remove the local-account-to-threshold upgrade path from:
  - `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEd25519Lifecycle.ts`
  - `client/src/core/signingEngine/orchestration/thresholdActivation.ts`
  - `client/src/core/signingEngine/threshold/workflows/rotateEd25519KeyPostRegistration.ts`
- Delete the internal worker request `SignAddKeyThresholdPublicKeyNoPrompt` once no local-key activation path remains.
- Revisit `TatchiPasskey.enrollThresholdEd25519Key(...)`. If it only exists to migrate legacy local accounts, remove the public API instead of preserving it.

## Phase 5: Simplify Relay Contracts To Threshold-Only

The client and server still preserve compatibility for local-key registration/linking. Remove that compatibility.

Registration:

- In `client/src/core/TatchiPasskey/faucets/createAccountRelayServer.ts`, stop passing `new_public_key` for NEAR registration.
- In server request parsing and types, delete `new_public_key` from:
  - `server/src/core/types.ts`
  - `server/src/router/relayRegistrationBootstrap.ts`
  - `server/src/core/AuthService.ts`
  - `server/src/README.md`
- In `server/src/core/AuthService.ts`, remove the compatibility branch that backfills `newPublicKey` from threshold keygen output. The threshold bootstrap flow should become the only flow.

Link device:

- Delete `local_public_key` handling from:
  - `server/src/core/AuthService.ts`
  - any route/request types that still mention it

This should leave registration and link-device payloads threshold-only and easier to reason about.

## Phase 6: UI, Export, And Docs Cleanup

Remove UI that still exposes local signer behavior:

- `client/src/react/components/AccountMenuButton/TransactionSettingsSection.tsx`
- `client/src/react/components/AccountMenuButton/index.tsx`
- `client/src/react/components/AccountMenuButton/LinkedDevicesModal.tsx`

Expected UI changes:

- no local-vs-threshold signing toggle
- no NEAR private-key export button or flow
- no UI copy that suggests a local fallback or local backup key

Remove or rewrite docs that describe local NEAR seed export or local signer behavior:

- `docs/homomorphic-key-export-ED25519.md`
- `docs/evm-device-linking.md`
- `docs/test-review.md`
- any README/docs text found by grepping:
  - `local-signer`
  - `backupLocalKey`
  - `localSignerEnabled`
  - `near-ed25519-seed-v1`

## Test Plan

Delete tests that exist only for local signing/export/recovery, and rewrite mixed-mode tests to threshold-only.

High-value cleanup targets:

- `tests/e2e/**` cases that pass `signerMode: { mode: 'local-signer' }`
- `tests/unit/**` export/decrypt/recover/local-key-storage tests
- `tests/wallet-iframe/**` preference/config tests that assume local is the default
- `tests/unit/linkDevice.immediateSign.test.ts`
- `tests/unit/confirmTxFlow.*`
- `tests/unit/privateKeyExportRecovery.*`
- `tests/unit/walletSessionReadiness.gate.unit.test.ts`

Add or keep threshold-only coverage for:

- registration
- link-device
- NEAR transaction signing
- delegate signing
- NEP-413 signing
- relayer session bootstrap/auth refresh
- failure behavior when threshold material or relayer support is missing

## Done Criteria

The removal is complete when all of the following are true:

- `rg "local-signer|backupLocalKey|localSignerEnabled|deriveNearKeypairAndEncrypt|decryptPrivateKeyWithPrf|recoverKeypairFromPasskey|local_near_sk_v3|local_sk_encrypted_v1|near-ed25519"` only returns intentional historical references or this plan doc.
- `wasm/near_signer` no longer enables or imports `near-ed25519`.
- NEAR registration/link-device/signing flows compile and run without any local-key branch.
- There is exactly one NEAR signing model in the codebase: threshold Ed25519.

