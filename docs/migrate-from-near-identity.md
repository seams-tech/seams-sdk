# Migration Plan: Remove NEAR-Coupled Identity from IndexedDB

## Goal

Migrate IndexedDB schema and API surface from NEAR-specific identity semantics to chain-agnostic identity semantics.

Today, IndexedDB still exposes NEAR-coupled concepts in names and method shapes (`nearAccountId`, `PasskeyNearKeysDB`, `getNear*` helpers). We want a multichain-first model where identity and key material are keyed by profile + account reference, not by NEAR naming.

## Constraints

- Breaking changes are acceptable.
- No legacy flags or deprecated symbols at merge.
- Temporary adapters are allowed only inside the branch while migrating call sites.
- Final merged surface should not include duplicate NEAR-only and multichain-only APIs for the same behavior.
- Physical IndexedDB database names may be renamed during this refactor. A hard reset of legacy local key material is acceptable.

## Target Model (End State)

Canonical identity/persistence keying:

- `profileId` = user/profile root identity
- `chainIdKey` = chain namespace key (for example `near:testnet`, `evm:8453`, `solana:mainnet`)
- `accountAddress` = chain account address for the row
- `signerSlot` = local account signer slot

Canonical key material keying:

- `[profileId, signerSlot, chainIdKey, keyKind]`

Canonical API shape:

- account lookups use `{ profileId, chainIdKey, accountAddress }` or typed `AccountRef`
- profile continuity APIs are profile/account-ref based, not `nearAccountId` based
- key material APIs are chain-generic (NEAR-specific validation stays in NEAR orchestration code, not base DB layer)

---

## Phase 0: Naming Freeze

### Files

- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/passkeyClientDB.types.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/accountKeyMaterialDB.types.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/index.ts`

### TODO

- [x] Freeze replacement names for NEAR-coupled types and methods.
- [x] Freeze canonical typed identity aliases (`ProfileId`, `ChainIdKey`, `AccountAddress`, `AccountRef`).
- [x] Freeze chain-generic key DB naming (`PasskeyAccountKeyMaterialDB*` naming family).
- [x] Freeze migration acceptance criteria (no `getNear*` DB APIs in final public IndexedDB surface).

---

## Phase 1: Type Surface Decoupling

### Files

- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/passkeyClientDB.types.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/accountKeyMaterialDB.types.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/accountData/near/types.ts`

### TODO

- [x] Replace NEAR-specific continuity/profile snapshot types with chain-generic projection types where they back generic IndexedDB records.
- [x] Remove `nearAccountId` from generic continuity snapshots and generic manager return shapes where it was only naming.
- [x] Keep NEAR-specific fields only in NEAR-specific orchestration payload types (outside generic DB types).
- [x] Rename `PasskeyNearKeyMaterial*` type families to chain-generic equivalents while preserving payload schema compatibility.

---

## Phase 2: PasskeyClientDB Manager API Migration

### Files

- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/passkeyClientDB/manager.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/profileAccountProjection.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/accountData/near/accountProjection.ts`

### TODO

- [x] Introduce generic methods (profile/account-ref keyed) to replace NEAR-named manager methods.
- [x] Migrate these NEAR-named methods to generic equivalents, then remove them from `PasskeyClientDBManager`:
  - `resolveNearAccountContext`
  - `getNearAccountIdForProfile`
  - `resolveNearAccountProfileContinuity`
  - `getLastSelectedNearAccount`
  - `setLastProfileStateForNearAccount`
  - `getNearAccountProjection`
  - `listNearAccountProjections`
  - `upsertNearAccountProjection`
  - `touchLastLoginForNearAccount`
  - `listNearAuthenticators`
  - `getNearAuthenticatorByCredentialId`
  - `clearNearAuthenticators`
  - `upsertNearAuthenticator`
  - `hasNearPasskeyCredential`
  - `deleteNearAccountData`
  - `rollbackNearAccountRegistration`
- [x] Move `accountData/near/accountProjection.ts` logic into chain-generic projection helpers plus a thin NEAR adapter (or remove adapter if no longer needed).

---

## Phase 3: Key Material Layer Migration

### Files

- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/accountKeyMaterial.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/accountKeyMaterialDB/schema.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/accountKeyMaterialDB/manager.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/accountKeyMaterialDB.types.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/accountData/near/keyMaterial.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/TatchiPasskey/thresholdWarmSessionBootstrap.ts`

### TODO

- [x] Rename exported DB manager/config naming to chain-generic `*KeyMaterialDB*` surface.
- [x] Rename the remaining file/type-path family (`passkeyNearKeysDB*`) to chain-generic naming.
- [x] Keep object-store key shape unchanged unless schema upgrade is required.
- [x] Remove hard NEAR-only constraints from generic DB key write path:
  - do not enforce `chainIdKey.startsWith('near:')` in generic layer
  - do not enforce `algorithm === 'ed25519'` in generic layer
- [x] Keep NEAR Option B validation in NEAR workflow code, not in generic key DB manager.
- [x] Rename the physical key-material IndexedDB name to a chain-generic name (`PasskeyAccountKeyMaterial`).

---

## Phase 4: UnifiedIndexedDBManager Surface Cleanup

### Files

- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/unifiedIndexedDBManager.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/index.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/singletons.ts`

### TODO

- [x] Rename `nearKeysDB` property to chain-generic naming.
- [x] Remove `getNearThresholdKeyMaterial` / `storeNearThresholdKeyMaterial` from `UnifiedIndexedDBManager`.
- [x] Remove NEAR naming from exported IndexedDB manager/singleton symbols.
- [x] Rename the remaining exported key-material type/path names.
- [x] Ensure saga repair paths use generic account/profile semantics.

---

## Phase 5: Call-Site Migration (Signer + Tatchi)

### Files (primary)

- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/TatchiPasskey/authSessions.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/TatchiPasskey/login.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/TatchiPasskey/registration.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/api/registration/registrationAccountLifecycle.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/api/recovery/privateKeyExportRecovery.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/api/evmSigning.ts`

### TODO

- [x] Migrate call sites from NEAR-named manager methods to generic methods.
- [x] Remove runtime call sites that depended on `UnifiedIndexedDBManager` NEAR threshold convenience methods.
- [x] Move registration lifecycle profile/account writes and authenticator persistence onto direct profile/account-ref client DB operations.
- [x] Move `SigningEngine` last-user selection and authenticator lookup off NEAR projection helper writes.
- [x] Fix registration local-persistence ordering so profile/account mapping is stored before threshold key material writes.
- [x] Make `getWalletSession(nearAccountId)` attempt explicit-account login-state recovery instead of relying only on the last-user pointer.
- [x] Persist wallet-iframe threshold-ed25519 session and sealed PRF state in reload-stable browser storage.
- [ ] Ensure login/session resolution works from profile/account-ref model without NEAR-only adapter dependencies.
- [ ] Ensure EVM/Tempo flows do not depend on NEAR-only projection helpers.
- [ ] Keep NEAR business rules in NEAR-specific orchestration modules only.

---

## Phase 6: Schema/Migration Validation

### Files

- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/passkeyClientDB/schema.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/passkeyClientDB/migrations.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/passkeyClientDB/invariants.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/passkeyClientDB/profileCleanup.ts`

### TODO

- [ ] Add migration logic for renamed stores/fields where needed.
- [ ] Verify invariants with multichain rows containing non-NEAR accounts.
- [ ] Ensure migration does not orphan authenticator/key material rows.
- [ ] Verify upgrade path from current `dbVersion` works without data loss.

---

## Phase 7: Test Migration

### Files (minimum)

- `/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/passkeyClientDB.deviceSelection.test.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/nearThresholdKeyMaterial.persistence.unit.test.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/smartAccountRegistrationRecords.unit.test.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/tests/e2e/executeAction.twice.walletIframe.test.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/tests/e2e/worker_events.test.ts`

### TODO

- [x] Replace direct test usage of removed `PasskeyClientDBManager` NEAR methods with helper/generic usage where covered.
- [x] Replace remaining NEAR-named DB helper usage in tests with generic API usage where those helpers were only stale scaffolding.
  Remaining NEAR-named test usage is now intentional adapter coverage in `/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/nearThresholdKeyMaterial.persistence.unit.test.ts`.
  [x] Touch-confirm, export-recovery, bootstrap-persistence, and warm-signing unit tests no longer mock deleted `resolveNearAccountContext(...)` APIs.
  [x] Session-selection and immediate-fallback unit tests now stub generic `clientDB`/`accountKeyMaterialDB` dependencies instead of deleted `indexedDB.getNearThresholdKeyMaterial(...)`.
  [x] Source-backed continuity snapshot test now exercises `resolveProfileAccountContext(...)` plus helper fallback instead of deleted `resolveNearAccountContext(...)` manager APIs.
  [x] `/Users/pta/Dev/rust/simple-threshold-signer/tests/e2e/thresholdEcdsa.sealedRefresh.walletIframe.test.ts` now uses generic client/key-material DB reads instead of the NEAR IndexedDB adapter.
  [x] `/Users/pta/Dev/rust/simple-threshold-signer/tests/e2e/thresholdEcdsa.sealedRefresh.walletIframe.test.ts` now provisions managed registration bootstrap grants and relay publishable-key auth in the harness.
  [x] `/Users/pta/Dev/rust/simple-threshold-signer/tests/e2e/thresholdEcdsa.sealedRefresh.walletIframe.test.ts` now captures threshold-ed25519 HSS finalize responses and seeds relay key material from the real finalize payload.
  [x] Wallet-iframe sealed-refresh continuity is fixed end-to-end: targeted sealed-refresh suite now passes with local PRF seal persistence, refresh reuse, Tempo/EVM prompt parity, and matrix coverage.
- [x] Add unit tests for generic profile/account-ref lookup behavior.
- [x] Add persistence tests for non-NEAR chain key material rows.
- [x] Keep NEAR flow regression tests green under generic DB surface.

---

## Phase 8: Final Cleanup (No Legacy Surface)

### TODO

- [x] Remove `client/src/core/accountData/near/*` helpers that only exist for legacy naming.
  [x] Removed dead NEAR-only authenticator/account-deletion helper surface with no remaining callers:
  `buildNearAccountProjection`, `listNearAuthenticators`, `getNearAuthenticatorByCredentialId`,
  `clearNearAuthenticators`, `upsertNearAuthenticator`, `hasNearPasskeyCredential`,
  `deleteNearAccountData`, `clearAllNearAccounts`, and `rollbackNearAccountRegistration`.
  [x] Repo code no longer imports the NEAR barrel directly; callers now use `accountData/near/accountRefs`,
  `accountData/near/accountProjection`, `accountData/near/keyMaterial`, and `accountData/near/types` explicitly.
- [x] Remove NEAR-only method/type names from exported IndexedDB public API.
  [x] Removed `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/accountData/near/index.ts`
  and moved the remaining intentional adapter deep import to
  `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/accountData/near/keyMaterial.ts`.
  [x] Removed NEAR-only type re-exports from barrel-style public entrypoints where generic callers were using them.
- [x] Remove dead comments/docs that describe NEAR as identity root.
- [x] Run full typecheck + targeted unit/e2e suites and ensure green.

---

## Definition of Done

- IndexedDB public API is chain-generic and profile/account-ref keyed.
- No NEAR-only naming remains in generic IndexedDB layers.
- NEAR-specific behavior exists only in NEAR signer/orchestration modules.
- Existing NEAR flows still work.
- Multichain paths can persist/read data without passing through NEAR-specific DB method names.
