# Migration Plan: Remove NEAR-Coupled Identity from IndexedDB

## Goal

Migrate IndexedDB schema and API surface from NEAR-specific identity semantics to chain-agnostic identity semantics.

Today, IndexedDB still exposes NEAR-coupled concepts in names and method shapes (`nearAccountId`, `PasskeyNearKeysDB`, `getNear*` helpers). We want a multichain-first model where identity and key material are keyed by profile + account reference, not by NEAR naming.

## Constraints

- Breaking changes are acceptable.
- No legacy flags or deprecated symbols at merge.
- Temporary adapters are allowed only inside the branch while migrating call sites.
- Final merged surface should not include duplicate NEAR-only and multichain-only APIs for the same behavior.

## Target Model (End State)

Canonical identity/persistence keying:

- `profileId` = user/profile root identity
- `chainIdKey` = chain namespace key (for example `near:testnet`, `evm:8453`, `solana:mainnet`)
- `accountAddress` = chain account address for the row
- `deviceNumber` = local device slot

Canonical key material keying:

- `[profileId, deviceNumber, chainIdKey, keyKind]` (already used by `keyMaterialV2`)

Canonical API shape:

- account lookups use `{ profileId, chainIdKey, accountAddress }` or typed `AccountRef`
- profile continuity APIs are profile/account-ref based, not `nearAccountId` based
- key material APIs are chain-generic (NEAR-specific validation stays in NEAR orchestration code, not base DB layer)

---

## Phase 0: Naming Freeze

### Files

- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/passkeyClientDB.types.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/passkeyNearKeysDB.types.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/index.ts`

### TODO

- [ ] Freeze replacement names for NEAR-coupled types and methods.
- [ ] Freeze canonical typed identity aliases (`ProfileId`, `ChainIdKey`, `AccountAddress`, `AccountRef`).
- [ ] Freeze chain-generic key DB naming (`PasskeyChainKeysDB*` naming family).
- [ ] Freeze migration acceptance criteria (no `getNear*` DB APIs in final public IndexedDB surface).

---

## Phase 1: Type Surface Decoupling

### Files

- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/passkeyClientDB.types.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/passkeyNearKeysDB.types.ts`

### TODO

- [ ] Replace NEAR-specific projection types with chain-generic projection types.
- [ ] Remove `nearAccountId` from base IndexedDB record types where it is only naming (not required semantics).
- [ ] Keep NEAR-specific fields only in NEAR-specific orchestration payload types (outside generic DB types).
- [ ] Rename `ThresholdEd25519ArtifactKind` / `PasskeyNearKeyMaterial*` type families to chain-generic equivalents while preserving payload schema compatibility.

---

## Phase 2: PasskeyClientDB Manager API Migration

### Files

- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/passkeyClientDB/manager.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/near/accountProjection.ts`

### TODO

- [ ] Introduce generic methods (profile/account-ref keyed) to replace NEAR-named manager methods.
- [ ] Migrate these NEAR-named methods to generic equivalents, then remove them before merge:
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
- [ ] Move `near/accountProjection.ts` logic into chain-generic projection helpers plus a thin NEAR adapter (or remove adapter if no longer needed).

---

## Phase 3: Key Material Layer Migration

### Files

- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/passkeyNearKeysDB/schema.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/passkeyNearKeysDB/manager.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/passkeyNearKeysDB.types.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/near/keyMaterial.ts`

### TODO

- [ ] Rename `PasskeyNearKeysDB*` schema/type/manager naming to chain-generic naming.
- [ ] Keep object-store key shape unchanged unless schema upgrade is required.
- [ ] Remove hard NEAR-only constraints from generic DB key write path:
  - do not enforce `chainIdKey.startsWith('near:')` in generic layer
  - do not enforce `algorithm === 'ed25519'` in generic layer
- [ ] Keep NEAR Option B validation in NEAR workflow code, not in generic key DB manager.
- [ ] If renaming DB/store names, add one migration step to preserve existing data and avoid reset.

---

## Phase 4: UnifiedIndexedDBManager Surface Cleanup

### Files

- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/unifiedIndexedDBManager.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/index.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/singletons.ts`

### TODO

- [ ] Rename `nearKeysDB` property to chain-generic naming.
- [ ] Replace `getNearThresholdKeyMaterial` / `storeNearThresholdKeyMaterial` with generic key material accessors.
- [ ] Remove NEAR naming from exported IndexedDB symbols.
- [ ] Ensure saga repair paths use generic account/profile semantics.

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

- [ ] Migrate call sites from NEAR-named manager methods to generic methods.
- [ ] Ensure login/session resolution works from profile/account-ref model.
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

- [ ] Replace NEAR-named DB API usage in tests with generic API usage.
- [ ] Add unit tests for generic profile/account-ref lookup behavior.
- [ ] Add persistence tests for non-NEAR chain key material rows.
- [ ] Keep NEAR flow regression tests green under generic DB surface.

---

## Phase 8: Final Cleanup (No Legacy Surface)

### TODO

- [ ] Remove `client/src/core/indexedDB/near/*` helpers that only exist for legacy naming.
- [ ] Remove NEAR-only method/type names from exported IndexedDB public API.
- [ ] Remove dead comments/docs that describe NEAR as identity root.
- [ ] Run full typecheck + targeted unit/e2e suites and ensure green.

---

## Definition of Done

- IndexedDB public API is chain-generic and profile/account-ref keyed.
- No NEAR-only naming remains in generic IndexedDB layers.
- NEAR-specific behavior exists only in NEAR signer/orchestration modules.
- Existing NEAR flows still work.
- Multichain paths can persist/read data without passing through NEAR-specific DB method names.
