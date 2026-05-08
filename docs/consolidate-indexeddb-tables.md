# IndexedDB Consolidation Plan

Date created: 2026-05-03

Status: active cleanup plan, not implemented. Runtime storage still uses four
IndexedDB databases: `PasskeyClientDB`, `PasskeyAccountKeyMaterial`,
`seams_wallet_v1`, and `seams_email_otp_device_enrollment_escrows_v1`. Keep this
document as the active IndexedDB cleanup plan until the completion criteria pass.

## Objective

Consolidate local IndexedDB storage into one consistent Seams-owned schema:

1. Every IndexedDB database and object store name uses `snake_case`.
2. Every Seams-owned database and object store name starts with `seams_`.
3. Wallet-iframe mode keeps IndexedDB owned by the wallet origin; app-origin
   IndexedDB remains disabled when persistence is routed through the iframe.
4. Legacy CamelCase database names and mixed-case object stores are deleted, not
   migrated or kept behind compatibility paths.
5. The storage layout should be boring to inspect in DevTools: one wallet database
   per origin, with clearly named Seams object stores inside it.

This is a breaking development cleanup. If existing local accounts depend on old
IndexedDB records, reset local browser state and create a fresh account/session.

## Current Problems

Current IndexedDB state is split across several names and naming styles:

| Current database | Current role | Problem |
| --- | --- | --- |
| `PasskeyClientDB` | profiles, authenticators, account signers, signer mutation outbox, recovery email hints, durable nonce leases and locks | CamelCase, old product term, broad mixed responsibilities |
| `PasskeyAccountKeyMaterial` | local account key material envelopes | CamelCase, old product term, separate DB where one transaction surface would be simpler |
| `seams_wallet_v1` | durable signing-session sealed records and restore leases | Seams-prefixed, but separate from profile/key material state and still has a version suffix in the DB name |
| `seams_email_otp_device_enrollment_escrows_v1` | Email OTP device enrollment escrow | Seams-prefixed, but separate DB and version suffix in DB/store names |

Object store names are also mixed: `appState`, `profiles`,
`profileAuthenticators`, `chainAccounts`, `accountSigners`, `signerOpsOutbox`,
`recoveryEmailsV2`, `nonceLaneLeasesV1`, `nonceLaneLocksV1`, `keyMaterial`,
`signing_session_seals_v1`, `signing_session_restore_leases_v1`, and
`email_otp_device_enrollment_escrows_v1`.

DevTools can still show repeated DB names when multiple origins or frames are
present. This plan cannot make Chrome collapse origins into one row, but it
should make each Seams origin use the same small set of canonical names.

Current implementation snapshot:

1. `client/src/core/indexedDB/passkeyClientDB/schema.ts` defines
   `PasskeyClientDB` at schema version 32.
2. `PasskeyClientDB` owns:
   - `appState`
   - `profiles`
   - `profileAuthenticators`
   - `chainAccounts`
   - `accountSigners`
   - `signerOpsOutbox`
   - `recoveryEmailsV2`
   - `nonceLaneLeasesV1`
   - `nonceLaneLocksV1`
3. `client/src/core/indexedDB/accountKeyMaterialDB/schema.ts` defines
   `PasskeyAccountKeyMaterial` at schema version 11 with the `keyMaterial`
   object store.
4. `shared/src/utils/signingSessionSeal.ts` defines `seams_wallet_v1` at schema
   version 4 with:
   - `signing_session_seals_v1`
   - `signing_session_restore_leases_v1`
5. `client/src/core/signingEngine/workerManager/workers/email-otp/deviceEnrollmentEscrowStore.ts`
   defines `seams_email_otp_device_enrollment_escrows_v1` at schema version 1
   with `email_otp_device_enrollment_escrows_v1`.
6. `client/src/core/indexedDB/index.ts` still configures both `app` and `wallet`
   modes to use `PasskeyClientDB` and `PasskeyAccountKeyMaterial`. `disabled`
   mode closes both managers and prevents app-origin persistence when wallet
   iframe mode routes persistence elsewhere.
7. `UnifiedIndexedDBManager` is still an adapter over `PasskeyClientDBManager`
   and `AccountKeyMaterialDBManager`; durable signing-session seals and Email OTP
   device enrollment escrows are opened through their own modules.
8. Refactor 33 has moved most signing-engine callsites out of `api/`,
   `orchestration/`, `chainAdaptors/`, and `signers/`. Use the Refactor 33
   "Folder And Filename Change Reference" as the naming source of truth:
   operation modules are `flows/*`, reusable wallet auth is `walletAuth/*`, and
   construction/runtime wiring is `assembly/*`. Some intermediate working-tree
   paths may still be named `operations/*`, `auth/*`, or `bootstrap/*` until
   Refactor 33 fully lands.
9. Several unit tests still create CamelCase test databases such as
   `PasskeyClientDB-*` and `PasskeyAccountKeyMaterial-*`. Those tests should be
   renamed or moved onto unified schema fixtures when this plan is implemented.

Post-refactor 33 paths to revisit during the consolidation:

1. `client/src/core/signingEngine/session/persistence/sealedSessionStore.ts` still opens
   `seams_wallet_v1` directly for signing-session seals and restore leases.
2. `client/src/core/signingEngine/workerManager/workers/email-otp/deviceEnrollmentEscrowStore.ts`
   still opens `seams_email_otp_device_enrollment_escrows_v1` directly.
3. `client/src/core/signingEngine/session/userPreferences.ts` still subscribes
   to `IndexedDBManager.clientDB` events and reads profile state through the old
   client DB surface.
4. `client/src/core/signingEngine/flows/registration/accountLifecycle.ts`,
   `flows/signEvmFamily/*`, `flows/signNear/*`, `flows/recovery/*`,
   any remaining Email OTP flow helpers, `session/warmSigning/*`, `threshold/*`,
   and `walletAuth/webauthn/*` still depend on `UnifiedIndexedDBManager`,
   `clientDB`, or `accountKeyMaterialDB` ports.
5. `sdk/rolldown.config.ts` still exposes the old IndexedDB managers and the
   Email OTP escrow store as stable deep-import entries for tests/tools.

## Target Model

Consolidate all current local wallet-origin IndexedDB persistence into one
canonical database:

```ts
export const SEAMS_WALLET_DB_NAME = 'seams_wallet' as const;
export const SEAMS_WALLET_DB_VERSION = 1 as const;
```

The unified database replaces all current runtime databases:

1. `PasskeyClientDB` v32.
2. `PasskeyAccountKeyMaterial` v11.
3. `seams_wallet_v1` v4.
4. `seams_email_otp_device_enrollment_escrows_v1` v1.

The implementation should delete the old database managers and direct
`indexedDB.open(...)` modules as each store moves under `seams_wallet`. Runtime
code should open one database per persistence origin.

Do not encode schema version in object-store names. IndexedDB already has a
numeric schema version. Record-level versions remain inside records where they
are cryptographically or semantically meaningful.

Canonical object stores:

| Store | Replaces |
| --- | --- |
| `seams_app_state` | `appState` |
| `seams_profiles` | `profiles` |
| `seams_profile_authenticators` | `profileAuthenticators` |
| `seams_chain_accounts` | `chainAccounts` |
| `seams_account_signers` | `accountSigners` |
| `seams_signer_ops_outbox` | `signerOpsOutbox` |
| `seams_recovery_emails` | `recoveryEmailsV2` |
| `seams_nonce_lane_leases` | `nonceLaneLeasesV1` |
| `seams_nonce_lane_locks` | `nonceLaneLocksV1` |
| `seams_key_material` | `keyMaterial` in `PasskeyAccountKeyMaterial` |
| `seams_signing_session_seals` | `signing_session_seals_v1` |
| `seams_signing_session_restore_leases` | `signing_session_restore_leases_v1` |
| `seams_email_otp_device_enrollment_escrows` | `email_otp_device_enrollment_escrows_v1` |

Index names should also be snake_case. They do not need the `seams_` prefix
because they are scoped under a Seams-prefixed object store. The canonical index
inventory is:

```ts
'profile_id'
'credential_id'
'profile_id_credential_id'
'profile_id_signer_slot'
'updated_at'
'chain_id_key'
'chain_id_key_account_address'
'profile_id_chain_id_key'
'chain_id_key_account_address_status'
'status'
'next_attempt_at'
'status_next_attempt_at'
'idempotency_key'
'lane_key'
'account_id'
'state'
'expires_at_ms'
'lane_state'
'account_expires_at'
'owner_id'
'chain_id_key_key_kind'
'public_key'
'wallet_id'
'user_id'
'auth_method'
'signing_root_id'
'wallet_signing_root_auth_method'
'ed25519_threshold_session_id'
'ecdsa_threshold_session_id'
'wallet_signing_session_id'
'auth_subject_id'
'enrollment_id'
'wallet_auth_subject'
'wallet_auth_subject_enrollment'
```

## Non-Negotiable Rules

1. Do not read from legacy IndexedDB database names in production code.
2. Do not migrate legacy CamelCase databases.
3. Do not keep compatibility aliases for old database or object-store names.
4. Do not create one-off IndexedDB databases for new local state.
5. Do not add version suffixes to object-store names.
6. Tests may use unique database names, but test database names must also be
   snake_case and start with `seams_`, for example
   `seams_test_wallet_<safe_suffix>`. Test helpers must normalize UUIDs by
   replacing hyphens with underscores.
7. All IndexedDB names must come from one constants module. No inline database or
   object-store string literals in runtime code.
8. If local dev data breaks, delete old databases and recreate the account. Do
   not add legacy rescue paths.

## Proposed Code Shape

Add one schema-name module:

```ts
// client/src/core/indexedDB/schemaNames.ts
export const SEAMS_WALLET_DB_NAME = 'seams_wallet' as const;

export const SEAMS_WALLET_STORES = {
  appState: 'seams_app_state',
  profiles: 'seams_profiles',
  profileAuthenticators: 'seams_profile_authenticators',
  chainAccounts: 'seams_chain_accounts',
  accountSigners: 'seams_account_signers',
  signerOpsOutbox: 'seams_signer_ops_outbox',
  recoveryEmails: 'seams_recovery_emails',
  nonceLaneLeases: 'seams_nonce_lane_leases',
  nonceLaneLocks: 'seams_nonce_lane_locks',
  keyMaterial: 'seams_key_material',
  signingSessionSeals: 'seams_signing_session_seals',
  signingSessionRestoreLeases: 'seams_signing_session_restore_leases',
  emailOtpDeviceEnrollmentEscrows: 'seams_email_otp_device_enrollment_escrows',
} as const;
```

Replace separate DB managers with one wallet DB manager plus narrow repositories:

```ts
type SeamsWalletDbManager = {
  getDbName(): typeof SEAMS_WALLET_DB_NAME | `seams_test_wallet_${string}`;
  getDB(): Promise<IDBPDatabase>;
};

type SeamsWalletRepositories = {
  appState: AppStateRepository;
  lastProfileState: LastProfileStateRepository;
  profiles: ProfileRepository;
  profileAuthenticators: ProfileAuthenticatorRepository;
  chainAccounts: ChainAccountRepository;
  accountSigners: AccountSignerRepository;
  signerOpsOutbox: SignerOpsOutboxRepository;
  recoveryEmails: RecoveryEmailRepository;
  keyMaterial: KeyMaterialRepository;
  signingSessionSeals: SigningSessionSealRepository;
  signingSessionRestoreLeases: SigningSessionRestoreLeaseRepository;
  emailOtpDeviceEnrollmentEscrows: EmailOtpDeviceEnrollmentEscrowRepository;
  nonceLaneCoordination: NonceLaneCoordinationRepository;
};
```

Keep repository APIs narrow. The manager owns opening, version upgrades, and
legacy database deletion. Repositories own object-store reads and writes.

## Implementation Plan

### Phase 1. Rescan, Constants, and Early Guards

1. Add `client/src/core/indexedDB/schemaNames.ts`.
2. Add schema constants for:
   - `SEAMS_WALLET_DB_NAME`
   - `SEAMS_WALLET_DB_VERSION`
   - `SEAMS_WALLET_STORES`
   - `SEAMS_WALLET_INDEXES`
   - `LEGACY_INDEXED_DB_NAMES`
   - `createSeamsTestWalletDbName(...)`
3. Add an architecture guard with an explicit temporary allowlist for legacy
   modules that have not moved yet. The final guard must fail if runtime code
   contains:
   - `PasskeyClientDB`
   - `PasskeyAccountKeyMaterial`
   - `seams_wallet_v1`
   - `seams_email_otp_device_enrollment_escrows_v1`
   - `signing_session_seals_v1`
   - `signing_session_restore_leases_v1`
   - `email_otp_device_enrollment_escrows_v1`
   - inline `indexedDB.open('<literal>')` outside the one DB manager
4. Add a guard that all configured database, object-store, and index names match:

```ts
/^seams_[a-z0-9]+(?:_[a-z0-9]+)*$/
```

5. Update test helpers so unique DB names are generated as
   `seams_test_wallet_<safe_suffix>`.
6. Record the current post-refactor 33 IndexedDB callsite inventory before
   moving repositories. Use the canonical `flows/`, `session/`, `threshold/`,
   `walletAuth/`, and worker-support paths from `docs/refactor-33.md` as the
   starting inventory, accounting for any intermediate folder names still in the
   working tree.

### Phase 2. Create the Unified Schema

1. Introduce `SeamsWalletDBManager` with `SEAMS_WALLET_DB_NAME`.
2. Move the existing `PasskeyClientDB` object stores into the unified schema
   under their `seams_*` store names.
3. Move `PasskeyAccountKeyMaterial` into the unified schema as
   `seams_key_material`.
4. Move signing-session sealed records into the unified schema as:
   - `seams_signing_session_seals`
   - `seams_signing_session_restore_leases`
5. Move Email OTP device enrollment escrow records into the unified schema as:
   - `seams_email_otp_device_enrollment_escrows`
6. Keep all record schemas strict. Do not add compatibility reads for old object
   store names.
7. Keep this phase focused on schema creation and repository construction. The
   runtime will still open legacy databases until Phase 3 replaces the manager
   assembly and direct stores.

### Phase 3. Replace Managers and Imports

1. Replace `PasskeyClientDBManager` with `SeamsWalletDBManager` and repository
   ports.
2. Delete `AccountKeyMaterialDBManager`; key material becomes a repository on
   the unified wallet DB.
3. Move signing-session seal reads/writes from
   `client/src/core/signingEngine/session/persistence/sealedSessionStore.ts` into a
   `seams_signing_session_seals` repository on the unified wallet DB.
4. Move Email OTP device enrollment escrow reads/writes from
   `client/src/core/signingEngine/workerManager/workers/email-otp/deviceEnrollmentEscrowStore.ts`
   into a
   `seams_email_otp_device_enrollment_escrows` repository on the unified wallet
   DB.
5. Replace `UnifiedIndexedDBManager` with a smaller assembly that exposes
   repositories, not separate database managers.
6. Update post-refactor 33 callsites to use the new repositories:
   - `session/userPreferences.ts`
   - `session/persistence/sealedSessionStore.ts`
   - `session/warmSigning/*`
   - `flows/registration/*`
   - `flows/recovery/*`
   - `flows/signEvmFamily/*`
   - `flows/signNear/*`
   - any remaining Email OTP flow helpers
   - `threshold/*`
   - `walletAuth/webauthn/*`
   - `workerManager/workers/email-otp/*`
7. Delete old manager files once no production import remains.
8. Confirm `seams_wallet` is the only runtime database opened by the wallet
   persistence path after this phase.

### Phase 4. Delete Legacy Local Databases

Add a dev-state cleanup command behind the new DB manager startup:

```ts
const LEGACY_INDEXED_DB_NAMES = [
  'PasskeyClientDB',
  'PasskeyAccountKeyMaterial',
  'seams_wallet_v1',
  'seams_email_otp_device_enrollment_escrows_v1',
] as const;
```

Rules:

1. Enable deletion only after runtime no longer opens the old managers or direct
   one-off IndexedDB stores.
2. Delete these databases after the new `seams_wallet` manager is configured and
   before new stores are opened.
3. Do not parse or migrate records from these databases.
4. If deletion is blocked by another open tab, log a development warning and
   continue with the new database.
5. Do not expose legacy database contents through status, snapshot, restore,
   transaction, or export paths.

### Phase 5. Tests

Add or update tests for:

1. New installs create only `seams_wallet` for wallet-origin persistence.
2. App-origin iframe mode creates no app-origin IndexedDB database.
3. All object stores in `seams_wallet` are `seams_*` and snake_case.
4. Legacy databases are deleted when present.
5. Legacy databases are not read during:
   - wallet-session status
   - transaction signing
   - key export
   - sealed-session restore
   - Email OTP device enrollment restore
6. Test database names are generated as `seams_test_wallet_*`.
7. Architecture guards reject new IndexedDB database names or stores that are not
   `seams_*` snake_case.

Existing tests to revisit during implementation:

1. `passkeyClientDB.*` tests should become repository tests over
   `SeamsWalletDBManager`.
2. Account key material, signer saga, smart-account, link-device, profile
   projection, and local signer reconciliation tests currently create
   `PasskeyClientDB-*` and `PasskeyAccountKeyMaterial-*` databases. Move them to
   `seams_test_wallet_*` fixtures.
3. `sealedSessionStore.unit.test.ts` currently inspects `seams_wallet_v1` and
   `signing_session_seals_v1`. Move it to the unified signing-session seal
   repository.
4. `emailOtpDeviceEnrollmentEscrowStore.unit.test.ts` currently inspects
   `seams_email_otp_device_enrollment_escrows_v1` and
   `email_otp_device_enrollment_escrows_v1`. Move it to the unified Email OTP
   escrow repository.
5. `availableSigningLanes.*`, `touchConfirm.workerRouter.*`,
   `thresholdEd25519.registrationWarmSession.*`, and post-refactor 33 operation
   tests should use the repository assembly rather than the old
   `clientDB`/`accountKeyMaterialDB` split.

### Phase 6. Manual Verification

1. Clear site data for all local wallet/app origins.
2. Create a fresh passkey account.
3. Create a fresh Email OTP account.
4. Confirm DevTools IndexedDB shows only Seams-prefixed DBs for each origin.
5. Verify:
   - wallet unlock
   - page refresh restore
   - ED25519 transaction signing
   - ECDSA transaction signing
   - session exhaustion step-up
   - ED25519 key export
   - ECDSA key export
6. Repeat in wallet-iframe mode and confirm the app origin does not create local
   IndexedDB state.

## Completion Criteria

- Runtime code has one canonical IndexedDB database name: `seams_wallet`.
- Every Seams object store is `seams_*` snake_case.
- No production runtime code references old database names.
- No production runtime code reads or migrates old IndexedDB databases.
- Key material, profile/account state, nonce coordination, signing-session seals,
  and Email OTP enrollment escrow records live under the unified wallet DB.
- Status, transaction signing, restore, and export paths do not create extra
  IndexedDB databases.
- Guard tests prevent reintroducing mixed-case or non-Seams storage names.
- Fresh local manual testing works for both passkey and Email OTP accounts after
  clearing old site data.
